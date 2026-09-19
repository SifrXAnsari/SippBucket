using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Machines;

/// <summary>One other person, as this person groups their machines.</summary>
/// <remarks>
/// The grouping is this person's own bookkeeping, made here and never taken from anywhere:
/// nothing on the wire says whose a machine is, so only the person who paired them can say
/// that two machines are one colleague (docs/DIRECT-MESSAGES.md, "A person, not a machine").
/// The name is the name this person gave them; what is actually verified is each machine's
/// device key.
/// </remarks>
public sealed record Person
{
    /// <summary>
    /// A stable key for the person, made at creation and never reused: what caps and message
    /// stores group by, so a rename changes no grouping.
    /// </summary>
    public required string Key { get; init; }

    /// <summary>The name this person knows them by.</summary>
    public required string Name { get; init; }

    /// <summary>The device IDs of their machines, as their keys proved them at pairing.</summary>
    public required IReadOnlyList<string> Devices { get; init; }
}

/// <summary>
/// One sender's scope for anything counted per person: the person's machines when the person
/// is known, and the one machine alone when not.
/// </summary>
/// <param name="Key">What to count under: the person's key, or <c>device:</c> and the device ID.</param>
/// <param name="Name">The person's name, or null for an ungrouped machine, whose own name stands.</param>
/// <param name="Devices">Every device the count covers. Always includes the device asked about.</param>
public sealed record PersonScope(string Key, string? Name, IReadOnlyList<string> Devices);

/// <summary>
/// The people this person has grouped other machines into, kept per user in
/// <c>people.json</c> beside the device key.
/// </summary>
/// <remarks>
/// <para>
/// Until a machine is grouped, it counts as a person of its own everywhere a count is per
/// person — the inbox space cap, the team size, a conversation — which is the conservative
/// reading of "one person with three machines doesn't count as a different person": the code
/// can count machines but cannot know they are one person until told
/// (docs/DIRECT-MESSAGES.md).
/// </para>
/// <para>
/// A file that cannot be read is reported, never guessed at: <see cref="Load"/> throws a
/// <see cref="JsonException"/> naming it. A caller deciding something that protects the
/// person treats every machine as ungrouped, and a caller deciding whether to switch team
/// features on treats them as off, each of which is the safe side. A file written by a newer
/// build is read as far as this build understands it and never rewritten by this one.
/// </para>
/// </remarks>
public sealed class PeopleStore
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "people.json";

    /// <summary>The schema this build writes, and the newest it can rewrite without loss.</summary>
    public const int CurrentSchema = 1;

    /// <summary>The prefix of an ungrouped machine's scope key, so it can never collide with a person's.</summary>
    public const string DeviceKeyPrefix = "device:";

    /// <summary>One gate per file, shared by every store over it in this process.</summary>
    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);

    private readonly object _gate;

    /// <summary>Creates a store over a file.</summary>
    /// <param name="path">Full path to <c>people.json</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public PeopleStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        FilePath = path;
        _gate = Gates.GetOrAdd(Path.GetFullPath(path), static _ => new object());
    }

    /// <summary>The file this store reads and writes.</summary>
    public string FilePath { get; }

    /// <summary>The store for the person running this process.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static PeopleStore ForThisUser() => new(Path.Combine(UserDataDirectory.Resolve(), FileName));

    /// <summary>Reads every person.</summary>
    /// <returns>The people, empty when there is no file yet.</returns>
    /// <exception cref="JsonException">The file cannot be read as this store. The message names it.</exception>
    public IReadOnlyList<Person> Load()
    {
        lock (_gate)
        {
            return Read().People;
        }
    }

    /// <summary>The person a device is grouped under, or null while it is not.</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>Their record, or null.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public Person? PersonOf(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        return PersonOf(Load(), deviceId);
    }

    /// <summary>The scope anything counted per person uses for one device.</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>The person's scope, or the device alone while it is ungrouped.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public PersonScope ScopeOf(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        return PersonOf(Load(), deviceId) is { } person
            ? new PersonScope(person.Key, person.Name, person.Devices)
            : SoleScope(deviceId);
    }

    /// <summary>The scope of a device counted alone: itself, under a key no person's can be.</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>The singleton scope.</returns>
    public static PersonScope SoleScope(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
#pragma warning disable CA1308 // Device IDs are lowercase identifiers; the key must match however the ID was typed.
        return new PersonScope(DeviceKeyPrefix + deviceId.ToLowerInvariant(), null, [deviceId]);
#pragma warning restore CA1308
    }

    /// <summary>Finds one person by name or key, ignoring case.</summary>
    /// <param name="nameOrKey">What the person typed.</param>
    /// <returns>Their record, or null.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public Person? Find(string nameOrKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nameOrKey);
        return Load().FirstOrDefault(person =>
            string.Equals(person.Name, nameOrKey, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(person.Key, nameOrKey, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Groups devices under a person, creating the person when the name is new. A device
    /// already grouped under someone else is refused, so a machine is never quietly moved.
    /// </summary>
    /// <param name="name">The person's name, as this person calls them.</param>
    /// <param name="deviceIds">Their machines' device IDs.</param>
    /// <param name="refused">Why a device was not added, one line each; empty when all were.</param>
    /// <returns>The person as written.</returns>
    /// <exception cref="ArgumentException">The name is blank, not displayable, or no devices were given.</exception>
    /// <exception cref="JsonException">The file cannot be read, so it is not overwritten.</exception>
    /// <exception cref="InvalidOperationException">The file was written by a newer build.</exception>
    public Person Add(string name, IReadOnlyList<string> deviceIds, out IReadOnlyList<string> refused)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(deviceIds);

        if (deviceIds.Count == 0)
        {
            throw new ArgumentException("A person is their machines; name at least one.", nameof(deviceIds));
        }

        if (name.Length > 64 || name.Any(DisplayText.IsInstruction))
        {
            throw new ArgumentException("A person's name is at most 64 characters, with nothing invisible in it.", nameof(name));
        }

        lock (_gate)
        {
            var stored = Read();
            RefuseNewer(stored.Schema);

            var people = stored.People.ToList();
            var index = people.FindIndex(person => string.Equals(person.Name, name, StringComparison.OrdinalIgnoreCase));
            var existing = index < 0 ? null : people[index];

            var problems = new List<string>();
            var devices = existing?.Devices.ToList() ?? [];
            foreach (var deviceId in deviceIds)
            {
                if (string.IsNullOrWhiteSpace(deviceId))
                {
                    problems.Add("a blank device ID was passed over");
                    continue;
                }

                if (devices.Any(known => DeviceIdentity.IsSameDevice(known, deviceId)))
                {
                    continue;
                }

                if (PersonOf(people, deviceId) is { } other)
                {
                    problems.Add($"{Short(deviceId)} is already {other.Name}'s; remove it from them first");
                    continue;
                }

                devices.Add(deviceId);
            }

            var person = new Person
            {
                Key = existing?.Key ?? NewKey(people),
                Name = existing?.Name ?? name,
                Devices = devices,
            };

            if (index < 0)
            {
                people.Add(person);
            }
            else
            {
                people[index] = person;
            }

            Write(people);
            refused = problems;
            return person;
        }
    }

    /// <summary>Removes one device from whoever it is grouped under; a person left with no machines is removed.</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>The person it was removed from, or null when it was grouped under nobody.</returns>
    /// <exception cref="ArgumentException">The device ID is blank.</exception>
    /// <exception cref="JsonException">The file cannot be read, so it is not overwritten.</exception>
    /// <exception cref="InvalidOperationException">The file was written by a newer build.</exception>
    public Person? Remove(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        lock (_gate)
        {
            var stored = Read();
            RefuseNewer(stored.Schema);

            var people = stored.People.ToList();
            var index = people.FindIndex(person => person.Devices.Any(known => DeviceIdentity.IsSameDevice(known, deviceId)));
            if (index < 0)
            {
                return null;
            }

            var person = people[index];
            var devices = person.Devices.Where(known => !DeviceIdentity.IsSameDevice(known, deviceId)).ToList();
            if (devices.Count == 0)
            {
                people.RemoveAt(index);
            }
            else
            {
                people[index] = person with { Devices = devices };
            }

            Write(people);
            return person;
        }
    }

    /// <summary>The person a device is grouped under in a list, or null.</summary>
    /// <param name="people">The people.</param>
    /// <param name="deviceId">The device.</param>
    /// <returns>Their record, or null.</returns>
    public static Person? PersonOf(IReadOnlyList<Person> people, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(people);
        return people.FirstOrDefault(person =>
            person.Devices.Any(known => DeviceIdentity.IsSameDevice(known, deviceId)));
    }

    private static string Short(string deviceId) => deviceId.Length > 12 ? deviceId[..12] : deviceId;

    private static string NewKey(IReadOnlyList<Person> people)
    {
        // Eight random bytes: sixteen hex characters, drawn until unused, which the first
        // draw is for any list a person could make by hand.
        while (true)
        {
#pragma warning disable CA1308 // The key is an identifier, and lowercase hex is its stored form.
            var key = "p-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
#pragma warning restore CA1308
            if (!people.Any(person => string.Equals(person.Key, key, StringComparison.OrdinalIgnoreCase)))
            {
                return key;
            }
        }
    }

    private static void RefuseNewer(int schema)
    {
        if (schema > CurrentSchema)
        {
            throw new InvalidOperationException(
                $"people.json was written by a newer SippBucket (schema {schema.ToString(CultureInfo.InvariantCulture)}), " +
                "and this one would lose what that version recorded by rewriting it. Update SippBucket, then try again. " +
                "Nothing was changed.");
        }
    }

    private StoredFile Read()
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(FilePath));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new StoredFile(CurrentSchema, []);
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return new StoredFile(CurrentSchema, []);
        }

        StoredFile? file;
        try
        {
            file = JsonSerializer.Deserialize<StoredFile>(json, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new JsonException(
                $"{FilePath} cannot be read ({ex.Message}). Until it is mended or deleted, every machine counts as " +
                "its own person wherever that protects you, team features stay off, and nothing is written to it.",
                ex);
        }

        if (file is null || file.People is null)
        {
            throw new JsonException(
                $"{FilePath} holds no list of people. Until it is mended or deleted, every machine counts as its own " +
                "person wherever that protects you, team features stay off, and nothing is written to it.");
        }

        return file;
    }

    private void Write(IReadOnlyList<Person> people)
    {
        var directory = Path.GetDirectoryName(FilePath)
            ?? throw new InvalidOperationException($"{FilePath} has no directory.");
        Directory.CreateDirectory(directory);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(new StoredFile(CurrentSchema, people), SipJson.Readable);

        // Written beside the file and swapped in whole, as machines.json is, so the file is
        // always the old grouping or the new one, never half of each.
        var temporary = $"{FilePath}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);

            if (File.Exists(FilePath))
            {
                SharingRetry.Run(() => File.Replace(temporary, FilePath, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, FilePath));
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    /// <summary>The file as stored.</summary>
    /// <param name="Schema">The schema it was written in.</param>
    /// <param name="People">One entry per person.</param>
    private sealed record StoredFile(int Schema, IReadOnlyList<Person> People);
}
