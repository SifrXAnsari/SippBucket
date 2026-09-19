using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Machines;

/// <summary>What this person has said about one paired device.</summary>
public sealed record KnownMachine
{
    /// <summary>The device's hexadecimal Ed25519 public key: the only thing that proves which machine it is.</summary>
    public required string DeviceId { get; init; }

    /// <summary>Whose machine it is, as the person answered.</summary>
    public MachineOwner Owner { get; init; }

    /// <summary>The name the person knows it by: set on this machine, never taken from the other.</summary>
    public string? Name { get; init; }

    /// <summary>When the person answered, or null while unanswered.</summary>
    public DateTimeOffset? AnsweredUtc { get; init; }
}

/// <summary>
/// The answers this person has given about the devices they paired with, kept once per user
/// for every folder, in <c>machines.json</c> beside the device key.
/// </summary>
/// <remarks>
/// <para>
/// Pairing is per folder, and a person can share several folders with one machine, but
/// whose machine it is has one answer. Keeping the answer once, per device, means two folders
/// can never disagree about it, and the question is asked once per machine however many
/// folders it later joins. The peer lists in each folder's <c>.sip</c> stay the only record
/// of who is paired: this file holds answers, never trust, and a device listed here that is
/// in no folder's peer list is paired with nothing.
/// </para>
/// <para>
/// It lives in the per-user data directory (<see cref="UserDataDirectory"/>), as the device
/// key does, because the daemon that acts on it runs as the person and the answers are theirs.
/// </para>
/// <para>
/// A file that cannot be read is reported, never guessed at: <see cref="Load"/> throws a
/// <see cref="JsonException"/> naming it, and a caller making a safety decision treats every
/// device as unanswered, which is the safe answer. A file written by a newer build is read
/// as far as this build understands it and is never rewritten by this one, so nothing the
/// newer build recorded is lost.
/// </para>
/// </remarks>
public sealed class KnownMachines
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "machines.json";

    /// <summary>The schema this build writes, and the newest it can rewrite without loss.</summary>
    public const int CurrentSchema = 1;

    /// <summary>One gate per file, shared by every store over it in this process.</summary>
    private static readonly ConcurrentDictionary<string, object> Gates =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly string _path;
    private readonly object _gate;

    /// <summary>Creates a store over a file.</summary>
    /// <param name="path">Full path to <c>machines.json</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public KnownMachines(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
        _gate = Gates.GetOrAdd(Path.GetFullPath(path), static _ => new object());
    }

    /// <summary>The store for the person running this process.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static KnownMachines ForThisUser() =>
        new(Path.Combine(UserDataDirectory.Resolve(), FileName));

    /// <summary>The file this store reads and writes.</summary>
    public string FilePath => _path;

    /// <summary>Reads every answer.</summary>
    /// <returns>One entry per device, empty when there is no file yet.</returns>
    /// <exception cref="JsonException">The file cannot be read as this store. The message names it.</exception>
    public IReadOnlyList<KnownMachine> Load()
    {
        lock (_gate)
        {
            return Read().Machines;
        }
    }

    /// <summary>Whose machine a device is, as the person answered.</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>The answer, or <see cref="MachineOwner.Unanswered"/> for a device never answered about.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public MachineOwner OwnerOf(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        return Find(Load(), deviceId)?.Owner ?? MachineOwner.Unanswered;
    }

    /// <summary>Records the person's answer about a device, replacing any earlier one.</summary>
    /// <param name="deviceId">The device.</param>
    /// <param name="owner">The answer. <see cref="MachineOwner.Unanswered"/> takes an answer back.</param>
    /// <param name="name">The name the person knows it by, or null to keep the one on record.</param>
    /// <param name="nowUtc">When the answer was given.</param>
    /// <returns>The answer that was on record before, or <see cref="MachineOwner.Unanswered"/>.</returns>
    /// <exception cref="ArgumentException">The device ID is blank.</exception>
    /// <exception cref="JsonException">The file cannot be read, so it is not overwritten.</exception>
    /// <exception cref="InvalidOperationException">
    /// The file was written by a newer build, which this one would lose information from by
    /// rewriting it.
    /// </exception>
    public MachineOwner Answer(string deviceId, MachineOwner owner, string? name, DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        lock (_gate)
        {
            var stored = Read();
            if (stored.Schema > CurrentSchema)
            {
                throw new InvalidOperationException(
                    $"{_path} was written by a newer SippBucket (schema {stored.Schema.ToString(CultureInfo.InvariantCulture)}), " +
                    "and this one would lose what that version recorded by rewriting it. Update SippBucket, " +
                    "then answer again. Nothing was changed.");
            }

            var machines = stored.Machines.ToList();
            var index = machines.FindIndex(m => SameDevice(m.DeviceId, deviceId));
            var before = index < 0 ? MachineOwner.Unanswered : machines[index].Owner;

            // An entry keeps the device ID as first written; a new one takes it as the caller
            // gave it. Device IDs are made in lower case, and every comparison ignores case.
            var entry = new KnownMachine
            {
                DeviceId = index < 0 ? deviceId : machines[index].DeviceId,
                Owner = owner,
                Name = name ?? (index < 0 ? null : machines[index].Name),
                AnsweredUtc = owner == MachineOwner.Unanswered ? null : nowUtc,
            };

            if (index < 0)
            {
                machines.Add(entry);
            }
            else
            {
                machines[index] = entry;
            }

            Write(machines);
            return before;
        }
    }

    /// <summary>The entry for a device in a list, matched ignoring case.</summary>
    /// <param name="machines">The list.</param>
    /// <param name="deviceId">The device.</param>
    /// <returns>Its entry, or null.</returns>
    public static KnownMachine? Find(IReadOnlyList<KnownMachine> machines, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(machines);
        return machines.FirstOrDefault(m => SameDevice(m.DeviceId, deviceId));
    }

    private static bool SameDevice(string? left, string? right) =>
        left is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private StoredFile Read()
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(_path));
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
                $"{_path} cannot be read ({ex.Message}). Until it is mended or deleted, every paired " +
                "machine is treated as someone else's wherever that protects you, and nothing is written to it.",
                ex);
        }

        if (file is null || file.Machines is null)
        {
            throw new JsonException(
                $"{_path} holds no list of machines. Until it is mended or deleted, every paired machine " +
                "is treated as someone else's wherever that protects you, and nothing is written to it.");
        }

        return file;
    }

    private void Write(IReadOnlyList<KnownMachine> machines)
    {
        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException($"{_path} has no directory.");
        Directory.CreateDirectory(directory);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(new StoredFile(CurrentSchema, machines), SipJson.Readable);

        // Written beside the file and swapped in whole, as the watch list is, so the file is
        // always the old answers or the new ones, never half of each.
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);

            if (File.Exists(_path))
            {
                SharingRetry.Run(() => File.Replace(temporary, _path, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, _path));
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
    /// <param name="Machines">One entry per device.</param>
    private sealed record StoredFile(int Schema, IReadOnlyList<KnownMachine> Machines);
}
