using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Machines;

/// <summary>This person's own team settings, kept per user in <c>team.json</c> beside the device key.</summary>
public sealed record TeamSettings
{
    /// <summary>The schema this build writes.</summary>
    public int Schema { get; init; } = TeamSettingsStore.CurrentSchema;

    /// <summary>
    /// The owner's exception: a team of two people counts as a team
    /// (docs/DIRECT-MESSAGES.md, "Teams are minimal 3 users. User can set an exception at
    /// 2 users if they wish."). Off until the person sets it.
    /// </summary>
    public bool TwoPersonException { get; init; }
}

/// <summary>Reads and writes <c>team.json</c>, following the same rules as every settings file here.</summary>
public sealed class TeamSettingsStore
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "team.json";

    /// <summary>The schema this build writes, and the newest it can rewrite without loss.</summary>
    public const int CurrentSchema = 1;

    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);

    private readonly object _gate;

    /// <summary>Creates a store over a file.</summary>
    /// <param name="path">Full path to <c>team.json</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public TeamSettingsStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        FilePath = path;
        _gate = Gates.GetOrAdd(Path.GetFullPath(path), static _ => new object());
    }

    /// <summary>The file this store reads and writes.</summary>
    public string FilePath { get; }

    /// <summary>The store for the person running this process.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static TeamSettingsStore ForThisUser() => new(Path.Combine(UserDataDirectory.Resolve(), FileName));

    /// <summary>Reads the settings.</summary>
    /// <returns>The settings; the defaults when there is no file yet.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public TeamSettings Load()
    {
        lock (_gate)
        {
            return Read();
        }
    }

    /// <summary>Changes the settings: reads them, applies a change, and writes the result.</summary>
    /// <param name="change">The change.</param>
    /// <returns>The settings as written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="change"/> was null.</exception>
    /// <exception cref="JsonException">The file cannot be read, so it is not overwritten.</exception>
    /// <exception cref="InvalidOperationException">The file was written by a newer build.</exception>
    public TeamSettings Update(Func<TeamSettings, TeamSettings> change)
    {
        ArgumentNullException.ThrowIfNull(change);

        lock (_gate)
        {
            var current = Read();
            if (current.Schema > CurrentSchema)
            {
                throw new InvalidOperationException(
                    $"{FilePath} was written by a newer SippBucket (schema {current.Schema.ToString(CultureInfo.InvariantCulture)}), " +
                    "and this one would lose what that version recorded by rewriting it. Update SippBucket, then " +
                    "try again. Nothing was changed.");
            }

            var changed = change(current) with { Schema = CurrentSchema };
            Write(changed);
            return changed;
        }
    }

    private TeamSettings Read()
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(FilePath));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new TeamSettings();
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return new TeamSettings();
        }

        TeamSettings? settings;
        try
        {
            settings = JsonSerializer.Deserialize<TeamSettings>(json, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new JsonException(
                $"{FilePath} cannot be read ({ex.Message}). Until it is mended or deleted, team features stay " +
                "off and nothing is written to it.",
                ex);
        }

        return settings
            ?? throw new JsonException(
                $"{FilePath} holds no team settings. Until it is mended or deleted, team features stay off " +
                "and nothing is written to it.");
    }

    private void Write(TeamSettings settings)
    {
        var directory = Path.GetDirectoryName(FilePath)
            ?? throw new InvalidOperationException($"{FilePath} has no directory.");
        Directory.CreateDirectory(directory);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(settings, SipJson.Readable);
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
}

/// <summary>What the team switch decided, and why, in words a status line can print.</summary>
/// <param name="On">Whether team features are on.</param>
/// <param name="PeopleCount">How many people the team counts, this person included.</param>
/// <param name="OtherPeople">The other people counted: named where grouped, one per ungrouped machine.</param>
/// <param name="Exception">Whether the two-person exception is set.</param>
/// <param name="Why">One sentence: why it is on, or what it is waiting for.</param>
public sealed record TeamDecision(
    bool On,
    int PeopleCount,
    IReadOnlyList<string> OtherPeople,
    bool Exception,
    string Why);

/// <summary>
/// The team switch: off until a team exists, decided from this person's own answers and
/// grouping, never guessed (docs/DIRECT-MESSAGES.md, "When DMs appear").
/// </summary>
/// <remarks>
/// <para>
/// A team is people, not machines. The count is this person plus every other person among
/// the machines paired here that they answered "someone else's" about: machines grouped
/// under one person count once, and each ungrouped machine counts as a person of its own —
/// which can only overcount, and an overcount here switches nothing off that safety needs,
/// because the safety measures run from the first "someone else's" answer regardless
/// (docs/DIRECT-MESSAGES.md, "Safety is not a team feature").
/// </para>
/// <para>
/// An unanswered machine is nobody: it gets every safety default of "someone else's", and
/// it builds no team, because a team the person never said exists must not switch features
/// on. A file that cannot be read decides the same way — off — and the reason says which
/// file. Only what protects the person is allowed to fail open, and this switch protects
/// them by failing shut.
/// </para>
/// </remarks>
public sealed class TeamFeatures
{
    private readonly KnownMachines _machines;
    private readonly PeopleStore _people;
    private readonly TeamSettingsStore _settings;
    private readonly Func<IReadOnlyList<string>> _pairedDevices;

    /// <summary>Creates the switch over this person's stores.</summary>
    /// <param name="machines">Their answers about whose each machine is.</param>
    /// <param name="people">Their grouping of machines into people.</param>
    /// <param name="settings">Their team settings.</param>
    /// <param name="pairedDevices">
    /// The device IDs paired with any folder here, read fresh each decision, so removing a
    /// machine from its last folder takes it out of the team at once.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public TeamFeatures(
        KnownMachines machines,
        PeopleStore people,
        TeamSettingsStore settings,
        Func<IReadOnlyList<string>> pairedDevices)
    {
        ArgumentNullException.ThrowIfNull(machines);
        ArgumentNullException.ThrowIfNull(people);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(pairedDevices);

        _machines = machines;
        _people = people;
        _settings = settings;
        _pairedDevices = pairedDevices;
    }

    /// <summary>The switch over this user's own files.</summary>
    /// <param name="pairedDevices">The device IDs paired with any folder here.</param>
    /// <returns>The switch.</returns>
    public static TeamFeatures ForThisUser(Func<IReadOnlyList<string>> pairedDevices) =>
        new(KnownMachines.ForThisUser(), PeopleStore.ForThisUser(), TeamSettingsStore.ForThisUser(), pairedDevices);

    /// <summary>Whether team features are on now. What the daemon's checks call.</summary>
    /// <returns>True when a team exists.</returns>
    public bool On() => Decide().On;

    /// <summary>Decides the switch, with the count and the reason.</summary>
    /// <returns>The decision.</returns>
    public TeamDecision Decide()
    {
        IReadOnlyList<KnownMachine> answers;
        IReadOnlyList<Person> people;
        TeamSettings settings;
        try
        {
            answers = _machines.Load();
            people = _people.Load();
            settings = _settings.Load();
        }
        catch (JsonException ex)
        {
            return new TeamDecision(false, 1, [], false, $"Team features are off: {ex.Message}");
        }

        var others = new List<string>();
        var countedPeople = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var deviceId in _pairedDevices())
        {
            if (KnownMachines.Find(answers, deviceId)?.Owner != MachineOwner.SomeoneElse)
            {
                continue;
            }

            if (PeopleStore.PersonOf(people, deviceId) is { } person)
            {
                if (countedPeople.Add(person.Key))
                {
                    others.Add(person.Name);
                }
            }
            else if (countedPeople.Add(PeopleStore.SoleScope(deviceId).Key))
            {
                var name = KnownMachines.Find(answers, deviceId)?.Name;
                others.Add(name is null ? $"the machine {Short(deviceId)}" : $"{name} (one machine, not grouped)");
            }
        }

        var count = 1 + countedPeople.Count;
        var on = count >= 3 || (count == 2 && settings.TwoPersonException);

        var why = on
            ? count >= 3
                ? string.Create(CultureInfo.InvariantCulture, $"Team features are on: {count} people.")
                : "Team features are on: 2 people, by your exception ('sip team exception')."
            : count == 2
                ? "Team features are off: a team is 3 people, and you are 2. 'sip team exception on' allows 2."
                : "Team features are off: no one else's machine is paired and answered about.";

        return new TeamDecision(on, count, others, settings.TwoPersonException, why);
    }

    private static string Short(string deviceId) => deviceId.Length > 12 ? deviceId[..12] : deviceId;
}
