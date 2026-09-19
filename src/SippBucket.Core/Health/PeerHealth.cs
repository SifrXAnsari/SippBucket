using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Health;

/// <summary>How a server is named in an alert or a listing.</summary>
/// <param name="Display">"Server 2 (Dell Inspiron 15 3511)" for the person's own machines; the name they gave another person's.</param>
/// <param name="ServerId">The <c>Server.ID#XXX-XXX-XXX</c>, for the person's own machines only; never another person's.</param>
public sealed record ServerNaming(string Display, string? ServerId);

/// <summary>How often one server was seen to commit one kind of fault.</summary>
public sealed record FaultTally
{
    /// <summary>The fault.</summary>
    public required HealthFault Fault { get; init; }

    /// <summary>How many times, ever.</summary>
    public int Count { get; init; }

    /// <summary>The first time.</summary>
    public DateTimeOffset First { get; init; }

    /// <summary>The latest time.</summary>
    public DateTimeOffset Last { get; init; }

    /// <summary>The times within the last day, for the day's count.</summary>
    public IReadOnlyList<DateTimeOffset> Recent { get; init; } = [];

    /// <summary>When the day's count last raised an alert.</summary>
    public DateTimeOffset? Alerted { get; init; }
}

/// <summary>One fault, in detail.</summary>
public sealed record HealthEvent
{
    /// <summary>When it was seen, in UTC.</summary>
    public required DateTimeOffset Utc { get; init; }

    /// <summary>The fault.</summary>
    public required HealthFault Fault { get; init; }

    /// <summary>What exactly was seen.</summary>
    public required string Detail { get; init; }

    /// <summary>The folder it happened in, when it happened in one.</summary>
    public string? Folder { get; init; }
}

/// <summary>What a server last said about itself, and what was found wrong with it: weak evidence.</summary>
public sealed record SelfReportCheck
{
    /// <summary>When the report was compared.</summary>
    public required DateTimeOffset Utc { get; init; }

    /// <summary>What was outside the safe ranges; empty when nothing was.</summary>
    public required IReadOnlyList<string> Findings { get; init; }
}

/// <summary>A server the person said sent a change that was not them.</summary>
public sealed record SuspectMark
{
    /// <summary>Since when.</summary>
    public required DateTimeOffset Since { get; init; }

    /// <summary>Why, in a sentence.</summary>
    public required string Reason { get; init; }

    /// <summary>The alert the person answered, when the mark came from one.</summary>
    public int? Alert { get; init; }
}

/// <summary>Everything this machine has seen one install do, and what that install said about itself.</summary>
public sealed record PeerHealthRecord
{
    /// <summary>The install, by device ID: the identity its handshakes proved.</summary>
    public required string Device { get; init; }

    /// <summary>A tally for each kind of fault seen.</summary>
    public IReadOnlyList<FaultTally> Faults { get; init; } = [];

    /// <summary>The latest faults, in detail, newest last.</summary>
    public IReadOnlyList<HealthEvent> Events { get; init; } = [];

    /// <summary>The latest comparison of what it says about itself: weak evidence.</summary>
    public SelfReportCheck? Report { get; init; }

    /// <summary>Set while the person has said a change from it was not them.</summary>
    public SuspectMark? Suspect { get; init; }
}

/// <summary>
/// Each server's health record, kept by this machine: what the others were seen to do, and
/// what they said about themselves, in <c>health.json</c> beside the device key
/// (docs/PEER-HEALTH.md).
/// </summary>
/// <remarks>
/// <para>
/// <b>Two kinds of evidence, never mixed.</b> What a server does is strong evidence, and each
/// fault is tallied here; one bad block is probably a disk error, and a day's worth reaching
/// <see cref="HealthSettings.FaultsPerDay"/> raises an alert in the permanent log. What a
/// server says about itself is weak evidence, kept apart in <see cref="PeerHealthRecord.Report"/>
/// and never alerted: it catches honest misconfiguration, and a hacked machine can lie.
/// </para>
/// <para>
/// <b>Guidance, not authority.</b> The record can report, and a suspect mark stops this machine
/// taking changes from one install; it can never fix, disable or judge another machine, and a
/// suspect install never stops the others syncing with each other.
/// </para>
/// <para>
/// Kept by install (device ID), the identity a handshake proves; listings group the installs
/// of one board under their server. Changed under a file lock, as <c>servers.json</c> is.
/// </para>
/// </remarks>
public sealed class PeerHealth
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "health.json";

    /// <summary>The schema this build writes.</summary>
    public const int CurrentSchema = 1;

    /// <summary>How many faults each install keeps in detail.</summary>
    public const int EventsKept = 50;

    /// <summary>The longest a detail is kept.</summary>
    public const int LongestDetail = 400;

    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan Day = TimeSpan.FromDays(1);

    private readonly string _path;
    private readonly object _gate;
    private readonly AlertLog _alerts;

    /// <summary>Creates a store over a file.</summary>
    /// <param name="path">Full path to <c>health.json</c>.</param>
    /// <param name="alerts">The permanent log alerts go to.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public PeerHealth(string path, AlertLog alerts)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(alerts);

        _path = Path.GetFullPath(path);
        _gate = Gates.GetOrAdd(_path, static _ => new object());
        _alerts = alerts;
    }

    /// <summary>The store for the person running this process, with their alerts log.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static PeerHealth ForThisUser() =>
        new(Path.Combine(UserDataDirectory.Resolve(), FileName), AlertLog.ForThisUser());

    /// <summary>The file this store reads and writes.</summary>
    public string FilePath => _path;

    /// <summary>The permanent log alerts go to.</summary>
    public AlertLog Alerts => _alerts;

    /// <summary>Every install's record.</summary>
    /// <returns>The records, empty when there is no file yet.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public IReadOnlyList<PeerHealthRecord> Load()
    {
        lock (_gate)
        {
            return Read().Peers;
        }
    }

    /// <summary>Whether the person said a change from this install was not them, and has not cleared it.</summary>
    /// <param name="device">The install.</param>
    /// <returns>True while it is marked suspect.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public bool IsSuspect(string device) => Find(Load(), device)?.Suspect is not null;

    /// <summary>Records one fault, and raises an alert when the day's count reaches the threshold.</summary>
    /// <param name="device">The install it came from.</param>
    /// <param name="naming">How to name its server in an alert.</param>
    /// <param name="fault">The fault.</param>
    /// <param name="detail">What exactly was seen.</param>
    /// <param name="folder">The folder it happened in, or null.</param>
    /// <param name="settings">The thresholds.</param>
    /// <param name="nowUtc">When.</param>
    /// <returns>The alert raised, or null.</returns>
    /// <exception cref="JsonException">The file cannot be read, so nothing was recorded.</exception>
    /// <exception cref="IOException">The file lock could not be taken, or a file written.</exception>
    /// <remarks>
    /// An alert for one kind of fault from one install is raised at most once a day, however
    /// many more arrive: the log is for the person to read, and a line per fault would bury the
    /// one that matters. Every fault is still counted and kept.
    /// </remarks>
    public Alert? Record(
        string device,
        ServerNaming naming,
        HealthFault fault,
        string detail,
        string? folder,
        HealthSettings settings,
        DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(device);
        ArgumentNullException.ThrowIfNull(naming);
        ArgumentNullException.ThrowIfNull(detail);
        ArgumentNullException.ThrowIfNull(settings);

        lock (_gate)
        {
            using var held = Lock();
            var stored = Read();
            var peers = stored.Peers.ToList();
            var record = Find(peers, device) ?? new PeerHealthRecord { Device = device };

            var tallies = record.Faults.ToList();
            var at = tallies.FindIndex(tally => tally.Fault == fault);
            var tally = at < 0 ? new FaultTally { Fault = fault, First = nowUtc } : tallies[at];
            var recent = tally.Recent.Where(when => nowUtc - when < Day).Append(nowUtc).TakeLast(1000).ToList();
            tally = tally with { Count = tally.Count + 1, Last = nowUtc, Recent = recent };

            Alert? raised = null;
            if (HealthFaults.IsAlerted(fault) &&
                recent.Count >= settings.FaultsPerDay &&
                (tally.Alerted is not { } last || nowUtc - last >= Day))
            {
                raised = _alerts.Raise(new Alert
                {
                    Id = 0,
                    Utc = nowUtc,
                    Kind = AlertKind.Faults,
                    Server = naming.Display,
                    ServerId = naming.ServerId,
                    Device = device,
                    What = string.Create(
                        CultureInfo.InvariantCulture,
                        $"{naming.Display} sent {recent.Count} {HealthFaults.Describe(fault)} in the last day. The latest: {Shorten(detail)}"),
                    Done = DoneFor(fault),
                    Folder = folder,
                });
                tally = tally with { Alerted = nowUtc };
            }

            if (at < 0)
            {
                tallies.Add(tally);
            }
            else
            {
                tallies[at] = tally;
            }

            var events = record.Events
                .Append(new HealthEvent { Utc = nowUtc, Fault = fault, Detail = Shorten(detail), Folder = folder })
                .TakeLast(EventsKept)
                .ToList();

            Replace(peers, record with { Faults = tallies, Events = events });
            Write(stored with { Peers = peers });
            return raised;
        }
    }

    /// <summary>Records what an install said about itself, compared with the safe ranges: weak evidence.</summary>
    /// <param name="device">The install.</param>
    /// <param name="findings">What was outside the safe ranges; empty when nothing was.</param>
    /// <param name="nowUtc">When.</param>
    /// <exception cref="JsonException">The file cannot be read, so nothing was recorded.</exception>
    /// <exception cref="IOException">The file lock could not be taken, or the file written.</exception>
    public void RecordReport(string device, IReadOnlyList<string> findings, DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(device);
        ArgumentNullException.ThrowIfNull(findings);

        lock (_gate)
        {
            using var held = Lock();
            var stored = Read();
            var peers = stored.Peers.ToList();
            var record = Find(peers, device) ?? new PeerHealthRecord { Device = device };

            // Written only when the findings change, so a healthy machine's every poll costs no write.
            if (record.Report is { } previous && previous.Findings.SequenceEqual(findings, StringComparer.Ordinal))
            {
                return;
            }

            Replace(peers, record with { Report = new SelfReportCheck { Utc = nowUtc, Findings = [.. findings.Select(Shorten)] } });
            Write(stored with { Peers = peers });
        }
    }

    /// <summary>Marks an install suspect: this machine stops taking its changes until the person clears it.</summary>
    /// <param name="device">The install.</param>
    /// <param name="reason">Why, in a sentence.</param>
    /// <param name="alert">The alert the person answered, or null.</param>
    /// <param name="nowUtc">When.</param>
    /// <exception cref="JsonException">The file cannot be read, so nothing was recorded.</exception>
    /// <exception cref="IOException">The file lock could not be taken, or the file written.</exception>
    public void MarkSuspect(string device, string reason, int? alert, DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(device);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        lock (_gate)
        {
            using var held = Lock();
            var stored = Read();
            var peers = stored.Peers.ToList();
            var record = Find(peers, device) ?? new PeerHealthRecord { Device = device };

            Replace(peers, record with { Suspect = new SuspectMark { Since = nowUtc, Reason = reason, Alert = alert } });
            Write(stored with { Peers = peers });
        }
    }

    /// <summary>Clears a suspect mark: this machine takes the install's changes again.</summary>
    /// <param name="device">The install.</param>
    /// <returns>The mark that was cleared, or null when it was not marked.</returns>
    /// <exception cref="JsonException">The file cannot be read, so nothing was changed.</exception>
    /// <exception cref="IOException">The file lock could not be taken, or the file written.</exception>
    public SuspectMark? ClearSuspect(string device)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(device);

        lock (_gate)
        {
            using var held = Lock();
            var stored = Read();
            var peers = stored.Peers.ToList();
            if (Find(peers, device) is not { Suspect: { } mark } record)
            {
                return null;
            }

            Replace(peers, record with { Suspect = null });
            Write(stored with { Peers = peers });
            return mark;
        }
    }

    /// <summary>One install's record in a list, matched ignoring case.</summary>
    /// <param name="peers">The records.</param>
    /// <param name="device">The install.</param>
    /// <returns>Its record, or null.</returns>
    public static PeerHealthRecord? Find(IReadOnlyList<PeerHealthRecord> peers, string device)
    {
        ArgumentNullException.ThrowIfNull(peers);
        return peers.FirstOrDefault(peer => string.Equals(peer.Device, device, StringComparison.OrdinalIgnoreCase));
    }

    private static string DoneFor(HealthFault fault) => fault switch
    {
        HealthFault.QuarantinedPush =>
            "Each file went to quarantine, where it stays until you release or delete it. Direct Push from it goes on, and so does the count.",
        HealthFault.Stall or HealthFault.HandshakeFailure =>
            "Each connection was given up on and tried again at the next poll. Nothing it sent was applied part way.",
        _ =>
            "Each was refused, and nothing it carried was applied. It is still synced with, and still counted; " +
            "'sip peer health' has the whole record.",
    };

    /// <summary>
    /// A detail as it is kept: made safe to show, and cut to <see cref="LongestDetail"/>. A detail
    /// can carry a peer's own words, such as the reason it gave for a refusal, and the log and the
    /// listings print it where a control character is an instruction (<see cref="DisplayText"/>).
    /// </summary>
    private static string Shorten(string text) => DisplayText.Printable(text, LongestDetail);

    private static void Replace(List<PeerHealthRecord> peers, PeerHealthRecord record)
    {
        var at = peers.FindIndex(peer => string.Equals(peer.Device, record.Device, StringComparison.OrdinalIgnoreCase));
        if (at < 0)
        {
            peers.Add(record);
        }
        else
        {
            peers[at] = record;
        }
    }

    private FileLock Lock()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path) ?? throw new IOException($"{_path} has no folder."));
        return FileLock.Acquire(_path + ".lock", FileLock.DefaultPatience);
    }

    private StoredHealth Read()
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(_path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new StoredHealth(CurrentSchema, []);
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return new StoredHealth(CurrentSchema, []);
        }

        StoredHealth? file;
        try
        {
            file = JsonSerializer.Deserialize<StoredHealth>(json, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new JsonException(
                $"{_path} cannot be read ({ex.Message}). Until it is mended or deleted, faults are not counted " +
                "and nothing is written to it; syncing is not affected, and every refusal still happens.",
                ex);
        }

        if (file?.Peers is null)
        {
            throw new JsonException(
                $"{_path} holds no list of records. Until it is mended or deleted, faults are not counted " +
                "and nothing is written to it; syncing is not affected, and every refusal still happens.");
        }

        if (file.Schema > CurrentSchema)
        {
            throw new JsonException(
                $"{_path} was written by a newer SippBucket (schema {file.Schema.ToString(CultureInfo.InvariantCulture)}), " +
                "which this one would lose information from by rewriting it. Update SippBucket; until then faults " +
                "are not counted here.");
        }

        return file;
    }

    private void Write(StoredHealth stored)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(stored with { Schema = CurrentSchema }, SipJson.Readable);
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

    /// <summary><c>health.json</c> as stored.</summary>
    /// <param name="Schema">The schema it was written in.</param>
    /// <param name="Peers">One record per install.</param>
    private sealed record StoredHealth(int Schema, IReadOnlyList<PeerHealthRecord> Peers);
}
