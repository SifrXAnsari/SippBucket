using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Hashing;
using SippBucket.Core.Machines;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Push;

/// <summary>One time a quarantined file arrived: who sent it, as what, and why it is here.</summary>
public sealed record QuarantineArrival
{
    /// <summary>When it arrived.</summary>
    public required DateTimeOffset ArrivedUtc { get; init; }

    /// <summary>The sending machine's device ID.</summary>
    public required string SenderDeviceId { get; init; }

    /// <summary>The name this machine knows the sender by.</summary>
    public required string SenderName { get; init; }

    /// <summary>Whose machine the sender is, as answered when it arrived.</summary>
    public required MachineOwner SenderOwner { get; init; }

    /// <summary>The name it was sent with.</summary>
    public required string SentName { get; init; }

    /// <summary>Why it was quarantined.</summary>
    public required QuarantineReason Reason { get; init; }

    /// <summary>What its content is, as the engine's type number.</summary>
    public required uint DetectedType { get; init; }

    /// <summary>What its name claimed, as the engine's type number.</summary>
    public required uint ClaimedType { get; init; }
}

/// <summary>The record kept beside one quarantined file.</summary>
public sealed record QuarantineRecord
{
    /// <summary>The schema it was written in.</summary>
    public int Schema { get; init; } = Quarantine.CurrentSchema;

    /// <summary>The BLAKE2b-256 of the content, which is also the file's name.</summary>
    public required ContentHash Hash { get; init; }

    /// <summary>The content's length in bytes.</summary>
    public required long Size { get; init; }

    /// <summary>Every time this content arrived, oldest first. Never empty.</summary>
    public required IReadOnlyList<QuarantineArrival> Arrivals { get; init; }

    /// <summary>
    /// When SippBucket found the file gone without having removed it: removed by something else
    /// on this machine, most likely its antivirus. Null while it is here.
    /// </summary>
    public DateTimeOffset? RemovedUtc { get; init; }
}

/// <summary>One quarantined file, as listed.</summary>
/// <param name="Record">Its record.</param>
/// <param name="Present">Whether the file is still here, rather than removed by something else.</param>
public sealed record QuarantineItem(QuarantineRecord Record, bool Present)
{
    /// <summary>The first arrival, which names the file wherever one name is needed.</summary>
    public QuarantineArrival First => Record.Arrivals[0];

    /// <summary>
    /// Whether it was quarantined as a program: for its content, or for a name Windows would run.
    /// Releasing one needs the person's explicit confirmation.
    /// </summary>
    public bool IsProgram => Record.Arrivals.Any(
        arrival => arrival.Reason is QuarantineReason.ExecutableContent or QuarantineReason.ExecutableName);
}

/// <summary>What listing the quarantine found.</summary>
/// <param name="Items">The quarantined files, oldest first.</param>
/// <param name="UnreadableRecords">The records that could not be read, by file name, for the person to look at.</param>
public sealed record QuarantineList(IReadOnlyList<QuarantineItem> Items, IReadOnlyList<string> UnreadableRecords);

/// <summary>How a file comes back out of quarantine.</summary>
public enum ReleaseName
{
    /// <summary>Under the name its content matches: the name it was sent with, with its content's extension.</summary>
    AsDetected,

    /// <summary>Under the name it was sent with.</summary>
    AsSent,
}

/// <summary>What asking to release or delete a quarantined file did.</summary>
public enum QuarantineActionOutcome
{
    /// <summary>Done.</summary>
    Done,

    /// <summary>Nothing in quarantine matches.</summary>
    NotFound,

    /// <summary>More than one file matches; nothing was done.</summary>
    Ambiguous,

    /// <summary>It is a program, and releasing it needs the person's explicit confirmation; nothing was done.</summary>
    NeedsConfirmation,

    /// <summary>Its content has no single right extension to release it under; nothing was done.</summary>
    NoDetectedExtension,

    /// <summary>The file is gone: something else on this machine removed it. Only its record can be deleted.</summary>
    Removed,
}

/// <summary>The result of <see cref="Quarantine.Release"/> or <see cref="Quarantine.Delete"/>.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Message">What happened, for the person.</param>
/// <param name="PlacedName">The name a released file was placed under in the inbox; null otherwise.</param>
/// <param name="Candidates">The files an ambiguous request matched; empty otherwise.</param>
public sealed record QuarantineAction(
    QuarantineActionOutcome Outcome,
    string Message,
    string? PlacedName,
    IReadOnlyList<QuarantineItem> Candidates);

/// <summary>What became of a file handed to the quarantine.</summary>
internal enum QuarantineAdd
{
    /// <summary>It is in quarantine now.</summary>
    Added,

    /// <summary>The same content was already there; this arrival was added to its record.</summary>
    AlreadyHeld,

    /// <summary>The quarantine has no room for it; it was deleted.</summary>
    OverCap,
}

/// <summary>
/// The quarantine: the spam folder under the inbox, where a disguised file or a program waits for
/// the person to look and decide (docs/DIRECT-PUSH.md, "Quarantine").
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing in it can run.</b> Each file is stored under a neutral name, its content's hash
/// with <c>.quarantine</c> after it, which no program is registered to open, beside a record
/// (<c>&lt;hash&gt;.json</c>) of every time it arrived: its name, its sender, when, why and what
/// its content is. The same content arriving again is kept once, and its record gains the arrival.
/// </para>
/// <para>
/// <b>Stored as it arrived, never encrypted</b>, so the antivirus sees it exactly as it is. An
/// encrypted store would hide malware from the antivirus, which is the interference this project
/// rules out. If the antivirus removes a file here, that is it doing its job, and the record says
/// so the next time the quarantine is listed.
/// </para>
/// <para>
/// <b>Nothing leaves it automatically.</b> No rule applies here, nothing is purged on a timer, and
/// there is no code path out of quarantine but <see cref="Release"/> and <see cref="Delete"/>, each
/// on the person's request. A program comes out only when the person has confirmed they know it is
/// one. <see cref="Delete"/> is permanent.
/// </para>
/// </remarks>
public sealed class Quarantine
{
    /// <summary>The extension a quarantined file is stored under.</summary>
    public const string ContentExtension = ".quarantine";

    /// <summary>The schema records are written in.</summary>
    public const int CurrentSchema = 1;

    /// <summary>The shortest hash prefix that names a quarantined file, as for a device ID.</summary>
    public const int MinimumPrefixLength = 8;

    private const string RecordExtension = ".json";

    private readonly PushInbox _inbox;

    internal Quarantine(string folder, PushInbox inbox)
    {
        Folder = folder;
        _inbox = inbox;
    }

    /// <summary>The quarantine's folder.</summary>
    public string Folder { get; }

    /// <summary>How much the files in quarantine take, in bytes.</summary>
    /// <returns>The total length of every quarantined file present.</returns>
    public long UsedBytes()
    {
        if (!Directory.Exists(Folder))
        {
            return 0;
        }

        return new DirectoryInfo(Folder)
            .EnumerateFiles("*" + ContentExtension)
            .Sum(file => file.Length);
    }

    /// <summary>Lists the quarantine, recording any file something else removed.</summary>
    /// <param name="nowUtc">The time to record a removal at.</param>
    /// <returns>Every quarantined file, and every record that could not be read.</returns>
    /// <exception cref="IOException">The inbox's lock stayed held, or the folder could not be read.</exception>
    public QuarantineList List(DateTimeOffset nowUtc)
    {
        // An inbox that has never received anything has no quarantine, and nothing to lock.
        if (!Directory.Exists(Folder))
        {
            return new QuarantineList([], []);
        }

        using (_inbox.Lock())
        {
            return ListLocked(nowUtc);
        }
    }

    /// <summary>Brings a quarantined file back into the inbox, on the person's request.</summary>
    /// <param name="hashOrPrefix">The file's hash, or at least <see cref="MinimumPrefixLength"/> characters of it.</param>
    /// <param name="name">Which name it comes back under.</param>
    /// <param name="programConfirmed">
    /// Whether the person has confirmed, after the warning, that they want a program out. Required
    /// for a file quarantined as a program; ignored otherwise.
    /// </param>
    /// <param name="nowUtc">The time to record.</param>
    /// <returns>What happened.</returns>
    /// <exception cref="IOException">The inbox's lock stayed held, or the file could not be moved.</exception>
    public QuarantineAction Release(string hashOrPrefix, ReleaseName name, bool programConfirmed, DateTimeOffset nowUtc)
    {
        if (!Directory.Exists(Folder))
        {
            return Empty(hashOrPrefix);
        }

        using (_inbox.Lock())
        {
            var (item, refusal) = FindLocked(hashOrPrefix, nowUtc);
            if (item is null)
            {
                return refusal!;
            }

            if (!item.Present)
            {
                return new QuarantineAction(
                    QuarantineActionOutcome.Removed,
                    "The file is no longer on this machine: something other than SippBucket, most likely its antivirus, " +
                    "removed it. Its record can be deleted.",
                    null,
                    []);
            }

            if (item.IsProgram && !programConfirmed)
            {
                return new QuarantineAction(
                    QuarantineActionOutcome.NeedsConfirmation,
                    ProgramWarning(item),
                    null,
                    []);
            }

            var releaseAs = NameFor(item, name);
            if (releaseAs is null)
            {
                return new QuarantineAction(
                    QuarantineActionOutcome.NoDetectedExtension,
                    $"Its content ({ContentTypes.NameOf(item.First.DetectedType)}) has no single right extension to release it " +
                    "under. Release it under the name it was sent with instead.",
                    null,
                    []);
            }

            var placed = _inbox.Place(ContentPath(item.Record.Hash), releaseAs);
            DeleteRecord(item.Record.Hash);

            _inbox.Record(new InboxEntry
            {
                ArrivedUtc = nowUtc,
                SenderDeviceId = item.First.SenderDeviceId,
                SenderName = item.First.SenderName,
                SenderOwner = item.First.SenderOwner,
                SentName = item.First.SentName,
                PlacedName = placed,
                Size = item.Record.Size,
                Hash = item.Record.Hash,
                DetectedType = item.First.DetectedType,
                ReleasedFromQuarantine = true,
            });

            return new QuarantineAction(
                QuarantineActionOutcome.Done,
                $"Released '{item.First.SentName}' into the inbox as '{placed}'.",
                placed,
                []);
        }
    }

    /// <summary>Deletes a quarantined file and its record, permanently, on the person's request.</summary>
    /// <param name="hashOrPrefix">The file's hash, or at least <see cref="MinimumPrefixLength"/> characters of it.</param>
    /// <param name="nowUtc">The time, for recording a removal found on the way.</param>
    /// <returns>What happened.</returns>
    /// <exception cref="IOException">The inbox's lock stayed held, or the file could not be deleted.</exception>
    public QuarantineAction Delete(string hashOrPrefix, DateTimeOffset nowUtc)
    {
        if (!Directory.Exists(Folder))
        {
            return Empty(hashOrPrefix);
        }

        using (_inbox.Lock())
        {
            var (item, refusal) = FindLocked(hashOrPrefix, nowUtc);
            if (item is null)
            {
                return refusal!;
            }

            var content = ContentPath(item.Record.Hash);
            if (File.Exists(content))
            {
                SharingRetry.Run(() => File.Delete(content));
            }

            DeleteRecord(item.Record.Hash);

            return new QuarantineAction(
                QuarantineActionOutcome.Done,
                item.Present
                    ? $"Deleted '{item.First.SentName}' from quarantine, permanently."
                    : $"Deleted the record of '{item.First.SentName}'; the file itself was already gone.",
                null,
                []);
        }
    }

    /// <summary>
    /// Takes a checked file into quarantine, or adds an arrival to the record of the same content.
    /// The caller holds the inbox's lock.
    /// </summary>
    /// <param name="staged">The staged file. Moved in, or deleted.</param>
    /// <param name="hash">Its content's hash, already verified.</param>
    /// <param name="size">Its length.</param>
    /// <param name="arrival">This arrival.</param>
    /// <param name="capBytes">The most the quarantine may hold.</param>
    /// <returns>What became of it.</returns>
    /// <exception cref="FileNotFoundException">The staged file is gone: something removed it on arrival.</exception>
    internal QuarantineAdd Add(string staged, ContentHash hash, long size, QuarantineArrival arrival, long capBytes)
    {
        Directory.CreateDirectory(Folder);

        var content = ContentPath(hash);
        var existing = TryReadRecord(RecordPath(hash), out _);

        if (File.Exists(content))
        {
            // The same content is already here, whether or not its record survived.
            SharingRetry.Run(() => File.Delete(staged));
            WriteRecord(Arrive(existing, hash, size, arrival));
            return existing is null ? QuarantineAdd.Added : QuarantineAdd.AlreadyHeld;
        }

        if (UsedBytes() + size > capBytes)
        {
            SharingRetry.Run(() => File.Delete(staged));
            return QuarantineAdd.OverCap;
        }

        SharingRetry.Run(() => File.Move(staged, content, overwrite: false));
        WriteRecord(Arrive(existing, hash, size, arrival));
        return QuarantineAdd.Added;
    }

    /// <summary>
    /// How much of the quarantine one sender's files take: those it sent first that are still here.
    /// </summary>
    /// <param name="deviceId">The sender.</param>
    /// <returns>Bytes.</returns>
    internal long SpaceFirstSentBy(string deviceId)
    {
        if (!Directory.Exists(Folder))
        {
            return 0;
        }

        long used = 0;
        foreach (var path in Directory.EnumerateFiles(Folder, "*" + RecordExtension))
        {
            if (TryReadRecord(path, out _) is { } record &&
                string.Equals(record.Arrivals[0].SenderDeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                File.Exists(ContentPath(record.Hash)))
            {
                used += record.Size;
            }
        }

        return used;
    }

    private static QuarantineAction Empty(string hashOrPrefix) =>
        new(QuarantineActionOutcome.NotFound, $"Nothing in quarantine matches '{hashOrPrefix}': it is empty.", null, []);

    private static QuarantineRecord Arrive(QuarantineRecord? existing, ContentHash hash, long size, QuarantineArrival arrival) =>
        existing is null
            ? new QuarantineRecord { Hash = hash, Size = size, Arrivals = [arrival] }
            : existing with { Arrivals = [.. existing.Arrivals, arrival], RemovedUtc = null };

    private static string? NameFor(QuarantineItem item, ReleaseName name)
    {
        var sent = item.First.SentName;
        if (name == ReleaseName.AsSent)
        {
            return sent;
        }

        var extension = ContentTypes.ExtensionOf(item.First.DetectedType);
        return extension.Length == 0 ? null : Path.GetFileNameWithoutExtension(sent) + "." + extension;
    }

    private static string ProgramWarning(QuarantineItem item) =>
        $"'{item.First.SentName}' is a program ({ContentTypes.NameOf(item.First.DetectedType)}), or has a name Windows " +
        "would run. Released, it can do anything you can do on this machine: read, change or delete your files, and " +
        "send them anywhere. Release it only if you know who made it and you meant to receive it. Nothing was released.";

    /// <summary>
    /// Lists the quarantine without changing anything: a removal is shown, not recorded. For
    /// <c>sip status</c> and <c>sip doctor</c>, which only read.
    /// </summary>
    /// <returns>Every quarantined file, and every record that could not be read.</returns>
    /// <remarks>
    /// Takes no lock, since the lock file itself would have to be created: every record is written
    /// whole, beside itself, so a reader always finds one whole record or the other.
    /// </remarks>
    public QuarantineList Inspect() => ReadAll(recordRemovalsAt: null);

    private QuarantineList ListLocked(DateTimeOffset nowUtc) => ReadAll(recordRemovalsAt: nowUtc);

    private QuarantineList ReadAll(DateTimeOffset? recordRemovalsAt)
    {
        if (!Directory.Exists(Folder))
        {
            return new QuarantineList([], []);
        }

        var items = new List<QuarantineItem>();
        var unreadable = new List<string>();

        foreach (var path in Directory.EnumerateFiles(Folder, "*" + RecordExtension))
        {
            var record = TryReadRecord(path, out var damaged);
            if (record is null)
            {
                if (damaged)
                {
                    unreadable.Add(Path.GetFileName(path));
                }

                continue;
            }

            var present = File.Exists(ContentPath(record.Hash));
            if (!present && record.RemovedUtc is null && recordRemovalsAt is { } nowUtc)
            {
                // Something other than SippBucket removed it: the antivirus, doing its job.
                record = record with { RemovedUtc = nowUtc };
                WriteRecord(record);
            }

            items.Add(new QuarantineItem(record, present));
        }

        return new QuarantineList([.. items.OrderBy(item => item.First.ArrivedUtc)], unreadable);
    }

    private (QuarantineItem? Item, QuarantineAction? Refusal) FindLocked(string hashOrPrefix, DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hashOrPrefix);

        if (hashOrPrefix.Length < MinimumPrefixLength || !hashOrPrefix.All(char.IsAsciiHexDigit))
        {
            return (null, new QuarantineAction(
                QuarantineActionOutcome.NotFound,
                $"Name a quarantined file by its hash, or at least its first {MinimumPrefixLength} characters, as " +
                "'sip quarantine' lists them.",
                null,
                []));
        }

        var matches = ListLocked(nowUtc).Items
            .Where(item => item.Record.Hash.ToString().StartsWith(hashOrPrefix, StringComparison.OrdinalIgnoreCase))
            .ToList();

        return matches.Count switch
        {
            0 => (null, new QuarantineAction(QuarantineActionOutcome.NotFound, $"Nothing in quarantine matches '{hashOrPrefix}'.", null, [])),
            1 => (matches[0], null),
            _ => (null, new QuarantineAction(
                QuarantineActionOutcome.Ambiguous,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{hashOrPrefix}' matches {matches.Count} files in quarantine; give more of the hash. Nothing was done."),
                null,
                matches)),
        };
    }

    private string ContentPath(ContentHash hash) => Path.Combine(Folder, hash + ContentExtension);

    private string RecordPath(ContentHash hash) => Path.Combine(Folder, hash + RecordExtension);

    private void DeleteRecord(ContentHash hash)
    {
        var record = RecordPath(hash);
        if (File.Exists(record))
        {
            SharingRetry.Run(() => File.Delete(record));
        }
    }

    /// <summary>Reads a record, or null when there is none or it cannot be read.</summary>
    /// <param name="path">The record's path.</param>
    /// <param name="damaged">True when the file is there and cannot be read as a record.</param>
    private static QuarantineRecord? TryReadRecord(string path, out bool damaged)
    {
        damaged = false;

        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        try
        {
            var record = JsonSerializer.Deserialize<QuarantineRecord>(json, SipJson.Readable);
            if (record is { Arrivals.Count: > 0 } && record.Schema <= CurrentSchema &&
                string.Equals(Path.GetFileNameWithoutExtension(path), record.Hash.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                return record;
            }
        }
        catch (JsonException)
        {
            // Reported below as damaged.
        }

        damaged = true;
        return null;
    }

    private void WriteRecord(QuarantineRecord record)
    {
        var path = RecordPath(record.Hash);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(record, SipJson.Readable);

        // Written beside it and swapped in whole, so a record is always the old one or the new one.
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);

            if (File.Exists(path))
            {
                SharingRetry.Run(() => File.Replace(temporary, path, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, path));
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
