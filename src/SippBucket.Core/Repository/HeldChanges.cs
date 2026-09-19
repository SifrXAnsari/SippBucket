using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>The person's answer to a held change.</summary>
public enum HeldAnswer
{
    /// <summary>Not answered yet: the change stays held.</summary>
    Unanswered,

    /// <summary>"That was me": the change is applied at the next sync with the server that sent it.</summary>
    ThatWasMe,

    /// <summary>"Not me — keep them out": the change stays held for good, and the server is suspect.</summary>
    NotMe,
}

/// <summary>One change peer health held instead of applying.</summary>
public sealed record HeldChange
{
    /// <summary>The newest snapshot held from this server: the one an answer applies to.</summary>
    public required ContentHash Snapshot { get; init; }

    /// <summary>Snapshots held from it earlier, while this was unanswered, which the newest supersedes.</summary>
    public IReadOnlyList<ContentHash> Earlier { get; init; } = [];

    /// <summary>The install that sent it.</summary>
    public required string Device { get; init; }

    /// <summary>How the server was named when it was held.</summary>
    public required string Server { get; init; }

    /// <summary>When it was first held.</summary>
    public required DateTimeOffset HeldUtc { get; init; }

    /// <summary>What was seen, in a sentence.</summary>
    public required string What { get; init; }

    /// <summary>The alert that asks about it, once raised.</summary>
    public int? Alert { get; init; }

    /// <summary>The person's answer.</summary>
    public HeldAnswer Answer { get; init; }

    /// <summary>When the person answered.</summary>
    public DateTimeOffset? AnsweredUtc { get; init; }

    /// <summary>When an approved change was applied here, which closes it.</summary>
    public DateTimeOffset? AppliedUtc { get; init; }

    /// <summary>Whether it is settled: applied, or refused for good.</summary>
    [JsonIgnore]
    public bool IsClosed => AppliedUtc is not null || Answer == HeldAnswer.NotMe;
}

/// <summary>
/// The changes peer health held in one folder instead of applying, in <c>.sip/held.json</c>,
/// with a copy of each held snapshot in <c>.sip/held</c> (docs/PEER-HEALTH.md).
/// </summary>
/// <remarks>
/// <para>
/// <b>Kept, never applied and never deleted, until the person answers.</b> A held snapshot is
/// copied out of the snapshot store, so that no trim of history in Simple mode removes it and no
/// peer is ever offered it, and its blocks count as in use, so no collection sweeps them
/// (<see cref="SipRepository.CollectAsync"/>). "That was me" lets the next sync with that server
/// apply it, and once applied it is closed and its copy goes: its content is in the history.
/// "Not me" closes it for good, and it is kept: the evidence stays.
/// </para>
/// <para>
/// <b>Encrypted as every snapshot is</b> (D-15, <see cref="SnapshotFile"/>): a held change's file
/// names are no more readable on disk than any other snapshot's, and a copy is checked against
/// its ID when it is read. A copy is kept whole, files and all, so it reads without the trees
/// the block store may since have swept (D-23).
/// </para>
/// <para>
/// At most one change per server is open at a time. While one is unanswered, newer snapshots
/// from the same server are held under it, so the person is asked once, about the newest.
/// </para>
/// <para>
/// Changed under a file lock beside it, because the daemon holds changes while the command line
/// answers them.
/// </para>
/// </remarks>
public sealed class HeldChanges
{
    /// <summary>The schema this build writes.</summary>
    public const int CurrentSchema = 1;

    private readonly RepositoryLayout _layout;
    private readonly RepositoryCipher _cipher;

    /// <summary>Creates the store for one folder.</summary>
    /// <param name="layout">The folder's layout.</param>
    /// <param name="cipher">The folder's cipher, which each held copy is encrypted under.</param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public HeldChanges(RepositoryLayout layout, RepositoryCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(cipher);
        _layout = layout;
        _cipher = cipher;
    }

    /// <summary>Every change held in this folder, closed ones included.</summary>
    /// <returns>The changes, oldest first.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public IReadOnlyList<HeldChange> Load() => Read().Changes;

    /// <summary>The open change from one server's install, if there is one.</summary>
    /// <param name="device">The install.</param>
    /// <returns>The change, or null.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public HeldChange? OpenFrom(string device) =>
        Load().LastOrDefault(change => !change.IsClosed && SameDevice(change.Device, device));

    /// <summary>Holds a change: keeps a copy of its snapshot, and records it or extends the open one.</summary>
    /// <param name="device">The install that sent it.</param>
    /// <param name="server">How to name the server.</param>
    /// <param name="snapshotId">The held snapshot's ID.</param>
    /// <param name="snapshot">The held snapshot.</param>
    /// <param name="what">What was seen, in a sentence.</param>
    /// <param name="nowUtc">When.</param>
    /// <returns>The open change, as recorded; with no alert yet when the person must be asked.</returns>
    /// <exception cref="JsonException">The file cannot be read, so nothing was held.</exception>
    /// <exception cref="IOException">The lock could not be taken, or a file written.</exception>
    /// <remarks>
    /// A change already answered "That was me" and followed by a newer snapshot that is held
    /// too is asked about again: the approval covered what the person was shown, not what came
    /// after it.
    /// </remarks>
    public HeldChange Hold(string device, string server, ContentHash snapshotId, Snapshot snapshot, string what, DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(device);
        ArgumentNullException.ThrowIfNull(snapshot);

        using var held = Lock();
        KeepCopy(snapshotId, snapshot);

        var stored = Read();
        var changes = stored.Changes.ToList();
        var at = changes.FindLastIndex(change => !change.IsClosed && SameDevice(change.Device, device));

        HeldChange entry;
        if (at < 0)
        {
            entry = new HeldChange
            {
                Snapshot = snapshotId,
                Device = device,
                Server = server,
                HeldUtc = nowUtc,
                What = what,
            };
            changes.Add(entry);
        }
        else if (changes[at].Snapshot == snapshotId)
        {
            return changes[at];
        }
        else
        {
            var open = changes[at];
            entry = open with
            {
                Snapshot = snapshotId,
                Earlier = [.. open.Earlier, open.Snapshot],
                Server = server,
                What = what,
                Alert = open.Answer == HeldAnswer.ThatWasMe ? null : open.Alert,
                Answer = open.Answer == HeldAnswer.ThatWasMe ? HeldAnswer.Unanswered : open.Answer,
                AnsweredUtc = open.Answer == HeldAnswer.ThatWasMe ? null : open.AnsweredUtc,
            };
            changes[at] = entry;
        }

        Write(stored with { Changes = changes });
        return entry;
    }

    /// <summary>
    /// Asks the person about an open change: raises its alert and records it, unless one was
    /// raised already.
    /// </summary>
    /// <param name="device">The install the change came from.</param>
    /// <param name="snapshotId">The held snapshot.</param>
    /// <param name="raise">
    /// Raises the alert and answers its number, or null when it could not be raised; then the
    /// next sync that finds the change waiting asks again.
    /// </param>
    /// <returns>The alert that asks about the change, or null while none could be raised.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="raise"/> was null.</exception>
    /// <exception cref="JsonException">The file cannot be read.</exception>
    /// <exception cref="IOException">The lock could not be taken, or the file written.</exception>
    /// <remarks>
    /// <para>
    /// Matched by install as well as snapshot: two installs can offer the same head, and each
    /// change is its own question.
    /// </para>
    /// <para>
    /// Under the lock from the check to the record, so the daemon and a command syncing this
    /// folder at the same moment raise one alert between them, not one each. The alerts log's
    /// own lock is taken inside this one and never the other way round.
    /// </para>
    /// </remarks>
    public int? Ask(string device, ContentHash snapshotId, Func<int?> raise)
    {
        ArgumentNullException.ThrowIfNull(raise);

        using var held = Lock();
        var stored = Read();
        var changes = stored.Changes.ToList();
        var at = changes.FindLastIndex(change =>
            !change.IsClosed && change.Snapshot == snapshotId && SameDevice(change.Device, device));
        if (at < 0)
        {
            return null;
        }

        if (changes[at].Alert is { } asked)
        {
            return asked;
        }

        if (raise() is not { } alert)
        {
            return null;
        }

        changes[at] = changes[at] with { Alert = alert };
        Write(stored with { Changes = changes });
        return alert;
    }

    /// <summary>Records the person's answer to the change an alert asked about.</summary>
    /// <param name="alert">The alert's number.</param>
    /// <param name="answer">The answer.</param>
    /// <param name="nowUtc">When.</param>
    /// <returns>The change answered, or null when no open change is asked about by that alert.</returns>
    /// <exception cref="JsonException">The file cannot be read.</exception>
    /// <exception cref="IOException">The lock could not be taken, or the file written.</exception>
    public HeldChange? Answer(int alert, HeldAnswer answer, DateTimeOffset nowUtc) =>
        Change(
            change => change.Alert == alert && !change.IsClosed && change.Answer == HeldAnswer.Unanswered,
            change => change with { Answer = answer, AnsweredUtc = nowUtc });

    /// <summary>Closes an approved change once the sync that applied it has finished.</summary>
    /// <param name="device">The install it came from.</param>
    /// <param name="nowUtc">When.</param>
    /// <returns>The change closed, or null when none was waiting.</returns>
    /// <exception cref="JsonException">The file cannot be read.</exception>
    /// <exception cref="IOException">The lock could not be taken, or a file written.</exception>
    public HeldChange? MarkApplied(string device, DateTimeOffset nowUtc)
    {
        using var held = Lock();
        var stored = Read();
        var changes = stored.Changes.ToList();
        var at = changes.FindLastIndex(change =>
            !change.IsClosed && change.Answer == HeldAnswer.ThatWasMe && SameDevice(change.Device, device));
        if (at < 0)
        {
            return null;
        }

        var closed = changes[at] with { AppliedUtc = nowUtc };
        changes[at] = closed;
        Write(stored with { Changes = changes });

        // Its content is in the history now; the copies were only to keep it until then. One
        // another change still holds is kept.
        foreach (var id in closed.Earlier.Append(closed.Snapshot))
        {
            if (!changes.Any(change => change.AppliedUtc is null && Holds(change, id)))
            {
                SharingRetry.Run(() => File.Delete(CopyPath(id)));
            }
        }

        return closed;
    }

    /// <summary>A held snapshot's copy, decrypted and checked against its ID, or null when it is missing or altered.</summary>
    /// <param name="snapshotId">The snapshot.</param>
    /// <returns>The snapshot.</returns>
    public Snapshot? ReadSnapshot(ContentHash snapshotId)
    {
        Snapshot snapshot;
        try
        {
            var stored = SharingRetry.Run(() => File.ReadAllBytes(CopyPath(snapshotId)));
            snapshot = SnapshotFile.Unprotect(stored, snapshotId, _cipher);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or CorruptBlockException or SnapshotNotFoundException)
        {
            return null;
        }

        // Kept whole, so it reads without its trees; its files must be the ones its ID covers.
        try
        {
            return SnapshotEncoding.IsConsistent(snapshot) && SipRepository.ComputeSnapshotId(snapshot) == snapshotId
                ? snapshot
                : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Every held snapshot still kept: what the collector must not sweep the blocks of.</summary>
    /// <returns>The snapshots.</returns>
    /// <remarks>
    /// Read from the copies themselves, never from <c>held.json</c>. Every change not yet applied
    /// keeps its copies, refused ones included, and an applied one's go as it closes, so the
    /// copies are exactly what must be kept; a <c>held.json</c> that cannot be read then stops no
    /// save and no collection, and every copy is protected all the same. A copy that does not
    /// match its name is not the snapshot it claims to be, and protects nothing.
    /// </remarks>
    public IReadOnlyList<Snapshot> Kept()
    {
        string[] copies;
        try
        {
            copies = Directory.GetFiles(_layout.HeldDirectory, "*.json");
        }
        catch (DirectoryNotFoundException)
        {
            return [];
        }

        var kept = new List<Snapshot>();
        foreach (var copy in copies)
        {
            if (ContentHash.TryParse(Path.GetFileNameWithoutExtension(copy), out var id) && ReadSnapshot(id) is { } snapshot)
            {
                kept.Add(snapshot);
            }
        }

        return kept;
    }

    private static bool Holds(HeldChange change, ContentHash id) => change.Snapshot == id || change.Earlier.Contains(id);

    private static bool SameDevice(string? left, string? right) =>
        left is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private string CopyPath(ContentHash id) => Path.Combine(_layout.HeldDirectory, $"{id}.json");

    private void KeepCopy(ContentHash snapshotId, Snapshot snapshot)
    {
        var path = CopyPath(snapshotId);
        if (File.Exists(path))
        {
            return;
        }

        Directory.CreateDirectory(_layout.HeldDirectory);
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, SnapshotFile.ProtectWhole(snapshot, snapshotId, _cipher));
            SharingRetry.Run(() => File.Move(temporary, path, overwrite: true));
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    private HeldChange? Change(Func<HeldChange, bool> which, Func<HeldChange, HeldChange> how)
    {
        using var held = Lock();
        var stored = Read();
        var changes = stored.Changes.ToList();
        var at = changes.FindLastIndex(change => which(change));
        if (at < 0)
        {
            return null;
        }

        changes[at] = how(changes[at]);
        Write(stored with { Changes = changes });
        return changes[at];
    }

    private FileLock Lock()
    {
        Directory.CreateDirectory(_layout.MetadataDirectory);
        return FileLock.Acquire(_layout.HeldFile + ".lock", FileLock.DefaultPatience);
    }

    private StoredHeld Read()
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(_layout.HeldFile));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new StoredHeld(CurrentSchema, []);
        }

        StoredHeld? file;
        try
        {
            file = JsonSerializer.Deserialize<StoredHeld>(json, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new JsonException(
                $"{_layout.HeldFile} cannot be read ({ex.Message}). Until it is mended, no change from another " +
                "server is applied to this folder. Saving goes on, and every held copy in .sip/held stays kept.",
                ex);
        }

        if (file?.Changes is null || file.Schema > CurrentSchema)
        {
            throw new JsonException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{_layout.HeldFile} is not one this build can read (schema {file?.Schema ?? 0}).") +
                " Until it is mended, no change from another server is applied to this folder. " +
                "Saving goes on, and every held copy in .sip/held stays kept.");
        }

        return file;
    }

    private void Write(StoredHeld stored)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(stored with { Schema = CurrentSchema }, SipJson.Readable);
        var temporary = $"{_layout.HeldFile}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);
            if (File.Exists(_layout.HeldFile))
            {
                SharingRetry.Run(() => File.Replace(temporary, _layout.HeldFile, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, _layout.HeldFile));
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

    /// <summary><c>held.json</c> as stored.</summary>
    /// <param name="Schema">The schema it was written in.</param>
    /// <param name="Changes">Every change held, oldest first.</param>
    private sealed record StoredHeld(int Schema, IReadOnlyList<HeldChange> Changes);
}
