using System.Globalization;
using System.Text;
using System.Text.Json;
using SippBucket.Core.Hashing;
using SippBucket.Core.Machines;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Push;

/// <summary>One file Direct Push placed in the inbox, as the inbox's ledger records it.</summary>
public sealed record InboxEntry
{
    /// <summary>When it was placed.</summary>
    public required DateTimeOffset ArrivedUtc { get; init; }

    /// <summary>The sending machine's device ID.</summary>
    public required string SenderDeviceId { get; init; }

    /// <summary>The name this machine knows the sender by.</summary>
    public required string SenderName { get; init; }

    /// <summary>Whose machine the sender is, as answered when it arrived.</summary>
    public required MachineOwner SenderOwner { get; init; }

    /// <summary>The name it was sent with.</summary>
    public required string SentName { get; init; }

    /// <summary>
    /// The name it was placed under in the inbox: the name it was sent with, numbered when a
    /// file of that name was already there. For a file released from quarantine, the name it
    /// was released as.
    /// </summary>
    public required string PlacedName { get; init; }

    /// <summary>Its length in bytes.</summary>
    public required long Size { get; init; }

    /// <summary>The BLAKE2b-256 of its content.</summary>
    public required ContentHash Hash { get; init; }

    /// <summary>What the content check found it to be, as the engine's type number.</summary>
    public required uint DetectedType { get; init; }

    /// <summary>Whether neither its name nor its content was a type SippBucket recognises.</summary>
    public bool Unrecognised { get; init; }

    /// <summary>Whether it came out of quarantine, by the person's choice, rather than straight in.</summary>
    public bool ReleasedFromQuarantine { get; init; }

    /// <summary>Where a forwarding rule moved it, when one did; null while it is in the inbox.</summary>
    public string? ForwardedTo { get; init; }
}

/// <summary>What the ledger holds: the entries that could be read, and how many lines could not.</summary>
/// <param name="Entries">The entries, oldest first.</param>
/// <param name="UnreadableLines">How many lines were skipped because they could not be read.</param>
public sealed record InboxLedger(IReadOnlyList<InboxEntry> Entries, int UnreadableLines);

/// <summary>
/// The inbox a pushed file arrives in, with its hidden staging area and its quarantine
/// (docs/DIRECT-PUSH.md, rules 4 and 5).
/// </summary>
/// <remarks>
/// <para>
/// <b>Layout.</b> The inbox is an ordinary folder the person can open, by default
/// <c>SippBucket Inbox</c> in their profile. Beside the files are two folders SippBucket owns:
/// <c>Quarantine</c>, visible, the spam folder under the inbox (<see cref="Push.Quarantine"/>);
/// and <c>.sippbucket</c>, hidden, which holds the staging area, the ledger and the lock.
/// </para>
/// <para>
/// <b>Staged, checked, then placed.</b> A file streams into the staging area under a random
/// name, is hashed and content-checked there, and only then is moved into the inbox, or into
/// quarantine. The staging area is inside the inbox, on the same volume, so placing is a rename:
/// a file in the inbox is always whole. <b>Nothing is overwritten</b>: a name already taken gets
/// a numbered one beside it, as Windows Explorer numbers a copy, <c>report (2).pdf</c>.
/// </para>
/// <para>
/// <b>The ledger</b> records every file placed, who sent it and what it was found to be, one
/// JSON line each, for <c>sip inbox</c> and for each other person's space cap. It is kept to a
/// bounded size (<see cref="LedgerCompactionBytes"/>): when it grows past that, the entries for
/// files no longer in the inbox are dropped, except the most recent, so history survives and the
/// file does not grow for ever. A line that cannot be read is skipped and counted, never allowed
/// to take the other entries with it.
/// </para>
/// <para>
/// Every change, placing a file, writing the ledger, anything in quarantine, is made under the
/// inbox's lock, which any process can take and which is never held while a file streams in.
/// </para>
/// </remarks>
public sealed class PushInbox
{
    /// <summary>The inbox's folder name, in the person's profile, when they have not chosen another.</summary>
    public const string DefaultFolderName = "SippBucket Inbox";

    /// <summary>The hidden folder SippBucket keeps its own files in.</summary>
    public const string MetadataFolderName = ".sippbucket";

    /// <summary>The quarantine's folder name.</summary>
    public const string QuarantineFolderName = "Quarantine";

    /// <summary>The ledger's size at which it is compacted.</summary>
    public const long LedgerCompactionBytes = 4L * 1024 * 1024;

    /// <summary>How many of the most recent entries compaction always keeps, whatever became of their files.</summary>
    public const int LedgerEntriesKept = 1000;

    /// <summary>The most numbered names tried before a clash is reported rather than numbered.</summary>
    private const int MostNumbers = 10_000;

    /// <summary>The ledger's encoding: UTF-8 with no byte order mark, so every line is one JSON value.</summary>
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// The ledger's size at which the next compaction happens, or 0 until the first. Under the
    /// inbox's lock, which every write of the ledger holds.
    /// </summary>
    private long _compactAt;

    /// <summary>Creates the inbox over a folder. Nothing is created until <see cref="Prepare"/>.</summary>
    /// <param name="root">The inbox folder: a fully qualified path on a local drive.</param>
    /// <exception cref="ArgumentException">The path is blank, relative, or not on a drive.</exception>
    public PushInbox(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);

        if (!IsUsableRoot(root, out var reason))
        {
            throw new ArgumentException(reason, nameof(root));
        }

        Root = Path.GetFullPath(root);
        MetadataFolder = Path.Combine(Root, MetadataFolderName);
        StagingFolder = Path.Combine(MetadataFolder, "staging");
        LedgerFile = Path.Combine(MetadataFolder, "inbox.jsonl");
        LockFile = Path.Combine(MetadataFolder, "lock");
        Quarantine = new Quarantine(Path.Combine(Root, QuarantineFolderName), this);
    }

    /// <summary>The inbox folder.</summary>
    public string Root { get; }

    /// <summary>The hidden folder SippBucket keeps its own files in.</summary>
    public string MetadataFolder { get; }

    /// <summary>Where files stream in before they are checked.</summary>
    public string StagingFolder { get; }

    /// <summary>The ledger of files placed.</summary>
    public string LedgerFile { get; }

    /// <summary>The file whose lock orders every change to the inbox and its quarantine.</summary>
    public string LockFile { get; }

    /// <summary>The quarantine under this inbox.</summary>
    public Quarantine Quarantine { get; }

    /// <summary>
    /// Test seam: the ledger's size at which it is compacted, <see cref="LedgerCompactionBytes"/>
    /// in production. Internal, so a test can watch compaction without writing megabytes of
    /// entries first; production code never sets it.
    /// </summary>
    internal long CompactionThreshold { get; init; } = LedgerCompactionBytes;

    /// <summary>Whether a folder can be an inbox at all: written out in full, on one of this machine's drives.</summary>
    /// <param name="root">The folder.</param>
    /// <param name="reason">Why it cannot, when this returns false.</param>
    /// <returns>True when it can.</returns>
    /// <remarks>A drive is needed so the free space the inbox's disk must keep can be checked.</remarks>
    public static bool IsUsableRoot(string? root, out string reason)
    {
        if (string.IsNullOrWhiteSpace(root) ||
            !Path.IsPathFullyQualified(root) ||
            Path.GetPathRoot(root) is not { Length: >= 2 } drive || drive[1] != ':')
        {
            reason = $"The inbox must be a folder on one of this machine's drives, written out in full, such as " +
                     $"C:\\Users\\you\\{DefaultFolderName}, and '{root}' is not one. A drive is needed so the free " +
                     "space it must keep can be checked.";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>The inbox folder when the person has not chosen one.</summary>
    /// <returns><c>SippBucket Inbox</c> in the person's profile.</returns>
    public static string DefaultRoot() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), DefaultFolderName);

    /// <summary>
    /// Why an inbox folder cannot sit where it is among the folders SippBucket syncs, or null when
    /// it can.
    /// </summary>
    /// <param name="inboxRoot">The inbox folder.</param>
    /// <param name="syncedFolders">Every folder SippBucket syncs on this machine.</param>
    /// <returns>The reason, or null.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="syncedFolders"/> was null.</exception>
    /// <remarks>
    /// An inbox inside a synced folder would sync everything that arrived to every machine that
    /// folder is shared with, quarantine included, which is exactly where a disguised program
    /// must never go; and one that holds a synced folder would put that folder's files among
    /// the deliveries. Direct Push does not start while either is so.
    /// </remarks>
    public static string? ConflictWithSyncedFolders(string inboxRoot, IEnumerable<string> syncedFolders)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inboxRoot);
        ArgumentNullException.ThrowIfNull(syncedFolders);

        foreach (var folder in syncedFolders)
        {
            if (FolderPaths.IsSameOrInside(inboxRoot, folder))
            {
                return $"the inbox, {inboxRoot}, is inside {folder}, which SippBucket syncs, so everything that " +
                       "arrived, quarantine included, would be synced to other machines";
            }

            if (FolderPaths.IsSameOrInside(folder, inboxRoot))
            {
                return $"the inbox, {inboxRoot}, holds {folder}, which SippBucket syncs";
            }
        }

        return null;
    }

    /// <summary>
    /// Readies the inbox before Direct Push starts listening: its folders, and a staging area
    /// cleared of anything a delivery interrupted by a crash left there.
    /// </summary>
    /// <exception cref="IOException">A folder could not be created, or the lock stayed held.</exception>
    /// <exception cref="UnauthorizedAccessException">The folder is not this person's to write.</exception>
    /// <remarks>
    /// Only before listening: while deliveries arrive, the staging area holds files still
    /// streaming in, which clearing it would destroy.
    /// </remarks>
    public void Prepare()
    {
        EnsureFolders();

        using (Lock())
        {
            // Only this machine's own staging files are here, each deleted by the delivery that
            // wrote it; one still here was left by a delivery that never finished.
            foreach (var leftover in Directory.EnumerateFiles(StagingFolder, "*.part"))
            {
                SharingRetry.Run(() => File.Delete(leftover));
            }
        }
    }

    /// <summary>
    /// Creates the inbox's folders if they are missing, and hides SippBucket's own. Safe at any
    /// time: the person may have deleted the inbox since the last delivery.
    /// </summary>
    /// <exception cref="IOException">A folder could not be created.</exception>
    /// <exception cref="UnauthorizedAccessException">The folder is not this person's to write.</exception>
    public void EnsureFolders()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Quarantine.Folder);

        var metadata = Directory.CreateDirectory(MetadataFolder);
        if (!metadata.Attributes.HasFlag(FileAttributes.Hidden))
        {
            metadata.Attributes |= FileAttributes.Hidden;
        }

        Directory.CreateDirectory(StagingFolder);
    }

    /// <summary>A new, unused path in the staging area for a file about to stream in.</summary>
    /// <returns>The path. Nothing is created.</returns>
    public string NewStagingPath() =>
        Path.Combine(StagingFolder, string.Create(CultureInfo.InvariantCulture, $"{Guid.NewGuid():N}.part"));

    /// <summary>Takes the inbox's lock.</summary>
    /// <returns>The held lock. Dispose it to release.</returns>
    /// <exception cref="IOException">It stayed held by someone else for longer than the patience.</exception>
    internal FileLock Lock() => FileLock.Acquire(LockFile, FileLock.DefaultPatience);

    /// <summary>Takes the inbox's lock without holding a thread while it waits.</summary>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>The held lock. Dispose it to release.</returns>
    /// <exception cref="IOException">It stayed held by someone else for longer than the patience.</exception>
    internal Task<FileLock> LockAsync(CancellationToken cancellationToken) =>
        FileLock.AcquireAsync(LockFile, FileLock.DefaultPatience, cancellationToken);

    /// <summary>
    /// Moves a checked file into the inbox under its name, or a numbered one when the name is
    /// taken. The caller holds <see cref="Lock"/>.
    /// </summary>
    /// <param name="source">The file: staged, or released from quarantine.</param>
    /// <param name="name">The name it should have, already found acceptable (<see cref="PushName"/>).</param>
    /// <returns>The name it was placed under.</returns>
    /// <exception cref="FileNotFoundException">The file is gone: something removed it before it could be placed.</exception>
    /// <exception cref="IOException">Every numbered name was taken, or the move failed.</exception>
    internal string Place(string source, string name) => MoveUnderFreeName(source, Root, name);

    /// <summary>
    /// Moves a file into a folder under its name, or a numbered one when the name is taken, never
    /// over anything already there.
    /// </summary>
    /// <param name="source">The file to move.</param>
    /// <param name="folder">The folder to move it into.</param>
    /// <param name="name">The name it should have.</param>
    /// <returns>The name it was placed under.</returns>
    /// <exception cref="FileNotFoundException">The file is gone.</exception>
    /// <exception cref="IOException">Every numbered name was taken, or the move failed.</exception>
    internal static string MoveUnderFreeName(string source, string folder, string name)
    {
        for (var number = 1; number <= MostNumbers; number++)
        {
            var candidate = number == 1 ? name : Numbered(name, number);
            var destination = Path.Combine(folder, candidate);

            if (File.Exists(destination) || Directory.Exists(destination))
            {
                continue;
            }

            try
            {
                // Never overwrites: a name taken since the check above fails the move, and the
                // next number is tried.
                SharingRetry.Run(() => File.Move(source, destination, overwrite: false));
                return candidate;
            }
            catch (IOException) when (File.Exists(destination) || Directory.Exists(destination))
            {
            }
        }

        throw new IOException(
            $"'{name}' and {MostNumbers - 1} numbered versions of it are all taken in {folder}; the file was not placed.");
    }

    /// <summary>A numbered form of a name, as Windows Explorer numbers a copy: <c>report (2).pdf</c>.</summary>
    /// <param name="name">The name.</param>
    /// <param name="number">The number, 2 or more.</param>
    /// <returns>The numbered name, shortened if need be to stay within <see cref="PushName.MaximumLength"/>.</returns>
    internal static string Numbered(string name, int number)
    {
        var extension = Path.GetExtension(name);
        var stem = Path.GetFileNameWithoutExtension(name);

        // ".gitignore" has no stem: the number goes after the whole name.
        if (stem.Length == 0)
        {
            stem = name;
            extension = string.Empty;
        }

        var suffix = string.Create(CultureInfo.InvariantCulture, $" ({number})");
        var room = PushName.MaximumLength - suffix.Length - extension.Length;
        if (stem.Length > room)
        {
            stem = stem[..Math.Max(1, room)].TrimEnd(' ', '.');
        }

        return stem + suffix + extension;
    }

    /// <summary>Adds an entry to the ledger. The caller holds <see cref="Lock"/>.</summary>
    /// <param name="entry">The entry.</param>
    /// <exception cref="IOException">The ledger could not be written.</exception>
    internal void Record(InboxEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var line = JsonSerializer.Serialize(entry, SipJson.Canonical) + "\n";
        SharingRetry.Run(() => File.AppendAllText(LedgerFile, line, Utf8));

        if (_compactAt == 0)
        {
            _compactAt = CompactionThreshold;
        }

        if (new FileInfo(LedgerFile).Length > _compactAt)
        {
            Compact();

            // When what is worth keeping is itself most of the threshold, compacting again on the
            // next entry would rewrite the whole ledger for every file that arrives. The next one
            // waits until the ledger has doubled, so the cost stays in proportion to what arrives.
            _compactAt = Math.Max(CompactionThreshold, new FileInfo(LedgerFile).Length * 2);
        }
    }

    /// <summary>Reads the ledger.</summary>
    /// <returns>Every entry that could be read, oldest first, and how many lines could not.</returns>
    /// <exception cref="IOException">The ledger could not be read.</exception>
    public InboxLedger ReadLedger()
    {
        string[] lines;
        try
        {
            lines = SharingRetry.Run(() => File.ReadAllLines(LedgerFile, Utf8));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new InboxLedger([], 0);
        }

        var entries = new List<InboxEntry>(lines.Length);
        var unreadable = 0;
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                if (JsonSerializer.Deserialize<InboxEntry>(line, SipJson.Canonical) is { } entry)
                {
                    entries.Add(entry);
                    continue;
                }
            }
            catch (JsonException)
            {
                // Counted below, and reported by whoever shows the ledger. One damaged line costs
                // only itself.
            }

            unreadable++;
        }

        return new InboxLedger(entries, unreadable);
    }

    /// <summary>
    /// How much of this machine one sender's files take now: those still in the inbox under the
    /// name the ledger gave them, and those in quarantine that it sent first.
    /// </summary>
    /// <param name="deviceId">The sender.</param>
    /// <returns>Bytes.</returns>
    /// <remarks>
    /// Counts what is actually here: a file the person moved, deleted or had forwarded no longer
    /// takes inbox space, and one released from quarantine counts where it now is.
    /// </remarks>
    public long SpaceUsedBy(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        long used = 0;
        foreach (var entry in ReadLedger().Entries)
        {
            if (entry.ForwardedTo is null &&
                string.Equals(entry.SenderDeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                new FileInfo(Path.Combine(Root, entry.PlacedName)) is { Exists: true } file &&
                file.Length == entry.Size)
            {
                used += entry.Size;
            }
        }

        return used + Quarantine.SpaceFirstSentBy(deviceId);
    }

    /// <summary>
    /// Rewrites the ledger keeping the entries whose files are still in the inbox and the most
    /// recent <see cref="LedgerEntriesKept"/>. The caller holds <see cref="Lock"/>.
    /// </summary>
    private void Compact()
    {
        var entries = ReadLedger().Entries;
        var recent = Math.Max(0, entries.Count - LedgerEntriesKept);

        var kept = entries
            .Where((entry, index) => index >= recent ||
                                     (entry.ForwardedTo is null && File.Exists(Path.Combine(Root, entry.PlacedName))))
            .Select(entry => JsonSerializer.Serialize(entry, SipJson.Canonical) + "\n");

        var temporary = $"{LedgerFile}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temporary, string.Concat(kept), Utf8);
            SharingRetry.Run(() => File.Replace(temporary, LedgerFile, destinationBackupFileName: null));
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
