using System.Globalization;
using SippBucket.Core.Chunking;
using SippBucket.Core.Crypto;
using SippBucket.Core.Model;
using SippBucket.Core.Protocol;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;
using SippBucket.Core.Text;

namespace SippBucket.Core.Sync;

/// <summary>
/// Brings a peer's snapshot into the working folder by a three-way comparison against a
/// common ancestor, for fast-forwards and merges alike.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why one engine.</b> There used to be two. A fast-forward called
/// <see cref="SipRepository.RestoreAsync"/>, which rewrote every file and deleted every file
/// the incoming snapshot lacked, so anything edited or created in the seconds a transfer
/// took was overwritten or deleted without ever being snapshotted (D-44). A merge walked
/// only the incoming file list and never deleted anything, so a file one machine deleted was
/// written back by the other (D-26). The same user action propagated or reversed depending
/// on which path the sync happened to take. Now a fast-forward is this engine with the
/// local head as the base, and a merge is this engine with the nearest common ancestor.
/// <c>sip restore</c> goes through it too, with a rule of its own (<see cref="RestoreAsync"/>),
/// so that a restore stages, checks and moves whole files exactly as a sync does (D-53).
/// </para>
/// <para>
/// <b>The rule, per path,</b> comparing entries by content: by block list when both were
/// split the same way, and by re-reading the file when they were not (see
/// <c>ReconcileRecipesAsync</c>):
/// </para>
/// <list type="bullet">
/// <item><description>Local equals remote: nothing to do.</description></item>
/// <item><description>Local equals the base, remote differs: take the remote version, or
/// delete the file when the remote deleted it. This is how deletions travel.</description></item>
/// <item><description>Remote equals the base, local differs: keep local.</description></item>
/// <item><description>Both changed, both present, different: keep both. The local file is
/// renamed to <c>&lt;name&gt;.conflict-&lt;device&gt;-&lt;stamp&gt;</c>, where the device is
/// this machine, whose version the renamed file holds, and the remote version takes the
/// name. One exception (T-01): a Markdown page whose base is known and whose two sides'
/// line edits do not touch is written once, with both sides' edits combined
/// (<see cref="MergeMarkdownConflictsAsync"/>); edits that touch keep both, as
/// ever.</description></item>
/// <item><description>Deleted here, modified there: restore the remote version. The edit is
/// the only copy of that content; the deletion can be repeated.</description></item>
/// <item><description>Modified here, deleted there: keep local, for the same
/// reason.</description></item>
/// <item><description>Ignored by this machine, or by the incoming snapshot's own
/// <c>.sipignore</c>: left alone, whatever either side did (D-56).</description></item>
/// <item><description>A link here, or under one: left alone. Nothing is written or deleted
/// through a link (DATA-01).</description></item>
/// <item><description>Read-only here, where the rule would replace it: keep both, as for a
/// conflict. Where the rule would delete it: it stays (T-04).</description></item>
/// </list>
/// <para>
/// With no base the base is absent for every path, which reduces the rule to a two-way
/// merge that never deletes — the behaviour before this engine existed, and safe.
/// </para>
/// <para>
/// <b>Order of work,</b> which is what makes a failure harmless. Every remote path is
/// validated before anything else (standard D1). The working folder is scanned now, after
/// the transfer, so the comparison is against what is on disk rather than what was saved.
/// Every incoming version is then written in full into <c>.sip/incoming</c> — a missing or
/// corrupt block fails here, with the working folder untouched. Then every file that will be
/// replaced, moved or deleted is checked: unchanged since the scan, and not held open by
/// another program. Only after all of that is anything in the working folder touched, and
/// then only by deleting, renaming, and moving a finished file over a path.
/// </para>
/// <para>
/// <b>A file held open by another program</b> — a document open in an editor that denies
/// sharing — stops the apply at the check, before any file has changed, with a
/// <see cref="WorkingTreeBusyException"/> naming it. The sync is retried next cycle. A file
/// is never written in place, so it is never half-written: the move either happens or it
/// does not, and a destination that is replaced at all is one whose content equals the base
/// and is therefore already held in a snapshot.
/// </para>
/// <para>
/// <b>What remains.</b> The check and the change are separate calls, so an edit landing in
/// the milliseconds between them can still be replaced; the window is the length of a
/// rename rather than the length of a transfer. And permissions: Microsoft documents that a
/// file moved <em>across</em> volumes is given the destination folder's default security
/// descriptor (MoveFileEx, Remarks:
/// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw),
/// which implies that one moved within a volume, as these are, keeps the descriptor it was
/// created with in <c>.sip/incoming</c>. If so, a subfolder given its own inheritable
/// permissions does not pass them to a file synced into it, as it did when RestoreAsync
/// created files in place. That has not been measured.
/// </para>
/// </remarks>
internal static class WorkingTreeMerge
{
    /// <summary>
    /// How old an abandoned staging folder must be before an apply removes it. Only a crash
    /// leaves one, and a day is far longer than any apply in progress could be.
    /// </summary>
    private static readonly TimeSpan StaleStagingAge = TimeSpan.FromDays(1);

    // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION, as .NET reports them: the Win32 code
    // under FACILITY_WIN32 (HRESULT_FROM_WIN32).
    private const int SharingViolation = unchecked((int)0x80070020);
    private const int LockViolation = unchecked((int)0x80070021);

    /// <summary>Applies a remote snapshot to the working folder.</summary>
    /// <param name="repository">The repository whose working folder changes.</param>
    /// <param name="baseFiles">The common ancestor's files, or null when there is none.</param>
    /// <param name="remote">The snapshot being brought in. Its blocks must all be present.</param>
    /// <param name="localHead">This replica's head, used only to avoid re-hashing unchanged files.</param>
    /// <param name="conflictDeviceId">
    /// This machine's device ID, named in conflict copies' file names: a conflict copy holds
    /// this machine's version, so it carries this machine's name.
    /// </param>
    /// <param name="log">Optional sink for progress lines.</param>
    /// <param name="cancellationToken">
    /// Cancels the apply up to the point where the working folder starts changing. After
    /// that the remaining renames run to completion, because stopping half way through a
    /// handful of renames gains nothing and leaves a folder matching neither side.
    /// </param>
    /// <param name="afterStaging">
    /// Test seam, given the staged files' paths once they are all written and before the
    /// pre-flight check. Null in production.
    /// </param>
    /// <returns>What changed.</returns>
    /// <exception cref="UnsafeSnapshotPathException">A remote path is not safe to write.</exception>
    /// <exception cref="WorkingTreeBusyException">A file to be changed is in use or changed.</exception>
    public static async Task<WorkingTreeMergeResult> ApplyAsync(
        SipRepository repository,
        IReadOnlyList<FileEntry>? baseFiles,
        Snapshot remote,
        Snapshot? localHead,
        string conflictDeviceId,
        Action<string>? log,
        CancellationToken cancellationToken,
        Func<IReadOnlyList<string>, Task>? afterStaging = null)
    {
        var root = repository.Layout.WorkingRoot;

        // D1: every incoming path, before anything is read, staged or touched.
        var remoteByPath = IndexRemote(remote, root);

        var scan = await repository
            .ScanAsync(storeBlocks: false, localHead, localHead, cancellationToken)
            .ConfigureAwait(false);
        var localByPath = scan.Files.ToDictionary(f => f.Path, StringComparer.Ordinal);
        var baseByPath = (baseFiles ?? []).ToDictionary(f => f.Path, StringComparer.Ordinal);

        await ReconcileRecipesAsync(localByPath, baseByPath, remoteByPath, scan, root, cancellationToken)
            .ConfigureAwait(false);

        var incomingIgnore = await ReadIgnoreRulesAsync(repository, remote, cancellationToken).ConfigureAwait(false);
        var before = repository.Ignore;
        var plan = Plan(localByPath, baseByPath, remoteByPath, before, before, incomingIgnore, scan, root);

        // A plan that writes or deletes .sipignore changes the rules every other path is
        // judged by, from the moment it has run. Judged by the rules this machine had before,
        // a path the peer stopped ignoring was left unwritten; the next scan read the new
        // rules, found the path missing, and recorded it as deleted, and the deletion went
        // back to the machine that had just started syncing it. So the folder is read again
        // by the rules that will be in force, and every path but .sipignore itself planned
        // by them.
        if (RulesAfter(plan, incomingIgnore) is { } after)
        {
            // .sipignore itself is judged as before (see Plan), so it keeps the entry the first
            // reading gave it, and its own plan is the same in both.
            var ignoreFile = localByPath.Where(pair => IsIgnoreFile(pair.Key)).ToList();

            scan = await repository
                .ScanAsync(storeBlocks: false, localHead, localHead, after, cancellationToken)
                .ConfigureAwait(false);
            localByPath = scan.Files
                .Where(f => !IsIgnoreFile(f.Path))
                .ToDictionary(f => f.Path, StringComparer.Ordinal);
            foreach (var (path, entry) in ignoreFile)
            {
                localByPath[path] = entry;
            }

            await ReconcileRecipesAsync(localByPath, baseByPath, remoteByPath, scan, root, cancellationToken)
                .ConfigureAwait(false);

            plan = Plan(localByPath, baseByPath, remoteByPath, after, before, incomingIgnore, scan, root);
        }

        await MergeMarkdownConflictsAsync(repository, plan, baseByPath, root, log, cancellationToken)
            .ConfigureAwait(false);

        return await ExecuteAsync(repository, plan, conflictDeviceId, log, afterStaging, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>The most bytes a page may have and still be merged as lines.</summary>
    private const long LargestMergablePage = 8 * 1024 * 1024;

    /// <summary>
    /// Combines both sides' edits to one Markdown page into one file, where the plan was
    /// about to keep both (T-01).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Runs over the finished plan: each keep-both — a local version moved aside beside a
    /// write of the remote version — whose path is a Markdown page, whose base version both
    /// sides started from is known and readable, and whose three versions are text within
    /// <see cref="LargestMergablePage"/>, is offered to <see cref="ThreeWayMerge"/>. Edits
    /// that do not touch come back as one merged page, staged from its literal bytes and
    /// replacing the local file in place: no conflict copy, nothing lost, both sides' words
    /// in the file. Anything else — overlapping edits, a binary or oversized version, a base
    /// held only as a file list, a read-only local file — leaves that page's keep-both
    /// exactly as it was, which is never wrong, only louder.
    /// </para>
    /// <para>
    /// Both machines produce identical merged bytes for the same three versions
    /// (<see cref="ThreeWayMerge"/>), so two machines that merge each other at the same
    /// moment write the same content, and the convergence rule settles the rest
    /// (<c>SyncEngine.SettleMergeAsync</c>).
    /// </para>
    /// </remarks>
    private static async Task MergeMarkdownConflictsAsync(
        SipRepository repository,
        MergePlan plan,
        Dictionary<string, FileEntry> baseline,
        string root,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        if (plan.Asides.Count == 0)
        {
            return;
        }

        foreach (var mine in plan.Asides.ToList())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!IsMarkdown(mine.Path) || mine.Size > LargestMergablePage)
            {
                continue;
            }

            // The write of the remote version this aside was making way for. A read-only
            // local file keeps the aside: merging would need to replace it in place.
            var index = plan.Writes.FindIndex(write =>
                write.Replacing is null && write.Literal is null &&
                string.Equals(write.Entry.Path, mine.Path, StringComparison.OrdinalIgnoreCase));
            if (index < 0 || IsReadOnly(Absolute(root, mine.Path)))
            {
                continue;
            }

            var theirs = plan.Writes[index].Entry;
            if (theirs.Size > LargestMergablePage ||
                FindBase(baseline, mine.Path) is not { } common || common.Size > LargestMergablePage)
            {
                continue;
            }

            byte[] mineBytes;
            byte[] theirsBytes;
            byte[] commonBytes;
            try
            {
                mineBytes = await File.ReadAllBytesAsync(Absolute(root, mine.Path), cancellationToken)
                    .ConfigureAwait(false);
                theirsBytes = await ReadWholeAsync(repository, theirs, cancellationToken).ConfigureAwait(false);
                commonBytes = await ReadWholeAsync(repository, common, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                           or BlockNotFoundException or CorruptBlockException)
            {
                // A base kept as a file list has no blocks here; a local file can vanish
                // mid-plan. Either way the keep-both stands, which is never wrong.
                continue;
            }

            if (ThreeWayMerge.Merge(commonBytes, mineBytes, theirsBytes) is not { } merged)
            {
                continue;
            }

            plan.Asides.Remove(mine);
            plan.Writes[index] = plan.Writes[index] with
            {
                Entry = theirs with { Size = merged.LongLength, ModifiedUtc = DateTimeOffset.UtcNow },
                Replacing = mine,
                Literal = merged,
            };

            log?.Invoke($"{mine.Path}: both sides' edits merged into one page");
        }
    }

    /// <summary>Whether a path is a Markdown page, which is what merges as lines (T-01).</summary>
    private static bool IsMarkdown(string path)
    {
        var extension = Path.GetExtension(path);
        return string.Equals(extension, ".md", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(extension, ".markdown", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The base entry for a path, however the base spelled its case.</summary>
    private static FileEntry? FindBase(Dictionary<string, FileEntry> baseline, string path)
    {
        if (baseline.TryGetValue(path, out var exact))
        {
            return exact;
        }

        FileEntry? folded = null;
        foreach (var entry in baseline.Values)
        {
            if (string.Equals(entry.Path, path, StringComparison.OrdinalIgnoreCase))
            {
                if (folded is not null)
                {
                    return null;
                }

                folded = entry;
            }
        }

        return folded;
    }

    /// <summary>Reads one recorded version whole from the block store.</summary>
    private static async Task<byte[]> ReadWholeAsync(
        SipRepository repository,
        FileEntry entry,
        CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream(entry.Size is > 0 and <= int.MaxValue ? (int)entry.Size : 0);
        foreach (var hash in entry.Blocks)
        {
            var block = await repository.Blobs.GetAsync(hash, cancellationToken).ConfigureAwait(false);
            await bytes.WriteAsync(block, cancellationToken).ConfigureAwait(false);
        }

        return bytes.ToArray();
    }

    /// <summary>
    /// The rules that will be in force once a plan has run, when it changes <c>.sipignore</c>:
    /// the incoming file's when it writes it, none when it deletes it. Null when it leaves the
    /// file as it is.
    /// </summary>
    private static IgnoreRules? RulesAfter(MergePlan plan, IgnoreRules? incoming)
    {
        if (plan.Writes.Any(write => IsIgnoreFile(write.Entry.Path)))
        {
            // Written only from the incoming snapshot's entry, which is what the rules were
            // read from, so they are there.
            return incoming ?? IgnoreRules.Empty;
        }

        return plan.Deletes.Any(entry => IsIgnoreFile(entry.Path)) ? IgnoreRules.Empty : null;
    }

    private static bool IsIgnoreFile(string path) =>
        string.Equals(path, RepositoryLayout.IgnoreFileName, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The rules in a snapshot's own <c>.sipignore</c>, read from the store, or null when the
    /// snapshot has none.
    /// </summary>
    /// <remarks>
    /// A synced <c>.sipignore</c> arrives in the same snapshot as the first save made under
    /// it, and that save no longer lists the paths it ignores (see
    /// <c>SipRepository.CarryIgnored</c>). Judged by this machine's rules alone, which have not
    /// seen the new file yet, each such path read as deleted by the peer and was deleted here,
    /// though all the peer had done was stop syncing it. Every block of the snapshot is in
    /// the store before the apply starts, so this reads nothing from the network.
    /// </remarks>
    private static async Task<IgnoreRules?> ReadIgnoreRulesAsync(
        SipRepository repository,
        Snapshot snapshot,
        CancellationToken cancellationToken)
    {
        var entry = snapshot.Files.FirstOrDefault(
            f => string.Equals(f.Path, RepositoryLayout.IgnoreFileName, StringComparison.OrdinalIgnoreCase));
        if (entry is null)
        {
            return null;
        }

        using var bytes = new MemoryStream();
        foreach (var hash in entry.Blocks)
        {
            var block = await repository.Blobs.GetAsync(hash, cancellationToken).ConfigureAwait(false);
            await bytes.WriteAsync(block, cancellationToken).ConfigureAwait(false);
        }

        bytes.Position = 0;
        using var reader = new StreamReader(bytes, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var lines = new List<string>();
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lines.Add(line);
        }

        return IgnoreRules.Parse(lines);
    }

    /// <summary>
    /// Puts the working folder back to a snapshot through the same staged apply, destroying
    /// nothing that no snapshot holds.
    /// </summary>
    /// <param name="repository">The repository whose working folder changes.</param>
    /// <param name="head">This replica's head: what the folder is compared with to tell
    /// saved work from unsaved. Null when nothing has been saved.</param>
    /// <param name="target">The snapshot to restore. Its blocks must all be present.</param>
    /// <param name="localDeviceId">This machine's device ID, for the names of kept copies.</param>
    /// <param name="log">Optional sink for progress lines.</param>
    /// <param name="cancellationToken">Cancels the restore until the folder starts changing.</param>
    /// <returns>What changed.</returns>
    /// <exception cref="UnsafeSnapshotPathException">A path in the snapshot is not safe to write.</exception>
    /// <exception cref="WorkingTreeBusyException">A file to be changed is in use or changed.</exception>
    /// <remarks>
    /// <para>
    /// <b>The rule, per path, comparing paths the way Windows does: without regard to
    /// case.</b> Restore used to write each file in place, delete every file the snapshot did
    /// not list, tracked or not, and compare names by exact case, so a snapshot naming
    /// <c>Report.txt</c> over <c>report.txt</c> wrote into the file and then deleted it
    /// (D-53).
    /// </para>
    /// <list type="bullet">
    /// <item><description>The file matches the snapshot: nothing, except that a name differing
    /// only in case is renamed to the snapshot's.</description></item>
    /// <item><description>The file is missing: the snapshot's version is written.</description></item>
    /// <item><description>The file differs, and matches head: it is saved, so it is replaced;
    /// its content is in head, which the restore then keeps as the parent of the snapshot
    /// recording it (see <c>SipRepository.RestoreAsync</c>).</description></item>
    /// <item><description>The file differs, and does not match head — an unsaved edit, or a
    /// file no snapshot has recorded standing where the snapshot has one — or it is
    /// read-only: keep both. It is moved aside under a conflict name carrying this machine's
    /// ID, and the snapshot's version takes the name.</description></item>
    /// <item><description>The snapshot lacks the file, head tracks it and it matches head:
    /// deleted, unless it is read-only, when it stays; its content is in head.</description></item>
    /// <item><description>The snapshot lacks the file, and head does not track it or it has
    /// unsaved changes: left where it is. A restore never deletes work no snapshot
    /// holds.</description></item>
    /// <item><description>A path this machine's ignore rules match, and a path that is a link
    /// or lies under one, is never written, replaced, moved or deleted. It used to be written
    /// where nothing was on disk, which brought back a file the person had stopped
    /// syncing.</description></item>
    /// </list>
    /// <para>
    /// <b>Why keep both for an unsaved edit</b> rather than keep only the edit or only the
    /// snapshot: the person asked for the snapshot's version at that name, and the edit is the
    /// only copy of what they typed. Keeping only the edit would quietly not restore that file;
    /// keeping only the snapshot would lose the edit. This is the rule sync already follows.
    /// </para>
    /// <para>
    /// A case-only rename is a rename of the file, not of the folders above it: a snapshot
    /// naming <c>Docs/a.txt</c> over <c>docs/a.txt</c> keeps the folder's casing, and is not
    /// counted as a rename, because nothing is renamed.
    /// </para>
    /// </remarks>
    public static async Task<WorkingTreeMergeResult> RestoreAsync(
        SipRepository repository,
        Snapshot? head,
        Snapshot target,
        string localDeviceId,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        var root = repository.Layout.WorkingRoot;

        // D1 for a restore too: the snapshot may have been received from a peer.
        var targetByPath = IndexRemote(target, root);

        var scan = await repository
            .ScanAsync(storeBlocks: false, head, head, cancellationToken)
            .ConfigureAwait(false);
        var localByPath = scan.Files.ToDictionary(f => f.Path, StringComparer.Ordinal);
        var headByPath = (head?.Files ?? []).ToDictionary(f => f.Path, StringComparer.Ordinal);

        await ReconcileRecipesAsync(localByPath, headByPath, targetByPath, scan, root, cancellationToken)
            .ConfigureAwait(false);

        var plan = PlanRestore(localByPath, headByPath, targetByPath, repository.Ignore, scan, root);
        return await ExecuteAsync(repository, plan, localDeviceId, log, afterStaging: null, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Stages, checks and applies a plan.</summary>
    private static async Task<WorkingTreeMergeResult> ExecuteAsync(
        SipRepository repository,
        MergePlan plan,
        string conflictDeviceId,
        Action<string>? log,
        Func<IReadOnlyList<string>, Task>? afterStaging,
        CancellationToken cancellationToken)
    {
        var root = repository.Layout.WorkingRoot;

        foreach (var kept in plan.KeptReadOnly)
        {
            log?.Invoke($"kept {kept}: it is read-only here, so it is not deleted");
        }

        if (plan.IsEmpty)
        {
            return new WorkingTreeMergeResult
            {
                FilesWritten = 0,
                FilesDeleted = 0,
                Conflicts = [],
                KeptReadOnly = plan.KeptReadOnly,
            };
        }

        RemoveStaleStaging(repository.Layout.IncomingDirectory, log);
        var staging = Path.Combine(repository.Layout.IncomingDirectory, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);

        try
        {
            var staged = await StageAsync(repository, plan.Writes, staging, cancellationToken)
                .ConfigureAwait(false);

            if (afterStaging is not null)
            {
                await afterStaging(staged).ConfigureAwait(false);
            }

            repository.BeforeWorkingTreeChanges?.Invoke();

            Preflight(plan, root);

            cancellationToken.ThrowIfCancellationRequested();

            return Mutate(plan, staged, root, conflictDeviceId, repository, log);
        }
        finally
        {
            RemoveStaging(staging, log);
        }
    }

    /// <summary>
    /// Validates every remote path and indexes the file list by it.
    /// </summary>
    /// <exception cref="UnsafeSnapshotPathException">A path is unsafe or repeated.</exception>
    internal static Dictionary<string, (FileEntry Entry, string Absolute)> IndexRemote(
        Snapshot snapshot,
        string workingRoot)
    {
        var byPath = new Dictionary<string, (FileEntry, string)>(StringComparer.Ordinal);
        var byFoldedPath = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in snapshot.Files)
        {
            if (!SafePath.TryResolve(file.Path, workingRoot, out var absolute, out var why))
            {
                throw new UnsafeSnapshotPathException(file.Path, why);
            }

            // Two entries for one name would be written to one file, the second over the
            // first, and on Windows a difference in case alone is the same file. Whichever
            // landed last would be what the next save recorded, silently dropping the other
            // from every machine. No honest Windows client produces either.
            if (!byFoldedPath.Add(file.Path))
            {
                throw new UnsafeSnapshotPathException(
                    file.Path,
                    "another path in the same snapshot names the same file");
            }

            byPath[file.Path] = (file, absolute);
        }

        return byPath;
    }

    /// <summary>
    /// Replaces a scanned entry with the recorded one it matches byte for byte, when the two
    /// were split with different recipes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rule above compares block lists, which is exact only when both entries were split
    /// the same way. Since D-22 a file re-read by the scan is split with FastCDC, while the
    /// base or the peer may still list it under the fixed-size split every entry had before.
    /// The same bytes split two ways have two block lists, so without this step a file that
    /// nobody changed reads as changed here, and the rule answers with a conflict copy, or
    /// with a deletion that fails to travel. The first divergent sync after the upgrade would
    /// have produced one conflict copy for every such file.
    /// </para>
    /// <para>
    /// The peer's entry is tried first, then the base's. A match takes the recorded entry's
    /// recipe and blocks, and keeps the scanned modification time, because the pre-flight
    /// check compares that with the file on disk. The file is re-read only when the sizes
    /// agree and the recipes differ, at most once per candidate.
    /// </para>
    /// </remarks>
    private static async Task ReconcileRecipesAsync(
        Dictionary<string, FileEntry> local,
        Dictionary<string, FileEntry> baseline,
        Dictionary<string, (FileEntry Entry, string Absolute)> remote,
        WorkingTreeScan scan,
        string root,
        CancellationToken cancellationToken)
    {
        foreach (var path in local.Keys.ToList())
        {
            // A carried entry was not read from the disk, and is not read now: the file could
            // not be read a moment ago, or sits behind a link.
            if (scan.Carried.Contains(path))
            {
                continue;
            }

            var mine = local[path];

            var candidates = new List<FileEntry>(2);
            if (remote.TryGetValue(path, out var incoming))
            {
                candidates.Add(incoming.Entry);
            }

            if (baseline.TryGetValue(path, out var common))
            {
                candidates.Add(common);
            }

            foreach (var recorded in candidates)
            {
                if (Same(mine, recorded) || SameRecipe(mine, recorded) || mine.Size != recorded.Size)
                {
                    continue;
                }

                if (await ChunkScheme
                    .SameContentAsync(Absolute(root, path), mine, recorded, cancellationToken)
                    .ConfigureAwait(false))
                {
                    local[path] = recorded with { ModifiedUtc = mine.ModifiedUtc };
                    break;
                }
            }
        }
    }

    private static bool SameRecipe(FileEntry left, FileEntry right) =>
        string.Equals(left.Chunker, right.Chunker, StringComparison.Ordinal) &&
        left.BlockSize == right.BlockSize;

    /// <remarks>
    /// <para>
    /// A path this machine ignores is left alone whatever either side did to it (D-56). The
    /// scan never lists it, so without this rule it read as deleted here: a peer's edit of it
    /// was "deleted here, modified there", which wrote the peer's version and moved this
    /// machine's own file aside. What it is here is this machine's business; where this
    /// machine's rules are its own, what the peer holds travels on in the snapshots, see
    /// <c>SipRepository.CarryIgnored</c>. A path the
    /// incoming snapshot's own <c>.sipignore</c> ignores is left alone too: that snapshot
    /// says nothing about it, so its absence there is not a deletion.
    /// </para>
    /// <para>
    /// A path that is a link here, or lies under one, is left alone the same way (DATA-01).
    /// The scan never follows a link, so what the peer holds under that name is not this
    /// folder's; writing or deleting it would act on wherever the link points.
    /// </para>
    /// <para>
    /// A read-only file is never overwritten or deleted (T-04). Where the rule would replace
    /// it, both are kept: it is moved aside, attribute and all, under a conflict name, and
    /// the peer's version takes the name. Where the rule would delete it, it stays, and the
    /// next save records it again. The pre-flight check used to open it for writing, which
    /// failed on the attribute and refused the whole apply: one read-only file the peer had
    /// touched stopped every other file arriving from that peer, for good.
    /// </para>
    /// <para>
    /// <paramref name="ignore"/> is what every path is judged by, <c>.sipignore</c> itself
    /// excepted, which is judged by <paramref name="ignoreFileRules"/>: the rules in force
    /// before the apply, which are what decide whether this machine syncs that file at all.
    /// The two differ only when the apply changes <c>.sipignore</c> (see <see cref="ApplyAsync"/>).
    /// </para>
    /// </remarks>
    private static MergePlan Plan(
        Dictionary<string, FileEntry> local,
        Dictionary<string, FileEntry> baseline,
        Dictionary<string, (FileEntry Entry, string Absolute)> remote,
        IgnoreRules ignore,
        IgnoreRules ignoreFileRules,
        IgnoreRules? incomingIgnore,
        WorkingTreeScan scan,
        string root)
    {
        var plan = new MergePlan();

        var paths = new SortedSet<string>(local.Keys, StringComparer.Ordinal);
        paths.UnionWith(remote.Keys);
        paths.UnionWith(baseline.Keys);

        foreach (var path in paths)
        {
            var rules = IsIgnoreFile(path) ? ignoreFileRules : ignore;
            if (rules.IsIgnored(path) || incomingIgnore?.IsIgnored(path) == true || scan.IsUnderLink(path))
            {
                continue;
            }

            local.TryGetValue(path, out var mine);
            baseline.TryGetValue(path, out var common);
            var theirs = remote.TryGetValue(path, out var incoming) ? incoming.Entry : null;

            if (Same(mine, theirs))
            {
                continue;
            }

            if (Same(mine, common))
            {
                // Only the remote side changed this path since the base.
                var readOnly = mine is not null && IsReadOnly(Absolute(root, mine.Path));
                if (theirs is null)
                {
                    if (readOnly)
                    {
                        plan.KeptReadOnly.Add(mine!.Path);
                    }
                    else
                    {
                        plan.Deletes.Add(mine!);
                    }
                }
                else if (readOnly)
                {
                    plan.Asides.Add(mine!);
                    plan.Writes.Add(new PlannedWrite(theirs, incoming.Absolute, Replacing: null));
                }
                else
                {
                    plan.Writes.Add(new PlannedWrite(theirs, incoming.Absolute, Replacing: mine));
                }

                continue;
            }

            if (Same(theirs, common))
            {
                // Only this side changed it. Keep it.
                continue;
            }

            // Both sides changed it, differently.
            if (mine is not null && theirs is not null)
            {
                plan.Asides.Add(mine);
                plan.Writes.Add(new PlannedWrite(theirs, incoming.Absolute, Replacing: null));
            }
            else if (theirs is not null)
            {
                // Deleted here, modified there: the modification is the only copy.
                plan.Writes.Add(new PlannedWrite(theirs, incoming.Absolute, Replacing: null));
            }

            // Modified here, deleted there: keep the modification, which is what falling
            // through does.
        }

        return plan;
    }

    /// <summary>The restore rule; see <see cref="RestoreAsync"/>.</summary>
    private static MergePlan PlanRestore(
        Dictionary<string, FileEntry> local,
        Dictionary<string, FileEntry> head,
        Dictionary<string, (FileEntry Entry, string Absolute)> target,
        IgnoreRules ignore,
        WorkingTreeScan scan,
        string root)
    {
        var plan = new MergePlan();

        // Keyed the way the filesystem compares names. A case-sensitive folder could hold two
        // names that fold together; the first is taken and the other is left alone, which is
        // never a deletion.
        var localFolded = new Dictionary<string, FileEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in local.Values)
        {
            localFolded.TryAdd(entry.Path, entry);
        }

        var headFolded = new Dictionary<string, FileEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in head.Values)
        {
            headFolded.TryAdd(entry.Path, entry);
        }

        var answered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (path, (wanted, absolute)) in target.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            if (ignore.IsIgnored(path) || scan.IsUnderLink(path))
            {
                continue;
            }

            if (!localFolded.TryGetValue(path, out var mine))
            {
                plan.Writes.Add(new PlannedWrite(wanted, absolute, Replacing: null));
                continue;
            }

            answered.Add(mine.Path);

            // The file's own name differs in case, not merely a folder above it: folder
            // casing is never changed, so a difference there alone needs no rename.
            var nameCaseOnly = !string.Equals(
                Path.GetFileName(mine.Path), Path.GetFileName(path), StringComparison.Ordinal);

            if (Same(mine, wanted))
            {
                if (nameCaseOnly)
                {
                    var from = Absolute(root, mine.Path);
                    plan.Renames.Add(new PlannedRename(
                        mine, from, Path.Combine(Path.GetDirectoryName(from)!, Path.GetFileName(absolute))));
                }

                continue;
            }

            var saved = headFolded.TryGetValue(path, out var recorded) && Same(mine, recorded);
            if (!saved || IsReadOnly(Absolute(root, mine.Path)))
            {
                plan.Asides.Add(mine);
                plan.Writes.Add(new PlannedWrite(wanted, absolute, Replacing: null));
            }
            else if (nameCaseOnly)
            {
                plan.Deletes.Add(mine);
                plan.Writes.Add(new PlannedWrite(wanted, absolute, Replacing: null));
            }
            else
            {
                plan.Writes.Add(new PlannedWrite(wanted, absolute, Replacing: mine));
            }
        }

        foreach (var mine in local.Values.Where(entry => !answered.Contains(entry.Path)))
        {
            if (scan.IsUnderLink(mine.Path))
            {
                continue;
            }

            // Only a file head records, unchanged since, is deleted: its content is in head.
            if (headFolded.TryGetValue(mine.Path, out var recorded) && Same(mine, recorded))
            {
                if (IsReadOnly(Absolute(root, mine.Path)))
                {
                    plan.KeptReadOnly.Add(mine.Path);
                }
                else
                {
                    plan.Deletes.Add(mine);
                }
            }
        }

        return plan;
    }

    /// <summary>
    /// True when the file carries the read-only attribute, which Windows documents as
    /// "Applications can read the file, but cannot write to it or delete it"
    /// (FILE_ATTRIBUTE_READONLY, https://learn.microsoft.com/windows/win32/fileio/file-attribute-constants).
    /// </summary>
    /// <remarks>
    /// A file that cannot be asked is taken as writable; the pre-flight check then finds out.
    /// Renaming one is not writing to it: measured on this desktop with .NET 10.0.12, a
    /// read-only file moves to a new name within its folder and keeps the attribute, which is
    /// what keeping one aside relies on and what the read-only tests exercise.
    /// </remarks>
    private static bool IsReadOnly(string absolute)
    {
        try
        {
            return (File.GetAttributes(absolute) & FileAttributes.ReadOnly) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Writes every incoming version in full, outside the working folder.</summary>
    /// <remarks>
    /// This is where the D-24 guarantee now lives on the apply side: every block was fetched
    /// before this runs, and a block that is missing or fails verification here throws while
    /// the working folder is still exactly as it was.
    /// </remarks>
    private static async Task<IReadOnlyList<string>> StageAsync(
        SipRepository repository,
        IReadOnlyList<PlannedWrite> writes,
        string staging,
        CancellationToken cancellationToken)
    {
        var staged = new List<string>(writes.Count);

        for (var i = 0; i < writes.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entry = writes[i].Entry;
            var temporary = Path.Combine(staging, i.ToString(CultureInfo.InvariantCulture));

            long written = 0;
            var output = SharingRetry.Run(() => new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 0, useAsync: true));

            await using (output.ConfigureAwait(false))
            {
                if (writes[i].Literal is { } literal)
                {
                    // A merged page: bytes made here, in no snapshot yet (see PlannedWrite).
                    await output.WriteAsync(literal, cancellationToken).ConfigureAwait(false);
                    written = literal.Length;
                }
                else
                {
                    foreach (var hash in entry.Blocks)
                    {
                        var block = await repository.Blobs.GetAsync(hash, cancellationToken)
                            .ConfigureAwait(false);
                        await output.WriteAsync(block, cancellationToken).ConfigureAwait(false);
                        written += block.Length;
                    }
                }
            }

            if (written != entry.Size)
            {
                throw new SipProtocolException(
                    SipProtocolFault.MalformedMessage,
                    $"The snapshot being applied says {entry.Path} is {entry.Size} bytes, but " +
                    $"its blocks hold {written}. Nothing was applied.");
            }

            File.SetLastWriteTimeUtc(temporary, entry.ModifiedUtc.UtcDateTime);
            staged.Add(temporary);
        }

        return staged;
    }

    /// <summary>
    /// Checks every file about to be replaced, moved or deleted, and every place a file is
    /// about to be written, before any of them is touched.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately does not wait out another program's hold, unlike every other file
    /// operation on <c>.sip</c> (D-69). This check is a view of the working folder taken just
    /// before it changes, and each second spent waiting here is a second in which that view
    /// goes stale for every file already checked. A held file defers the whole sync to the
    /// next cycle instead, with nothing changed, which costs a minute and never a file.
    /// </para>
    /// <para>
    /// The plan already leaves alone every path the scan found a link on, and every read-only
    /// file it would have overwritten or deleted. Both are asked again here, of the disk as it
    /// is now, because the scan was some time ago: a folder replaced by a link since then, or
    /// a file made read-only, stops the apply here with nothing changed, rather than letting a
    /// move go through the link or a delete fail half way through the changes.
    /// </para>
    /// </remarks>
    private static void Preflight(MergePlan plan, string root)
    {
        var links = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in plan.Deletes.Concat(plan.Asides).Concat(plan.Renames.Select(r => r.Entry)))
        {
            var absolute = Absolute(root, entry.Path);
            EnsureNoLinkAbove(absolute, entry.Path, root, links);
            EnsureUnchangedSinceScan(entry, absolute);
            EnsureNotHeldOpen(absolute, entry.Path);
        }

        foreach (var entry in plan.Deletes)
        {
            EnsureNotReadOnly(Absolute(root, entry.Path), entry.Path);
        }

        foreach (var write in plan.Writes)
        {
            EnsureNoLinkAbove(write.Absolute, write.Entry.Path, root, links);

            if (write.Replacing is { } replaced)
            {
                EnsureUnchangedSinceScan(replaced, write.Absolute);
                EnsureNotHeldOpen(write.Absolute, replaced.Path);
                EnsureNotReadOnly(write.Absolute, replaced.Path);
            }
            else if (File.Exists(write.Absolute))
            {
                // Something the scan did not record under this exact name is in the way: a
                // file differing only in case, an ignored file, or one created since. It will
                // be kept under a conflict name, so it must be movable.
                EnsureNotHeldOpen(write.Absolute, write.Entry.Path);
            }
        }
    }

    /// <summary>
    /// Fails with <see cref="WorkingTreeBusyException"/> when a folder between the working
    /// folder and <paramref name="absolute"/> is a link, so nothing is written, moved or
    /// deleted through one.
    /// </summary>
    private static void EnsureNoLinkAbove(
        string absolute,
        string relativePath,
        string root,
        Dictionary<string, bool> known)
    {
        for (var folder = Path.GetDirectoryName(absolute);
             folder is not null && folder.Length > root.Length;
             folder = Path.GetDirectoryName(folder))
        {
            if (!known.TryGetValue(folder, out var isLink))
            {
                isLink = IsLinkOrUnknown(folder);
                known[folder] = isLink;
            }

            if (isLink)
            {
                throw new WorkingTreeBusyException(
                    relativePath, "is under a folder that is now a link, which is never written through", null);
            }
        }
    }

    /// <summary>
    /// True when <paramref name="folder"/> is a junction or symbolic link, or when that cannot
    /// be told, which is treated the same way.
    /// </summary>
    private static bool IsLinkOrUnknown(string folder)
    {
        try
        {
            var info = new DirectoryInfo(folder);
            return info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0 && info.LinkTarget is not null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static void EnsureNotReadOnly(string absolute, string relativePath)
    {
        if (IsReadOnly(absolute))
        {
            throw new WorkingTreeBusyException(relativePath, "was made read-only while this sync was running", null);
        }
    }

    private static WorkingTreeMergeResult Mutate(
        MergePlan plan,
        IReadOnlyList<string> staged,
        string root,
        string conflictDeviceId,
        SipRepository repository,
        Action<string>? log)
    {
        var conflicts = new List<string>();
        var emptied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Deletions first, so a path the remote side moved to a different case, or turned
        // from a file into a folder, is clear before the new version arrives.
        foreach (var entry in plan.Deletes)
        {
            var absolute = Absolute(root, entry.Path);
            File.Delete(absolute);
            emptied.Add(Path.GetDirectoryName(absolute)!);
        }

        // A name that differs only in case: the same file, given the snapshot's casing. File.Move
        // does this in place on NTFS. That is not documented: the File.Move page says only
        // that it "does not throw an exception if the source and destination are the same"
        // (https://learn.microsoft.com/dotnet/api/system.io.file.move), not whether a name
        // differing in case counts as the same. It was measured on .NET 10.0.12 on the desktop,
        // and A_case_only_difference_is_a_rename_to_the_snapshots_casing pins it.
        foreach (var rename in plan.Renames)
        {
            File.Move(rename.From, rename.To, overwrite: false);
        }

        foreach (var entry in plan.Asides)
        {
            conflicts.Add(MoveAside(Absolute(root, entry.Path), conflictDeviceId, repository));
        }

        for (var i = 0; i < plan.Writes.Count; i++)
        {
            var write = plan.Writes[i];

            ClearParentFolders(write.Absolute, root, conflictDeviceId, repository, conflicts);

            if (Directory.Exists(write.Absolute))
            {
                // A folder where the remote side has a file. An empty one is what deletions
                // leave behind; anything still in it is kept, folder and all.
                if (Directory.EnumerateFileSystemEntries(write.Absolute).Any())
                {
                    conflicts.Add(MoveAside(write.Absolute, conflictDeviceId, repository));
                }
                else
                {
                    Directory.Delete(write.Absolute);
                }
            }

            // The staged file was written moments ago, so it is exactly what a scanner is
            // likely to be reading, and a rename needs the delete access such a hold denies.
            // Waited out rather than failed (D-69): by this point files are already changing,
            // and giving up half way would leave a folder matching neither side. The wait
            // lengthens the window between the pre-flight check and the change by at most
            // the patience, which is the smaller cost.
            var source = staged[i];
            if (write.Replacing is not null)
            {
                SharingRetry.Run(() => File.Move(source, write.Absolute, overwrite: true));
                continue;
            }

            if (File.Exists(write.Absolute))
            {
                conflicts.Add(MoveAside(write.Absolute, conflictDeviceId, repository));
            }

            SharingRetry.Run(() => File.Move(source, write.Absolute, overwrite: false));
        }

        PruneEmptiedFolders(emptied, root, log);

        return new WorkingTreeMergeResult
        {
            FilesWritten = plan.Writes.Count,
            FilesDeleted = plan.Deletes.Count,
            FilesRenamed = plan.Renames.Count,
            Conflicts = conflicts,
            KeptReadOnly = plan.KeptReadOnly,
        };
    }

    /// <summary>
    /// Makes sure every folder above <paramref name="absolute"/> is a folder, keeping any
    /// file standing where a folder must go.
    /// </summary>
    private static void ClearParentFolders(
        string absolute,
        string root,
        string conflictDeviceId,
        SipRepository repository,
        List<string> conflicts)
    {
        var parent = Path.GetDirectoryName(absolute)!;
        var chain = new Stack<string>();
        for (var folder = parent;
             folder.Length > root.Length && !string.Equals(folder, root, StringComparison.OrdinalIgnoreCase);
             folder = Path.GetDirectoryName(folder)!)
        {
            chain.Push(folder);
        }

        foreach (var folder in chain)
        {
            if (File.Exists(folder))
            {
                conflicts.Add(MoveAside(folder, conflictDeviceId, repository));
            }
        }

        Directory.CreateDirectory(parent);
    }

    /// <summary>Renames a file or folder to a free conflict name and returns that name.</summary>
    private static string MoveAside(string absolute, string conflictDeviceId, SipRepository repository)
    {
        var target = ConflictNameFor(absolute, conflictDeviceId);

        if (Directory.Exists(absolute))
        {
            Directory.Move(absolute, target);
        }
        else
        {
            File.Move(absolute, target, overwrite: false);
        }

        return repository.ToRelativePath(target);
    }

    /// <summary>
    /// Builds the name a local file is moved to when it has to make way. The device ID says
    /// which machine made the version the renamed file holds, which is always this one, and
    /// the timestamp says when it was moved; a counter keeps the name free when two conflicts
    /// on the same file land in the same second, which a criss-cross of merges does.
    /// </summary>
    /// <remarks>
    /// Syncthing's documentation gives its conflict name as
    /// <c>&lt;filename&gt;.sync-conflict-&lt;date&gt;-&lt;time&gt;-&lt;modifiedBy&gt;.&lt;ext&gt;</c>
    /// ("Conflicting Changes", https://docs.syncthing.net/users/syncing.html): the device
    /// field names who modified the renamed copy, which is the convention followed here. The
    /// name used to carry the other machine's ID, so a person asking "which machine made this
    /// version?" was told the wrong one (D-59).
    /// </remarks>
    private static string ConflictNameFor(string absolutePath, string localDeviceId)
    {
        var directory = Path.GetDirectoryName(absolutePath) ?? string.Empty;
        var stem = Path.GetFileNameWithoutExtension(absolutePath);
        var extension = Path.GetExtension(absolutePath);
        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var shortId = localDeviceId[..Math.Min(8, localDeviceId.Length)];

        var candidate = Path.Combine(directory, $"{stem}.conflict-{shortId}-{stamp}{extension}");
        for (var n = 2; File.Exists(candidate) || Directory.Exists(candidate); n++)
        {
            candidate = Path.Combine(
                directory,
                string.Create(CultureInfo.InvariantCulture, $"{stem}.conflict-{shortId}-{stamp}-{n}{extension}"));
        }

        return candidate;
    }

    private static void EnsureUnchangedSinceScan(FileEntry scanned, string absolute)
    {
        var info = new FileInfo(absolute);
        if (!info.Exists ||
            info.Length != scanned.Size ||
            new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero) != scanned.ModifiedUtc)
        {
            throw new WorkingTreeBusyException(
                scanned.Path, "changed while this sync was running", innerException: null);
        }
    }

    /// <summary>
    /// Fails with <see cref="WorkingTreeBusyException"/> when another program holds the file
    /// open in a way that would stop it being replaced, renamed or deleted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Opens the file for reading and shares nothing, which fails if any other program has it
    /// open at all. That is stricter than a rename needs: a program sharing everything but
    /// write access would let the rename through and still be refused here. That errs towards
    /// waiting a cycle, never towards changing a file under an editor.
    /// </para>
    /// <para>
    /// For reading, not for writing. It used to ask for write access too, which a read-only
    /// file refuses with an <see cref="UnauthorizedAccessException"/> that nothing caught, so
    /// one read-only file the peer had changed refused every apply from that peer (T-04).
    /// A file that cannot even be opened for reading is reported the same way as one held
    /// open, naming it, rather than as a bare access error.
    /// </para>
    /// </remarks>
    private static void EnsureNotHeldOpen(string absolute, string relativePath)
    {
        try
        {
            new FileStream(absolute, FileMode.Open, FileAccess.Read, FileShare.None).Dispose();
        }
        catch (IOException ex) when (ex.HResult is SharingViolation or LockViolation)
        {
            throw new WorkingTreeBusyException(relativePath, "is open in another program", ex);
        }
        catch (FileNotFoundException ex)
        {
            throw new WorkingTreeBusyException(relativePath, "was removed while this sync was running", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new WorkingTreeBusyException(relativePath, "cannot be opened here", ex);
        }
    }

    private static void PruneEmptiedFolders(HashSet<string> folders, string root, Action<string>? log)
    {
        foreach (var start in folders)
        {
            for (var folder = start;
                 folder.Length > root.Length && Directory.Exists(folder) &&
                 !Directory.EnumerateFileSystemEntries(folder).Any();
                 folder = Path.GetDirectoryName(folder)!)
            {
                try
                {
                    Directory.Delete(folder);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Something arrived in it since it was checked, or it cannot be removed.
                    // Either is a reason to keep an empty folder, not to fail a sync whose
                    // files have all been applied.
                    log?.Invoke($"kept folder {folder}: {ex.Message}");
                    break;
                }
            }
        }
    }

    private static void RemoveStaleStaging(string incoming, Action<string>? log)
    {
        if (!Directory.Exists(incoming))
        {
            return;
        }

        foreach (var folder in Directory.EnumerateDirectories(incoming))
        {
            if (DateTime.UtcNow - Directory.GetCreationTimeUtc(folder) > StaleStagingAge)
            {
                RemoveStaging(folder, log);
            }
        }
    }

    private static void RemoveStaging(string staging, Action<string>? log)
    {
        try
        {
            if (Directory.Exists(staging))
            {
                SharingRetry.Run(() => Directory.Delete(staging, recursive: true));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The apply itself is finished or failed on its own terms; a leftover staging
            // folder only costs disk, and the next apply removes it once it is a day old.
            log?.Invoke($"could not remove staging folder {staging}: {ex.Message}");
        }
    }

    private static string Absolute(string root, string relativePath) =>
        Path.GetFullPath(Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar)));

    private static bool Same(FileEntry? left, FileEntry? right)
    {
        if (left is null || right is null)
        {
            return left is null && right is null;
        }

        if (left.Size != right.Size || left.Blocks.Count != right.Blocks.Count)
        {
            return false;
        }

        for (var i = 0; i < left.Blocks.Count; i++)
        {
            if (left.Blocks[i] != right.Blocks[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <param name="Entry">What is written: the remote entry, or a synthesised one for a merged page.</param>
    /// <param name="Absolute">Where it lands.</param>
    /// <param name="Replacing">The scanned local entry it replaces in place, or null.</param>
    /// <param name="Literal">
    /// The exact bytes to stage, for a merged Markdown page whose content exists on neither
    /// side and so is in no snapshot's blocks yet; null stages from <paramref name="Entry"/>'s
    /// blocks as ever. The next save records it like anything else in the folder.
    /// </param>
    private sealed record PlannedWrite(FileEntry Entry, string Absolute, FileEntry? Replacing, byte[]? Literal = null);

    private sealed record PlannedRename(FileEntry Entry, string From, string To);

    private sealed class MergePlan
    {
        public List<FileEntry> Deletes { get; } = [];

        public List<PlannedRename> Renames { get; } = [];

        public List<FileEntry> Asides { get; } = [];

        public List<PlannedWrite> Writes { get; } = [];

        /// <summary>Read-only files the rule would have deleted, left where they are.</summary>
        public List<string> KeptReadOnly { get; } = [];

        public bool IsEmpty =>
            Deletes.Count == 0 && Renames.Count == 0 && Asides.Count == 0 && Writes.Count == 0;
    }
}

/// <summary>What a three-way apply changed in the working folder.</summary>
internal sealed record WorkingTreeMergeResult
{
    /// <summary>Files written with the remote version.</summary>
    public required int FilesWritten { get; init; }

    /// <summary>Files deleted because the remote side deleted them.</summary>
    public required int FilesDeleted { get; init; }

    /// <summary>Files renamed to a casing that differed only in case. Restore only.</summary>
    public int FilesRenamed { get; init; }

    /// <summary>Where local versions were kept, relative to the working folder.</summary>
    public required IReadOnlyList<string> Conflicts { get; init; }

    /// <summary>Read-only files left in place where the rule would have deleted them.</summary>
    public IReadOnlyList<string> KeptReadOnly { get; init; } = [];
}
