using System.Globalization;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;
using SippBucket.Core.Text;

namespace SippBucket.Cli;

/// <summary>
/// The read-only views of history: <c>sip show</c>, <c>sip diff</c>, <c>sip blame</c>, and
/// <c>sip log &lt;file&gt;</c>. Nothing here writes anything.
/// </summary>
internal static class HistoryCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary>The most bytes a file may have and still be diffed or blamed as lines.</summary>
    private const long LargestTextFile = 8 * 1024 * 1024;

    /// <summary>The most changed paths a stat list prints before summarising the rest.</summary>
    private const int LongestChangeList = 500;

    /// <summary>
    /// Resolves what a person typed into one snapshot held here: <c>head</c>, a full ID, a
    /// tag's name, or an unambiguous ID prefix, in that order.
    /// </summary>
    /// <param name="repository">The repository.</param>
    /// <param name="reference">What was typed.</param>
    /// <returns>The snapshot, or null with why not.</returns>
    /// <remarks>
    /// A tag wins over a prefix of the same spelling: the thing the owner named beats the
    /// thing that merely matches. An exact ID wins over both, which is why a tag cannot be
    /// named like one (<see cref="TagStore.IsValidName"/>).
    /// </remarks>
    public static async Task<(ContentHash Id, string? Problem)> ResolveAsync(
        SipRepository repository,
        string reference)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            return (default, "A snapshot is named by 'head', an ID, an ID prefix, or a tag.");
        }

        if (string.Equals(reference, "head", StringComparison.OrdinalIgnoreCase))
        {
            var head = repository.GetHead();
            return head.IsEmpty
                ? (default, "No snapshots yet. Run 'sip save'.")
                : (head, null);
        }

        if (ContentHash.TryParse(reference, out var exact))
        {
            return repository.HasSnapshot(exact)
                ? (exact, null)
                : (default, $"Snapshot {exact.ToShortString()} is not held on this machine.");
        }

        if (repository.Tags.Find(reference) is { } tag)
        {
            return repository.HasSnapshot(tag.SnapshotId)
                ? (tag.SnapshotId, null)
                : (default,
                    $"Tag '{DisplayText.Printable(tag.Name, TagStore.MaximumNameLength)}' names snapshot " +
                    $"{tag.SnapshotId.ToShortString()}, which this machine does not hold.");
        }

        var matches = (await repository.GetHistoryAsync().ConfigureAwait(false))
            .Select(entry => entry.SnapshotId)
            .Where(id => id.ToString().StartsWith(reference, StringComparison.OrdinalIgnoreCase))
            .Distinct()
            .ToList();

        return matches.Count switch
        {
            1 => (matches[0], null),
            0 => (default,
                $"Nothing here is called '{DisplayText.Printable(reference, 64)}': not a tag, and no " +
                "snapshot ID starts with it. 'sip log' lists snapshots; 'sip tag' lists tags."),
            _ => (default,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{DisplayText.Printable(reference, 64)}' starts {matches.Count} snapshot IDs; give more of it.")),
        };
    }

    /// <summary><c>sip show [&lt;snapshot&gt;] [&lt;file&gt;]</c>.</summary>
    /// <param name="args">What followed <c>show</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> ShowAsync(string[] args)
    {
        if (args.Length > 2)
        {
            return Usage("sip show [<snapshot>] [<file>] - at most a snapshot and a file.");
        }

        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());
        var (id, problem) = await ResolveAsync(repository, args.Length == 0 ? "head" : args[0])
            .ConfigureAwait(false);
        if (problem is not null)
        {
            return Fail(problem);
        }

        var snapshot = await repository.GetSnapshotAsync(id).ConfigureAwait(false);

        return args.Length == 2
            ? await ShowFileAsync(repository, id, snapshot, args[1]).ConfigureAwait(false)
            : await ShowSnapshotAsync(repository, id, snapshot).ConfigureAwait(false);
    }

    /// <summary>Prints one recorded file's bytes to standard output, exactly as saved.</summary>
    private static async Task<int> ShowFileAsync(
        SipRepository repository,
        ContentHash id,
        Snapshot snapshot,
        string path)
    {
        if (FindFile(snapshot, path) is not { } file)
        {
            return Fail($"Snapshot {id.ToShortString()} has no file '{DisplayText.Printable(path, 260)}'.");
        }

        try
        {
            var stdout = Console.OpenStandardOutput();
            await using (stdout.ConfigureAwait(false))
            {
                await repository.CopyFileToAsync(file, stdout).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is BlockNotFoundException or CorruptBlockException)
        {
            await Console.Error.WriteLineAsync().ConfigureAwait(false);
            return Fail($"That file cannot be read back here: {ex.Message}");
        }

        return ExitSuccess;
    }

    /// <summary>Prints a snapshot's record, and what it changed against its parent.</summary>
    private static async Task<int> ShowSnapshotAsync(
        SipRepository repository,
        ContentHash id,
        Snapshot snapshot)
    {
        Console.WriteLine($"snapshot  {id}");

        var canonical = snapshot.Format == SnapshotFormat.Canonical;
        Console.WriteLine($"format    {(canonical ? "canonical (v2)" : "legacy (JSON)")}");
        Console.WriteLine($"device    {DisplayText.Printable(snapshot.DeviceId, 64)}{LocalDeviceMark(snapshot.DeviceId)}");
        Console.WriteLine(
            $"date      {snapshot.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}");
        Console.WriteLine(snapshot.ParentId.IsEmpty
            ? "parent    none (first snapshot)"
            : $"parent    {snapshot.ParentId}");
        if (!snapshot.MergeParentId.IsEmpty)
        {
            Console.WriteLine($"merged    {snapshot.MergeParentId}");
        }

        if (canonical)
        {
            Console.WriteLine($"tree      {snapshot.Tree}");
            Console.WriteLine(SnapshotSigner.Verify(snapshot.DeviceId, id, snapshot.Signature)
                ? "signature verifies, by the device the snapshot names"
                : "signature DOES NOT VERIFY - this snapshot does not prove its maker");
        }
        else
        {
            Console.WriteLine("signature none: legacy snapshots predate signing");
        }

        Console.WriteLine($"message   {(string.IsNullOrWhiteSpace(snapshot.Message) ? "(no message)" : DisplayText.Printable(snapshot.Message, 500))}");
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"files     {snapshot.Files.Count} file(s), {BucketBytes(snapshot.TotalSize)}"));
        Console.WriteLine();

        if (snapshot.ParentId.IsEmpty)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"First snapshot: {snapshot.Files.Count} file(s) added."));
            return ExitSuccess;
        }

        if (!repository.HasSnapshot(snapshot.ParentId))
        {
            Console.WriteLine(
                $"Parent {snapshot.ParentId.ToShortString()} is not held on this machine, so there is no change list.");
            return ExitSuccess;
        }

        var parent = await repository.GetSnapshotAsync(snapshot.ParentId).ConfigureAwait(false);
        var changes = ChangesBetween(parent, snapshot);
        if (changes.Count == 0)
        {
            Console.WriteLine("No file changes against its parent.");
            return ExitSuccess;
        }

        Console.WriteLine($"Against parent {snapshot.ParentId.ToShortString()}:");
        foreach (var (kind, path) in changes.Take(LongestChangeList))
        {
            Console.WriteLine($"  {kind,-9} {path}");
        }

        if (changes.Count > LongestChangeList)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"  ... and {changes.Count - LongestChangeList} more"));
        }

        return ExitSuccess;
    }

    /// <summary><c>sip diff &lt;a&gt; &lt;b&gt; [&lt;file&gt;]</c>.</summary>
    /// <param name="args">What followed <c>diff</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> DiffAsync(string[] args)
    {
        if (args.Length is < 2 or > 3)
        {
            return Usage("sip diff <a> <b> [<file>] - two snapshots, oldest first reads best.");
        }

        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());

        var (fromId, fromProblem) = await ResolveAsync(repository, args[0]).ConfigureAwait(false);
        if (fromProblem is not null)
        {
            return Fail(fromProblem);
        }

        var (toId, toProblem) = await ResolveAsync(repository, args[1]).ConfigureAwait(false);
        if (toProblem is not null)
        {
            return Fail(toProblem);
        }

        if (fromId == toId)
        {
            Console.WriteLine("Those are the same snapshot.");
            return ExitSuccess;
        }

        var from = await repository.GetSnapshotAsync(fromId).ConfigureAwait(false);
        var to = await repository.GetSnapshotAsync(toId).ConfigureAwait(false);

        var only = args.Length == 3 ? NormalizePath(args[2]) : null;
        var fromFiles = ByPath(from);
        var toFiles = ByPath(to);

        var paths = fromFiles.Keys.Union(toFiles.Keys, StringComparer.Ordinal)
            .Where(path => only is null || string.Equals(path, only, StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (only is not null && paths.Count == 0)
        {
            return Fail($"Neither snapshot has a file '{DisplayText.Printable(only, 260)}'.");
        }

        Console.WriteLine($"diff {fromId.ToShortString()}..{toId.ToShortString()}");

        var added = 0;
        var removed = 0;
        var changed = 0;
        var unreadable = 0;

        foreach (var path in paths)
        {
            var before = fromFiles.GetValueOrDefault(path);
            var after = toFiles.GetValueOrDefault(path);

            if (before is not null && after is not null && before.Blocks.SequenceEqual(after.Blocks))
            {
                continue;
            }

            if (before is null)
            {
                added++;
            }
            else if (after is null)
            {
                removed++;
            }
            else
            {
                changed++;
            }

            Console.WriteLine();
            if (!await DiffOneFileAsync(repository, path, before, after).ConfigureAwait(false))
            {
                unreadable++;
            }
        }

        Console.WriteLine();
        if (added + removed + changed == 0)
        {
            Console.WriteLine("No differences.");
        }
        else
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{added + removed + changed} file(s) differ: {added} added, {changed} changed, {removed} removed."));
        }

        if (unreadable > 0)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{unreadable} of them could not be read back on this machine; the lines above say which."));
            return ExitFailure;
        }

        return ExitSuccess;
    }

    /// <summary>Diffs one path between the two snapshots. False when a side could not be read.</summary>
    private static async Task<bool> DiffOneFileAsync(
        SipRepository repository,
        string path,
        FileEntry? before,
        FileEntry? after)
    {
        byte[] beforeBytes;
        byte[] afterBytes;
        try
        {
            beforeBytes = before is null
                ? []
                : await repository.ReadFileAsync(before).ConfigureAwait(false);
            afterBytes = after is null
                ? []
                : await repository.ReadFileAsync(after).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is BlockNotFoundException or CorruptBlockException)
        {
            Console.WriteLine($"{path}: cannot be read back here: {ex.Message}");
            return false;
        }

        var beforeName = before is null ? "/dev/null" : $"a/{path}";
        var afterName = after is null ? "/dev/null" : $"b/{path}";

        if ((before?.Size ?? 0) > LargestTextFile || (after?.Size ?? 0) > LargestTextFile)
        {
            Console.WriteLine($"{path}: too large to diff as lines ({BucketBytes(Math.Max(before?.Size ?? 0, after?.Size ?? 0))}).");
            return true;
        }

        if (LineDiff.LooksBinary(beforeBytes) || LineDiff.LooksBinary(afterBytes))
        {
            Console.WriteLine($"Binary files {beforeName} and {afterName} differ.");
            return true;
        }

        var beforeText = SplitText.From(beforeBytes);
        var afterText = SplitText.From(afterBytes);
        var script = LineDiff.Compare(beforeText.Lines, afterText.Lines);

        foreach (var line in LineDiff.Unified(beforeName, afterName, beforeText, afterText, script))
        {
            Console.WriteLine(line);
        }

        return true;
    }

    /// <summary><c>sip blame &lt;file&gt;</c>: whose save each line of today's version is from.</summary>
    /// <param name="args">What followed <c>blame</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> BlameAsync(string[] args)
    {
        if (args.Length != 1)
        {
            return Usage("sip blame <file> - one file, as it is at head.");
        }

        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());
        var head = repository.GetHead();
        if (head.IsEmpty)
        {
            return Fail("No snapshots yet. Run 'sip save'.");
        }

        // Every held snapshot once, newest first, trees read once across the lot.
        var history = await repository.GetHistoryAsync().ConfigureAwait(false);
        var held = history.ToDictionary(entry => entry.SnapshotId, entry => entry.Snapshot);

        if (!held.TryGetValue(head, out var headSnapshot))
        {
            return Fail("Head could not be read back; 'sip verify' will say why.");
        }

        if (FindFile(headSnapshot, args[0]) is not { } file)
        {
            return Fail($"Head has no file '{DisplayText.Printable(args[0], 260)}'.");
        }

        if (file.Size > LargestTextFile)
        {
            return Fail($"That file is {BucketBytes(file.Size)}; blame reads lines, up to {BucketBytes(LargestTextFile)}.");
        }

        byte[] headBytes;
        try
        {
            headBytes = await repository.ReadFileAsync(file).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is BlockNotFoundException or CorruptBlockException)
        {
            return Fail($"That file cannot be read back here: {ex.Message}");
        }

        if (LineDiff.LooksBinary(headBytes))
        {
            return Fail("That file is binary; blame reads lines.");
        }

        var headText = SplitText.From(headBytes);
        var origins = await AttributeLinesAsync(repository, held, head, headSnapshot, file, headText)
            .ConfigureAwait(false);
        if (origins is null)
        {
            return Fail("A version of that file along its history cannot be read back here; 'sip verify' will say why.");
        }

        var labels = DeviceNames.For(repository);
        var width = Math.Min(16, Math.Max(3, origins.Where(origin => !origin.IsEmpty)
            .Select(origin => Label(labels, held, origin).Length).DefaultIfEmpty(3).Max()));

        for (var i = 0; i < headText.Lines.Count; i++)
        {
            var origin = origins[i];
            var when = origin.IsEmpty || !held.TryGetValue(origin, out var snapshot)
                ? "         ?"
                : snapshot.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            var shortId = origin.IsEmpty ? "????????????" : origin.ToShortString();

            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{shortId}  {Label(labels, held, origin).PadRight(width)}  {when}  {i + 1,5}) {headText.Lines[i]}"));
        }

        Console.WriteLine();
        Console.WriteLine("Blame follows this machine's held history along first parents; a merge's other");
        Console.WriteLine("side is credited to the merge. 'sip log " + DisplayText.Printable(args[0], 260) + "' lists the saves themselves.");
        return ExitSuccess;
    }

    /// <summary>
    /// Walks the first-parent chain, attributing each of today's lines to the snapshot that
    /// introduced it. Null when a version on the way cannot be read back.
    /// </summary>
    private static async Task<ContentHash[]?> AttributeLinesAsync(
        SipRepository repository,
        Dictionary<ContentHash, Snapshot> held,
        ContentHash head,
        Snapshot headSnapshot,
        FileEntry headFile,
        SplitText headText)
    {
        var origins = new ContentHash[headText.Lines.Count];

        // map[i]: which head line the i-th line of the version under the cursor became, or
        // -1 for a line that never reaches head.
        var map = new int[headText.Lines.Count];
        for (var i = 0; i < map.Length; i++)
        {
            map[i] = i;
        }

        var atId = head;
        var at = headSnapshot;
        var atLines = headText.Lines;
        var atFile = headFile;

        while (true)
        {
            Snapshot? parent = null;
            FileEntry? parentFile = null;
            if (!at.ParentId.IsEmpty && held.TryGetValue(at.ParentId, out parent))
            {
                parentFile = FindFile(parent, atFile.Path);
            }

            if (parent is null || parentFile is null)
            {
                // The chain ends here - the first snapshot, a gap in what this machine
                // holds, or the file first appearing. Whatever is still unattributed was
                // written by the version under the cursor.
                foreach (var headLine in map)
                {
                    if (headLine >= 0 && origins[headLine].IsEmpty)
                    {
                        origins[headLine] = atId;
                    }
                }

                return origins;
            }

            IReadOnlyList<string> parentLines;
            if (parentFile.Blocks.SequenceEqual(atFile.Blocks))
            {
                parentLines = atLines;
            }
            else
            {
                byte[] parentBytes;
                try
                {
                    parentBytes = await repository.ReadFileAsync(parentFile).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is BlockNotFoundException or CorruptBlockException)
                {
                    return null;
                }

                if (LineDiff.LooksBinary(parentBytes))
                {
                    // The file was binary back then: everything still open was written since.
                    foreach (var headLine in map)
                    {
                        if (headLine >= 0 && origins[headLine].IsEmpty)
                        {
                            origins[headLine] = atId;
                        }
                    }

                    return origins;
                }

                parentLines = SplitText.From(parentBytes).Lines;
            }

            var nextMap = new int[parentLines.Count];
            for (var i = 0; i < nextMap.Length; i++)
            {
                nextMap[i] = -1;
            }

            foreach (var line in LineDiff.Compare(parentLines, atLines))
            {
                if (line.Change == LineChange.Same)
                {
                    nextMap[line.BeforeLine] = map[line.AfterLine];
                }
                else if (line.Change == LineChange.Added)
                {
                    var headLine = map[line.AfterLine];
                    if (headLine >= 0 && origins[headLine].IsEmpty)
                    {
                        origins[headLine] = atId;
                    }
                }
            }

            atId = at.ParentId;
            at = parent;
            atLines = parentLines;
            atFile = parentFile;
            map = nextMap;
        }
    }

    /// <summary><c>sip log &lt;file&gt;</c>: the saves that changed one file, newest first.</summary>
    /// <param name="repository">The open repository.</param>
    /// <param name="path">The file asked about.</param>
    /// <param name="limit">The most events to print.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> FileHistoryAsync(SipRepository repository, string path, int limit)
    {
        var normalized = NormalizePath(path);
        var history = await repository.GetHistoryAsync().ConfigureAwait(false);
        var held = history.ToDictionary(entry => entry.SnapshotId, entry => entry.Snapshot);

        var printed = 0;
        foreach (var entry in history)
        {
            if (printed >= limit)
            {
                break;
            }

            var mine = FindFile(entry.Snapshot, normalized);

            // A first snapshot's "no parent" is known-empty, which is not the same as a
            // parent this machine no longer holds: only the former can call a file added.
            var parentKnown = entry.Snapshot.ParentId.IsEmpty;
            FileEntry? parents = null;
            if (!parentKnown && held.TryGetValue(entry.Snapshot.ParentId, out var parentSnapshot))
            {
                parentKnown = true;
                parents = FindFile(parentSnapshot, normalized);
            }

            var kind = (mine, parents) switch
            {
                (null, null) => null,
                (null, not null) => "removed",
                (not null, null) => parentKnown ? "added" : "present",
                _ => mine!.Blocks.SequenceEqual(parents!.Blocks) ? null : "changed",
            };

            if (kind is null)
            {
                continue;
            }

            var when = entry.Snapshot.CreatedUtc.ToLocalTime()
                .ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            var who = entry.Snapshot.DeviceId[..Math.Min(8, entry.Snapshot.DeviceId.Length)];
            var what = string.IsNullOrWhiteSpace(entry.Snapshot.Message)
                ? "(no message)"
                : entry.Snapshot.Message;

            Console.WriteLine($"{entry.SnapshotId.ToShortString()}  {when}  {who}  {kind,-7}  {what}");
            printed++;
        }

        if (printed == 0)
        {
            Console.WriteLine(
                $"No held snapshot records a change to '{DisplayText.Printable(normalized, 260)}'. " +
                "A rename reads as a remove and an add, under each name.");
        }

        return ExitSuccess;
    }

    /// <summary>Finds a file in a snapshot by path: exactly first, then ignoring case if unique.</summary>
    private static FileEntry? FindFile(Snapshot snapshot, string path)
    {
        var normalized = NormalizePath(path);

        FileEntry? relaxed = null;
        var relaxedMatches = 0;
        foreach (var file in snapshot.Files)
        {
            if (string.Equals(file.Path, normalized, StringComparison.Ordinal))
            {
                return file;
            }

            if (string.Equals(file.Path, normalized, StringComparison.OrdinalIgnoreCase))
            {
                relaxed = file;
                relaxedMatches++;
            }
        }

        return relaxedMatches == 1 ? relaxed : null;
    }

    /// <summary>Snapshot paths use forward slashes; what a person types on Windows may not.</summary>
    private static string NormalizePath(string path)
    {
        var normalized = path.Replace('\\', '/');
        while (normalized.StartsWith("./", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }

        return normalized.TrimStart('/');
    }

    private static Dictionary<string, FileEntry> ByPath(Snapshot snapshot)
    {
        var files = new Dictionary<string, FileEntry>(StringComparer.Ordinal);
        foreach (var file in snapshot.Files)
        {
            files[file.Path] = file;
        }

        return files;
    }

    /// <summary>What each snapshot changed against another, ordered by path.</summary>
    private static List<(string Kind, string Path)> ChangesBetween(Snapshot from, Snapshot to)
    {
        var before = ByPath(from);
        var after = ByPath(to);
        var changes = new List<(string Kind, string Path)>();

        foreach (var path in before.Keys.Union(after.Keys, StringComparer.Ordinal)
                     .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            var was = before.GetValueOrDefault(path);
            var now = after.GetValueOrDefault(path);
            if (was is null)
            {
                changes.Add(("added", path));
            }
            else if (now is null)
            {
                changes.Add(("removed", path));
            }
            else if (!was.Blocks.SequenceEqual(now.Blocks))
            {
                changes.Add(("modified", path));
            }
        }

        return changes;
    }

    /// <summary>" (this machine)" when the device is this one, else nothing.</summary>
    private static string LocalDeviceMark(string deviceId)
    {
        try
        {
            using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
            return DeviceIdentity.IsSameDevice(identity.DeviceId, deviceId) ? "  (this machine)" : string.Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            return string.Empty;
        }
    }

    private static string Label(
        Dictionary<string, string> labels,
        Dictionary<ContentHash, Snapshot> held,
        ContentHash origin) =>
        origin.IsEmpty || !held.TryGetValue(origin, out var snapshot)
            ? "?"
            : DeviceNames.Label(labels, snapshot.DeviceId);

    /// <summary>Sizes in the words the rest of the CLI uses.</summary>
    private static string BucketBytes(long bytes) => BucketUsage.Bytes(bytes);

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitFailure;
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitUsage;
    }
}
