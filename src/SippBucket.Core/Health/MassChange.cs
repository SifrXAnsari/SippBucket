using System.Globalization;
using SippBucket.Core.Model;
using SippBucket.Core.Native;

namespace SippBucket.Core.Health;

/// <summary>What an incoming change did to a folder, and whether it looks like damage.</summary>
public sealed record MassChangeFindings
{
    /// <summary>How many files the folder had before the change.</summary>
    public int FilesBefore { get; init; }

    /// <summary>How many of them the change altered.</summary>
    public int Changed { get; init; }

    /// <summary>How many of them it deleted, renamed ones included.</summary>
    public int Deleted { get; init; }

    /// <summary>How many files it added, renamed ones included.</summary>
    public int Added { get; init; }

    /// <summary>How many altered or renamed files had their content judged before and after.</summary>
    public int Judged { get; init; }

    /// <summary>How many of those turned random-looking when they were not before.</summary>
    public int BecameRandom { get; init; }

    /// <summary>The one new extension most files were renamed to, when any were.</summary>
    public string? RenamedTo { get; init; }

    /// <summary>How many files were renamed to it.</summary>
    public int Renamed { get; init; }

    /// <summary>Why the change should be held, in phrases; empty when it should not.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];

    /// <summary>Whether the change should be held.</summary>
    public bool Hold => Reasons.Count > 0;

    /// <summary>The findings in one sentence, for the alert and the log.</summary>
    /// <param name="server">How to name the server that sent the change.</param>
    /// <param name="folder">The folder's name.</param>
    /// <returns>For example "Server 2 changed 4,000 files at once in 'docs': …".</returns>
    public string Describe(string server, string folder) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{server} changed {Changed + Deleted:N0} files at once in '{folder}': {string.Join("; ", Reasons)}. They were not copied here.");
}

/// <summary>
/// The mass-change check: whether a change another server sent looks like damage rather than
/// the person's own work, and so should be held instead of applied (docs/PEER-HEALTH.md, "The
/// case that matters most").
/// </summary>
/// <remarks>
/// <para>
/// <b>Three signs,</b> any one of which holds a change, with thresholds from the master
/// config's <c>health</c> section (<see cref="HealthSettings"/>), whose limits keep the check
/// on:
/// </para>
/// <list type="number">
/// <item><description>A large share of the folder's files changed or deleted, once the folder
/// holds enough files for a share to mean anything.</description></item>
/// <item><description>Files whose content turned random-looking when it was not before, judged
/// by the engine's randomness test (<c>sipe_randomness</c>) on each file's first 64 KiB, before
/// against after. Photos, videos and archives look random before as well as after, so they are
/// never counted. At least <see cref="MinimumBecameRandom"/> must turn, and the share among
/// those judged must reach the threshold.</description></item>
/// <item><description>A wave of renames to one extension the folder never had, as when
/// everything becomes <c>.locked</c>: <c>report.docx</c> to <c>report.docx.locked</c> or to
/// <c>report.locked</c>.</description></item>
/// </list>
/// <para>
/// <b>What it judges against.</b> What the folder held before the sender's change: the snapshot
/// both sides share for a merge, this machine's head for a fast-forward. So only the sender's
/// own changes count, never this machine's.
/// </para>
/// <para>
/// <b>What it costs.</b> Comparing file lists is cheap. Reading content is not, so at most
/// <see cref="MaximumJudged"/> files are judged, spread evenly through the changed and renamed
/// files in path order, the same files on every run. A file whose blocks are not held here
/// (the older side of a merge, trimmed in Simple mode) is passed over.
/// </para>
/// <para>
/// <b>What it cannot do.</b> Reorganising a folder, or deleting an old project, looks like the
/// first sign, which is why the person is asked and "That was me" is one command. A careful
/// attacker who changes a few files at a time is not a mass change. It never deletes or
/// undoes anything: it only decides whether to ask first.
/// </para>
/// </remarks>
public static class MassChange
{
    /// <summary>The most files whose content is judged for one change.</summary>
    public const int MaximumJudged = 64;

    /// <summary>The fewest files that must turn random-looking before the share of them counts.</summary>
    public const int MinimumBecameRandom = 5;

    // The engine's verdicts: SIPE_RANDOMNESS_STRUCTURED and SIPE_RANDOMNESS_RANDOM.
    private const uint Structured = 1;
    private const uint Random = 2;

    /// <summary>Judges a change.</summary>
    /// <param name="before">The files before the sender's change.</param>
    /// <param name="after">The files after it: the sender's snapshot.</param>
    /// <param name="readHead">
    /// Reads up to 64 KiB of a file's content from the blocks held here, or answers null when
    /// they are not all here.
    /// </param>
    /// <param name="settings">The thresholds.</param>
    /// <param name="cancellationToken">Cancels the reading.</param>
    /// <returns>What the change did, and whether to hold it.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public static async Task<MassChangeFindings> AssessAsync(
        IReadOnlyList<FileEntry> before,
        IReadOnlyList<FileEntry> after,
        Func<FileEntry, CancellationToken, Task<byte[]?>> readHead,
        HealthSettings settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        ArgumentNullException.ThrowIfNull(readHead);
        ArgumentNullException.ThrowIfNull(settings);

        var beforeByPath = before.ToDictionary(file => file.Path, StringComparer.Ordinal);
        var afterByPath = after.ToDictionary(file => file.Path, StringComparer.Ordinal);

        var pairs = new List<(FileEntry Before, FileEntry After)>();
        var changed = 0;
        foreach (var (path, old) in beforeByPath)
        {
            if (afterByPath.TryGetValue(path, out var now) && Differs(old, now))
            {
                changed++;
                pairs.Add((old, now));
            }
        }

        var deleted = beforeByPath.Keys.Where(path => !afterByPath.ContainsKey(path)).ToList();
        var added = afterByPath.Keys.Where(path => !beforeByPath.ContainsKey(path)).ToList();
        var (renamedTo, renames) = RenameWave(before, deleted, added);

        foreach (var (from, to) in renames)
        {
            pairs.Add((beforeByPath[from], afterByPath[to]));
        }

        var reasons = new List<string>();

        if (before.Count >= settings.MassChangeMinimumFiles &&
            (long)(changed + deleted.Count) * 100 >= (long)settings.MassChangePercent * before.Count)
        {
            reasons.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"it changed or deleted {changed + deleted.Count:N0} of the folder's {before.Count:N0} files"));
        }

        var (judged, becameRandom) = await JudgeAsync(pairs, readHead, cancellationToken).ConfigureAwait(false);
        if (becameRandom >= MinimumBecameRandom && (long)becameRandom * 100 >= (long)settings.RandomChangePercent * judged)
        {
            reasons.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"{becameRandom} of the {judged} changed files looked at turned random-looking, as encrypted files do"));
        }

        if (renamedTo is not null && renames.Count >= settings.RenameWaveMinimumFiles)
        {
            reasons.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"it renamed {renames.Count:N0} files to {renamedTo}, an extension the folder never had"));
        }

        return new MassChangeFindings
        {
            FilesBefore = before.Count,
            Changed = changed,
            Deleted = deleted.Count,
            Added = added.Count,
            Judged = judged,
            BecameRandom = becameRandom,
            RenamedTo = renamedTo,
            Renamed = renamedTo is null ? 0 : renames.Count,
            Reasons = reasons,
        };
    }

    /// <summary>Whether two versions of a file differ in content.</summary>
    /// <remarks>
    /// By block list when both were split the same way. Split two ways (a file saved before and
    /// after content-defined chunking, D-22), the lists differ for the same bytes, so only a
    /// change of size counts; re-reading every such file to be sure would cost a mass change's
    /// worth of reading on every sync after an upgrade.
    /// </remarks>
    private static bool Differs(FileEntry old, FileEntry now)
    {
        if (!string.Equals(old.Chunker, now.Chunker, StringComparison.Ordinal) ||
            (old.Chunker is null && old.BlockSize != now.BlockSize))
        {
            return old.Size != now.Size;
        }

        return !old.Blocks.SequenceEqual(now.Blocks);
    }

    /// <summary>The one new extension most deleted files reappeared under, and the pairs that did.</summary>
    private static (string? Extension, List<(string From, string To)> Pairs) RenameWave(
        IReadOnlyList<FileEntry> before,
        IReadOnlyList<string> deleted,
        IReadOnlyList<string> added)
    {
        var known = before
            .Select(file => Extension(file.Path))
            .Where(extension => extension.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var deletedSet = deleted.ToHashSet(StringComparer.Ordinal);
        var deletedByStem = deleted
            .GroupBy(Stem, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);

        var byExtension = new Dictionary<string, List<(string From, string To)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in added)
        {
            var extension = Extension(path);
            if (extension.Length == 0 || known.Contains(extension))
            {
                continue;
            }

            // report.docx to report.docx.locked, or report.docx to report.locked.
            var appendedTo = path[..^extension.Length];
            var from = deletedSet.Contains(appendedTo) ? appendedTo
                : deletedByStem.TryGetValue(Stem(path), out var sameStem) ? sameStem
                : null;

            if (from is null)
            {
                continue;
            }

            if (!byExtension.TryGetValue(extension, out var pairs))
            {
                pairs = [];
                byExtension[extension] = pairs;
            }

            pairs.Add((from, path));
        }

        var largest = byExtension
            .OrderByDescending(entry => entry.Value.Count)
            .ThenBy(entry => entry.Key, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        return largest.Value is null ? (null, []) : (largest.Key, largest.Value);
    }

    /// <summary>Judges up to <see cref="MaximumJudged"/> pairs, spread evenly in path order.</summary>
    private static async Task<(int Judged, int BecameRandom)> JudgeAsync(
        List<(FileEntry Before, FileEntry After)> pairs,
        Func<FileEntry, CancellationToken, Task<byte[]?>> readHead,
        CancellationToken cancellationToken)
    {
        var ordered = pairs.OrderBy(pair => pair.After.Path, StringComparer.Ordinal).ToList();
        var step = Math.Max(1.0, (double)ordered.Count / MaximumJudged);

        int judged = 0, becameRandom = 0;
        for (var i = 0.0; i < ordered.Count && judged < MaximumJudged; i += step)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (old, now) = ordered[(int)i];

            var beforeHead = await readHead(old, cancellationToken).ConfigureAwait(false);
            var afterHead = await readHead(now, cancellationToken).ConfigureAwait(false);
            if (beforeHead is null || afterHead is null)
            {
                continue;
            }

            var was = SipEngine.Randomness(beforeHead, beforeHead.Length).Verdict;
            var became = SipEngine.Randomness(afterHead, afterHead.Length).Verdict;
            if (was is not (Structured or Random) || became is not (Structured or Random))
            {
                continue;
            }

            judged++;
            if (was == Structured && became == Random)
            {
                becameRandom++;
            }
        }

        return (judged, becameRandom);
    }

    /// <summary>A path's last extension, with its dot, or empty.</summary>
    private static string Extension(string path)
    {
        var name = path[(path.LastIndexOf('/') + 1)..];
        var dot = name.LastIndexOf('.');
        return dot <= 0 ? string.Empty : name[dot..];
    }

    /// <summary>A path without its last extension.</summary>
    private static string Stem(string path) => path[..^Extension(path).Length];
}
