using System.Text.Json;
using SippBucket.Core.Hashing;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>A bisect in progress: what the owner has marked so far.</summary>
public sealed record BisectState
{
    /// <summary>The newest snapshot known to carry the problem.</summary>
    public required ContentHash Bad { get; init; }

    /// <summary>Snapshots known not to carry it. May be empty while only bad is marked.</summary>
    public required IReadOnlyList<ContentHash> Good { get; init; }

    /// <summary>Head when the bisect started, so the owner can restore back to it.</summary>
    public required ContentHash StartedAtHead { get; init; }

    /// <summary>When the bisect started, in UTC.</summary>
    public required DateTimeOffset StartedUtc { get; init; }
}

/// <summary>What the marks so far say, and what to test next.</summary>
public sealed record BisectPlan
{
    /// <summary>Snapshots that could still be the first bad one, bad itself included.</summary>
    public required IReadOnlyList<ContentHash> Suspects { get; init; }

    /// <summary>
    /// The culprit, when the suspects have narrowed to one. Empty while more marks are needed.
    /// </summary>
    public ContentHash Culprit { get; init; }

    /// <summary>
    /// The snapshot to test next: the held suspect that splits the remaining range most
    /// evenly. Empty when there is a culprit, or when no suspect but bad itself is held here.
    /// </summary>
    public ContentHash Next { get; init; }

    /// <summary>
    /// How many marks the remaining range is worth, roughly: log2 of the suspect count.
    /// </summary>
    public int StepsLeft =>
        Suspects.Count <= 1 ? 0 : (int)Math.Ceiling(Math.Log2(Suspects.Count));
}

/// <summary>
/// <c>sip bisect</c>: finds the first snapshot that carries a problem, by halving.
/// </summary>
/// <remarks>
/// <para>
/// The owner marks one snapshot bad and at least one good; every snapshot that is an
/// ancestor of the bad one and not an ancestor of any good one is suspect. The suggestion
/// each round is the suspect that splits the remaining set most evenly by ancestry — the
/// same measure git bisect uses — restricted to snapshots this machine holds, because a
/// suggestion that cannot be restored cannot be tested. The owner restores it, looks, and
/// marks it; one snapshot remains after about log2 of them.
/// </para>
/// <para>
/// The walk runs over the ancestry index, so it sees through snapshots this replica no
/// longer holds as files, and it stops where the index stops: after Simple mode's
/// compaction, "as far as this machine's history knows" is the honest limit. Marks are
/// judged by that same index, and a mark it does not know is refused rather than guessed
/// about. Nothing here touches the working folder — restoring a suggestion is the owner's
/// own <c>sip restore</c>, which keeps unsaved work aside as it always does.
/// </para>
/// </remarks>
public static class Bisect
{
    /// <summary>Works out the suspects and the next snapshot to test.</summary>
    /// <param name="ancestry">The folder's ancestry index.</param>
    /// <param name="isHeld">Whether a snapshot is held here as a file, so it can be restored.</param>
    /// <param name="state">The marks so far.</param>
    /// <returns>The plan.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <exception cref="ArgumentException">
    /// The marks contradict each other: the bad snapshot is an ancestor of a good one, so
    /// every suspect is ruled out.
    /// </exception>
    public static BisectPlan Plan(
        AncestryIndex ancestry,
        Func<ContentHash, bool> isHeld,
        BisectState state)
    {
        ArgumentNullException.ThrowIfNull(ancestry);
        ArgumentNullException.ThrowIfNull(isHeld);
        ArgumentNullException.ThrowIfNull(state);

        var cleared = new HashSet<ContentHash>();
        foreach (var good in state.Good)
        {
            AddAncestorsOrSelf(ancestry, good, cleared);
        }

        var suspects = new HashSet<ContentHash>();
        AddAncestorsOrSelf(ancestry, state.Bad, suspects);
        suspects.ExceptWith(cleared);

        if (suspects.Count == 0)
        {
            throw new ArgumentException(
                "The marks contradict each other: the bad snapshot is in a good one's " +
                "history, so nothing is left to suspect. Check which snapshot was really bad.");
        }

        // Deterministic order, so the same marks always name the same next step.
        var ordered = suspects.OrderBy(id => id.ToString(), StringComparer.Ordinal).ToList();

        if (ordered.Count == 1)
        {
            return new BisectPlan { Suspects = ordered, Culprit = ordered[0] };
        }

        // The best next test splits the suspects most evenly: score each held suspect by
        // how many suspects its own history covers, and take the one whose smaller side is
        // largest. Bad itself is already known bad, so it is never suggested.
        var best = default(ContentHash);
        var bestScore = -1;
        foreach (var candidate in ordered)
        {
            if (candidate == state.Bad || !isHeld(candidate))
            {
                continue;
            }

            var covered = new HashSet<ContentHash>();
            AddAncestorsOrSelf(ancestry, candidate, covered, suspects);
            var score = Math.Min(covered.Count, ordered.Count - covered.Count);
            if (score > bestScore)
            {
                bestScore = score;
                best = candidate;
            }
        }

        return new BisectPlan { Suspects = ordered, Next = best };
    }

    /// <summary>
    /// Adds a snapshot and every ancestor the index knows to <paramref name="into"/>,
    /// staying inside <paramref name="within"/> when one is given.
    /// </summary>
    private static void AddAncestorsOrSelf(
        AncestryIndex ancestry,
        ContentHash start,
        HashSet<ContentHash> into,
        HashSet<ContentHash>? within = null)
    {
        var pending = new Stack<ContentHash>();
        pending.Push(start);

        while (pending.Count > 0)
        {
            var id = pending.Pop();
            if (id.IsEmpty || (within is not null && !within.Contains(id)) || !into.Add(id))
            {
                continue;
            }

            if (ancestry.TryGet(id, out var entry))
            {
                pending.Push(entry.ParentId);
                pending.Push(entry.MergeParentId);
            }
        }
    }
}

/// <summary>Reads and writes the bisect file, <c>.sip/bisect.json</c>.</summary>
public sealed class BisectStore
{
    private const int CurrentSchema = 1;

    private readonly string _path;

    /// <summary>Creates a store over one repository's bisect file.</summary>
    /// <param name="path">The file, <see cref="RepositoryLayout.BisectFile"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="path"/> was null or blank.</exception>
    public BisectStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    /// <summary>Reads the bisect in progress, or null when there is none.</summary>
    /// <exception cref="FormatException">The file exists and is not a bisect file.</exception>
    /// <exception cref="IOException">The file exists and could not be read.</exception>
    public BisectState? Load()
    {
        byte[] bytes;
        try
        {
            bytes = SharingRetry.Run(() => File.ReadAllBytes(_path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        StoredFile? stored;
        try
        {
            stored = JsonSerializer.Deserialize<StoredFile>(bytes, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new FormatException(
                $"The bisect file is not readable: {ex.Message} 'sip bisect reset' deletes it.", ex);
        }

        return stored is null
            ? throw new FormatException("The bisect file holds no bisect object. 'sip bisect reset' deletes it.")
            : stored.State;
    }

    /// <summary>Writes the bisect in progress, whole.</summary>
    /// <param name="state">The marks so far.</param>
    /// <exception cref="ArgumentNullException"><paramref name="state"/> was null.</exception>
    public void Save(BisectState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new StoredFile { Schema = CurrentSchema, State = state }, SipJson.Readable);

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

    /// <summary>Ends the bisect, deleting the file.</summary>
    /// <returns>True when one was in progress.</returns>
    public bool Clear()
    {
        if (!File.Exists(_path))
        {
            return false;
        }

        SharingRetry.Run(() => File.Delete(_path));
        return true;
    }

    private sealed record StoredFile
    {
        public required int Schema { get; init; }

        public required BisectState State { get; init; }
    }
}
