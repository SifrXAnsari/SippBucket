using System.Diagnostics.CodeAnalysis;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Repository;

namespace SippBucket.Core.Sync;

/// <summary>
/// This replica's ancestry index joined with what one peer said about its own history, for
/// the length of one pull.
/// </summary>
/// <remarks>
/// The peer's entries are claims. Where this replica can check one — a snapshot it holds, or
/// the peer's head, whose snapshot has been verified against its ID — the check is made
/// while the entries arrive and a contradiction drops the peer. The rest are believed for as
/// long as the pull runs, which gives a peer no power it does not already have: a peer holding
/// the repository key could as easily write a genuine snapshot that descends from ours and
/// deletes every file. That gap is D-21, unsigned snapshots, not this class.
/// </remarks>
internal sealed class AncestryGraph
{
    private readonly AncestryIndex _local;
    private readonly IReadOnlyDictionary<ContentHash, AncestryEntry> _learned;

    /// <summary>Joins the local index with a peer's entries.</summary>
    /// <param name="local">This replica's index, which wins where both know a snapshot.</param>
    /// <param name="learned">What the peer said, keyed by snapshot ID.</param>
    public AncestryGraph(AncestryIndex local, IReadOnlyDictionary<ContentHash, AncestryEntry> learned)
    {
        _local = local;
        _learned = learned;
    }

    /// <summary>
    /// True when <paramref name="candidate"/> is <paramref name="descendant"/> or reachable
    /// back from it.
    /// </summary>
    public bool IsAncestorOrSelf(ContentHash candidate, ContentHash descendant) =>
        !candidate.IsEmpty && Distances(descendant).ContainsKey(candidate);

    /// <summary>
    /// Every snapshot both heads descend from, the preferred merge base first.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Preferred means the smallest combined distance from the two heads — the ancestor
    /// that shares the most history with both, so the fewest paths look changed on both
    /// sides. It is not necessarily the unique lowest common ancestor; after a criss-cross of
    /// merges there are two, and any common ancestor is safe here, because a base that is
    /// further back than it could be makes the three-way rule call more paths "changed on
    /// both sides", and that rule keeps both versions. The cost of a worse base is spurious
    /// conflict copies, never a lost file.
    /// </para>
    /// <para>
    /// Ties go to the lexicographically smaller ID, and that is not cosmetic. Two machines
    /// that merge each other's heads at the same moment each compute a base from the same
    /// pair of heads; if they chose differently they could build different merged trees and
    /// go round again. Choosing the same base makes their merged trees the same, and the
    /// convergence rule in <see cref="SyncEngine"/> then settles them on one head.
    /// </para>
    /// </remarks>
    public IReadOnlyList<ContentHash> CommonAncestorsNearestFirst(ContentHash left, ContentHash right)
    {
        var fromLeft = Distances(left);
        var fromRight = Distances(right);

        return fromLeft
            .Where(pair => fromRight.ContainsKey(pair.Key))
            .Select(pair => (Id: pair.Key, Distance: pair.Value + fromRight[pair.Key], Hex: pair.Key.ToString()))
            .OrderBy(candidate => candidate.Distance)
            .ThenBy(candidate => candidate.Hex, StringComparer.Ordinal)
            .Select(candidate => candidate.Id)
            .ToList();
    }

    /// <summary>
    /// The peer's entries that join this replica's history: those from which some snapshot
    /// this replica already knows, or the first snapshot of the repository, can be reached.
    /// </summary>
    /// <returns>The entries worth keeping in the ancestry index.</returns>
    /// <remarks>
    /// <para>
    /// Only these are written to the index when a pull adopts or merges the peer's head. An
    /// entry that leads nowhere known is either the unfinished end of a walk that hit
    /// <see cref="SyncTuning.AncestryWalkLimit"/>, or history a peer made up; in both cases
    /// keeping it would add a permanent record per entry and answer nothing. A peer that
    /// invents parents without end would otherwise add up to the walk limit — a hundred
    /// thousand records — to this replica's index on every poll.
    /// </para>
    /// <para>
    /// A cycle, which no real history can contain because each ID hashes its parents, is
    /// treated as leading nowhere rather than walked forever.
    /// </para>
    /// </remarks>
    public IReadOnlyList<AncestryEntry> AnchoredLearnedEntries()
    {
        var anchored = new Dictionary<ContentHash, bool>();
        var visiting = new HashSet<ContentHash>();

        foreach (var start in _learned.Keys)
        {
            var pending = new Stack<(ContentHash Id, bool Expanded)>();
            pending.Push((start, false));

            while (pending.Count > 0)
            {
                var (id, expanded) = pending.Pop();
                if (anchored.ContainsKey(id))
                {
                    continue;
                }

                var entry = _learned[id];
                ContentHash[] parents = [.. new[] { entry.ParentId, entry.MergeParentId }.Where(p => !p.IsEmpty)];

                if (!expanded)
                {
                    if (!visiting.Add(id))
                    {
                        continue;
                    }

                    pending.Push((id, true));
                    foreach (var parent in parents)
                    {
                        if (_learned.ContainsKey(parent) && !anchored.ContainsKey(parent) && !visiting.Contains(parent))
                        {
                            pending.Push((parent, false));
                        }
                    }

                    continue;
                }

                anchored[id] = parents.Length == 0 || parents.Any(parent =>
                    _local.Contains(parent) || (anchored.TryGetValue(parent, out var joined) && joined));
            }
        }

        return [.. _learned.Values.Where(entry => anchored.TryGetValue(entry.Id, out var joined) && joined)];
    }

    /// <summary>
    /// Every snapshot reachable back from <paramref name="start"/>, with the fewest parent
    /// steps it takes to reach it.
    /// </summary>
    private Dictionary<ContentHash, int> Distances(ContentHash start)
    {
        var distances = new Dictionary<ContentHash, int>();
        if (start.IsEmpty)
        {
            return distances;
        }

        var pending = new Queue<ContentHash>();
        distances[start] = 0;
        pending.Enqueue(start);

        while (pending.Count > 0)
        {
            var id = pending.Dequeue();
            if (!TryGet(id, out var entry))
            {
                continue;
            }

            var next = distances[id] + 1;
            foreach (var parent in new[] { entry.ParentId, entry.MergeParentId })
            {
                if (!parent.IsEmpty && distances.TryAdd(parent, next))
                {
                    pending.Enqueue(parent);
                }
            }
        }

        return distances;
    }

    private bool TryGet(ContentHash id, [NotNullWhen(true)] out AncestryEntry? entry) =>
        _local.TryGet(id, out entry) || _learned.TryGetValue(id, out entry);
}
