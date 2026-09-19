using SippBucket.Core.Hashing;
using SippBucket.Core.Model;

namespace SippBucket.Core.Storage;

/// <summary>
/// Storage accounting and collection for one repository: what it holds, what it is allowed
/// to hold, and what could be released.
/// </summary>
/// <remarks>
/// <para>
/// This closes D-11, which was a real broken promise rather than a missing feature. Simple
/// mode trims the snapshot chain after every save so there is never any history to reason
/// about — but it never deleted the blocks those snapshots referred to. So the mode that
/// exists to stay small grew forever, and grew <em>faster</em> than Power mode would have,
/// because nothing was ever reachable to clean up.
/// </para>
/// <para>
/// Collection is mark-and-sweep over the snapshots head reaches — through both parents of a
/// merge, and past any snapshot this replica never held — and it is deliberately the dullest
/// possible implementation. A block is live if any of those snapshots names it. There is no
/// reference counting, because a count that drifts is worse than a walk that is slow: an
/// over-count wastes disk quietly and an under-count deletes a block some file still needs,
/// which turns a document into an unreadable one.
/// </para>
/// </remarks>
public sealed class VirtualBucket
{
    private readonly BlobStore _blobs;
    private readonly Func<CancellationToken, Task<IReadOnlyList<SnapshotRecord>>> _readChain;
    private readonly Func<ContentHash, bool> _deleteSnapshot;
    private readonly Func<ContentHash, bool> _isPinned;
    private readonly Func<IReadOnlyList<Snapshot>> _readKept;

    /// <summary>Creates a bucket over a repository's store and snapshot chain.</summary>
    /// <param name="blobs">The block store.</param>
    /// <param name="readChain">
    /// Reads the snapshots head reaches, head first and then newest first. See
    /// <see cref="Repository.SipRepository.GetHistoryAsync"/>.
    /// </param>
    /// <param name="deleteSnapshot">Deletes one snapshot file. Returns true if it existed.</param>
    /// <param name="isPinned">
    /// True for a snapshot the retention policy must never delete, whatever its age or
    /// place in the chain: a merge base kept for a peer (D-55). Null pins nothing.
    /// </param>
    /// <param name="readKept">
    /// Reads the snapshots kept outside the chain whose blocks must never be swept, whatever the
    /// policy: the changes peer health held (<see cref="Repository.HeldChanges"/>). Null for none.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public VirtualBucket(
        BlobStore blobs,
        Func<CancellationToken, Task<IReadOnlyList<SnapshotRecord>>> readChain,
        Func<ContentHash, bool> deleteSnapshot,
        Func<ContentHash, bool>? isPinned = null,
        Func<IReadOnlyList<Snapshot>>? readKept = null)
    {
        ArgumentNullException.ThrowIfNull(blobs);
        ArgumentNullException.ThrowIfNull(readChain);
        ArgumentNullException.ThrowIfNull(deleteSnapshot);

        _blobs = blobs;
        _readChain = readChain;
        _deleteSnapshot = deleteSnapshot;
        _isPinned = isPinned ?? (static _ => false);
        _readKept = readKept ?? (static () => []);
    }

    /// <summary>Measures what the store is using, and what could be freed.</summary>
    /// <param name="policy">The folder's retention and quota policy.</param>
    /// <param name="nowUtc">The current time, for age-based retention.</param>
    /// <param name="cancellationToken">Cancels the walk.</param>
    /// <returns>Usage, including the reclaimable figure.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="policy"/> was null.</exception>
    public async Task<BucketUsage> MeasureAsync(
        BucketPolicy policy,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var blocks = _blobs.List();
        var chain = await _readChain(cancellationToken).ConfigureAwait(false);

        var live = LiveBlocks(chain, policy, nowUtc, _isPinned, out var doomedSnapshots);
        AddKept(live);

        long used = 0;
        long reclaimable = 0;
        var unreferenced = 0;

        foreach (var block in blocks)
        {
            used += block.SizeInBytes;

            if (!live.Contains(block.Hash))
            {
                reclaimable += block.SizeInBytes;
                unreferenced++;
            }
        }

        return new BucketUsage
        {
            UsedBytes = used,
            QuotaBytes = policy.QuotaBytes,
            ReclaimableBytes = reclaimable,
            BlockCount = blocks.Count,
            SnapshotCount = chain.Count,
            UnreferencedBlockCount = unreferenced,
            PrunableSnapshotCount = doomedSnapshots,
        };
    }

    /// <summary>
    /// Deletes snapshots the policy no longer keeps, then every block nothing refers to.
    /// </summary>
    /// <param name="policy">The folder's retention and quota policy.</param>
    /// <param name="nowUtc">The current time, for age-based retention.</param>
    /// <param name="cancellationToken">Cancels the collection.</param>
    /// <returns>What was removed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="policy"/> was null.</exception>
    /// <remarks>
    /// Order matters and is not interchangeable. Snapshots go first, then the live set is
    /// recomputed from what survived, then blocks are swept. Sweeping first would compute a
    /// live set that includes snapshots about to be deleted, which is merely wasteful — but
    /// deleting snapshots while holding a stale live set would sweep blocks the survivors
    /// still need, which is data loss. The cheap mistake and the expensive one are one
    /// reordering apart.
    /// </remarks>
    public async Task<CollectionResult> CollectAsync(
        BucketPolicy policy,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var chain = await _readChain(cancellationToken).ConfigureAwait(false);

        var snapshotsRemoved = 0;
        if (policy.Prunes)
        {
            for (var i = 0; i < chain.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!policy.Keeps(i, chain[i].TakenUtc, nowUtc) && !_isPinned(chain[i].Id) &&
                    _deleteSnapshot(chain[i].Id))
                {
                    snapshotsRemoved++;
                }
            }
        }

        // Re-read rather than filtering the list in memory. What survives on disk is the
        // only authority on what the live set must protect.
        var survivors = await _readChain(cancellationToken).ConfigureAwait(false);
        var live = LiveBlocks(survivors, BucketPolicy.Unlimited, nowUtc, _isPinned, out _);
        AddKept(live);

        long bytesFreed = 0;
        var blocksRemoved = 0;

        foreach (var block in _blobs.List())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (live.Contains(block.Hash))
            {
                continue;
            }

            if (_blobs.Delete(block.Hash))
            {
                bytesFreed += block.SizeInBytes;
                blocksRemoved++;
            }
        }

        return new CollectionResult
        {
            SnapshotsRemoved = snapshotsRemoved,
            BlocksRemoved = blocksRemoved,
            BytesFreed = bytesFreed,
        };
    }

    /// <summary>Adds the blocks of every snapshot kept outside the chain: held changes, never swept.</summary>
    private void AddKept(HashSet<ContentHash> live)
    {
        foreach (var snapshot in _readKept())
        {
            AddReferenced(snapshot, live);
        }
    }

    /// <summary>
    /// The set of blocks referred to by every snapshot the policy keeps.
    /// </summary>
    private static HashSet<ContentHash> LiveBlocks(
        IReadOnlyList<SnapshotRecord> chain,
        BucketPolicy policy,
        DateTimeOffset nowUtc,
        Func<ContentHash, bool> isPinned,
        out int doomedSnapshots)
    {
        var live = new HashSet<ContentHash>();
        doomedSnapshots = 0;

        for (var i = 0; i < chain.Count; i++)
        {
            if (!policy.Keeps(i, chain[i].TakenUtc, nowUtc) && !isPinned(chain[i].Id))
            {
                doomedSnapshots++;
                continue;
            }

            AddReferenced(chain[i].Snapshot, live);
        }

        return live;
    }

    /// <summary>
    /// Adds every block a snapshot refers to: its files' blocks and, for a canonical snapshot,
    /// its trees, which are blocks too (D-23).
    /// </summary>
    /// <remarks>
    /// The trees are worked out from the files, which gives exactly the ones stored, because a
    /// tree is named by the hash of an encoding its files fix. A snapshot whose files cannot be
    /// a snapshot's never had trees written, and protects its blocks alone.
    /// </remarks>
    private static void AddReferenced(Snapshot snapshot, HashSet<ContentHash> live)
    {
        foreach (var file in snapshot.Files)
        {
            foreach (var hash in file.Blocks)
            {
                live.Add(hash);
            }
        }

        if (snapshot.Format != SnapshotFormat.Canonical)
        {
            return;
        }

        try
        {
            foreach (var tree in SnapshotTree.Build(snapshot.Files).Trees.Keys)
            {
                live.Add(tree);
            }
        }
        catch (ArgumentException)
        {
            // Not a list any tree was written for; see the remarks.
        }
    }
}

/// <summary>One snapshot in the chain, with what the collector needs to judge it.</summary>
/// <param name="Id">The snapshot's content hash.</param>
/// <param name="TakenUtc">When it was taken.</param>
/// <param name="Snapshot">Its contents, for the blocks it refers to.</param>
public sealed record SnapshotRecord(ContentHash Id, DateTimeOffset TakenUtc, Snapshot Snapshot);

/// <summary>What a collection removed.</summary>
public sealed record CollectionResult
{
    /// <summary>Snapshots deleted because the retention policy no longer kept them.</summary>
    public required int SnapshotsRemoved { get; init; }

    /// <summary>Blocks deleted because no surviving snapshot referred to them.</summary>
    public required int BlocksRemoved { get; init; }

    /// <summary>Bytes released.</summary>
    public required long BytesFreed { get; init; }

    /// <summary>True when nothing needed removing.</summary>
    public bool IsEmpty => SnapshotsRemoved == 0 && BlocksRemoved == 0;

    /// <summary>A one-line description ready to print.</summary>
    public string Summary =>
        IsEmpty
            ? "Nothing to reclaim."
            : $"Removed {SnapshotsRemoved} snapshot(s) and {BlocksRemoved} block(s), " +
              $"freeing {BucketUsage.Bytes(BytesFreed)}.";
}
