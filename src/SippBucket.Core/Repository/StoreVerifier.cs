using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>One thing <c>sip verify</c> found wrong, in words ready to print.</summary>
/// <param name="What">The finding.</param>
public sealed record VerifyProblem(string What);

/// <summary>How far a verify has got, reported as it walks.</summary>
/// <param name="Phase">Which part is being checked.</param>
/// <param name="Done">Items checked so far in this phase.</param>
/// <param name="Total">Items this phase will check.</param>
public sealed record VerifyProgress(string Phase, int Done, int Total);

/// <summary>What a verify of the whole store found.</summary>
public sealed record VerifyReport
{
    /// <summary>How many snapshot files were checked.</summary>
    public required int SnapshotsChecked { get; init; }

    /// <summary>How many distinct blocks were read, decrypted and re-hashed.</summary>
    public required int BlocksChecked { get; init; }

    /// <summary>Blocks in the store that no snapshot names: reclaimable, not damage.</summary>
    public required int UnreferencedBlocks { get; init; }

    /// <summary>Everything wrong, in the order found. Empty is the good answer.</summary>
    public required IReadOnlyList<VerifyProblem> Problems { get; init; }

    /// <summary>True when nothing is wrong.</summary>
    public bool IsClean => Problems.Count == 0;
}

/// <summary>
/// <c>sip verify</c>: reads every snapshot and every block the snapshots name, and checks
/// each against its own hash, so "the store is intact" is a measured claim and not a hope.
/// </summary>
/// <remarks>
/// <para>
/// Everything in the store is content-addressed, so verification is reading: a snapshot
/// file authenticates under its ID, a tree under its hash, a block decrypts and its
/// plaintext re-hashes to its name. A canonical snapshot must also carry a signature by the
/// device it names (D-21). Anything that fails is reported with its place; nothing is
/// repaired, because the repair for a damaged block is fetching it again from a peer, and
/// deciding that is the owner's, not a verifier's.
/// </para>
/// <para>
/// Blocks no snapshot names are counted, not condemned: they are what <c>sip bucket
/// collect</c> reclaims. Reads take the same path every other reader takes, so what verify
/// passes is what a restore or a served peer would actually get.
/// </para>
/// </remarks>
public static class StoreVerifier
{
    /// <summary>Checks the whole store.</summary>
    /// <param name="repository">The repository to check.</param>
    /// <param name="progress">Told how far the walk has got, or null.</param>
    /// <param name="cancellationToken">Cancels the walk.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="repository"/> was null.</exception>
    public static async Task<VerifyReport> VerifyAsync(
        SipRepository repository,
        Action<VerifyProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repository);

        var problems = new List<VerifyProblem>();
        var referenced = new HashSet<ContentHash>();
        var snapshotIds = SnapshotFiles(repository);

        var head = repository.GetHead();
        if (!head.IsEmpty && !snapshotIds.Contains(head))
        {
            problems.Add(new VerifyProblem(
                $"head names snapshot {head.ToShortString()} and no file holds it"));
        }

        var done = 0;
        foreach (var id in snapshotIds)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await VerifySnapshotAsync(repository, id, referenced, problems, cancellationToken)
                .ConfigureAwait(false);

            progress?.Invoke(new VerifyProgress("snapshots", ++done, snapshotIds.Count));
        }

        var blocksChecked = 0;
        done = 0;
        foreach (var hash in referenced)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                _ = await repository.Blobs.GetAsync(hash, cancellationToken).ConfigureAwait(false);
                blocksChecked++;
            }
            catch (BlockNotFoundException)
            {
                problems.Add(new VerifyProblem(
                    $"block {hash.ToShortString()} is named by a snapshot and is not in the store"));
            }
            catch (CorruptBlockException)
            {
                problems.Add(new VerifyProblem(
                    $"block {hash.ToShortString()} does not authenticate: its bytes are not what its name promises"));
            }

            progress?.Invoke(new VerifyProgress("blocks", ++done, referenced.Count));
        }

        var unreferenced = repository.Blobs.List().Count(block => !referenced.Contains(block.Hash));

        return new VerifyReport
        {
            SnapshotsChecked = snapshotIds.Count,
            BlocksChecked = blocksChecked,
            UnreferencedBlocks = unreferenced,
            Problems = problems,
        };
    }

    /// <summary>
    /// Checks one snapshot: it reads back under its ID, its trees materialize, a canonical
    /// one is signed by the device it names, and the ancestry index tells the same parents.
    /// Its blocks and trees join <paramref name="referenced"/> for the block pass.
    /// </summary>
    private static async Task VerifySnapshotAsync(
        SipRepository repository,
        ContentHash id,
        HashSet<ContentHash> referenced,
        List<VerifyProblem> problems,
        CancellationToken cancellationToken)
    {
        Snapshot? snapshot;
        try
        {
            snapshot = await repository.TryGetSnapshotAsync(id, cancellationToken).ConfigureAwait(false);
        }
        catch (SnapshotNotFoundException ex)
        {
            problems.Add(new VerifyProblem($"snapshot {id.ToShortString()} does not read back: {ex.Message}"));
            return;
        }
        catch (CorruptBlockException)
        {
            problems.Add(new VerifyProblem(
                $"snapshot {id.ToShortString()}, or one of its trees, does not authenticate"));
            return;
        }

        if (snapshot is null)
        {
            // The file was deleted between the listing and the read: a Simple-mode trim in
            // another process. Not damage.
            return;
        }

        if (snapshot.Format == SnapshotFormat.Canonical &&
            !SnapshotSigner.Verify(snapshot.DeviceId, id, snapshot.Signature))
        {
            problems.Add(new VerifyProblem(
                $"snapshot {id.ToShortString()} is not signed by the device it names"));
        }

        if (repository.Ancestry.TryGet(id, out var entry))
        {
            if (entry.ParentId != snapshot.ParentId || entry.MergeParentId != snapshot.MergeParentId)
            {
                problems.Add(new VerifyProblem(
                    $"the ancestry index records different parents for snapshot {id.ToShortString()} than the snapshot itself"));
            }
        }
        else
        {
            problems.Add(new VerifyProblem(
                $"snapshot {id.ToShortString()} is missing from the ancestry index (a save or sync repairs this)"));
        }

        foreach (var file in snapshot.Files)
        {
            foreach (var hash in file.Blocks)
            {
                referenced.Add(hash);
            }
        }

        if (snapshot.Format == SnapshotFormat.Canonical)
        {
            try
            {
                foreach (var tree in SnapshotTree.Build(snapshot.Files).Trees.Keys)
                {
                    referenced.Add(tree);
                }
            }
            catch (ArgumentException)
            {
                problems.Add(new VerifyProblem(
                    $"snapshot {id.ToShortString()} lists files that cannot be a snapshot's"));
            }
        }
    }

    /// <summary>Every snapshot file present, by the ID its name claims.</summary>
    private static List<ContentHash> SnapshotFiles(SipRepository repository)
    {
        var ids = new List<ContentHash>();
        if (!Directory.Exists(repository.Layout.SnapshotsDirectory))
        {
            return ids;
        }

        foreach (var path in Directory.EnumerateFiles(repository.Layout.SnapshotsDirectory, "*.json"))
        {
            if (ContentHash.TryParse(Path.GetFileNameWithoutExtension(path), out var id))
            {
                ids.Add(id);
            }
        }

        ids.Sort((a, b) => string.CompareOrdinal(a.ToString(), b.ToString()));
        return ids;
    }
}
