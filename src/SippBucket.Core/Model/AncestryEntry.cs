using SippBucket.Core.Hashing;

namespace SippBucket.Core.Model;

/// <summary>
/// One snapshot's place in history: its ID and the IDs of its parents, without its files.
/// </summary>
/// <remarks>
/// This is what lets two machines answer "is that snapshot one of mine?" after the snapshot
/// itself is gone. Simple mode deletes every snapshot but the newest, and a peer that is
/// behind then offers an ID this replica no longer holds. Deciding from the snapshot files
/// alone made that older snapshot look new, and it was written over the newer work (D-39).
/// </remarks>
public sealed record AncestryEntry
{
    /// <summary>The snapshot's ID.</summary>
    public required ContentHash Id { get; init; }

    /// <summary>Its parent, or empty for the first snapshot in a repository.</summary>
    public required ContentHash ParentId { get; init; }

    /// <summary>Its second parent when it records a merge, or empty.</summary>
    public ContentHash MergeParentId { get; init; }

    /// <summary>The entry for a snapshot, taken from its own parent fields.</summary>
    /// <param name="id">The snapshot's ID.</param>
    /// <param name="snapshot">The snapshot.</param>
    /// <returns>The entry.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="snapshot"/> was null.</exception>
    public static AncestryEntry For(ContentHash id, Snapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        return new AncestryEntry
        {
            Id = id,
            ParentId = snapshot.ParentId,
            MergeParentId = snapshot.MergeParentId,
        };
    }

    /// <summary>True when both entries name the same parents.</summary>
    /// <param name="other">The entry to compare with.</param>
    /// <returns>True when the parent fields match.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="other"/> was null.</exception>
    public bool HasSameParentsAs(AncestryEntry other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return ParentId == other.ParentId && MergeParentId == other.MergeParentId;
    }
}
