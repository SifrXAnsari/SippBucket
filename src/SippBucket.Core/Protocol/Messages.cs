using SippBucket.Core.Hashing;
using SippBucket.Core.Model;

namespace SippBucket.Core.Protocol;

/// <summary>Carries a peer's newest snapshot ID.</summary>
public sealed record HeadResponseMessage
{
    /// <summary>The peer's head, empty when it has never saved.</summary>
    public required ContentHash SnapshotId { get; init; }

    /// <summary>The peer's name for the repository, for display.</summary>
    public required string RepositoryName { get; init; }
}

/// <summary>Asks for one snapshot.</summary>
public sealed record SnapshotRequestMessage
{
    /// <summary>The snapshot wanted.</summary>
    public required ContentHash SnapshotId { get; init; }
}

/// <summary>Carries one snapshot, or reports that the peer does not hold it.</summary>
public sealed record SnapshotResponseMessage
{
    /// <summary>The snapshot's ID.</summary>
    public required ContentHash SnapshotId { get; init; }

    /// <summary>The snapshot, or null when the peer does not have it.</summary>
    public Snapshot? Snapshot { get; init; }
}

/// <summary>
/// Asks the peer to walk back through its history from some snapshot IDs and report what
/// it finds.
/// </summary>
/// <remarks>
/// Paged, and bounded on both ends. The puller asks from the IDs it has not placed yet, the
/// server walks breadth first from them and stops at <see cref="Limit"/>, and the puller
/// asks again from wherever that page ran out. Neither side trusts the other's numbers: the
/// server clamps the limit and refuses more than <see cref="MaximumRoots"/> starting
/// points, and the puller refuses a page longer than it asked for and stops walking
/// altogether at <see cref="Sync.SyncTuning.AncestryWalkLimit"/> entries.
/// </remarks>
public sealed record AncestryRequestMessage
{
    /// <summary>The most starting points one request may carry.</summary>
    public const int MaximumRoots = 64;

    /// <summary>The most entries one response may carry.</summary>
    /// <remarks>
    /// An entry is three hashes, at most about 235 bytes of JSON, so a full page is under a
    /// quarter of a megabyte: far below <see cref="Framing.MaximumFrameSize"/>. The puller
    /// starts well below this, because a peer is usually a few saves ahead and a full page
    /// would be mostly history both sides already share.
    /// </remarks>
    public const int MaximumLimit = 1024;

    /// <summary>The snapshots to walk back from.</summary>
    public required IReadOnlyList<ContentHash> From { get; init; }

    /// <summary>The most entries wanted in the response.</summary>
    public required int Limit { get; init; }
}

/// <summary>One page of a peer's history.</summary>
public sealed record AncestryResponseMessage
{
    /// <summary>
    /// The snapshots found, nearest the requested IDs first. An ID the peer does not know
    /// contributes nothing, so an empty page means the walk has reached the end of what the
    /// peer can say.
    /// </summary>
    public required IReadOnlyList<AncestryEntry> Entries { get; init; }
}

/// <summary>Asks for a set of blocks.</summary>
public sealed record BlockRequestMessage
{
    /// <summary>The content hashes wanted.</summary>
    public required IReadOnlyList<ContentHash> Hashes { get; init; }
}

/// <summary>
/// One block as a test's scripted peer shapes it before the binary encoding
/// (<see cref="BlockWire"/>): the shipping wire is <see cref="MessageType.BlockData"/>'s raw
/// body, and this record is the seam the resilience tests corrupt at.
/// </summary>
public sealed record BlockResponseMessage
{
    /// <summary>The block's content hash.</summary>
    public required ContentHash Hash { get; init; }

    /// <summary>The block's ciphertext, base64 encoded. Null when the peer lacks it.</summary>
    public string? Ciphertext { get; init; }
}

/// <summary>Asks which of a set of blocks the peer holds (D-28).</summary>
/// <remarks>
/// The question BitTorrent's <c>bitfield</c> and Bitswap's <c>want-have</c> both exist to
/// answer: "should I be convinced this data exists here", asked before a byte of it moves,
/// so a peer's lack of a block routes the fetch instead of failing it one round trip late.
/// </remarks>
public sealed record HaveRequestMessage
{
    /// <summary>The most hashes one request may carry.</summary>
    public const int MaximumHashes = 1024;

    /// <summary>The content hashes asked about.</summary>
    public required IReadOnlyList<ContentHash> Hashes { get; init; }
}

/// <summary>Which of the asked-about blocks the peer holds, in the order asked.</summary>
public sealed record HaveResponseMessage
{
    /// <summary>One flag per hash of the request, in order.</summary>
    public required IReadOnlyList<bool> Present { get; init; }
}

/// <summary>Reports that a request could not be served.</summary>
public sealed record ErrorMessage
{
    /// <summary>What went wrong, in terms the other end can log.</summary>
    public required string Reason { get; init; }
}

/// <summary>Asks the peer where its key ring stands (D-70).</summary>
public sealed record KeyStatusRequestMessage
{
    /// <summary>How many keys the caller's ring holds: 1 before any rotation.</summary>
    public required int Generation { get; init; }
}

/// <summary>A whole key ring and the devices its rotations revoked (D-70).</summary>
/// <remarks>
/// Travels only inside the authenticated channel, between machines that already share the
/// folder's keys: it is how the <em>remaining</em> machines learn a rotation, and a removed
/// machine, being in nobody's peer list once the update lands, is never sent it.
/// </remarks>
public sealed record KeyUpdateMessage
{
    /// <summary>The most keys one ring may hold. A folder sees a handful of rotations, not thousands.</summary>
    public const int MaximumKeys = 64;

    /// <summary>The most revoked devices one update may carry.</summary>
    public const int MaximumRevoked = 256;

    /// <summary>Every key of the ring, base64, oldest first; the last is the current key.</summary>
    public required IReadOnlyList<string> Keys { get; init; }

    /// <summary>The devices rotations have revoked, lowercase hexadecimal.</summary>
    public required IReadOnlyList<string> Revoked { get; init; }
}

/// <summary>The server's answer about its key ring (D-70).</summary>
public sealed record KeyStatusResponseMessage
{
    /// <summary>How many keys the server's ring holds now.</summary>
    public required int Generation { get; init; }

    /// <summary>The server's ring and revoked devices, sent only when it is ahead of the caller.</summary>
    public KeyUpdateMessage? Update { get; init; }
}

/// <summary>
/// The discovery key one machine minted for the caller (docs/DISCOVERY.md), or nothing for a
/// caller it does not announce to.
/// </summary>
public sealed record DiscoveryKeyResponseMessage
{
    /// <summary>The 32-byte key, base64; null when the server announces nothing to this caller.</summary>
    public string? KeyBase64 { get; init; }
}
