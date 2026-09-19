namespace SippBucket.Core.Protocol;

/// <summary>
/// The message kinds that travel between two peers once the channel is encrypted.
/// </summary>
/// <remarks>
/// The set is intentionally small. Sync is a pull: ask what the other side's head is, learn
/// how that head relates to this replica's history, fetch the snapshots and blocks that are
/// missing, and stop.
/// </remarks>
// CA1028 wants Int32. This is a wire format: the type is a single byte at the head of every
// encrypted frame, and widening it would put three pointless bytes on every message.
#pragma warning disable CA1028
public enum MessageType : byte
#pragma warning restore CA1028
{
    /// <summary>Reserved so that a zero byte is never a valid message.</summary>
    None = 0,

    /// <summary>Asks the peer for the ID of its newest snapshot.</summary>
    HeadRequest = 1,

    /// <summary>Carries the peer's newest snapshot ID.</summary>
    HeadResponse = 2,

    /// <summary>Asks for one snapshot by ID.</summary>
    SnapshotRequest = 3,

    /// <summary>Carries one snapshot.</summary>
    SnapshotResponse = 4,

    /// <summary>Asks for a set of blocks by content hash.</summary>
    BlockRequest = 5,

    /// <summary>
    /// Carried one block as base64 inside JSON, until <see cref="BlockData"/> replaced it
    /// (D-45). Never sent or served by this build; the byte stays reserved so no future
    /// message can be mistaken for one by an old build.
    /// </summary>
    BlockResponse = 6,

    /// <summary>Ends the session cleanly.</summary>
    Goodbye = 7,

    /// <summary>Reports that a request could not be served.</summary>
    Error = 8,

    /// <summary>Asks for the IDs and parents of snapshots behind a set of snapshot IDs.</summary>
    AncestryRequest = 9,

    /// <summary>Carries one page of ancestry entries, nearest the requested IDs first.</summary>
    AncestryResponse = 10,

    /// <summary>
    /// Carries the caller's Server.ID record, report and passed-on claims, and asks for the
    /// server's (<see cref="Servers.ServerExchangeMessage"/>). Empty unless the caller's person
    /// said the server is theirs.
    /// </summary>
    /// <remarks>
    /// Added without a protocol version: a build that does not know it answers
    /// <see cref="Error"/>, which the caller takes as "no record", and syncs as before.
    /// </remarks>
    ServerRecordRequest = 11,

    /// <summary>Carries the server's own record, report and claims; empty unless its person said the caller is theirs.</summary>
    ServerRecordResponse = 12,

    /// <summary>
    /// Asks the server how many keys its ring holds, carrying the caller's own count, so a
    /// rotation (D-70) reaches every remaining machine at its next sync.
    /// </summary>
    KeyStatusRequest = 13,

    /// <summary>
    /// The server's ring count, with the whole ring and the revoked devices when the server
    /// is ahead of the caller; the caller's cue to push its own when the caller is ahead.
    /// </summary>
    KeyStatusResponse = 14,

    /// <summary>Carries the caller's ring and revoked devices to a server that is behind.</summary>
    KeyUpdatePush = 15,

    /// <summary>
    /// Asks the server for the discovery key it minted for this caller (docs/DISCOVERY.md).
    /// Answered empty for a caller the server does not announce to.
    /// </summary>
    DiscoveryKeyRequest = 16,

    /// <summary>Carries the server's discovery key for the caller, or nothing.</summary>
    DiscoveryKeyResponse = 17,

    /// <summary>
    /// Carries one block as raw bytes — the hash, then the stored ciphertext — with no
    /// base64 and no JSON (D-45, <see cref="BlockWire"/>). A body of the hash alone means
    /// the peer does not hold the block.
    /// </summary>
    BlockData = 18,

    /// <summary>Asks which of a set of blocks the peer holds, before any is fetched (D-28).</summary>
    HaveRequest = 19,

    /// <summary>Answers a have request, one flag per hash asked about, in order.</summary>
    HaveResponse = 20,
}
