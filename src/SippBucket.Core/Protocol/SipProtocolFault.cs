namespace SippBucket.Core.Protocol;

/// <summary>
/// Why a connection was refused, as a value rather than as a sentence.
/// </summary>
/// <remarks>
/// <para>
/// Every one of these also has a human-readable message on the exception, and the two have
/// different consumers. The message is for whoever is reading a log at two in the morning
/// and should be free to be reworded whenever a clearer wording is found. This enum is for
/// code — tests, and any future structured logging — and must not move.
/// </para>
/// <para>
/// It exists because of a specific near-miss. The test for the pre-authentication frame
/// ceiling originally asserted that the server hung up, which proved nothing: an oversized
/// frame that <em>is</em> accepted also ends in a hangup once the body never arrives and the
/// stall deadline fires. Both paths close the socket. The assertion moved to the refusal
/// reason, which is the only place they genuinely differ — but expressed as a substring of
/// English prose, it could quietly become vacuous again the first time somebody improved
/// the wording, updated the expected string to match, and did not re-check that the new
/// wording appears <em>only</em> on the refusal path. That is the same vacuity arrived at
/// by maintenance rather than by authorship, and it is harder to spot because a test with
/// an edit history reads as more trustworthy than a new one.
/// </para>
/// </remarks>
public enum SipProtocolFault
{
    /// <summary>No specific fault was recorded.</summary>
    Unspecified = 0,

    /// <summary>The peer announced a frame larger than the ceiling in force.</summary>
    /// <remarks>
    /// Before authentication that ceiling is <see cref="Framing.HandshakeFrameSize"/>, and
    /// this is the fault that says the amplification attack was refused rather than served.
    /// </remarks>
    FrameTooLarge = 1,

    /// <summary>The connection ended part way through a frame.</summary>
    FrameTruncated = 2,

    /// <summary>The peer speaks a protocol version this build does not.</summary>
    UnsupportedVersion = 3,

    /// <summary>The peer asked for a repository this daemon does not serve.</summary>
    UnknownRepository = 4,

    /// <summary>The caller's device is not a known peer of this repository.</summary>
    UnknownDevice = 5,

    /// <summary>The peer that answered is not the device that was dialled.</summary>
    WrongDevice = 6,

    /// <summary>A handshake signature did not verify.</summary>
    /// <remarks>
    /// Raised only by protocol 1, whose handshake was signed. The Noise handshake of protocol 2
    /// authenticates by key agreement instead; the member stays so the numbering never moves.
    /// </remarks>
    BadSignature = 7,

    /// <summary>A message could not be parsed, or a field was malformed.</summary>
    MalformedMessage = 8,

    /// <summary>A valid message arrived, but not the one the exchange called for.</summary>
    UnexpectedMessage = 9,

    /// <summary>A message failed its authentication tag.</summary>
    AuthenticationFailed = 10,

    /// <summary>The peer could not produce a block its own snapshot refers to.</summary>
    MissingBlock = 11,

    /// <summary>The peer answered with a different block from the one requested.</summary>
    WrongBlock = 12,

    /// <summary>A block body was not valid base64.</summary>
    MalformedBlock = 13,

    /// <summary>The peer stopped making progress and was given up on.</summary>
    /// <remarks>
    /// Not a protocol violation, and carried here anyway so that a log or a test can
    /// distinguish "refused before allocating" from "allocated, then waited out the
    /// deadline" — which is exactly the pair that shares an observable outcome.
    /// </remarks>
    PeerStalled = 14,

    /// <summary>
    /// The caller proved it holds one key and named a device ID that does not belong to it.
    /// </summary>
    /// <remarks>
    /// The Noise handshake authenticates the caller's X25519 static key; the device ID it sends
    /// alongside is only a claim until it converts to that same key. A caller that fails the
    /// check is trying to borrow another machine's place in the peer list, so it is refused
    /// before the peer list is even consulted.
    /// </remarks>
    IdentityMismatch = 15,

    /// <summary>
    /// The peer answered a snapshot request with a snapshot whose content does not hash to
    /// the ID that was asked for.
    /// </summary>
    /// <remarks>
    /// Standard D2 for snapshots. Blocks were always verified against their names before
    /// being filed; snapshots were filed under the hash of whatever arrived, so a peer could
    /// substitute any snapshot it liked for the one it had advertised (D-41).
    /// </remarks>
    WrongSnapshot = 16,

    /// <summary>
    /// The peer's account of history contradicts a snapshot this replica can check it
    /// against: it named different parents for a snapshot whose own content says otherwise.
    /// </summary>
    InconsistentAncestry = 17,

    /// <summary>
    /// The caller did not finish the handshake within
    /// <see cref="Sync.SyncTuning.HandshakeDeadline"/> of being accepted.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="PeerStalled"/>, which is silence. The stall deadline restarts
    /// on every byte, by design, so a caller that sent one byte just inside each stall
    /// interval was never stalled and was held open for as long as it liked, with no
    /// credential (SEC-3). This is the deadline trickling cannot extend.
    /// </remarks>
    HandshakeTimedOut = 18,

    /// <summary>
    /// The caller was still in the handshake when the listener's limit on unauthenticated
    /// connections was reached, and it was the one closed to make room.
    /// </summary>
    /// <remarks>
    /// The listener sheds the oldest unauthenticated connection from the address holding the
    /// most of them, so that a flood from one place costs that place its own connections. A
    /// real peer's handshake is closed only when its own address holds as many unfinished
    /// handshakes as the busiest one, which a flood spread one connection per address can
    /// arrange; then the oldest of them goes, and the peer's next attempt is let in (SEC-3).
    /// </remarks>
    HandshakeShed = 19,
}
