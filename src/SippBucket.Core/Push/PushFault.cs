namespace SippBucket.Core.Push;

/// <summary>
/// Why a Direct Push connection was refused or ended, as a value rather than as a sentence.
/// </summary>
/// <remarks>
/// The same split <see cref="Protocol.SipProtocolFault"/> makes for sync: each exception also
/// carries a sentence for whoever reads the log, which may be reworded at any time, and this for
/// code and tests, which must not move. The numbers are stable; a retired one is never reused.
/// </remarks>
public enum PushFault
{
    /// <summary>No specific fault was recorded.</summary>
    Unspecified = 0,

    /// <summary>
    /// The caller did not finish the SSH handshake, authentication included, within the
    /// deadline set when its connection was accepted.
    /// </summary>
    /// <remarks>
    /// A whole-handshake deadline that a trickle of bytes cannot extend, as sync's is (SEC-3).
    /// </remarks>
    HandshakeTimedOut = 1,

    /// <summary>
    /// The caller was still in the handshake when the limit on unauthenticated connections was
    /// reached, and it was the one closed to make room.
    /// </summary>
    HandshakeShed = 2,

    /// <summary>The machine that answered is not the one that was dialled: its key is not the paired key.</summary>
    WrongDevice = 3,

    /// <summary>The receiving machine did not accept this machine's key.</summary>
    /// <remarks>
    /// It is not paired there, or it is paired as someone else's machine while team features
    /// are off there. The receiving machine does not say which, and the sender is not told more.
    /// </remarks>
    NotAccepted = 4,

    /// <summary>The receiving machine refused the delivery channel.</summary>
    ChannelRefused = 5,

    /// <summary>
    /// The receiving machine already has as many deliveries arriving as it takes at once.
    /// </summary>
    Busy = 6,

    /// <summary>
    /// The other side sent more than the SSH flow-control window it was given allows
    /// (RFC 4254 section 5.2).
    /// </summary>
    /// <remarks>
    /// The SSH library buffers whatever arrives, trusting the other side to keep to the window.
    /// SippBucket holds it to the window instead, so that no machine, paired or not, can make it
    /// hold more than the window in memory.
    /// </remarks>
    WindowExceeded = 7,

    /// <summary>The other side stopped making progress and was given up on.</summary>
    PeerStalled = 8,

    /// <summary>The SSH session failed: the other side broke the protocol, or the connection was lost.</summary>
    SessionFailed = 9,

    /// <summary>The other machine could not be reached at all.</summary>
    Unreachable = 10,

    /// <summary>A delivery message could not be read: cut short, too long, or with a field out of range.</summary>
    MalformedMessage = 11,

    /// <summary>A valid delivery message arrived where the exchange called for another.</summary>
    UnexpectedMessage = 12,

    /// <summary>The two machines speak no version of the delivery format in common.</summary>
    UnsupportedVersion = 13,

    /// <summary>The receiving machine refused the whole batch; the answer says why.</summary>
    BatchRefused = 14,
}
