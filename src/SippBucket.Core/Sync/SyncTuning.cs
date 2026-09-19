using SippBucket.Core.Protocol;

namespace SippBucket.Core.Sync;

/// <summary>
/// The deadlines a sync runs under.
/// </summary>
/// <remarks>
/// <para>
/// These exist as a type rather than as constants for one reason: a deadline that cannot be
/// shortened cannot be tested. Asserting that a stalled peer is given up on means waiting
/// out the timeout, and a suite that waits thirty seconds to prove one thing is a suite
/// nobody runs. The defaults are what ships; tests pass hundreds of milliseconds.
/// </para>
/// <para>
/// The defaults are deliberately not equal. Connecting either works or does not, and ten
/// seconds is already generous for a machine on the same LAN — the three peers behind a
/// recycled DHCP lease should cost half a minute in total, not a minute each. Once a
/// connection is established the other side is doing real work, and thirty seconds of
/// silence is the point at which it has stopped rather than slowed.
/// </para>
/// </remarks>
public sealed record SyncTuning
{
    /// <summary>The deadlines used when a caller does not ask for others.</summary>
    public static SyncTuning Default { get; } = new();

    /// <summary>How long to wait for a peer to accept a TCP connection.</summary>
    /// <remarks>
    /// Without this, an address that silently drops packets — a recycled DHCP lease, a
    /// firewall configured to discard rather than refuse — costs the operating system's own
    /// connect timeout, which on Windows is about 21 seconds of a cycle that should take
    /// milliseconds.
    /// </remarks>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>How long one read or write may make no progress before the peer is dropped.</summary>
    public TimeSpan StallTimeout { get; init; } = Framing.DefaultStallTimeout;

    /// <summary>How often peers are polled even when nothing changed locally.</summary>
    /// <remarks>
    /// Lives here rather than as a static on the service for the same reason the deadlines
    /// do: status freshness is measured in multiples of this interval, so a decay rule that
    /// could not be tested without waiting ten real minutes is a decay rule nobody would
    /// ever verify.
    /// </remarks>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>How long file changes must settle before a save is taken.</summary>
    /// <remarks>
    /// An application saving a document can touch it several times in a second, and a
    /// snapshot per touch would fill the store with noise.
    /// </remarks>
    public TimeSpan DebounceInterval { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>How long a served connection may sit idle between one request and the next.</summary>
    /// <remarks>
    /// <para>
    /// Deliberately not <see cref="StallTimeout"/>, and the difference is not cosmetic.
    /// Silence part way through a message means something is wrong. Silence between
    /// messages usually means the other end is working: after each batch of 64 blocks the
    /// puller decrypts, verifies and writes every one of them to disk before asking for the
    /// next batch, and on a slow disk with large blocks that pause is measured in seconds.
    /// </para>
    /// <para>
    /// Holding both to thirty seconds would mean a server that hangs up on a peer for the
    /// crime of having a slow disk — a failure that appears only on large transfers, which
    /// is to say only on the transfers that matter. Anyone tempted to collapse these two
    /// values into one should make a large folder sync to a spinning disk first.
    /// </para>
    /// </remarks>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The most ancestry entries a pull will accept from one peer before it stops asking.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A bound rather than a deadline, and it lives here for the same reason the deadlines
    /// do: a limit nobody can shrink is a limit nobody can test. A peer's account of its
    /// history is untrusted input, and each page is already capped by the frame ceiling —
    /// but a peer that kept inventing parents one page at a time would otherwise be allowed
    /// to fill this process's memory at its own pace.
    /// </para>
    /// <para>
    /// A hundred thousand entries is on the order of 20 MB held for the length of one pull,
    /// and is ten months of a save every minute of every eight-hour working day. Reaching
    /// it is not a failure. The walk stops, anything not yet placed is
    /// treated as unknown, and an unknown relationship is merged keeping both versions —
    /// which costs spurious conflict copies and never a file.
    /// </para>
    /// </remarks>
    public int AncestryWalkLimit { get; init; } = 100_000;

    /// <summary>
    /// The longest a caller may take, from the moment its connection is accepted, to prove
    /// which device it is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A whole-handshake deadline, separate from <see cref="StallTimeout"/> on purpose (SEC-3).
    /// The stall deadline restarts on every byte that arrives, which is right for a transfer
    /// and meant that a caller with no credential could hold a connection open forever by
    /// sending one byte just inside each stall interval. Nothing a handshake exchanges is
    /// larger than a hundred bytes, so no honest caller needs long; fifteen seconds covers
    /// several round trips on the slowest link a sync could run over at all, and the two
    /// seconds <c>peers.json</c> may be waited on (D-69).
    /// </para>
    /// <para>
    /// A hard limit in code, like the pre-authentication frame ceiling, and not a setting in
    /// <c>master.json</c>: the file tunes, and never loosens what an unauthenticated caller
    /// can cost (docs/MASTER-CONFIG.md). A property only so that tests can shorten it.
    /// </para>
    /// </remarks>
    public TimeSpan HandshakeDeadline { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// The most connections this machine's server holds that have not finished the
    /// handshake, from everyone together.
    /// </summary>
    /// <remarks>
    /// Each costs a socket, a buffer of at most <see cref="Framing.HandshakeFrameSize"/> and
    /// a task until its deadline, and before SEC-3 there was no limit on how many. At the
    /// limit the server closes the oldest unauthenticated connection from whichever address
    /// holds the most, rather than refusing the newcomer, so a flood cannot keep a real peer
    /// out by filling the table first. A hard limit, for the reason
    /// <see cref="HandshakeDeadline"/> gives.
    /// </remarks>
    public int MaximumPendingHandshakes { get; init; } = 64;

    /// <summary>
    /// The most connections still in the handshake that one source address may hold.
    /// </summary>
    /// <remarks>
    /// A machine syncing several folders with this one opens one connection per folder, and
    /// the tray starts every folder's first cycle within the same second, so the limit is set
    /// above the number of folders a person keeps rather than at one. When an address is at
    /// the limit, its own oldest unauthenticated connection is closed to make room, so an
    /// address flooding the port only ever displaces itself. A hard limit, for the reason
    /// <see cref="HandshakeDeadline"/> gives.
    /// </remarks>
    public int MaximumPendingHandshakesPerAddress { get; init; } = 16;
}
