using SippBucket.Core.Configuration;

namespace SippBucket.Core.Push;

/// <summary>
/// The deadlines and limits a Direct Push connection runs under.
/// </summary>
/// <remarks>
/// <para>
/// A type rather than constants for the reason <see cref="Sync.SyncTuning"/> gives: a deadline
/// that cannot be shortened cannot be tested. The defaults are what ships.
/// </para>
/// <para>
/// Two of them come from <c>master.json</c> through <see cref="ForMachine"/>: the connect and
/// stall timeouts, which are the machine's network deadlines in its <c>sync</c> section and
/// mean the same thing here. The rest are hard limits in code, like sync's limits on
/// unauthenticated callers: the file tunes, and never loosens what a caller that has not proved
/// its key can cost (docs/MASTER-CONFIG.md).
/// </para>
/// </remarks>
public sealed record PushTuning
{
    /// <summary>The deadlines and limits used when a caller does not ask for others.</summary>
    public static PushTuning Default { get; } = new();

    /// <summary>How long to wait for the other machine to accept a TCP connection.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>How long one read or write may make no progress before the other side is given up on.</summary>
    public TimeSpan StallTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The longest a caller may take, from the moment its connection is accepted, to finish the
    /// SSH handshake, prove its key and open the delivery channel.
    /// </summary>
    /// <remarks>
    /// The SSH handshake is about five round trips: the version lines, the key exchange, the
    /// service request, the key check and the channel. Fifteen seconds covers those on the
    /// slowest link a push could run over at all, and the moment the key check spends reading
    /// the peer lists. A trickle of bytes cannot extend it (SEC-3).
    /// </remarks>
    public TimeSpan HandshakeDeadline { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>The most connections still in the handshake, from everyone together.</summary>
    /// <remarks>
    /// Each costs a socket, a key exchange's worth of work and a task until its deadline. At the
    /// limit the oldest unauthenticated connection from the busiest address is closed, as for
    /// sync (<see cref="Protocol.HandshakeAdmission"/>).
    /// </remarks>
    public int MaximumPendingHandshakes { get; init; } = 16;

    /// <summary>The most connections still in the handshake that one source address may hold.</summary>
    /// <remarks>
    /// A sender opens one connection for each batch, so a handful covers a person sending two
    /// batches at once from each of their machines behind one address.
    /// </remarks>
    public int MaximumPendingHandshakesPerAddress { get; init; } = 4;

    /// <summary>The most deliveries arriving at once, from everyone together.</summary>
    /// <remarks>
    /// Each holds up to <c>push.windowKiB</c> in memory, at most 64 MiB, so four keep the whole
    /// of Direct Push's receiving inside 256 MiB whatever the file says. A fifth sender is told
    /// the machine is busy and tries again later.
    /// </remarks>
    public int MaximumSessions { get; init; } = 4;

    /// <summary>
    /// The deadlines this machine's settings describe, with the hard limits at their built-in
    /// values.
    /// </summary>
    /// <param name="machine">This machine's settings, from <c>master.json</c>.</param>
    /// <returns>The tuning.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="machine"/> was null.</exception>
    public static PushTuning ForMachine(MasterConfig machine)
    {
        ArgumentNullException.ThrowIfNull(machine);

        return Default with
        {
            ConnectTimeout = machine.Sync.ConnectTimeout,
            StallTimeout = machine.Sync.StallTimeout,
        };
    }

    /// <summary>Checks that every deadline and limit is usable.</summary>
    /// <param name="parameterName">The caller's parameter these came in as, for the exception.</param>
    /// <exception cref="ArgumentOutOfRangeException">A deadline or limit is not positive.</exception>
    internal void Validate(string parameterName)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ConnectTimeout, TimeSpan.Zero, parameterName);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(StallTimeout, TimeSpan.Zero, parameterName);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(HandshakeDeadline, TimeSpan.Zero, parameterName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumPendingHandshakes, parameterName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumPendingHandshakesPerAddress, parameterName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumSessions, parameterName);
    }
}
