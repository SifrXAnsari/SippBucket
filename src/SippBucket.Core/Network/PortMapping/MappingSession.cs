using System.Net;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// One protocol's conversation with the gateway about one mapping: asking for it, renewing
/// it, and deleting it.
/// </summary>
/// <remarks>
/// Every exchange is bounded by a budget the caller passes, so nothing a gateway does, or
/// fails to do, can hold a caller for longer than it allowed.
/// </remarks>
internal abstract class MappingSession : IAsyncDisposable
{
    /// <summary>Creates a session for one mapping.</summary>
    /// <param name="gateway">The gateway.</param>
    /// <param name="internalAddress">This machine's address on the route to it.</param>
    /// <param name="internalPort">The port on this machine being mapped.</param>
    /// <param name="options">Destinations and timings.</param>
    /// <param name="log">Optional sink for log lines.</param>
    protected MappingSession(
        IPAddress gateway,
        IPAddress internalAddress,
        ushort internalPort,
        PortMapperOptions options,
        Action<string>? log)
    {
        Gateway = gateway;
        InternalAddress = internalAddress;
        InternalPort = internalPort;
        Options = options;
        Log = log;
    }

    /// <summary>The protocol this session speaks.</summary>
    public abstract PortMappingProtocol Protocol { get; }

    /// <summary>The gateway.</summary>
    public IPAddress Gateway { get; }

    /// <summary>This machine's address, the one the mapping forwards to.</summary>
    public IPAddress InternalAddress { get; }

    /// <summary>The port on this machine.</summary>
    public ushort InternalPort { get; }

    /// <summary>How many answers were refused: wrong source, wrong nonce, wrong size.</summary>
    public int Ignored { get; protected set; }

    /// <summary>How many times the gateway was seen to have lost its mappings.</summary>
    public virtual int GatewayRestarts => 0;

    /// <summary>Destinations and timings.</summary>
    protected PortMapperOptions Options { get; }

    /// <summary>Optional sink for log lines.</summary>
    protected Action<string>? Log { get; }

    /// <summary>Asks for the mapping, or renews it.</summary>
    /// <param name="lifetimeSeconds">The lifetime to ask for.</param>
    /// <param name="renewal">True when renewing a mapping this session already holds.</param>
    /// <param name="budget">The longest the whole exchange may take.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The grant, or why there was none.</returns>
    public abstract Task<SessionOutcome> RequestAsync(
        uint lifetimeSeconds,
        bool renewal,
        TimeSpan budget,
        CancellationToken cancellationToken);

    /// <summary>
    /// Asks the gateway for its external address, where the mapping response did not say.
    /// </summary>
    /// <param name="cancellationToken">Cancels the question.</param>
    /// <returns>The address, or null when the gateway did not give a usable one.</returns>
    public virtual Task<IPAddress?> LookUpExternalAddressAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IPAddress?>(null);

    /// <summary>Asks the gateway to delete the mapping.</summary>
    /// <param name="budget">The longest the exchange may take.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>True when the gateway confirmed the deletion.</returns>
    public abstract Task<bool> DeleteAsync(TimeSpan budget, CancellationToken cancellationToken);

    /// <inheritdoc />
    public virtual ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

/// <summary>What one exchange produced: a grant, or why not.</summary>
internal sealed record SessionOutcome
{
    /// <summary>The mapping granted, or null.</summary>
    public MappingGrant? Grant { get; init; }

    /// <summary>Why there is no grant; <see cref="PortMappingFailure.None"/> when there is one.</summary>
    public PortMappingFailure Failure { get; init; }

    /// <summary>One line naming what the gateway said.</summary>
    public string Detail { get; init; } = "";

    /// <summary>For PCP only: the gateway answered in NAT-PMP, so ask it that way instead.</summary>
    public bool GatewaySpeaksNatPmp { get; init; }

    /// <summary>How long the gateway said the same request would keep failing, when it said.</summary>
    public TimeSpan? RetryAfter { get; init; }

    /// <summary>A grant.</summary>
    /// <param name="grant">What was granted.</param>
    /// <returns>The outcome.</returns>
    public static SessionOutcome Granted(MappingGrant grant) => new() { Grant = grant };

    /// <summary>No grant.</summary>
    /// <param name="failure">Why.</param>
    /// <param name="detail">One line naming what the gateway said.</param>
    /// <param name="retryAfter">How long the failure is expected to last, when known.</param>
    /// <returns>The outcome.</returns>
    public static SessionOutcome Failed(PortMappingFailure failure, string detail, TimeSpan? retryAfter = null) =>
        new() { Failure = failure, Detail = detail, RetryAfter = retryAfter };
}

/// <summary>A mapping as the gateway granted it.</summary>
/// <param name="ExternalPort">The external port the gateway forwards.</param>
/// <param name="ExternalAddress">The gateway's external address, when known.</param>
/// <param name="Lifetime">How long the gateway will keep it without a renewal.</param>
internal sealed record MappingGrant(ushort ExternalPort, IPAddress? ExternalAddress, TimeSpan Lifetime);
