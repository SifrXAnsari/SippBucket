using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// Asks the home router to forward one TCP port to this machine: PCP first, then NAT-PMP,
/// then UPnP IGD.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why it exists (D-05).</strong> Two machines on two home networks cannot reach
/// each other while both routers drop unsolicited inbound connections. A forwarded port on
/// one side makes that side reachable. It is the first part of NAT traversal and not all of
/// it: a router that does not map, a carrier's second NAT in front of the router, and two
/// machines that both need mapping are for the rest of D-05.
/// </para>
/// <para>
/// <strong>Opt-in, and it does nothing until called.</strong> Constructing this sends
/// nothing. Only <see cref="MapAsync"/> talks to the router, and only the owner's explicit
/// choice should ever lead to calling it. It maps exactly the one port it is given, TCP only,
/// to this machine only, and never asks for an external port it was not given: the first
/// request of every protocol asks for the external port equal to the internal one. A PCP or
/// NAT-PMP gateway may still assign a different one, which is reported, not refused; a
/// renewal asks to keep what was assigned, as both RFCs say it should.
/// </para>
/// <para>
/// <strong>Why this order.</strong> PCP (RFC 6887) is the IETF's current protocol and the
/// only one of the three whose answers are tied to the request by an unguessable nonce.
/// NAT-PMP (RFC 6886) is its predecessor on the same port, and RFC 6887 section 9 says a
/// client may fall back to it when the gateway answers PCP with NAT-PMP's "Unsupported
/// Version". UPnP IGD has no nonce, runs over HTTP and XML from the router, and is the
/// largest attack surface of the three, so it is the last resort.
/// </para>
/// <para>
/// <strong>How long nothing takes.</strong> A gateway that answers nothing costs one PCP
/// probe (<see cref="PortMapperOptions.PcpProbeDuration"/>, 15 seconds) and three unicast
/// SSDP searches a second apart, about 18 seconds in all, and then the result says
/// <see cref="PortMappingFailure.NoAnswer"/>.
/// </para>
/// <para>
/// <strong>What a forwarded port exposes, and what protects it.</strong> The sync listener
/// becomes reachable from the whole internet, and anyone scanning finds it. What protects
/// it: before anything is authenticated a connection gets frames of at most
/// <c>Framing.HandshakeFrameSize</c> (8 KiB), each under the stall timeout, so a stranger
/// cannot make it allocate more; the handshake is Noise XK, whose first message decrypts only
/// if it was encrypted to this machine's static key, which only someone who knows its device
/// ID can derive; and after the third message the caller's own key must belong to a device in
/// the peer list before a single request is served. What does not: nothing limits how many
/// connections are open at once or how fast they arrive (the <c>RateLimiter</c> exists and
/// nothing uses it, D-29), and each one costs a task and a socket for as long as the stall
/// timeout lets it sit silent, plus a Diffie-Hellman operation for every first handshake
/// message; the plaintext preamble answer tells any scanner the port is SippBucket's and
/// which protocol version it speaks; and anyone who already knows the device ID can learn
/// whether a repository ID they guess is served here, from the second handshake message. A
/// flood of connection attempts can tie the listener up; it still gets nothing served. The
/// pairing listener, on the port after the sync port, must never be mapped, and this maps
/// only the port it is given.
/// </para>
/// </remarks>
public sealed class PortMapper
{
    private static readonly TimeSpan ShortestLifetime = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan LongestLifetime = TimeSpan.FromDays(7);

    private readonly PortMapperOptions _options;
    private readonly Action<string>? _log;

    /// <summary>Creates a mapper that asks this machine's default gateway. Sends nothing.</summary>
    /// <param name="log">Optional sink for log lines.</param>
    public PortMapper(Action<string>? log = null)
        : this(PortMapperOptions.Default, log)
    {
    }

    /// <summary>Creates a mapper with other destinations and timings: the test seam.</summary>
    /// <param name="options">Destinations and timings.</param>
    /// <param name="log">Optional sink for log lines.</param>
    internal PortMapper(PortMapperOptions options, Action<string>? log)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _log = log;
    }

    /// <summary>
    /// Asks the gateway to forward <paramref name="port"/> on its outside to the same port on
    /// this machine, and keeps the mapping renewed until it is removed.
    /// </summary>
    /// <param name="port">The TCP port on this machine: the sync listen port.</param>
    /// <param name="lifetime">
    /// The lifetime to ask for, between one second and seven days. The gateway may grant less,
    /// and UPnP IGD is never asked for more than an hour. Renewal keeps it alive regardless.
    /// </param>
    /// <param name="cancellationToken">Cancels the whole attempt.</param>
    /// <returns>
    /// The mapping, whose removal or disposal deletes it from the router; or no mapping and
    /// why. It does not throw for anything the network or the router does.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="port"/> is not 1 to 65535, or <paramref name="lifetime"/> is out of range.
    /// Port 0 is refused rather than sent, because PCP reads it as "all ports".
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// The token was cancelled. A mapping obtained before that is deleted first.
    /// </exception>
    public async Task<PortMappingResult> MapAsync(
        int port,
        TimeSpan lifetime,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, ushort.MaxValue);
        ArgumentOutOfRangeException.ThrowIfLessThan(lifetime, ShortestLifetime);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(lifetime, LongestLifetime);

        var internalPort = (ushort)port;
        var seconds = (uint)Math.Ceiling(lifetime.TotalSeconds);
        var attempts = new List<PortMappingAttempt>();

        var gateway = _options.Gateway ?? DefaultGateway.FindIPv4();
        if (gateway is null)
        {
            return PortMappingResult.Failed(
                PortMappingFailure.NoGateway,
                "No port mapping: this machine has no IPv4 default gateway to ask.",
                attempts);
        }

        IPAddress local;
        try
        {
            local = GatewayUdpChannel.LocalAddressToward(new IPEndPoint(gateway, _options.PcpServerPort));
        }
        catch (SocketException ex)
        {
            return PortMappingResult.Failed(
                PortMappingFailure.NoGateway,
                Say($"No port mapping: there is no route to the gateway {gateway} ({ex.SocketErrorCode})."),
                attempts);
        }

        // PCP, and NAT-PMP when the gateway answers PCP in NAT-PMP. They share a port, and one
        // bounded PCP probe decides both (see PortMapperOptions.PcpProbeDuration).
        var (mapping, pcp) = await TryAsync(
                () => new PcpSession(gateway, local, internalPort, _options, _log),
                seconds,
                _options.PcpProbeDuration,
                attempts,
                cancellationToken)
            .ConfigureAwait(false);

        if (mapping is null && pcp.GatewaySpeaksNatPmp)
        {
            (mapping, _) = await TryAsync(
                    () => new NatPmpSession(gateway, local, internalPort, _options, _log),
                    seconds,
                    NatPmpSession.FullSchedule(_options),
                    attempts,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        // UPnP IGD, the last resort.
        if (mapping is null)
        {
            (mapping, _) = await TryAsync(
                    () => new UpnpIgdSession(gateway, local, internalPort, _options, _log),
                    seconds,
                    _options.HttpTimeout,
                    attempts,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return mapping is not null
            ? PortMappingResult.Obtained(mapping, attempts)
            : Conclude(gateway, attempts, pcp.RetryAfter);
    }

    /// <summary>
    /// Asks one protocol for the mapping and, when it is granted, wraps it in a mapping that
    /// owns the session and renews it.
    /// </summary>
    private async Task<(ActivePortMapping? Mapping, SessionOutcome Outcome)> TryAsync(
        Func<MappingSession> open,
        uint seconds,
        TimeSpan budget,
        List<PortMappingAttempt> attempts,
        CancellationToken cancellationToken)
    {
        var session = open();
        var handedOver = false;
        try
        {
            SessionOutcome outcome;
            try
            {
                outcome = await session.RequestAsync(seconds, renewal: false, budget, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                outcome = SessionOutcome.Failed(
                    PortMappingFailure.NoAnswer,
                    Say($"{session.Protocol.Name()}: could not send to {session.Gateway}: {ex.SocketErrorCode}"));
            }

            if (outcome.Grant is null)
            {
                attempts.Add(new PortMappingAttempt(session.Protocol, outcome.Failure, outcome.Detail));
                _log?.Invoke(outcome.Detail);
                return (null, outcome);
            }

            var mapping = new ActivePortMapping(session, outcome.Grant, seconds, _options, _log);
            handedOver = true;

            if (outcome.Grant.ExternalAddress is null)
            {
                try
                {
                    mapping.SetExternalAddress(
                        await session.LookUpExternalAddressAsync(cancellationToken).ConfigureAwait(false));
                }
                catch (OperationCanceledException)
                {
                    // The router holds the mapping now. Cancelled or not, it must not be left
                    // there with nothing renewing it and nothing going to delete it.
                    await mapping.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }

            mapping.Start();
            _log?.Invoke(Say(
                $"{mapping.Protocol.Name()}: {mapping.Gateway} forwards TCP {mapping.ExternalAddress?.ToString() ?? "?"}:{mapping.ExternalPort} to {mapping.InternalAddress}:{mapping.InternalPort} until {mapping.ExpiresUtc:u}"));

            return (mapping, outcome);
        }
        finally
        {
            if (!handedOver)
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>The result when no protocol produced a mapping.</summary>
    /// <remarks>
    /// The reason given is the last protocol that answered at all, because an answer says more
    /// than silence: a router that refused over UPnP after ignoring PCP is a refusal, not a
    /// router that is not there. Every attempt's own line is in the summary.
    /// </remarks>
    private static PortMappingResult Conclude(
        IPAddress gateway,
        List<PortMappingAttempt> attempts,
        TimeSpan? retryAfter)
    {
        var answered = attempts.LastOrDefault(a => a.Failure != PortMappingFailure.NoAnswer);
        var failure = answered?.Failure ?? PortMappingFailure.NoAnswer;

        return PortMappingResult.Failed(
            failure,
            Say($"No port mapping from {gateway}: {string.Join("; ", attempts.Select(a => a.Detail))}"),
            attempts,
            retryAfter);
    }

    private static string Say(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
