using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// A NAT-PMP mapping for one TCP port, RFC 6886 section 3.3, used when the gateway answered
/// PCP in NAT-PMP.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What an answer must be to count.</strong> From the gateway's address and port
/// (<see cref="GatewayUdpChannel"/>; section 3.1 has the client "silently discard the packet
/// if the address is not the address of the gateway to which the request was sent"), exactly
/// the size section 3.3 draws, the TCP mapping opcode plus 128, and this request's internal
/// port. NAT-PMP has no nonce, so that is all there is to match, and it is weaker than PCP:
/// anything that can send from the gateway's address can answer. On a home network that is
/// the gateway, or a machine already able to impersonate it for everything else too.
/// </para>
/// <para>
/// <strong>What it asks for.</strong> TCP, the one internal port, and the same external port
/// on the first request. A renewal suggests the port the gateway assigned, as section 3.3
/// says it SHOULD, so a gateway that restarted can give the same one back.
/// </para>
/// </remarks>
internal sealed class NatPmpSession : MappingSession
{
    /// <summary>
    /// Attempts for the external address question, which follows a mapping the gateway has
    /// just answered and so needs none of the patience of a first contact.
    /// </summary>
    private const int AddressAttempts = 4;

    private readonly GatewayEpoch _epoch = new();
    private ushort _assignedPort;

    /// <summary>Creates a session. Nothing is sent until <see cref="RequestAsync"/>.</summary>
    /// <param name="gateway">The gateway.</param>
    /// <param name="internalAddress">This machine's address on the route to it.</param>
    /// <param name="internalPort">The port to map.</param>
    /// <param name="options">Destinations and timings.</param>
    /// <param name="log">Optional sink for log lines.</param>
    public NatPmpSession(
        IPAddress gateway,
        IPAddress internalAddress,
        ushort internalPort,
        PortMapperOptions options,
        Action<string>? log)
        : base(gateway, internalAddress, internalPort, options, log)
    {
    }

    /// <inheritdoc />
    public override PortMappingProtocol Protocol => PortMappingProtocol.NatPmp;

    /// <inheritdoc />
    public override int GatewayRestarts => _epoch.Restarts;

    /// <summary>
    /// How long section 3.1's full schedule takes: every attempt, each waiting twice as long
    /// as the one before.
    /// </summary>
    /// <param name="options">The timings.</param>
    /// <returns>The first interval times <c>2^attempts - 1</c>.</returns>
    public static TimeSpan FullSchedule(PortMapperOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.NatPmpInitialRetransmission * ((1L << options.NatPmpAttempts) - 1);
    }

    /// <inheritdoc />
    public override async Task<SessionOutcome> RequestAsync(
        uint lifetimeSeconds,
        bool renewal,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        var request = NatPmpMessage.MapTcpRequest(
            InternalPort,
            _assignedPort != 0 ? _assignedPort : InternalPort,
            lifetimeSeconds);

        var reply = await ExchangeAsync(request, IsMappingAnswer, Options.NatPmpAttempts, budget, cancellationToken)
            .ConfigureAwait(false);

        if (reply is null)
        {
            return SessionOutcome.Failed(
                PortMappingFailure.NoAnswer,
                Say($"no NAT-PMP answer from {Gateway} within {budget.TotalSeconds:0.#} s"));
        }

        NoteEpoch(reply.Epoch);

        if (reply.Result != NatPmpResultCode.Success)
        {
            return SessionOutcome.Failed(
                PortMappingFailure.Refused,
                Say($"{Gateway} refused the mapping: {reply.Result} ({(int)reply.Result})"));
        }

        if (reply.ExternalPort == 0 || reply.Lifetime == 0)
        {
            return SessionOutcome.Failed(
                PortMappingFailure.Refused,
                Say($"{Gateway} answered success with port {reply.ExternalPort} for {reply.Lifetime} s"));
        }

        _assignedPort = reply.ExternalPort;
        return SessionOutcome.Granted(new MappingGrant(_assignedPort, null, TimeSpan.FromSeconds(reply.Lifetime)));
    }

    /// <inheritdoc />
    /// <remarks>Section 3.2's external address request.</remarks>
    public override async Task<IPAddress?> LookUpExternalAddressAsync(CancellationToken cancellationToken)
    {
        var budget = Options.NatPmpInitialRetransmission * ((1 << AddressAttempts) - 1);

        NatPmpReply? reply;
        try
        {
            reply = await ExchangeAsync(
                    NatPmpMessage.ExternalAddressRequest(),
                    static r => r.Kind == NatPmpReplyKind.ExternalAddress,
                    AddressAttempts,
                    budget,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            Log?.Invoke(Say($"could not ask {Gateway} for its external address: {ex.SocketErrorCode}"));
            return null;
        }

        if (reply is null)
        {
            return null;
        }

        NoteEpoch(reply.Epoch);
        return reply.Result == NatPmpResultCode.Success && !IPAddress.Any.Equals(reply.ExternalAddress)
            ? reply.ExternalAddress
            : null;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Section 3.4: a request with "the Requested Lifetime in Seconds set to zero", whose
    /// "Suggested External Port MUST be set to zero by the client on sending". The gateway's
    /// success answer carries external port 0 and lifetime 0.
    /// </remarks>
    public override async Task<bool> DeleteAsync(TimeSpan budget, CancellationToken cancellationToken)
    {
        if (_assignedPort == 0)
        {
            return true;
        }

        var reply = await ExchangeAsync(
                NatPmpMessage.MapTcpRequest(InternalPort, 0, 0),
                IsMappingAnswer,
                Options.NatPmpAttempts,
                budget,
                cancellationToken)
            .ConfigureAwait(false);

        if (reply is null)
        {
            return false;
        }

        NoteEpoch(reply.Epoch);
        if (reply.Result != NatPmpResultCode.Success || reply.ExternalPort != 0 || reply.Lifetime != 0)
        {
            Log?.Invoke(Say($"{Gateway} did not confirm the deletion: {reply.Result}"));
            return false;
        }

        _assignedPort = 0;
        return true;
    }

    private bool IsMappingAnswer(NatPmpReply reply) =>
        reply.Kind == NatPmpReplyKind.MapTcp && reply.InternalPort == InternalPort;

    /// <summary>
    /// Sends <paramref name="request"/> on section 3.1's schedule, 250 ms and then twice as
    /// long each time, until an answer arrives, the attempts run out or the budget is spent.
    /// </summary>
    private async Task<NatPmpReply?> ExchangeAsync(
        byte[] request,
        Func<NatPmpReply, bool> isAnswer,
        int attempts,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        var channel = GatewayUdpChannel.Open(new IPEndPoint(Gateway, Options.PcpServerPort));
        try
        {
            var end = Stopwatch.GetTimestamp() + (long)(budget.TotalSeconds * Stopwatch.Frequency);
            var interval = Options.NatPmpInitialRetransmission;

            for (var attempt = 0; attempt < attempts; attempt++)
            {
                await channel.SendAsync(request, cancellationToken).ConfigureAwait(false);

                var resendAt = Math.Min(end, Stopwatch.GetTimestamp() + (long)(interval.TotalSeconds * Stopwatch.Frequency));
                while (await channel.ReceiveAsync(resendAt, cancellationToken).ConfigureAwait(false) is { } datagram)
                {
                    var reply = NatPmpMessage.Parse(datagram);
                    if (isAnswer(reply))
                    {
                        return reply;
                    }

                    channel.CountIgnored();
                }

                if (Stopwatch.GetTimestamp() >= end)
                {
                    return null;
                }

                interval *= 2;
            }

            return null;
        }
        finally
        {
            Ignored += channel.Ignored;
            channel.Dispose();
        }
    }

    private void NoteEpoch(uint epoch)
    {
        if (!_epoch.AcceptNatPmp(epoch))
        {
            Log?.Invoke(Say($"{Gateway} restarted and lost its mappings (epoch {epoch})"));
        }
    }

    private static string Say(FormattableString text) =>
        "NAT-PMP: " + text.ToString(CultureInfo.InvariantCulture);
}
