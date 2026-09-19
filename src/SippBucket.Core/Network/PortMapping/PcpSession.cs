using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// A PCP <c>MAP</c> mapping for one TCP port, RFC 6887 section 11.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What an answer must be to count.</strong> From the gateway's address and PCP port
/// (<see cref="GatewayUdpChannel"/>), a valid PCP response by section 8.3's size and bit
/// rules, and a <c>MAP</c> response whose Mapping Nonce, Protocol and Internal Port are this
/// request's. Section 11.3 has a gateway refuse a request that matches an existing mapping
/// "but the mapping nonce does not match" with NOT_AUTHORIZED (as quoted in
/// https://github.com/GeiserX/tailscaled-rs/pull/373; section 11.3 itself was not readable
/// in full here), so the nonce is what makes a mapping this session's. An answer carrying
/// another nonce is somebody else's, or forged, and is ignored. The one exception is
/// NAT-PMP's eight-byte "Unsupported Version", which has no nonce to carry (see
/// <see cref="PcpMessage.Parse"/>).
/// </para>
/// <para>
/// <strong>One nonce for the mapping's life.</strong> Drawn once, "following accepted
/// practices for generating unguessable random numbers" (section 11.1), and used for the
/// request, every retransmission ("The retransmissions MUST use the same Mapping Nonce
/// value", section 11.2.1), every renewal and the deletion. A deletion with a fresh nonce is
/// refused with NOT_AUTHORIZED and leaves the port open until it expires, which is the bug
/// that pull request fixed.
/// </para>
/// <para>
/// <strong>What it asks for.</strong> TCP, the one internal port, the external port equal to
/// it on the first request, and no preference of external address. A renewal asks for the
/// port and address the gateway assigned, as section 11.2.1 says it SHOULD, "so if the PCP
/// server has lost state it can recreate the lost mapping". Never options, so never
/// <c>THIRD_PARTY</c>: the mapping is always to the address the request came from.
/// </para>
/// </remarks>
internal sealed class PcpSession : MappingSession
{
    private static readonly TimeSpan LongestRetryAfter = TimeSpan.FromDays(1);

    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(PcpMessage.NonceSize);
    private readonly GatewayEpoch _epoch = new();
    private ushort _assignedPort;
    private IPAddress? _assignedAddress;

    /// <summary>Creates a session. Nothing is sent until <see cref="RequestAsync"/>.</summary>
    /// <param name="gateway">The gateway.</param>
    /// <param name="internalAddress">This machine's address on the route to it.</param>
    /// <param name="internalPort">The port to map.</param>
    /// <param name="options">Destinations and timings.</param>
    /// <param name="log">Optional sink for log lines.</param>
    public PcpSession(
        IPAddress gateway,
        IPAddress internalAddress,
        ushort internalPort,
        PortMapperOptions options,
        Action<string>? log)
        : base(gateway, internalAddress, internalPort, options, log)
    {
    }

    /// <inheritdoc />
    public override PortMappingProtocol Protocol => PortMappingProtocol.Pcp;

    /// <inheritdoc />
    public override int GatewayRestarts => _epoch.Restarts;

    /// <summary>The Mapping Nonce every request of this session carries.</summary>
    internal ReadOnlySpan<byte> Nonce => _nonce;

    /// <inheritdoc />
    /// <remarks>
    /// A first request is retransmitted by section 8.1.1's schedule until the budget ends. A
    /// renewal is "a single renewal request packet" (section 11.2.1), answered or not by the
    /// end of its budget, after which the caller sends the next one on the renewal schedule.
    /// </remarks>
    public override async Task<SessionOutcome> RequestAsync(
        uint lifetimeSeconds,
        bool renewal,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        var request = PcpMessage.MapRequest(
            lifetimeSeconds,
            InternalAddress,
            _nonce,
            InternalPort,
            _assignedPort != 0 ? _assignedPort : InternalPort,
            _assignedAddress);

        var reply = await ExchangeAsync(request, singlePacket: renewal, budget, cancellationToken)
            .ConfigureAwait(false);

        if (reply is null)
        {
            return SessionOutcome.Failed(
                PortMappingFailure.NoAnswer,
                Say($"no PCP answer from {Gateway} within {budget.TotalSeconds:0.#} s"));
        }

        if (reply.Kind == PcpReplyKind.NatPmpUnsupportedVersion)
        {
            return new SessionOutcome
            {
                Failure = PortMappingFailure.Refused,
                Detail = Say($"{Gateway} answered in NAT-PMP: unsupported version"),
                GatewaySpeaksNatPmp = true,
            };
        }

        if (reply.Version != PcpMessage.Version)
        {
            return SessionOutcome.Failed(
                PortMappingFailure.Refused,
                Say($"{Gateway} speaks PCP version {reply.Version} only, not {PcpMessage.Version}"));
        }

        NoteEpoch(reply.Epoch);

        if (reply.Result != PcpResultCode.Success)
        {
            var retryAfter = TimeSpan.FromSeconds(reply.Lifetime);
            return SessionOutcome.Failed(
                reply.Result == PcpResultCode.CannotProvideExternal
                    ? PortMappingFailure.ExternalPortInUse
                    : PortMappingFailure.Refused,
                Say($"{Gateway} refused the PCP MAP: {reply.Result} ({(int)reply.Result})"),
                retryAfter < LongestRetryAfter ? retryAfter : LongestRetryAfter);
        }

        if (reply.ExternalPort == 0 || reply.Lifetime == 0)
        {
            return SessionOutcome.Failed(
                PortMappingFailure.Refused,
                Say($"{Gateway} answered SUCCESS with port {reply.ExternalPort} for {reply.Lifetime} s"));
        }

        _assignedPort = reply.ExternalPort;
        _assignedAddress = reply.ExternalAddress is { AddressFamily: AddressFamily.InterNetwork } address &&
                           !address.Equals(IPAddress.Any)
            ? address
            : null;

        return SessionOutcome.Granted(
            new MappingGrant(_assignedPort, _assignedAddress, TimeSpan.FromSeconds(reply.Lifetime)));
    }

    /// <inheritdoc />
    /// <remarks>
    /// Section 15.1 as corrected by erratum 3621 (https://www.rfc-editor.org/errata/eid3621):
    /// Requested Lifetime 0, "the Suggested External Port field MUST be set to zero", and the
    /// Suggested External Address "must be set to the appropriate all-zeros address", here the
    /// IPv4 one. Same nonce as the mapping.
    /// </remarks>
    public override async Task<bool> DeleteAsync(TimeSpan budget, CancellationToken cancellationToken)
    {
        if (_assignedPort == 0)
        {
            return true;
        }

        var request = PcpMessage.MapRequest(0, InternalAddress, _nonce, InternalPort, 0, null);
        var reply = await ExchangeAsync(request, singlePacket: false, budget, cancellationToken)
            .ConfigureAwait(false);

        if (reply is not { Kind: PcpReplyKind.Map, Version: PcpMessage.Version })
        {
            return false;
        }

        NoteEpoch(reply.Epoch);
        if (reply.Result != PcpResultCode.Success)
        {
            Log?.Invoke(Say($"{Gateway} refused to delete the mapping: {reply.Result}"));
            return false;
        }

        _assignedPort = 0;
        _assignedAddress = null;
        return true;
    }

    /// <summary>
    /// Sends <paramref name="request"/> and waits for the answer to it, retransmitting as
    /// section 8.1.1 says, until <paramref name="budget"/> is spent.
    /// </summary>
    /// <returns>The first answer that is this request's, or null.</returns>
    private async Task<PcpReply?> ExchangeAsync(
        byte[] request,
        bool singlePacket,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        var channel = GatewayUdpChannel.Open(new IPEndPoint(Gateway, Options.PcpServerPort));
        try
        {
            var end = Stopwatch.GetTimestamp() + TicksOf(budget);
            var timeout = MappingTimers.FirstPcpTimeout(Options.PcpInitialRetransmission);

            while (true)
            {
                await channel.SendAsync(request, cancellationToken).ConfigureAwait(false);

                var resendAt = singlePacket
                    ? end
                    : Math.Min(end, Stopwatch.GetTimestamp() + TicksOf(timeout));

                while (await channel.ReceiveAsync(resendAt, cancellationToken).ConfigureAwait(false) is { } datagram)
                {
                    var reply = PcpMessage.Parse(datagram);
                    if (IsAnswerTo(reply))
                    {
                        return reply;
                    }

                    channel.CountIgnored();
                }

                if (Stopwatch.GetTimestamp() >= end)
                {
                    return null;
                }

                timeout = MappingTimers.NextPcpTimeout(timeout, Options.PcpMaximumRetransmission);
            }
        }
        finally
        {
            Ignored += channel.Ignored;
            channel.Dispose();
        }
    }

    /// <summary>Whether a parsed datagram is the answer to this session's request.</summary>
    private bool IsAnswerTo(PcpReply reply) => reply.Kind switch
    {
        PcpReplyKind.NatPmpUnsupportedVersion => true,

        // A PCP server of another version refusing ours has nothing of the request to echo
        // back that could be matched, and all it can cause is the next protocol being tried.
        PcpReplyKind.Header or PcpReplyKind.Map when reply.Version != PcpMessage.Version =>
            reply.Result == PcpResultCode.UnsupportedVersion,

        PcpReplyKind.Map =>
            reply.Opcode == PcpMessage.MapOpcode &&
            reply.Protocol == PcpMessage.TcpProtocol &&
            reply.InternalPort == InternalPort &&
            CryptographicOperations.FixedTimeEquals(reply.Nonce, _nonce),

        _ => false,
    };

    private void NoteEpoch(uint epoch)
    {
        if (!_epoch.AcceptPcp(epoch))
        {
            Log?.Invoke(Say($"{Gateway} restarted and lost its mappings (epoch {epoch})"));
        }
    }

    private static long TicksOf(TimeSpan span) => (long)(span.TotalSeconds * Stopwatch.Frequency);

    private static string Say(FormattableString text) =>
        "PCP: " + text.ToString(CultureInfo.InvariantCulture);
}
