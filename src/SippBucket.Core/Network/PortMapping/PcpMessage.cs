using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// The PCP <c>MAP</c> request and response, byte for byte as RFC 6887 draws them.
/// </summary>
/// <remarks>
/// <para>
/// Layouts from RFC 6887 (https://www.rfc-editor.org/rfc/rfc6887): the common request
/// header drawn in section 7.1, the common response header drawn in section 7.2, and the
/// <c>MAP</c> opcode's request and response, Figures 9 and 10 in section 11.1. Every number
/// is "most significant octet first" (section 7), and every address field is 128 bits, an
/// IPv4 address being written as an IPv4-mapped IPv6 address (section 5).
/// </para>
/// <para>
/// Only the <c>MAP</c> opcode, and no options. In particular never <c>THIRD_PARTY</c>, which
/// is how a PCP client asks for a mapping to some other machine: without it the mapping is
/// for the address the request came from, which is the "to this machine only" rule.
/// </para>
/// </remarks>
internal static class PcpMessage
{
    /// <summary>The PCP version this speaks (section 7.1: "Version = 2").</summary>
    public const byte Version = 2;

    /// <summary>
    /// The <c>MAP</c> opcode, 1 in IANA's PCP Opcodes registry
    /// (https://www.iana.org/assignments/pcp-parameters/pcp-parameters.xhtml).
    /// </summary>
    public const byte MapOpcode = 1;

    /// <summary>The R bit: set in a response, clear in a request (section 7.1).</summary>
    public const byte ResponseBit = 0x80;

    /// <summary>TCP, from the IANA protocol numbers the Protocol field uses (section 11.1).</summary>
    public const byte TcpProtocol = 6;

    /// <summary>The common header, request or response: 24 bytes.</summary>
    public const int HeaderSize = 24;

    /// <summary>The <c>MAP</c> opcode-specific part: 36 bytes.</summary>
    public const int MapPayloadSize = 36;

    /// <summary>A <c>MAP</c> request or response with no options.</summary>
    public const int MapMessageSize = HeaderSize + MapPayloadSize;

    /// <summary>The largest PCP message: "a maximum UDP payload length of 1100 octets" (section 7).</summary>
    public const int MaximumSize = 1100;

    /// <summary>The Mapping Nonce: 96 bits (Figure 9).</summary>
    public const int NonceSize = 12;

    /// <summary>NAT-PMP's result code 1, Unsupported Version, a 16-bit number (RFC 6886 section 3.5).</summary>
    private const ushort NatPmpUnsupportedVersion = 1;

    /// <summary>Builds a <c>MAP</c> request: section 7.1's header followed by Figure 9.</summary>
    /// <param name="requestedLifetime">Seconds; zero deletes the mapping (section 15).</param>
    /// <param name="client">This machine's address, as the gateway will see it.</param>
    /// <param name="nonce">The mapping nonce, <see cref="NonceSize"/> bytes.</param>
    /// <param name="internalPort">The port on this machine. Never zero, which means "all ports".</param>
    /// <param name="suggestedExternalPort">The external port asked for, or zero for no preference.</param>
    /// <param name="suggestedExternalAddress">The external address asked for, or null for none.</param>
    /// <returns>The 60-byte datagram.</returns>
    public static byte[] MapRequest(
        uint requestedLifetime,
        IPAddress client,
        ReadOnlySpan<byte> nonce,
        ushort internalPort,
        ushort suggestedExternalPort,
        IPAddress? suggestedExternalAddress)
    {
        ArgumentNullException.ThrowIfNull(client);

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException("A PCP mapping nonce is 96 bits.", nameof(nonce));
        }

        if (internalPort == 0)
        {
            // Figure 9's Internal Port: "The value 0 indicates 'all ports'". Never.
            throw new ArgumentOutOfRangeException(nameof(internalPort), internalPort, "Port 0 would map every port.");
        }

        var message = new byte[MapMessageSize];
        var span = message.AsSpan();

        // Section 7.1: Version, R (clear) and Opcode, Reserved (16 bits, zero), Requested
        // Lifetime, PCP Client's IP Address.
        span[0] = Version;
        span[1] = MapOpcode;
        BinaryPrimitives.WriteUInt32BigEndian(span[4..], requestedLifetime);
        WriteAddress(span.Slice(8, 16), client);

        // Figure 9: Mapping Nonce, Protocol, Reserved (24 bits, zero), Internal Port,
        // Suggested External Port, Suggested External IP Address.
        nonce.CopyTo(span.Slice(24, NonceSize));
        span[36] = TcpProtocol;
        BinaryPrimitives.WriteUInt16BigEndian(span[40..], internalPort);
        BinaryPrimitives.WriteUInt16BigEndian(span[42..], suggestedExternalPort);
        WriteAddress(span.Slice(44, 16), suggestedExternalAddress ?? IPAddress.Any);

        return message;
    }

    /// <summary>Reads a datagram as a PCP response, applying section 8.3's size and bit rules.</summary>
    /// <param name="datagram">The datagram, already known to come from the gateway's PCP port.</param>
    /// <returns>What it is. <see cref="PcpReplyKind.Invalid"/> for anything to be ignored.</returns>
    public static PcpReply Parse(ReadOnlySpan<byte> datagram)
    {
        // Section 8.3: "If the received PCP response message is less than 4 octets long, it
        // is silently dropped."
        if (datagram.Length < 4)
        {
            return PcpReply.Invalid;
        }

        if (datagram[0] == 0)
        {
            return ParseNatPmpRefusal(datagram);
        }

        // Section 8.3: "If the R bit is clear, the message is silently dropped." Then:
        // "Responses shorter than 24 octets, longer than 1100 octets, or not a multiple of
        // 4 octets are invalid and ignored."
        if ((datagram[1] & ResponseBit) == 0 ||
            datagram.Length < HeaderSize ||
            datagram.Length > MaximumSize ||
            datagram.Length % 4 != 0)
        {
            return PcpReply.Invalid;
        }

        // Section 7.2: Version, R and Opcode, Reserved (8 bits), Result Code, Lifetime, Epoch
        // Time, Reserved (96 bits).
        var reply = new PcpReply
        {
            Kind = PcpReplyKind.Header,
            Version = datagram[0],
            Opcode = (byte)(datagram[1] & ~ResponseBit),
            Result = (PcpResultCode)datagram[3],
            Lifetime = BinaryPrimitives.ReadUInt32BigEndian(datagram[4..]),
            Epoch = BinaryPrimitives.ReadUInt32BigEndian(datagram[8..]),
        };

        if (reply.Opcode != MapOpcode || datagram.Length < MapMessageSize)
        {
            return reply;
        }

        // Figure 10: Mapping Nonce, Protocol, Reserved (24 bits), Internal Port, Assigned
        // External Port, Assigned External IP Address. Anything after it is options, which
        // this never asked for and ignores.
        return reply with
        {
            Kind = PcpReplyKind.Map,
            Nonce = datagram.Slice(24, NonceSize).ToArray(),
            Protocol = datagram[36],
            InternalPort = BinaryPrimitives.ReadUInt16BigEndian(datagram[40..]),
            ExternalPort = BinaryPrimitives.ReadUInt16BigEndian(datagram[42..]),
            ExternalAddress = ReadAddress(datagram.Slice(44, 16)),
        };
    }

    /// <summary>Writes an address in PCP's 128-bit form (RFC 6887 section 5).</summary>
    /// <param name="destination">Sixteen bytes.</param>
    /// <param name="address">An IPv4 or IPv6 address.</param>
    /// <remarks>
    /// IPv4 becomes <c>::ffff:a.b.c.d</c>: "the first 80 bits set to zero and the next 16 set
    /// to one, while its last 32 bits are filled with the IPv4 address". So the IPv4 all-zeros
    /// address, which is what a request with no preference and a deletion both carry
    /// (section 11.1, and erratum 3621 on section 15.1), is <c>::ffff:0:0</c>, not <c>::</c>.
    /// </remarks>
    public static void WriteAddress(Span<byte> destination, IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        var mapped = address.AddressFamily == AddressFamily.InterNetwork
            ? address.MapToIPv6()
            : address;

        if (!mapped.TryWriteBytes(destination[..16], out var written) || written != 16)
        {
            throw new ArgumentException("Not an address PCP can carry.", nameof(address));
        }
    }

    /// <summary>Reads a 128-bit PCP address, turning an IPv4-mapped one back into IPv4.</summary>
    /// <param name="source">Sixteen bytes.</param>
    /// <returns>The address.</returns>
    public static IPAddress ReadAddress(ReadOnlySpan<byte> source)
    {
        var address = new IPAddress(source[..16]);
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    /// <summary>
    /// Recognises a NAT-PMP gateway's answer to a PCP request (RFC 6887 section 9).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A NAT-PMP gateway answers a request whose version is not 0 with "Unsupported Version":
    /// version 0, an opcode byte, result code 1 as a 16-bit number, and its Seconds Since
    /// Start of Epoch, eight bytes in all (RFC 6886 sections 1.1 and 3.5). RFC 6887 section 9:
    /// "If the version number in the UNSUPP_VERSION response is zero then that means this is
    /// a NAT-PMP server". Eight bytes is shorter than RFC 6887 section 8.3's 24-byte minimum,
    /// and its R bit may be clear, so this is recognised before those rules apply; without
    /// that, section 9 could never be followed.
    /// </para>
    /// <para>
    /// <strong>The opcode byte takes two values in the wild, and both are accepted.</strong>
    /// RFC 6886 section 3.5 draws this reply with <c>OP = 0</c>, as read through two
    /// renderings of the RFC. miniupnpd, a common router implementation, answers
    /// <c>128 + opcode</c> instead, that is <c>0x81</c> for a PCP <c>MAP</c>: its
    /// <c>natpmp.c</c> sets <c>resp[1] = 128 + req[1]</c> before checking the version
    /// (https://github.com/miniupnp/miniupnp/blob/master/miniupnpd/natpmp.c). Anything else in
    /// that byte is not this reply.
    /// </para>
    /// <para>
    /// The reply carries no nonce, because NAT-PMP has none. What stops it being anyone's:
    /// the caller has already required it to come from the gateway's own address and port,
    /// and all it can do is send the next question to the same gateway in NAT-PMP.
    /// </para>
    /// </remarks>
    private static PcpReply ParseNatPmpRefusal(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < 8 ||
            datagram.Length > MaximumSize ||
            datagram.Length % 4 != 0 ||
            datagram[1] is not (0 or (ResponseBit | MapOpcode)) ||
            BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]) != NatPmpUnsupportedVersion)
        {
            return PcpReply.Invalid;
        }

        return new PcpReply
        {
            Kind = PcpReplyKind.NatPmpUnsupportedVersion,
            Version = 0,
            Opcode = MapOpcode,
            Epoch = BinaryPrimitives.ReadUInt32BigEndian(datagram[4..]),
        };
    }
}

/// <summary>What a datagram from the gateway's PCP port turned out to be.</summary>
internal enum PcpReplyKind
{
    /// <summary>Not a PCP response: ignored.</summary>
    Invalid = 0,

    /// <summary>A PCP response header with no <c>MAP</c> payload to match against a request.</summary>
    Header = 1,

    /// <summary>A PCP <c>MAP</c> response, Figure 10.</summary>
    Map = 2,

    /// <summary>NAT-PMP's "Unsupported Version": this gateway speaks NAT-PMP and not PCP.</summary>
    NatPmpUnsupportedVersion = 3,
}

/// <summary>The fields of a PCP response, as far as they were present.</summary>
internal sealed record PcpReply
{
    /// <summary>Something to ignore.</summary>
    public static PcpReply Invalid { get; } = new();

    /// <summary>What the datagram was.</summary>
    public PcpReplyKind Kind { get; init; }

    /// <summary>The Version field.</summary>
    public byte Version { get; init; }

    /// <summary>The Opcode, without the R bit.</summary>
    public byte Opcode { get; init; }

    /// <summary>The Result Code.</summary>
    public PcpResultCode Result { get; init; }

    /// <summary>The Lifetime field, in seconds: the mapping's on success, the error's on failure.</summary>
    public uint Lifetime { get; init; }

    /// <summary>The Epoch Time field, in seconds (section 8.5).</summary>
    public uint Epoch { get; init; }

    /// <summary>The Mapping Nonce copied from the request.</summary>
    public byte[] Nonce { get; init; } = [];

    /// <summary>The Protocol field.</summary>
    public byte Protocol { get; init; }

    /// <summary>The Internal Port.</summary>
    public ushort InternalPort { get; init; }

    /// <summary>The Assigned External Port.</summary>
    public ushort ExternalPort { get; init; }

    /// <summary>The Assigned External IP Address.</summary>
    public IPAddress? ExternalAddress { get; init; }
}

/// <summary>
/// PCP result codes, RFC 6887 section 7.4, with the values of IANA's PCP Result Codes registry.
/// </summary>
internal enum PcpResultCode : byte
{
    /// <summary>Success.</summary>
    Success = 0,

    /// <summary>The version at the start of the request is not recognised.</summary>
    UnsupportedVersion = 1,

    /// <summary>Disabled for this client, or refused by the server's security policy.</summary>
    NotAuthorized = 2,

    /// <summary>The request could not be parsed.</summary>
    MalformedRequest = 3,

    /// <summary>Unsupported opcode.</summary>
    UnsupportedOpcode = 4,

    /// <summary>Unsupported mandatory option.</summary>
    UnsupportedOption = 5,

    /// <summary>Malformed option.</summary>
    MalformedOption = 6,

    /// <summary>The server or device is experiencing a network failure.</summary>
    NetworkFailure = 7,

    /// <summary>Insufficient resources at this time.</summary>
    NoResources = 8,

    /// <summary>Unsupported transport protocol.</summary>
    UnsupportedProtocol = 9,

    /// <summary>The mapping would exceed this subscriber's port quota.</summary>
    UserExceededQuota = 10,

    /// <summary>The suggested external port or address cannot be provided.</summary>
    CannotProvideExternal = 11,

    /// <summary>The request's source address does not match the PCP Client's IP Address field.</summary>
    AddressMismatch = 12,

    /// <summary>The server could not create the filters in this request.</summary>
    ExcessiveRemotePeers = 13,
}
