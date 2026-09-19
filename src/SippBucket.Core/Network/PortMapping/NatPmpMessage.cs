using System.Buffers.Binary;
using System.Net;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// The NAT-PMP requests and responses this uses, byte for byte as RFC 6886 draws them.
/// </summary>
/// <remarks>
/// <para>
/// Layouts from RFC 6886 (https://www.rfc-editor.org/rfc/rfc6886): the external address
/// request and response in section 3.2, the mapping request and response in section 3.3.
/// Numbers are in network byte order.
/// </para>
/// <para>
/// Only the sizes the RFC defines are accepted: 12 bytes for an external address response and
/// 16 for a mapping response. The RFC says nothing about longer ones, and a reply that is not
/// the size it should be is not trusted to mean what its first bytes say.
/// </para>
/// </remarks>
internal static class NatPmpMessage
{
    /// <summary>NAT-PMP's version: "Vers = 0".</summary>
    public const byte Version = 0;

    /// <summary>The external address request, "OP = 0" (section 3.2).</summary>
    public const byte ExternalAddressOpcode = 0;

    /// <summary>Map TCP, "OP = 2" (section 3.3: 1 is UDP, 2 is TCP).</summary>
    public const byte MapTcpOpcode = 2;

    /// <summary>A response's opcode is the request's plus 128 ("OP = 128 + x").</summary>
    public const byte ResponseOffset = 128;

    /// <summary>The external address response: 12 bytes.</summary>
    public const int ExternalAddressResponseSize = 12;

    /// <summary>The mapping request: 12 bytes.</summary>
    public const int MapRequestSize = 12;

    /// <summary>The mapping response: 16 bytes.</summary>
    public const int MapResponseSize = 16;

    /// <summary>Builds the external address request, section 3.2: version and opcode, both zero.</summary>
    /// <returns>The two-byte datagram.</returns>
    public static byte[] ExternalAddressRequest() => [Version, ExternalAddressOpcode];

    /// <summary>Builds a TCP mapping request, section 3.3.</summary>
    /// <param name="internalPort">The port on this machine. Never zero.</param>
    /// <param name="suggestedExternalPort">The external port asked for; zero when deleting.</param>
    /// <param name="lifetime">The requested lifetime in seconds; zero deletes (section 3.4).</param>
    /// <returns>The 12-byte datagram.</returns>
    public static byte[] MapTcpRequest(ushort internalPort, ushort suggestedExternalPort, uint lifetime)
    {
        if (internalPort == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(internalPort), internalPort, "Internal port 0 is not a port.");
        }

        // Vers = 0, OP = 2, Reserved (16 bits, "MUST be set to zero on transmission"),
        // Internal Port, Suggested External Port, Requested Port Mapping Lifetime in Seconds.
        var message = new byte[MapRequestSize];
        var span = message.AsSpan();
        span[0] = Version;
        span[1] = MapTcpOpcode;
        BinaryPrimitives.WriteUInt16BigEndian(span[4..], internalPort);
        BinaryPrimitives.WriteUInt16BigEndian(span[6..], suggestedExternalPort);
        BinaryPrimitives.WriteUInt32BigEndian(span[8..], lifetime);
        return message;
    }

    /// <summary>Reads a datagram as a NAT-PMP response.</summary>
    /// <param name="datagram">The datagram, already known to come from the gateway's port.</param>
    /// <returns>What it is. <see cref="NatPmpReplyKind.Invalid"/> for anything to be ignored.</returns>
    public static NatPmpReply Parse(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < 8 || datagram[0] != Version)
        {
            return NatPmpReply.Invalid;
        }

        var result = (NatPmpResultCode)BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);
        var epoch = BinaryPrimitives.ReadUInt32BigEndian(datagram[4..]);

        // Section 3.2: Vers = 0, OP = 128 + 0, Result Code, Seconds Since Start of Epoch,
        // External IPv4 Address.
        if (datagram[1] == ResponseOffset + ExternalAddressOpcode &&
            datagram.Length == ExternalAddressResponseSize)
        {
            return new NatPmpReply
            {
                Kind = NatPmpReplyKind.ExternalAddress,
                Result = result,
                Epoch = epoch,
                ExternalAddress = new IPAddress(datagram.Slice(8, 4)),
            };
        }

        // Section 3.3: Vers = 0, OP = 128 + x, Result Code, Seconds Since Start of Epoch,
        // Internal Port, Mapped External Port, Port Mapping Lifetime in Seconds.
        if (datagram[1] == ResponseOffset + MapTcpOpcode &&
            datagram.Length == MapResponseSize)
        {
            return new NatPmpReply
            {
                Kind = NatPmpReplyKind.MapTcp,
                Result = result,
                Epoch = epoch,
                InternalPort = BinaryPrimitives.ReadUInt16BigEndian(datagram[8..]),
                ExternalPort = BinaryPrimitives.ReadUInt16BigEndian(datagram[10..]),
                Lifetime = BinaryPrimitives.ReadUInt32BigEndian(datagram[12..]),
            };
        }

        return NatPmpReply.Invalid;
    }
}

/// <summary>What a datagram from the gateway's NAT-PMP port turned out to be.</summary>
internal enum NatPmpReplyKind
{
    /// <summary>Not a response this understands: ignored.</summary>
    Invalid = 0,

    /// <summary>An external address response, section 3.2.</summary>
    ExternalAddress = 1,

    /// <summary>A TCP mapping response, section 3.3.</summary>
    MapTcp = 2,
}

/// <summary>The fields of a NAT-PMP response.</summary>
internal sealed record NatPmpReply
{
    /// <summary>Something to ignore.</summary>
    public static NatPmpReply Invalid { get; } = new();

    /// <summary>What the datagram was.</summary>
    public NatPmpReplyKind Kind { get; init; }

    /// <summary>The Result Code.</summary>
    public NatPmpResultCode Result { get; init; }

    /// <summary>Seconds Since Start of Epoch (section 3.6).</summary>
    public uint Epoch { get; init; }

    /// <summary>The Internal Port of a mapping response.</summary>
    public ushort InternalPort { get; init; }

    /// <summary>The Mapped External Port of a mapping response.</summary>
    public ushort ExternalPort { get; init; }

    /// <summary>The Port Mapping Lifetime in Seconds of a mapping response.</summary>
    public uint Lifetime { get; init; }

    /// <summary>The External IPv4 Address of an external address response.</summary>
    public IPAddress? ExternalAddress { get; init; }
}

/// <summary>NAT-PMP result codes, RFC 6886 section 3.5.</summary>
internal enum NatPmpResultCode : ushort
{
    /// <summary>Success.</summary>
    Success = 0,

    /// <summary>Unsupported Version.</summary>
    UnsupportedVersion = 1,

    /// <summary>Not Authorized/Refused.</summary>
    NotAuthorized = 2,

    /// <summary>Network Failure.</summary>
    NetworkFailure = 3,

    /// <summary>Out of resources.</summary>
    OutOfResources = 4,

    /// <summary>Unsupported opcode.</summary>
    UnsupportedOpcode = 5,
}
