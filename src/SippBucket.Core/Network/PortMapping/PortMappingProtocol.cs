namespace SippBucket.Core.Network.PortMapping;

/// <summary>The protocol a home router was asked to forward a port with.</summary>
/// <remarks>
/// Tried in this order, which is the order of preference: PCP, then NAT-PMP when the router
/// answers PCP with NAT-PMP's "unsupported version", then UPnP IGD as the last resort. See
/// <see cref="PortMapper"/> for why.
/// </remarks>
public enum PortMappingProtocol
{
    /// <summary>
    /// The Port Control Protocol, RFC 6887
    /// (https://www.rfc-editor.org/rfc/rfc6887), with the <c>MAP</c> opcode.
    /// </summary>
    Pcp = 0,

    /// <summary>
    /// The NAT Port Mapping Protocol, RFC 6886 (https://www.rfc-editor.org/rfc/rfc6886).
    /// </summary>
    NatPmp = 1,

    /// <summary>
    /// UPnP Internet Gateway Device, <c>WANIPConnection:1</c> or <c>:2</c>, found by SSDP.
    /// </summary>
    UpnpIgd = 2,
}

/// <summary>The names the protocols go by in log lines and summaries.</summary>
internal static class PortMappingProtocolNames
{
    /// <summary>The protocol's usual written name: PCP, NAT-PMP or UPnP IGD.</summary>
    /// <param name="protocol">The protocol.</param>
    /// <returns>The name.</returns>
    public static string Name(this PortMappingProtocol protocol) => protocol switch
    {
        PortMappingProtocol.Pcp => "PCP",
        PortMappingProtocol.NatPmp => "NAT-PMP",
        PortMappingProtocol.UpnpIgd => "UPnP IGD",
        _ => protocol.ToString(),
    };
}
