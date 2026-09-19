using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SippBucket.Core.Platform;

/// <summary>
/// The IPv4 addresses another machine could use to reach this one, most likely first.
/// </summary>
/// <remarks>
/// <para>
/// Exists because of D-43. <c>sip pair offer</c> with no address argument used to put
/// <c>127.0.0.1</c> into what it handed the other machine, and the other machine stored
/// that as the address of its new peer: two real machines paired successfully and then
/// could not sync, because each was being told to reach the other at itself.
/// </para>
/// <para>
/// So this lists what is actually usable, and puts the ones with a default gateway first,
/// because the adapter carrying the default route is the one on the network the other
/// machine is most likely to share. It does not guess which one the user means. A machine
/// with Wi-Fi, Ethernet and a VPN has three honest answers, and the person reading them out
/// knows which network the other machine is on; this program does not.
/// </para>
/// <para>
/// <strong>What is left out, and why (D-63).</strong> The first version listed everything
/// that was up and not loopback, and on the desktop that printed 192.168.1.98, 169.254.83.107
/// and 172.26.192.1. The second is the link-local address Windows gave the Tailscale adapter,
/// which had no Tailscale address of its own; the third is the host's side of WSL's virtual
/// switch. Neither can be
/// reached from another machine, and an invite tries its addresses in order, so an
/// unreachable one first costs the joiner a connection timeout. Left out:
/// </para>
/// <list type="bullet">
/// <item>An interface that is not <see cref="OperationalStatus.Up"/>
/// (<see cref="NetworkInterface.OperationalStatus"/>).</item>
/// <item>Anything that is not IPv4. The listeners are IPv4 only until D-05.</item>
/// <item>Loopback: the loopback interface (<see cref="NetworkInterfaceType.Loopback"/>) and
/// any 127.0.0.0/8 address.</item>
/// <item>Link-local 169.254.0.0/16. Windows assigns one when no address was configured, and
/// RFC 3927 section 2.7 says a packet to or from one "MUST NOT be sent to any router for
/// forwarding" (https://www.rfc-editor.org/rfc/rfc3927): at best it reaches the same
/// cable, and only when the other machine has also failed to get an address.</item>
/// <item>A Hyper-V virtual adapter with no default gateway, which is what WSL's switch and
/// Hyper-V's Default Switch present on the host. Microsoft describes an internal switch as
/// one "that can be used only by the virtual machines running on the host that has the
/// virtual switch, and between the host and the virtual machines"
/// (https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/plan-hyper-v-networking-in-windows-server),
/// and WSL "by default ... uses a NAT based architecture"
/// (https://learn.microsoft.com/en-us/windows/wsl/networking). The adapter is recognised
/// by its <see cref="NetworkInterface.Description"/>, "Hyper-V Virtual Ethernet Adapter",
/// which is what the desktop's WSL adapter reports (measured, not assumed), and the
/// gateway is <see cref="IPInterfaceProperties.GatewayAddresses"/>. An external Hyper-V
/// switch carries the host's real LAN address on an adapter with the same description,
/// and it has the LAN's gateway, so it is kept.</item>
/// </list>
/// <para>
/// <strong>Kept on purpose:</strong> a VPN or mesh adapter with an address of its own and no
/// default gateway, such as Tailscale once it is connected. Its address is how a machine on
/// another network reaches this one, which is the route the debt sheet names for D-05, and
/// with no gateway it sorts after every address that has one, so it is only tried when
/// those have failed. A gateway-less physical adapter, a cable run straight between the two
/// machines, is kept for the same reason. What cannot be recognised from the properties
/// above, VirtualBox's and VMware's host-only adapters for instance, is not left out: this
/// build has no measured description for them, and guessing one would be the thing the
/// uncertainty rule forbids.
/// </para>
/// </remarks>
public static class LocalAddresses
{
    /// <summary>
    /// The start of <see cref="NetworkInterface.Description"/> on a Hyper-V virtual adapter.
    /// </summary>
    /// <remarks>
    /// Read from the desktop's WSL adapter, "vEthernet (WSL (Hyper-V firewall))", whose
    /// description is exactly this; a second adapter is numbered "... #2". Compared as a
    /// prefix, ignoring case.
    /// </remarks>
    internal const string HyperVAdapterDescription = "Hyper-V Virtual Ethernet Adapter";

    /// <summary>This machine's usable IPv4 addresses, gateway interfaces first.</summary>
    /// <returns>Dotted-quad addresses. Empty when there is no usable interface.</returns>
    public static IReadOnlyList<string> UsableIPv4()
    {
        var candidates = new List<Candidate>();

        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            var properties = adapter.GetIPProperties();

            var hasGateway = properties.GatewayAddresses.Any(g =>
                g.Address is { AddressFamily: AddressFamily.InterNetwork } gateway &&
                !gateway.Equals(IPAddress.Any));

            var isHyperV = adapter.Description.StartsWith(
                HyperVAdapterDescription, StringComparison.OrdinalIgnoreCase);

            foreach (var unicast in properties.UnicastAddresses)
            {
                candidates.Add(new Candidate(
                    unicast.Address,
                    adapter.OperationalStatus == OperationalStatus.Up,
                    adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback,
                    hasGateway)
                {
                    IsHyperVAdapter = isHyperV,
                });
            }
        }

        return Choose(candidates);
    }

    /// <summary>The filtering and ordering, separated from the operating system so it can be tested.</summary>
    /// <param name="candidates">Every address on every interface.</param>
    /// <returns>The usable IPv4 ones, gateway interfaces first, otherwise in the order given.</returns>
    internal static IReadOnlyList<string> Choose(IEnumerable<Candidate> candidates) =>
        [.. candidates
            .Where(IsUsable)
            .OrderBy(c => c.HasGateway ? 0 : 1)
            .Select(c => c.Address.ToString())
            .Distinct(StringComparer.Ordinal)];

    /// <summary>Whether another machine could reach this address. See the class remarks.</summary>
    private static bool IsUsable(Candidate candidate) =>
        candidate.IsUp &&
        !candidate.IsLoopbackInterface &&
        candidate.Address.AddressFamily == AddressFamily.InterNetwork &&
        !IPAddress.IsLoopback(candidate.Address) &&
        !candidate.Address.Equals(IPAddress.Any) &&
        !IsLinkLocal(candidate.Address) &&
        !(candidate.IsHyperVAdapter && !candidate.HasGateway);

    /// <summary>Whether an IPv4 address is in 169.254.0.0/16 (RFC 3927).</summary>
    private static bool IsLinkLocal(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        return address.TryWriteBytes(bytes, out var written) &&
               written == 4 &&
               bytes[0] == 169 &&
               bytes[1] == 254;
    }

    /// <summary>One address, and what is known about the interface carrying it.</summary>
    /// <param name="Address">The address.</param>
    /// <param name="IsUp">Whether the interface is up.</param>
    /// <param name="IsLoopbackInterface">Whether the interface is the loopback adapter.</param>
    /// <param name="HasGateway">Whether the interface has an IPv4 default gateway.</param>
    internal readonly record struct Candidate(
        IPAddress Address,
        bool IsUp,
        bool IsLoopbackInterface,
        bool HasGateway)
    {
        /// <summary>Whether the interface is a Hyper-V virtual adapter, WSL's included.</summary>
        public bool IsHyperVAdapter { get; init; }
    }
}
