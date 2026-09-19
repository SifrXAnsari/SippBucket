using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>This machine's IPv4 default gateway: the home router, on a home network.</summary>
/// <remarks>
/// The same choice <c>NetworkIdentity</c> makes for per-network consent: the first adapter
/// that is up, is not loopback, and has both an IPv4 default gateway and an IPv4 address of
/// its own. A machine with Wi-Fi, Ethernet and a VPN at once can have more than one such
/// adapter, and then this asks whichever Windows lists first. Every result and log line names
/// the gateway it asked, so a person can see which router that was. IPv4 only: the listeners
/// bind IPv4 only (D-63).
/// </remarks>
internal static class DefaultGateway
{
    /// <summary>The gateway's address, or null when there is no IPv4 default gateway.</summary>
    /// <returns>The address.</returns>
    public static IPAddress? FindIPv4()
    {
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            var properties = adapter.GetIPProperties();

            var gateway = properties.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a is not null &&
                                     a.AddressFamily == AddressFamily.InterNetwork &&
                                     !a.Equals(IPAddress.Any));

            if (gateway is not null &&
                properties.UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
            {
                return gateway;
            }
        }

        return null;
    }
}
