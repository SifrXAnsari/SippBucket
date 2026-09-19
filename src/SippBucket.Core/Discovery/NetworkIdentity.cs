using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace SippBucket.Core.Discovery;

/// <summary>
/// Works out which network this machine is on, so consent can be keyed to it.
/// </summary>
/// <remarks>
/// <para>
/// Per-network consent needs a way to say "this network" that survives disconnecting and
/// reconnecting, and that tells a café from a home. The identifier is a hash of the
/// default gateway's MAC address, the gateway's IP address and the adapter type, behind a
/// prefix of its own.
/// </para>
/// <para>
/// <strong>Why the MAC (D-18).</strong> The first version hashed the gateway's IP, the
/// local /24 and the adapter type. Two networks that both use <c>192.168.1.1</c> and hand
/// out addresses in the same range, a very common configuration, came out identical, so
/// consent given at home applied in the café. That is a false
/// <em>match</em>, the dangerous direction: it announces where the user never agreed to
/// be announced. Those two routers have different MACs, and the MAC is now in the hash.
/// </para>
/// <para>
/// <strong>Fail closed.</strong> When the MAC cannot be read with confidence the answer is
/// null, meaning no identifiable network, which <see cref="NetworkConsent"/> treats as
/// never announce. There is no fallback to the old approximation, because the fallback is
/// the false match. Listening is unaffected; only announcing needs consent.
/// </para>
/// <para>
/// <strong>Consent recorded under the old identifiers is asked for again, once.</strong>
/// The new material starts with a prefix the old material never had, so an old identifier
/// and a new one are hashes of different strings, and an old decision could match a new
/// ID only through a 64-bit collision of the truncated hash. That is the safe direction. It costs one repeated question per network. Carrying an
/// old "allowed" across would carry across exactly the false matches this removes. Old
/// entries stay in the consent file, unused.
/// </para>
/// <para>
/// <strong>How the MAC is read.</strong> <c>GetIpNetEntry2</c> reads one entry of this
/// machine's neighbor (ARP) cache: the gateway's address, on the gateway's own interface
/// (https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnetentry2).
/// It fills a buffer this code owns, so there is no table to release with
/// <c>FreeMibTable</c>. The page does not say whether a miss triggers resolution, so it
/// was measured on the desktop: for addresses not in the cache it returned
/// <c>ERROR_NOT_FOUND</c> in under 0.1 ms once loaded, and left no entry behind. An
/// address that is being resolved shows up in the cache as Incomplete, so none was.
/// The alternatives were rejected on purpose. <c>ResolveIpNetEntry2</c> first flushes the
/// cached entry and then sends ARP requests, on every call: it changes system state and
/// puts traffic on the wire
/// (https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-resolveipnetentry2).
/// <c>SendARP</c> sends an ARP request whenever the address is not already cached, and
/// returns only an address, with no state, so a stale entry and a fresh one look the same
/// (https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp).
/// <c>GetIpNetTable2</c> would work, but it allocates the whole table, which must then be
/// freed with <c>FreeMibTable</c>, to find the one row this call looks up directly
/// (https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2).
/// </para>
/// <para>
/// <strong>Only a Reachable entry counts.</strong> Reachable means the neighbor was
/// confirmed within the last few tens of seconds
/// (https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2).
/// Stale, Delay and Probe mean it has not been confirmed since, and Microsoft's description
/// of the cache says a Stale entry must be resolved again by ARP before it is used
/// (https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/address-resolution-protocol-arp-caching-behavior).
/// An unconfirmed entry for <c>192.168.1.1</c> can be the router of the network the
/// machine has just left: nothing documented says the cache is emptied when the network
/// changes, so trusting it would bring the false match back. A Permanent entry is a static
/// one somebody typed, never confirmed on the current link, and is refused for the same
/// reason.
/// </para>
/// <para>
/// <strong>What it still does not handle.</strong> A replaced router, or a mesh system
/// whose gateway role moves between units, has a new MAC and looks like a new network:
/// one needless question, the safe direction. A gateway with no MAC at all, as on a
/// point-to-point link or some VPN tunnels, has no ARP entry with a MAC to read, so that
/// network is never identified and never announced on. An idle machine whose gateway has
/// not been confirmed for 15 to 45 seconds gets null until Windows next talks to the
/// gateway, which for discovery means an announcement skipped, not a wrong one. If the
/// cache is not emptied on a network change, the previous gateway's entry can stay
/// Reachable for up to that same 15 to 45 seconds after the switch. That is a residual
/// false match. It has not been measured, and nothing documented rules it out. Two
/// routers reporting the same MAC, cloned or spoofed, still match, because a MAC is
/// whatever the gateway says it is. Only the first adapter Windows lists with an IPv4
/// default gateway is considered, as before. IPv6-only networks are not identified.
/// Anywhere but Windows the answer is always null.
/// </para>
/// </remarks>
public static class NetworkIdentity
{
    /// <summary>
    /// Leads every identifier's hashed material. A first-version identifier hashed a
    /// string beginning with the gateway's IP address, so the two never hash the same
    /// string.
    /// </summary>
    private const string Domain = "sippbucket-network-v2";

    /// <summary>The identifier for the network this machine is currently on.</summary>
    /// <returns>
    /// Sixteen uppercase hex characters, or null when no network can be identified with
    /// confidence: no adapter with an IPv4 gateway, no confirmed MAC for the gateway, or
    /// not Windows.
    /// </returns>
    public static string? Current()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var gateway = FindGateway();
        if (gateway is null)
        {
            return null;
        }

        var interfaceIndex = IPv4InterfaceIndex(gateway.Properties);
        if (interfaceIndex is null)
        {
            return null;
        }

        var row = QueryNeighbor(interfaceIndex.Value, gateway.Address);
        if (row is null)
        {
            return null;
        }

        var (state, mac) = row.Value;
        return FromGatewayNeighbor(state, mac, gateway.Address, gateway.Adapter.NetworkInterfaceType);
    }

    /// <summary>
    /// Turns what the neighbor cache says about the gateway into a network identifier,
    /// or into null when it does not say enough.
    /// </summary>
    /// <param name="state">The state of the gateway's neighbor cache entry.</param>
    /// <param name="gatewayMac">The MAC address the entry holds.</param>
    /// <param name="gatewayAddress">The gateway's IP address.</param>
    /// <param name="adapterType">The kind of adapter the gateway is reached through.</param>
    /// <returns>Sixteen uppercase hex characters, or null.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="gatewayAddress"/> was null.</exception>
    /// <remarks>
    /// The pure half of <see cref="Current"/>, kept apart from the operating-system query
    /// so the two properties that carry the safety can be tested without two routers:
    /// that the same gateway IP behind different MACs gives different identifiers, and
    /// that anything short of a confirmed, non-empty MAC gives null. An empty MAC is never
    /// hashed, because hashing without it rebuilds the approximation this replaced.
    /// </remarks>
    public static string? FromGatewayNeighbor(
        NeighborState state,
        ReadOnlySpan<byte> gatewayMac,
        IPAddress gatewayAddress,
        NetworkInterfaceType adapterType)
    {
        ArgumentNullException.ThrowIfNull(gatewayAddress);

        if (state != NeighborState.Reachable || !gatewayMac.ContainsAnyExcept((byte)0))
        {
            return null;
        }

        var material = string.Create(
            CultureInfo.InvariantCulture,
            $"{Domain}|{Convert.ToHexString(gatewayMac)}|{gatewayAddress}|{adapterType}");
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));

        return Convert.ToHexString(digest)[..16];
    }

    /// <summary>The identifier for the network one adapter is on (docs/DISCOVERY.md).</summary>
    /// <param name="adapter">The adapter.</param>
    /// <returns>
    /// Sixteen uppercase hex characters, or null when that adapter's network cannot be
    /// identified with confidence — which, for anything that decides whether to emit, is a
    /// refusal.
    /// </returns>
    /// <remarks>
    /// The per-adapter form of <see cref="Current"/>, for the announcer that walks every
    /// adapter: a two-gateway machine is on two networks, and consent is per network, not
    /// per machine.
    /// </remarks>
    public static string? ForAdapter(NetworkInterface adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        if (adapter.OperationalStatus != OperationalStatus.Up ||
            adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback)
        {
            return null;
        }

        var properties = adapter.GetIPProperties();
        var gateway = properties.GatewayAddresses
            .Select(g => g.Address)
            .FirstOrDefault(a => a is not null &&
                                 a.AddressFamily == AddressFamily.InterNetwork &&
                                 !a.Equals(IPAddress.Any));
        if (gateway is null)
        {
            return null;
        }

        var interfaceIndex = IPv4InterfaceIndex(properties);
        if (interfaceIndex is null)
        {
            return null;
        }

        var row = QueryNeighbor(interfaceIndex.Value, gateway);
        if (row is null)
        {
            return null;
        }

        var (state, mac) = row.Value;
        return FromGatewayNeighbor(state, mac, gateway, adapter.NetworkInterfaceType);
    }

    /// <summary>A name for the current network that a person would recognise.</summary>
    /// <returns>The adapter's connection name, or null when there is no usable network.</returns>
    /// <remarks>
    /// Shown to the user instead of <see cref="Current"/>, which is a hash and means
    /// nothing to anybody. It names the same adapter <see cref="Current"/> identifies.
    /// It is the Windows connection name, such as "Wi-Fi" or "Ethernet", and <em>not</em>
    /// the Wi-Fi network's SSID, which an earlier version of this remark claimed. Measured
    /// on the desktop: this returned "Wi-Fi" while <c>netsh wlan show interfaces</c>
    /// reported the SSID. So it does not tell a home network from a café reached through
    /// the same adapter.
    /// </remarks>
    public static string? CurrentDisplayName() => FindGateway()?.Adapter.Name;

    /// <summary>
    /// The first adapter that is up, is not loopback, and has an IPv4 default gateway and
    /// an IPv4 address of its own.
    /// </summary>
    private static GatewayAdapter? FindGateway()
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

            if (gateway is null ||
                !properties.UnicastAddresses.Any(
                    u => u.Address.AddressFamily == AddressFamily.InterNetwork))
            {
                continue;
            }

            return new GatewayAdapter(adapter, properties, gateway);
        }

        return null;
    }

    /// <summary>The IPv4 interface index, which is what the neighbor table is keyed by.</summary>
    /// <remarks>
    /// Documented to change when an adapter is disabled and enabled again, so it is read
    /// at the moment of the query and never stored. It is not part of the identifier.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    private static int? IPv4InterfaceIndex(IPInterfaceProperties properties)
    {
        try
        {
            return properties.GetIPv4Properties().Index;
        }
        catch (NetworkInformationException)
        {
            // Thrown when the interface has no IPv4 configuration, which can happen if the
            // adapter is reconfigured between being listed and being asked. No index means
            // no lookup, and no lookup means no identifier: the closed answer.
            return null;
        }
    }

    /// <summary>
    /// Reads the neighbor cache entry for <paramref name="gateway"/> on one interface.
    /// </summary>
    /// <returns>The entry's state and MAC, or null when there is no entry.</returns>
    [SupportedOSPlatform("windows")]
    private static (NeighborState State, byte[] Mac)? QueryNeighbor(int interfaceIndex, IPAddress gateway)
    {
        var row = new byte[NativeMethods.RowSize];

        // Address, a SOCKADDR_IN inside the SOCKADDR_INET union: the family in host order,
        // which is little-endian on every Windows architecture, then the address in network
        // order, which is what IPAddress already holds.
        BinaryPrimitives.WriteUInt16LittleEndian(
            row.AsSpan(NativeMethods.AddressOffset + NativeMethods.SinFamilyOffset),
            NativeMethods.AfInet);

        if (!gateway.TryWriteBytes(
                row.AsSpan(NativeMethods.AddressOffset + NativeMethods.SinAddrOffset, 4),
                out var written) || written != 4)
        {
            return null;
        }

        // InterfaceLuid stays zero, so the call uses InterfaceIndex. The page for
        // GetIpNetEntry2 documents that order: the LUID if it is set, otherwise the index.
        BinaryPrimitives.WriteUInt32LittleEndian(
            row.AsSpan(NativeMethods.InterfaceIndexOffset),
            (uint)interfaceIndex);

        if (NativeMethods.GetIpNetEntry2(row) != NativeMethods.NoError)
        {
            return null;
        }

        var state = (NeighborState)BinaryPrimitives.ReadInt32LittleEndian(
            row.AsSpan(NativeMethods.StateOffset));

        var length = BinaryPrimitives.ReadUInt32LittleEndian(
            row.AsSpan(NativeMethods.PhysicalAddressLengthOffset));

        if (length > NativeMethods.MaximumPhysicalAddressLength)
        {
            return null;
        }

        return (state, row.AsSpan(NativeMethods.PhysicalAddressOffset, (int)length).ToArray());
    }

    private sealed record GatewayAdapter(
        NetworkInterface Adapter,
        IPInterfaceProperties Properties,
        IPAddress Address);

    /// <summary>
    /// <c>GetIpNetEntry2</c>, and the <c>MIB_IPNET_ROW2</c> layout it fills.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The row is passed as a blittable <c>byte[]</c>, which the marshaller pins, rather
    /// than as a struct. The struct holds a fixed 32-byte array, which C# can only declare
    /// with unsafe code, and <c>AllowUnsafeBlocks</c> is off for this library on purpose
    /// (see <c>SleepBlocker</c>). DllImport rather than LibraryImport for the same reason.
    /// </para>
    /// <para>
    /// The offsets are not guessed. They were printed by a C program compiled against
    /// <c>netioapi.h</c> from Windows SDK 10.0.22621 with MSVC 14.44, for x64 and for x86,
    /// and both gave the same layout: size 88, Address at 0, InterfaceIndex at 28,
    /// InterfaceLuid at 32, PhysicalAddress at 40, PhysicalAddressLength at 72, State at
    /// 76. Within Address, <c>sin_family</c> is at 0 and <c>sin_addr</c> at 4, and
    /// <c>AF_INET</c> is 2. The <c>NL_NEIGHBOR_STATE</c> values are from <c>nldef.h</c> in
    /// the same SDK.
    /// </para>
    /// </remarks>
    private static class NativeMethods
    {
        public const int RowSize = 88;
        public const int AddressOffset = 0;
        public const int SinFamilyOffset = 0;
        public const int SinAddrOffset = 4;
        public const int InterfaceIndexOffset = 28;
        public const int PhysicalAddressOffset = 40;
        public const int PhysicalAddressLengthOffset = 72;
        public const int StateOffset = 76;

        /// <summary><c>IF_MAX_PHYS_ADDRESS_LENGTH</c> in <c>ifdef.h</c>.</summary>
        public const int MaximumPhysicalAddressLength = 32;

        public const ushort AfInet = 2;
        public const uint NoError = 0;

        /// <summary>
        /// Reads one neighbor cache entry. A miss is reported, not resolved: measured, see
        /// <see cref="NetworkIdentity"/>.
        /// </summary>
        /// <returns><c>NO_ERROR</c>, or a Win32 error code such as <c>ERROR_NOT_FOUND</c>.</returns>
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern uint GetIpNetEntry2([In, Out] byte[] row);
    }
}

/// <summary>
/// The state of a neighbor (ARP) cache entry, with the values of Windows'
/// <c>NL_NEIGHBOR_STATE</c>.
/// </summary>
/// <remarks>
/// Meanings as Microsoft documents them for <c>MIB_IPNET_ROW2</c>:
/// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2.
/// Only <see cref="Reachable"/> is trusted to identify a network; see
/// <see cref="NetworkIdentity"/>.
/// </remarks>
public enum NeighborState
{
    /// <summary>The neighbor is unreachable.</summary>
    Unreachable = 0,

    /// <summary>Resolution is in progress; the MAC is not known yet.</summary>
    Incomplete = 1,

    /// <summary>No longer known to be reachable; probes are being sent.</summary>
    Probe = 2,

    /// <summary>No longer known to be reachable; probing is about to start.</summary>
    Delay = 3,

    /// <summary>No longer known to be reachable; it will be checked when next used.</summary>
    Stale = 4,

    /// <summary>Known to have been reachable within the last few tens of seconds.</summary>
    Reachable = 5,

    /// <summary>A static entry, set by hand rather than learned.</summary>
    Permanent = 6,
}
