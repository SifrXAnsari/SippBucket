using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SippBucket.Core.Discovery;

/// <summary>One place an announcement may go: an adapter's address and its subnet broadcast.</summary>
/// <param name="NetworkId">The network's identifier, or null for one not identified, which consent refuses.</param>
/// <param name="Address">The adapter's own IPv4 address, which each token is bound to.</param>
/// <param name="Broadcast">The subnet broadcast address the packet goes to.</param>
public sealed record AnnounceTarget(string? NetworkId, IPAddress Address, IPAddress Broadcast);

/// <summary>
/// Announces this machine's presence to the peers it was given keys for, and listens for
/// theirs, with the token packet that says nothing to anyone else (docs/DISCOVERY.md, D-32).
/// </summary>
/// <remarks>
/// <para>
/// Announcing and listening are separate permissions and are deliberately not bundled.
/// <strong>Listening is free of privacy cost — it emits nothing</strong> — so it runs
/// wherever the daemon runs. Announcing emits a packet to everyone on the network; the
/// packet itself identifies nothing (<see cref="DiscoveryPacket"/>), and it is still sent
/// only on networks the person consented to, because emitting anything at all on a hotel's
/// network is the person's call, not the program's.
/// </para>
/// <para>
/// <b>Where an announcement goes.</b> From each consented adapter's own IPv4 address to that
/// adapter's subnet broadcast address, TTL 1, never to 255.255.255.255 — the limited
/// broadcast address is routed in ways that can leave the subnet, which the desktop's own
/// route table shows. An adapter announces only when its network is identified, consented,
/// and out of the hold-down that follows an address change: sixty seconds, so a beacon
/// never straddles two networks during a move (the page's formula floors at sixty, which is
/// what real interfaces come out at; the appendix records the fixed value).
/// </para>
/// <para>
/// <b>What the receiver does.</b> A packet must be exactly the fixed size with the magic and
/// version; its nonce must be fresh (<see cref="ReplayGuard"/>); and each token is checked
/// against the keys peers minted for this machine, bound to the sender's source address and
/// the time slot. A match is a sighting of that device at that source address — an
/// <em>addition</em> to the configured address, never a replacement, and never an
/// introduction: a device with no key here matches nothing, and a device that is no longer
/// in any peer list is not dialled however it announces.
/// </para>
/// <para>
/// The listener binds with <c>SO_EXCLUSIVEADDRUSE</c>, per Microsoft's guidance, so another
/// process cannot sit on the port beside it and take its datagrams; the cost, that a second
/// signed-in user cannot listen, is already true of the TCP listener. Never announce in
/// reply to a received packet: an answered beacon confirms a listener exists, which is
/// exactly what the packet design hides.
/// </para>
/// </remarks>
public sealed class LocalDiscovery : IAsyncDisposable
{
    /// <summary>How often a consented adapter announces.</summary>
    public static TimeSpan AnnounceInterval => DiscoveryPacket.AnnounceInterval;

    /// <summary>The hold-down after an address change, during which nothing is announced.</summary>
    public static TimeSpan HoldDown { get; } = TimeSpan.FromSeconds(60);

    private readonly Func<IReadOnlyList<(string DeviceId, byte[] Key)>> _mintedKeys;
    private readonly Func<IReadOnlyList<(string DeviceId, byte[] Key)>> _theirKeys;
    private readonly Func<string, bool> _isKnownPeer;
    private readonly Func<string?, bool> _mayAnnounceOn;
    private readonly Func<IReadOnlyList<AnnounceTarget>>? _targets;
    private readonly Action<string>? _log;
    private readonly TimeProvider _time;
    private readonly CancellationTokenSource _stopping = new();
    private readonly ReplayGuard _replays = new();
    private readonly int _port;

    private UdpClient? _socket;
    private Task? _listening;
    private Task? _announcing;
    private DateTimeOffset _lastAddressChangeUtc = DateTimeOffset.MinValue;
    private NetworkAddressChangedEventHandler? _addressChanged;
    private bool _disposed;

    /// <summary>Creates a discovery service. Nothing is sent or received until <see cref="Start"/>.</summary>
    /// <param name="mintedKeys">The keys this machine minted, one per peer it announces to.</param>
    /// <param name="theirKeys">The keys peers minted for this machine, which recognise their packets.</param>
    /// <param name="isKnownPeer">Whether a device is still in any peer list here: a sighting's gate.</param>
    /// <param name="mayAnnounceOn">
    /// Whether announcing is permitted on a network, by its identifier; null is an
    /// unidentified network, which is a refusal. Consulted on every tick rather than once at
    /// start, because a laptop changes networks without restarting the daemon — which is
    /// exactly the case per-network consent exists for.
    /// </param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="port">The UDP port, overridable for tests.</param>
    /// <param name="time">The clock, or null for the system's.</param>
    /// <param name="targets">
    /// Where announcements go, or null to walk this machine's adapters: the test seam, so a
    /// test can announce over loopback without a packet ever leaving the machine. Consent
    /// still gates every target, whichever way they come.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public LocalDiscovery(
        Func<IReadOnlyList<(string DeviceId, byte[] Key)>> mintedKeys,
        Func<IReadOnlyList<(string DeviceId, byte[] Key)>> theirKeys,
        Func<string, bool> isKnownPeer,
        Func<string?, bool> mayAnnounceOn,
        Action<string>? log = null,
        int port = DiscoveryPacket.Port,
        TimeProvider? time = null,
        Func<IReadOnlyList<AnnounceTarget>>? targets = null)
    {
        ArgumentNullException.ThrowIfNull(mintedKeys);
        ArgumentNullException.ThrowIfNull(theirKeys);
        ArgumentNullException.ThrowIfNull(isKnownPeer);
        ArgumentNullException.ThrowIfNull(mayAnnounceOn);

        _mintedKeys = mintedKeys;
        _theirKeys = theirKeys;
        _isKnownPeer = isKnownPeer;
        _mayAnnounceOn = mayAnnounceOn;
        _targets = targets;
        _log = log;
        _port = port;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Peers heard from recently.</summary>
    public DiscoveredPeers Peers { get; } = new();

    /// <summary>How many packets this machine has sent.</summary>
    public int Announced { get; private set; }

    /// <summary>How many datagrams were received and matched nothing.</summary>
    /// <remarks>
    /// Counted rather than logged per packet. On a noisy network this is the number that
    /// tells you whether something is shouting at the port, and a log line per rejected
    /// datagram would be the denial of service rather than the report of one.
    /// </remarks>
    public int Refused { get; private set; }

    /// <summary>Starts listening, and announcing where that is permitted.</summary>
    /// <exception cref="ObjectDisposedException">The service was disposed.</exception>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_socket is not null)
        {
            return;
        }

        var socket = new UdpClient(AddressFamily.InterNetwork);

        // Exclusive, not ReuseAddress: with reuse, another process of any account could bind
        // beside this one and take its datagrams (socket hijacking, per Microsoft's own
        // guidance). The cost — a second signed-in user cannot listen — is already true of
        // the TCP listener.
        if (OperatingSystem.IsWindows())
        {
            socket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
        }

        socket.Client.Bind(new IPEndPoint(IPAddress.Any, _port));
        socket.EnableBroadcast = true;
        _socket = socket;

        // The hold-down clock starts at every address change the stack reports; nothing is
        // announced until it has passed, so a beacon never straddles a network move.
        _addressChanged = (_, _) => _lastAddressChangeUtc = _time.GetUtcNow();
        NetworkChange.NetworkAddressChanged += _addressChanged;

        _listening = ListenAsync(_stopping.Token);
        _announcing = AnnounceLoopAsync(_stopping.Token);
    }

    /// <summary>Sends one round of announcements now, one packet per consented adapter.</summary>
    /// <param name="cancellationToken">Cancels the sends.</param>
    /// <returns>How many packets went out.</returns>
    /// <remarks>
    /// Nothing is sent while no peer holds a key — an empty packet would still say "a
    /// SippBucket that announces is here" — during the hold-down, or on adapters whose
    /// network is unidentified or unconsented.
    /// </remarks>
    public async Task<int> AnnounceOnceAsync(CancellationToken cancellationToken = default)
    {
        if (_socket is not { } socket)
        {
            return 0;
        }

        var keys = _mintedKeys().Select(pair => pair.Key).ToList();
        if (keys.Count == 0)
        {
            return 0;
        }

        var now = _time.GetUtcNow();
        if (now - _lastAddressChangeUtc < HoldDown)
        {
            return 0;
        }

        var slot = DiscoveryPacket.SlotOf(now);
        var sent = 0;

        foreach (var target in _targets?.Invoke() ?? EnumerateAdapters())
        {
            // Consent gates every target the same way, injected or walked: an unidentified
            // network is a refusal.
            if (!_mayAnnounceOn(target.NetworkId))
            {
                continue;
            }

            var (address, broadcast) = (target.Address, target.Broadcast);
            cancellationToken.ThrowIfCancellationRequested();

            // More peers than slots are covered in turn, a packet per group per adapter.
            foreach (var group in keys.Chunk(DiscoveryPacket.Slots))
            {
                var packet = DiscoveryPacket.Build(group, slot, address);
                await socket.SendAsync(packet, new IPEndPoint(broadcast, _port), cancellationToken)
                    .ConfigureAwait(false);
                Announced++;
                sent++;
            }
        }

        return sent;
    }

    /// <summary>
    /// This machine's IPv4 adapters as announce targets: up, with an identified network and
    /// a subnet broadcast address. Never the limited broadcast address. Consent is judged by
    /// the caller, per target.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Reads the operating system's adapter tables, whose failures on a network mid-change are " +
                        "as varied as drivers are; an adapter that cannot be read announces nothing, which is the " +
                        "safe side of a privacy switch.")]
    private List<AnnounceTarget> EnumerateAdapters()
    {
        var adapters = new List<AnnounceTarget>();

        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                // The identity rule the consent screen names networks by: per adapter, and an
                // unidentified network comes through as null, which consent refuses.
                var networkId = NetworkIdentity.ForAdapter(adapter);
                var properties = adapter.GetIPProperties();

                foreach (var unicast in properties.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }

                    var broadcast = SubnetBroadcast(unicast.Address, unicast.IPv4Mask);
                    if (broadcast is not null)
                    {
                        adapters.Add(new AnnounceTarget(networkId, unicast.Address, broadcast));
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _log?.Invoke($"discovery: the adapters could not be read, so nothing was announced: {ex.Message}");
        }

        return adapters;
    }

    /// <summary>The subnet broadcast address, or null where the mask gives none worth using.</summary>
    private static IPAddress? SubnetBroadcast(IPAddress address, IPAddress? mask)
    {
        if (mask is null || mask.AddressFamily != AddressFamily.InterNetwork)
        {
            return null;
        }

        Span<byte> a = stackalloc byte[4];
        Span<byte> m = stackalloc byte[4];
        if (!address.TryWriteBytes(a, out _) || !mask.TryWriteBytes(m, out _))
        {
            return null;
        }

        Span<byte> b = stackalloc byte[4];
        for (var i = 0; i < 4; i++)
        {
            b[i] = (byte)(a[i] | ~m[i]);
        }

        var broadcast = new IPAddress(b);

        // A /32 has no subnet to broadcast on, and 255.255.255.255 is exactly the address
        // this never sends to.
        return broadcast.Equals(address) || broadcast.Equals(IPAddress.Broadcast) ? null : broadcast;
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "A daemon loop reading unauthenticated input from the network. " +
                        "Anything escaping stops discovery permanently and silently.")]
    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var received = await _socket!.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                var now = _time.GetUtcNow();

                if (!DiscoveryPacket.TryReadNonce(received.Buffer, out var nonce) ||
                    !_replays.IsFresh(nonce, now))
                {
                    Refused++;
                    continue;
                }

                var matched = DiscoveryPacket.Match(
                    received.Buffer, received.RemoteEndPoint.Address, _theirKeys(), now);

                if (matched.Count == 0)
                {
                    // A stranger's noise, our own packet coming back, or a peer whose key we
                    // do not hold yet. All ordinary; none worth a log line a minute.
                    Refused++;
                    continue;
                }

                // Never trust an address inside a packet; this packet carries none, and the
                // source is the only address the sender cannot choose on someone else's behalf.
                var source = received.RemoteEndPoint.Address.ToString();
                foreach (var deviceId in matched)
                {
                    if (!Peers.SightDevice(deviceId, source, _isKnownPeer))
                    {
                        Refused++;
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                // A network going away underneath the socket. Ordinary on a laptop.
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"discovery: listener stopped: {ex.GetType().Name}: {ex.Message}");
                return;
            }
        }
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "A daemon loop. An escaping exception stops announcing silently.")]
    private async Task AnnounceLoopAsync(CancellationToken cancellationToken)
    {
        using var ticker = new PeriodicTimer(AnnounceInterval, _time);

        try
        {
            while (await ticker.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    _ = await AnnounceOnceAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (SocketException)
                {
                    // Between networks. The next tick tries again.
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"discovery: announce failed: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_addressChanged is { } handler)
        {
            NetworkChange.NetworkAddressChanged -= handler;
        }

        await _stopping.CancelAsync().ConfigureAwait(false);

        _socket?.Dispose();

        foreach (var task in new[] { _listening, _announcing })
        {
            if (task is null)
            {
                continue;
            }

            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _stopping.Dispose();
    }
}
