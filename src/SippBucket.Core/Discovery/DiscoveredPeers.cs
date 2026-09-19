namespace SippBucket.Core.Discovery;

/// <summary>
/// Addresses learned from announcements, held separately from the peers that were
/// configured.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The separation is the security property, and it is the one thing about discovery
/// that is easy to get wrong.</strong> With the token packet an announcement is
/// authenticated as far as a keyed MAC bound to its source address and time slot can carry —
/// far enough that a stranger cannot forge one — but the obvious implementation, writing the
/// discovered address into the peer record, would still hand whoever <em>can</em> make a
/// token (a machine holding a minted key) the ability to replace a configured address for
/// good, and a mistake anywhere in the matching the ability to do it from noise.
/// </para>
/// <para>
/// So a discovered address is an <em>addition</em>, never a replacement. The configured
/// address is always tried; sighted ones are extra candidates, tried after it, and a wrong
/// candidate costs a bounded connection attempt against the handshake's own deadline.
/// </para>
/// <para>
/// Sightings of devices that are not in any peer list here are <em>dropped entirely</em>.
/// Discovery answers "where is the machine I already trust", not "who else is here" —
/// pairing is a separate, deliberate act, and letting a broadcast introduce a peer would
/// make it not one.
/// </para>
/// </remarks>
public sealed class DiscoveredPeers
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Sighting> _sightings =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Func<DateTimeOffset> _clock;
    private readonly TimeSpan _lifetime;

    /// <summary>Creates a table of sightings.</summary>
    /// <param name="lifetime">How long a sighting is believed, or null for five minutes.</param>
    /// <param name="clock">A clock, for tests.</param>
    public DiscoveredPeers(TimeSpan? lifetime = null, Func<DateTimeOffset>? clock = null)
    {
        _lifetime = lifetime ?? TimeSpan.FromMinutes(5);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Records that a device's token was heard from an address, if and only if the device is
    /// still a configured peer.
    /// </summary>
    /// <param name="deviceId">The device a token matched (docs/DISCOVERY.md).</param>
    /// <param name="sourceAddress">The address the datagram came from: the only address there is.</param>
    /// <param name="isKnownPeer">Whether this device is in any peer list here.</param>
    /// <returns>True when the sighting was recorded.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="isKnownPeer"/> was null.</exception>
    public bool SightDevice(string deviceId, string sourceAddress, Func<string, bool> isKnownPeer)
    {
        ArgumentNullException.ThrowIfNull(isKnownPeer);

        if (string.IsNullOrWhiteSpace(deviceId) ||
            string.IsNullOrWhiteSpace(sourceAddress) ||
            !isKnownPeer(deviceId))
        {
            return false;
        }

        lock (_gate)
        {
            _sightings[deviceId] = new Sighting
            {
                DeviceId = deviceId,
                Host = sourceAddress,
                SeenUtc = _clock(),
            };

            return true;
        }
    }

    /// <summary>Extra addresses to try for a peer, newest first.</summary>
    /// <param name="deviceId">The peer's device ID.</param>
    /// <returns>Sighted addresses that have not gone stale.</returns>
    /// <remarks>
    /// Called <c>Extra</c> rather than <c>AddressFor</c> deliberately. The name is the
    /// contract: whatever this returns is tried <em>in addition to</em> the configured
    /// address, never instead of it. The packet carries no port — the peer's configured
    /// record has it — so a sighting is an address alone.
    /// </remarks>
    public IReadOnlyList<Sighting> ExtraAddressesFor(string deviceId)
    {
        if (string.IsNullOrEmpty(deviceId))
        {
            return [];
        }

        lock (_gate)
        {
            if (!_sightings.TryGetValue(deviceId, out var sighting))
            {
                return [];
            }

            return _clock() - sighting.SeenUtc > _lifetime ? [] : [sighting];
        }
    }

    /// <summary>Every peer seen recently.</summary>
    /// <returns>Sightings that have not gone stale.</returns>
    public IReadOnlyList<Sighting> Recent()
    {
        lock (_gate)
        {
            var now = _clock();
            return _sightings.Values
                .Where(s => now - s.SeenUtc <= _lifetime)
                .OrderByDescending(s => s.SeenUtc)
                .ToList();
        }
    }
}

/// <summary>One sighting, as remembered.</summary>
/// <remarks>
/// This used to carry the announcer's self-reported machine name, port and run ID. The token
/// packet carries none of them (docs/DISCOVERY.md): the name and port come from this
/// machine's own peer record for the device, and restart detection lives in the Server.ID
/// <c>run</c> field inside the encrypted channel, where it identifies nothing to the network.
/// </remarks>
public sealed record Sighting
{
    /// <summary>The device whose token matched.</summary>
    public required string DeviceId { get; init; }

    /// <summary>The address the datagram actually came from.</summary>
    /// <remarks>
    /// The source address of the packet. The packet carries no address at all, so there is
    /// nothing inside it to be tempted by.
    /// </remarks>
    public required string Host { get; init; }

    /// <summary>When it was seen.</summary>
    public required DateTimeOffset SeenUtc { get; init; }
}
