namespace SippBucket.Core.Repository;

/// <summary>
/// One machine this repository syncs with.
/// </summary>
/// <remarks>
/// A peer is trusted by its device ID, not by its address. The address can change — a
/// laptop moves from the LAN to a 5G connection — while the Ed25519 identity does not, so
/// the identity is what authentication is pinned to.
/// </remarks>
public sealed record PeerRecord
{
    /// <summary>The peer's hexadecimal Ed25519 public key.</summary>
    public required string DeviceId { get; init; }

    /// <summary>A label for the peer, such as "desktop" or "laptop".</summary>
    public required string Name { get; init; }

    /// <summary>Host name or IP address last known to reach this peer.</summary>
    public required string Host { get; init; }

    /// <summary>TCP port the peer's daemon listens on.</summary>
    public required int Port { get; init; }

    /// <summary>When this peer was last synced with successfully, if ever.</summary>
    public DateTimeOffset? LastSyncedUtc { get; init; }

    /// <summary>
    /// True for a member whose changes this replica never takes: it may read — it holds the
    /// key, and pretending otherwise would be a lie — but a snapshot it authored is refused
    /// at every pull here, which the snapshot's signature makes enforceable (D-21).
    /// </summary>
    /// <remarks>
    /// Set on each machine that wants the rule, like every peer setting: <c>peers.json</c> is
    /// never synced. Omitted from the JSON when false, so existing files are unchanged.
    /// </remarks>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool ReadOnlyMember { get; init; }

    /// <summary>
    /// When this membership ends, in UTC, or null for no end. From that moment this replica
    /// neither serves nor dials the peer, and says why. Expiry cuts off what comes after it;
    /// only removal, which rotates the folder key (D-70), also stops the machine reading new
    /// data other machines might still send it.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? ExpiresUtc { get; init; }

    /// <summary>Whether this membership has ended.</summary>
    /// <param name="nowUtc">The current time.</param>
    /// <returns>True when an expiry is set and past.</returns>
    public bool IsExpired(DateTimeOffset nowUtc) => ExpiresUtc is { } expires && expires <= nowUtc;
}
