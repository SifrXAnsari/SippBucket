namespace SippBucket.Core.Repository;

/// <summary>
/// Everything a second machine needs to become a replica of a repository: the payload that
/// pairing seals under the CPace session key and sends to a machine that has proved it holds
/// the code.
/// </summary>
/// <remarks>
/// <para>
/// Two machines are replicas of the same repository only if they share its ID and its
/// encryption key. Without that they are two unrelated folders that happen to have the same
/// name. This is how the second machine gets both.
/// </para>
/// <para>
/// <strong>Internal, and with no way to become a string a person could copy.</strong> This
/// type used to be public and had <c>Encode</c>, which printed the key as a <c>sip1_</c>
/// invite, and <c>Decode</c>, which read one — so the key lived in chat logs and clipboards
/// (D-49). Both are gone. The one place this is serialised is inside
/// <c>PairingProtocol.Seal</c>, straight into an AEAD under a key only the two paired
/// machines can derive, and <see cref="ToString"/> leaves the key out.
/// </para>
/// <para>
/// It carries no host. Where to reach the offering machine is whatever address the joining
/// machine actually dialled; taking an address from inside a message is how D-43 put
/// <c>127.0.0.1</c> into a peer list.
/// </para>
/// </remarks>
internal sealed record RepositoryInvite
{
    /// <summary>The shared repository identifier.</summary>
    public required string RepositoryId { get; init; }

    /// <summary>The repository's name.</summary>
    public required string Name { get; init; }

    /// <summary>The shared XChaCha20-Poly1305 key — the ring's current key — base64 encoded.</summary>
    public required string EncryptionKey { get; init; }

    /// <summary>
    /// The ring's older keys, base64, oldest first (D-70): what lets a machine joining after
    /// a rotation read everything written before it. Empty for a folder never rotated, which
    /// keeps the sealed payload byte-compatible with builds before rotation existed.
    /// </summary>
    public IReadOnlyList<string> PreviousKeys { get; init; } = [];

    /// <summary>The devices rotations have revoked, so a new replica never dials or serves them.</summary>
    public IReadOnlyList<string> RevokedDevices { get; init; } = [];

    /// <summary>Device ID of the machine that issued the invite.</summary>
    public required string DeviceId { get; init; }

    /// <summary>Port that machine's daemon listens on.</summary>
    public required int Port { get; init; }

    /// <summary>Renders the invite for a log line, without the key.</summary>
    /// <returns>A short description.</returns>
    public override string ToString() =>
        $"'{Name}' from {DeviceId[..Math.Min(12, DeviceId.Length)]}, port {Port}";
}
