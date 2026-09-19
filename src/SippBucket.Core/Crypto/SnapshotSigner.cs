using SippBucket.Core.Hashing;
using SippBucket.Core.Model;

namespace SippBucket.Core.Crypto;

/// <summary>
/// Signs this machine's snapshots with its device key, and checks other machines' signatures,
/// under the snapshot signature's own context label (D-21, docs/SNAPSHOT-FORMAT.md).
/// </summary>
/// <remarks>
/// <para>
/// A snapshot's <see cref="Snapshot.DeviceId"/> was attribution without proof: any holder of
/// the repository key could write a snapshot claiming any device at all, and every hash
/// verified. The transport (Noise, and Direct Push's SSH) proves which machine <em>sent</em> a
/// snapshot, never which machine <em>made</em> it. The signature closes that: it is made with
/// the device key the snapshot names, over the snapshot's ID, which covers every byte of the
/// snapshot through its header and trees.
/// </para>
/// <para>
/// The signed message begins with <see cref="SnapshotEncoding.SignatureLabel"/>, following
/// D-52's standing rule, so a snapshot signature can never pass for an SSH signature, a direct
/// message's, or anything else this key signs — the labels, lengths and first bytes all differ
/// (<see cref="SnapshotEncoding.SignatureLabel"/>'s remarks lay the forms side by side). Noise
/// section 14's advice against using a Noise static key outside Noise is answered the same way
/// it was for SSH: what is signed here cannot be mistaken for any Noise message, Noise itself
/// signs nothing, and the joint-security literature on sharing this key pair is weighed in
/// <see cref="DeviceIdentity"/>'s remarks.
/// </para>
/// <para>
/// Who verifies, and against what: the puller, against the key the snapshot itself names. That
/// proves the maker holds that key's private half. It does not prove the maker is <em>welcome</em>
/// — any device can make a key and sign — so authorization stays where it always was, in the
/// peer list, and the signature is what lets a rule about a member (read-only, removed) be
/// enforced against the snapshots that member made rather than the machine that relayed them.
/// </para>
/// </remarks>
public sealed class SnapshotSigner
{
    private readonly DeviceIdentity _identity;

    /// <summary>Creates a signer over this machine's identity.</summary>
    /// <param name="identity">The identity. Borrowed: the caller keeps it alive and disposes it.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identity"/> was null.</exception>
    public SnapshotSigner(DeviceIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        _identity = identity;
    }

    /// <summary>The device ID the signatures name: this machine's.</summary>
    public string DeviceId => _identity.DeviceId;

    /// <summary>Signs a snapshot's ID.</summary>
    /// <param name="snapshotId">The ID.</param>
    /// <returns>The signature, as the snapshot carries it: lowercase hexadecimal.</returns>
    /// <exception cref="ObjectDisposedException">The identity was disposed.</exception>
    public string Sign(ContentHash snapshotId)
    {
        var signature = _identity.Sign(SnapshotEncoding.SignedBytes(snapshotId));
#pragma warning disable CA1308 // A signature is an identifier; lowercase hex is its wire form, as device IDs are.
        return Convert.ToHexString(signature).ToLowerInvariant();
#pragma warning restore CA1308
    }

    /// <summary>Checks a snapshot's signature against the device its <c>DeviceId</c> names.</summary>
    /// <param name="deviceId">The device the snapshot claims made it.</param>
    /// <param name="snapshotId">The snapshot's ID.</param>
    /// <param name="signature">The signature as the snapshot carries it, or null for none.</param>
    /// <returns>True when the signature is that device's, over this ID, under the label.</returns>
    public static bool Verify(string deviceId, ContentHash snapshotId, string? signature)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || signature is null)
        {
            return false;
        }

        byte[] raw;
        try
        {
            raw = SnapshotEncoding.DecodeSignature(signature);
        }
        catch (ArgumentException)
        {
            return false;
        }

        return DeviceIdentity.Verify(deviceId, SnapshotEncoding.SignedBytes(snapshotId), raw);
    }
}
