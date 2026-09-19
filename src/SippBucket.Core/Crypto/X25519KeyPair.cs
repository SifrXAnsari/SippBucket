using System.Security.Cryptography;

namespace SippBucket.Core.Crypto;

/// <summary>
/// A key pair that can take part in an X25519 exchange without handing out its private key.
/// </summary>
/// <remarks>
/// Noise's handshake needs to run <c>DH(s, re)</c> with the device's static key, and the
/// device key must never be exported through public API. Asking the key pair to perform the
/// exchange, rather than asking it for the private key, is what lets
/// <see cref="DeviceIdentity"/> satisfy both.
/// </remarks>
internal interface IX25519KeyPair
{
    /// <summary>The 32-byte X25519 public key.</summary>
    ReadOnlySpan<byte> PublicKey { get; }

    /// <summary>Runs X25519 between this key pair's private key and <paramref name="publicKey"/>.</summary>
    /// <param name="publicKey">The other side's public key.</param>
    /// <param name="sharedSecret">The 32-byte result when this returns true. The caller zeroes it.</param>
    /// <returns>False when the result is all zeros; see <see cref="RawX25519.TryAgree"/>.</returns>
    bool TryAgree(ReadOnlySpan<byte> publicKey, out byte[] sharedSecret);
}

/// <summary>
/// A plain X25519 key pair: the Noise <c>GENERATE_KEYPAIR()</c> output (Noise revision 34,
/// section 12.1), used for ephemeral keys and for the static keys in published test vectors.
/// </summary>
/// <remarks>
/// The private key lives on the pinned object heap and is zeroed on dispose. Pinned, because
/// a compacting collection can move an ordinary array and leave the old copy of the key in
/// memory that nothing will ever clear.
/// </remarks>
internal sealed class X25519KeyPair : IX25519KeyPair, IDisposable
{
    private readonly byte[] _privateKey;
    private readonly byte[] _publicKey;
    private bool _disposed;

    private X25519KeyPair(byte[] pinnedPrivateKey)
    {
        _privateKey = pinnedPrivateKey;
        _publicKey = RawX25519.PublicKeyOf(_privateKey);
    }

    /// <inheritdoc />
    public ReadOnlySpan<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    /// <summary>Generates a fresh key pair from the operating system's CSPRNG.</summary>
    /// <returns>The new key pair.</returns>
    /// <remarks>
    /// Any 32 random bytes are a valid X25519 private key, because the scalar is clamped
    /// inside the DH function itself (RFC 7748 section 5).
    /// </remarks>
    public static X25519KeyPair Generate()
    {
        var privateKey = GC.AllocateArray<byte>(RawX25519.KeySize, pinned: true);
        RandomNumberGenerator.Fill(privateKey);
        return new X25519KeyPair(privateKey);
    }

    /// <summary>Wraps a known private key. Used for published test vectors.</summary>
    /// <param name="privateKey">The 32-byte private key, copied rather than kept.</param>
    /// <returns>The key pair.</returns>
    public static X25519KeyPair FromPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != RawX25519.KeySize)
        {
            throw new ArgumentException($"An X25519 private key is {RawX25519.KeySize} bytes.", nameof(privateKey));
        }

        var pinned = GC.AllocateArray<byte>(RawX25519.KeySize, pinned: true);
        privateKey.CopyTo(pinned);
        return new X25519KeyPair(pinned);
    }

    /// <inheritdoc />
    public bool TryAgree(ReadOnlySpan<byte> publicKey, out byte[] sharedSecret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return RawX25519.TryAgree(_privateKey, publicKey, out sharedSecret);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_privateKey);
        _disposed = true;
    }
}
