using System.Buffers.Binary;
using NSec.Cryptography;

namespace SippBucket.Core.Protocol.Noise;

/// <summary>
/// The Noise <c>CipherState</c>: a key <c>k</c> and a nonce <c>n</c> (Noise revision 34,
/// section 5.1; https://noiseprotocol.org/noise.html), with the ChaChaPoly cipher functions
/// of section 12.3.
/// </summary>
/// <remarks>
/// <para>
/// <b>Cipher.</b> IETF ChaCha20-Poly1305 (RFC 7539's <c>AEAD_CHACHA20_POLY1305</c>) through
/// NSec, with the key imported from raw bytes so it lives in libsodium's guarded memory
/// rather than a managed array. Section 12.3: "The 96-bit nonce is formed by encoding 32 bits
/// of zeros followed by little-endian encoding of n." Little-endian, which is the opposite of
/// what the previous hand-rolled channel used and exactly the kind of detail the published
/// test vectors exist to catch.
/// </para>
/// <para>
/// <b>The reserved nonce.</b> Section 5.1: "The maximum n value (2^64-1) is reserved for other
/// use. If incrementing n results in 2^64-1, then any further EncryptWithAd() or
/// DecryptWithAd() calls will signal an error to the caller." That is enforced here rather
/// than trusted to be unreachable, because a nonce reused under one key is the failure
/// ChaCha20-Poly1305 does not survive.
/// </para>
/// <para>
/// <b>Deliberately absent:</b> <c>Rekey()</c> and the <c>REKEY</c> function. Section 11.3
/// leaves rekeying to the application, and nothing in SippBucket asks for it: a channel lives
/// for one sync, and its 2^64 nonces cannot be spent in that time. An unused cryptographic
/// function with no test vector would be code that looks verified and is not.
/// </para>
/// </remarks>
internal sealed class CipherState : IDisposable
{
    /// <summary>The size of a ChaChaPoly key.</summary>
    public const int KeyLength = 32;

    /// <summary>The Poly1305 tag appended to every ciphertext.</summary>
    public const int TagLength = 16;

    private const ulong ReservedNonce = ulong.MaxValue;

    private static readonly AeadAlgorithm ChaChaPoly = AeadAlgorithm.ChaCha20Poly1305;

    private Key? _key;
    private ulong _nonce;
    private bool _disposed;

    /// <summary><c>HasKey()</c>: true when <c>k</c> is non-empty.</summary>
    public bool HasKey => _key is not null;

    /// <summary><c>InitializeKey(key)</c>: sets <c>k = key</c> and <c>n = 0</c>.</summary>
    /// <param name="key">The 32-byte key, or empty for the spec's <c>empty</c> value.</param>
    public void InitializeKey(ReadOnlySpan<byte> key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!key.IsEmpty && key.Length != KeyLength)
        {
            throw new ArgumentException($"A cipher key is {KeyLength} bytes.", nameof(key));
        }

        _key?.Dispose();
        _key = key.IsEmpty ? null : Key.Import(ChaChaPoly, key, KeyBlobFormat.RawSymmetricKey);
        _nonce = 0;
    }

    /// <summary><c>SetNonce(nonce)</c>: sets <c>n</c>.</summary>
    /// <param name="nonce">The new nonce.</param>
    /// <remarks>
    /// Section 5.1 defines this for out-of-order transports (section 11.4). SippBucket runs
    /// over TCP and never needs that; it is here so the tests can reach the reserved nonce
    /// without sending 2^64 messages first.
    /// </remarks>
    public void SetNonce(ulong nonce)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _nonce = nonce;
    }

    /// <summary>
    /// <c>EncryptWithAd(ad, plaintext)</c>: <c>ENCRYPT(k, n++, ad, plaintext)</c>, or the
    /// plaintext unchanged while <c>k</c> is empty.
    /// </summary>
    /// <param name="associatedData">The associated data.</param>
    /// <param name="plaintext">The plaintext.</param>
    /// <returns>The ciphertext, sixteen bytes longer than the plaintext when keyed.</returns>
    public byte[] EncryptWithAd(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_key is null)
        {
            return plaintext.ToArray();
        }

        var ciphertext = new byte[plaintext.Length + TagLength];
        EncryptWithAd(associatedData, plaintext, ciphertext);
        return ciphertext;
    }

    /// <summary>Encrypts into a caller-supplied buffer. Requires a key.</summary>
    /// <param name="associatedData">The associated data.</param>
    /// <param name="plaintext">The plaintext.</param>
    /// <param name="ciphertext">Exactly <c>plaintext.Length + 16</c> bytes.</param>
    public void EncryptWithAd(
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var key = _key ?? throw new InvalidOperationException("This cipher state has no key.");
        ThrowIfNonceReserved();

        Span<byte> nonce = stackalloc byte[ChaChaPoly.NonceSize];
        WriteNonce(nonce, _nonce);

        ChaChaPoly.Encrypt(key, nonce, associatedData, plaintext, ciphertext);
        _nonce++;
    }

    /// <summary>
    /// <c>DecryptWithAd(ad, ciphertext)</c>: <c>DECRYPT(k, n++, ad, ciphertext)</c>, or the
    /// ciphertext unchanged while <c>k</c> is empty.
    /// </summary>
    /// <param name="associatedData">The associated data.</param>
    /// <param name="ciphertext">The ciphertext.</param>
    /// <returns>The plaintext.</returns>
    /// <exception cref="SipProtocolException">
    /// Authentication failed (<see cref="SipProtocolFault.AuthenticationFailed"/>), or the
    /// ciphertext is too short to hold a tag (<see cref="SipProtocolFault.MalformedMessage"/>).
    /// Per section 5.1, <c>n</c> is not incremented when authentication fails.
    /// </exception>
    public byte[] DecryptWithAd(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_key is null)
        {
            return ciphertext.ToArray();
        }

        if (ciphertext.Length < TagLength)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                "An encrypted message was shorter than its authentication tag.");
        }

        var plaintext = new byte[ciphertext.Length - TagLength];
        DecryptWithAd(associatedData, ciphertext, plaintext);
        return plaintext;
    }

    /// <summary>Decrypts into a caller-supplied buffer. Requires a key.</summary>
    /// <param name="associatedData">The associated data.</param>
    /// <param name="ciphertext">The ciphertext, tag included.</param>
    /// <param name="plaintext">Exactly <c>ciphertext.Length - 16</c> bytes.</param>
    /// <exception cref="SipProtocolException">Authentication failed.</exception>
    public void DecryptWithAd(
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var key = _key ?? throw new InvalidOperationException("This cipher state has no key.");
        ThrowIfNonceReserved();

        Span<byte> nonce = stackalloc byte[ChaChaPoly.NonceSize];
        WriteNonce(nonce, _nonce);

        if (!ChaChaPoly.Decrypt(key, nonce, associatedData, ciphertext, plaintext))
        {
            throw new SipProtocolException(
                SipProtocolFault.AuthenticationFailed,
                "A message failed authentication: it was altered, replayed, reordered, or " +
                "encrypted under a different key.");
        }

        _nonce++;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _key?.Dispose();
        _key = null;
        _disposed = true;
    }

    /// <summary>Section 12.3: 32 bits of zeros, then <c>n</c> little-endian.</summary>
    private static void WriteNonce(Span<byte> nonce, ulong counter)
    {
        nonce[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
    }

    private void ThrowIfNonceReserved()
    {
        if (_nonce == ReservedNonce)
        {
            throw new InvalidOperationException(
                "This cipher state has used every nonce Noise allows (2^64-1 is reserved). " +
                "A new handshake is required.");
        }
    }
}
