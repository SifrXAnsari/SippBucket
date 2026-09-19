using System.Security.Cryptography;

namespace SippBucket.Core.Protocol.Noise;

/// <summary>
/// The Noise <c>SymmetricState</c>: a <see cref="CipherState"/>, a chaining key <c>ck</c> and
/// a handshake hash <c>h</c> (Noise revision 34, section 5.2;
/// https://noiseprotocol.org/noise.html).
/// </summary>
/// <remarks>
/// <c>MixKeyAndHash()</c> is not implemented. Section 5.2 says it "is used for handling
/// pre-shared symmetric keys", and SippBucket's patterns use no PSK. It would be an untested
/// branch of the key schedule, which is worse than an absent one.
/// </remarks>
internal sealed class SymmetricState : IDisposable
{
    private readonly CipherState _cipher = new();
    private byte[] _chainingKey;
    private byte[] _hash;
    private bool _disposed;

    /// <summary><c>InitializeSymmetric(protocol_name)</c>.</summary>
    /// <param name="protocolName">The ASCII protocol name, for example <c>Noise_XK_25519_ChaChaPoly_BLAKE2b</c>.</param>
    /// <remarks>
    /// "If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to
    /// protocol_name with zero bytes appended to make HASHLEN bytes. Otherwise sets
    /// h = HASH(protocol_name). Sets ck = h. Calls InitializeKey(empty)."
    /// </remarks>
    public SymmetricState(ReadOnlySpan<byte> protocolName)
    {
        if (protocolName.Length <= NoiseHash.HashLength)
        {
            _hash = new byte[NoiseHash.HashLength];
            protocolName.CopyTo(_hash);
        }
        else
        {
            _hash = NoiseHash.Hash(protocolName);
        }

        _chainingKey = (byte[])_hash.Clone();
        _cipher.InitializeKey(ReadOnlySpan<byte>.Empty);
    }

    /// <summary>Whether the inner cipher state has a key yet.</summary>
    public bool HasKey => _cipher.HasKey;

    /// <summary>
    /// <c>GetHandshakeHash()</c>: a copy of <c>h</c>. Meaningful only once the handshake has
    /// finished.
    /// </summary>
    /// <returns>The 64-byte handshake hash.</returns>
    public byte[] GetHandshakeHash()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_hash.Clone();
    }

    /// <summary>
    /// <c>MixKey(input_key_material)</c>: <c>ck, temp_k = HKDF(ck, ikm, 2)</c>, truncate
    /// <c>temp_k</c> to 32 bytes because <c>HASHLEN</c> is 64, then <c>InitializeKey(temp_k)</c>.
    /// </summary>
    /// <param name="inputKeyMaterial">A DH output.</param>
    public void MixKey(ReadOnlySpan<byte> inputKeyMaterial)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var outputs = NoiseHash.Hkdf(_chainingKey, inputKeyMaterial, 2);
        CryptographicOperations.ZeroMemory(_chainingKey);
        _chainingKey = outputs[0];

        try
        {
            _cipher.InitializeKey(outputs[1].AsSpan(0, CipherState.KeyLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(outputs[1]);
        }
    }

    /// <summary><c>MixHash(data)</c>: <c>h = HASH(h || data)</c>.</summary>
    /// <param name="data">The data to mix in.</param>
    public void MixHash(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _hash = NoiseHash.Hash(_hash, data);
    }

    /// <summary>
    /// <c>EncryptAndHash(plaintext)</c>: encrypt with <c>h</c> as associated data, then mix the
    /// ciphertext into <c>h</c>.
    /// </summary>
    /// <param name="plaintext">The plaintext.</param>
    /// <returns>The ciphertext, or the plaintext itself while there is no key.</returns>
    public byte[] EncryptAndHash(ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var ciphertext = _cipher.EncryptWithAd(_hash, plaintext);
        MixHash(ciphertext);
        return ciphertext;
    }

    /// <summary>
    /// <c>DecryptAndHash(ciphertext)</c>: decrypt with <c>h</c> as associated data, then mix
    /// the ciphertext into <c>h</c>.
    /// </summary>
    /// <param name="ciphertext">The ciphertext.</param>
    /// <returns>The plaintext.</returns>
    /// <exception cref="SipProtocolException">Authentication failed.</exception>
    public byte[] DecryptAndHash(ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var plaintext = _cipher.DecryptWithAd(_hash, ciphertext);
        MixHash(ciphertext);
        return plaintext;
    }

    /// <summary>
    /// <c>Split()</c>: <c>temp_k1, temp_k2 = HKDF(ck, zerolen, 2)</c>, each truncated to 32
    /// bytes, as the keys of two new cipher states.
    /// </summary>
    /// <returns>
    /// <c>c1</c>, for messages the initiator sends, and <c>c2</c>, for messages the responder
    /// sends. The caller owns both.
    /// </returns>
    public (CipherState Initiator, CipherState Responder) Split()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var outputs = NoiseHash.Hkdf(_chainingKey, ReadOnlySpan<byte>.Empty, 2);
        var first = new CipherState();
        var second = new CipherState();

        try
        {
            first.InitializeKey(outputs[0].AsSpan(0, CipherState.KeyLength));
            second.InitializeKey(outputs[1].AsSpan(0, CipherState.KeyLength));
            return (first, second);
        }
        catch
        {
            first.Dispose();
            second.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(outputs[0]);
            CryptographicOperations.ZeroMemory(outputs[1]);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _cipher.Dispose();
        CryptographicOperations.ZeroMemory(_chainingKey);
        CryptographicOperations.ZeroMemory(_hash);
        _disposed = true;
    }
}
