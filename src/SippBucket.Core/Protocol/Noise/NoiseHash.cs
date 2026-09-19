using System.Security.Cryptography;
using HashAlgorithm = NSec.Cryptography.HashAlgorithm;

namespace SippBucket.Core.Protocol.Noise;

/// <summary>
/// The Noise hash functions for BLAKE2b: <c>HASH</c>, <c>HMAC-HASH</c> and <c>HKDF</c>
/// (Noise revision 34, sections 4.3 and 12.8; https://noiseprotocol.org/noise.html).
/// </summary>
/// <remarks>
/// <para>
/// HMAC is written out as RFC 2104 defines it rather than approximated with BLAKE2b's own
/// keyed mode. The two are different functions with different outputs, and Noise section 4.3
/// names HMAC explicitly: "Applies HMAC from [RFC 2104] using the HASH() function", with
/// <c>BLOCKLEN</c> as RFC 2104's <c>B</c>. Keyed BLAKE2b would interoperate with nothing. The
/// published test vectors are what would catch the substitution: changing only the HMAC
/// block size from 128 to 64 fails every one of them.
/// </para>
/// <para>
/// Intermediate keys are zeroed once used. They are chaining-key material, and a stale copy
/// is as good as the live one to anyone who reads it.
/// </para>
/// </remarks>
internal static class NoiseHash
{
    /// <summary><c>HASHLEN</c> for BLAKE2b (section 12.8).</summary>
    public const int HashLength = 64;

    /// <summary><c>BLOCKLEN</c> for BLAKE2b (section 12.8), RFC 2104's <c>B</c>.</summary>
    public const int BlockLength = 128;

    private const byte InnerPad = 0x36;
    private const byte OuterPad = 0x5C;

    private static readonly HashAlgorithm Blake2b = HashAlgorithm.Blake2b_512;

    /// <summary><c>HASH(data)</c>: BLAKE2b with a 64-byte digest (RFC 7693).</summary>
    /// <param name="data">The input.</param>
    /// <returns>The 64-byte digest.</returns>
    public static byte[] Hash(ReadOnlySpan<byte> data) => Blake2b.Hash(data);

    /// <summary><c>HASH(first || second)</c>, without the caller building the concatenation.</summary>
    /// <param name="first">The first input.</param>
    /// <param name="second">The second input.</param>
    /// <returns>The 64-byte digest.</returns>
    public static byte[] Hash(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var joined = new byte[first.Length + second.Length];
        first.CopyTo(joined);
        second.CopyTo(joined.AsSpan(first.Length));
        return Blake2b.Hash(joined);
    }

    /// <summary><c>HMAC-HASH(key, data)</c> exactly as RFC 2104 section 2 defines it.</summary>
    /// <param name="key">The HMAC key.</param>
    /// <param name="data">The message.</param>
    /// <returns>The 64-byte MAC.</returns>
    /// <remarks>
    /// <c>H(K XOR opad, H(K XOR ipad, text))</c>, where K is the key zero-padded to
    /// <c>B</c> = 128 bytes, or first hashed if it is longer than that (RFC 2104 section 2:
    /// "Applications that use keys longer than B bytes will first hash the key using H").
    /// </remarks>
    public static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var block = new byte[BlockLength];
        byte[]? hashedKey = null;

        try
        {
            if (key.Length > BlockLength)
            {
                hashedKey = Hash(key);
                hashedKey.CopyTo(block, 0);
            }
            else
            {
                key.CopyTo(block);
            }

            var inner = new byte[BlockLength + data.Length];
            var outer = new byte[BlockLength + HashLength];
            byte[]? innerDigest = null;

            try
            {
                for (var i = 0; i < BlockLength; i++)
                {
                    inner[i] = (byte)(block[i] ^ InnerPad);
                    outer[i] = (byte)(block[i] ^ OuterPad);
                }

                data.CopyTo(inner.AsSpan(BlockLength));
                innerDigest = Hash(inner);
                innerDigest.CopyTo(outer, BlockLength);
                return Hash(outer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(inner);
                CryptographicOperations.ZeroMemory(outer);
                if (innerDigest is not null)
                {
                    CryptographicOperations.ZeroMemory(innerDigest);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            if (hashedKey is not null)
            {
                CryptographicOperations.ZeroMemory(hashedKey);
            }
        }
    }

    /// <summary>
    /// <c>HKDF(chaining_key, input_key_material, num_outputs)</c> as section 4.3 defines it.
    /// </summary>
    /// <param name="chainingKey">The <c>HASHLEN</c>-byte chaining key, used as the HKDF salt.</param>
    /// <param name="inputKeyMaterial">Zero bytes, 32 bytes or <c>DHLEN</c> bytes.</param>
    /// <param name="outputCount">Two or three.</param>
    /// <returns>That many outputs, each <c>HASHLEN</c> bytes. The caller zeroes them.</returns>
    /// <remarks>
    /// Section 4.3 in full: <c>temp_key = HMAC-HASH(chaining_key, input_key_material)</c>;
    /// <c>output1 = HMAC-HASH(temp_key, byte(0x01))</c>;
    /// <c>output2 = HMAC-HASH(temp_key, output1 || byte(0x02))</c>; and, for three outputs,
    /// <c>output3 = HMAC-HASH(temp_key, output2 || byte(0x03))</c>. The spec notes this is
    /// RFC 5869 HKDF with the chaining key as salt and an empty info string.
    /// </remarks>
    public static byte[][] Hkdf(ReadOnlySpan<byte> chainingKey, ReadOnlySpan<byte> inputKeyMaterial, int outputCount)
    {
        if (chainingKey.Length != HashLength)
        {
            throw new ArgumentException($"A chaining key is {HashLength} bytes.", nameof(chainingKey));
        }

        if (inputKeyMaterial.Length is not (0 or 32))
        {
            // DHLEN is also 32 for 25519, so this is the whole of section 4.3's allowed set.
            throw new ArgumentException("HKDF input key material is zero or 32 bytes.", nameof(inputKeyMaterial));
        }

        if (outputCount is not (2 or 3))
        {
            throw new ArgumentOutOfRangeException(nameof(outputCount), outputCount, "HKDF returns two or three outputs.");
        }

        var tempKey = Hmac(chainingKey, inputKeyMaterial);
        var input = new byte[HashLength + 1];

        try
        {
            var outputs = new byte[outputCount][];
            outputs[0] = Hmac(tempKey, [0x01]);

            for (var i = 1; i < outputCount; i++)
            {
                outputs[i - 1].CopyTo(input, 0);
                input[HashLength] = (byte)(i + 1);
                outputs[i] = Hmac(tempKey, input);
            }

            return outputs;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tempKey);
            CryptographicOperations.ZeroMemory(input);
        }
    }
}
