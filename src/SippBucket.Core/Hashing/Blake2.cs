using NSec.Cryptography;

namespace SippBucket.Core.Hashing;

/// <summary>
/// Content hashing for the store. BLAKE2b-256 via libsodium.
/// </summary>
/// <remarks>
/// BLAKE2b is the hash libsodium exposes as its general-purpose primitive and is faster
/// than SHA-256 on the 64-bit machines SippBucket targets. Every block, file manifest and
/// snapshot in the store is named by its BLAKE2b-256 digest.
/// </remarks>
public static class Blake2
{
    private static readonly HashAlgorithm Algorithm = HashAlgorithm.Blake2b_256;

    /// <summary>Hashes a block of bytes.</summary>
    /// <param name="data">The bytes to hash.</param>
    /// <returns>The content hash of <paramref name="data"/>.</returns>
    public static ContentHash Hash(ReadOnlySpan<byte> data)
    {
        Span<byte> digest = stackalloc byte[ContentHash.SizeInBytes];
        Algorithm.Hash(data, digest);
        return new ContentHash(digest);
    }

    /// <summary>Hashes a stream from its current position to its end.</summary>
    /// <param name="stream">The stream to read.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The content hash of the remaining bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> was null.</exception>
    public static async Task<ContentHash> HashStreamAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        // IncrementalHash is the streaming form; the whole file never has to be resident.
        IncrementalHash.Initialize(Algorithm, out var state);
        var buffer = new byte[64 * 1024];

        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            IncrementalHash.Update(ref state, buffer.AsSpan(0, read));
        }

        var digest = new byte[ContentHash.SizeInBytes];
        IncrementalHash.Finalize(ref state, digest);
        return new ContentHash(digest);
    }
}
