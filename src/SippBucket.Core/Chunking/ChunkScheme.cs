using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;

namespace SippBucket.Core.Chunking;

/// <summary>
/// How a file is split into blocks: the recipe a <see cref="FileEntry"/> records in
/// <see cref="FileEntry.Chunker"/> and <see cref="FileEntry.BlockSize"/>, so the same split
/// can be made again.
/// </summary>
/// <remarks>
/// <para>
/// Two recipes exist. Every entry written before content-defined chunking is fixed-size, with
/// no chunker name. Every file saved since is <see cref="FastCdc"/>. Both kinds live in the
/// same snapshots for as long as a file stays unchanged, because an unchanged file's entry is
/// reused rather than re-read. Restoring and syncing never care which is which — a file is
/// the concatenation of its blocks — but <em>comparing</em> two entries does.
/// </para>
/// <para>
/// That is the failure this type exists to prevent. The same bytes split two ways have two
/// different block lists, so a comparison of block lists calls identical files different.
/// The merge path renames the local copy of any file that differs from the incoming one, so
/// after the upgrade every unchanged multi-block file on a peer would have come back as a
/// conflict copy on the first divergent sync. <see cref="SameContentAsync"/> is the
/// comparison that does not.
/// </para>
/// </remarks>
public sealed record ChunkScheme
{
    private readonly FastCdcParameters? _contentDefined;

    private ChunkScheme(string? chunker, int blockSize, FastCdcParameters? contentDefined)
    {
        Chunker = chunker;
        BlockSize = blockSize;
        _contentDefined = contentDefined;
    }

    /// <summary>The value for <see cref="FileEntry.Chunker"/>. Null for fixed-size.</summary>
    public string? Chunker { get; }

    /// <summary>
    /// The value for <see cref="FileEntry.BlockSize"/>: the block length for fixed-size, the
    /// average chunk length for FastCDC.
    /// </summary>
    public int BlockSize { get; }

    /// <summary>The recipe for a file being saved now.</summary>
    /// <param name="fileSizeInBytes">The length of the file, in bytes.</param>
    /// <returns>FastCDC, at the tier for the file's size.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The size was negative.</exception>
    public static ChunkScheme ForNewFile(long fileSizeInBytes)
    {
        var parameters = FastCdc.ForFileSize(fileSizeInBytes);
        return new ChunkScheme(FastCdc.Name, parameters.Average, parameters);
    }

    /// <summary>The fixed-size recipe every entry before FastCDC was written with.</summary>
    /// <param name="blockSize">
    /// The block length: a power of two from <see cref="BlockSizer.MinimumBlockSize"/> to
    /// <see cref="BlockSizer.MaximumBlockSize"/>, the only sizes that build ever used.
    /// </param>
    /// <returns>The recipe.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The size was not one that build used.</exception>
    public static ChunkScheme FixedSize(int blockSize)
    {
        if (!IsFixedBlockSize(blockSize))
        {
            throw new ArgumentOutOfRangeException(
                nameof(blockSize),
                blockSize,
                "A fixed-size block is a power of two from 128 KiB to 16 MiB.");
        }

        return new ChunkScheme(null, blockSize, null);
    }

    /// <summary>Reads the recipe an entry was written with.</summary>
    /// <param name="entry">The entry.</param>
    /// <param name="scheme">The recipe, when this build knows it.</param>
    /// <returns>
    /// False for a chunker name this build does not know, or a block size its recipe never
    /// produces. Such an entry still restores; it just cannot be re-split for comparison.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="entry"/> was null.</exception>
    /// <remarks>
    /// The block size comes from a snapshot, which may have come from a peer, so it is
    /// checked against the sizes each recipe really uses before anything is allocated for
    /// it. An entry claiming one-byte blocks, or a gigabyte average, is refused.
    /// </remarks>
    public static bool TryFor(FileEntry entry, [NotNullWhen(true)] out ChunkScheme? scheme)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (entry.Chunker is null)
        {
            scheme = IsFixedBlockSize(entry.BlockSize) ? new ChunkScheme(null, entry.BlockSize, null) : null;
            return scheme is not null;
        }

        if (string.Equals(entry.Chunker, FastCdc.Name, StringComparison.Ordinal) &&
            FastCdc.TryGetTier(entry.BlockSize, out var parameters))
        {
            scheme = new ChunkScheme(FastCdc.Name, parameters.Average, parameters);
            return true;
        }

        scheme = null;
        return false;
    }

    /// <summary>Splits a stream into blocks with this recipe, as it is read.</summary>
    /// <param name="stream">The stream to split, from its current position to its end.</param>
    /// <param name="lengthHint">How long the stream is expected to be. Sizes buffers only.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// Each block in order. A block is a view of a buffer the next block reuses, so finish
    /// with it before asking for the next.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="lengthHint"/> was negative.</exception>
    public IAsyncEnumerable<ReadOnlyMemory<byte>> SplitAsync(
        Stream stream,
        long lengthHint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegative(lengthHint);

        return _contentDefined is { } parameters
            ? FastCdc.SplitAsync(stream, parameters, lengthHint, cancellationToken)
            : SplitFixedAsync(stream, BlockSize, cancellationToken);
    }

    /// <summary>
    /// True when the file at <paramref name="path"/> holds exactly the bytes
    /// <paramref name="recorded"/> describes, however each entry was chunked.
    /// </summary>
    /// <param name="path">The file <paramref name="scanned"/> was made from.</param>
    /// <param name="scanned">An entry just made from the file.</param>
    /// <param name="recorded">The entry to compare it with, typically a peer's.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>True when the content is the same.</returns>
    /// <exception cref="ArgumentException"><paramref name="path"/> was null or blank.</exception>
    /// <exception cref="ArgumentNullException">An entry was null.</exception>
    /// <remarks>
    /// <para>
    /// Two entries with the same recipe are compared by block list, which is exact: the
    /// split is a pure function of the bytes. Only when the recipes differ is the file read
    /// again, split the way <paramref name="recorded"/> was, and hashed block by block — at
    /// most once per file, and only for files whose recipe changed, which is the one-time
    /// cost of the upgrade. The read stops at the first block that differs.
    /// </para>
    /// <para>
    /// A recipe this build does not know compares as different. In the merge that means a
    /// conflict copy, which keeps both versions: the safe way to be wrong.
    /// </para>
    /// </remarks>
    public static async Task<bool> SameContentAsync(
        string path,
        FileEntry scanned,
        FileEntry recorded,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(scanned);
        ArgumentNullException.ThrowIfNull(recorded);

        if (scanned.Size != recorded.Size)
        {
            return false;
        }

        if (string.Equals(scanned.Chunker, recorded.Chunker, StringComparison.Ordinal) &&
            scanned.BlockSize == recorded.BlockSize)
        {
            return scanned.Blocks.SequenceEqual(recorded.Blocks);
        }

        return (await ReadMatchesAsync(path, recorded, cancellationToken).ConfigureAwait(false)).Same;
    }

    /// <summary>
    /// Reads the file at <paramref name="path"/>, splits it the way <paramref name="recorded"/>
    /// was split, and says whether every block matches, with how many bytes were read.
    /// </summary>
    /// <param name="path">The file.</param>
    /// <param name="recorded">The entry to compare it with.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// Whether the file holds exactly the recorded blocks, and the bytes read on the way to
    /// that answer: the whole file when it matches, and fewer when the read stopped at the
    /// first block that differed.
    /// </returns>
    /// <remarks>
    /// The byte count is what lets the scan check that what it compared was the whole file
    /// as it stood before and after the read, rather than a file that changed part way
    /// through (D-61). A recipe this build does not know matches nothing and reads nothing.
    /// </remarks>
    internal static async Task<(bool Same, long BytesRead)> ReadMatchesAsync(
        string path,
        FileEntry recorded,
        CancellationToken cancellationToken)
    {
        if (!TryFor(recorded, out var scheme))
        {
            return (false, 0);
        }

        var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 0,
            useAsync: true);

        await using (stream.ConfigureAwait(false))
        {
            var index = 0;
            long read = 0;
            await foreach (var block in scheme
                .SplitAsync(stream, recorded.Size, cancellationToken)
                .ConfigureAwait(false))
            {
                read += block.Length;
                if (index >= recorded.Blocks.Count || Blake2.Hash(block.Span) != recorded.Blocks[index])
                {
                    return (false, read);
                }

                index++;
            }

            return (index == recorded.Blocks.Count, read);
        }
    }

    private static bool IsFixedBlockSize(int blockSize) =>
        blockSize is >= BlockSizer.MinimumBlockSize and <= BlockSizer.MaximumBlockSize &&
        BitOperations.IsPow2(blockSize);

    /// <summary>
    /// The fixed-size split exactly as the scan did it before FastCDC: fill a block, emit it,
    /// repeat until a read returns nothing.
    /// </summary>
    private static async IAsyncEnumerable<ReadOnlyMemory<byte>> SplitFixedAsync(
        Stream stream,
        int blockSize,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var buffer = new byte[blockSize];
        while (true)
        {
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await stream
                    .ReadAsync(buffer.AsMemory(total), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            if (total == 0)
            {
                yield break;
            }

            yield return buffer.AsMemory(0, total);
        }
    }
}
