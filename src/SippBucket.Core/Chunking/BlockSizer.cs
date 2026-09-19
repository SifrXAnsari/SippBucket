namespace SippBucket.Core.Chunking;

/// <summary>
/// Chooses the block size a file is split into before hashing and transfer.
/// </summary>
/// <remarks>
/// <para>
/// The scheme follows Syncthing's Block Exchange Protocol: blocks run from 128 KiB to
/// 16 MiB in powers of two, chosen so that a file lands near a target block count. Files
/// under 250 MiB use 128 KiB blocks; files past 16 GiB use 16 MiB blocks. Small blocks
/// transfer less on a small edit, large blocks keep the manifest from bloating.
/// </para>
/// <para>See https://docs.syncthing.net/specs/bep-v1.html for the source of these numbers.</para>
/// </remarks>
public static class BlockSizer
{
    /// <summary>Smallest block SippBucket will use, in bytes.</summary>
    public const int MinimumBlockSize = 128 * 1024;

    /// <summary>Largest block SippBucket will use, in bytes.</summary>
    public const int MaximumBlockSize = 16 * 1024 * 1024;

    /// <summary>
    /// Block count a file is aimed at before the size is stepped up. 2000 blocks of the
    /// 128 KiB minimum is the 250 MiB threshold quoted in the BEP specification.
    /// </summary>
    public const int TargetBlockCount = 2000;

    /// <summary>Returns the block size to use for a file of the given length.</summary>
    /// <param name="fileSizeInBytes">The length of the file, in bytes.</param>
    /// <returns>A power-of-two block size between the minimum and maximum.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The size was negative.</exception>
    public static int ForFileSize(long fileSizeInBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(fileSizeInBytes);

        var blockSize = (long)MinimumBlockSize;
        while (blockSize < MaximumBlockSize && fileSizeInBytes / blockSize > TargetBlockCount)
        {
            blockSize <<= 1;
        }

        return (int)blockSize;
    }

    /// <summary>Returns how many blocks a file of the given length occupies.</summary>
    /// <param name="fileSizeInBytes">The length of the file, in bytes.</param>
    /// <param name="blockSize">The block size in use, from <see cref="ForFileSize"/>.</param>
    /// <returns>The block count. An empty file occupies zero blocks.</returns>
    /// <exception cref="ArgumentOutOfRangeException">A size was out of range.</exception>
    public static int BlockCount(long fileSizeInBytes, int blockSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(fileSizeInBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);

        return (int)((fileSizeInBytes + blockSize - 1) / blockSize);
    }
}
