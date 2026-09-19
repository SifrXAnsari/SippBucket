using System.Globalization;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;

namespace SippBucket.Core.Storage;

/// <summary>
/// The content-addressed blob store: every block of every file, named by the BLAKE2b-256
/// hash of its plaintext and stored encrypted.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here is ever overwritten. A block's name is derived from its content, so a
/// write of content that already exists is a no-op rather than a conflict. That single
/// property is what lets two machines sync in any direction without a merge step, and it
/// is the model Perkeep uses for personal storage.
/// </para>
/// <para>
/// Blocks are fanned out one level by the first byte of the hash — <c>objects/ab/cdef…</c>
/// — so no directory grows to hundreds of thousands of entries.
/// </para>
/// </remarks>
public sealed class BlobStore
{
    private readonly string _root;
    private readonly RepositoryCipher _cipher;
    private bool _fanoutCreated;

    /// <summary>Creates a store over a directory.</summary>
    /// <param name="rootDirectory">Directory holding the object fan-out.</param>
    /// <param name="cipher">Cipher for the repository these blocks belong to.</param>
    /// <exception cref="ArgumentException">The directory was null or blank.</exception>
    /// <exception cref="ArgumentNullException">The cipher was null.</exception>
    public BlobStore(string rootDirectory, RepositoryCipher cipher)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        ArgumentNullException.ThrowIfNull(cipher);

        _root = rootDirectory;
        _cipher = cipher;
        Directory.CreateDirectory(_root);
    }

    /// <summary>
    /// Test seam: runs after a block has been written to its temporary name and before it is
    /// renamed into place, with the temporary file's path.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only. The temporary name is random, so the only way to show
    /// that a scanner reading the file just written does not fail the rename (D-69) is to
    /// open it in exactly this window, which is what a scanner does. Production code never
    /// sets it.
    /// </remarks>
    internal Func<string, Task>? AfterTemporaryWritten { get; set; }

    /// <summary>True when the store already holds a block.</summary>
    /// <param name="hash">The block's content hash.</param>
    /// <returns>True when the block is present.</returns>
    public bool Contains(ContentHash hash) => File.Exists(PathFor(hash));

    /// <summary>
    /// Stores a block. Returns false without writing when the block is already present.
    /// </summary>
    /// <param name="plaintext">The block's bytes.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>The block's hash, and whether it was newly written.</returns>
    public async Task<(ContentHash Hash, bool Written)> PutAsync(
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken = default)
    {
        var hash = Blake2.Hash(plaintext.Span);
        if (Contains(hash))
        {
            return (hash, false);
        }

        var ciphertext = _cipher.Encrypt(hash, plaintext.Span);
        await WriteRawAsync(hash, ciphertext, cancellationToken).ConfigureAwait(false);
        return (hash, true);
    }

    /// <summary>Reads and decrypts a block.</summary>
    /// <param name="hash">The block's content hash.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The block's plaintext.</returns>
    /// <exception cref="BlockNotFoundException">The store does not hold the block.</exception>
    /// <exception cref="CorruptBlockException">The block failed verification.</exception>
    public async Task<byte[]> GetAsync(
        ContentHash hash,
        CancellationToken cancellationToken = default)
    {
        var ciphertext = await GetRawAsync(hash, cancellationToken).ConfigureAwait(false);
        var plaintext = _cipher.Decrypt(hash, ciphertext);

        // The tag proves the ciphertext was not altered; this proves the store filed it
        // under the right name. A mismatch means the store itself is inconsistent.
        var actual = Blake2.Hash(plaintext);
        if (actual != hash)
        {
            throw new CorruptBlockException(
                $"Block {hash.ToShortString()} decrypted to content hashing " +
                $"{actual.ToShortString()}; the store is inconsistent.");
        }

        return plaintext;
    }

    /// <summary>
    /// Reads a block without decrypting it. This is the form that travels between peers.
    /// </summary>
    /// <param name="hash">The block's content hash.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The stored ciphertext.</returns>
    /// <exception cref="BlockNotFoundException">The store does not hold the block.</exception>
    public async Task<byte[]> GetRawAsync(
        ContentHash hash,
        CancellationToken cancellationToken = default) =>
        await TryGetRawAsync(hash, cancellationToken).ConfigureAwait(false)
        ?? throw new BlockNotFoundException(hash);

    /// <summary>
    /// Reads a block without decrypting it, or answers null when the store does not hold it.
    /// </summary>
    /// <param name="hash">The block's content hash.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The stored ciphertext, or null when no file holds it.</returns>
    /// <remarks>
    /// <para>
    /// One read, and "not here" decided by that read: the shape D-57 gave snapshots. Asking
    /// <see cref="Contains"/> first and then reading let a collection, which runs after every
    /// Simple-mode save, delete the block between the two, and the peer being served lost
    /// its connection instead of hearing "I do not have that".
    /// </para>
    /// <para>
    /// What the read finds is whole. A block reaches its name only by a rename once it is
    /// fully written (<see cref="PutAsync"/>), and a delete cannot land part way through the
    /// read: the read's handle shares no delete access, so Windows refuses the collector's
    /// delete until the read has finished, which the collector waits out
    /// (<see cref="SharingRetry"/>).
    /// </para>
    /// </remarks>
    public async Task<byte[]?> TryGetRawAsync(
        ContentHash hash,
        CancellationToken cancellationToken = default)
    {
        var path = PathFor(hash);

        try
        {
            return await SharingRetry
                .RunAsync(token => File.ReadAllBytesAsync(path, token), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>
    /// Stores a block received from a peer, still encrypted, after checking it decrypts to
    /// the name it claims.
    /// </summary>
    /// <param name="hash">The hash the peer says this block has.</param>
    /// <param name="ciphertext">The received bytes.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>True when the block was newly written.</returns>
    /// <exception cref="CorruptBlockException">The block did not match its claimed hash.</exception>
    public async Task<bool> PutRawVerifiedAsync(
        ContentHash hash,
        ReadOnlyMemory<byte> ciphertext,
        CancellationToken cancellationToken = default)
    {
        if (Contains(hash))
        {
            return false;
        }

        // Never trust a peer's label. Decrypt and re-hash before the block is filed.
        var plaintext = _cipher.Decrypt(hash, ciphertext.Span);
        var actual = Blake2.Hash(plaintext);
        if (actual != hash)
        {
            throw new CorruptBlockException(
                $"A peer sent a block labelled {hash.ToShortString()} that actually " +
                $"hashes to {actual.ToShortString()}; it was rejected.");
        }

        await WriteRawAsync(hash, ciphertext, cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>Total bytes the store occupies on disk.</summary>
    /// <returns>The sum of every object file's length.</returns>
    public long TotalSizeInBytes()
    {
        if (!Directory.Exists(_root))
        {
            return 0;
        }

        long total = 0;
        foreach (var file in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
        {
            total += new FileInfo(file).Length;
        }

        return total;
    }

    /// <summary>Counts the blocks in the store.</summary>
    /// <returns>The number of stored objects.</returns>
    public int Count() =>
        Directory.Exists(_root)
            ? Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories).Count()
            : 0;

    /// <summary>Lists every block the store holds, with its size on disk.</summary>
    /// <returns>Each stored block's hash and byte length.</returns>
    /// <remarks>
    /// Walks the fan-out rather than trusting an index, because there is no index. A store
    /// that could disagree with its own directory listing would be worse than one that has
    /// to be counted.
    /// </remarks>
    public IReadOnlyList<StoredBlock> List()
    {
        if (!Directory.Exists(_root))
        {
            return [];
        }

        var blocks = new List<StoredBlock>();

        foreach (var file in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
        {
            // Skip half-written temporaries. They belong to a write in flight and are not
            // blocks yet; counting them would make usage jitter during a sync.
            if (file.EndsWith(".tmp", StringComparison.Ordinal))
            {
                continue;
            }

            var info = new FileInfo(file);
            var name = info.Directory!.Name + info.Name;

            if (ContentHash.TryParse(name, out var hash))
            {
                blocks.Add(new StoredBlock(hash, info.Length));
            }
        }

        return blocks;
    }

    /// <summary>Deletes one block.</summary>
    /// <param name="hash">The block to remove.</param>
    /// <returns>True when a file was deleted.</returns>
    /// <remarks>
    /// Deliberately not public on the repository. Deleting a block that some snapshot still
    /// refers to turns a file into an unreadable one, so the only caller that should reach
    /// this is a collector that has just computed the live set.
    /// </remarks>
    public bool Delete(ContentHash hash)
    {
        var path = PathFor(hash);
        if (!File.Exists(path))
        {
            return false;
        }

        SharingRetry.Run(() => File.Delete(path));
        return true;
    }

    private async Task WriteRawAsync(
        ContentHash hash,
        ReadOnlyMemory<byte> ciphertext,
        CancellationToken cancellationToken)
    {
        var path = PathFor(hash);
        var directory = Path.GetDirectoryName(path)!;

        // The 256 fan-out directories are pre-created once per store rather than
        // CreateDirectory being called per block. Per-file metadata operations dominate
        // this path: measured, the filesystem is 68-76% of a cold save, so every syscall
        // removed from the per-block loop is worth more than any amount of CPU tuning.
        EnsureFanoutCreated();

        // Write to a temporary name and move into place, so a crash mid-write never leaves
        // a truncated object under a hash that claims to be complete.
        //
        // The rename is where another program's hold bites (D-69): a scanner reading the file
        // just written holds it without sharing delete, and a rename needs exactly that, so
        // the move failed and took the save with it. It is waited out. A destination that
        // already exists is not a sharing violation and is not retried; it falls to the catch
        // below as before.
        var temporary = Path.Combine(directory, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        var moved = false;
        try
        {
            await SharingRetry
                .RunAsync(token => File.WriteAllBytesAsync(temporary, ciphertext, token), cancellationToken)
                .ConfigureAwait(false);

            if (AfterTemporaryWritten is { } afterWritten)
            {
                await afterWritten(temporary).ConfigureAwait(false);
            }

            SharingRetry.Run(() => File.Move(temporary, path, overwrite: false));
            moved = true;
        }
        catch (IOException) when (File.Exists(path))
        {
            // Another writer stored the same content first. Content addressing means their
            // bytes and ours are identical, so there is nothing to reconcile.
        }
        finally
        {
            // Only stat the temp file when the Move did not happen. After a successful
            // Move the old code called File.Exists on a name that is always gone, paying
            // a syscall per block for an answer that is always false.
            if (!moved && File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    /// <summary>
    /// Creates the 256 first-byte fan-out directories once, so the per-block write path
    /// never has to.
    /// </summary>
    private void EnsureFanoutCreated()
    {
        if (_fanoutCreated)
        {
            return;
        }

        for (var i = 0; i < 256; i++)
        {
            Directory.CreateDirectory(Path.Combine(_root, i.ToString("x2", CultureInfo.InvariantCulture)));
        }

        _fanoutCreated = true;
    }

    private string PathFor(ContentHash hash)
    {
        var hex = hash.ToString();
        return Path.Combine(_root, hex[..2], hex[2..]);
    }
}

/// <summary>One block as it sits on disk.</summary>
/// <param name="Hash">The block's content hash.</param>
/// <param name="SizeInBytes">Its size on disk, which includes the authentication tag.</param>
public readonly record struct StoredBlock(ContentHash Hash, long SizeInBytes);
