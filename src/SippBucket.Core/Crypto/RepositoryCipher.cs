using NSec.Cryptography;
using SippBucket.Core.Hashing;

namespace SippBucket.Core.Crypto;

/// <summary>
/// Encrypts and decrypts the blocks of one repository with XChaCha20-Poly1305, under the
/// repository's key ring: one current key that everything new is written with, and the older
/// keys still needed to read what was written before a rotation (D-70).
/// </summary>
/// <remarks>
/// <para>
/// Blocks are stored encrypted and travel encrypted: the bytes on disk are the bytes on
/// the wire, so a peer relays content without ever decrypting it. Snapshots are encrypted
/// at rest under the same keys but are not sent in this form — they travel inside the
/// already-encrypted <c>SecureChannel</c> as ordinary messages.
/// </para>
/// <para>
/// The nonce is derived from the block's own content hash rather than drawn at random.
/// That is deliberate. The store is content addressed, so the same plaintext always has
/// the same name; deriving the nonce from that name means the same block encrypts to the
/// same ciphertext under one key, which keeps deduplication working and makes a write
/// idempotent. It also makes nonce reuse across *different* content impossible, which is
/// the property that actually matters. The cost is that equal blocks are visibly equal on
/// disk — but a content-addressed store already reveals exactly that through its filenames.
/// </para>
/// <para>
/// <b>The ring (D-70).</b> Removing a machine rotates the folder's key: a fresh key becomes
/// current, and everything written from then on is under it, which the removed machine never
/// receives. The old keys are kept, because the blocks written under them are not rewritten —
/// rewriting a whole store to rotate would make removal so expensive nobody would do it, and
/// the removed machine already holds, or could already have copied, everything the old keys
/// protect. Rotation guards what comes <em>after</em> it; nothing can un-share what was
/// already shared. Decryption tries the current key first — after a rotation settles, that is
/// every new block — then the older keys, newest first; the authentication tag says which key
/// a ciphertext was written under, so a wrong key can never yield wrong plaintext, only a
/// clean failure.
/// </para>
/// <para>
/// The ring can be replaced while the repository runs (<see cref="ReplaceRing"/>): the daemon
/// learns of a rotation mid-poll. Replacement swaps one immutable key set for another, so a
/// decrypt in flight finishes on the set it started with; retired key objects are kept until
/// the cipher is disposed, because an operation may still hold them, and a repository sees at
/// most a handful of rotations in its life.
/// </para>
/// </remarks>
public sealed class RepositoryCipher : IDisposable
{
    private static readonly AeadAlgorithm Algorithm = AeadAlgorithm.XChaCha20Poly1305;

    private readonly Lock _gate = new();
    private readonly List<Key> _retired = [];
    private KeySet _keys;
    private bool _disposed;

    /// <summary>Creates a cipher from a raw repository key, with no older keys.</summary>
    /// <param name="keyMaterial">The key. Must be <see cref="KeySize"/> bytes.</param>
    /// <exception cref="ArgumentException">The key was the wrong length.</exception>
    public RepositoryCipher(ReadOnlySpan<byte> keyMaterial)
    {
        _keys = new KeySet(Import(keyMaterial), []);
    }

    /// <summary>Creates a cipher from a whole key ring.</summary>
    /// <param name="keyMaterial">The current key: what everything new is written with.</param>
    /// <param name="previousKeys">The older keys, oldest first; still read, never written with.</param>
    /// <exception cref="ArgumentNullException"><paramref name="previousKeys"/> was null.</exception>
    /// <exception cref="ArgumentException">A key was the wrong length.</exception>
    public RepositoryCipher(ReadOnlySpan<byte> keyMaterial, IReadOnlyList<byte[]> previousKeys)
    {
        ArgumentNullException.ThrowIfNull(previousKeys);

        var older = new Key[previousKeys.Count];
        try
        {
            // Kept newest-first, because a block that is not under the current key is most
            // often under the key just before it.
            for (var i = 0; i < previousKeys.Count; i++)
            {
                older[i] = Import(previousKeys[previousKeys.Count - 1 - i]);
            }

            _keys = new KeySet(Import(keyMaterial), older);
        }
        catch
        {
            foreach (var key in older)
            {
                key?.Dispose();
            }

            throw;
        }
    }

    /// <summary>Length of a repository key in bytes.</summary>
    public static int KeySize => Algorithm.KeySize;

    /// <summary>Bytes the authentication tag adds to every encrypted block.</summary>
    public static int Overhead => Algorithm.TagSize;

    /// <summary>How many keys the ring holds: 1 before any rotation.</summary>
    public int Generation
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return 1 + Volatile.Read(ref _keys).Older.Length;
        }
    }

    /// <summary>Generates a fresh random repository key.</summary>
    /// <returns>A new key, as raw bytes.</returns>
    public static byte[] CreateKey()
    {
        using var key = Key.Create(
            Algorithm,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return key.Export(KeyBlobFormat.RawSymmetricKey);
    }

    /// <summary>
    /// Replaces the whole ring: what a rotation, made here or learned from a peer, installs.
    /// </summary>
    /// <param name="ring">Every key, oldest first; the last is the new current key.</param>
    /// <exception cref="ArgumentException">The ring is empty, or a key is the wrong length.</exception>
    /// <exception cref="ObjectDisposedException">The cipher was disposed.</exception>
    public void ReplaceRing(IReadOnlyList<byte[]> ring)
    {
        ArgumentNullException.ThrowIfNull(ring);

        if (ring.Count == 0)
        {
            throw new ArgumentException("A key ring holds at least its current key.", nameof(ring));
        }

        var older = new Key[ring.Count - 1];
        Key? current = null;
        try
        {
            for (var i = 0; i < older.Length; i++)
            {
                older[i] = Import(ring[ring.Count - 2 - i]);
            }

            current = Import(ring[^1]);
        }
        catch
        {
            current?.Dispose();
            foreach (var key in older)
            {
                key?.Dispose();
            }

            throw;
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            var replaced = _keys;
            Volatile.Write(ref _keys, new KeySet(current, older));

            // An operation in flight may still hold the replaced set, so its keys retire
            // rather than die; they are disposed with the cipher.
            _retired.Add(replaced.Current);
            _retired.AddRange(replaced.Older);
        }
    }

    /// <summary>Encrypts one block, always under the current key.</summary>
    /// <param name="contentHash">The hash of the plaintext, which derives the nonce.</param>
    /// <param name="plaintext">The block's bytes.</param>
    /// <returns>Ciphertext, <see cref="Overhead"/> bytes longer than the plaintext.</returns>
    /// <exception cref="ObjectDisposedException">The cipher was disposed.</exception>
    public byte[] Encrypt(ContentHash contentHash, ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Span<byte> nonce = stackalloc byte[Algorithm.NonceSize];
        DeriveNonce(contentHash, nonce);
        return Algorithm.Encrypt(Volatile.Read(ref _keys).Current, nonce, ReadOnlySpan<byte>.Empty, plaintext);
    }

    /// <summary>Decrypts one block and verifies its authentication tag, trying the ring newest first.</summary>
    /// <param name="contentHash">The hash of the expected plaintext.</param>
    /// <param name="ciphertext">The stored or received bytes.</param>
    /// <returns>The plaintext.</returns>
    /// <exception cref="CorruptBlockException">No key of the ring authenticates the block.</exception>
    /// <exception cref="ObjectDisposedException">The cipher was disposed.</exception>
    public byte[] Decrypt(ContentHash contentHash, ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (ciphertext.Length < Algorithm.TagSize)
        {
            throw new CorruptBlockException(contentHash);
        }

        Span<byte> nonce = stackalloc byte[Algorithm.NonceSize];
        DeriveNonce(contentHash, nonce);

        var keys = Volatile.Read(ref _keys);
        var plaintext = new byte[ciphertext.Length - Algorithm.TagSize];

        if (Algorithm.Decrypt(keys.Current, nonce, ReadOnlySpan<byte>.Empty, ciphertext, plaintext))
        {
            return plaintext;
        }

        foreach (var older in keys.Older)
        {
            if (Algorithm.Decrypt(older, nonce, ReadOnlySpan<byte>.Empty, ciphertext, plaintext))
            {
                return plaintext;
            }
        }

        throw new CorruptBlockException(contentHash);
    }

    /// <summary>Encrypts a snapshot's stored plaintext, always under the current key.</summary>
    /// <param name="snapshotId">The snapshot's ID, which is the hash of the plaintext.</param>
    /// <param name="plaintext">The stored form's bytes.</param>
    /// <returns>Ciphertext, <see cref="Overhead"/> bytes longer than the plaintext.</returns>
    /// <exception cref="ObjectDisposedException">The cipher was disposed.</exception>
    /// <remarks>
    /// <para>
    /// Same nonce derivation as a block, and for the same reason: a snapshot's ID is the
    /// hash of its own stored bytes' header, so identical snapshots encrypt identically and a
    /// rewrite is idempotent. Deriving a nonce from a hash of the plaintext means nonce
    /// reuse across *different* plaintexts would require a BLAKE2b-256 collision — the same
    /// assumption the content-addressed store already rests on, so it adds no new risk.
    /// </para>
    /// <para>
    /// The associated data separates the snapshot domain from the block domain. Without it,
    /// a snapshot ciphertext and a block ciphertext are interchangeable to the cipher, and a
    /// file whose bytes happened to equal a snapshot's would share both its hash and
    /// its nonce. Domain separation costs nothing and removes the whole question.
    /// </para>
    /// </remarks>
    public byte[] EncryptSnapshot(ContentHash snapshotId, ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Span<byte> nonce = stackalloc byte[Algorithm.NonceSize];
        DeriveNonce(snapshotId, nonce);
        return Algorithm.Encrypt(Volatile.Read(ref _keys).Current, nonce, SnapshotDomain, plaintext);
    }

    /// <summary>Decrypts a snapshot and verifies its authentication tag, trying the ring newest first.</summary>
    /// <param name="snapshotId">The snapshot's ID.</param>
    /// <param name="ciphertext">The stored bytes.</param>
    /// <returns>The stored form's bytes.</returns>
    /// <exception cref="CorruptBlockException">No key of the ring authenticates the snapshot.</exception>
    /// <exception cref="ObjectDisposedException">The cipher was disposed.</exception>
    public byte[] DecryptSnapshot(ContentHash snapshotId, ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (ciphertext.Length < Algorithm.TagSize)
        {
            throw new CorruptBlockException(snapshotId);
        }

        Span<byte> nonce = stackalloc byte[Algorithm.NonceSize];
        DeriveNonce(snapshotId, nonce);

        var keys = Volatile.Read(ref _keys);
        var plaintext = new byte[ciphertext.Length - Algorithm.TagSize];

        if (Algorithm.Decrypt(keys.Current, nonce, SnapshotDomain, ciphertext, plaintext))
        {
            return plaintext;
        }

        foreach (var older in keys.Older)
        {
            if (Algorithm.Decrypt(older, nonce, SnapshotDomain, ciphertext, plaintext))
            {
                return plaintext;
            }
        }

        throw new CorruptBlockException(snapshotId);
    }

    /// <summary>Associated data marking a ciphertext as a snapshot rather than a block.</summary>
    private static ReadOnlySpan<byte> SnapshotDomain => "sippbucket-snapshot-v1"u8;

    /// <summary>
    /// Fills <paramref name="nonce"/> from the content hash. The hash is 32 bytes and the
    /// nonce is 24, so the leading bytes are used.
    /// </summary>
    private static void DeriveNonce(ContentHash contentHash, Span<byte> nonce)
    {
        Span<byte> digest = stackalloc byte[ContentHash.SizeInBytes];
        contentHash.WriteTo(digest);
        digest[..nonce.Length].CopyTo(nonce);
    }

    private static Key Import(ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length != KeySize)
        {
            throw new ArgumentException(
                $"A repository key is {KeySize} bytes; got {keyMaterial.Length}.",
                nameof(keyMaterial));
        }

        return Key.Import(Algorithm, keyMaterial, KeyBlobFormat.RawSymmetricKey);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            var keys = _keys;
            keys.Current.Dispose();
            foreach (var older in keys.Older)
            {
                older.Dispose();
            }

            foreach (var retired in _retired)
            {
                retired.Dispose();
            }
        }
    }

    /// <summary>One immutable view of the ring, swapped whole so a reader never sees half a rotation.</summary>
    private sealed record KeySet(Key Current, Key[] Older);
}
