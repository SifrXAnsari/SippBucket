using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Serialization;

namespace SippBucket.Core.Repository;

/// <summary>
/// The on-disk form of a snapshot: encrypted under the repository key.
/// </summary>
/// <remarks>
/// <para>
/// Snapshots used to be stored as readable JSON, which meant that locking a repository hid
/// file <em>contents</em> and nothing else. The complete directory tree, every filename,
/// every size and every modification time stayed in the clear — a real snapshot file read
/// <c>"path": "Tax Returns 2025/P60-confidential.txt"</c> to anyone holding the folder. For
/// a documents tool a filename is frequently as sensitive as the document, so a lock that
/// left them readable was promising something it did not deliver.
/// </para>
/// <para>
/// Encrypting blocks without encrypting snapshots is the weaker half of a pair. Neither is
/// worth much on its own: blocks alone leak the metadata, and snapshots alone leak the
/// contents. Both are needed before the word "locked" means anything, and neither means
/// anything at all until the repository key itself stops living in plaintext beside them
/// (D-09, the Argon2 unlock).
/// </para>
/// <para>
/// A file written before this change begins with <c>{</c> and is still read. It is not read
/// <em>forever</em>: leaving the old plaintext on disk would preserve exactly the leak this
/// closes, so <see cref="SipRepository.Open"/> rewrites them on the way through.
/// </para>
/// </remarks>
public static class SnapshotFile
{
    /// <summary>Marks a file as an encrypted snapshot. Legacy files begin with <c>{</c>.</summary>
    private static ReadOnlySpan<byte> Magic => "SIPSNAP1"u8;

    /// <summary>True when these bytes are an encrypted snapshot rather than legacy JSON.</summary>
    /// <param name="stored">The file's bytes.</param>
    /// <returns>True when the magic header is present.</returns>
    public static bool IsEncrypted(ReadOnlySpan<byte> stored) =>
        stored.Length >= Magic.Length && stored[..Magic.Length].SequenceEqual(Magic);

    /// <summary>Encodes and encrypts a snapshot for the snapshot store.</summary>
    /// <param name="snapshot">The snapshot to store.</param>
    /// <param name="snapshotId">Its ID.</param>
    /// <param name="cipher">The repository's cipher.</param>
    /// <returns>The bytes to write.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <remarks>
    /// A canonical snapshot is stored as its header — the exact bytes its ID is the hash of —
    /// followed by its signature (D-21); its files are in its trees, which the block store holds
    /// (D-23). A legacy snapshot is stored as its canonical JSON, the bytes its ID is the hash
    /// of. Either way a decrypted snapshot can be checked against the name it was filed under.
    /// </remarks>
    public static byte[] Protect(Snapshot snapshot, ContentHash snapshotId, RepositoryCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(cipher);

        var plaintext = snapshot.Format == SnapshotFormat.Canonical
            ? SnapshotEncoding.EncodeStored(snapshot)
            : JsonSerializer.SerializeToUtf8Bytes(snapshot, SipJson.Canonical);
        return Seal(plaintext, snapshotId, cipher);
    }

    /// <summary>
    /// Encodes and encrypts a snapshot whole, files and all, so that it can be read again
    /// without its trees: for a copy kept outside the snapshot store.
    /// </summary>
    /// <param name="snapshot">The snapshot, its files read out of its trees when it is canonical.</param>
    /// <param name="snapshotId">Its ID.</param>
    /// <param name="cipher">The repository's cipher.</param>
    /// <returns>The bytes to write.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <remarks>
    /// The JSON is only a container here: a canonical snapshot's identity is still its header,
    /// and whoever reads it back checks its files against its tree
    /// (<see cref="SnapshotEncoding.IsConsistent"/>).
    /// </remarks>
    public static byte[] ProtectWhole(Snapshot snapshot, ContentHash snapshotId, RepositoryCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(cipher);

        return Seal(JsonSerializer.SerializeToUtf8Bytes(snapshot, SipJson.Canonical), snapshotId, cipher);
    }

    /// <summary>Reads a stored snapshot, whether encrypted or written by an older build.</summary>
    /// <param name="stored">The file's bytes.</param>
    /// <param name="snapshotId">The ID the file was filed under.</param>
    /// <param name="cipher">The repository's cipher.</param>
    /// <returns>
    /// The snapshot. A canonical one stored as its header comes back naming its tree with no
    /// files, and the caller reads them out of the trees.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="cipher"/> was null.</exception>
    /// <exception cref="CorruptBlockException">The snapshot failed authentication.</exception>
    /// <exception cref="SnapshotNotFoundException">The file was not a readable snapshot.</exception>
    public static Snapshot Unprotect(
        ReadOnlySpan<byte> stored,
        ContentHash snapshotId,
        RepositoryCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(cipher);

        var plaintext = IsEncrypted(stored)
            ? cipher.DecryptSnapshot(snapshotId, stored[Magic.Length..])
            : stored.ToArray();

        if (SnapshotEncoding.IsHeader(plaintext))
        {
            try
            {
                return SnapshotEncoding.DecodeStored(plaintext);
            }
            catch (FormatException ex)
            {
                throw new SnapshotNotFoundException(snapshotId, ex);
            }
        }

        try
        {
            return JsonSerializer.Deserialize<Snapshot>(plaintext, SipJson.Readable)
                ?? throw new SnapshotNotFoundException(snapshotId);
        }
        catch (JsonException ex)
        {
            throw new SnapshotNotFoundException(snapshotId, ex);
        }
    }

    private static byte[] Seal(byte[] plaintext, ContentHash snapshotId, RepositoryCipher cipher)
    {
        var ciphertext = cipher.EncryptSnapshot(snapshotId, plaintext);

        var file = new byte[Magic.Length + ciphertext.Length];
        Magic.CopyTo(file);
        ciphertext.CopyTo(file.AsSpan(Magic.Length));
        return file;
    }
}
