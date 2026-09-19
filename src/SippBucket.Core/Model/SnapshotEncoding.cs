using System.Text.Json;
using SippBucket.Core.Hashing;
using SippBucket.Core.Serialization;

namespace SippBucket.Core.Model;

/// <summary>The encodings a snapshot's identity can come from (<see cref="Snapshot.Format"/>).</summary>
public static class SnapshotFormat
{
    /// <summary>
    /// The ID is the hash of the snapshot's canonical JSON: every snapshot written before the
    /// canonical format. Read for good, and never written by this build.
    /// </summary>
    public const int Legacy = 0;

    /// <summary>
    /// The ID is the hash of the canonical header, which names the root tree (D-12, D-23,
    /// docs/SNAPSHOT-FORMAT.md). Everything this build saves.
    /// </summary>
    public const int Canonical = 2;
}

/// <summary>
/// A snapshot's identity, and the canonical header that defines it (D-12,
/// docs/SNAPSHOT-FORMAT.md).
/// </summary>
/// <remarks>
/// <para>
/// A snapshot's ID was the hash of its JSON as one serializer wrote it, so a change to how that
/// serializer wrote a date, escaped a character or ordered a field would give every snapshot a
/// new ID and fork every repository. An ID is now the BLAKE2b-256 of bytes this class defines:
/// the label <see cref="Label"/>, the parent, the merge parent (32 zero bytes for none), the time
/// as UTC ticks, the message, the device ID, and the root tree (<see cref="SnapshotTree"/>),
/// which covers every file. Text and integers are as <see cref="CanonicalWriter"/> writes them.
/// </para>
/// <para>
/// Snapshots made before are <see cref="SnapshotFormat.Legacy"/>, keep their IDs, and stay
/// readable; a new snapshot may name one as its parent. The time is taken as a UTC instant,
/// so two ways of writing one moment are one snapshot.
/// </para>
/// </remarks>
internal static class SnapshotEncoding
{
    /// <summary>The label a canonical header starts with.</summary>
    public const string Label = "sippbucket-snapshot-v2";

    /// <summary>The longest message a canonical snapshot may carry, in UTF-8 bytes.</summary>
    public const int MaximumMessageBytes = 1024 * 1024;

    /// <summary>The longest device ID a canonical snapshot may carry, in UTF-8 bytes.</summary>
    public const int MaximumDeviceIdBytes = 256;

    /// <summary>The context label a snapshot signature covers, before the snapshot's ID (D-21).</summary>
    /// <remarks>
    /// D-52's standing rule: every signature made with the device key begins with its own ASCII
    /// label, so none can pass for another. What else the key signs starts differently: an SSH
    /// authentication request begins with a four-byte length whose first byte is zero, an SSH
    /// exchange hash is exactly 48 bytes, and a direct message's signed body begins with the
    /// length-prefixed <c>sippbucket-dm-v1</c>. This message begins with 's' and is exactly
    /// <see cref="SignedBytesLength"/> bytes.
    /// </remarks>
    public const string SignatureLabel = "sippbucket-snapshot-sig-v1";

    /// <summary>An Ed25519 signature's length.</summary>
    public const int SignatureSize = 64;

    /// <summary>The length of the bytes a snapshot signature covers.</summary>
    public static int SignedBytesLength => SignatureLabelBytes.Length + ContentHash.SizeInBytes;

    /// <summary>The bytes a snapshot's signature covers: the label's ASCII, then the ID's 32 bytes.</summary>
    /// <param name="snapshotId">The snapshot's ID.</param>
    /// <returns>The message to sign or verify.</returns>
    /// <remarks>
    /// The ID already covers every byte of the snapshot through its header and trees, so signing
    /// the ID signs the whole snapshot, and the signature can live beside the snapshot rather
    /// than inside the hashed bytes (D-21).
    /// </remarks>
    public static byte[] SignedBytes(ContentHash snapshotId)
    {
        var message = new byte[SignedBytesLength];
        SignatureLabelBytes.CopyTo(message.AsSpan());
        snapshotId.WriteTo(message.AsSpan(SignatureLabelBytes.Length));
        return message;
    }

    private static readonly byte[] SignatureLabelBytes = CanonicalWriter.StrictUtf8.GetBytes(SignatureLabel);

    /// <summary>The ID a snapshot is filed and known under.</summary>
    /// <param name="snapshot">The snapshot.</param>
    /// <returns>Its content hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="snapshot"/> was null.</exception>
    /// <exception cref="ArgumentException">
    /// Its format is not one this build knows; a legacy snapshot names a tree; or a canonical
    /// one cannot be encoded (see <see cref="EncodeHeader"/>).
    /// </exception>
    public static ContentHash ComputeId(Snapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        return snapshot.Format switch
        {
            SnapshotFormat.Legacy when !snapshot.Tree.IsEmpty =>
                throw new ArgumentException("A snapshot in the legacy format names a tree, which only the canonical format has.", nameof(snapshot)),
            SnapshotFormat.Legacy when snapshot.Signature is not null =>
                throw new ArgumentException("A snapshot in the legacy format carries a signature, which only the canonical format has.", nameof(snapshot)),
            SnapshotFormat.Legacy =>
                Blake2.Hash(JsonSerializer.SerializeToUtf8Bytes(snapshot, SipJson.Canonical)),
            SnapshotFormat.Canonical => Blake2.Hash(EncodeHeader(snapshot)),
            _ => throw new ArgumentException($"Snapshot format {snapshot.Format} is not one this build knows.", nameof(snapshot)),
        };
    }

    /// <summary>The canonical header of a snapshot in the canonical format.</summary>
    /// <param name="snapshot">The snapshot. Its <see cref="Snapshot.Tree"/> is used when set, and built from its files when not.</param>
    /// <returns>The bytes its ID is the hash of.</returns>
    /// <exception cref="ArgumentException">
    /// It is not in the canonical format, its text has no UTF-8 form or is too long, or its files
    /// cannot be a snapshot's (see <see cref="SnapshotTree.Build"/>).
    /// </exception>
    public static byte[] EncodeHeader(Snapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        if (snapshot.Format != SnapshotFormat.Canonical)
        {
            throw new ArgumentException("Only a snapshot in the canonical format has a header.", nameof(snapshot));
        }

        CheckLength(snapshot.Message, MaximumMessageBytes, "message");
        CheckLength(snapshot.DeviceId, MaximumDeviceIdBytes, "device ID");

        var root = snapshot.Tree.IsEmpty ? SnapshotTree.RootOf(snapshot.Files) : snapshot.Tree;

        var writer = new CanonicalWriter();
        writer.Text(Label);
        writer.Hash(snapshot.ParentId);
        writer.Hash(snapshot.MergeParentId);
        writer.Int64(snapshot.CreatedUtc.UtcTicks);
        writer.Text(snapshot.Message);
        writer.Text(snapshot.DeviceId);
        writer.Hash(root);
        return writer.ToArray();
    }

    /// <summary>
    /// The stored form of a canonical snapshot: its header, then its signature's length and
    /// bytes, or a zero length for an unsigned one.
    /// </summary>
    /// <param name="snapshot">The snapshot.</param>
    /// <returns>The bytes to store.</returns>
    /// <exception cref="ArgumentException">
    /// It cannot be encoded (<see cref="EncodeHeader"/>), or its signature is not
    /// <see cref="SignatureSize"/> bytes of hexadecimal.
    /// </exception>
    /// <remarks>
    /// The signature follows the header rather than living in it, because it signs the ID, which
    /// is the hash of the header: it cannot be inside the bytes it covers. The ID is still the
    /// hash of the header alone, so the stored form is checked against the name it was filed
    /// under by decoding it and hashing the header back.
    /// </remarks>
    public static byte[] EncodeStored(Snapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var header = EncodeHeader(snapshot);
        var signature = DecodeSignature(snapshot.Signature);

        var writer = new CanonicalWriter();
        writer.Bytes(header);
        writer.UInt32((uint)signature.Length);
        writer.Bytes(signature);
        return writer.ToArray();
    }

    /// <summary>Reads a stored canonical snapshot back: its header, and its signature when it has one.</summary>
    /// <param name="bytes">The stored form.</param>
    /// <returns>The snapshot, with <see cref="Snapshot.Files"/> empty until its trees are read.</returns>
    /// <exception cref="FormatException">The bytes are not exactly a stored canonical snapshot.</exception>
    public static Snapshot DecodeStored(ReadOnlySpan<byte> bytes)
    {
        var reader = new CanonicalReader(bytes);
        var snapshot = ReadHeader(ref reader);

        var signatureLength = reader.UInt32();
        if (signatureLength is not 0 and not SignatureSize)
        {
            throw new FormatException($"A stored snapshot's signature is {signatureLength} bytes; {SignatureSize} or none are the forms.");
        }

        string? signature = null;
        if (signatureLength == SignatureSize)
        {
#pragma warning disable CA1308 // A signature is an identifier; lowercase hex is its stored form, as device IDs are.
            signature = Convert.ToHexString(reader.Bytes(SignatureSize)).ToLowerInvariant();
#pragma warning restore CA1308
        }

        reader.End();
        return snapshot with { Signature = signature };
    }

    /// <summary>Reads a canonical header back into a snapshot that names its tree and lists no files.</summary>
    /// <param name="bytes">The header, exactly.</param>
    /// <returns>The snapshot, with <see cref="Snapshot.Files"/> empty until its trees are read.</returns>
    /// <exception cref="FormatException">The bytes are not exactly a canonical header.</exception>
    public static Snapshot DecodeHeader(ReadOnlySpan<byte> bytes)
    {
        var reader = new CanonicalReader(bytes);
        var snapshot = ReadHeader(ref reader);
        reader.End();
        return snapshot;
    }

    /// <summary>A signature's raw bytes, or an empty array for null.</summary>
    /// <param name="signature">The signature as stored on the snapshot: lowercase hexadecimal.</param>
    /// <returns>Its bytes.</returns>
    /// <exception cref="ArgumentException">It is not <see cref="SignatureSize"/> bytes of hexadecimal.</exception>
    public static byte[] DecodeSignature(string? signature)
    {
        if (signature is null)
        {
            return [];
        }

        byte[] raw;
        try
        {
            raw = Convert.FromHexString(signature);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("A snapshot's signature is not hexadecimal.", nameof(signature), ex);
        }

        return raw.Length == SignatureSize
            ? raw
            : throw new ArgumentException($"A snapshot's signature is {raw.Length} bytes; Ed25519's are {SignatureSize}.", nameof(signature));
    }

    private static Snapshot ReadHeader(ref CanonicalReader reader)
    {
        reader.Label(Label);
        var parent = reader.Hash();
        var mergeParent = reader.Hash();
        var created = reader.Int64();
        var message = reader.Text(MaximumMessageBytes);
        var deviceId = reader.Text(MaximumDeviceIdBytes);
        var root = reader.Hash();

        if (created < 0 || created > DateTimeOffset.MaxValue.UtcTicks)
        {
            throw new FormatException("A snapshot header's time is out of range.");
        }

        if (root.IsEmpty)
        {
            throw new FormatException("A snapshot header names no tree.");
        }

        return new Snapshot
        {
            Format = SnapshotFormat.Canonical,
            ParentId = parent,
            MergeParentId = mergeParent,
            CreatedUtc = new DateTimeOffset(created, TimeSpan.Zero),
            Message = message,
            DeviceId = deviceId,
            Tree = root,
            Files = [],
        };
    }

    /// <summary>Whether a stored plaintext is a canonical header rather than JSON.</summary>
    /// <param name="plaintext">The bytes.</param>
    /// <returns>True when they start with the header's label.</returns>
    public static bool IsHeader(ReadOnlySpan<byte> plaintext) =>
        plaintext.Length >= 4 + LabelBytes.Length &&
        System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(plaintext) == (uint)LabelBytes.Length &&
        plaintext.Slice(4, LabelBytes.Length).SequenceEqual(LabelBytes);

    private static readonly byte[] LabelBytes = CanonicalWriter.StrictUtf8.GetBytes(Label);

    /// <summary>
    /// Whether a snapshot's file list is the one its tree names: always, for a legacy snapshot,
    /// which has no tree.
    /// </summary>
    /// <param name="snapshot">The snapshot.</param>
    /// <returns>False for a canonical snapshot whose files make another tree, or none.</returns>
    public static bool IsConsistent(Snapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        if (snapshot.Format != SnapshotFormat.Canonical)
        {
            return snapshot.Tree.IsEmpty;
        }

        try
        {
            return !snapshot.Tree.IsEmpty && SnapshotTree.RootOf(snapshot.Files) == snapshot.Tree;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static void CheckLength(string text, int maximumBytes, string what)
    {
        ArgumentNullException.ThrowIfNull(text);

        int length;
        try
        {
            length = CanonicalWriter.StrictUtf8.GetByteCount(text);
        }
        catch (System.Text.EncoderFallbackException ex)
        {
            throw new ArgumentException($"The snapshot's {what} holds half of a surrogate pair, which has no UTF-8 form.", nameof(text), ex);
        }

        if (length > maximumBytes)
        {
            throw new ArgumentException($"The snapshot's {what} is longer than {maximumBytes} bytes.", nameof(text));
        }
    }
}
