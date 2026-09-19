using System.Buffers.Binary;

namespace SippBucket.Core.Hashing;

/// <summary>
/// A 256-bit content address: the BLAKE2b-256 digest of a block, a file manifest or a
/// snapshot. SippBucket is content addressed throughout, so this type is the identity of
/// every piece of data the store holds.
/// </summary>
/// <remarks>
/// Held as four 64-bit words rather than a byte array so that it stays a value type with
/// no allocation and cheap equality. Nothing in the store is ever overwritten, so two
/// equal hashes always name byte-identical content.
/// </remarks>
public readonly struct ContentHash : IEquatable<ContentHash>
{
    /// <summary>Length of a content hash in bytes.</summary>
    public const int SizeInBytes = 32;

    /// <summary>Length of the lowercase hexadecimal form of a content hash.</summary>
    public const int HexLength = SizeInBytes * 2;

    private readonly ulong _w0;
    private readonly ulong _w1;
    private readonly ulong _w2;
    private readonly ulong _w3;

    /// <summary>Creates a content hash from a 32-byte digest.</summary>
    /// <param name="digest">The digest. Must be exactly <see cref="SizeInBytes"/> bytes.</param>
    /// <exception cref="ArgumentException">The digest was not the right length.</exception>
    public ContentHash(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != SizeInBytes)
        {
            throw new ArgumentException(
                $"A content hash is {SizeInBytes} bytes; got {digest.Length}.",
                nameof(digest));
        }

        _w0 = BinaryPrimitives.ReadUInt64LittleEndian(digest);
        _w1 = BinaryPrimitives.ReadUInt64LittleEndian(digest[8..]);
        _w2 = BinaryPrimitives.ReadUInt64LittleEndian(digest[16..]);
        _w3 = BinaryPrimitives.ReadUInt64LittleEndian(digest[24..]);
    }

    /// <summary>
    /// True when this is the default, all-zero hash, which never names real content.
    /// </summary>
    public bool IsEmpty => (_w0 | _w1 | _w2 | _w3) == 0UL;

    /// <summary>Writes the raw digest into <paramref name="destination"/>.</summary>
    /// <param name="destination">A span of at least <see cref="SizeInBytes"/> bytes.</param>
    /// <exception cref="ArgumentException">The destination was too short.</exception>
    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < SizeInBytes)
        {
            throw new ArgumentException(
                $"Need {SizeInBytes} bytes to write a content hash.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt64LittleEndian(destination, _w0);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], _w1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[16..], _w2);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[24..], _w3);
    }

    /// <summary>Returns the digest as a new byte array.</summary>
    /// <returns>A fresh 32-byte array holding the digest.</returns>
    public byte[] ToByteArray()
    {
        var bytes = new byte[SizeInBytes];
        WriteTo(bytes);
        return bytes;
    }

    /// <summary>Parses a hash from its lowercase or uppercase hexadecimal form.</summary>
    /// <param name="hex">Exactly <see cref="HexLength"/> hexadecimal characters.</param>
    /// <returns>The parsed hash.</returns>
    /// <exception cref="FormatException">The text was not a valid content hash.</exception>
    public static ContentHash Parse(ReadOnlySpan<char> hex)
    {
        if (hex.Length != HexLength)
        {
            throw new FormatException(
                $"A content hash is {HexLength} hex characters; got {hex.Length}.");
        }

        Span<byte> digest = stackalloc byte[SizeInBytes];
        if (!TryDecodeHex(hex, digest))
        {
            throw new FormatException("A content hash must be hexadecimal.");
        }

        return new ContentHash(digest);
    }

    /// <summary>Tries to parse a hash from its hexadecimal form.</summary>
    /// <param name="hex">The text to parse.</param>
    /// <param name="hash">The parsed hash when this returns true.</param>
    /// <returns>True when <paramref name="hex"/> was a valid content hash.</returns>
    public static bool TryParse(ReadOnlySpan<char> hex, out ContentHash hash)
    {
        if (hex.Length != HexLength)
        {
            hash = default;
            return false;
        }

        Span<byte> digest = stackalloc byte[SizeInBytes];
        if (!TryDecodeHex(hex, digest))
        {
            hash = default;
            return false;
        }

        hash = new ContentHash(digest);
        return true;
    }

    /// <summary>
    /// Decodes hexadecimal into <paramref name="destination"/>. Written out rather than
    /// using a framework helper because the available overloads differ across targets and
    /// this has to behave identically everywhere a hash is parsed.
    /// </summary>
    private static bool TryDecodeHex(ReadOnlySpan<char> hex, Span<byte> destination)
    {
        if (hex.Length != destination.Length * 2)
        {
            return false;
        }

        for (var i = 0; i < destination.Length; i++)
        {
            var high = DecodeNibble(hex[i * 2]);
            var low = DecodeNibble(hex[(i * 2) + 1]);
            if (high < 0 || low < 0)
            {
                return false;
            }

            destination[i] = (byte)((high << 4) | low);
        }

        return true;
    }

    private static int DecodeNibble(char value) => value switch
    {
        >= '0' and <= '9' => value - '0',
        >= 'a' and <= 'f' => value - 'a' + 10,
        >= 'A' and <= 'F' => value - 'A' + 10,
        _ => -1,
    };

    /// <summary>
    /// The first <paramref name="characters"/> of the hexadecimal form, for display.
    /// </summary>
    /// <param name="characters">How many characters to keep. Clamped to the full length.</param>
    /// <returns>A shortened hexadecimal string.</returns>
    public string ToShortString(int characters = 12)
    {
        var full = ToString();
        return characters >= full.Length ? full : full[..characters];
    }

    /// <summary>Returns the lowercase hexadecimal form of the digest.</summary>
    /// <returns>A 64-character hexadecimal string.</returns>
    public override string ToString()
    {
        Span<byte> digest = stackalloc byte[SizeInBytes];
        WriteTo(digest);
#pragma warning disable CA1308 // Hashes are identifiers, not text: lowercase hex is the wire form.
        return Convert.ToHexString(digest).ToLowerInvariant();
#pragma warning restore CA1308
    }

    /// <inheritdoc />
    public bool Equals(ContentHash other) =>
        _w0 == other._w0 && _w1 == other._w1 && _w2 == other._w2 && _w3 == other._w3;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ContentHash other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(_w0, _w1, _w2, _w3);

    /// <summary>Compares two hashes for equality.</summary>
    /// <param name="left">The first hash.</param>
    /// <param name="right">The second hash.</param>
    /// <returns>True when both name the same content.</returns>
    public static bool operator ==(ContentHash left, ContentHash right) => left.Equals(right);

    /// <summary>Compares two hashes for inequality.</summary>
    /// <param name="left">The first hash.</param>
    /// <param name="right">The second hash.</param>
    /// <returns>True when the hashes differ.</returns>
    public static bool operator !=(ContentHash left, ContentHash right) => !left.Equals(right);
}
