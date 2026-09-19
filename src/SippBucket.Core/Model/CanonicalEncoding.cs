using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using SippBucket.Core.Hashing;

namespace SippBucket.Core.Model;

/// <summary>
/// Writes a canonical encoding: fields in a fixed order, integers at a fixed width in
/// big-endian order, a content hash as its 32 raw bytes, and text as strict UTF-8 preceded by
/// its length in bytes as a 4-byte big-endian integer (docs/SNAPSHOT-FORMAT.md).
/// </summary>
/// <remarks>
/// One value has one encoding, and the encoding is defined here, not by a serializer, so an
/// identity taken from it cannot move when a library does (D-12). Text that is not valid
/// Unicode, a string holding half of a surrogate pair, has no UTF-8 form and is refused rather
/// than replaced: two different strings must never write the same bytes.
/// </remarks>
internal sealed class CanonicalWriter
{
    /// <summary>UTF-8 that throws on text with no UTF-8 form, and writes no byte order mark.</summary>
    internal static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly ArrayBufferWriter<byte> _buffer = new();

    /// <summary>How many bytes have been written.</summary>
    public int Length => _buffer.WrittenCount;

    /// <summary>Writes one byte.</summary>
    /// <param name="value">The byte.</param>
    public void Byte(byte value)
    {
        _buffer.GetSpan(1)[0] = value;
        _buffer.Advance(1);
    }

    /// <summary>Writes a 32-bit integer, big-endian.</summary>
    /// <param name="value">The integer.</param>
    public void Int32(int value)
    {
        BinaryPrimitives.WriteInt32BigEndian(_buffer.GetSpan(sizeof(int)), value);
        _buffer.Advance(sizeof(int));
    }

    /// <summary>Writes an unsigned 32-bit integer, big-endian.</summary>
    /// <param name="value">The integer.</param>
    public void UInt32(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.GetSpan(sizeof(uint)), value);
        _buffer.Advance(sizeof(uint));
    }

    /// <summary>Writes a 64-bit integer, big-endian.</summary>
    /// <param name="value">The integer.</param>
    public void Int64(long value)
    {
        BinaryPrimitives.WriteInt64BigEndian(_buffer.GetSpan(sizeof(long)), value);
        _buffer.Advance(sizeof(long));
    }

    /// <summary>Writes a content hash as its 32 raw bytes; the empty hash is 32 zero bytes.</summary>
    /// <param name="hash">The hash.</param>
    public void Hash(ContentHash hash)
    {
        hash.WriteTo(_buffer.GetSpan(ContentHash.SizeInBytes));
        _buffer.Advance(ContentHash.SizeInBytes);
    }

    /// <summary>Writes raw bytes, exactly as given, with no length: the field's own rule says how many.</summary>
    /// <param name="bytes">The bytes.</param>
    public void Bytes(ReadOnlySpan<byte> bytes)
    {
        bytes.CopyTo(_buffer.GetSpan(bytes.Length));
        _buffer.Advance(bytes.Length);
    }

    /// <summary>Writes text: its UTF-8 length as a 4-byte big-endian integer, then the UTF-8.</summary>
    /// <param name="value">The text.</param>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> was null.</exception>
    /// <exception cref="ArgumentException">The text is not valid Unicode, so it has no UTF-8 form.</exception>
    public void Text(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(value);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException("The text holds half of a surrogate pair, which has no UTF-8 form.", nameof(value), ex);
        }

        UInt32((uint)bytes.Length);
        bytes.CopyTo(_buffer.GetSpan(bytes.Length));
        _buffer.Advance(bytes.Length);
    }

    /// <summary>The bytes written.</summary>
    /// <returns>A new array holding them.</returns>
    public byte[] ToArray() => _buffer.WrittenSpan.ToArray();

    /// <summary>Whether text has a UTF-8 form: it holds no half of a surrogate pair.</summary>
    /// <param name="text">The text.</param>
    /// <returns>True when <see cref="Text"/> would write it.</returns>
    public static bool IsValidUnicode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]))
            {
                if (i + 1 >= text.Length || !char.IsLowSurrogate(text[i + 1]))
                {
                    return false;
                }

                i++;
            }
            else if (char.IsLowSurrogate(text[i]))
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// Reads a canonical encoding written by <see cref="CanonicalWriter"/>, refusing anything that
/// is not exactly what the writer would have produced.
/// </summary>
/// <remarks>
/// The bytes may come from another machine, so every length is checked against what remains
/// before anything is allocated for it, and text that is not valid UTF-8 is refused rather
/// than repaired: repaired text would be a different string from the one whose bytes were
/// hashed.
/// </remarks>
internal ref struct CanonicalReader
{
    private readonly ReadOnlySpan<byte> _bytes;
    private int _position;

    /// <summary>Starts reading at the first byte.</summary>
    /// <param name="bytes">The encoding.</param>
    public CanonicalReader(ReadOnlySpan<byte> bytes)
    {
        _bytes = bytes;
        _position = 0;
    }

    /// <summary>How many bytes are left.</summary>
    public readonly int Remaining => _bytes.Length - _position;

    /// <summary>Reads one byte.</summary>
    /// <returns>The byte.</returns>
    /// <exception cref="FormatException">The encoding ended.</exception>
    public byte Byte() => Take(1)[0];

    /// <summary>Reads a 32-bit big-endian integer.</summary>
    /// <returns>The integer.</returns>
    /// <exception cref="FormatException">The encoding ended.</exception>
    public int Int32() => BinaryPrimitives.ReadInt32BigEndian(Take(sizeof(int)));

    /// <summary>Reads an unsigned 32-bit big-endian integer.</summary>
    /// <returns>The integer.</returns>
    /// <exception cref="FormatException">The encoding ended.</exception>
    public uint UInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(sizeof(uint)));

    /// <summary>Reads a 64-bit big-endian integer.</summary>
    /// <returns>The integer.</returns>
    /// <exception cref="FormatException">The encoding ended.</exception>
    public long Int64() => BinaryPrimitives.ReadInt64BigEndian(Take(sizeof(long)));

    /// <summary>Reads a content hash.</summary>
    /// <returns>The hash.</returns>
    /// <exception cref="FormatException">The encoding ended.</exception>
    public ContentHash Hash() => new(Take(ContentHash.SizeInBytes));

    /// <summary>Reads raw bytes whose count the field's own rule fixed.</summary>
    /// <param name="count">How many.</param>
    /// <returns>A new array holding them.</returns>
    /// <exception cref="FormatException">The encoding ended.</exception>
    public byte[] Bytes(int count) => Take(count).ToArray();

    /// <summary>Reads length-prefixed text.</summary>
    /// <param name="maximumBytes">The longest the text may be, in UTF-8 bytes.</param>
    /// <returns>The text.</returns>
    /// <exception cref="FormatException">The encoding ended, the text is too long, or it is not valid UTF-8.</exception>
    public string Text(int maximumBytes)
    {
        var length = UInt32();
        if (length > (uint)maximumBytes)
        {
            throw new FormatException($"A text field is {length} bytes; at most {maximumBytes} are allowed.");
        }

        var bytes = Take((int)length);
        try
        {
            return CanonicalWriter.StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException ex)
        {
            throw new FormatException("A text field is not valid UTF-8.", ex);
        }
    }

    /// <summary>Reads text and checks it is exactly <paramref name="expected"/>.</summary>
    /// <param name="expected">The label the encoding must start with.</param>
    /// <exception cref="FormatException">It is anything else.</exception>
    public void Label(string expected)
    {
        ArgumentNullException.ThrowIfNull(expected);

        var label = Text(expected.Length * 4);
        if (!string.Equals(label, expected, StringComparison.Ordinal))
        {
            throw new FormatException($"Expected '{expected}', found another label.");
        }
    }

    /// <summary>Checks that every byte has been read.</summary>
    /// <exception cref="FormatException">Bytes are left over.</exception>
    public readonly void End()
    {
        if (Remaining != 0)
        {
            throw new FormatException($"{Remaining} byte(s) follow the end of the encoding.");
        }
    }

    private ReadOnlySpan<byte> Take(int count)
    {
        if (count < 0 || count > Remaining)
        {
            throw new FormatException("The encoding ends part way through a field.");
        }

        var taken = _bytes.Slice(_position, count);
        _position += count;
        return taken;
    }
}
