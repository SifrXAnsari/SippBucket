using SippBucket.Core.Hashing;

namespace SippBucket.Core.Protocol;

/// <summary>
/// The binary body of a <see cref="MessageType.BlockData"/> message: the one place block
/// bytes cross the wire, with no base64 and no JSON around them (D-45).
/// </summary>
/// <remarks>
/// <para>
/// Blocks used to travel as base64 inside a JSON string inside the encrypted channel, which
/// inflated every transfer by about 44%: base64's third, plus the JSON encoder writing every
/// <c>+</c> as six bytes. The channel has carried raw bodies since it was built — the send
/// overload exists precisely for this — so the body is now simply the hash and the stored
/// ciphertext.
/// </para>
/// <para>
/// <b>The layout.</b> The block's 32-byte content hash, then its ciphertext exactly as the
/// store holds it. A body of exactly 32 bytes is the answer "I do not have that block":
/// unambiguous, because a present block's ciphertext is never empty — even a zero-byte
/// plaintext carries the cipher's 16-byte tag — so a present body is at least 48 bytes.
/// Anything shorter than 32, or strictly between 32 and 48, is not a body this build writes
/// and is refused.
/// </para>
/// </remarks>
public static class BlockWire
{
    /// <summary>The shortest body a present block can have: the hash and one tag's worth of ciphertext.</summary>
    public const int MinimumPresentBody = ContentHash.SizeInBytes + 16;

    /// <summary>Encodes one answer: the hash, and the ciphertext or absence.</summary>
    /// <param name="hash">The block's content hash.</param>
    /// <param name="ciphertext">The stored ciphertext, or null for a block not held.</param>
    /// <returns>The message body.</returns>
    public static byte[] Encode(ContentHash hash, byte[]? ciphertext)
    {
        var body = new byte[ContentHash.SizeInBytes + (ciphertext?.Length ?? 0)];
        hash.WriteTo(body);
        ciphertext?.CopyTo(body.AsSpan(ContentHash.SizeInBytes));
        return body;
    }

    /// <summary>Decodes one answer.</summary>
    /// <param name="body">The message body.</param>
    /// <param name="hash">The hash the answer names.</param>
    /// <param name="ciphertext">The ciphertext, or null for "not held".</param>
    /// <returns>True when the body is a well-formed answer.</returns>
    /// <remarks>Never throws: the body is a peer's input.</remarks>
    public static bool TryDecode(ReadOnlyMemory<byte> body, out ContentHash hash, out ReadOnlyMemory<byte>? ciphertext)
    {
        hash = default;
        ciphertext = null;

        if (body.Length < ContentHash.SizeInBytes ||
            (body.Length > ContentHash.SizeInBytes && body.Length < MinimumPresentBody))
        {
            return false;
        }

        hash = new ContentHash(body.Span[..ContentHash.SizeInBytes]);

        if (body.Length > ContentHash.SizeInBytes)
        {
            ciphertext = body[ContentHash.SizeInBytes..];
        }

        return true;
    }
}
