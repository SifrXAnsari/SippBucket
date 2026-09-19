using System.Security.Cryptography;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Push;

namespace SippBucket.Core.Messages;

/// <summary>One attachment a direct message names: a Direct Push file that travelled beside it.</summary>
/// <param name="Name">The file's name, as it was pushed.</param>
/// <param name="Size">Its length in bytes.</param>
/// <param name="Hash">The BLAKE2b-256 of its content, which ties the message to the exact bytes.</param>
public sealed record DmAttachment(string Name, long Size, ContentHash Hash);

/// <summary>
/// One direct message, exactly what its signature covers: who wrote it, for which machine,
/// when, the text, and the hashes of its attachments (docs/DIRECT-MESSAGES.md).
/// </summary>
public sealed record DirectMessage
{
    /// <summary>The message's identifier: 16 random bytes, lowercase hexadecimal, chosen by the sender.</summary>
    /// <remarks>
    /// What makes a retry harmless: a copy already stored under this ID and sender is not
    /// stored twice. Random, so two messages can never collide by counting.
    /// </remarks>
    public required string MessageId { get; init; }

    /// <summary>The device that wrote and signed it.</summary>
    public required string SenderDeviceId { get; init; }

    /// <summary>The one machine this copy is for. A person's other machines get their own signed copies.</summary>
    public required string RecipientDeviceId { get; init; }

    /// <summary>When the sender wrote it, in UTC. The sender's clock's claim, shown as such.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>The text. Plain text; SippBucket never runs HTML (docs/DIRECT-MESSAGES.md).</summary>
    public required string Text { get; init; }

    /// <summary>The attachments it names, in order. They travel as Direct Push files.</summary>
    public required IReadOnlyList<DmAttachment> Attachments { get; init; }

    /// <summary>A new random message ID.</summary>
    /// <returns>16 random bytes as lowercase hexadecimal.</returns>
    public static string NewMessageId()
    {
#pragma warning disable CA1308 // The ID is an identifier, and lowercase hex is its wire form.
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(PushWire.MessageIdBytes)).ToLowerInvariant();
#pragma warning restore CA1308
    }
}

/// <summary>
/// The signed body of a direct message: the <c>sippbucket-dm-v1</c> format, byte for byte
/// (docs/DIRECT-MESSAGES.md, "Signed, with its own context label").
/// </summary>
/// <remarks>
/// <para>
/// The body is a canonical, length-prefixed encoding (<see cref="CanonicalWriter"/>): the
/// label <see cref="Label"/> as text, the sender device ID as text, the recipient device ID
/// as text, the message ID as its 16 raw bytes, the time as UTC ticks, the text as text, then
/// the attachment count and each attachment's name as text, size and 32-byte hash. The
/// Ed25519 signature covers the whole body. The label is the first field, so the signed bytes
/// begin with a four-byte length of 16 — which no SSH-signed blob begins with (a session
/// identifier is 32 or 48 bytes) and no snapshot signature's message does (those begin with
/// ASCII 's'): D-52's rule, argued in full in <see cref="DeviceIdentity"/>'s remarks.
/// </para>
/// <para>
/// The recipient is inside the signed bytes, so a message for one machine cannot be replayed
/// to another as if written for it; the time and message ID are inside, so a stored copy says
/// when it was written and a retry is the same message. What the format does not do: hide
/// anything from the two machines (the channel encrypts in transit; the stores protect at
/// rest), or prove the time true (it is the sender's clock).
/// </para>
/// </remarks>
public static class DmWire
{
    /// <summary>The label every signed body starts with, and the signature's context.</summary>
    public const string Label = "sippbucket-dm-v1";

    /// <summary>The most attachments one message may name.</summary>
    public const int MaximumAttachments = 64;

    /// <summary>The hard ceiling on a message's text, above every configurable cap: 16 MiB of UTF-8.</summary>
    public const int MaximumTextBytes = 16 * 1024 * 1024;

    /// <summary>
    /// The most bytes a body's fields other than the text can take: the label, two device IDs,
    /// the message ID, the time, the counts, and every attachment at its largest. What a
    /// receiver adds to its text cap when it judges a body length before the body moves.
    /// </summary>
    public const int MaximumEnvelopeBytes =
        (4 + 16) +
        (2 * (4 + SnapshotDeviceIdBytes)) +
        PushWire.MessageIdBytes +
        8 +
        4 +
        4 +
        (MaximumAttachments * (4 + PushWire.MaximumNameBytes + 8 + ContentHash.SizeInBytes));

    /// <summary>The longest device ID a body may carry, as a snapshot's rule has it.</summary>
    private const int SnapshotDeviceIdBytes = 256;

    /// <summary>Encodes a message's signed body.</summary>
    /// <param name="message">The message.</param>
    /// <returns>The bytes the signature covers.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="message"/> was null.</exception>
    /// <exception cref="ArgumentException">A field is outside what the format carries.</exception>
    public static byte[] EncodeBody(DirectMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(message.Attachments, nameof(message));

        if (message.Attachments.Count > MaximumAttachments)
        {
            throw new ArgumentException($"A message names at most {MaximumAttachments} attachments.", nameof(message));
        }

        var writer = new CanonicalWriter();
        writer.Text(Label);
        writer.Text(Bounded(message.SenderDeviceId, SnapshotDeviceIdBytes, "sender device ID"));
        writer.Text(Bounded(message.RecipientDeviceId, SnapshotDeviceIdBytes, "recipient device ID"));
        writer.Bytes(MessageIdBytes(message.MessageId));
        writer.Int64(message.CreatedUtc.UtcTicks);
        writer.Text(Bounded(message.Text, MaximumTextBytes, "text"));
        writer.UInt32((uint)message.Attachments.Count);

        foreach (var attachment in message.Attachments)
        {
            ArgumentNullException.ThrowIfNull(attachment, nameof(message));
            ArgumentOutOfRangeException.ThrowIfNegative(attachment.Size, nameof(message));
            writer.Text(Bounded(attachment.Name, PushWire.MaximumNameBytes, "an attachment's name"));
            writer.Int64(attachment.Size);
            writer.Hash(attachment.Hash);
        }

        return writer.ToArray();
    }

    /// <summary>Decodes a signed body, refusing anything that is not exactly the format.</summary>
    /// <param name="body">The body.</param>
    /// <param name="maximumTextBytes">
    /// The most text this machine accepts, from its own settings; never above
    /// <see cref="MaximumTextBytes"/>, which bounds it whatever the settings say.
    /// </param>
    /// <returns>The message.</returns>
    /// <exception cref="FormatException">The bytes are not a message of this format, or the text is over the cap.</exception>
    public static DirectMessage DecodeBody(ReadOnlySpan<byte> body, int maximumTextBytes)
    {
        var textCap = Math.Clamp(maximumTextBytes, 0, MaximumTextBytes);

        var reader = new CanonicalReader(body);
        reader.Label(Label);
        var sender = reader.Text(SnapshotDeviceIdBytes);
        var recipient = reader.Text(SnapshotDeviceIdBytes);
#pragma warning disable CA1308 // The ID is an identifier, and lowercase hex is its record form.
        var messageId = Convert.ToHexString(reader.Bytes(PushWire.MessageIdBytes)).ToLowerInvariant();
#pragma warning restore CA1308
        var created = reader.Int64();
        var text = reader.Text(textCap);

        if (created < 0 || created > DateTimeOffset.MaxValue.UtcTicks)
        {
            throw new FormatException("A message's time is out of range.");
        }

        var count = reader.UInt32();
        if (count > MaximumAttachments)
        {
            throw new FormatException($"A message names {count} attachments; at most {MaximumAttachments} are allowed.");
        }

        var attachments = new List<DmAttachment>((int)count);
        for (var i = 0u; i < count; i++)
        {
            var name = reader.Text(PushWire.MaximumNameBytes);
            var size = reader.Int64();
            var hash = reader.Hash();
            if (size < 0)
            {
                throw new FormatException($"A message's attachment '{name}' has a negative size.");
            }

            attachments.Add(new DmAttachment(name, size, hash));
        }

        reader.End();

        return new DirectMessage
        {
            MessageId = messageId,
            SenderDeviceId = sender,
            RecipientDeviceId = recipient,
            CreatedUtc = new DateTimeOffset(created, TimeSpan.Zero),
            Text = text,
            Attachments = attachments,
        };
    }

    /// <summary>Signs a body with this machine's device key.</summary>
    /// <param name="identity">The identity. Borrowed.</param>
    /// <param name="body">The body, from <see cref="EncodeBody"/>.</param>
    /// <returns>The signature as the wire carries it: lowercase hexadecimal.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    public static string Sign(DeviceIdentity identity, byte[] body)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(body);

#pragma warning disable CA1308 // The signature is an identifier, and lowercase hex is its wire form.
        return Convert.ToHexString(identity.Sign(body)).ToLowerInvariant();
#pragma warning restore CA1308
    }

    /// <summary>Checks a body's signature against the sender it names.</summary>
    /// <param name="senderDeviceId">The device the body claims wrote it.</param>
    /// <param name="body">The body as received.</param>
    /// <param name="signature">The signature from the offer, lowercase hexadecimal.</param>
    /// <returns>True when the signature is that device's over exactly these bytes.</returns>
    public static bool Verify(string senderDeviceId, ReadOnlySpan<byte> body, string signature)
    {
        if (string.IsNullOrWhiteSpace(senderDeviceId) || string.IsNullOrWhiteSpace(signature))
        {
            return false;
        }

        byte[] raw;
        try
        {
            raw = Convert.FromHexString(signature);
        }
        catch (FormatException)
        {
            return false;
        }

        return raw.Length == 64 && DeviceIdentity.Verify(senderDeviceId, body, raw);
    }

    private static string Bounded(string value, int maximumBytes, string what)
    {
        ArgumentNullException.ThrowIfNull(value);

        return CanonicalWriter.StrictUtf8.GetByteCount(value) <= maximumBytes
            ? value
            : throw new ArgumentException($"A message's {what} is longer than {maximumBytes} bytes of UTF-8.", nameof(value));
    }

    private static byte[] MessageIdBytes(string messageId)
    {
        ArgumentNullException.ThrowIfNull(messageId);

        byte[] raw;
        try
        {
            raw = Convert.FromHexString(messageId);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("A message ID is not hexadecimal.", nameof(messageId), ex);
        }

        return raw.Length == PushWire.MessageIdBytes
            ? raw
            : throw new ArgumentException($"A message ID is {raw.Length} bytes, and must be {PushWire.MessageIdBytes}.", nameof(messageId));
    }
}
