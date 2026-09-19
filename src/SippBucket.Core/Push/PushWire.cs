using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using SippBucket.Core.Hashing;
using SippBucket.Core.Protocol;

namespace SippBucket.Core.Push;

// CA1028 wants Int32 underneath these enums, and CA1008 wants FileOutcome to have a zero.
// They are wire bytes: each is one byte in a Direct Push frame, widening would put three
// dead bytes on the wire, and FileOutcome's absent zero is deliberate — a zeroed byte must
// read as invalid, never as an outcome.
#pragma warning disable CA1028, CA1008

/// <summary>Why the receiving machine refused a whole batch.</summary>
/// <remarks>Wire values: stable, and never reused.</remarks>
public enum BatchRefusal : byte
{
    /// <summary>Not refused.</summary>
    None = 0,

    /// <summary>The receiving machine does not speak the version the sender offered.</summary>
    UnsupportedVersion = 1,

    /// <summary>The batch offers more files than one batch may hold.</summary>
    TooManyFiles = 2,

    /// <summary>The receiving machine cannot take deliveries now; the detail says why.</summary>
    Unavailable = 3,
}

/// <summary>Why the receiving machine refused one file.</summary>
/// <remarks>Wire values: stable, and never reused.</remarks>
public enum FileRefusal : byte
{
    /// <summary>Not refused.</summary>
    None = 0,

    /// <summary>The name is not one that may be written as it is (<see cref="PushName"/>).</summary>
    BadName = 1,

    /// <summary>The file is larger than the receiving machine's <c>push.largestFileMiB</c>.</summary>
    TooLarge = 2,

    /// <summary>Writing it would leave the inbox's disk with less than its reserve free.</summary>
    NoSpace = 3,

    /// <summary>It would take the sender, another person, past their inbox space on this machine.</summary>
    OverPersonCap = 4,

    /// <summary>It belongs in quarantine, and the quarantine is full.</summary>
    OverQuarantineCap = 5,

    /// <summary>What arrived does not hash to what was offered.</summary>
    HashMismatch = 6,

    /// <summary>
    /// Something on the receiving machine removed the file as it arrived, before SippBucket could
    /// place it: most likely its antivirus, doing its job.
    /// </summary>
    Removed = 7,
}

/// <summary>Why the receiving machine did not take one direct message.</summary>
/// <remarks>
/// Wire values: stable, and never reused. Only reasons safe to give a sender exist here
/// (docs/DIRECT-MESSAGES.md, "What the sender sees"): blocking is never one of them, and a
/// blocked sender's connection simply never answers, which is indistinguishable from
/// unreachable.
/// </remarks>
public enum MessageRefusal : byte
{
    /// <summary>Not refused.</summary>
    None = 0,

    /// <summary>The message is larger than the receiving machine's <c>push.largestMessageKiB</c>.</summary>
    TooLarge = 1,

    /// <summary>More messages than <c>push.messagesPerMinute</c> from this sender.</summary>
    TooManyTooFast = 2,

    /// <summary>The signature did not verify, or did not match the machine that sent it.</summary>
    SignatureRejected = 3,

    /// <summary>
    /// The receiving machine is not taking messages: its team features are off, its store is
    /// unavailable, or the sender is its own person's machine. No further reason is given.
    /// </summary>
    NotAvailable = 4,
}

/// <summary>Where one delivered file ended up.</summary>
/// <remarks>Wire values: stable, and never reused.</remarks>
public enum FileOutcome : byte
{
    /// <summary>In the inbox.</summary>
    Inbox = 1,

    /// <summary>In the inbox, marked <em>type not recognised</em>.</summary>
    InboxUnrecognised = 2,

    /// <summary>In quarantine; the receipt says why.</summary>
    Quarantined = 3,

    /// <summary>Not kept; the receipt says why.</summary>
    Refused = 4,
}

#pragma warning restore CA1028, CA1008

/// <summary>One message of the delivery format.</summary>
public abstract record PushMessage;

/// <summary>The sender's opening: which version it speaks, and how many files follow.</summary>
/// <param name="Version">The format version. Only this field and the type are read from an offer of a version this build does not speak.</param>
/// <param name="BatchId">The batch's random identifier, for logs on both machines; empty for a version this build does not speak.</param>
/// <param name="FileCount">How many file offers follow; 0 for a version this build does not speak.</param>
public sealed record PushOffer(ushort Version, Guid BatchId, int FileCount) : PushMessage;

/// <summary>One file the sender offers.</summary>
/// <param name="Index">Its place in the batch, from 0, in order.</param>
/// <param name="Name">Its name, one component, as it will be judged and written.</param>
/// <param name="Size">Its length in bytes.</param>
/// <param name="Hash">The BLAKE2b-256 of its content.</param>
public sealed record PushFileOffer(int Index, string Name, long Size, ContentHash Hash) : PushMessage;

/// <summary>The receiving machine's answer to an offer.</summary>
/// <param name="Version">The version it will speak: the offer's, or when it refuses one it does not speak, its own highest.</param>
/// <param name="Refusal">Why the whole batch is refused, or <see cref="BatchRefusal.None"/>.</param>
/// <param name="Detail">A sentence for the person sending, when the batch is refused; empty otherwise.</param>
/// <param name="Files">For each file offered, in order, <see cref="FileRefusal.None"/> to send it or why not. Empty when the batch is refused.</param>
public sealed record PushAnswer(ushort Version, BatchRefusal Refusal, string Detail, IReadOnlyList<FileRefusal> Files) : PushMessage;

/// <summary>What became of one file that was sent.</summary>
/// <param name="Index">Its place in the batch.</param>
/// <param name="Outcome">Where it ended up.</param>
/// <param name="Quarantine">Why it is in quarantine, when it is; otherwise <see cref="QuarantineReason.None"/>.</param>
/// <param name="Refusal">Why it was not kept, when it was not; otherwise <see cref="FileRefusal.None"/>.</param>
/// <param name="DetectedType">What the receiving machine's content check found it to be, as the engine's type number.</param>
public sealed record PushFileReceipt(
    int Index,
    FileOutcome Outcome,
    QuarantineReason Quarantine,
    FileRefusal Refusal,
    uint DetectedType) : PushMessage;

/// <summary>The end of a batch: what became of every file offered.</summary>
/// <param name="Delivered">How many are in the inbox.</param>
/// <param name="Quarantined">How many are in quarantine.</param>
/// <param name="Refused">How many were not kept, counting those refused in the answer.</param>
public sealed record PushBatchReceipt(int Delivered, int Quarantined, int Refused) : PushMessage;

/// <summary>One direct message the sender offers (docs/DIRECT-MESSAGES.md).</summary>
/// <param name="MessageId">The message's 16-byte identifier, as lowercase hexadecimal, chosen by the sender.</param>
/// <param name="BodyLength">How many bytes of signed body follow an accepting answer.</param>
/// <param name="Signature">The Ed25519 signature over the body, 64 bytes as lowercase hexadecimal.</param>
public sealed record MessageOffer(string MessageId, int BodyLength, string Signature) : PushMessage;

/// <summary>The receiving machine's answer to a message offer, before any body moves.</summary>
/// <param name="Refusal">Why the message is refused, or <see cref="MessageRefusal.None"/> to send the body.</param>
/// <param name="Detail">A sentence for the person sending, when refused; empty otherwise.</param>
public sealed record MessageAnswer(MessageRefusal Refusal, string Detail) : PushMessage;

/// <summary>What became of one direct message that was sent.</summary>
/// <param name="MessageId">The message it answers, as offered.</param>
/// <param name="Delivered">True when the message was checked, saved, and flushed to disk.</param>
/// <param name="Refusal">Why it was not, when it was not; otherwise <see cref="MessageRefusal.None"/>.</param>
/// <param name="Detail">A sentence for the person sending, when refused; empty otherwise.</param>
public sealed record MessageReceipt(string MessageId, bool Delivered, MessageRefusal Refusal, string Detail) : PushMessage;

/// <summary>
/// The delivery format inside the SSH channel: what each message is, byte for byte.
/// </summary>
/// <remarks>
/// <para>
/// <b>The exchange.</b> The sender sends a <see cref="PushOffer"/> and then one
/// <see cref="PushFileOffer"/> for each file. The receiving machine answers once
/// (<see cref="PushAnswer"/>), deciding each file before any of it is sent, so a file that would
/// be refused for its name, its size or the space it needs costs nothing to transfer. The sender
/// then sends the content of every file the answer accepted, in order, back to back, each
/// exactly its offered size, with no framing and no round trip between files. The receiving
/// machine sends a <see cref="PushFileReceipt"/> for each file it received, as it finishes with
/// it, and a <see cref="PushBatchReceipt"/> at the end.
/// </para>
/// <para>
/// <b>Framing.</b> Every message is one frame (<see cref="Framing"/>): a four-byte big-endian
/// length, then the message, at most <see cref="MaximumFrame"/> bytes. A message begins with its
/// type, one byte. Every integer is big-endian, as SSH's are. A string is a two-byte length and
/// that many bytes of UTF-8, which must be valid. A message is exactly as long as its fields: a
/// byte short or a byte over is malformed, and so is any value outside its range.
/// </para>
/// <list type="table">
/// <listheader><term>Message</term><description>Fields after the type byte</description></listheader>
/// <item><term><c>0x01</c> offer</term><description>version (2); then, in version 1: batch ID (16,
/// a GUID in big-endian order), file count (4, at least 1)</description></item>
/// <item><term><c>0x02</c> file offer</term><description>index (4), name (string, at most
/// <see cref="MaximumNameBytes"/> bytes), size (8), BLAKE2b-256 of the content (32)</description></item>
/// <item><term><c>0x81</c> answer</term><description>version (2), batch refusal (1), detail (string,
/// at most <see cref="MaximumDetailBytes"/> bytes), file count (4), then one file refusal (1) per
/// file</description></item>
/// <item><term><c>0x82</c> file receipt</term><description>index (4), outcome (1), reason (1: the
/// quarantine reason or the file refusal, else 0), detected type (4)</description></item>
/// <item><term><c>0x83</c> batch receipt</term><description>delivered (4), quarantined (4),
/// refused (4)</description></item>
/// <item><term><c>0x03</c> message offer</term><description>message ID (16), body length (4,
/// 1 to <see cref="MaximumMessageBody"/>), signature (64). An accepting answer is followed by
/// exactly that many bytes of signed body, raw, with no framing</description></item>
/// <item><term><c>0x85</c> message answer</term><description>refusal (1), detail (string, at
/// most <see cref="MaximumDetailBytes"/> bytes)</description></item>
/// <item><term><c>0x84</c> message receipt</term><description>message ID (16), delivered (1:
/// 0 or 1), refusal (1), detail (string). Delivered means checked, saved and flushed; a
/// receipt may not both deliver and refuse</description></item>
/// </list>
/// <para>
/// <b>Versions.</b> The offer's type and version come first in every version, for ever, so a
/// receiving machine can always read what it was offered and answer: an answer refusing with
/// <see cref="BatchRefusal.UnsupportedVersion"/> carries the highest version it speaks. Every
/// other layout belongs to its version.
/// </para>
/// <para>
/// The format is pinned by golden-bytes tests. A change to a layout is a new version.
/// </para>
/// </remarks>
public static class PushWire
{
    /// <summary>The version of the format this build speaks.</summary>
    public const ushort Version = 1;

    /// <summary>The most files one batch may hold; a larger selection goes as several batches.</summary>
    /// <remarks>
    /// Keeps the answer, one byte per file, in one small frame, and a batch's receipts well inside
    /// the sender's window. A hard limit of the format, not a setting.
    /// </remarks>
    public const int MaximumFiles = 4096;

    /// <summary>The longest name, in UTF-8 bytes: 255 characters of up to four bytes each.</summary>
    public const int MaximumNameBytes = PushName.MaximumLength * 4;

    /// <summary>The longest detail sentence in an answer, in UTF-8 bytes.</summary>
    public const int MaximumDetailBytes = 1024;

    /// <summary>The largest frame either side sends or accepts.</summary>
    public const int MaximumFrame = 16 * 1024;

    /// <summary>A direct message's 16-byte identifier, as lowercase hexadecimal.</summary>
    public const int MessageIdBytes = 16;

    /// <summary>An Ed25519 signature's length in bytes.</summary>
    private const int Ed25519SignatureBytes = 64;

    /// <summary>
    /// The largest signed message body the format carries: the hard ceiling of
    /// <c>push.largestMessageKiB</c> plus the body's own envelope
    /// (<see cref="Messages.DmWire.MaximumEnvelopeBytes"/>). A hard limit of the format, above
    /// every configurable one, so no setting can make a message unbounded.
    /// </summary>
    public const int MaximumMessageBody = (16 * 1024 * 1024) + Messages.DmWire.MaximumEnvelopeBytes;

    private const byte OfferType = 0x01;
    private const byte FileOfferType = 0x02;
    private const byte MessageOfferType = 0x03;
    private const byte AnswerType = 0x81;
    private const byte FileReceiptType = 0x82;
    private const byte BatchReceiptType = 0x83;
    private const byte MessageReceiptType = 0x84;
    private const byte MessageAnswerType = 0x85;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Encodes a message, without its frame.</summary>
    /// <param name="message">The message.</param>
    /// <returns>Its bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="message"/> was null.</exception>
    /// <exception cref="ArgumentException">A field is outside what the format can carry.</exception>
    public static byte[] Encode(PushMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        var writer = new Writer();
        switch (message)
        {
            case PushOffer offer:
                RequireVersionOne(offer.Version);
                RequireCount(offer.FileCount, 1, int.MaxValue, "an offer's file count");
                writer.Byte(OfferType);
                writer.UInt16(offer.Version);
                writer.Guid(offer.BatchId);
                writer.UInt32(checked((uint)offer.FileCount));
                break;

            case PushFileOffer file:
                RequireCount(file.Index, 0, int.MaxValue, "a file's index");
                ArgumentOutOfRangeException.ThrowIfNegative(file.Size, nameof(message));
                writer.Byte(FileOfferType);
                writer.UInt32(checked((uint)file.Index));
                writer.String(file.Name, MaximumNameBytes, "a file's name");
                writer.UInt64(checked((ulong)file.Size));
                writer.Hash(file.Hash);
                break;

            case PushAnswer answer:
                ArgumentNullException.ThrowIfNull(answer.Detail, nameof(message));
                ArgumentNullException.ThrowIfNull(answer.Files, nameof(message));
                RequireDefined(answer.Refusal);
                RequireCount(answer.Files.Count, 0, MaximumFiles, "an answer's file count");
                if (answer.Refusal != BatchRefusal.None && answer.Files.Count != 0)
                {
                    throw new ArgumentException("An answer that refuses the batch decides no files.", nameof(message));
                }

                writer.Byte(AnswerType);
                writer.UInt16(answer.Version);
                writer.Byte((byte)answer.Refusal);
                writer.String(answer.Detail, MaximumDetailBytes, "an answer's detail");
                writer.UInt32(checked((uint)answer.Files.Count));
                foreach (var refusal in answer.Files)
                {
                    RequireDefined(refusal);
                    writer.Byte((byte)refusal);
                }

                break;

            case PushFileReceipt receipt:
                RequireCount(receipt.Index, 0, int.MaxValue, "a receipt's index");
                writer.Byte(FileReceiptType);
                writer.UInt32(checked((uint)receipt.Index));
                writer.Byte((byte)receipt.Outcome);
                writer.Byte(ReasonOf(receipt));
                writer.UInt32(receipt.DetectedType);
                break;

            case PushBatchReceipt batch:
                RequireCount(batch.Delivered, 0, MaximumFiles, "a batch receipt's delivered count");
                RequireCount(batch.Quarantined, 0, MaximumFiles, "a batch receipt's quarantined count");
                RequireCount(batch.Refused, 0, MaximumFiles, "a batch receipt's refused count");
                RequireCount(batch.Delivered + batch.Quarantined + batch.Refused, 1, MaximumFiles, "a batch receipt's files");
                writer.Byte(BatchReceiptType);
                writer.UInt32(checked((uint)batch.Delivered));
                writer.UInt32(checked((uint)batch.Quarantined));
                writer.UInt32(checked((uint)batch.Refused));
                break;

            case MessageOffer offer:
                RequireCount(offer.BodyLength, 1, MaximumMessageBody, "a message's body length");
                writer.Byte(MessageOfferType);
                writer.RawHex(offer.MessageId, MessageIdBytes, "a message ID");
                writer.UInt32(checked((uint)offer.BodyLength));
                writer.RawHex(offer.Signature, Ed25519SignatureBytes, "a message signature");
                break;

            case MessageAnswer answer:
                ArgumentNullException.ThrowIfNull(answer.Detail, nameof(message));
                RequireDefined(answer.Refusal);
                writer.Byte(MessageAnswerType);
                writer.Byte((byte)answer.Refusal);
                writer.String(answer.Detail, MaximumDetailBytes, "a message answer's detail");
                break;

            case MessageReceipt receipt:
                ArgumentNullException.ThrowIfNull(receipt.Detail, nameof(message));
                RequireDefined(receipt.Refusal);
                if (receipt.Delivered != (receipt.Refusal == MessageRefusal.None))
                {
                    throw new ArgumentException("A message receipt delivers or refuses, never both and never neither.", nameof(message));
                }

                writer.Byte(MessageReceiptType);
                writer.RawHex(receipt.MessageId, MessageIdBytes, "a message ID");
                writer.Byte(receipt.Delivered ? (byte)1 : (byte)0);
                writer.Byte((byte)receipt.Refusal);
                writer.String(receipt.Detail, MaximumDetailBytes, "a message receipt's detail");
                break;

            default:
                throw new ArgumentException($"{message.GetType().Name} is not a message of the delivery format.", nameof(message));
        }

        return writer.ToArray();
    }

    /// <summary>Decodes one message, without its frame.</summary>
    /// <param name="message">The message's bytes, exactly.</param>
    /// <returns>The message.</returns>
    /// <exception cref="PushException">
    /// The bytes are not a message of this version (<see cref="PushFault.MalformedMessage"/>).
    /// </exception>
    public static PushMessage Decode(ReadOnlySpan<byte> message)
    {
        var reader = new Reader(message);

        PushMessage decoded = reader.Byte() switch
        {
            OfferType => ReadOffer(ref reader),
            FileOfferType => ReadFileOffer(ref reader),
            MessageOfferType => ReadMessageOffer(ref reader),
            AnswerType => ReadAnswer(ref reader),
            FileReceiptType => ReadFileReceipt(ref reader),
            BatchReceiptType => ReadBatchReceipt(ref reader),
            MessageReceiptType => ReadMessageReceipt(ref reader),
            MessageAnswerType => ReadMessageAnswer(ref reader),
            var type => throw Malformed(string.Create(CultureInfo.InvariantCulture, $"0x{type:x2} is not a message type")),
        };

        reader.End();
        return decoded;
    }

    /// <summary>Writes one message, framed, under the stall deadline.</summary>
    /// <param name="stream">The channel.</param>
    /// <param name="message">The message.</param>
    /// <param name="stallTimeout">How long the write may make no progress.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes when the message has been written.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="PeerStalledException">The other side stopped taking data.</exception>
    public static Task WriteAsync(Stream stream, PushMessage message, TimeSpan stallTimeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return Framing.WriteFrameAsync(stream, Encode(message), stallTimeout, cancellationToken);
    }

    /// <summary>Reads one message, framed, under the stall deadline.</summary>
    /// <param name="stream">The channel.</param>
    /// <param name="stallTimeout">How long the read may make no progress.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The message, or null when the other side ended the channel between messages.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> was null.</exception>
    /// <exception cref="PushException">
    /// The frame was larger than <see cref="MaximumFrame"/>, cut short, or not a message
    /// (<see cref="PushFault.MalformedMessage"/>).
    /// </exception>
    /// <exception cref="PeerStalledException">The other side stopped sending.</exception>
    public static async Task<PushMessage?> ReadAsync(Stream stream, TimeSpan stallTimeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[]? frame;
        try
        {
            frame = await Framing.ReadFrameAsync(stream, MaximumFrame, stallTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (SipProtocolException ex)
        {
            throw new PushException(PushFault.MalformedMessage, $"A delivery frame could not be read: {ex.Message}", ex);
        }

        return frame is null ? null : Decode(frame);
    }

    private static PushOffer ReadOffer(ref Reader reader)
    {
        var version = reader.UInt16();
        if (version != Version)
        {
            // What follows belongs to a version this build does not speak, so it is not read:
            // the version alone is enough to answer.
            reader.Skip();
            return new PushOffer(version, Guid.Empty, 0);
        }

        var batchId = reader.Guid();
        var count = reader.Count("an offer's file count", 1, int.MaxValue);
        return new PushOffer(version, batchId, count);
    }

    private static PushFileOffer ReadFileOffer(ref Reader reader)
    {
        var index = reader.Count("a file's index", 0, int.MaxValue);
        var name = reader.String(MaximumNameBytes, "a file's name");
        var size = reader.UInt64();
        if (size > long.MaxValue)
        {
            throw Malformed("a file's size is beyond what any disk holds");
        }

        var hash = reader.Hash();
        return new PushFileOffer(index, name, (long)size, hash);
    }

    private static PushAnswer ReadAnswer(ref Reader reader)
    {
        var version = reader.UInt16();
        var refusal = reader.Defined<BatchRefusal>("a batch refusal");
        var detail = reader.String(MaximumDetailBytes, "an answer's detail");
        var count = reader.Count("an answer's file count", 0, MaximumFiles);

        if (refusal != BatchRefusal.None && count != 0)
        {
            throw Malformed("an answer that refuses the batch decides files");
        }

        var files = new FileRefusal[count];
        for (var i = 0; i < count; i++)
        {
            files[i] = reader.Defined<FileRefusal>("a file refusal");
        }

        return new PushAnswer(version, refusal, detail, files);
    }

    private static PushFileReceipt ReadFileReceipt(ref Reader reader)
    {
        var index = reader.Count("a receipt's index", 0, int.MaxValue);
        var outcome = reader.Defined<FileOutcome>("an outcome");
        var reason = reader.Byte();
        var detected = reader.UInt32();

        return outcome switch
        {
            FileOutcome.Quarantined when reason != 0 && Enum.IsDefined((QuarantineReason)reason) =>
                new PushFileReceipt(index, outcome, (QuarantineReason)reason, FileRefusal.None, detected),
            FileOutcome.Refused when reason != 0 && Enum.IsDefined((FileRefusal)reason) =>
                new PushFileReceipt(index, outcome, QuarantineReason.None, (FileRefusal)reason, detected),
            FileOutcome.Inbox or FileOutcome.InboxUnrecognised when reason == 0 =>
                new PushFileReceipt(index, outcome, QuarantineReason.None, FileRefusal.None, detected),
            _ => throw Malformed(string.Create(CultureInfo.InvariantCulture, $"a receipt's reason {reason} does not fit its outcome, {outcome}")),
        };
    }

    private static PushBatchReceipt ReadBatchReceipt(ref Reader reader)
    {
        var delivered = reader.Count("a batch receipt's delivered count", 0, MaximumFiles);
        var quarantined = reader.Count("a batch receipt's quarantined count", 0, MaximumFiles);
        var refused = reader.Count("a batch receipt's refused count", 0, MaximumFiles);

        var total = delivered + quarantined + refused;
        if (total is < 1 or > MaximumFiles)
        {
            throw Malformed(string.Create(CultureInfo.InvariantCulture, $"a batch receipt accounts for {total} files"));
        }

        return new PushBatchReceipt(delivered, quarantined, refused);
    }

    private static MessageOffer ReadMessageOffer(ref Reader reader)
    {
        var messageId = reader.RawHex(MessageIdBytes);
        var bodyLength = reader.Count("a message's body length", 1, MaximumMessageBody);
        var signature = reader.RawHex(Ed25519SignatureBytes);
        return new MessageOffer(messageId, bodyLength, signature);
    }

    private static MessageAnswer ReadMessageAnswer(ref Reader reader)
    {
        var refusal = reader.Defined<MessageRefusal>("a message refusal");
        var detail = reader.String(MaximumDetailBytes, "a message answer's detail");
        return new MessageAnswer(refusal, detail);
    }

    private static MessageReceipt ReadMessageReceipt(ref Reader reader)
    {
        var messageId = reader.RawHex(MessageIdBytes);
        var delivered = reader.Byte() switch
        {
            0 => false,
            1 => true,
            var value => throw Malformed(string.Create(CultureInfo.InvariantCulture, $"{value} is not a delivered flag")),
        };
        var refusal = reader.Defined<MessageRefusal>("a message refusal");
        var detail = reader.String(MaximumDetailBytes, "a message receipt's detail");

        if (delivered != (refusal == MessageRefusal.None))
        {
            throw Malformed("a message receipt delivers or refuses, never both and never neither");
        }

        return new MessageReceipt(messageId, delivered, refusal, detail);
    }

    private static byte ReasonOf(PushFileReceipt receipt) => receipt.Outcome switch
    {
        FileOutcome.Quarantined when receipt.Quarantine != QuarantineReason.None && receipt.Refusal == FileRefusal.None &&
                                     Enum.IsDefined(receipt.Quarantine) => (byte)receipt.Quarantine,
        FileOutcome.Refused when receipt.Refusal != FileRefusal.None && receipt.Quarantine == QuarantineReason.None &&
                                 Enum.IsDefined(receipt.Refusal) => (byte)receipt.Refusal,
        FileOutcome.Inbox or FileOutcome.InboxUnrecognised when receipt.Quarantine == QuarantineReason.None &&
                                                                 receipt.Refusal == FileRefusal.None => 0,
        _ => throw new ArgumentException(
            $"A receipt with outcome {receipt.Outcome} cannot carry quarantine reason {receipt.Quarantine} and refusal {receipt.Refusal}.",
            nameof(receipt)),
    };

    private static void RequireVersionOne(ushort version)
    {
        if (version != Version)
        {
            throw new ArgumentOutOfRangeException(
                nameof(version), version, $"This build writes version {Version} of the delivery format only.");
        }
    }

    private static void RequireCount(int value, int minimum, int maximum, string what)
    {
        if (value < minimum || value > maximum)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value), value, $"{what} must be between {minimum} and {maximum}.");
        }
    }

    private static void RequireDefined<T>(T value)
        where T : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, $"{value} is not a {typeof(T).Name}.");
        }
    }

    private static PushException Malformed(string what) =>
        new(PushFault.MalformedMessage, $"A delivery message is malformed: {what}.");

    /// <summary>Appends big-endian fields to a growing buffer.</summary>
    private sealed class Writer
    {
        private readonly ArrayBufferWriter<byte> _buffer = new();

        public void Byte(byte value)
        {
            _buffer.GetSpan(1)[0] = value;
            _buffer.Advance(1);
        }

        public void UInt16(ushort value)
        {
            BinaryPrimitives.WriteUInt16BigEndian(_buffer.GetSpan(2), value);
            _buffer.Advance(2);
        }

        public void UInt32(uint value)
        {
            BinaryPrimitives.WriteUInt32BigEndian(_buffer.GetSpan(4), value);
            _buffer.Advance(4);
        }

        public void UInt64(ulong value)
        {
            BinaryPrimitives.WriteUInt64BigEndian(_buffer.GetSpan(8), value);
            _buffer.Advance(8);
        }

        public void Guid(Guid value)
        {
            if (!value.TryWriteBytes(_buffer.GetSpan(16), bigEndian: true, out var written) || written != 16)
            {
                throw new InvalidOperationException("A GUID did not write as 16 bytes.");
            }

            _buffer.Advance(16);
        }

        public void Hash(ContentHash value)
        {
            value.WriteTo(_buffer.GetSpan(ContentHash.SizeInBytes));
            _buffer.Advance(ContentHash.SizeInBytes);
        }

        public void String(string value, int limit, string what)
        {
            ArgumentNullException.ThrowIfNull(value);

            var bytes = StrictUtf8.GetBytes(value);
            if (bytes.Length > limit)
            {
                throw new ArgumentException($"{what} is {bytes.Length} bytes of UTF-8, and the limit is {limit}.", nameof(value));
            }

            UInt16(checked((ushort)bytes.Length));
            bytes.CopyTo(_buffer.GetSpan(bytes.Length));
            _buffer.Advance(bytes.Length);
        }

        /// <summary>Writes a fixed-length field held in memory as lowercase hexadecimal, as its raw bytes.</summary>
        public void RawHex(string hex, int rawBytes, string what)
        {
            ArgumentNullException.ThrowIfNull(hex);

            byte[] raw;
            try
            {
                raw = Convert.FromHexString(hex);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException($"{what} is not hexadecimal.", nameof(hex), ex);
            }

            if (raw.Length != rawBytes)
            {
                throw new ArgumentException($"{what} is {raw.Length} bytes, and must be {rawBytes}.", nameof(hex));
            }

            raw.CopyTo(_buffer.GetSpan(rawBytes));
            _buffer.Advance(rawBytes);
        }

        public byte[] ToArray() => _buffer.WrittenSpan.ToArray();
    }

    /// <summary>Reads big-endian fields from one message, refusing to read past its end.</summary>
    private ref struct Reader
    {
        private ReadOnlySpan<byte> _rest;

        public Reader(ReadOnlySpan<byte> message)
        {
            _rest = message;
        }

        public byte Byte() => Take(1)[0];

        public ushort UInt16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));

        public uint UInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

        public ulong UInt64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));

        public Guid Guid() => new(Take(16), bigEndian: true);

        public ContentHash Hash() => new(Take(ContentHash.SizeInBytes));

        public int Count(string what, int minimum, int maximum)
        {
            var value = UInt32();
            if (value < (uint)minimum || value > (uint)maximum)
            {
                throw Malformed(string.Create(CultureInfo.InvariantCulture, $"{what} is {value}, outside {minimum} to {maximum}"));
            }

            return (int)value;
        }

        public T Defined<T>(string what)
            where T : struct, Enum
        {
            var raw = Byte();
            var value = (T)Enum.ToObject(typeof(T), raw);
            if (!Enum.IsDefined(value))
            {
                throw Malformed(string.Create(CultureInfo.InvariantCulture, $"{raw} is not {what}"));
            }

            return value;
        }

        public string String(int limit, string what)
        {
            var length = UInt16();
            if (length > limit)
            {
                throw Malformed(string.Create(CultureInfo.InvariantCulture, $"{what} is {length} bytes, and the limit is {limit}"));
            }

            var bytes = Take(length);
            try
            {
                return StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException ex)
            {
                throw new PushException(PushFault.MalformedMessage, $"A delivery message is malformed: {what} is not valid UTF-8.", ex);
            }
        }

        /// <summary>Reads a fixed-length field into the lowercase hexadecimal its record holds.</summary>
        public string RawHex(int rawBytes)
        {
#pragma warning disable CA1308 // The field is an identifier, and lowercase hex is its record form.
            return Convert.ToHexString(Take(rawBytes)).ToLowerInvariant();
#pragma warning restore CA1308
        }

        /// <summary>Passes over the rest of the message: for an offer of a version this build does not speak.</summary>
        public void Skip() => _rest = [];

        /// <summary>Checks nothing is left over.</summary>
        public readonly void End()
        {
            if (!_rest.IsEmpty)
            {
                throw Malformed(string.Create(CultureInfo.InvariantCulture, $"{_rest.Length} bytes follow its last field"));
            }
        }

        private ReadOnlySpan<byte> Take(int count)
        {
            if (_rest.Length < count)
            {
                throw Malformed("it ends part way through a field");
            }

            var taken = _rest[..count];
            _rest = _rest[count..];
            return taken;
        }
    }
}
