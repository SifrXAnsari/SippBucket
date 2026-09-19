using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Protocol.Noise;

namespace SippBucket.Core.Protocol;

/// <summary>
/// The byte layouts <see cref="SecureChannel"/> puts on the wire around and inside Noise:
/// the version preamble, the three handshake payloads, and the transport chunking.
/// </summary>
/// <remarks>
/// <para>
/// Kept apart from <see cref="SecureChannel"/> so the tests can build a hostile or outdated
/// peer from the same definitions the shipping code uses, rather than from a copy that could
/// drift from it.
/// </para>
/// <para>
/// Every handshake payload starts with a format byte, which is what lets a payload grow
/// without guessing at what an older peer meant. One listener serves every folder on a
/// machine by routing on the repository ID in the first payload (D-40,
/// <see cref="Sync.PeerHost"/>); that needed no change here, because the ID was already there.
/// </para>
/// </remarks>
internal static class ChannelWire
{
    /// <summary>The protocol version this build speaks. Version 1 was the hand-rolled handshake.</summary>
    /// <remarks>
    /// Version 2 is also the version in which file entries can carry <c>FileEntry.Chunker</c>
    /// (D-22). A version 1 build would ignore that field when it read a snapshot, hash what it
    /// received to a different ID than the one it asked for, and then report the snapshot
    /// missing. Version 2 also added the ancestry messages and snapshots with a second parent
    /// (D-39, D-27): a version 1 peer would answer an ancestry request with an error, and
    /// would file a merge snapshot under the hash of the fields it knows. Refusing the
    /// connection by version says what is actually wrong, and one bump covers all three
    /// changes because they ship together.
    /// <para>
    /// Version 3 is snapshots in the canonical format (D-12, D-23): one travels as its header,
    /// naming its root tree and listing no files, and its trees travel as blocks. A version 2
    /// build would read such a header as a snapshot with no files at all, and a pull would
    /// delete every file the peer had not changed. Refusing the connection by version is what
    /// stops that.
    /// </para>
    /// </remarks>
    public const ushort ProtocolVersion = 3;

    /// <summary>Four bytes of magic and a 16-bit big-endian version.</summary>
    public const int PreambleLength = 6;

    /// <summary>The largest transport frame: one Noise message (Noise section 3).</summary>
    public const int TransportFrameSize = HandshakeState.MaximumMessageLength;

    /// <summary>The plaintext one transport frame can carry once its tag is taken off.</summary>
    public const int TransportPlaintextCapacity = TransportFrameSize - CipherState.TagLength;

    /// <summary>The length that opens the first chunk of every application message.</summary>
    public const int MessageLengthSize = 4;

    /// <summary>The longest repository ID the first handshake payload can carry, in UTF-8 bytes.</summary>
    public const int MaximumRepositoryIdLength = byte.MaxValue;

    private const byte PayloadFormat = 1;
    private const byte AnswerAccepted = 0;
    private const byte AnswerUnknownRepository = 1;
    private const int Ed25519PublicKeySize = 32;

    /// <summary>
    /// The only layout that must never change between versions: a peer on any version has to
    /// be able to read another's preamble well enough to say which version it speaks.
    /// </summary>
    private static ReadOnlySpan<byte> Magic => "SIPB"u8;

    /// <summary>
    /// What a protocol 1 build expects as the answer to its JSON hello, carrying this
    /// build's version.
    /// </summary>
    /// <remarks>
    /// A protocol 1 build deserialises the reply to its hello as a <c>HelloMessage</c> and
    /// checks the version before anything else, so this is enough for it to raise its own
    /// <c>UnsupportedVersion</c> with "The peer speaks protocol version 3; this build speaks
    /// 1." Every field that build marks <c>required</c> is present, because a missing one
    /// would make it report a malformed message instead of the version, which is the unclear
    /// failure this exists to avoid. Nothing identifying is sent: every string is empty. The
    /// literal must carry <see cref="ProtocolVersion"/>; it said 2 after the version moved to
    /// 3, and the old build would have named a version that was already behind.
    /// </remarks>
    public static ReadOnlySpan<byte> LegacyRefusal =>
        """{"protocolVersion":3,"deviceId":"","ephemeralPublicKey":"","repositoryId":"","signature":""}"""u8;

    /// <summary>Builds a preamble naming <paramref name="version"/>.</summary>
    /// <param name="version">The version to name.</param>
    /// <returns>The six preamble bytes.</returns>
    public static byte[] Preamble(ushort version)
    {
        var preamble = new byte[PreambleLength];
        Magic.CopyTo(preamble);
        BinaryPrimitives.WriteUInt16BigEndian(preamble.AsSpan(Magic.Length), version);
        return preamble;
    }

    /// <summary>Reads a preamble.</summary>
    /// <param name="frame">A received frame.</param>
    /// <param name="version">The version it names, when this returns true.</param>
    /// <returns>True when the frame is exactly a preamble.</returns>
    public static bool TryReadPreamble(ReadOnlySpan<byte> frame, out ushort version)
    {
        version = 0;
        if (frame.Length != PreambleLength || !frame.StartsWith(Magic))
        {
            return false;
        }

        version = BinaryPrimitives.ReadUInt16BigEndian(frame[Magic.Length..]);
        return true;
    }

    /// <summary>
    /// The Noise prologue: both preambles, the initiator's first.
    /// </summary>
    /// <param name="initiatorPreamble">What the initiator sent.</param>
    /// <param name="responderPreamble">What the responder answered.</param>
    /// <returns>The prologue bytes.</returns>
    /// <remarks>
    /// Noise section 6: "If both parties do not provide identical prologue data, the handshake
    /// will fail due to a decryption error." The preambles are the one part of the exchange
    /// that travels in plaintext before any key exists, so this is what makes altering them,
    /// to force a downgrade or anything else, break the handshake. The magic also separates
    /// this use of the device key from any future Noise protocol, which must choose a
    /// different prologue.
    /// </remarks>
    public static byte[] Prologue(ReadOnlySpan<byte> initiatorPreamble, ReadOnlySpan<byte> responderPreamble)
    {
        var prologue = new byte[initiatorPreamble.Length + responderPreamble.Length];
        initiatorPreamble.CopyTo(prologue);
        responderPreamble.CopyTo(prologue.AsSpan(initiatorPreamble.Length));
        return prologue;
    }

    /// <summary>Recognises the JSON hello a protocol 1 build opens with.</summary>
    /// <param name="frame">The first frame a caller sent.</param>
    /// <param name="version">The version the hello names, when this returns true.</param>
    /// <returns>True when the frame is a JSON object with a numeric <c>protocolVersion</c>.</returns>
    /// <remarks>
    /// The frame is bounded by <see cref="Framing.HandshakeFrameSize"/> before it gets here,
    /// so parsing it costs an unauthenticated caller at most 8 KiB of JSON.
    /// </remarks>
    public static bool TryReadLegacyHello(ReadOnlyMemory<byte> frame, out long version)
    {
        version = 0;
        if (frame.IsEmpty || frame.Span[0] != (byte)'{')
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(frame);
            return document.RootElement.ValueKind == JsonValueKind.Object
                   && document.RootElement.TryGetProperty("protocolVersion", out var property)
                   && property.ValueKind == JsonValueKind.Number
                   && property.TryGetInt64(out version);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>The first handshake payload: which repository the initiator wants.</summary>
    /// <param name="repositoryId">The repository ID.</param>
    /// <returns><c>[format 1][length][UTF-8 repository ID]</c>.</returns>
    public static byte[] EncodeRequest(string repositoryId)
    {
        ArgumentException.ThrowIfNullOrEmpty(repositoryId);

        var utf8 = Encoding.UTF8.GetBytes(repositoryId);
        if (utf8.Length > MaximumRepositoryIdLength)
        {
            throw new ArgumentException(
                $"A repository ID is at most {MaximumRepositoryIdLength} bytes of UTF-8.", nameof(repositoryId));
        }

        var payload = new byte[2 + utf8.Length];
        payload[0] = PayloadFormat;
        payload[1] = (byte)utf8.Length;
        utf8.CopyTo(payload, 2);
        return payload;
    }

    /// <summary>Reads the first handshake payload.</summary>
    /// <param name="payload">The decrypted payload.</param>
    /// <returns>The repository ID.</returns>
    /// <exception cref="SipProtocolException">The payload is not in format 1.</exception>
    public static string ReadRequest(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 3 || payload[0] != PayloadFormat || payload.Length != 2 + payload[1])
        {
            throw Malformed("The caller's repository request is not in a format this build reads.");
        }

        try
        {
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(payload[2..]);
        }
        catch (DecoderFallbackException ex)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage, "The caller's repository ID is not valid UTF-8.", ex);
        }
    }

    /// <summary>The second handshake payload: the responder's answer to the request.</summary>
    /// <param name="accepted">False when the responder does not serve the repository.</param>
    /// <returns><c>[format 1][status]</c>.</returns>
    public static byte[] EncodeAnswer(bool accepted) =>
        [PayloadFormat, accepted ? AnswerAccepted : AnswerUnknownRepository];

    /// <summary>Reads the second handshake payload.</summary>
    /// <param name="payload">The decrypted payload.</param>
    /// <returns>True when the responder accepted the request.</returns>
    /// <exception cref="SipProtocolException">The payload is not in format 1.</exception>
    public static bool ReadAnswer(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 2 || payload[0] != PayloadFormat || payload[1] is not (AnswerAccepted or AnswerUnknownRepository))
        {
            throw Malformed("The peer's answer to the repository request is not in a format this build reads.");
        }

        return payload[1] == AnswerAccepted;
    }

    /// <summary>The third handshake payload: the initiator's Ed25519 device ID.</summary>
    /// <param name="ed25519PublicKey">The 32-byte device ID.</param>
    /// <returns><c>[format 1][32 bytes]</c>.</returns>
    public static byte[] EncodeIdentity(ReadOnlySpan<byte> ed25519PublicKey)
    {
        if (ed25519PublicKey.Length != Ed25519PublicKeySize)
        {
            throw new ArgumentException($"A device ID is {Ed25519PublicKeySize} bytes.", nameof(ed25519PublicKey));
        }

        var payload = new byte[1 + Ed25519PublicKeySize];
        payload[0] = PayloadFormat;
        ed25519PublicKey.CopyTo(payload.AsSpan(1));
        return payload;
    }

    /// <summary>Reads the third handshake payload.</summary>
    /// <param name="payload">The decrypted payload.</param>
    /// <returns>The claimed 32-byte Ed25519 device ID, not yet checked against anything.</returns>
    /// <exception cref="SipProtocolException">The payload is not in format 1.</exception>
    public static byte[] ReadIdentity(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 1 + Ed25519PublicKeySize || payload[0] != PayloadFormat)
        {
            throw Malformed("The caller's device ID is not in a format this build reads.");
        }

        return payload[1..].ToArray();
    }

    /// <summary>The X25519 static key a device ID implies.</summary>
    /// <param name="deviceId">A hexadecimal Ed25519 device ID, either case.</param>
    /// <param name="ed25519PublicKey">The device ID's 32 bytes.</param>
    /// <returns>The X25519 public key.</returns>
    /// <exception cref="ArgumentException">The device ID is not a usable Ed25519 public key.</exception>
    public static byte[] StaticKeyOf(string deviceId, out byte[] ed25519PublicKey)
    {
        ArgumentNullException.ThrowIfNull(deviceId);

        try
        {
            ed25519PublicKey = Convert.FromHexString(deviceId);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("A device ID is 64 hexadecimal characters.", nameof(deviceId), ex);
        }

        if (!RawX25519.TryConvertEd25519PublicKey(ed25519PublicKey, out var staticKey))
        {
            throw new ArgumentException(
                "That device ID is not a usable Ed25519 public key, so no machine can hold its private key.",
                nameof(deviceId));
        }

        return staticKey;
    }

    private static SipProtocolException Malformed(string message) =>
        new(SipProtocolFault.MalformedMessage, message);
}
