using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using NSec.Cryptography;
using SippBucket.Core.Crypto;
using SippBucket.Core.Protocol;
using SippBucket.Core.Serialization;

namespace SippBucket.Core.Pairing;

/// <summary>
/// The pairing exchange: CPace, explicit key confirmation both ways, then identities and the
/// repository key sealed under keys derived from the CPace session key.
/// </summary>
/// <remarks>
/// <para>
/// Six frames on the pairing port, each JSON under <see cref="Framing"/>'s
/// pre-authentication ceiling:
/// </para>
/// <list type="number">
/// <item>Joiner: protocol version and a 16-byte random nonce.</item>
/// <item>Offerer: its version and its own nonce. The session identifier is the two nonces
/// concatenated, joiner's first. That is the draft's recommendation in section 10.9 —
/// "One suitable option for generating sid is concatenation of ephemeral random strings
/// contributed by both parties" — and it costs one round trip, which buys the uniqueness
/// the composability proof relies on rather than running with an empty sid.</item>
/// <item>Joiner: its CPace share Ya and associated data ADa.</item>
/// <item>Offerer: Yb, ADb, its confirmation tag, and its device ID sealed under ISK. The
/// attempt is counted before this is computed.</item>
/// <item>Joiner, only once the offerer's tag verified: its own tag, and its device ID,
/// machine name and listen port sealed under ISK.</item>
/// <item>Offerer, only once the joiner's tag verified: accepted, and the repository ID,
/// name, key, its device ID and listen port sealed under ISK. Or not accepted, with nothing
/// else.</item>
/// </list>
/// <para>
/// <strong>The key never moves until both tags have verified.</strong> A wrong code fails
/// at step 4 on the joiner's side and at step 5 on the offerer's, and at neither point has
/// anything secret been sent: the only sealed payload a wrong-code party can receive is the
/// offerer's device ID, under a key it cannot derive.
/// </para>
/// <para>
/// <strong>Identities are bound by ISK, not by the clear text.</strong> Device IDs travel
/// sealed, so a wiretap does not learn a stable identifier for either machine (D-47's
/// concern, applied here from the start). A relay that forwards a correct-code run cannot
/// substitute its own device ID: it does not know ISK, because it knows neither scalar, so
/// it cannot seal anything either side will open. Section 10.1.1 of the draft asks for
/// identities not placed in CI to be authenticated and checked by the application; here
/// they are authenticated by the AEAD under ISK and checked against the invite when there
/// is one.
/// </para>
/// <para>
/// CI carries the protocol name and the two roles, initiator first, as section 10.1.2
/// recommends ("role information ... should be included as part of the party identity"),
/// so a message from one role can never be accepted in the other. The roles are fixed:
/// the machine that offers a code only ever answers, the machine that enters one only ever
/// dials, which is the draft's own defence against a party being tricked into pairing with
/// itself.
/// </para>
/// </remarks>
internal static class PairingProtocol
{
    /// <summary>
    /// The pairing protocol version. 1 was the code-in-clear exchange with an Argon2id
    /// envelope; it is refused, never spoken.
    /// </summary>
    public const int Version = 2;

    /// <summary>Bytes of randomness each side contributes to the session identifier.</summary>
    public const int NonceSize = 16;

    /// <summary>How long one frame may make no progress.</summary>
    public static TimeSpan StallTimeout { get; } = TimeSpan.FromSeconds(20);

    /// <summary>CI: the protocol and both roles, initiator first (draft section 10.1.1).</summary>
    public static byte[] ChannelIdentifier { get; } =
        CPace.LvCat(
            "SippBucket pairing v2"u8.ToArray(),
            "initiator:joiner"u8.ToArray(),
            "responder:offerer"u8.ToArray());

    /// <summary>ADa: what the joiner says it is, authenticated by the transcript.</summary>
    public static byte[] JoinerAssociatedData { get; } = "SippBucket pairing v2 joiner"u8.ToArray();

    /// <summary>ADb: what the offerer says it is, authenticated by the transcript.</summary>
    public static byte[] OffererAssociatedData { get; } = "SippBucket pairing v2 offerer"u8.ToArray();

    /// <summary>The message a joiner is shown for every kind of refusal.</summary>
    /// <remarks>
    /// One sentence for wrong, expired, used up and closed, because the offerer deliberately
    /// makes them indistinguishable and inventing detail here would be inventing it.
    /// </remarks>
    public const string NotAcceptedMessage =
        "That code or invite was not accepted, and nothing was written here. Check it, or " +
        "ask for a new one - each lasts ten minutes, works once, and stops working after " +
        "five failed attempts.";

    private static readonly AeadAlgorithm Aead = AeadAlgorithm.XChaCha20Poly1305;

    /// <summary>What a sealed payload is for. Each gets its own key and its own AD.</summary>
    public enum Purpose
    {
        /// <summary>Step 4: the offerer's device ID.</summary>
        OffererIdentity = 0,

        /// <summary>Step 5: the joiner's device ID, name and port.</summary>
        JoinerIdentity = 1,

        /// <summary>Step 6: the repository and its key.</summary>
        Repository = 2,
    }

    /// <summary>Seals a payload under a key derived from ISK for one purpose.</summary>
    /// <typeparam name="T">The payload type.</typeparam>
    /// <param name="payload">The payload.</param>
    /// <param name="isk">The CPace session key.</param>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="purpose">Which payload this is.</param>
    /// <returns>A random 24-byte nonce followed by the ciphertext.</returns>
    /// <remarks>
    /// The key is HKDF-SHA-512 (RFC 5869) with ISK as input keying material, sid as salt and
    /// the purpose as info — section 10.3 recommends running ISK through a KDF before use.
    /// One key per purpose means one message per key. The nonce is still drawn at random
    /// rather than fixed, by the house rule (standard E2) rather than necessity.
    /// </remarks>
    public static byte[] Seal<T>(T payload, byte[] isk, byte[] sessionId, Purpose purpose)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload, SipJson.Canonical);
        var nonce = RandomNumberGenerator.GetBytes(Aead.NonceSize);
        var label = Label(purpose);

        try
        {
            using var key = DeriveKey(isk, sessionId, label);
            return [.. nonce, .. Aead.Encrypt(key, nonce, label, plaintext)];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Opens a sealed payload, or reports that it does not open.</summary>
    /// <typeparam name="T">The payload type.</typeparam>
    /// <param name="sealedPayload">Nonce and ciphertext, untrusted.</param>
    /// <param name="isk">The CPace session key.</param>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="purpose">Which payload this should be.</param>
    /// <param name="payload">The payload, when this returns true.</param>
    /// <returns>True when it authenticated and parsed.</returns>
    public static bool TryOpen<T>(
        byte[]? sealedPayload,
        byte[] isk,
        byte[] sessionId,
        Purpose purpose,
        [NotNullWhen(true)] out T? payload)
        where T : class
    {
        payload = null;

        if (sealedPayload is null || sealedPayload.Length <= Aead.NonceSize + Aead.TagSize)
        {
            return false;
        }

        var label = Label(purpose);
        var plaintext = new byte[sealedPayload.Length - Aead.NonceSize - Aead.TagSize];

        try
        {
            using var key = DeriveKey(isk, sessionId, label);
            if (!Aead.Decrypt(
                    key,
                    sealedPayload.AsSpan(0, Aead.NonceSize),
                    label,
                    sealedPayload.AsSpan(Aead.NonceSize),
                    plaintext))
            {
                return false;
            }

            payload = JsonSerializer.Deserialize<T>(plaintext, SipJson.Canonical);
            return payload is not null;
        }
        catch (JsonException)
        {
            // Authenticated but unparseable means a peer running something else entirely.
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Serialises a message for the wire.</summary>
    /// <typeparam name="T">The message type.</typeparam>
    /// <param name="stream">The connection.</param>
    /// <param name="message">The message.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes once the frame is written.</returns>
    public static Task WriteAsync<T>(Stream stream, T message, CancellationToken cancellationToken) =>
        Framing.WriteFrameAsync(
            stream,
            JsonSerializer.SerializeToUtf8Bytes(message, SipJson.Canonical),
            StallTimeout,
            cancellationToken);

    /// <summary>Reads one message, or null when the other side closed or sent nonsense.</summary>
    /// <typeparam name="T">The message type.</typeparam>
    /// <param name="stream">The connection.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The message, or null.</returns>
    /// <remarks>
    /// Read under <see cref="Framing.HandshakeFrameSize"/>, because until the last frame
    /// nobody on this port has proved anything, and four bytes of length prefix must not be
    /// able to buy an arbitrary allocation.
    /// </remarks>
    public static async Task<T?> ReadAsync<T>(Stream stream, CancellationToken cancellationToken)
        where T : class
    {
        var frame = await Framing.ReadFrameAsync(
            stream, Framing.HandshakeFrameSize, StallTimeout, cancellationToken)
            .ConfigureAwait(false);

        if (frame is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(frame, SipJson.Canonical);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The session identifier: joiner's nonce, then offerer's (draft section 10.9).</summary>
    /// <param name="joinerNonce">The joiner's nonce.</param>
    /// <param name="offererNonce">The offerer's nonce.</param>
    /// <returns>sid.</returns>
    public static byte[] SessionId(byte[] joinerNonce, byte[] offererNonce) =>
        [.. joinerNonce, .. offererNonce];

    /// <summary>Whether a device ID is a well-formed Ed25519 public key.</summary>
    /// <param name="deviceId">The candidate.</param>
    /// <returns>True when it is.</returns>
    public static bool IsDeviceId(string? deviceId) =>
        deviceId is not null && DeviceIdentity.TryImportPublicKey(deviceId, out _);

    /// <summary>Whether a port number is one a peer could listen on.</summary>
    /// <param name="port">The candidate.</param>
    /// <returns>True for 1 to 65535.</returns>
    public static bool IsPort(int port) => port is > 0 and <= 65535;

    private static byte[] Label(Purpose purpose) => purpose switch
    {
        Purpose.OffererIdentity => "SippBucket pairing v2: offerer identity"u8.ToArray(),
        Purpose.JoinerIdentity => "SippBucket pairing v2: joiner identity"u8.ToArray(),
        Purpose.Repository => "SippBucket pairing v2: repository"u8.ToArray(),
        _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Not a purpose."),
    };

    private static Key DeriveKey(byte[] isk, byte[] sessionId, byte[] label)
    {
        var material = HKDF.DeriveKey(HashAlgorithmName.SHA512, isk, Aead.KeySize, sessionId, label);
        try
        {
            return Key.Import(Aead, material, KeyBlobFormat.RawSymmetricKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }
}

/// <summary>Step 1: the joiner introduces itself.</summary>
internal sealed record PairingHello
{
    /// <summary>The pairing protocol version the joiner speaks.</summary>
    public int Protocol { get; init; }

    /// <summary>The joiner's half of the session identifier.</summary>
    public byte[]? Nonce { get; init; }
}

/// <summary>Step 2: the offerer answers with its version and its half of the sid.</summary>
/// <remarks>
/// A version mismatch is answered with the offerer's version and no nonce, and the
/// connection closed, so a mismatched machine is told why in words rather than meeting a
/// decryption failure three frames later.
/// </remarks>
internal sealed record PairingHelloReply
{
    /// <summary>The pairing protocol version the offerer speaks.</summary>
    public int Protocol { get; init; }

    /// <summary>The offerer's half of the session identifier. Absent on a version refusal.</summary>
    public byte[]? Nonce { get; init; }
}

/// <summary>Step 3: the joiner's CPace message, Ya and ADa.</summary>
internal sealed record PairingShareMessage
{
    /// <summary>Ya.</summary>
    public byte[]? Share { get; init; }

    /// <summary>ADa.</summary>
    public byte[]? AssociatedData { get; init; }
}

/// <summary>Step 4: the offerer's CPace message, its confirmation, and its sealed device ID.</summary>
internal sealed record PairingAnswer
{
    /// <summary>Yb.</summary>
    public byte[]? Share { get; init; }

    /// <summary>ADb.</summary>
    public byte[]? AssociatedData { get; init; }

    /// <summary>Tb: MAC(mac_key, lv_cat(Yb, ADb)).</summary>
    public byte[]? Confirmation { get; init; }

    /// <summary>An <see cref="OffererIdentity"/>, sealed.</summary>
    public byte[]? Sealed { get; init; }
}

/// <summary>Step 5: the joiner's confirmation and its sealed identity.</summary>
internal sealed record PairingConfirmation
{
    /// <summary>Ta: MAC(mac_key, lv_cat(Ya, ADa)).</summary>
    public byte[]? Confirmation { get; init; }

    /// <summary>A <see cref="JoinerIdentity"/>, sealed.</summary>
    public byte[]? Sealed { get; init; }
}

/// <summary>Step 6: whether the joiner was accepted, and if so the repository.</summary>
/// <remarks>
/// Two fields, and deliberately no reason field: which kind of refusal it was would tell a
/// guesser whether a pairing window is open, which is worth more to them than knowing that
/// one guess was wrong. With no field to put a reason in, no future change can start
/// leaking one by filling it in.
/// </remarks>
internal sealed record PairingResultMessage
{
    /// <summary>Whether both confirmations verified and the joiner was recorded.</summary>
    public bool Accepted { get; init; }

    /// <summary>The repository, sealed. Absent on refusal.</summary>
    public byte[]? Sealed { get; init; }
}

/// <summary>Sealed in step 4: who the offerer is.</summary>
internal sealed record OffererIdentity
{
    /// <summary>The offerer's device ID.</summary>
    public string? DeviceId { get; init; }
}

/// <summary>Sealed in step 5: who the joiner is and where it will listen.</summary>
internal sealed record JoinerIdentity
{
    /// <summary>The joiner's device ID.</summary>
    public string? DeviceId { get; init; }

    /// <summary>What the offerer should call it.</summary>
    public string? MachineName { get; init; }

    /// <summary>The port its daemon will serve on.</summary>
    public int ListenPort { get; init; }
}
