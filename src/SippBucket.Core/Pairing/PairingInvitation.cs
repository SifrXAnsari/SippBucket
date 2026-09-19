using System.Text.Json;
using SippBucket.Core.Serialization;

namespace SippBucket.Core.Pairing;

/// <summary>
/// A pasteable pairing offer: where to find the offering machine, who it is, and a one-time
/// secret to run CPace with. The <c>sip2_</c> string <c>sip invite</c> prints.
/// </summary>
/// <remarks>
/// <para>
/// <strong>It does not contain the repository key, and nothing that can print one does.</strong>
/// Its predecessor, <c>sip1_</c>, was the repository ID and key in base64: anyone who saw it
/// in a chat log could read every document, for ever, and nothing could revoke it. This one
/// is a secret for ten minutes and one use, and even inside that window it is only the
/// password of a PAKE — the key itself is sent later, sealed to whichever machine proved it
/// held the secret, and a wiretap on that exchange learns neither.
/// </para>
/// <para>
/// The secret is longer than a spoken code because it is pasted rather than read out:
/// 128 bits instead of 48. The attempt budget still applies, and still matters less here.
/// </para>
/// <para>
/// The offerer's device ID is carried so the joiner can check, before anything is sent
/// back, that the machine that answered is the one that made the invite. That check runs
/// on the device ID received sealed under the CPace session key, so a relay cannot satisfy
/// it by repeating the one in this string.
/// </para>
/// </remarks>
public sealed record PairingInvitation
{
    /// <summary>What every invitation from this build starts with.</summary>
    public const string Prefix = "sip2_";

    /// <summary>What the retired key-bearing invites started with.</summary>
    public const string LegacyPrefix = "sip1_";

    /// <summary>The offering machine's addresses, the most likely first.</summary>
    public required IReadOnlyList<string> Hosts { get; init; }

    /// <summary>The offering machine's sync port. Pairing is one above it.</summary>
    public required int Port { get; init; }

    /// <summary>The offering machine's device ID.</summary>
    public required string DeviceId { get; init; }

    /// <summary>The one-time secret, URL-safe base64 without padding.</summary>
    public required string Secret { get; init; }

    /// <summary>Packs the invitation into one pasteable string.</summary>
    /// <returns><c>sip2_</c> followed by URL-safe base64 of canonical JSON.</returns>
    public string Encode() =>
        Prefix + ToBase64Url(JsonSerializer.SerializeToUtf8Bytes(this, SipJson.Canonical));

    /// <summary>Unpacks and checks an invitation string.</summary>
    /// <param name="encoded">What the user pasted.</param>
    /// <returns>The invitation.</returns>
    /// <exception cref="LegacyInviteException">It is a <c>sip1_</c> invite, which is refused.</exception>
    /// <exception cref="FormatException">It is not a valid invitation.</exception>
    /// <remarks>
    /// A <c>sip1_</c> string is refused before a single byte of it is decoded. There is no
    /// path in this build that reads one: accepting it "just this once, for compatibility"
    /// would keep alive the exact thing being retired, and the key in it has been in the
    /// clear since the moment it was printed whatever this program does now.
    /// </remarks>
    public static PairingInvitation Decode(string encoded)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encoded);

        var trimmed = encoded.Trim();

        if (trimmed.StartsWith(LegacyPrefix, StringComparison.Ordinal))
        {
            throw new LegacyInviteException();
        }

        if (!trimmed.StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"That is not a SippBucket invite. An invite starts with '{Prefix}'.");
        }

        byte[] json;
        try
        {
            json = FromBase64Url(trimmed[Prefix.Length..]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("That invite is damaged or incomplete.", ex);
        }

        PairingInvitation? invitation;
        try
        {
            invitation = JsonSerializer.Deserialize<PairingInvitation>(json, SipJson.Canonical);
        }
        catch (JsonException ex)
        {
            throw new FormatException("That invite is damaged or incomplete.", ex);
        }

        if (invitation is null ||
            invitation.Hosts is not { Count: > 0 } ||
            invitation.Hosts.Any(string.IsNullOrWhiteSpace) ||
            !PairingProtocol.IsPort(invitation.Port) ||
            !PairingProtocol.IsDeviceId(invitation.DeviceId) ||
            !TryDecodeSecret(invitation.Secret, out _))
        {
            throw new FormatException("That invite is damaged or incomplete.");
        }

        return invitation;
    }

    /// <summary>Renders the parts a person would check, without the secret.</summary>
    /// <returns>A short description.</returns>
    public override string ToString() =>
        $"device {DeviceId[..Math.Min(12, DeviceId.Length)]} at " +
        $"{string.Join(", ", Hosts)} port {Port}";

    /// <summary>The CPace password this invitation carries.</summary>
    /// <returns>The raw secret.</returns>
    /// <exception cref="FormatException">The secret is not the right shape.</exception>
    internal byte[] Password() =>
        TryDecodeSecret(Secret, out var raw)
            ? raw
            : throw new FormatException("That invite's secret is damaged.");

    /// <summary>Writes a raw secret the way an invitation carries it.</summary>
    /// <param name="secret">The raw secret.</param>
    /// <returns>URL-safe base64, no padding.</returns>
    internal static string EncodeSecret(byte[] secret) => ToBase64Url(secret);

    private static bool TryDecodeSecret(string? text, out byte[] raw)
    {
        raw = [];
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        try
        {
            raw = FromBase64Url(text);
        }
        catch (FormatException)
        {
            return false;
        }

        return raw.Length == PairingSession.InvitationSecretSize;
    }

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] FromBase64Url(string text)
    {
        var body = text.Replace('-', '+').Replace('_', '/');
        body = body.PadRight(body.Length + ((4 - (body.Length % 4)) % 4), '=');
        return Convert.FromBase64String(body);
    }
}

/// <summary>
/// Thrown for a <c>sip1_</c> invite: one that carries the repository key in clear text.
/// </summary>
/// <remarks>
/// Its own type, because the right response is specific and nothing else produces it: the
/// string is not damaged, it is dangerous, and the person holding it needs to know that the
/// key in it is already exposed to everyone who has seen it.
/// </remarks>
public sealed class LegacyInviteException : FormatException
{
    /// <summary>Creates the exception with the explanation.</summary>
    public LegacyInviteException()
        : base(
            "That is an old 'sip1_' invite, and this version refuses it. It holds the " +
            "folder's encryption key in plain text: anyone who has seen that string can read " +
            "every document in the folder, and nothing can take that back. Treat it as " +
            "leaked - delete it from wherever it was sent. To join, run 'sip invite' (or " +
            "'sip pair offer') on the other machine and use what it prints; neither contains " +
            "the key.")
    {
    }

    /// <summary>Creates the exception with a custom message.</summary>
    /// <param name="message">The message.</param>
    public LegacyInviteException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public LegacyInviteException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
