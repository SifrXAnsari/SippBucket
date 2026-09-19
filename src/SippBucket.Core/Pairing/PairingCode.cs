using System.Security.Cryptography;

namespace SippBucket.Core.Pairing;

/// <summary>
/// A short code that can be read out loud, typed, and got right first time.
/// </summary>
/// <remarks>
/// <para>
/// This replaces pasting a 400-character base64 invite between two machines, which was the
/// worst interaction in the product and was worst exactly when a new user met it first.
/// </para>
/// <para>
/// <strong>The alphabet is the design.</strong> Sixteen symbols is not a round number
/// chosen for tidiness — it is what survives two filters, and it happens to be a power of
/// two, so each character is exactly one nibble and a code can be cut straight from CSPRNG
/// bytes with no modulo bias and no rejection-sampling loop to get subtly wrong.
/// </para>
/// <para>
/// The read-alike filter is the easy half: 0/O, 1/I/L, 5/S, 2/Z, 6/G, 8/B. The speak-alike
/// filter is the half usually skipped and is the harder constraint, because the rhyming
/// "ee" set — B C D E G P T V Z — all sound alike across a room, and removing it costs nine
/// of the twenty-six letters in one stroke. Then J and K collide with A, N with M, S with F,
/// H with the digit 8, and U with Q. Nine letters and seven digits survive. There is no
/// spare letter left to add.
/// </para>
/// </remarks>
public static class PairingCode
{
    /// <summary>The sixteen symbols a code is drawn from.</summary>
    /// <remarks>
    /// Seven digits and nine letters, chosen so that no two are confusable by eye
    /// <em>or</em> by ear. Sixteen is the maximum this construction yields.
    /// </remarks>
    public const string Alphabet = "2345679AFHMQRWXY";

    /// <summary>How many symbols a code has.</summary>
    /// <remarks>
    /// <para>
    /// Twelve symbols at four bits each is exactly 48 bits, cut from exactly 6 bytes.
    /// </para>
    /// <para>
    /// Eight symbols would be enough <em>if the attempt budget is implemented correctly</em>:
    /// five guesses against 2^32 is about one in 860 million. Twelve is kept because of what
    /// happens when it is not. At 48 bits an attacker hammering 10,000 guesses a second for
    /// the whole ten-minute window still only reaches about one in 47 million — so twelve
    /// characters is the length at which <strong>forgetting to rate limit, or shipping a
    /// rate limiter with a bug in it, is not a breach.</strong> At eight characters the same
    /// mistake is one in 716, which is a bad afternoon. Four extra keystrokes buys immunity
    /// to the likeliest implementation error in the feature.
    /// </para>
    /// </remarks>
    public const int Length = 12;

    /// <summary>Bits of entropy in a code.</summary>
    public const int EntropyBits = Length * 4;

    private const int GroupSize = 4;

    /// <summary>Generates a fresh code.</summary>
    /// <returns>Twelve symbols, unformatted.</returns>
    public static string Generate()
    {
        // Exactly one nibble per symbol. No modulo, so no bias; no rejection loop, so no
        // subtle bug in the loop.
        var bytes = RandomNumberGenerator.GetBytes(Length / 2);
        var code = new char[Length];

        for (var i = 0; i < bytes.Length; i++)
        {
            code[i * 2] = Alphabet[bytes[i] >> 4];
            code[(i * 2) + 1] = Alphabet[bytes[i] & 0x0F];
        }

        CryptographicOperations.ZeroMemory(bytes);
        return new string(code);
    }

    /// <summary>The separator between groups.</summary>
    /// <remarks>
    /// <para>
    /// A plain ASCII hyphen, not the typographic middle dot the design boards use. The
    /// difference is not cosmetic: a middle dot is U+00B7, and a console running a non-UTF-8
    /// code page — which is most Windows consoles — renders it as a question mark or drops
    /// it. Somebody reading a code off their own terminal would be reading a corrupted one.
    /// </para>
    /// <para>
    /// Found by redirecting the output of <c>sip pair offer</c> and watching the separator
    /// come back as nothing. The hyphen survives every code page and is already stripped by
    /// <see cref="TryNormalise"/>, so a user can type it back exactly as shown.
    /// </para>
    /// </remarks>
    public const char GroupSeparator = '-';

    /// <summary>Formats a code for display, in groups of four.</summary>
    /// <param name="code">A normalised code.</param>
    /// <returns>The code in groups of four.</returns>
    /// <exception cref="ArgumentException">The code was not the right length.</exception>
    public static string Format(string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);

        if (code.Length != Length)
        {
            throw new ArgumentException(
                $"A pairing code is {Length} symbols; got {code.Length}.", nameof(code));
        }

        var groups = new List<string>();
        for (var i = 0; i < code.Length; i += GroupSize)
        {
            groups.Add(code.Substring(i, GroupSize));
        }

        return string.Join(GroupSeparator, groups);
    }

    /// <summary>
    /// Turns whatever the user typed into a canonical code, or reports that it cannot be.
    /// </summary>
    /// <param name="typed">What was entered.</param>
    /// <param name="normalised">The canonical form, when it could be produced.</param>
    /// <returns>True when the input resolved to a well-formed code.</returns>
    /// <remarks>
    /// <para>
    /// Separators are dropped, case is ignored, and a short list of by-eye substitutions is
    /// forgiven. <strong>That list is shorter than the usual one, and deliberately so.</strong>
    /// The conventional set — O to 0, I and L to 1, B to 8 — is inherited from Crockford
    /// base32, where the <em>target</em> of each substitution is in the alphabet. Here it is
    /// not: 0, 1 and 8 were removed by the read-alike filter too. Forgiving O to 0 would
    /// resolve one invalid character into another, which is worse than rejecting it, because
    /// the user is told the code is wrong instead of being told which character is wrong.
    /// </para>
    /// <para>
    /// Only three substitutions survive that test, and each one maps a removed character
    /// onto the symbol that displaced it: S to 5, Z to 2, G to 6.
    /// </para>
    /// <para>
    /// A character that does not resolve is rejected outright rather than dropped. A code of
    /// the wrong length must fail rather than be silently padded or trimmed.
    /// </para>
    /// </remarks>
    public static bool TryNormalise(string? typed, out string normalised)
    {
        normalised = string.Empty;

        if (string.IsNullOrWhiteSpace(typed))
        {
            return false;
        }

        var builder = new System.Text.StringBuilder(Length);

        foreach (var raw in typed)
        {
            if (raw is '-' or ' ' or '\t' or '·' or '_')
            {
                continue;
            }

            var symbol = char.ToUpperInvariant(raw) switch
            {
                'S' => '5',
                'Z' => '2',
                'G' => '6',
                var other => other,
            };

            if (!Alphabet.Contains(symbol, StringComparison.Ordinal))
            {
                return false;
            }

            if (builder.Length == Length)
            {
                // Too long. Stop here rather than truncating: a code with an extra
                // character is a typo, and accepting its prefix would spend one of the
                // user's five attempts on an input they could see was wrong.
                return false;
            }

            builder.Append(symbol);
        }

        if (builder.Length != Length)
        {
            return false;
        }

        normalised = builder.ToString();
        return true;
    }

    /// <summary>Compares two codes without leaking where they first differ.</summary>
    /// <param name="left">One code.</param>
    /// <param name="right">The other.</param>
    /// <returns>True when they match.</returns>
    public static bool Equal(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(left),
            System.Text.Encoding.ASCII.GetBytes(right));
    }
}
