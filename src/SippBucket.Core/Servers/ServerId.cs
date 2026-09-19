using SippBucket.Core.Pairing;

namespace SippBucket.Core.Servers;

/// <summary>
/// A server's standard identifier, <c>Server.ID#XXX-XXX-XXX</c>: a fingerprint of its
/// permanent ID, for display, logs and lookup.
/// </summary>
/// <remarks>
/// <para>
/// Nine symbols in three groups of three, from the pairing-code alphabet
/// (<see cref="PairingCode.Alphabet"/>), chosen so no two symbols can be confused by eye or by
/// ear, so an identifier can be read aloud between two machines (docs/SERVER-ID.md).
/// </para>
/// <para>
/// <b>The mapping, fixed here and pinned by a golden test:</b> the first 36 bits of the
/// permanent ID's 256-bit hash, taken four at a time from the first byte on, each byte's high
/// four bits before its low four, each group of four naming one symbol by its position in the
/// alphabet. So the first four and a half bytes make the nine symbols.
/// </para>
/// <para>
/// 36 bits identify a server among a person's own machines, not among everyone's. Exact
/// comparison always uses the full hash (<see cref="PermanentId.Hex"/>); this is what a person
/// reads.
/// </para>
/// </remarks>
public sealed record ServerId
{
    /// <summary>What every identifier starts with.</summary>
    public const string Prefix = "Server.ID#";

    /// <summary>How many symbols an identifier has.</summary>
    public const int Symbols = 9;

    /// <summary>How many bits of the permanent ID those symbols carry.</summary>
    public const int Bits = Symbols * 4;

    private const int GroupSize = 3;

    private ServerId(string code)
    {
        Code = code;
    }

    /// <summary>The nine symbols alone, without the prefix or the dashes.</summary>
    public string Code { get; }

    /// <summary>The fingerprint of a permanent ID.</summary>
    /// <param name="permanentHash">The permanent ID's hash: at least the first five bytes of it.</param>
    /// <returns>The identifier.</returns>
    /// <exception cref="ArgumentException">Fewer than five bytes were given.</exception>
    public static ServerId FromPermanent(ReadOnlySpan<byte> permanentHash)
    {
        const int bytesNeeded = (Bits + 7) / 8;
        if (permanentHash.Length < bytesNeeded)
        {
            throw new ArgumentException(
                $"A fingerprint takes the first {bytesNeeded} bytes of a permanent ID; {permanentHash.Length} were given.",
                nameof(permanentHash));
        }

        Span<char> code = stackalloc char[Symbols];
        for (var i = 0; i < Symbols; i++)
        {
            var b = permanentHash[i / 2];
            var nibble = i % 2 == 0 ? b >> 4 : b & 0x0F;
            code[i] = PairingCode.Alphabet[nibble];
        }

        return new ServerId(new string(code));
    }

    /// <summary>Reads an identifier as a person types it.</summary>
    /// <param name="text">
    /// With or without the <c>Server.ID#</c> prefix, in any case, with or without the dashes or
    /// spaces between the groups.
    /// </param>
    /// <param name="id">The identifier, when this returns true.</param>
    /// <returns>False unless exactly nine symbols of the alphabet remain. Nothing is guessed from a near miss.</returns>
    public static bool TryParse(string? text, out ServerId? id)
    {
        id = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var body = text.Trim();
        if (body.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            body = body[Prefix.Length..];
        }

        Span<char> code = stackalloc char[Symbols];
        var count = 0;
        foreach (var c in body)
        {
            if (c is '-' or ' ')
            {
                continue;
            }

            var symbol = char.ToUpperInvariant(c);
            if (count == Symbols || !PairingCode.Alphabet.Contains(symbol, StringComparison.Ordinal))
            {
                return false;
            }

            code[count++] = symbol;
        }

        if (count != Symbols)
        {
            return false;
        }

        id = new ServerId(new string(code));
        return true;
    }

    /// <summary>The standard form: <c>Server.ID#XXX-XXX-XXX</c>.</summary>
    /// <returns>The identifier as code, logs and files write it.</returns>
    public override string ToString() =>
        $"{Prefix}{Code[..GroupSize]}-{Code[GroupSize..(2 * GroupSize)]}-{Code[(2 * GroupSize)..]}";
}
