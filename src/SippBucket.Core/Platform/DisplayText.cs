namespace SippBucket.Core.Platform;

/// <summary>
/// What may be shown of text another machine wrote: the one rule every listing, log line and
/// alert applies to words SippBucket did not write itself.
/// </summary>
/// <remarks>
/// Two kinds of character are instructions to whatever shows the text, not text. A control
/// character, such as the escape that begins a terminal sequence, can move the cursor, rewrite a
/// line already printed or retitle the window. A character of the Unicode bidirectional algorithm
/// (UAX #9) reorders how the text around it is displayed, so <c>photo[U+202E]gpj.exe</c> shows as
/// <c>photoexe.jpg</c>. Neither may reach the person in a name a peer gave itself, a reason it gave
/// for a refusal, or anything else it sent. The characters are written here as escapes, never as
/// themselves, so this file cannot be read other than as it is.
/// </remarks>
public static class DisplayText
{
    /// <summary>Whether a character is an instruction to the display rather than text.</summary>
    /// <param name="character">The character.</param>
    /// <returns>True for a control character, or one that reorders how text is displayed.</returns>
    public static bool IsInstruction(char character) => char.IsControl(character) || ReordersDisplay(character);

    /// <summary>
    /// The characters that change the direction text is displayed in: the marks, embeddings,
    /// overrides and isolates of the Unicode bidirectional algorithm (UAX #9).
    /// </summary>
    /// <param name="character">The character.</param>
    /// <returns>True for one of them.</returns>
    public static bool ReordersDisplay(char character) => character switch
    {
        '؜' => true, // ARABIC LETTER MARK
        '‎' or '‏' => true, // LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK
        >= '‪' and <= '‮' => true, // embeddings, pop, overrides
        >= '⁦' and <= '⁩' => true, // isolates and pop
        _ => false,
    };

    /// <summary>Text made safe to show: each instruction replaced by <c>?</c>, and cut to a length.</summary>
    /// <param name="text">The text.</param>
    /// <param name="maximumLength">The most characters kept; text cut short ends with an ellipsis.</param>
    /// <returns>The text as it may be shown.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="text"/> was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maximumLength"/> was below 1.</exception>
    public static string Printable(string text, int maximumLength)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumLength, 1);

        var cut = text.Length > maximumLength;
        var kept = cut ? text[..maximumLength] : text;

        // Never half a character: a cut between the two halves of a surrogate pair would leave
        // one half, which is not text at all.
        if (cut && char.IsHighSurrogate(kept[^1]))
        {
            kept = kept[..^1];
        }

        if (kept.Any(IsInstruction))
        {
            kept = new string(kept.Select(c => IsInstruction(c) ? '?' : c).ToArray());
        }

        return cut ? kept + "…" : kept;
    }
}
