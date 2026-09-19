using System.Text;

namespace SippBucket.Core.Text;

/// <summary>
/// A three-way line merge for text pages: two machines' edits to one file, combined against
/// the version both started from, when their edits do not touch (T-01).
/// </summary>
/// <remarks>
/// <para>
/// <b>What it promises.</b> The result is the base with both sides' edits applied, and it
/// exists only when that sentence is unambiguous: every edited region is edited by one side,
/// or edited identically by both. Regions where the sides' edits overlap or touch — even
/// end-to-start, with no unchanged line between them — make the whole merge answer null, and
/// the caller keeps both files, exactly as every conflict was kept before this existed.
/// Touching counts as overlap on purpose: two edits that meet at a line boundary have an
/// ordering question this code refuses to answer for the person.
/// </para>
/// <para>
/// <b>Bytes are preserved, not normalised.</b> Lines are compared with their endings
/// stripped, so a Windows ending equals a Unix one, but every line of the result carries the
/// exact bytes of whichever version contributed it: unchanged lines the base's, edits the
/// editing side's. Content that is not strict UTF-8 refuses to merge rather than pass
/// through a decoder that would rewrite it.
/// </para>
/// <para>
/// <b>Both machines produce the same bytes.</b> A merge may run on either machine, or on
/// both at once with the sides swapped, and convergence needs the results identical. Regions
/// come out as above regardless of which side is "mine"; where both sides made the same edit
/// with different bytes — the same words saved with different endings — the ordinally
/// smaller bytes are taken, a rule with no side in it.
/// </para>
/// </remarks>
public static class ThreeWayMerge
{
    /// <summary>Merges two sides' versions of one text file against their common base.</summary>
    /// <param name="baseBytes">The version both sides started from.</param>
    /// <param name="mineBytes">One side's version.</param>
    /// <param name="theirsBytes">The other side's version.</param>
    /// <returns>
    /// The merged bytes, or null when the edits overlap or the content is not strict UTF-8
    /// text — the caller keeps both versions then.
    /// </returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    public static byte[]? Merge(byte[] baseBytes, byte[] mineBytes, byte[] theirsBytes)
    {
        ArgumentNullException.ThrowIfNull(baseBytes);
        ArgumentNullException.ThrowIfNull(mineBytes);
        ArgumentNullException.ThrowIfNull(theirsBytes);

        if (LineDiff.LooksBinary(baseBytes) || LineDiff.LooksBinary(mineBytes) || LineDiff.LooksBinary(theirsBytes))
        {
            return null;
        }

        if (SplitRaw(baseBytes) is not { } baseLines ||
            SplitRaw(mineBytes) is not { } mineLines ||
            SplitRaw(theirsBytes) is not { } theirsLines)
        {
            return null;
        }

        var mineEdits = EditsAgainstBase(baseLines.Keys, mineLines);
        var theirsEdits = EditsAgainstBase(baseLines.Keys, theirsLines);

        var result = new StringBuilder();
        var basePosition = 0;
        var mi = 0;
        var ti = 0;

        while (mi < mineEdits.Count || ti < theirsEdits.Count)
        {
            var mine = mi < mineEdits.Count ? mineEdits[mi] : null;
            var theirs = ti < theirsEdits.Count ? theirsEdits[ti] : null;

            if (mine is not null && theirs is not null &&
                mine.BaseStart <= theirs.BaseEnd && theirs.BaseStart <= mine.BaseEnd)
            {
                // The regions overlap or touch. Identical edits are one edit; anything else
                // is the person's decision, not this code's.
                if (mine.BaseStart != theirs.BaseStart || mine.BaseEnd != theirs.BaseEnd ||
                    !mine.NormalizedReplacement.SequenceEqual(theirs.NormalizedReplacement, StringComparer.Ordinal))
                {
                    return null;
                }

                CopyBase(result, baseLines.Raw, basePosition, mine.BaseStart);
                result.Append(SmallerOf(mine.RawReplacement, theirs.RawReplacement));
                basePosition = mine.BaseEnd;
                mi++;
                ti++;
                continue;
            }

            var next = theirs is null || (mine is not null && mine.BaseStart <= theirs.BaseStart)
                ? mineEdits[mi++]
                : theirsEdits[ti++];

            CopyBase(result, baseLines.Raw, basePosition, next.BaseStart);
            result.Append(next.RawReplacement);
            basePosition = next.BaseEnd;
        }

        CopyBase(result, baseLines.Raw, basePosition, baseLines.Raw.Count);
        return Encoding.UTF8.GetBytes(result.ToString());
    }

    private static void CopyBase(StringBuilder result, IReadOnlyList<string> raw, int from, int to)
    {
        for (var i = from; i < to; i++)
        {
            result.Append(raw[i]);
        }
    }

    /// <summary>The ordinally smaller of two equal edits' bytes, so both machines pick one.</summary>
    private static string SmallerOf(string first, string second) =>
        string.CompareOrdinal(first, second) <= 0 ? first : second;

    /// <summary>One side's edit: which base lines it replaces, and with what.</summary>
    /// <param name="BaseStart">The first base line replaced.</param>
    /// <param name="BaseEnd">One past the last base line replaced. Equal to start for an insertion.</param>
    /// <param name="RawReplacement">The replacing lines, endings and all, concatenated.</param>
    /// <param name="NormalizedReplacement">The replacing lines with endings stripped, for equality.</param>
    private sealed record Edit(
        int BaseStart,
        int BaseEnd,
        string RawReplacement,
        IReadOnlyList<string> NormalizedReplacement);

    /// <summary>Reads one side's changes out of its diff against the base, as edit regions.</summary>
    private static List<Edit> EditsAgainstBase(IReadOnlyList<string> baseKeys, RawLines side)
    {
        var script = LineDiff.Compare(baseKeys, side.Keys);
        var edits = new List<Edit>();
        var basePosition = 0;
        var i = 0;

        while (i < script.Count)
        {
            if (script[i].Change == LineChange.Same)
            {
                basePosition++;
                i++;
                continue;
            }

            var start = basePosition;
            var raw = new StringBuilder();
            var normalized = new List<string>();
            while (i < script.Count && script[i].Change != LineChange.Same)
            {
                if (script[i].Change == LineChange.Removed)
                {
                    basePosition++;
                }
                else
                {
                    raw.Append(side.Raw[script[i].AfterLine]);
                    normalized.Add(side.Keys[script[i].AfterLine]);
                }

                i++;
            }

            edits.Add(new Edit(start, basePosition, raw.ToString(), normalized));
        }

        return edits;
    }

    /// <summary>A file as raw lines, each with its own ending, and keys with endings stripped.</summary>
    private sealed record RawLines(IReadOnlyList<string> Raw, IReadOnlyList<string> Keys);

    /// <summary>
    /// Splits strict UTF-8 into lines that keep their endings, or answers null for bytes a
    /// decode would rewrite.
    /// </summary>
    private static RawLines? SplitRaw(byte[] bytes)
    {
        string text;
        try
        {
            text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }

        var raw = new List<string>();
        var keys = new List<string>();
        var start = 0;

        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '\n')
            {
                continue;
            }

            raw.Add(text[start..(i + 1)]);
            var end = i > start && text[i - 1] == '\r' ? i - 1 : i;
            keys.Add(text[start..end]);
            start = i + 1;
        }

        if (start < text.Length)
        {
            raw.Add(text[start..]);
            keys.Add(text[start..]);
        }

        return new RawLines(raw, keys);
    }
}
