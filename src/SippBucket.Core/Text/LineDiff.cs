using System.Text;

namespace SippBucket.Core.Text;

/// <summary>How one line of a comparison relates the two sides.</summary>
public enum LineChange
{
    /// <summary>The line is in both versions.</summary>
    Same,

    /// <summary>The line is only in the older version.</summary>
    Removed,

    /// <summary>The line is only in the newer version.</summary>
    Added,
}

/// <summary>
/// One line of a diff script: what happened to it and where it sits in each version.
/// </summary>
/// <param name="Change">Whether the line is shared, removed or added.</param>
/// <param name="BeforeLine">Zero-based line in the older version, or -1 for an added line.</param>
/// <param name="AfterLine">Zero-based line in the newer version, or -1 for a removed line.</param>
/// <param name="Text">The line, without its ending.</param>
public readonly record struct DiffLine(LineChange Change, int BeforeLine, int AfterLine, string Text);

/// <summary>A file's bytes as lines, remembering what the split cannot reconstruct.</summary>
/// <remarks>
/// Lines end at <c>\n</c>, with one <c>\r</c> before it dropped, so the same text saved by a
/// Windows editor and a Unix one reads as the same lines — which is exactly how the two copies
/// of a file synced between such machines should compare. The bytes are decoded as UTF-8 with
/// U+FFFD for anything that is not, never thrown on: the diff is a view, and a view that
/// refuses to open is worse than one with a replacement character in it.
/// </remarks>
public sealed class SplitText
{
    private SplitText(IReadOnlyList<string> lines, bool endsWithoutNewline)
    {
        Lines = lines;
        EndsWithoutNewline = endsWithoutNewline;
    }

    /// <summary>The lines, without their endings.</summary>
    public IReadOnlyList<string> Lines { get; }

    /// <summary>True when the last line was not closed by a newline.</summary>
    public bool EndsWithoutNewline { get; }

    /// <summary>Splits a file's bytes into lines.</summary>
    /// <param name="bytes">The file's content.</param>
    /// <returns>The lines and whether the file ended without a newline.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="bytes"/> was null.</exception>
    public static SplitText From(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        var text = Encoding.UTF8.GetString(bytes);
        var lines = new List<string>();
        var start = 0;

        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '\n')
            {
                continue;
            }

            var end = i > start && text[i - 1] == '\r' ? i - 1 : i;
            lines.Add(text[start..end]);
            start = i + 1;
        }

        var endsWithoutNewline = start < text.Length;
        if (endsWithoutNewline)
        {
            lines.Add(text[start..]);
        }

        return new SplitText(lines, endsWithoutNewline && lines.Count > 0);
    }
}

/// <summary>
/// A line diff: Myers' O(ND) algorithm in its linear-space form, with a depth cap for
/// pathological inputs.
/// </summary>
/// <remarks>
/// <para>
/// The script is minimal — the fewest added and removed lines — except where two regions are
/// so unrelated that finding the minimum would cost more than it tells. There the search is
/// cut off at <see cref="MaximumSearchDepth"/> differences and the region is reported as all
/// of one side removed and all of the other added: a coarser hunk, still a correct diff, and
/// a bounded amount of work whatever the input. Nothing about the cut-off changes which lines
/// are equal; it only groups them less finely.
/// </para>
/// <para>
/// Comparison is ordinal and case-sensitive: two lines are the same line only when their
/// characters are, because a diff that "helpfully" equates lines is a diff that hides edits.
/// </para>
/// </remarks>
public static class LineDiff
{
    /// <summary>
    /// How many differences the middle-snake search will look for before calling a region
    /// unrelated. 2,048 differences inside one region is a rewrite, not an edit.
    /// </summary>
    public const int MaximumSearchDepth = 2048;

    /// <summary>How many leading bytes are read when deciding whether content is text.</summary>
    private const int BinarySniffLength = 8000;

    /// <summary>
    /// True when the bytes look like a binary file: a NUL among the first 8,000 bytes, the
    /// same heuristic git uses. Text in any real encoding does not contain NUL; almost every
    /// binary format does, early.
    /// </summary>
    /// <param name="bytes">The content to sniff.</param>
    public static bool LooksBinary(ReadOnlySpan<byte> bytes) =>
        bytes[..Math.Min(bytes.Length, BinarySniffLength)].IndexOf((byte)0) >= 0;

    /// <summary>Compares two versions line by line.</summary>
    /// <param name="before">The older version's lines.</param>
    /// <param name="after">The newer version's lines.</param>
    /// <returns>
    /// The full script, in order: every line of both versions appears exactly once, shared
    /// lines once as <see cref="LineChange.Same"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Either argument was null.</exception>
    public static IReadOnlyList<DiffLine> Compare(
        IReadOnlyList<string> before,
        IReadOnlyList<string> after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var script = new List<DiffLine>(Math.Max(before.Count, after.Count));
        Walk(before, 0, before.Count, after, 0, after.Count, script);
        return script;
    }

    /// <summary>
    /// Diffs one region of each side into the script, recursively, in linear space.
    /// </summary>
    private static void Walk(
        IReadOnlyList<string> before, int beforeStart, int beforeEnd,
        IReadOnlyList<string> after, int afterStart, int afterEnd,
        List<DiffLine> script)
    {
        // Shared head and tail first: cheap, and it is most of most diffs.
        while (beforeStart < beforeEnd && afterStart < afterEnd &&
               string.Equals(before[beforeStart], after[afterStart], StringComparison.Ordinal))
        {
            script.Add(new DiffLine(LineChange.Same, beforeStart, afterStart, before[beforeStart]));
            beforeStart++;
            afterStart++;
        }

        var sharedTail = 0;
        while (beforeEnd > beforeStart && afterEnd > afterStart &&
               string.Equals(before[beforeEnd - 1], after[afterEnd - 1], StringComparison.Ordinal))
        {
            beforeEnd--;
            afterEnd--;
            sharedTail++;
        }

        var n = beforeEnd - beforeStart;
        var m = afterEnd - afterStart;

        if (n == 0)
        {
            for (var j = afterStart; j < afterEnd; j++)
            {
                script.Add(new DiffLine(LineChange.Added, -1, j, after[j]));
            }
        }
        else if (m == 0)
        {
            for (var i = beforeStart; i < beforeEnd; i++)
            {
                script.Add(new DiffLine(LineChange.Removed, i, -1, before[i]));
            }
        }
        else if (FindMiddleSnake(before, beforeStart, n, after, afterStart, m) is { } snake)
        {
            if (snake.Cost <= 1)
            {
                // One insertion or one deletion apart: emitted by a single walk, which is
                // also what stops the recursion — a split here could hand back the whole
                // region and never get smaller.
                EmitNearIdentical(before, beforeStart, beforeEnd, after, afterStart, afterEnd, script);
            }
            else
            {
                Walk(before, beforeStart, beforeStart + snake.X, after, afterStart, afterStart + snake.Y, script);
                for (var i = 0; i < snake.Length; i++)
                {
                    script.Add(new DiffLine(
                        LineChange.Same,
                        beforeStart + snake.X + i,
                        afterStart + snake.Y + i,
                        before[beforeStart + snake.X + i]));
                }

                Walk(before, beforeStart + snake.X + snake.Length, beforeEnd,
                     after, afterStart + snake.Y + snake.Length, afterEnd, script);
            }
        }
        else
        {
            // The search hit its depth cap: the regions are unrelated. All of one out, all
            // of the other in.
            for (var i = beforeStart; i < beforeEnd; i++)
            {
                script.Add(new DiffLine(LineChange.Removed, i, -1, before[i]));
            }

            for (var j = afterStart; j < afterEnd; j++)
            {
                script.Add(new DiffLine(LineChange.Added, -1, j, after[j]));
            }
        }

        for (var i = 0; i < sharedTail; i++)
        {
            script.Add(new DiffLine(LineChange.Same, beforeEnd + i, afterEnd + i, before[beforeEnd + i]));
        }
    }

    /// <summary>
    /// Emits a region whose two sides differ by at most one line, found by a single walk.
    /// </summary>
    private static void EmitNearIdentical(
        IReadOnlyList<string> before, int beforeStart, int beforeEnd,
        IReadOnlyList<string> after, int afterStart, int afterEnd,
        List<DiffLine> script)
    {
        var i = beforeStart;
        var j = afterStart;

        while (i < beforeEnd || j < afterEnd)
        {
            if (i < beforeEnd && j < afterEnd &&
                string.Equals(before[i], after[j], StringComparison.Ordinal))
            {
                script.Add(new DiffLine(LineChange.Same, i, j, before[i]));
                i++;
                j++;
            }
            else if (beforeEnd - i > afterEnd - j)
            {
                script.Add(new DiffLine(LineChange.Removed, i, -1, before[i]));
                i++;
            }
            else
            {
                script.Add(new DiffLine(LineChange.Added, -1, j, after[j]));
                j++;
            }
        }
    }

    /// <summary>A middle snake: where the optimal path crosses the halfway diagonal.</summary>
    /// <param name="X">Where the snake starts, in lines into the before-region.</param>
    /// <param name="Y">Where it starts, in lines into the after-region.</param>
    /// <param name="Length">How many equal lines it runs for. May be zero.</param>
    /// <param name="Cost">The edit distance of the whole region.</param>
    private readonly record struct MiddleSnake(int X, int Y, int Length, int Cost);

    /// <summary>
    /// Finds the middle snake of the optimal path through one region, walking D-paths
    /// forward from the top-left and backward from the bottom-right until they overlap
    /// (Myers 1986, the linear-space refinement).
    /// </summary>
    /// <returns>The snake, or null when the search passed <see cref="MaximumSearchDepth"/>.</returns>
    private static MiddleSnake? FindMiddleSnake(
        IReadOnlyList<string> before, int beforeStart, int n,
        IReadOnlyList<string> after, int afterStart, int m)
    {
        var delta = n - m;
        var odd = (delta & 1) != 0;
        var half = (n + m + 1) / 2;
        var limit = Math.Min(half, MaximumSearchDepth);

        // Furthest-reaching x on each diagonal k, for the forward and the backward walk.
        // Indexed by k + half so k may run negative.
        var forward = new int[(2 * half) + 2];
        var backward = new int[(2 * half) + 2];
        forward[half + 1] = 0;
        backward[half + 1] = 0;

        for (var d = 0; d <= limit; d++)
        {
            for (var k = -d; k <= d; k += 2)
            {
                var x = k == -d || (k != d && forward[half + k - 1] < forward[half + k + 1])
                    ? forward[half + k + 1]
                    : forward[half + k - 1] + 1;
                var y = x - k;

                var snakeStartX = x;
                var snakeStartY = y;
                while (x < n && y < m &&
                       string.Equals(before[beforeStart + x], after[afterStart + y], StringComparison.Ordinal))
                {
                    x++;
                    y++;
                }

                forward[half + k] = x;

                // The overlap check the paper specifies: on odd delta, after extending a
                // forward path, against the backward paths of the previous step.
                if (odd && k - delta >= -(d - 1) && k - delta <= d - 1 &&
                    x + backward[half + (delta - k)] >= n)
                {
                    return new MiddleSnake(snakeStartX, snakeStartY, x - snakeStartX, (2 * d) - 1);
                }
            }

            for (var k = -d; k <= d; k += 2)
            {
                // The backward walk in mirrored coordinates: x counts lines from the end,
                // and the mirrored diagonal k corresponds to the forward diagonal delta - k.
                var x = k == -d || (k != d && backward[half + k - 1] < backward[half + k + 1])
                    ? backward[half + k + 1]
                    : backward[half + k - 1] + 1;
                var y = x - k;

                var snakeStartX = x;
                while (x < n && y < m &&
                       string.Equals(
                           before[beforeStart + n - 1 - x],
                           after[afterStart + m - 1 - y],
                           StringComparison.Ordinal))
                {
                    x++;
                    y++;
                }

                backward[half + k] = x;

                if (!odd && delta - k >= -d && delta - k <= d &&
                    x + forward[half + (delta - k)] >= n)
                {
                    // The snake just extended runs, in real coordinates, from (n - x, m - y)
                    // for as many lines as the extension covered.
                    return new MiddleSnake(n - x, m - y, x - snakeStartX, 2 * d);
                }
            }
        }

        return null;
    }

    /// <summary>Renders a script as a unified diff.</summary>
    /// <param name="beforeName">The older side's label, after <c>---</c>.</param>
    /// <param name="afterName">The newer side's label, after <c>+++</c>.</param>
    /// <param name="before">The older version, for its missing-newline note.</param>
    /// <param name="after">The newer version, for its missing-newline note.</param>
    /// <param name="script">The script from <see cref="Compare"/>.</param>
    /// <param name="context">Shared lines shown around each change.</param>
    /// <returns>The rendered lines; empty when the script holds no changes.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="context"/> was negative.</exception>
    public static IReadOnlyList<string> Unified(
        string beforeName,
        string afterName,
        SplitText before,
        SplitText after,
        IReadOnlyList<DiffLine> script,
        int context = 3)
    {
        ArgumentNullException.ThrowIfNull(beforeName);
        ArgumentNullException.ThrowIfNull(afterName);
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        ArgumentNullException.ThrowIfNull(script);
        ArgumentOutOfRangeException.ThrowIfNegative(context);

        if (script.All(line => line.Change == LineChange.Same))
        {
            return [];
        }

        var output = new List<string>
        {
            $"--- {beforeName}",
            $"+++ {afterName}",
        };

        // Hunks: runs of the script where changes sit within 2·context shared lines of each
        // other, each shown with up to `context` shared lines either side.
        var index = 0;
        while (index < script.Count)
        {
            if (script[index].Change == LineChange.Same)
            {
                index++;
                continue;
            }

            var start = index;
            var end = index;
            var sameRun = 0;
            for (var i = index + 1; i < script.Count; i++)
            {
                if (script[i].Change == LineChange.Same)
                {
                    sameRun++;
                    if (sameRun > 2 * context)
                    {
                        break;
                    }
                }
                else
                {
                    sameRun = 0;
                    end = i;
                }
            }

            var hunkFrom = Math.Max(0, ContextBack(script, start, context));
            var hunkTo = Math.Min(script.Count - 1, ContextForward(script, end, context));

            AppendHunk(output, before, after, script, hunkFrom, hunkTo);
            index = hunkTo + 1;
        }

        return output;
    }

    private static int ContextBack(IReadOnlyList<DiffLine> script, int from, int context)
    {
        var taken = 0;
        var i = from - 1;
        while (i >= 0 && taken < context && script[i].Change == LineChange.Same)
        {
            taken++;
            i--;
        }

        return from - taken;
    }

    private static int ContextForward(IReadOnlyList<DiffLine> script, int from, int context)
    {
        var taken = 0;
        var i = from + 1;
        while (i < script.Count && taken < context && script[i].Change == LineChange.Same)
        {
            taken++;
            i++;
        }

        return from + taken;
    }

    private static void AppendHunk(
        List<string> output,
        SplitText before,
        SplitText after,
        IReadOnlyList<DiffLine> script,
        int from,
        int to)
    {
        var beforeCount = 0;
        var afterCount = 0;
        var beforeFirst = -1;
        var afterFirst = -1;

        for (var i = from; i <= to; i++)
        {
            if (script[i].Change != LineChange.Added)
            {
                beforeCount++;
                if (beforeFirst < 0)
                {
                    beforeFirst = script[i].BeforeLine;
                }
            }

            if (script[i].Change != LineChange.Removed)
            {
                afterCount++;
                if (afterFirst < 0)
                {
                    afterFirst = script[i].AfterLine;
                }
            }
        }

        // Unified convention: one-based starts; an empty side names the line before it.
        var beforeStart = beforeCount == 0 ? BeforeOfEmptySide(script, from) : beforeFirst + 1;
        var afterStart = afterCount == 0 ? AfterOfEmptySide(script, from) : afterFirst + 1;

        output.Add(FormattableString.Invariant(
            $"@@ -{beforeStart},{beforeCount} +{afterStart},{afterCount} @@"));

        for (var i = from; i <= to; i++)
        {
            var line = script[i];
            output.Add(line.Change switch
            {
                LineChange.Same => $" {line.Text}",
                LineChange.Removed => $"-{line.Text}",
                _ => $"+{line.Text}",
            });

            var lastOfBefore = line.Change != LineChange.Added &&
                               line.BeforeLine == before.Lines.Count - 1 && before.EndsWithoutNewline;
            var lastOfAfter = line.Change != LineChange.Removed &&
                              line.AfterLine == after.Lines.Count - 1 && after.EndsWithoutNewline;
            if (lastOfBefore || lastOfAfter)
            {
                output.Add(@"\ No newline at end of file");
            }
        }
    }

    /// <summary>The one-based before-line a hunk with nothing removed sits after.</summary>
    private static int BeforeOfEmptySide(IReadOnlyList<DiffLine> script, int from)
    {
        for (var i = from - 1; i >= 0; i--)
        {
            if (script[i].BeforeLine >= 0)
            {
                return script[i].BeforeLine + 1;
            }
        }

        return 0;
    }

    /// <summary>The one-based after-line a hunk with nothing added sits after.</summary>
    private static int AfterOfEmptySide(IReadOnlyList<DiffLine> script, int from)
    {
        for (var i = from - 1; i >= 0; i--)
        {
            if (script[i].AfterLine >= 0)
            {
                return script[i].AfterLine + 1;
            }
        }

        return 0;
    }
}
