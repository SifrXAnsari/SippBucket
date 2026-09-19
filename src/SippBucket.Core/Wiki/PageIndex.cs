using System.Text;
using SippBucket.Core.Crypto;
using SippBucket.Core.Model;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;
using SippBucket.Core.Text;

namespace SippBucket.Core.Wiki;

/// <summary>One link written in a page.</summary>
public sealed record PageLink
{
    /// <summary>The target as the page wrote it, before resolution.</summary>
    public required string Target { get; init; }

    /// <summary>
    /// The page it names, as a path in the folder, or null: an outside URL, an asset, or a
    /// page that does not exist — which is how a page still to be written shows up.
    /// </summary>
    public string? ResolvedPage { get; init; }
}

/// <summary>
/// A folder's pages, their links and their backlinks, read from one snapshot (T-01).
/// </summary>
/// <remarks>
/// Built from what is saved, not from the working files: the daemon saves as you work, so
/// the two are moments apart, and an index over a snapshot is the same on every machine at
/// the same head — what a wiki's readers should agree on.
/// </remarks>
public sealed class WikiIndex
{
    private readonly Dictionary<string, IReadOnlyList<PageLink>> _links;
    private readonly Dictionary<string, List<string>> _backlinks;

    internal WikiIndex(
        IReadOnlyList<string> pages,
        Dictionary<string, IReadOnlyList<PageLink>> links,
        Dictionary<string, List<string>> backlinks)
    {
        Pages = pages;
        _links = links;
        _backlinks = backlinks;
    }

    /// <summary>Every page, ordered by path.</summary>
    public IReadOnlyList<string> Pages { get; }

    /// <summary>The links one page makes, in the order written. Empty for a page without any.</summary>
    /// <param name="page">The page's path.</param>
    public IReadOnlyList<PageLink> LinksFrom(string page) =>
        _links.TryGetValue(page, out var links) ? links : [];

    /// <summary>The pages that link to one page, ordered by path.</summary>
    /// <param name="page">The page's path.</param>
    public IReadOnlyList<string> BacklinksTo(string page) =>
        _backlinks.TryGetValue(page, out var from)
            ? [.. from.Order(StringComparer.OrdinalIgnoreCase)]
            : [];

    /// <summary>
    /// Finds one page from what a person typed: its path, or its name without the extension,
    /// when that names exactly one page.
    /// </summary>
    /// <param name="typed">What was typed.</param>
    /// <returns>The page's path, or null.</returns>
    public string? FindPage(string typed)
    {
        if (string.IsNullOrWhiteSpace(typed))
        {
            return null;
        }

        var normalized = typed.Replace('\\', '/').TrimStart('/');

        var exact = Pages.FirstOrDefault(page => string.Equals(page, normalized, StringComparison.Ordinal))
            ?? Pages.FirstOrDefault(page => string.Equals(page, normalized, StringComparison.OrdinalIgnoreCase));
        if (exact is not null)
        {
            return exact;
        }

        var matches = Pages
            .Where(page =>
                string.Equals(WithoutExtension(page), normalized, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(NameOf(page), normalized, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return matches.Count == 1 ? matches[0] : null;
    }

    private static string WithoutExtension(string page)
    {
        var dot = page.LastIndexOf('.');
        return dot > page.LastIndexOf('/') ? page[..dot] : page;
    }

    private static string NameOf(string page)
    {
        var slash = page.LastIndexOf('/');
        var name = slash < 0 ? page : page[(slash + 1)..];
        var dot = name.LastIndexOf('.');
        return dot > 0 ? name[..dot] : name;
    }
}

/// <summary>
/// Builds a <see cref="WikiIndex"/>: which files are pages, what each links to, and what
/// links back.
/// </summary>
/// <remarks>
/// <para>
/// A page is a Markdown file. Two spellings of link are read: <c>[text](target)</c> and
/// <c>[[Page Name]]</c>, the latter with an optional <c>|label</c>. A target with a URL
/// scheme is kept as written and resolves to no page; a relative one resolves against the
/// page's own folder, with <c>.md</c> tried when no extension is given; a bare
/// <c>[[name]]</c> also matches a page anywhere in the folder by its name, when exactly one
/// has it. An anchor (<c>#section</c>) is dropped before resolving.
/// </para>
/// <para>
/// This is an index, not a renderer: fenced code blocks and inline code are skipped so a
/// documented example is not counted as a link, but full CommonMark nesting is not
/// re-implemented here, and a bracket arrangement this parse misreads costs a link in a
/// listing, nothing more.
/// </para>
/// </remarks>
public static class PageIndex
{
    /// <summary>The most bytes a page is parsed at.</summary>
    public const long LargestParsedPage = 8 * 1024 * 1024;

    /// <summary>Whether a path is a page.</summary>
    /// <param name="path">The path, folder-relative.</param>
    public static bool IsPage(string path)
    {
        var extension = Path.GetExtension(path);
        return string.Equals(extension, ".md", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(extension, ".markdown", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Builds the index over one snapshot's pages.</summary>
    /// <param name="repository">The repository the pages' blocks are read from.</param>
    /// <param name="snapshot">The snapshot, usually head.</param>
    /// <param name="cancellationToken">Cancels the build.</param>
    /// <returns>The index.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    public static async Task<WikiIndex> BuildAsync(
        SipRepository repository,
        Snapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(snapshot);

        var pages = snapshot.Files
            .Where(file => IsPage(file.Path))
            .OrderBy(file => file.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var pagePaths = pages.Select(page => page.Path).ToList();

        var links = new Dictionary<string, IReadOnlyList<PageLink>>(StringComparer.Ordinal);
        var backlinks = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var page in pages)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (page.Size > LargestParsedPage)
            {
                continue;
            }

            byte[] bytes;
            try
            {
                bytes = await repository.ReadFileAsync(page, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is BlockNotFoundException or CorruptBlockException)
            {
                // A page whose blocks are not all here is still a page; it just shows no links.
                continue;
            }

            if (LineDiff.LooksBinary(bytes))
            {
                continue;
            }

            var targets = ExtractTargets(Encoding.UTF8.GetString(bytes));
            if (targets.Count == 0)
            {
                continue;
            }

            var resolved = new List<PageLink>(targets.Count);
            foreach (var target in targets)
            {
                var to = ResolveTarget(page.Path, target, pagePaths);
                resolved.Add(new PageLink { Target = target, ResolvedPage = to });

                if (to is not null && !string.Equals(to, page.Path, StringComparison.Ordinal))
                {
                    if (!backlinks.TryGetValue(to, out var from))
                    {
                        from = [];
                        backlinks[to] = from;
                    }

                    if (!from.Contains(page.Path, StringComparer.Ordinal))
                    {
                        from.Add(page.Path);
                    }
                }
            }

            links[page.Path] = resolved;
        }

        return new WikiIndex(pagePaths, links, backlinks);
    }

    /// <summary>Reads every link target out of one page's text, in order.</summary>
    internal static IReadOnlyList<string> ExtractTargets(string markdown)
    {
        var targets = new List<string>();
        var inFence = false;

        foreach (var rawLine in markdown.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("```", StringComparison.Ordinal) ||
                trimmed.StartsWith("~~~", StringComparison.Ordinal))
            {
                inFence = !inFence;
                continue;
            }

            if (inFence)
            {
                continue;
            }

            ScanLine(line, targets);
        }

        return targets;
    }

    /// <summary>Scans one line, skipping inline code spans.</summary>
    private static void ScanLine(string line, List<string> targets)
    {
        var inCode = false;
        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] == '`')
            {
                inCode = !inCode;
                continue;
            }

            if (inCode || line[i] != '[')
            {
                continue;
            }

            if (i + 1 < line.Length && line[i + 1] == '[')
            {
                var close = line.IndexOf("]]", i + 2, StringComparison.Ordinal);
                if (close < 0)
                {
                    continue;
                }

                var inner = line[(i + 2)..close];
                var pipe = inner.IndexOf('|', StringComparison.Ordinal);
                var target = (pipe < 0 ? inner : inner[..pipe]).Trim();
                if (target.Length > 0)
                {
                    targets.Add(target);
                }

                i = close + 1;
                continue;
            }

            var label = line.IndexOf(']', i + 1);
            if (label < 0 || label + 1 >= line.Length || line[label + 1] != '(')
            {
                continue;
            }

            var end = line.IndexOf(')', label + 2);
            if (end < 0)
            {
                continue;
            }

            var written = line[(label + 2)..end].Trim();
            if (TidyInlineTarget(written) is { Length: > 0 } target2)
            {
                targets.Add(target2);
            }

            i = end;
        }
    }

    /// <summary>An inline target as written, without its wrapping, title or anchor.</summary>
    private static string? TidyInlineTarget(string written)
    {
        var target = written;
        if (target.StartsWith('<'))
        {
            var close = target.IndexOf('>', StringComparison.Ordinal);
            if (close < 0)
            {
                return null;
            }

            target = target[1..close];
        }
        else
        {
            var space = target.IndexOf(' ', StringComparison.Ordinal);
            if (space >= 0)
            {
                target = target[..space];
            }
        }

        var anchor = target.IndexOf('#', StringComparison.Ordinal);
        if (anchor == 0)
        {
            return null;
        }

        return anchor > 0 ? target[..anchor] : target;
    }

    /// <summary>Resolves one written target to a page, or to null.</summary>
    private static string? ResolveTarget(string fromPage, string target, IReadOnlyList<string> pages)
    {
        if (target.Contains("://", StringComparison.Ordinal) ||
            target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var relative = target.Replace('\\', '/');

        // A bare wiki name with no path may live anywhere in the folder.
        if (!relative.Contains('/', StringComparison.Ordinal) && Path.GetExtension(relative).Length == 0)
        {
            var byName = pages
                .Where(page => string.Equals(NameWithoutExtension(page), relative, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (byName.Count == 1)
            {
                return byName[0];
            }
        }

        var folder = fromPage.Contains('/', StringComparison.Ordinal)
            ? fromPage[..fromPage.LastIndexOf('/')]
            : string.Empty;
        if (Combine(folder, relative) is not { } combined)
        {
            return null;
        }

        foreach (var candidate in Candidates(combined))
        {
            var match = pages.FirstOrDefault(page => string.Equals(page, candidate, StringComparison.Ordinal))
                ?? pages.FirstOrDefault(page => string.Equals(page, candidate, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                return match;
            }
        }

        return null;
    }

    private static IEnumerable<string> Candidates(string combined)
    {
        yield return combined;
        if (Path.GetExtension(combined).Length == 0)
        {
            yield return combined + ".md";
            yield return combined + ".markdown";
        }
    }

    private static string NameWithoutExtension(string page)
    {
        var slash = page.LastIndexOf('/');
        var name = slash < 0 ? page : page[(slash + 1)..];
        var dot = name.LastIndexOf('.');
        return dot > 0 ? name[..dot] : name;
    }

    /// <summary>Joins and normalises a relative target against a folder, refusing escapes.</summary>
    private static string? Combine(string folder, string relative)
    {
        var segments = new List<string>();
        if (folder.Length > 0)
        {
            segments.AddRange(folder.Split('/'));
        }

        foreach (var part in relative.Split('/'))
        {
            switch (part)
            {
                case "" or ".":
                    continue;
                case "..":
                    if (segments.Count == 0)
                    {
                        return null;
                    }

                    segments.RemoveAt(segments.Count - 1);
                    break;
                default:
                    segments.Add(part);
                    break;
            }
        }

        return segments.Count == 0 ? null : string.Join('/', segments);
    }
}
