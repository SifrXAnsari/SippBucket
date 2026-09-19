using System.Text.RegularExpressions;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>
/// Decides which files in the working folder the repository ignores.
/// </summary>
/// <remarks>
/// Patterns come from an optional <c>.sipignore</c> at the repository root, one per line,
/// with <c>#</c> starting a comment. A pattern supports <c>*</c> for any run of characters
/// within a path segment and <c>**</c> for any run across segments. A pattern ending in
/// <c>/</c> matches a directory and everything under it. This is a deliberately small
/// subset of what git supports: no negation, no anchoring rules to memorise.
/// </remarks>
public sealed partial class IgnoreRules
{
    private readonly IReadOnlyList<Regex> _patterns;
    private readonly IReadOnlyList<Regex> _directoryPatterns;

    private IgnoreRules(IReadOnlyList<Regex> patterns, IReadOnlyList<Regex> directoryPatterns)
    {
        _patterns = patterns;
        _directoryPatterns = directoryPatterns;
    }

    /// <summary>Rules that ignore nothing beyond the always-ignored metadata directory.</summary>
    public static IgnoreRules Empty { get; } = new IgnoreRules([], []);

    /// <summary>Loads rules from a <c>.sipignore</c> file, if one exists.</summary>
    /// <param name="ignoreFilePath">Full path to the ignore file.</param>
    /// <returns>The parsed rules, or <see cref="Empty"/> when there is no file.</returns>
    /// <exception cref="IOException">
    /// The file exists and could not be read, including when another program held it for
    /// longer than <see cref="SharingRetry.Patience"/>.
    /// </exception>
    /// <remarks>
    /// The file is the person's own, in the working folder, where an editor or a scanner may
    /// have it open for a moment; that is waited out (D-69), because a repository that failed
    /// to open over it would stop the folder syncing for a reason nobody could see. Read once,
    /// with a missing file meaning no rules, rather than asked about and then read.
    /// </remarks>
    public static IgnoreRules Load(string ignoreFilePath)
    {
        if (string.IsNullOrWhiteSpace(ignoreFilePath))
        {
            return Empty;
        }

        string[] lines;
        try
        {
            lines = SharingRetry.Run(() => File.ReadAllLines(ignoreFilePath));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return Empty;
        }

        return Parse(lines);
    }

    /// <summary>Parses the lines of an ignore file.</summary>
    /// <param name="lines">The file's lines.</param>
    /// <returns>The parsed rules.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="lines"/> was null.</exception>
    public static IgnoreRules Parse(IEnumerable<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);

        var patterns = new List<Regex>();
        var directoryPatterns = new List<Regex>();
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var compiled = Compile(line);
            patterns.Add(compiled);
            if (line.EndsWith('/'))
            {
                directoryPatterns.Add(compiled);
            }
        }

        return new IgnoreRules(patterns, directoryPatterns);
    }

    /// <summary>
    /// True when a folder, and therefore everything under it, is ignored, so a scan need not
    /// look inside it at all.
    /// </summary>
    /// <param name="relativeDirectory">A folder relative to the root, with forward slashes.</param>
    /// <returns>True for the metadata directory and for a folder a <c>name/</c> pattern names.</returns>
    /// <remarks>
    /// Only a pattern ending in <c>/</c> says anything about a folder's contents. A pattern
    /// such as <c>*.tmp</c> that happens to match a folder's name matches that name and
    /// nothing under it, so such a folder is still walked and its files judged one by one,
    /// exactly as before this existed. Pruning a folder the rules ignore also means a folder
    /// that cannot be listed, once named in <c>.sipignore</c>, is not reported on every scan.
    /// </remarks>
    public bool IsIgnoredDirectory(string relativeDirectory)
    {
        if (string.IsNullOrEmpty(relativeDirectory))
        {
            return false;
        }

        if (relativeDirectory.Equals(RepositoryLayout.MetadataDirectoryName, StringComparison.Ordinal))
        {
            return true;
        }

        foreach (var pattern in _directoryPatterns)
        {
            if (pattern.IsMatch(relativeDirectory))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>True when a repository-relative path should be ignored.</summary>
    /// <param name="relativePath">A path relative to the root, with forward slashes.</param>
    /// <returns>True when the file is ignored.</returns>
    public bool IsIgnored(string relativePath)
    {
        if (string.IsNullOrEmpty(relativePath))
        {
            return false;
        }

        // The metadata directory is never tracked, whatever the ignore file says.
        if (relativePath.Equals(RepositoryLayout.MetadataDirectoryName, StringComparison.Ordinal) ||
            relativePath.StartsWith(RepositoryLayout.MetadataDirectoryName + "/", StringComparison.Ordinal))
        {
            return true;
        }

        foreach (var pattern in _patterns)
        {
            if (pattern.IsMatch(relativePath))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Turns one ignore line into an anchored regular expression. Directory patterns get a
    /// trailing wildcard so everything beneath them is covered.
    /// </summary>
    private static Regex Compile(string pattern)
    {
        var isDirectory = pattern.EndsWith('/');
        var body = isDirectory ? pattern[..^1] : pattern;

        var builder = new System.Text.StringBuilder("^");
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (c == '*')
            {
                if (i + 1 < body.Length && body[i + 1] == '*')
                {
                    builder.Append(".*");
                    i++;
                }
                else
                {
                    builder.Append("[^/]*");
                }
            }
            else if (c == '?')
            {
                builder.Append("[^/]");
            }
            else
            {
                builder.Append(Regex.Escape(c.ToString()));
            }
        }

        // A directory pattern also matches its contents; a file pattern matches exactly.
        builder.Append(isDirectory ? "(/.*)?$" : "$");

        return new Regex(
            builder.ToString(),
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(1));
    }
}
