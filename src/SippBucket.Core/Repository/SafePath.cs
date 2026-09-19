using System.Globalization;

namespace SippBucket.Core.Repository;

/// <summary>
/// Validates that a path taken from a snapshot really is a relative path inside the working
/// folder, before anything is written to it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> A snapshot arriving from a peer is attacker-controlled data.
/// <c>FileEntry.Path</c> was used to build a destination with
/// <c>Path.Combine(WorkingRoot, entry.Path)</c> and written to with no checking at all,
/// which is an arbitrary file write on this machine. Two mechanisms, both confirmed by
/// measurement rather than reasoning:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>Traversal.</b> <c>..\..\</c> segments escape the folder. A path ending in the user's
/// Startup folder gives persistence that survives cleaning the machine that sent it.
/// </description></item>
/// <item><description>
/// <b>Root replacement, which is the worse one.</b> <c>Path.Combine</c> DISCARDS the first
/// argument entirely when the second is absolute:
/// <c>Path.Combine(@"C:\repo", @"C:\Windows\System32\evil.dll")</c> returns
/// <c>C:\Windows\System32\evil.dll</c>. No <c>..</c> is needed and nothing looks unusual.
/// </description></item>
/// </list>
/// <para>
/// The blast radius is everything the user can write, because the daemon runs as the user:
/// every document on the disk, not only the synced folder. Writing to
/// <c>.sip/config.json</c> destroys the repository key and makes the block store
/// permanently unreadable, and that one needs no traversal at all.
/// </para>
/// <para>
/// <b>Reject, do not sanitise.</b> A path that fails these checks is not a mistake to be
/// tidied up — no honest client produces one. Syncthing's approach is to drop the peer, and
/// that is right: silently rewriting a hostile path leaves an attacker free to keep probing
/// for an encoding the sanitiser misses.
/// </para>
/// </remarks>
public static class SafePath
{
    /// <summary>Longest path this accepts, before it is joined to the working root.</summary>
    /// <remarks>
    /// Bounded so a peer cannot force an enormous allocation or defeat the Windows path
    /// limit in a way that produces a partially-created tree.
    /// </remarks>
    public const int MaximumLength = 1024;

    /// <summary>
    /// Names Windows still reserves for devices, in any directory and with any extension.
    /// Writing to one of these does not create a file; it talks to hardware.
    /// </summary>
    private static readonly string[] ReservedNames =
    [
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    /// <summary>
    /// Checks a snapshot path and, when it is safe, produces the absolute path to write to.
    /// </summary>
    /// <param name="relativePath">The path as recorded in a snapshot, with forward slashes.</param>
    /// <param name="workingRoot">The repository's working folder, already absolute.</param>
    /// <param name="absolutePath">Where the file may be written, when this returns true.</param>
    /// <param name="reason">Why the path was refused, when this returns false.</param>
    /// <returns>True when the path is a relative path resolving inside the working folder.</returns>
    public static bool TryResolve(
        string? relativePath,
        string workingRoot,
        out string absolutePath,
        out string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingRoot);

        absolutePath = string.Empty;

        if (string.IsNullOrWhiteSpace(relativePath))
        {
            reason = "the path is empty";
            return false;
        }

        if (relativePath.Length > MaximumLength)
        {
            reason = $"the path is {relativePath.Length} characters; the limit is {MaximumLength}";
            return false;
        }

        // Snapshots record forward slashes on every platform. A backslash is therefore
        // never legitimate here, and on Windows it is a separator — so accepting it would
        // let "a\\..\\..\\b" through a check that only looked at forward-slash segments.
        if (relativePath.Contains('\\', StringComparison.Ordinal))
        {
            reason = "the path contains a backslash; snapshot paths use forward slashes only";
            return false;
        }

        if (relativePath.Contains('\0', StringComparison.Ordinal))
        {
            reason = "the path contains a null character";
            return false;
        }

        // Catches "C:/x", "C:x" (drive-relative, which resolves against a per-drive current
        // directory), "/x", and "//server/share".
        if (Path.IsPathRooted(relativePath) ||
            relativePath.StartsWith('/') ||
            (relativePath.Length >= 2 && relativePath[1] == ':'))
        {
            reason = "the path is absolute or drive-qualified; it must be relative";
            return false;
        }

        // The extended-length and device prefixes bypass normal path parsing entirely.
        if (relativePath.StartsWith("\\\\", StringComparison.Ordinal) ||
            relativePath.StartsWith("//", StringComparison.Ordinal))
        {
            reason = "the path looks like a UNC or device path";
            return false;
        }

        foreach (var segment in relativePath.Split('/'))
        {
            if (segment.Length == 0)
            {
                reason = "the path has an empty segment";
                return false;
            }

            if (segment is "." or "..")
            {
                reason = "the path contains a '.' or '..' segment";
                return false;
            }

            // An alternate data stream rides on a colon: "notes.txt:hidden".
            if (segment.Contains(':', StringComparison.Ordinal))
            {
                reason = "a path segment contains a colon";
                return false;
            }

            // Windows strips trailing dots and spaces, so "evil.exe " and "evil.exe."
            // both land on "evil.exe" — a way to smuggle a name past a comparison.
            if (segment.EndsWith(' ') || segment.EndsWith('.'))
            {
                reason = "a path segment ends with a space or a dot";
                return false;
            }

            var stem = segment.Split('.')[0];
            foreach (var reserved in ReservedNames)
            {
                if (string.Equals(stem, reserved, StringComparison.OrdinalIgnoreCase))
                {
                    reason = $"'{segment}' uses the reserved device name {reserved}";
                    return false;
                }
            }
        }

        // The repository's own metadata is never a sync target. Overwriting config.json
        // destroys the encryption key and with it the whole store, and needs no traversal.
        var firstSegment = relativePath.Split('/')[0];
        if (string.Equals(firstSegment, RepositoryLayout.MetadataDirectoryName, StringComparison.OrdinalIgnoreCase))
        {
            reason = $"the path targets the {RepositoryLayout.MetadataDirectoryName} metadata directory";
            return false;
        }

        // Belt and braces. Everything above is a syntactic check; this one asks the
        // filesystem API where the path actually lands, which is the property that matters.
        var root = Path.GetFullPath(workingRoot);
        var rootWithSeparator = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;

        string candidate;
        try
        {
            candidate = Path.GetFullPath(
                Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        }
        catch (ArgumentException)
        {
            reason = "the path could not be resolved";
            return false;
        }
        catch (PathTooLongException)
        {
            reason = "the resolved path is too long";
            return false;
        }

        if (!candidate.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
        {
            reason = string.Create(
                CultureInfo.InvariantCulture,
                $"the path resolves outside the repository, to '{candidate}'");
            return false;
        }

        absolutePath = candidate;
        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Checks every path in a set, and throws on the first that is not safe.
    /// </summary>
    /// <param name="relativePaths">Paths from a snapshot.</param>
    /// <param name="workingRoot">The repository's working folder.</param>
    /// <exception cref="UnsafeSnapshotPathException">A path was not safe.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="relativePaths"/> was null.</exception>
    public static void ValidateAll(IEnumerable<string> relativePaths, string workingRoot)
    {
        ArgumentNullException.ThrowIfNull(relativePaths);

        foreach (var path in relativePaths)
        {
            if (!TryResolve(path, workingRoot, out _, out var reason))
            {
                throw new UnsafeSnapshotPathException(path, reason);
            }
        }
    }
}

/// <summary>
/// Thrown when a snapshot contains a path that would write outside the repository.
/// </summary>
/// <remarks>
/// This is never a recoverable condition and never sanitised away. A snapshot carrying such
/// a path did not come from an honest client, so the correct response is to reject the whole
/// snapshot and stop talking to the peer that sent it.
/// </remarks>
public sealed class UnsafeSnapshotPathException : Exception
{
    /// <summary>Creates the exception for a rejected path.</summary>
    /// <param name="path">The offending path, as it appeared in the snapshot.</param>
    /// <param name="reason">Why it was refused.</param>
    public UnsafeSnapshotPathException(string? path, string reason)
        : base($"Refusing a snapshot: the path '{path}' is not safe to write — {reason}. " +
               "An honest client does not produce this, so the snapshot was rejected in full.")
    {
        Path = path;
        Reason = reason;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public UnsafeSnapshotPathException(string message)
        : base(message)
    {
        Reason = string.Empty;
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public UnsafeSnapshotPathException(string message, Exception innerException)
        : base(message, innerException)
    {
        Reason = string.Empty;
    }

    /// <summary>Creates the exception with no detail.</summary>
    public UnsafeSnapshotPathException()
        : base("A snapshot contained a path that is not safe to write.")
    {
        Reason = string.Empty;
    }

    /// <summary>The offending path, when one was identified.</summary>
    public string? Path { get; }

    /// <summary>Why the path was refused.</summary>
    public string Reason { get; }
}
