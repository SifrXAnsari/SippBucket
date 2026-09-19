namespace SippBucket.Core.Platform;

/// <summary>How two folders on Windows relate: the same folder, one inside the other, or neither.</summary>
/// <remarks>
/// Compared as Windows compares names, ignoring case, on full paths with no trailing separator, and
/// only on whole components, so <c>C:\Inbox2</c> is not inside <c>C:\Inbox</c>.
/// </remarks>
public static class FolderPaths
{
    /// <summary>A folder's full path with no trailing separator, for comparing.</summary>
    /// <param name="folder">The folder.</param>
    /// <returns>Its full path.</returns>
    /// <exception cref="ArgumentException">The path is blank or not a path.</exception>
    public static string Normalize(string folder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder));
    }

    /// <summary>Whether a path is a folder, or is inside it.</summary>
    /// <param name="path">The path.</param>
    /// <param name="folder">The folder.</param>
    /// <returns>True when <paramref name="path"/> is <paramref name="folder"/> or anything under it.</returns>
    /// <exception cref="ArgumentException">A path is blank or not a path.</exception>
    public static bool IsSameOrInside(string path, string folder)
    {
        var candidate = Normalize(path);
        var root = Normalize(folder);

        return string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase) ||
               candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
