using SippBucket.Core.Model;

namespace SippBucket.Core.Repository;

/// <summary>
/// What one scan of the working folder found: an entry per tracked file, and the paths it
/// did not read.
/// </summary>
/// <remarks>
/// <see cref="Files"/> holds an entry for a path the scan skipped only when an earlier
/// snapshot recorded one, carried forward unchanged; <see cref="Carried"/> says which. A
/// caller comparing the folder with a snapshot must not read the disk for those paths, and a
/// caller changing the folder must never reach through a link (see <see cref="IsUnderLink"/>).
/// </remarks>
internal sealed class WorkingTreeScan
{
    /// <summary>Every tracked file, read or carried, ordered by path.</summary>
    public required IReadOnlyList<FileEntry> Files { get; init; }

    /// <summary>What was not read, and why.</summary>
    public required IReadOnlyList<SkippedPath> Skipped { get; init; }

    /// <summary>The paths in <see cref="Files"/> whose entry was carried rather than read.</summary>
    public required IReadOnlySet<string> Carried { get; init; }

    /// <summary>
    /// True when <paramref name="path"/> was not read: it was skipped, or lies under a folder
    /// that was. Compared without regard to case, as the filesystem compares names.
    /// </summary>
    /// <param name="path">A path relative to the working folder, with forward slashes.</param>
    /// <returns>True when this scan says nothing about what is on disk at that path.</returns>
    public bool IsSkipped(string path)
    {
        foreach (var skipped in Skipped)
        {
            if (skipped.IsFolder
                    ? path.StartsWith(skipped.Path, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(path, skipped.Path, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when <paramref name="path"/> is a link the scan found, or lies under one. Compared
    /// without regard to case, as the filesystem compares names.
    /// </summary>
    /// <param name="path">A path relative to the working folder, with forward slashes.</param>
    /// <returns>True when nothing may be written or deleted at that path.</returns>
    public bool IsUnderLink(string path)
    {
        foreach (var skipped in Skipped)
        {
            if (skipped.Reason != SkipReason.Link)
            {
                continue;
            }

            if (skipped.IsFolder
                    ? path.StartsWith(skipped.Path, StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(path + "/", skipped.Path, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(path, skipped.Path, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
