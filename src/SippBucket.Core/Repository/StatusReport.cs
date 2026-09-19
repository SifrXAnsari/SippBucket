namespace SippBucket.Core.Repository;

/// <summary>
/// What has changed in the working folder since the newest snapshot.
/// </summary>
public sealed record StatusReport
{
    /// <summary>Files present now that the snapshot does not have.</summary>
    public required IReadOnlyList<string> Added { get; init; }

    /// <summary>Files whose content differs from the snapshot.</summary>
    public required IReadOnlyList<string> Modified { get; init; }

    /// <summary>Files in the snapshot that are gone from the working folder.</summary>
    public required IReadOnlyList<string> Removed { get; init; }

    /// <summary>How many tracked files are unchanged.</summary>
    public required int UnchangedCount { get; init; }

    /// <summary>
    /// What the scan did not read — links, which are never followed, and files or folders it
    /// could not read — each counted in none of the lists above.
    /// </summary>
    public IReadOnlyList<SkippedPath> Skipped { get; init; } = [];

    /// <summary>True when the working folder matches the newest snapshot exactly.</summary>
    public bool IsClean => Added.Count == 0 && Modified.Count == 0 && Removed.Count == 0;

    /// <summary>Total number of changed files.</summary>
    public int ChangeCount => Added.Count + Modified.Count + Removed.Count;
}
