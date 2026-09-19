using SippBucket.Core.Hashing;
using SippBucket.Core.Model;

namespace SippBucket.Core.Repository;

/// <summary>A snapshot together with the ID it is filed under.</summary>
public sealed record SaveResult
{
    /// <summary>The snapshot's content hash.</summary>
    public required ContentHash SnapshotId { get; init; }

    /// <summary>The snapshot itself.</summary>
    public required Snapshot Snapshot { get; init; }

    /// <summary>
    /// What the after-save hook reported when it failed, ready to print; null when it ran
    /// clean or no hook is set (<see cref="SaveHooks"/>). The save itself stands either way.
    /// </summary>
    public string? AfterSaveNote { get; init; }
}

/// <summary>What a restore changed on disk.</summary>
public sealed record RestoreResult
{
    /// <summary>How many files were written or rewritten.</summary>
    public required int FilesWritten { get; init; }

    /// <summary>
    /// How many files were deleted because the snapshot lacked them. Only files head records
    /// and that still matched head, so their content is in the head the restore started
    /// from, which stays in history as the parent of <see cref="SnapshotId"/>.
    /// </summary>
    public required int FilesDeleted { get; init; }

    /// <summary>How many files were renamed to the snapshot's casing of their name.</summary>
    public int FilesRenamed { get; init; }

    /// <summary>
    /// Where files were kept, relative to the working folder: moved aside so the snapshot's
    /// version could take their name. Work no snapshot holds, and read-only files, which are
    /// never overwritten.
    /// </summary>
    public IReadOnlyList<string> KeptAside { get; init; } = [];

    /// <summary>
    /// Read-only files the snapshot does not have, left where they are rather than deleted,
    /// relative to the working folder.
    /// </summary>
    public IReadOnlyList<string> KeptReadOnly { get; init; } = [];

    /// <summary>
    /// The snapshot that records the folder after the restore, now head, whose parent is the
    /// head the restore started from. Empty when the folder already matched head, so there
    /// was nothing to record.
    /// </summary>
    public ContentHash SnapshotId { get; init; }
}
