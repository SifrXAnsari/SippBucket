namespace SippBucket.Core.Repository;

/// <summary>
/// A file or folder in the working folder that a scan did not read, and why.
/// </summary>
/// <remarks>
/// <para>
/// A scan used to stop at the first entry it could not read, and the save, the status and
/// every pull stopped with it: one folder that refuses listing, such as the hidden
/// <c>My Music</c> link Windows keeps in every Documents folder, or one file another program
/// holds open, and the whole folder never saved or synced again (D-61, DATA-03). Now such an
/// entry is left out of the reading, listed here, and its last recorded state is carried
/// forward, so a path this machine could not look at is never recorded as deleted.
/// </para>
/// <para>
/// A link is never followed (DATA-01): a junction or symbolic link inside the folder points
/// somewhere the person did not choose to sync, and following it copied that content into
/// every snapshot and let a peer's deletion reach through it.
/// </para>
/// </remarks>
public sealed record SkippedPath
{
    /// <summary>
    /// The path, relative to the working folder with forward slashes. A folder's path ends
    /// with a slash, and everything under it was skipped with it.
    /// </summary>
    public required string Path { get; init; }

    /// <summary>Why it was not read.</summary>
    public required SkipReason Reason { get; init; }

    /// <summary>
    /// What was found: the link's target, or the error the filesystem gave. For display.
    /// </summary>
    public required string Detail { get; init; }

    /// <summary>True when the path is a folder, and everything under it was skipped.</summary>
    public bool IsFolder => Path.EndsWith('/');

    /// <summary>A one-line description ready to print.</summary>
    public string Describe() => Reason switch
    {
        SkipReason.Link => $"{Path} is a link to {Detail}; links are not followed",
        SkipReason.KeptChanging => $"{Path} changed every time it was read; what was last recorded for it is kept",
        SkipReason.InvalidName => $"{Path}: {Detail}; rename it to sync it",
        SkipReason.TooDeep => $"{Path} is {Detail}, deeper than a snapshot records; move it up to sync it",
        _ => $"{Path} could not be read ({Detail}); what was last recorded for it is kept",
    };
}

/// <summary>Why a scan did not read a path.</summary>
public enum SkipReason
{
    /// <summary>
    /// A junction or symbolic link. Never followed, and nothing is written or deleted
    /// through it.
    /// </summary>
    Link = 0,

    /// <summary>
    /// The filesystem refused it: a folder that cannot be listed, a file another program
    /// holds without sharing, a name Windows will not open by its own path.
    /// </summary>
    Unreadable = 1,

    /// <summary>A file that changed during every read of it, so no one state of it was seen.</summary>
    KeptChanging = 2,

    /// <summary>
    /// A name that is not valid Unicode: it holds half of a surrogate pair, which Windows allows
    /// and no snapshot can record, because it has no UTF-8 form (D-12). Never recorded, so there
    /// is nothing to carry.
    /// </summary>
    InvalidName = 3,

    /// <summary>
    /// A folder so deep that the paths under it have more segments than a snapshot's trees may
    /// nest (D-23). Nothing under it is read.
    /// </summary>
    TooDeep = 4,
}
