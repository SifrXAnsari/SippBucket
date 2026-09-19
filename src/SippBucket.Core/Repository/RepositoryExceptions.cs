using SippBucket.Core.Hashing;

namespace SippBucket.Core.Repository;

/// <summary>Thrown when a command needs a repository and there is none.</summary>
/// <remarks>
/// Only for "there is no repository here". A repository that is there but cannot be read is
/// <see cref="RepositoryUnreadableException"/>: this one used to carry both, with whole
/// sentences passed in as the directory, so the person read "No SippBucket repository at
/// 'The repository at … has neither a key…'" about a folder that plainly had one (D-66).
/// </remarks>
public sealed class RepositoryNotFoundException : Exception
{
    /// <summary>Creates the exception for a directory that had no repository above it.</summary>
    /// <param name="directory">Where the search started.</param>
    public RepositoryNotFoundException(string directory)
        : base($"No SippBucket repository at '{directory}' or in any folder above it. " +
               "Run 'sip init' to create one.")
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RepositoryNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public RepositoryNotFoundException()
        : base("No SippBucket repository was found.")
    {
    }
}

/// <summary>Thrown when initialising a folder that already holds a repository.</summary>
public sealed class RepositoryAlreadyExistsException : Exception
{
    /// <summary>Creates the exception for a folder that is already a repository.</summary>
    /// <param name="directory">The folder.</param>
    public RepositoryAlreadyExistsException(string directory)
        : base($"'{directory}' is already a SippBucket repository.")
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RepositoryAlreadyExistsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public RepositoryAlreadyExistsException()
        : base("That folder is already a SippBucket repository.")
    {
    }
}

/// <summary>Why a repository that exists could not be opened.</summary>
public enum RepositoryUnreadableReason
{
    /// <summary>No detail was given.</summary>
    Unspecified = 0,

    /// <summary><c>config.json</c> is not valid JSON, is empty, or is missing a setting.</summary>
    DamagedConfig = 1,

    /// <summary><c>config.json</c> holds neither the key nor a passphrase-wrapped key.</summary>
    MissingKey = 2,

    /// <summary><c>config.json</c> holds a key that is not a repository key.</summary>
    DamagedKey = 3,

    /// <summary>The repository was written by a newer SippBucket than this one.</summary>
    NewerFormat = 4,
}

/// <summary>
/// Thrown when a folder holds a repository that this build cannot open: its config is
/// damaged, or it was written by a newer SippBucket.
/// </summary>
/// <remarks>
/// <para>
/// Its own type because the person's next step is the opposite of the one for
/// <see cref="RepositoryNotFoundException"/>. "There is no repository here" means run
/// <c>sip init</c> or change folder; "there is one and it cannot be read" means leave it
/// alone and fix or update something, and running <c>sip init</c> would be refused anyway.
/// Both used to arrive as the first, so a too-new format read as a missing repository
/// (D-66).
/// </para>
/// <para>
/// Nothing is written on the way to throwing this, so the folder is exactly as it was.
/// </para>
/// </remarks>
public sealed class RepositoryUnreadableException : Exception
{
    /// <summary>Creates the exception for a repository that cannot be opened.</summary>
    /// <param name="workingRoot">The repository's folder.</param>
    /// <param name="reason">Why it cannot be opened.</param>
    /// <param name="detail">
    /// The rest of the sentence, starting lower case: what is wrong, and what to do.
    /// </param>
    /// <param name="innerException">The underlying failure, when there is one.</param>
    internal RepositoryUnreadableException(
        string workingRoot,
        RepositoryUnreadableReason reason,
        string detail,
        Exception? innerException = null)
        : base($"The SippBucket repository at '{workingRoot}' cannot be opened: {detail}", innerException)
    {
        WorkingRoot = workingRoot;
        Reason = reason;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public RepositoryUnreadableException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RepositoryUnreadableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public RepositoryUnreadableException()
        : base("A SippBucket repository was found but cannot be opened.")
    {
    }

    /// <summary>The repository's folder, when known.</summary>
    public string? WorkingRoot { get; }

    /// <summary>Why it cannot be opened.</summary>
    public RepositoryUnreadableReason Reason { get; }
}

/// <summary>
/// Thrown when a repository needs a passphrase before it can be opened.
/// </summary>
/// <remarks>
/// Its own type rather than a generic failure, because the caller's correct response is
/// specific and nothing else produces it: ask for a passphrase and call
/// <c>SipRepository.Unlock</c>. A tray that cannot distinguish this from "the folder is
/// broken" will show the wrong thing at the only moment the lock feature is visible.
/// </remarks>
public sealed class RepositoryLockedException : Exception
{
    /// <summary>Creates the exception for a locked folder.</summary>
    /// <param name="workingRoot">The folder that is locked.</param>
    public RepositoryLockedException(string workingRoot)
        : base($"The copy of this repository at {workingRoot} is locked on this machine. " +
               "A passphrase is needed to open it.")
    {
        WorkingRoot = workingRoot;
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RepositoryLockedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public RepositoryLockedException()
        : base("This repository is locked on this machine.")
    {
    }

    /// <summary>The folder that is locked, when known.</summary>
    public string? WorkingRoot { get; }
}

/// <summary>Thrown when a snapshot is asked for that this replica does not hold.</summary>
public sealed class SnapshotNotFoundException : Exception
{
    /// <summary>Creates the exception for a named snapshot.</summary>
    /// <param name="snapshotId">The snapshot that was not found.</param>
    public SnapshotNotFoundException(ContentHash snapshotId)
        : base($"Snapshot {snapshotId.ToShortString()} is not in this repository. " +
               "In simple mode only the newest snapshot is kept.")
    {
        SnapshotId = snapshotId;
    }

    /// <summary>Creates the exception for a snapshot whose file could not be read.</summary>
    /// <param name="snapshotId">The snapshot that could not be read.</param>
    /// <param name="innerException">Why the file was unreadable.</param>
    public SnapshotNotFoundException(ContentHash snapshotId, Exception innerException)
        : base($"Snapshot {snapshotId.ToShortString()} is present but could not be read.",
               innerException)
    {
        SnapshotId = snapshotId;
    }

    /// <summary>Creates the exception with a custom message.</summary>
    /// <param name="message">The message.</param>
    public SnapshotNotFoundException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SnapshotNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public SnapshotNotFoundException()
        : base("That snapshot is not in this repository.")
    {
    }

    /// <summary>The snapshot that was not found, when one was identified.</summary>
    public ContentHash SnapshotId { get; }
}
