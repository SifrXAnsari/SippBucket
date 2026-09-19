namespace SippBucket.Core.Sync;

/// <summary>
/// Thrown when a sync would have to replace, move or delete a file that another program has
/// open, or that changed after the sync looked at it. Nothing in the working folder has been
/// touched when this is thrown, and the next cycle tries again.
/// </summary>
/// <remarks>
/// An <see cref="IOException"/>, so everything that already treats a file held open by
/// another application as "defer and retry" keeps doing so. Its own type so the message can
/// name the file: "connection failed" was the old wording for every IO error during a sync,
/// and for a document open in Word it was simply untrue.
/// </remarks>
public sealed class WorkingTreeBusyException : IOException
{
    /// <summary>Creates the exception for one file.</summary>
    /// <param name="relativePath">The file, relative to the working folder.</param>
    /// <param name="reason">What is wrong with it, completing "the file ...".</param>
    /// <param name="innerException">The underlying failure, if there was one.</param>
    public WorkingTreeBusyException(string relativePath, string reason, Exception? innerException)
        : base($"{relativePath} {reason}; nothing was changed and the sync will try again.", innerException)
    {
        RelativePath = relativePath;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public WorkingTreeBusyException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public WorkingTreeBusyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public WorkingTreeBusyException()
        : base("A file in the working folder is in use; the sync will try again.")
    {
    }

    /// <summary>The file, relative to the working folder, when one was identified.</summary>
    public string? RelativePath { get; }
}
