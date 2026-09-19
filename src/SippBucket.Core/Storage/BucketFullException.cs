namespace SippBucket.Core.Storage;

/// <summary>
/// Thrown when a folder is at its quota and a save cannot be made room for.
/// </summary>
/// <remarks>
/// <para>
/// Carries the usage rather than only a message, so that whatever catches it can say what
/// would fix the problem instead of only that there is one. "Bucket full" names a dead end;
/// "full, 2.9 GiB of 3 GiB, and nothing is reclaimable — raise the quota or shorten
/// retention" names a decision.
/// </para>
/// <para>
/// It is thrown only after a collection has already been attempted, so by the time a user
/// sees it the program has done everything it can on their behalf.
/// </para>
/// </remarks>
public sealed class BucketFullException : Exception
{
    /// <summary>Creates the exception for a full bucket.</summary>
    /// <param name="usage">What the store holds and what could be freed.</param>
    /// <exception cref="ArgumentNullException"><paramref name="usage"/> was null.</exception>
    public BucketFullException(BucketUsage usage)
        : base(Describe(usage))
    {
        Usage = usage;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public BucketFullException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public BucketFullException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public BucketFullException()
        : base("This folder is at its storage quota.")
    {
    }

    /// <summary>What the store held when the save was refused.</summary>
    public BucketUsage? Usage { get; }

    private static string Describe(BucketUsage usage)
    {
        ArgumentNullException.ThrowIfNull(usage);

        var head = $"This folder is at its storage quota ({usage.Describe()}), so the save " +
                   "was refused. Your documents are untouched; only the new snapshot was " +
                   "not taken.";

        return usage.HasReclaimable
            ? $"{head} {BucketUsage.Bytes(usage.ReclaimableBytes)} could be reclaimed by " +
              "'sip bucket collect'."
            : $"{head} Nothing is reclaimable under the current retention policy — raise " +
              "the quota with 'sip bucket quota', or shorten retention with " +
              "'sip bucket keep'.";
    }
}
