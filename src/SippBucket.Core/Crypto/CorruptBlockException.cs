using SippBucket.Core.Hashing;

namespace SippBucket.Core.Crypto;

/// <summary>
/// Thrown when a block fails its authentication tag or does not hash to the name it was
/// stored under.
/// </summary>
/// <remarks>
/// This is never a recoverable condition to paper over. It means the block was altered on
/// disk, altered in transit, or decrypted with the wrong repository key, and the caller
/// should refuse the data rather than use it.
/// </remarks>
public sealed class CorruptBlockException : Exception
{
    /// <summary>Creates the exception for a named block.</summary>
    /// <param name="contentHash">The block that failed verification.</param>
    public CorruptBlockException(ContentHash contentHash)
        : base($"Block {contentHash.ToShortString()} failed verification: " +
               "it was altered, truncated, or encrypted under a different repository key.")
    {
        ContentHash = contentHash;
    }

    /// <summary>Creates the exception with a custom message.</summary>
    /// <param name="message">The message.</param>
    public CorruptBlockException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public CorruptBlockException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public CorruptBlockException()
        : base("A block failed verification.")
    {
    }

    /// <summary>The block that failed verification, when one was identified.</summary>
    public ContentHash ContentHash { get; }
}
