using SippBucket.Core.Hashing;

namespace SippBucket.Core.Storage;

/// <summary>
/// Thrown when a block is asked for that the local store does not hold.
/// </summary>
/// <remarks>
/// During a sync this is expected and is how the engine discovers what to request from a
/// peer. Outside a sync it means the store is missing data a snapshot refers to.
/// </remarks>
public sealed class BlockNotFoundException : Exception
{
    /// <summary>Creates the exception for a named block.</summary>
    /// <param name="contentHash">The block that was not found.</param>
    public BlockNotFoundException(ContentHash contentHash)
        : base($"Block {contentHash.ToShortString()} is not in this store.")
    {
        ContentHash = contentHash;
    }

    /// <summary>Creates the exception with a custom message.</summary>
    /// <param name="message">The message.</param>
    public BlockNotFoundException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public BlockNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public BlockNotFoundException()
        : base("A block was not found in the store.")
    {
    }

    /// <summary>The block that was not found, when one was identified.</summary>
    public ContentHash ContentHash { get; }
}
