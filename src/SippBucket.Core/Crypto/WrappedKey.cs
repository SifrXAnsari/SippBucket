namespace SippBucket.Core.Crypto;

/// <summary>
/// A repository key sealed behind a passphrase, as stored in <c>.sip/config.json</c>.
/// </summary>
/// <remarks>
/// The Argon2id cost is stored <em>with</em> the wrapping rather than assumed by the code
/// reading it. Two reasons, both of which would be painful to discover later: a repository
/// locked on a memory-constrained machine must still open on a roomier one, and the cost has
/// to be raisable as hardware improves without orphaning every repository that already
/// exists.
/// </remarks>
public sealed record WrappedKey
{
    /// <summary>The Argon2id salt, base64 encoded. Exactly 16 bytes when decoded.</summary>
    public required string Salt { get; init; }

    /// <summary>The XChaCha20-Poly1305 nonce, base64 encoded.</summary>
    public required string Nonce { get; init; }

    /// <summary>The wrapped repository key and its authentication tag, base64 encoded.</summary>
    public required string Ciphertext { get; init; }

    /// <summary>Argon2id memory cost in kibibytes.</summary>
    /// <remarks>
    /// Kibibytes, not bytes. The unit is named in the property because getting it wrong
    /// costs an hour and twenty gibibytes of thrashing, which is how it was established.
    /// </remarks>
    public required long MemoryKib { get; init; }

    /// <summary>Argon2id iteration count.</summary>
    public required long Passes { get; init; }

    /// <summary>Argon2id degree of parallelism. Always 1 on this stack.</summary>
    public required int Parallelism { get; init; }
}

/// <summary>Thrown when a passphrase does not open a wrapped key.</summary>
/// <remarks>
/// Carries no detail on purpose. "Wrong passphrase" is the only thing the caller may learn
/// and the only thing worth saying — anything about how close it was, or which part failed,
/// is a gift to whoever is guessing.
/// </remarks>
public sealed class WrongPassphraseException : Exception
{
    /// <summary>Creates the exception.</summary>
    public WrongPassphraseException()
        : base("That passphrase does not open this repository.")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public WrongPassphraseException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public WrongPassphraseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Thrown when a stored key wrapping is structurally unusable.</summary>
/// <remarks>
/// Distinct from <see cref="WrongPassphraseException"/>, and the distinction matters to the
/// person on the other end: a wrong passphrase means try again, whereas this means the file
/// is damaged or was written by something else, and no amount of retyping will help.
/// </remarks>
public sealed class InvalidKeyWrapException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">What was wrong with the stored wrapping.</param>
    public InvalidKeyWrapException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">What was wrong with the stored wrapping.</param>
    /// <param name="innerException">The underlying failure.</param>
    public InvalidKeyWrapException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public InvalidKeyWrapException()
        : base("The stored key wrapping is not valid.")
    {
    }
}
