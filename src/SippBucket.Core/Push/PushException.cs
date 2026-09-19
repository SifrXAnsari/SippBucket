namespace SippBucket.Core.Push;

/// <summary>
/// Thrown when a Direct Push connection is refused or ends before its work is done.
/// </summary>
/// <remarks>
/// Derived from <see cref="IOException"/>, as <see cref="Protocol.PeerStalledException"/> is:
/// to every caller this is a transport failure, and the handling for a dropped connection is
/// the right handling for a refused one. Branch on <see cref="Fault"/>, never on the message.
/// </remarks>
public sealed class PushException : IOException
{
    /// <summary>Creates the exception with a fault and a message.</summary>
    /// <param name="fault">Which fault this is, for code to branch on.</param>
    /// <param name="message">What happened, for a person to read.</param>
    public PushException(PushFault fault, string message)
        : base(message)
    {
        Fault = fault;
    }

    /// <summary>Creates the exception with a fault, a message and an inner cause.</summary>
    /// <param name="fault">Which fault this is, for code to branch on.</param>
    /// <param name="message">What happened, for a person to read.</param>
    /// <param name="innerException">The underlying failure.</param>
    public PushException(PushFault fault, string message, Exception innerException)
        : base(message, innerException)
    {
        Fault = fault;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">What happened.</param>
    public PushException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The underlying failure.</param>
    public PushException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public PushException()
        : base("The Direct Push connection failed.")
    {
    }

    /// <summary>Which fault this is, independent of how the message happens to be worded.</summary>
    public PushFault Fault { get; } = PushFault.Unspecified;
}
