namespace SippBucket.Core.Protocol;

/// <summary>
/// Thrown when a peer sends something the protocol does not allow.
/// </summary>
/// <remarks>
/// Always fatal to the connection. A peer that violates framing or fails authentication is
/// dropped rather than tolerated, because the alternative is guessing at what it meant.
/// </remarks>
public sealed class SipProtocolException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">What the peer did wrong.</param>
    public SipProtocolException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and a machine-readable fault.</summary>
    /// <param name="fault">Which fault this is, for code to branch on.</param>
    /// <param name="message">What the peer did wrong, for a person to read.</param>
    public SipProtocolException(SipProtocolFault fault, string message)
        : base(message)
    {
        Fault = fault;
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">What the peer did wrong.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SipProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with a fault, a message and an inner cause.</summary>
    /// <param name="fault">Which fault this is, for code to branch on.</param>
    /// <param name="message">What the peer did wrong, for a person to read.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SipProtocolException(SipProtocolFault fault, string message, Exception innerException)
        : base(message, innerException)
    {
        Fault = fault;
    }

    /// <summary>
    /// Which fault this is, independent of how the message happens to be worded.
    /// </summary>
    /// <remarks>
    /// Branch on this, never on <see cref="Exception.Message"/>. The message is prose and
    /// is expected to change; this is not.
    /// </remarks>
    public SipProtocolFault Fault { get; } = SipProtocolFault.Unspecified;

    /// <summary>Creates the exception with no detail.</summary>
    public SipProtocolException()
        : base("The peer violated the SippBucket protocol.")
    {
    }
}

