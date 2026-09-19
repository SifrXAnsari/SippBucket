namespace SippBucket.Core.Protocol;

/// <summary>
/// Thrown when a peer accepted a connection but then stopped making progress on it.
/// </summary>
/// <remarks>
/// <para>
/// This is the lid-closing case, and it needs no attacker: a laptop suspended mid-transfer
/// leaves the desktop holding a socket that is open, healthy by every check the operating
/// system makes, and never going to deliver another byte. TCP keepalive does not save this
/// — it is off by default, and when enabled the first probe is two hours away.
/// </para>
/// <para>
/// Derived from <see cref="IOException"/> deliberately: to every caller this is a transport
/// failure like any other, and the existing handling for a dropped connection is exactly
/// the right handling for a stalled one. Only the message differs, because the distinction
/// matters when reading a log.
/// </para>
/// </remarks>
public sealed class PeerStalledException : IOException
{
    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">What stalled, and for how long.</param>
    public PeerStalledException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">What stalled, and for how long.</param>
    /// <param name="innerException">The underlying failure.</param>
    public PeerStalledException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public PeerStalledException()
        : base("The peer stopped responding.")
    {
    }
}
