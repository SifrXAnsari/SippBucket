using SippBucket.Core.Protocol;

namespace SippBucket.Core.Health;

/// <summary>
/// What one server was seen to do wrong: the strong evidence a health record keeps
/// (docs/PEER-HEALTH.md, "What a peer does").
/// </summary>
/// <remarks>
/// The numbers are stored in <c>health.json</c> and in the alerts log by name, never by value,
/// so the order here can change; a name, once written, keeps its meaning.
/// </remarks>
public enum HealthFault
{
    /// <summary>A block whose content did not match its hash.</summary>
    BadBlock,

    /// <summary>A snapshot that was not the one asked for, or that did not verify.</summary>
    WrongSnapshot,

    /// <summary>A path that tried to leave the folder, used a reserved name, or reached into <c>.sip</c>.</summary>
    UnsafePath,

    /// <summary>A block the server's own snapshot names, which it could not produce.</summary>
    MissingBlock,

    /// <summary>A malformed or out-of-order protocol message, or a malformed Server.ID record.</summary>
    MalformedMessage,

    /// <summary>A handshake with it that failed after it was reached.</summary>
    HandshakeFailure,

    /// <summary>It stopped responding part way through.</summary>
    Stall,

    /// <summary>A timestamp it sent, hours from this machine's clock.</summary>
    ClockSkew,

    /// <summary>A file it pushed that went to quarantine.</summary>
    QuarantinedPush,

    /// <summary>A direct message whose signature did not verify.</summary>
    BadSignature,

    /// <summary>More messages than the configured rate. Recorded, and never alerted: it may just be a chatty person.</summary>
    MessageVolume,
}

/// <summary>What the health record says about each fault.</summary>
public static class HealthFaults
{
    /// <summary>Whether a fault ever raises an alert. Message volume never does.</summary>
    /// <param name="fault">The fault.</param>
    /// <returns>False for <see cref="HealthFault.MessageVolume"/> alone.</returns>
    public static bool IsAlerted(HealthFault fault) => fault != HealthFault.MessageVolume;

    /// <summary>The fault in words, for listings and alerts.</summary>
    /// <param name="fault">The fault.</param>
    /// <returns>A short phrase, for example "bad blocks".</returns>
    public static string Describe(HealthFault fault) => fault switch
    {
        HealthFault.BadBlock => "blocks that did not match their hash",
        HealthFault.WrongSnapshot => "snapshots that were not the ones asked for",
        HealthFault.UnsafePath => "paths that tried to leave the folder or use reserved names",
        HealthFault.MissingBlock => "blocks its own snapshots name that it could not produce",
        HealthFault.MalformedMessage => "malformed or out-of-order messages",
        HealthFault.HandshakeFailure => "failed handshakes",
        HealthFault.Stall => "stalls part way through",
        HealthFault.ClockSkew => "timestamps hours from this machine's clock",
        HealthFault.QuarantinedPush => "pushed files that went to quarantine",
        HealthFault.BadSignature => "direct messages whose signature did not verify",
        HealthFault.MessageVolume => "messages over the configured rate",
        _ => fault.ToString(),
    };

    /// <summary>The fault a failed sync or served connection shows, from the protocol's own fault code.</summary>
    /// <param name="fault">The protocol fault.</param>
    /// <returns>The health fault, or null for one that says nothing about the peer.</returns>
    /// <remarks>
    /// <para>
    /// Only what the machine that was reached, or that proved which machine it is, can be
    /// blamed for. The rest maps to nothing:
    /// </para>
    /// <list type="bullet">
    /// <item><description>anything before a caller has proved which device it is (a stranger
    /// could have caused it): a timed-out or shed handshake, an unknown device, a device ID that
    /// does not match its key;</description></item>
    /// <item><description>the dialled address answering with another device's key, which is the
    /// address's doing (a lease handed to someone else), not the peer's;</description></item>
    /// <item><description>a connection ending part way through a frame, which a network or a
    /// machine going to sleep does as often as a faulty peer.</description></item>
    /// </list>
    /// <para>
    /// A peer refusing the folder in its second handshake message, which only the dialled
    /// device's key could have written, is a failed handshake: misconfiguration more often than
    /// anything worse, and worth knowing when it happens every poll. A different protocol
    /// version is not blamed: the preamble that says so is not authenticated, so it could come
    /// from whatever machine now has the address. The caller also blames nothing else that
    /// happens before the handshake has proved which machine it is talking to.
    /// </para>
    /// </remarks>
    public static HealthFault? FromProtocol(SipProtocolFault fault) => fault switch
    {
        SipProtocolFault.WrongSnapshot => HealthFault.WrongSnapshot,
        SipProtocolFault.InconsistentAncestry => HealthFault.WrongSnapshot,
        SipProtocolFault.MissingBlock => HealthFault.MissingBlock,
        SipProtocolFault.WrongBlock => HealthFault.MalformedMessage,
        SipProtocolFault.MalformedMessage => HealthFault.MalformedMessage,
        SipProtocolFault.MalformedBlock => HealthFault.MalformedMessage,
        SipProtocolFault.UnexpectedMessage => HealthFault.MalformedMessage,
        SipProtocolFault.FrameTooLarge => HealthFault.MalformedMessage,
        SipProtocolFault.AuthenticationFailed => HealthFault.MalformedMessage,
        SipProtocolFault.UnknownRepository => HealthFault.HandshakeFailure,
        SipProtocolFault.PeerStalled => HealthFault.Stall,
        _ => null,
    };
}
