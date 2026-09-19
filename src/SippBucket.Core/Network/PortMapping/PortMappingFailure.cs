namespace SippBucket.Core.Network.PortMapping;

/// <summary>Why a port mapping was not obtained, or stopped being held.</summary>
/// <remarks>
/// A value rather than a sentence, so that a status line and a test can both match on it
/// without depending on wording (standard B3). The sentence that goes with it is in
/// <see cref="PortMappingResult.Summary"/> and <see cref="PortMappingAttempt.Detail"/>.
/// </remarks>
public enum PortMappingFailure
{
    /// <summary>Nothing failed: the mapping was obtained, or is still held.</summary>
    None = 0,

    /// <summary>This machine has no IPv4 default gateway to ask.</summary>
    NoGateway = 1,

    /// <summary>
    /// The gateway could not be reached or did not answer in time. On a result, that is true
    /// of every protocol tried; on one attempt, of that protocol; on a held mapping, of every
    /// renewal up to its expiry.
    /// </summary>
    NoAnswer = 2,

    /// <summary>
    /// The gateway answered and said no: not authorized, out of resources, or an error this
    /// has no more specific value for. The detail names the protocol's own code.
    /// </summary>
    Refused = 3,

    /// <summary>
    /// The router already forwards the external port asked for to somewhere else, and this
    /// never asks for a different one it was not given.
    /// </summary>
    ExternalPortInUse = 4,

    /// <summary>
    /// The router offered only something this refuses to accept: a mapping that never
    /// expires, or one that forwards every external port rather than the one asked for.
    /// </summary>
    Unsafe = 5,

    /// <summary>
    /// Something answered with what this refused to read: too large, a DTD, a redirect, or
    /// an address other than the gateway's own.
    /// </summary>
    UntrustedAnswer = 6,

    /// <summary>An unexpected error in this program while renewing a held mapping.</summary>
    Fault = 7,
}
