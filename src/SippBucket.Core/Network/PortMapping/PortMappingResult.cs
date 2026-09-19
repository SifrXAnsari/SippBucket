using System.Globalization;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>What one protocol said when it was asked.</summary>
/// <param name="Protocol">The protocol tried.</param>
/// <param name="Failure">Why it did not produce a mapping.</param>
/// <param name="Detail">One line for a log or <c>sip doctor</c>, naming the protocol's own code where there was one.</param>
public sealed record PortMappingAttempt(
    PortMappingProtocol Protocol,
    PortMappingFailure Failure,
    string Detail);

/// <summary>
/// What <see cref="PortMapper.MapAsync"/> obtained, or why it obtained nothing.
/// </summary>
/// <remarks>
/// Exactly one of the two holds: <see cref="Mapping"/> is set and <see cref="Failure"/> is
/// <see cref="PortMappingFailure.None"/>, or <see cref="Mapping"/> is null and
/// <see cref="Failure"/> says why. <see cref="Attempts"/> lists every protocol that was tried
/// and did not produce the mapping, in the order tried, so a success reached through UPnP still
/// records that PCP was not answered.
/// </remarks>
public sealed class PortMappingResult
{
    private PortMappingResult(
        ActivePortMapping? mapping,
        PortMappingFailure failure,
        string summary,
        IReadOnlyList<PortMappingAttempt> attempts,
        TimeSpan? retryAfter)
    {
        Mapping = mapping;
        Failure = failure;
        Summary = summary;
        Attempts = attempts;
        RetryAfter = retryAfter;
    }

    /// <summary>The mapping obtained, or null when none was.</summary>
    public ActivePortMapping? Mapping { get; }

    /// <summary>True when a mapping was obtained.</summary>
    public bool Succeeded => Mapping is not null;

    /// <summary>Why nothing was obtained, or <see cref="PortMappingFailure.None"/> when something was.</summary>
    public PortMappingFailure Failure { get; }

    /// <summary>One line saying what happened, for a log or a status line.</summary>
    public string Summary { get; }

    /// <summary>Every protocol tried that did not produce the mapping, in the order tried.</summary>
    public IReadOnlyList<PortMappingAttempt> Attempts { get; }

    /// <summary>
    /// How long the gateway said the same request would keep failing, when it said so, or null.
    /// </summary>
    /// <remarks>
    /// Only PCP carries this. On an error response the Lifetime field "indicates how long
    /// clients should assume they'll get the same error response from that PCP server if they
    /// repeat the same request" (RFC 6887 section 7.2), and section 8.3 says the client
    /// "SHOULD NOT resend the same request for the indicated lifetime of the error (as limited
    /// by the sanity checking detailed in Section 15)". The limit here is a day. That number
    /// is this program's choice, not the RFC's: section 15 was not readable in full when this
    /// was written.
    /// </remarks>
    public TimeSpan? RetryAfter { get; }

    internal static PortMappingResult Obtained(ActivePortMapping mapping, IReadOnlyList<PortMappingAttempt> attempts)
    {
        var summary = string.Create(
            CultureInfo.InvariantCulture,
            $"{mapping.Protocol.Name()}: the gateway {mapping.Gateway} forwards TCP " +
            $"{mapping.ExternalAddress?.ToString() ?? "(external address unknown)"}:{mapping.ExternalPort} " +
            $"to {mapping.InternalAddress}:{mapping.InternalPort} until {mapping.ExpiresUtc:u}");

        return new PortMappingResult(mapping, PortMappingFailure.None, summary, attempts, null);
    }

    internal static PortMappingResult Failed(
        PortMappingFailure failure,
        string summary,
        IReadOnlyList<PortMappingAttempt> attempts,
        TimeSpan? retryAfter = null) =>
        new(null, failure, summary, attempts, retryAfter);
}
