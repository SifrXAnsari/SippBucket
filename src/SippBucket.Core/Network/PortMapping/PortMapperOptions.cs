using System.Net;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// Where the port mapper sends its questions, and how long it waits for answers.
/// </summary>
/// <remarks>
/// <para>
/// Internal, and a type rather than constants, for the reason <c>SyncTuning</c> gives: a
/// deadline nobody can shorten is a deadline nobody can test. The tests point every field
/// that names a destination at a fake gateway on loopback, so nothing they run can reach the
/// real router. Production uses <see cref="Default"/>, whose destinations are the machine's
/// default gateway and the ports the protocols define.
/// </para>
/// <para>
/// Nothing here is configurable by a person. The port numbers are the protocols' own, and the
/// timings are the specifications' except where a remark says otherwise and why.
/// </para>
/// </remarks>
internal sealed record PortMapperOptions
{
    /// <summary>What <see cref="PortMapper"/> uses when it is not given anything else.</summary>
    public static PortMapperOptions Default { get; } = new();

    /// <summary>The gateway to ask, or null for this machine's IPv4 default gateway.</summary>
    public IPAddress? Gateway { get; init; }

    /// <summary>The UDP port PCP and NAT-PMP servers listen on.</summary>
    /// <remarks>
    /// 5351 for both: RFC 6886 section 3 sends NAT-PMP requests to "port 5351 of its
    /// configured gateway address", and RFC 6886 section 1.1 says PCP shares that port, with
    /// the version byte telling the two apart (0 for NAT-PMP, 2 for PCP).
    /// </remarks>
    public int PcpServerPort { get; init; } = 5351;

    /// <summary>The UDP port a UPnP device answers a unicast M-SEARCH on.</summary>
    /// <remarks>
    /// UPnP Device Architecture 2.0 section 1.3.2: the HOST of a unicast search is the device's
    /// address and "either port 1900 or the SEARCHPORT provided by the target device". No
    /// SEARCHPORT is known before the first answer, so it is 1900.
    /// </remarks>
    public int SsdpPort { get; init; } = 1900;

    /// <summary>PCP's initial retransmission time, IRT.</summary>
    /// <remarks>RFC 6887 section 8.1.1: "IRT ... SHOULD be 3 seconds".</remarks>
    public TimeSpan PcpInitialRetransmission { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>PCP's maximum retransmission time, MRT.</summary>
    /// <remarks>RFC 6887 section 8.1.1: "MRT ... SHOULD be 1024 seconds".</remarks>
    public TimeSpan PcpMaximumRetransmission { get; init; } = TimeSpan.FromSeconds(1024);

    /// <summary>
    /// How long a first PCP request is retransmitted before the gateway is taken not to speak
    /// PCP or NAT-PMP: the maximum retransmission duration, MRD.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>A deliberate departure from the RFC's default.</strong> RFC 6887 section 8.1.1
    /// says MRD "SHOULD be 0 (0 indicates no maximum)", and also that "Unless MRD is zero, the
    /// message exchange fails once MRD seconds have elapsed". With no maximum there is no
    /// fallback: a router that speaks only UPnP would be retried forever. Fifteen seconds
    /// covers three transmissions, at about 0, 3 and 9 seconds with IRT at 3.
    /// </para>
    /// <para>
    /// One probe covers NAT-PMP too. A NAT-PMP gateway answers a PCP request with its own
    /// "Unsupported Version" at once (RFC 6886 section 1.1), so silence to PCP is silence from
    /// both, and NAT-PMP's own 64-second give-up (RFC 6886 section 3.1) is spent only on a
    /// gateway that has already shown it speaks NAT-PMP.
    /// </para>
    /// </remarks>
    public TimeSpan PcpProbeDuration { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>NAT-PMP's first retransmission interval.</summary>
    /// <remarks>
    /// RFC 6886 section 3.1: the first retry after 250 ms, "the interval between attempts
    /// doubling each time".
    /// </remarks>
    public TimeSpan NatPmpInitialRetransmission { get; init; } = TimeSpan.FromMilliseconds(250);

    /// <summary>How many times one NAT-PMP request is sent before the gateway is given up on.</summary>
    /// <remarks>
    /// RFC 6886 section 3.1: "If, after sending its ninth attempt (and then waiting for 64
    /// seconds), the client has still received no response, then it SHOULD conclude that this
    /// gateway does not support NAT Port Mapping Protocol."
    /// </remarks>
    public int NatPmpAttempts { get; init; } = 9;

    /// <summary>How long to wait for an answer to each unicast M-SEARCH.</summary>
    /// <remarks>
    /// UPnP Device Architecture 2.0 section 1.3.2: a device "should respond within 1 second",
    /// and "The sender of the unicast request should wait at least 1 second for the response."
    /// </remarks>
    public TimeSpan SsdpWait { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>How many times the unicast M-SEARCH is sent.</summary>
    /// <remarks>
    /// UPnP Device Architecture 2.0 section 1.3.2: "Due to the unreliable nature of UDP,
    /// control points should send each M-SEARCH message more than once."
    /// </remarks>
    public int SsdpAttempts { get; init; } = 3;

    /// <summary>The deadline for one HTTP exchange with the gateway, reading included.</summary>
    /// <remarks>
    /// UPnP Device Architecture 2.0 section 3.2.2: "The service shall complete invoking the
    /// action and respond within 30 seconds, including expected transmission time." The same
    /// deadline bounds the description, which a device sends far faster.
    /// </remarks>
    public TimeSpan HttpTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The least time between two renewal requests.</summary>
    /// <remarks>
    /// RFC 6887 section 11.2.1: "renewal requests MUST NOT be sent less than four seconds
    /// apart". Only the tests shorten it, with lifetimes of seconds that no real gateway grants.
    /// </remarks>
    public TimeSpan MinimumRenewalSpacing { get; init; } = TimeSpan.FromSeconds(4);

    /// <summary>How long removing a mapping may take, the gateway's answer included.</summary>
    /// <remarks>
    /// Long enough for three PCP transmissions at IRT 3 seconds. A removal that is not
    /// answered is not retried beyond this: the mapping has a finite lifetime and ends on its
    /// own, which is the reason lifetimes exist.
    /// </remarks>
    public TimeSpan RemovalBudget { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>The largest device description read, in bytes. Anything larger is refused.</summary>
    /// <remarks>
    /// A real IGD description is a few kilobytes. The bound is what makes a hostile or broken
    /// device cost this process a known amount, whatever it sends.
    /// </remarks>
    public int MaximumDescriptionBytes { get; init; } = 128 * 1024;

    /// <summary>The largest SOAP response read, in bytes. Anything larger is refused.</summary>
    public int MaximumControlResponseBytes { get; init; } = 16 * 1024;

    /// <summary>The largest SSDP search response read, in bytes. Anything larger is ignored.</summary>
    public int MaximumSearchResponseBytes { get; init; } = 4 * 1024;
}
