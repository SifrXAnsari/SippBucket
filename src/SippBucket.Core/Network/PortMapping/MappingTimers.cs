using System.Security.Cryptography;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// When to retransmit a request and when to renew a mapping, as the RFCs lay them out.
/// </summary>
/// <remarks>
/// The random factors are drawn with <see cref="RandomNumberGenerator"/>. They are not
/// secrets; the point of the jitter is that many clients restarted together do not all ask
/// at the same instant, and any uniform source does that.
/// </remarks>
internal static class MappingTimers
{
    private const int RandomScale = 1_000_000;

    /// <summary>The first PCP retransmission timeout: <c>RT = (1 + RAND) * IRT</c>.</summary>
    /// <param name="initial">IRT.</param>
    /// <returns>RT.</returns>
    /// <remarks>
    /// RFC 6887 section 8.1.1, where RAND is "a random number chosen with a uniform
    /// distribution between -0.1 and +0.1".
    /// </remarks>
    public static TimeSpan FirstPcpTimeout(TimeSpan initial) => initial * (1 + Rand());

    /// <summary>The next PCP retransmission timeout: <c>RT = (1 + RAND) * MIN(2 * RTprev, MRT)</c>.</summary>
    /// <param name="previous">RTprev.</param>
    /// <param name="maximum">MRT.</param>
    /// <returns>RT.</returns>
    /// <remarks>RFC 6887 section 8.1.1.</remarks>
    public static TimeSpan NextPcpTimeout(TimeSpan previous, TimeSpan maximum)
    {
        var doubled = previous * 2;
        return (doubled < maximum ? doubled : maximum) * (1 + Rand());
    }

    /// <summary>When to send each renewal, measured from when the mapping was granted.</summary>
    /// <param name="lifetime">The lifetime the gateway granted.</param>
    /// <param name="minimumSpacing">The least time between two renewal requests.</param>
    /// <returns>Up to three offsets, in order, each before <paramref name="lifetime"/>.</returns>
    /// <remarks>
    /// RFC 6887 section 11.2.1: "send a single renewal request packet at a time chosen with
    /// uniform random distribution in the range 1/2 to 5/8 of expiration time", and if that is
    /// not answered, "the next renewal request should be sent 3/4 to 3/4 + 1/16 to expiration,
    /// and then another 7/8 to 7/8 + 1/32 to expiration", while "renewal requests MUST NOT be
    /// sent less than four seconds apart". NAT-PMP asks only that renewal begin "halfway to
    /// expiry time" (RFC 6886 section 3.3), which the same schedule meets, so both use it.
    /// UPnP IGD leaves the margin to the control point (WANIPConnection:1 section 2.2.21:
    /// "The value of threshold seconds is implementation dependent"), and uses it too.
    /// </remarks>
    public static IReadOnlyList<TimeSpan> RenewalOffsets(TimeSpan lifetime, TimeSpan minimumSpacing)
    {
        (double From, double Width)[] windows =
        [
            (1.0 / 2, 1.0 / 8),
            (3.0 / 4, 1.0 / 16),
            (7.0 / 8, 1.0 / 32),
        ];

        var offsets = new List<TimeSpan>(windows.Length);
        foreach (var (from, width) in windows)
        {
            var offset = lifetime * (from + (width * Unit()));
            if (offsets.Count > 0 && offset < offsets[^1] + minimumSpacing)
            {
                offset = offsets[^1] + minimumSpacing;
            }

            if (offset >= lifetime)
            {
                break;
            }

            offsets.Add(offset);
        }

        return offsets;
    }

    /// <summary>Uniform on [-0.1, +0.1].</summary>
    private static double Rand() => (Unit() * 0.2) - 0.1;

    /// <summary>Uniform on [0, 1].</summary>
    private static double Unit() => RandomNumberGenerator.GetInt32(0, RandomScale + 1) / (double)RandomScale;
}
