using System.Diagnostics;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// Notices when the gateway has restarted and forgotten its mappings, from the epoch every
/// answer carries.
/// </summary>
/// <remarks>
/// <para>
/// PCP and NAT-PMP gateways count seconds from when they last lost their mapping state, a
/// reboot for example, and put the count in every answer. A count that has not advanced as far
/// as this machine's own clock has means the state was lost in between. Both RFCs say what to do then: RFC 6887
/// section 8.5 says the client "promptly renews all its active port mapping leases", RFC 6886
/// section 3.6 that it "MUST immediately renew all its active port mapping leases".
/// </para>
/// <para>
/// The answer this is judged on is itself a renewal of the one mapping this machine holds
/// (both protocols carry the assigned port back in a renewal so a gateway that lost state can
/// recreate it), so the renewal the rules call for has already happened by the time a
/// restart is noticed. What noticing adds is the record: <see cref="Restarts"/> is what a
/// status line can report when the external port moves for no visible reason.
/// </para>
/// </remarks>
internal sealed class GatewayEpoch
{
    private bool _seen;
    private long _previousClientTimestamp;
    private uint _previousServerSeconds;

    /// <summary>How many times an answer showed the gateway had lost its mappings.</summary>
    public int Restarts { get; private set; }

    /// <summary>Checks a PCP answer's epoch, and records it.</summary>
    /// <param name="serverSeconds">The Epoch Time field.</param>
    /// <returns>True when the epoch is consistent with no restart since the last answer.</returns>
    public bool AcceptPcp(uint serverSeconds) =>
        Accept(serverSeconds, (clientSeconds, previousServer, currentServer) =>
            PcpEpochIsValid(clientSeconds, previousServer, currentServer));

    /// <summary>Checks a NAT-PMP answer's epoch, and records it.</summary>
    /// <param name="serverSeconds">The Seconds Since Start of Epoch field.</param>
    /// <returns>True when the epoch is consistent with no restart since the last answer.</returns>
    public bool AcceptNatPmp(uint serverSeconds) =>
        Accept(serverSeconds, (clientSeconds, previousServer, currentServer) =>
            NatPmpEpochIsValid(clientSeconds, previousServer, currentServer));

    /// <summary>RFC 6887 section 8.5's test, as a pure function.</summary>
    /// <param name="clientDeltaSeconds">Whole seconds elapsed on this machine since the previous answer.</param>
    /// <param name="previousServer">The previous answer's Epoch Time.</param>
    /// <param name="currentServer">This answer's Epoch Time.</param>
    /// <returns>False when the gateway has evidently lost state.</returns>
    /// <remarks>
    /// Section 8.5, in order. Time going backwards "by up to one second is not deemed invalid",
    /// so more than that is. Then with <c>client_delta</c> and <c>server_delta</c> the two
    /// elapsed times: invalid "If client_delta+2 &lt; server_delta - server_delta/16 or
    /// server_delta+2 &lt; client_delta - client_delta/16". The 2 allows for each clock's
    /// one-second resolution and the sixteenth for cheap clocks running up to 6.25% apart. The
    /// divisions are integer divisions, as the RFC's arithmetic on whole seconds implies.
    /// </remarks>
    public static bool PcpEpochIsValid(long clientDeltaSeconds, uint previousServer, uint currentServer)
    {
        if ((long)currentServer + 1 < previousServer)
        {
            return false;
        }

        var serverDelta = (long)currentServer - previousServer;

        return !(clientDeltaSeconds + 2 < serverDelta - (serverDelta / 16) ||
                 serverDelta + 2 < clientDeltaSeconds - (clientDeltaSeconds / 16));
    }

    /// <summary>RFC 6886 section 3.6's test, as a pure function.</summary>
    /// <param name="clientDeltaSeconds">Seconds elapsed on this machine since the previous answer.</param>
    /// <param name="previousServer">The previous answer's Seconds Since Start of Epoch.</param>
    /// <param name="currentServer">This answer's Seconds Since Start of Epoch.</param>
    /// <returns>False when the gateway has evidently lost state.</returns>
    /// <remarks>
    /// Section 3.6: the client's "conservative estimate" of the gateway's count is the last
    /// count plus 7/8 of the time elapsed on the client's clock, and the gateway is taken to
    /// have lost its mappings when the new count "is less than the client's conservative
    /// estimate by more than 2 seconds".
    /// </remarks>
    public static bool NatPmpEpochIsValid(long clientDeltaSeconds, uint previousServer, uint currentServer)
    {
        var estimate = previousServer + (clientDeltaSeconds * 7.0 / 8.0);
        return !(currentServer < estimate - 2);
    }

    private bool Accept(uint serverSeconds, Func<long, uint, uint, bool> isValid)
    {
        var now = Stopwatch.GetTimestamp();

        // RFC 6887 section 8.5: "If this is the first PCP response the client has received
        // from this PCP server, the Epoch Time value is treated as necessarily valid". NAT-PMP
        // has nothing earlier to compare with either.
        var valid = !_seen || isValid(
            (long)Stopwatch.GetElapsedTime(_previousClientTimestamp, now).TotalSeconds,
            _previousServerSeconds,
            serverSeconds);

        if (!valid)
        {
            Restarts++;
        }

        _seen = true;
        _previousClientTimestamp = now;
        _previousServerSeconds = serverSeconds;
        return valid;
    }
}
