namespace SippBucket.Core.Sync;

/// <summary>
/// How much the claim "in sync" is still worth, based only on how long ago it was last
/// true.
/// </summary>
/// <remarks>
/// <para>
/// This is the answer to the defect class that made P0 dangerous. Those failures were
/// <em>silent by construction</em>: a wedged read never returns, so there is no exception to
/// catch, no callback to fire and nothing to display. A status that only changes when
/// something reports a problem will never change, and the user goes on believing a green
/// tick that stopped meaning anything hours ago.
/// </para>
/// <para>
/// So freshness is computed from a clock rather than from events. It decays by default and
/// success refreshes it, which inverts the failure mode: a bug that stops syncing can no
/// longer also stop the display from noticing, because the display is not waiting to be
/// told. The worst a new silent failure can now do is let the status decay correctly.
/// </para>
/// </remarks>
public enum SyncFreshness
{
    /// <summary>Set up, but never yet synced with anything.</summary>
    /// <remarks>
    /// Deliberately not <see cref="Current"/>. Synced with nobody is not synced, and a
    /// folder that has never reached a peer is the state most likely to be mistaken for
    /// working — it looks calm because nothing has gone wrong yet.
    /// </remarks>
    NeverSynced = 0,

    /// <summary>Verified against every peer recently enough to be believed.</summary>
    Current = 1,

    /// <summary>
    /// Last verified longer ago than expected. Not yet a failure — a peer asleep for a few
    /// minutes lands here — but the interface stops saying "in sync" and starts saying when.
    /// </summary>
    Ageing = 2,

    /// <summary>
    /// Long enough since the last successful check that syncing should be assumed broken
    /// rather than slow.
    /// </summary>
    NotChecking = 3,

    /// <summary>
    /// No peers are configured, so there is nothing this copy could be out of date with.
    /// </summary>
    /// <remarks>
    /// Honest rather than flattering: it is not "in sync", because there is nothing to be in
    /// sync with, and a single-machine folder should not sit permanently accusing itself of
    /// being stale either.
    /// </remarks>
    NothingToSyncWith = 4,
}

/// <summary>
/// Turns the time of the last successful sync into a <see cref="SyncFreshness"/>.
/// </summary>
public static class Freshness
{
    /// <summary>Multiple of the poll interval after which "in sync" stops being claimed.</summary>
    /// <remarks>
    /// Two polls, not one. One missed poll is ordinary — a peer mid-reboot, a laptop that
    /// slept for ninety seconds — and a status that flickered to a warning every time one
    /// poll was late would train the user to ignore it, which costs more than the warning
    /// buys.
    /// </remarks>
    public const int AgeingAfterPolls = 2;

    /// <summary>Multiple of the poll interval after which syncing is assumed broken.</summary>
    /// <remarks>
    /// Ten polls is ten minutes at the default interval. Long enough that a sleeping laptop
    /// and a flaky network have both had every chance; short enough that a person who opens
    /// the tray over lunch finds out before the afternoon.
    /// </remarks>
    public const int NotCheckingAfterPolls = 10;

    /// <summary>Works out how much the last successful sync is still worth.</summary>
    /// <param name="lastSuccessUtc">When every peer was last reached, or null if never.</param>
    /// <param name="nowUtc">The current time.</param>
    /// <param name="pollInterval">How often a sync is attempted.</param>
    /// <param name="hasPeers">Whether any peer is configured at all.</param>
    /// <returns>The freshness to display.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="pollInterval"/> was not positive.</exception>
    public static SyncFreshness Evaluate(
        DateTimeOffset? lastSuccessUtc,
        DateTimeOffset nowUtc,
        TimeSpan pollInterval,
        bool hasPeers)
    {
        if (pollInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pollInterval), pollInterval, "The poll interval must be positive.");
        }

        if (!hasPeers)
        {
            return SyncFreshness.NothingToSyncWith;
        }

        if (lastSuccessUtc is null)
        {
            return SyncFreshness.NeverSynced;
        }

        var age = nowUtc - lastSuccessUtc.Value;

        // A clock that has gone backwards - a manual change, an NTP correction - would
        // otherwise read as a negative age and be treated as fresh forever. Treat it as
        // unknown rather than as good news.
        if (age < TimeSpan.Zero)
        {
            return SyncFreshness.Ageing;
        }

        if (age <= pollInterval * AgeingAfterPolls)
        {
            return SyncFreshness.Current;
        }

        return age <= pollInterval * NotCheckingAfterPolls
            ? SyncFreshness.Ageing
            : SyncFreshness.NotChecking;
    }
}
