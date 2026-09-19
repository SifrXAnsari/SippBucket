using System.Globalization;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Sync;

/// <summary>
/// Everything the interface is allowed to say about one folder, and nothing it is not.
/// </summary>
/// <remarks>
/// <para>
/// This type exists so that the tray cannot invent a status. Previously the tray read two
/// loose properties and composed a sentence, which is how "synced" came to mean "the last
/// cycle did not throw" — the display was doing the reasoning, and it reasoned wrongly
/// because it had almost nothing to reason from.
/// </para>
/// <para>
/// The design research for this product listed nine states the interface must express and
/// noted that the implementation had two. The gap was not a rendering problem: the states
/// did not exist in the code, so anything the display could not express collapsed into the
/// tick. Putting them here, in one type, means a new surface — the tray, the CLI, a future
/// window — gets all nine for free and cannot quietly support fewer.
/// </para>
/// </remarks>
public sealed record FolderStatus
{
    /// <summary>The repository's display name.</summary>
    public required string FolderName { get; init; }

    /// <summary>How much the last successful sync is still worth.</summary>
    public required SyncFreshness Freshness { get; init; }

    /// <summary>When every peer was last reached, or null if that has never happened.</summary>
    public DateTimeOffset? LastSyncUtc { get; init; }

    /// <summary>When a cycle last ran, whatever it concluded.</summary>
    public DateTimeOffset? LastAttemptUtc { get; init; }

    /// <summary>How many cycles in a row have failed to reach every peer.</summary>
    public int ConsecutiveFailures { get; init; }

    /// <summary>Why the last cycle did not fully sync, or null if it did.</summary>
    public string? LastFailureReason { get; init; }

    /// <summary>
    /// Why the last cycle was skipped, or why a peer's changes were not applied in it,
    /// because another operation was writing to this folder or it changed under the pull;
    /// null when the last cycle ran and applied everything it was offered.
    /// </summary>
    /// <remarks>
    /// Not a failure, so it changes no headline of its own: nothing is marked synced while
    /// it holds, so freshness keeps decaying on its clock, which is what says so if it goes
    /// on (D-38); and a deferred pull that learned how far behind this copy is still leads
    /// with "Behind … by N".
    /// </remarks>
    public string? SkippedReason { get; init; }

    /// <summary>Why this machine is not serving other peers, or null when it is.</summary>
    public string? ServerFault { get; init; }

    /// <summary>Whether a transfer is in progress, and how far along.</summary>
    public TransferProgress? Transfer { get; init; }

    /// <summary>One entry per configured peer.</summary>
    public IReadOnlyList<PeerStatus> Peers { get; init; } = [];

    /// <summary>Files kept under both versions because two machines changed them at once.</summary>
    /// <remarks>
    /// Carried in the status, and deliberately not as an alert. Nothing was lost and nothing
    /// is urgent, so this is something the folder mentions rather than something the program
    /// interrupts anyone about.
    /// </remarks>
    public IReadOnlyList<string> RecentConflicts { get; init; } = [];

    /// <summary>
    /// What the last save here did not read: links, which are never followed, and files or
    /// folders it could not read, whose last recorded state is kept instead.
    /// </summary>
    /// <remarks>
    /// Mentioned in <see cref="Detail"/> and not made a failure. The rest of the folder saved
    /// and synced, and the commonest case — the <c>My Music</c> link in a Documents folder —
    /// is permanent and harmless; a folder that read as unhealthy for as long as it existed
    /// would teach the person to ignore the icon.
    /// </remarks>
    public IReadOnlyList<SkippedPath> NotSynced { get; init; } = [];

    /// <summary>True when this machine's copy has a passphrase set.</summary>
    /// <remarks>
    /// Says a passphrase <em>exists</em>, not that the folder is sealed right now. The two
    /// are different facts and conflating them produced a status that was wrong in the most
    /// embarrassing possible way: a folder being actively synced, with its key in memory,
    /// described as "contents unreadable". Caught by an adversarial review of the design
    /// boards, where the drawing was right and the code was wrong.
    /// </remarks>
    public bool HasPassphrase { get; init; }

    /// <summary>
    /// True when the key is in memory and the folder can actually be read right now.
    /// </summary>
    /// <remarks>
    /// A repository that is open at all has its key loaded — that is what opening it means —
    /// so anything reporting on a running service sets this. It is false only where a
    /// surface is describing a folder it could <em>not</em> open, which is the one case the
    /// word "locked" honestly applies to.
    /// </remarks>
    public bool IsUnlockedForSession { get; init; }

    /// <summary>Storage use against the folder's quota, when one is set.</summary>
    public BucketUsage? Bucket { get; init; }

    /// <summary>True when this folder is genuinely current and serving.</summary>
    public bool IsHealthy =>
        ServerFault is null
        && ConsecutiveFailures == 0
        && Freshness is SyncFreshness.Current or SyncFreshness.NothingToSyncWith
        && (Bucket is null || !Bucket.IsFull);

    /// <summary>
    /// The single line a person reads to decide whether their work is safe.
    /// </summary>
    /// <remarks>
    /// Ordered worst-first on purpose. When several things are true at once the interface
    /// must lead with the one that would change what the user does next — a full bucket
    /// stops new saves, so it outranks a peer being asleep, which is normal.
    /// </remarks>
    public string Headline
    {
        get
        {
            if (ServerFault is not null)
            {
                return "Not serving peers";
            }

            if (Bucket is { IsFull: true })
            {
                return $"Bucket full · {Bucket.Describe()}";
            }

            if (Freshness == SyncFreshness.NotChecking)
            {
                return LastSyncUtc is { } last
                    ? $"Sync is not running · last checked {Local(last)}"
                    : "Sync is not running";
            }

            if (Transfer is { } transfer)
            {
                return transfer.Describe();
            }

            // Ahead of every other failure, and not merely for emphasis. A peer is only ever
            // behind-by-N when it was reached and the pull then failed or was deferred, so this
            // state arrives with a cycle that did not sync — and placed after the failure lines
            // below, as it was, it could never be shown: those lines would say a peer that had
            // just answered was "offline since" its last success. It also outranks "never synced",
            // because a first pull that learned the head and then failed is exactly when the
            // number matters.
            if (Peers.FirstOrDefault(p => p.SnapshotsBehind > 0) is { } ahead)
            {
                return $"Behind {ahead.Name} by {ahead.SnapshotsBehind} snapshot(s)";
            }

            if (Freshness == SyncFreshness.NeverSynced)
            {
                return "Set up, not yet synced with anything";
            }

            if (Freshness == SyncFreshness.NothingToSyncWith)
            {
                return "No peers set up yet";
            }

            if (ConsecutiveFailures > 0)
            {
                var offline = Peers.Where(p => !p.IsReachable).ToList();

                // A peer that answered and then failed is on the network; saying it is offline
                // would send the person to check cables for a fault in the data (D-58).
                var answered = Peers.Where(p => p.IsReachable && p.SyncFailed).ToList();
                if (offline.Count == 0 && answered.Count == 1)
                {
                    return $"{answered[0].Name} answered but did not sync · still safe locally";
                }

                if (offline.Count == 0 && answered.Count > 1)
                {
                    return $"{answered.Count} of {Peers.Count} peers answered but did not sync · still safe locally";
                }

                if (offline.Count == 1)
                {
                    return offline[0].LastSeenUtc is { } seen
                        ? $"{offline[0].Name} offline since {Local(seen)} · still safe locally"
                        : $"{offline[0].Name} unreachable · still safe locally";
                }

                return $"{offline.Count} of {Peers.Count} peers unreachable · still safe locally";
            }

            if (Freshness == SyncFreshness.Ageing)
            {
                return LastSyncUtc is { } last
                    ? $"Last checked {Local(last)}"
                    : "Last check is overdue";
            }

            return LastSyncUtc is { } current
                ? $"In sync · {Local(current)}"
                : "In sync";
        }
    }

    /// <summary>
    /// A second line, when there is something true worth adding. Null when there is not.
    /// </summary>
    public string? Detail
    {
        get
        {
            var parts = new List<string>();

            if (HasPassphrase)
            {
                // The distinction a running daemon has to make. "Contents unreadable" about
                // a folder this process is actively syncing would be false, and falsely
                // reassuring in the direction that matters — it implies a protection that
                // is not in force while the session is open.
                parts.Add(IsUnlockedForSession
                    ? "Passphrase set · unlocked for this session"
                    : "Locked on this machine · contents unreadable");
            }

            if (RecentConflicts.Count == 1)
            {
                parts.Add($"Both versions kept · {RecentConflicts[0]}");
            }
            else if (RecentConflicts.Count > 1)
            {
                parts.Add($"Both versions kept · {RecentConflicts.Count} files");
            }

            if (NotSynced.Count == 1)
            {
                parts.Add($"Not synced here · {NotSynced[0].Path}");
            }
            else if (NotSynced.Count > 1)
            {
                parts.Add($"Not synced here · {NotSynced.Count} items");
            }

            if (ServerFault is not null)
            {
                parts.Add(ServerFault);
            }
            else if (LastFailureReason is not null && Freshness != SyncFreshness.Current)
            {
                parts.Add(LastFailureReason);
            }
            else if (SkippedReason is not null)
            {
                parts.Add(SkippedReason);
            }

            return parts.Count == 0 ? null : string.Join(" · ", parts);
        }
    }

    private static string Local(DateTimeOffset utc) =>
        utc.ToLocalTime().ToString("HH:mm", CultureInfo.CurrentCulture);
}

/// <summary>What one peer looks like from here.</summary>
public sealed record PeerStatus
{
    /// <summary>The peer's display name.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// Whether the peer answered the last attempt: connected, and completed the handshake as
    /// the machine it was dialled as.
    /// </summary>
    /// <remarks>
    /// Says nothing about whether the sync that followed worked; that is
    /// <see cref="SyncFailed"/>. The two used to be one value, so a peer that answered and
    /// then failed on its data read as off the network (D-58).
    /// </remarks>
    public required bool IsReachable { get; init; }

    /// <summary>
    /// True when the last attempt to sync with it failed, whether or not it answered.
    /// </summary>
    public bool SyncFailed { get; init; }

    /// <summary>When it last answered, or null if it never has.</summary>
    public DateTimeOffset? LastSeenUtc { get; init; }

    /// <summary>Why the last sync with it failed, when it did.</summary>
    public string? FailureReason { get; init; }

    /// <summary>How many snapshots this replica is behind that peer.</summary>
    /// <remarks>
    /// Known only when the last attempt reached the peer, learned its head and then failed
    /// or deferred the pull; zero after every successful sync, and zero for a peer that could
    /// not be reached at all, since nothing is known about how far ahead that one is.
    /// </remarks>
    public int SnapshotsBehind { get; init; }
}

/// <summary>A transfer in progress.</summary>
/// <remarks>
/// Carries the source, because a percentage with no source does not answer the question the
/// user is actually asking, which is "is my laptop sending or receiving right now".
/// </remarks>
public sealed record TransferProgress
{
    /// <summary>True when receiving, false when serving.</summary>
    public required bool IsReceiving { get; init; }

    /// <summary>The peer on the other end.</summary>
    public required string PeerName { get; init; }

    /// <summary>Blocks completed so far.</summary>
    public required int BlocksDone { get; init; }

    /// <summary>Blocks in this transfer.</summary>
    public required int BlocksTotal { get; init; }

    /// <summary>Bytes transferred so far.</summary>
    public long BytesDone { get; init; }

    /// <summary>The fraction complete, between 0 and 1.</summary>
    public double Fraction => BlocksTotal <= 0 ? 0 : (double)BlocksDone / BlocksTotal;

    /// <summary>A one-line description ready to display.</summary>
    public string Describe()
    {
        var verb = IsReceiving ? "Receiving" : "Sending";
        var count = string.Create(
            CultureInfo.CurrentCulture,
            $"{BlocksDone:N0} / {BlocksTotal:N0} blocks");

        return $"{verb} · {count} · {(IsReceiving ? "from" : "to")} {PeerName}";
    }
}
