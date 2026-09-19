using System.Globalization;

namespace SippBucket.Core.Sync;

/// <summary>
/// The wording for statements that speak for several folders at once.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="FolderStatus"/> owns every sentence about one folder so that no surface can
/// invent a status of its own. A window that lists several folders needs a few sentences
/// that are about none of them in particular — how many peers can be reached, how many
/// folders have a passphrase — and those follow the same rule for the same reason. If each
/// surface composed its own, the tray and the window would drift into disagreeing, and the
/// one that sounded more reassuring would be believed.
/// </para>
/// <para>
/// Every judgement here errs toward the less reassuring reading. A peer that has not been
/// tried yet is not "reachable", and a peer that one folder reached while another could not
/// is not either. A count that is short of its total is the honest summary; rounding it up
/// is the exact failure this product was built to stop.
/// </para>
/// </remarks>
public static class MachineOverview
{
    /// <summary>Every peer the folders know about, once each.</summary>
    /// <param name="folders">The folders' current statuses, in display order.</param>
    /// <returns>
    /// One entry per distinct peer name, in the order each was first met — folder order,
    /// then the order within the folder — so the list does not rearrange itself as states
    /// change.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="folders"/> was null.</exception>
    public static IReadOnlyList<PeerOverview> Peers(IEnumerable<FolderStatus> folders)
    {
        ArgumentNullException.ThrowIfNull(folders);

        var order = new List<string>();
        var sightings = new Dictionary<string, List<PeerStatus>>(StringComparer.Ordinal);

        foreach (var folder in folders)
        {
            foreach (var peer in folder.Peers)
            {
                if (!sightings.TryGetValue(peer.Name, out var list))
                {
                    list = [];
                    sightings[peer.Name] = list;
                    order.Add(peer.Name);
                }

                list.Add(peer);
            }
        }

        return order.Select(name => PeerOverview.From(name, sightings[name])).ToList();
    }

    /// <summary>How many of the known peers can actually be reached.</summary>
    /// <param name="folders">The folders' current statuses.</param>
    /// <returns>A short line such as <c>1 of 2 peers reachable</c>.</returns>
    /// <remarks>
    /// Carries no verdict colour on purpose. There is no colour that means "partly", and a
    /// green dot beside "1 of 2" is the window's highest summary telling the most reassuring
    /// half of the truth.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="folders"/> was null.</exception>
    public static string Reachability(IEnumerable<FolderStatus> folders)
    {
        var peers = Peers(folders);

        if (peers.Count == 0)
        {
            return "No peers yet";
        }

        var reachable = peers.Count(p => p.IsReachable);
        return string.Create(
            CultureInfo.CurrentCulture,
            $"{reachable} of {peers.Count} {(peers.Count == 1 ? "peer" : "peers")} reachable");
    }

    /// <summary>How many folders on this machine have a passphrase.</summary>
    /// <param name="folders">The folders' current statuses.</param>
    /// <returns>A short line such as <c>2 of 3 folders have no passphrase</c>.</returns>
    /// <remarks>
    /// A count, never a claim about the machine. Locking is per folder, per machine, so there
    /// is no machine-wide state to report — and a line that described "this PC" as locked
    /// would be false the moment one folder had no passphrase.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="folders"/> was null.</exception>
    public static string Passphrases(IEnumerable<FolderStatus> folders)
    {
        ArgumentNullException.ThrowIfNull(folders);

        var list = folders.ToList();
        var total = list.Count;
        var without = list.Count(f => !f.HasPassphrase);

        if (total == 0)
        {
            return "No folders yet";
        }

        if (without == 0)
        {
            return total == 1
                ? "The folder has a passphrase"
                : string.Create(CultureInfo.CurrentCulture, $"All {total} folders have a passphrase");
        }

        if (without == total)
        {
            return total == 1
                ? "The folder has no passphrase"
                : string.Create(CultureInfo.CurrentCulture, $"None of the {total} folders has a passphrase");
        }

        return string.Create(
            CultureInfo.CurrentCulture,
            $"{without} of {total} folders have no passphrase");
    }
}

/// <summary>One peer, as every folder that knows it sees it.</summary>
public sealed record PeerOverview
{
    /// <summary>The peer's display name.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// True only when every folder that knows this peer has actually reached it.
    /// </summary>
    /// <remarks>
    /// <see cref="FolderStatus"/> reports a peer nobody has tried yet as reachable with no
    /// last-seen time, so that a folder's headline is not alarming in the seconds before
    /// its first cycle. That default is right for one folder's headline and wrong for a
    /// count: this requires a real contact, from every folder, before saying "reachable".
    /// </remarks>
    public required bool IsReachable { get; init; }

    /// <summary>True when some folder has tried this peer and it did not answer.</summary>
    public required bool IsUnreachable { get; init; }

    /// <summary>
    /// True when some folder reached this peer and the sync with it then failed: the peer is
    /// on the network and the fault is in what it served, not in getting to it.
    /// </summary>
    public bool IsFailing { get; init; }

    /// <summary>The most recent time any folder reached this peer, or null if none has.</summary>
    public DateTimeOffset? LastSeenUtc { get; init; }

    /// <summary>Why a folder could not reach it or sync with it, when one could not.</summary>
    public string? FailureReason { get; init; }

    /// <summary>How many folders sync with this peer.</summary>
    public required int FolderCount { get; init; }

    /// <summary>One line describing what is known about this peer.</summary>
    /// <returns>For example <c>Offline since 18:20</c> or <c>Not checked yet</c>.</returns>
    /// <remarks>
    /// States what was observed and stops. It does not guess why a peer is missing — asleep,
    /// switched off, or on another network look identical from here.
    /// </remarks>
    public string Describe()
    {
        if (IsUnreachable)
        {
            return LastSeenUtc is { } seen
                ? $"Offline since {Local(seen)}"
                : "Never reached";
        }

        if (IsFailing && LastSeenUtc is { } answered)
        {
            return $"Reachable · sync failed · last seen {Local(answered)}";
        }

        if (IsReachable && LastSeenUtc is { } last)
        {
            return $"Reachable · last seen {Local(last)}";
        }

        return "Not checked yet";
    }

    internal static PeerOverview From(string name, IReadOnlyList<PeerStatus> sightings)
    {
        var failed = sightings.Where(s => !s.IsReachable).ToList();
        var failing = sightings.Where(s => s.IsReachable && s.SyncFailed).ToList();
        var lastSeen = sightings
            .Where(s => s.LastSeenUtc is not null)
            .Select(s => s.LastSeenUtc!.Value)
            .DefaultIfEmpty()
            .Max();

        return new PeerOverview
        {
            Name = name,
            IsReachable = failed.Count == 0 && sightings.All(s => s.LastSeenUtc is not null),
            IsUnreachable = failed.Count > 0,
            IsFailing = failing.Count > 0,
            LastSeenUtc = lastSeen == default ? null : lastSeen,
            FailureReason = failed.Concat(failing)
                .Select(s => s.FailureReason)
                .FirstOrDefault(r => r is not null),
            FolderCount = sightings.Count,
        };
    }

    private static string Local(DateTimeOffset utc) =>
        utc.ToLocalTime().ToString("HH:mm", CultureInfo.CurrentCulture);
}
