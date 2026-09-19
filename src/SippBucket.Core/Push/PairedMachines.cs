using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Repository;
using SippBucket.Core.Servers;

namespace SippBucket.Core.Push;

/// <summary>
/// The machines paired with any folder this person syncs: the ones Direct Push knows, since it
/// is per machine while pairing is per folder (docs/DIRECT-PUSH.md, rule 7).
/// </summary>
/// <remarks>
/// Read from each folder's <c>peers.json</c> every time, so a machine removed from its last folder
/// is known to nobody from that moment, and safe to call from any thread. A folder whose peer list
/// cannot be read contributes nothing: for the listener that refuses its peers, which is the safe
/// side, and for the command line it is reported.
/// </remarks>
public static class PairedMachines
{
    /// <summary>The name this machine knows a device by, or null when no folder here is paired with it.</summary>
    /// <param name="folders">Every folder this person syncs.</param>
    /// <param name="deviceId">The device.</param>
    /// <returns>Its name in the first folder that lists it, or null.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="folders"/> was null.</exception>
    public static string? NameOf(IEnumerable<string> folders, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(folders);
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        foreach (var peers in PeerListsOf(folders))
        {
            if (peers.FirstOrDefault(peer => DeviceIdentity.IsSameDevice(peer.DeviceId, deviceId)) is { } match)
            {
                return match.Name;
            }
        }

        return null;
    }

    /// <summary>
    /// The one machine a person named, by device ID, prefix or name, across every folder, as
    /// <see cref="PeerRegistry.Find"/> finds one in a folder.
    /// </summary>
    /// <param name="folders">Every folder this person syncs.</param>
    /// <param name="deviceIdOrName">What the person typed.</param>
    /// <param name="unreadable">The folders whose peer lists could not be read.</param>
    /// <returns>
    /// The machine, when everything the argument names across all the folders is one device: its
    /// record from the folder it most recently synced in, whose address is the likeliest still to
    /// be right. Otherwise why not.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="folders"/> was null.</exception>
    public static PeerLookup Find(IEnumerable<string> folders, string deviceIdOrName, out IReadOnlyList<string> unreadable)
    {
        ArgumentNullException.ThrowIfNull(folders);

        var skipped = new List<string>();
        var found = new List<PeerRecord>();

        foreach (var folder in folders)
        {
            var layout = new RepositoryLayout(folder);
            if (!layout.Exists)
            {
                continue;
            }

            try
            {
                var lookup = new PeerRegistry(layout.PeersFile).Find(deviceIdOrName);
                if (lookup.Peer is { } peer)
                {
                    found.Add(peer);
                }

                found.AddRange(lookup.Candidates);
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                skipped.Add(folder);
            }
        }

        unreadable = skipped;

        var devices = found
            .GroupBy(peer => peer.DeviceId, StringComparer.OrdinalIgnoreCase)
            .Select(records => records.OrderByDescending(record => record.LastSyncedUtc ?? DateTimeOffset.MinValue).First())
            .ToList();

        return devices.Count switch
        {
            0 => new PeerLookup { Outcome = PeerLookupOutcome.NotFound },
            1 => new PeerLookup { Outcome = PeerLookupOutcome.Found, Peer = devices[0] },
            _ => new PeerLookup { Outcome = PeerLookupOutcome.Ambiguous, Candidates = devices },
        };
    }

    /// <summary>
    /// The one machine a person named: by server number ("Server 2", "2"), Server.ID or label
    /// first, then by device ID, prefix or name as <see cref="Find"/> finds it.
    /// </summary>
    /// <param name="folders">Every folder this person syncs.</param>
    /// <param name="servers">The directory of the person's servers.</param>
    /// <param name="typed">What the person typed.</param>
    /// <param name="unreadable">The folders whose peer lists could not be read.</param>
    /// <returns>
    /// The machine, named by its server's number when it has one. A server with more than one
    /// install paired here (a dual-boot board) is reached at the install that synced most
    /// recently, which is the one likeliest to be running.
    /// </returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <remarks>
    /// The directory only says which device a number means; whether that device may be pushed
    /// to, and where it is, still comes from the folders' peer lists, so a server this machine
    /// is no longer paired with is not a target however it is named.
    /// </remarks>
    public static PeerLookup FindTarget(IEnumerable<string> folders, ServerDirectory servers, string typed, out IReadOnlyList<string> unreadable)
    {
        ArgumentNullException.ThrowIfNull(folders);
        ArgumentNullException.ThrowIfNull(servers);

        var matches = servers.Find(typed);
        if (matches.Count == 0)
        {
            return Find(folders, typed, out unreadable);
        }

        var folderList = folders.ToList();
        var skipped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var reachable = new List<PeerRecord>();

        foreach (var server in matches)
        {
            // Collected then chosen, rather than tracked through a loop-carried nullable:
            // that shape is one CA1508's flow analysis misjudges as dead code.
            var candidates = new List<PeerRecord>();
            foreach (var install in server.Installs)
            {
                var found = Find(folderList, install.Device, out var bad);
                skipped.UnionWith(bad);

                if (found.Peer is { } peer)
                {
                    candidates.Add(peer);
                }
            }

            if (candidates.Count > 0)
            {
                var best = candidates.MaxBy(peer => peer.LastSyncedUtc ?? DateTimeOffset.MinValue)!;
                reachable.Add(best with { Name = servers.NameOf(best.DeviceId) ?? best.Name });
            }
        }

        unreadable = [.. skipped];
        return reachable.Count switch
        {
            0 => new PeerLookup { Outcome = PeerLookupOutcome.NotFound },
            1 => new PeerLookup { Outcome = PeerLookupOutcome.Found, Peer = reachable[0] },
            _ => new PeerLookup { Outcome = PeerLookupOutcome.Ambiguous, Candidates = reachable },
        };
    }

    /// <summary>Every device paired with any folder here, each once.</summary>
    /// <param name="folders">Every folder this person syncs.</param>
    /// <returns>Their device IDs. A folder whose peer list cannot be read contributes nothing.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="folders"/> was null.</exception>
    /// <remarks>
    /// What the team switch counts (<see cref="Machines.TeamFeatures"/>): pairing is per
    /// folder, and a person is on the team while any folder here is paired with any of their
    /// machines. Skipping an unreadable folder errs toward fewer people, which errs toward
    /// team features off, the safe side of that switch.
    /// </remarks>
    public static IReadOnlyList<string> AllDeviceIds(IEnumerable<string> folders)
    {
        ArgumentNullException.ThrowIfNull(folders);

        var devices = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var peers in PeerListsOf(folders))
        {
            foreach (var peer in peers)
            {
                if (!string.IsNullOrWhiteSpace(peer.DeviceId) && seen.Add(peer.DeviceId))
                {
                    devices.Add(peer.DeviceId);
                }
            }
        }

        return devices;
    }

    /// <summary>Each readable folder's usable peers; a folder whose list cannot be read is passed over.</summary>
    private static IEnumerable<IReadOnlyList<PeerRecord>> PeerListsOf(IEnumerable<string> folders)
    {
        foreach (var folder in folders)
        {
            var layout = new RepositoryLayout(folder);
            if (!layout.Exists)
            {
                continue;
            }

            IReadOnlyList<PeerRecord> peers;
            try
            {
                peers = new PeerRegistry(layout.PeersFile).Load();
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                continue;
            }

            yield return peers;
        }
    }
}
