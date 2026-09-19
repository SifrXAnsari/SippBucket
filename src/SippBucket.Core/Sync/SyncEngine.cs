using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using SippBucket.Core.Chunking;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Health;
using SippBucket.Core.Model;
using SippBucket.Core.Native;
using SippBucket.Core.Platform;
using SippBucket.Core.Protocol;
using SippBucket.Core.Repository;
using SippBucket.Core.Servers;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Sync;

/// <summary>
/// Pulls a peer's changes into this replica.
/// </summary>
/// <remarks>
/// <para>
/// Sync is a pull, run from both ends. Each machine asks the other what its newest snapshot
/// is, works out how that snapshot relates to its own history, fetches whatever it does not
/// already hold, and applies it. There is no push, which means there is no single machine
/// that has to be reachable and no ordering to get wrong.
/// </para>
/// <para>
/// The relationship decides everything. A peer whose head is in this replica's ancestry is
/// behind, and nothing happens. A peer whose ancestry contains this replica's head is ahead,
/// however many saves ahead, and this replica fast-forwards onto it. Otherwise both sides
/// saved since they last agreed, and the pull merges against the nearest snapshot they
/// share. Fast-forward and merge are the same three-way apply (<see cref="WorkingTreeMerge"/>)
/// with different bases, so a deletion, a delete-versus-edit and a file edited while the
/// sync was running are handled the same way whichever path a sync takes.
/// </para>
/// <para>
/// Where both sides changed the same file since their common ancestor, neither side wins:
/// the local copy is renamed and both survive. That is Syncthing's approach, and it is the
/// only one that never silently loses a document.
/// </para>
/// </remarks>
public sealed class SyncEngine
{
    private const int BlockRequestBatchSize = 64;

    /// <summary>The first ancestry page asked for. Most pulls are a few saves behind.</summary>
    private const int FirstAncestryPage = 64;

    /// <summary>How many candidate merge bases to try before merging without one.</summary>
    /// <remarks>
    /// Each candidate this replica does not hold costs one snapshot request. Past the first
    /// few, a candidate is far enough back that a two-way merge loses little by comparison.
    /// </remarks>
    private const int MergeBaseAttempts = 4;

    private readonly SipRepository _repository;
    private readonly DeviceIdentity _identity;
    private readonly Action<string>? _log;
    private readonly SyncTuning _tuning;

    /// <summary>Creates an engine for one repository.</summary>
    /// <param name="repository">The repository to sync.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="log">Optional sink for progress lines.</param>
    /// <param name="tuning">The deadlines to run under, or null for the defaults.</param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public SyncEngine(
        SipRepository repository,
        DeviceIdentity identity,
        Action<string>? log = null,
        SyncTuning? tuning = null)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(identity);

        _repository = repository;
        _identity = identity;
        _log = log;
        _tuning = tuning ?? SyncTuning.Default;

        // A folder that syncs signs: the merge snapshots this engine records must verify at
        // every peer (D-21). Whoever opened the repository with another signer keeps it.
        repository.Signer ??= new SnapshotSigner(identity);
    }

    /// <summary>
    /// Test seam: runs after the last message is exchanged with the peer and before the
    /// working folder is scanned or touched.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only. Two properties can only be shown by acting in exactly
    /// this window: that a file edited after the local save and before the apply survives a
    /// fast-forward (D-44), and that two machines merging each other at the same moment
    /// still converge — which needs each side held here until the other has read its head.
    /// Production code never sets it.
    /// </remarks>
    internal Func<CancellationToken, Task>? BeforeApply { get; set; }

    /// <summary>
    /// Test seam: given the staged files of an apply once they are written, before any of
    /// them is moved into the working folder.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only: the staged files have random names, and the only way to
    /// show that a scanner reading one does not fail the apply half way (D-69) is to open it
    /// in exactly this window. Production code never sets it.
    /// </remarks>
    internal Func<IReadOnlyList<string>, Task>? AfterStaging { get; set; }

    /// <summary>Syncs with every registered peer in turn.</summary>
    /// <param name="cancellationToken">Cancels the sync.</param>
    /// <returns>
    /// One result per registered peer, including the ones that failed. A failed peer is
    /// reported rather than omitted, because a caller cannot tell the difference between
    /// "no peers are configured" and "every peer failed" from a list that only holds
    /// successes — and those two states mean opposite things to a user.
    /// </returns>
    /// <remarks>
    /// A folder that another operation holds (D-38) defers the peer whose apply found it held,
    /// and is not thrown. It used to be thrown, which discarded the results of the peers
    /// already applied: their files were on disk, and their conflict copies and statuses were
    /// never recorded, while the caller printed "nothing was changed". The peers after it are
    /// not contacted, because each would wait out the same lock before being deferred for the
    /// same reason, and each is reported as <see cref="SyncOutcome.NotTried"/>, never as
    /// deferred: a deferral says the peer answered, and these were never asked.
    /// </remarks>
    public async Task<IReadOnlyList<SyncResult>> SyncAllAsync(
        CancellationToken cancellationToken = default)
    {
        var results = new List<SyncResult>();
        var peers = _repository.Peers.Load();

        for (var i = 0; i < peers.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var (result, busy) = await SyncWithPeerSafelyAsync(peers[i], cancellationToken).ConfigureAwait(false);
            results.Add(result);

            if (busy is not null)
            {
                foreach (var untried in peers.Skip(i + 1))
                {
                    results.Add(NotTried(Named(untried), $"not tried while the folder was busy: {busy.Message}"));
                }

                break;
            }
        }

        return results;
    }

    /// <summary>
    /// Syncs with one peer as <see cref="SyncAllAsync"/> syncs each: a failure is a result, never
    /// an exception.
    /// </summary>
    /// <param name="peer">The peer, as the folder's peer list has it.</param>
    /// <param name="cancellationToken">Cancels the sync.</param>
    /// <returns>What the sync did; a peer that could not be reached, or refused, is a failed result.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="peer"/> was null.</exception>
    /// <remarks>
    /// For a command that acts on one peer, as <c>sip alerts answer</c> applies a change it held:
    /// a machine that is switched off is an answer to report, not an error to stop on. A cycle of
    /// its own, so nothing learned in an earlier one carries into it.
    /// </remarks>
    public async Task<SyncResult> SyncOneAsync(PeerRecord peer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peer);

        var (result, _) = await SyncWithPeerSafelyAsync(peer, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static SyncResult Deferred(PeerRecord peer, string reason, SyncProgress progress) =>
        new()
        {
            PeerName = peer.Name,
            DeviceId = peer.DeviceId,
            Outcome = SyncOutcome.Deferred,
            FailureReason = reason,
            PeerReached = progress.Authenticated,
            SnapshotsBehind = progress.SnapshotsBehind,
        };

    private static SyncResult NotTried(PeerRecord peer, string reason) =>
        new()
        {
            PeerName = peer.Name,
            DeviceId = peer.DeviceId,
            Outcome = SyncOutcome.NotTried,
            FailureReason = reason,
        };

    /// <summary>
    /// The peer as log lines and results name it: its server's number and label when it is one
    /// of the person's own numbered servers, its peer-list name otherwise.
    /// </summary>
    /// <remarks>
    /// Only the name changes. Everything that reaches the peer (its device ID, host and port)
    /// is the peer list's, and a peer-list entry is still what the folder syncs with.
    /// </remarks>
    private PeerRecord Named(PeerRecord peer) =>
        Servers?.NameOf(peer.DeviceId) is { } name ? peer with { Name = name } : peer;

    /// <summary>
    /// Syncs with one peer and turns any failure into a result rather than an exception.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a fault boundary, and it is the fix for a defect that a user would experience
    /// as the program silently giving up: one peer that had vanished — a recycled DHCP lease
    /// was the case found — threw past the loop, abandoning every peer after it in the list,
    /// and then past the cycle, killing the poll loop that also takes the local snapshots.
    /// One unplugged laptop stopped the desktop from saving its own work.
    /// </para>
    /// <para>
    /// So the catch is broad on purpose. The rule for what belongs on the other side of a
    /// boundary like this is not "the exceptions I thought of" — that list was already
    /// wrong once here — but "anything that is not this process being asked to stop."
    /// </para>
    /// <para>
    /// A failure after the peer's head was learned still says how far behind this replica
    /// is, which is what lets the folder read "Behind desktop by 3 snapshots" instead of
    /// only "not synced".
    /// </para>
    /// <para>
    /// Two local states are not failures of the peer, and become
    /// <see cref="SyncOutcome.Deferred"/>: another operation holding this folder
    /// (<see cref="FolderBusyException"/>), and a working folder that changed under the pull
    /// or holds a file open (<see cref="WorkingTreeBusyException"/>). Both used to be recorded
    /// as the peer failing, which marked a machine that had just answered as unreachable.
    /// </para>
    /// </remarks>
    /// <returns>The result, and the busy folder that deferred it when that was the reason.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "A per-peer fault boundary. One unreachable peer must never stop " +
                        "the others or the daemon; cancellation is still propagated.")]
    private async Task<(SyncResult Result, FolderBusyException? Busy)> SyncWithPeerSafelyAsync(
        PeerRecord listed,
        CancellationToken cancellationToken)
    {
        var progress = new SyncProgress();
        var peer = Named(listed);

        try
        {
            return (await SyncWithAsync(peer, progress, cancellationToken).ConfigureAwait(false), null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The daemon is stopping. That is not a peer failure and must not be recorded
            // as one.
            throw;
        }
        catch (FolderBusyException ex)
        {
            // Nor is this. Another operation holds this folder (D-38), which is this
            // machine's own state and would refuse every peer's apply alike.
            _log?.Invoke($"{peer.Name}: not applied: {ex.Message}");
            return (Deferred(peer, $"not applied: {ex.Message}", progress), ex);
        }
        catch (WorkingTreeBusyException ex)
        {
            _log?.Invoke($"{peer.Name}: not applied: {ex.Message}");
            return (Deferred(peer, $"not applied: {ex.Message}", progress), null);
        }
        catch (Exception ex)
        {
            var reason = ex switch
            {
                SocketException socket => $"unreachable ({socket.SocketErrorCode})",
                PeerStalledException => "stopped responding",
                SipProtocolException => $"refused ({ex.Message})",
                IOException => $"connection failed ({ex.Message})",
                _ => $"{ex.GetType().Name}: {ex.Message}",
            };

            _log?.Invoke($"{peer.Name}: {reason}");
            RecordFault(peer, progress, ex);

            return (
                new SyncResult
                {
                    PeerName = peer.Name,
                    DeviceId = peer.DeviceId,
                    Outcome = SyncOutcome.Failed,
                    FailureReason = reason,
                    PeerReached = progress.Authenticated,
                    SnapshotsBehind = progress.SnapshotsBehind,
                },
                null);
        }
    }

    /// <summary>
    /// Records what a failed sync shows about the peer in its health record, when it shows
    /// anything the peer can be blamed for.
    /// </summary>
    /// <remarks>
    /// Only once the handshake has proved the machine on the other end is the peer: before
    /// that, whatever answered may be another machine that now has the address. The one
    /// exception is a peer refusing the folder, which it can only do in a handshake message
    /// that only its key could have written. A connection that could not be made at all says
    /// nothing against the peer; it is recorded as the sync's failure, and that is all.
    /// </remarks>
    private void RecordFault(PeerRecord peer, SyncProgress progress, Exception ex)
    {
        if (Servers is not { } servers)
        {
            return;
        }

        var authenticated = progress.Authenticated ||
                            ex is SipProtocolException { Fault: SipProtocolFault.UnknownRepository };
        if (!authenticated)
        {
            return;
        }

        HealthFault? fault = ex switch
        {
            SipProtocolException protocol => HealthFaults.FromProtocol(protocol.Fault),
            PeerStalledException => HealthFault.Stall,
            CorruptBlockException => HealthFault.BadBlock,
            UnsafeSnapshotPathException => HealthFault.UnsafePath,
            _ => null,
        };

        if (fault is { } found)
        {
            servers.RecordFault(peer.DeviceId, found, ex.Message, _repository.Config.Name, peer.Name);
        }
    }

    /// <summary>
    /// Extra addresses learned from local discovery, or null when discovery is not running.
    /// </summary>
    /// <remarks>
    /// Set rather than injected so that discovery remains optional and the engine works
    /// identically without it. The name says <em>extra</em> because that is the contract:
    /// the configured address is always tried first and these are only tried after it
    /// fails. An announcement is unauthenticated, so letting one replace a configured
    /// address would let anyone on the network cut two machines off from each other by
    /// shouting.
    /// </remarks>
    public Func<string, IReadOnlyList<(string Host, int Port)>>? ExtraAddresses { get; set; }

    /// <summary>
    /// Server.ID's exchange, the names it gives the person's servers, and the health records it
    /// keeps; or null when this engine takes no part in them.
    /// </summary>
    /// <remarks>
    /// Set rather than injected, as <see cref="ExtraAddresses"/> is, so the engine syncs the
    /// same without it. With it, each connection to one of the person's own machines starts by
    /// exchanging Server.ID records, log lines and results name the peer "Server 2 (…)", and
    /// what a failed sync shows against the peer goes to its health record. Sync never waits on
    /// any of it: a peer that does not exchange records is synced as before.
    /// </remarks>
    public ServerExchange? Servers { get; set; }

    /// <summary>
    /// The ceiling on what this engine fetches as blocks (D-29): the machine's
    /// <c>network.downloadKiBps</c>, or <see cref="RateLimiter.Unlimited"/>, the default.
    /// </summary>
    public RateLimiter Download { get; set; } = RateLimiter.Unlimited;

    /// <summary>
    /// Told how far a block transfer has got, every block (D-31): what "Receiving · 812 /
    /// 1,284 blocks · from laptop" is fed by. Or null, and nothing is reported.
    /// </summary>
    /// <remarks>May be invoked from more than one task at once when peers share a fetch.</remarks>
    public Action<TransferProgress>? Progress { get; set; }

    /// <summary>
    /// Where a discovery key a peer minted for this machine is kept (docs/DISCOVERY.md), or
    /// null while discovery does not run here: only then is the key asked for.
    /// </summary>
    /// <remarks>
    /// Set rather than injected, as <see cref="Servers"/> is. The fetch is one request after
    /// the ring exchange, answered empty by a peer that does not announce to this machine and
    /// with <see cref="MessageType.Error"/> by an older build; both are taken as "no key" and
    /// the sync goes on.
    /// </remarks>
    public Action<string, string>? DiscoveryKeySink { get; set; }

    /// <summary>Syncs with one peer.</summary>
    /// <param name="peer">The peer to contact.</param>
    /// <param name="cancellationToken">Cancels the sync.</param>
    /// <returns>What the sync did.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="peer"/> was null.</exception>
    public async Task<SyncResult> SyncWithAsync(
        PeerRecord peer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peer);

        return await SyncWithAsync(Named(peer), new SyncProgress(), cancellationToken).ConfigureAwait(false);
    }

    private async Task<SyncResult> SyncWithAsync(
        PeerRecord peer,
        SyncProgress progress,
        CancellationToken cancellationToken)
    {
        // A membership that ended is over on this side too: the peer is neither dialled nor
        // believed, and the reason names the date, so an expiry never reads as an outage.
        if (peer.IsExpired(DateTimeOffset.UtcNow))
        {
            var since = peer.ExpiresUtc!.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            _log?.Invoke($"{peer.Name}: not synced: its membership ended {since}");
            return new SyncResult
            {
                PeerName = peer.Name,
                DeviceId = peer.DeviceId,
                Outcome = SyncOutcome.NotTried,
                FailureReason =
                    $"its membership ended {since}. 'sip peer expire {peer.Name} never' renews it; " +
                    "'sip peer remove' ends it for good and rotates the folder key",
            };
        }

        // A rotation revoked it (D-70): it is not dialled, whatever a hand edit put back.
        if (_repository.IsRevoked(peer.DeviceId))
        {
            _log?.Invoke($"{peer.Name}: not synced: a removal revoked it");
            return new SyncResult
            {
                PeerName = peer.Name,
                DeviceId = peer.DeviceId,
                Outcome = SyncOutcome.NotTried,
                FailureReason = "it was removed from this folder, and the folder's key was rotated; re-pair it to bring it back",
            };
        }

        // The person said a change from it was not them: nothing of its is taken, and it is not
        // even asked, until they clear it. Every other machine syncs as before (PEER-HEALTH.md).
        if (Servers?.IsSuspect(peer.DeviceId) == true)
        {
            _log?.Invoke($"{peer.Name}: no change of its is taken: you said an earlier one was not you");
            return new SyncResult
            {
                PeerName = peer.Name,
                DeviceId = peer.DeviceId,
                Outcome = SyncOutcome.Held,
                FailureReason =
                    "you said a change from it was not you, so no change of its is taken until " +
                    "'sip peer health clear' says otherwise",
            };
        }

        var result = await ExchangeAsync(peer, progress, cancellationToken).ConfigureAwait(false);
        if (result.Outcome != SyncOutcome.Held)
        {
            RecordLastSynced(peer);
        }

        // Every result that comes back rather than being thrown was reached: the exchange
        // returns nothing before the handshake has completed.
        return result with { PeerReached = true };
    }

    private async Task<SyncResult> ExchangeAsync(
        PeerRecord peer,
        SyncProgress progress,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await ConnectAnywhereAsync(client, peer, cancellationToken).ConfigureAwait(false);

        var network = client.GetStream();
        await using var _ = network.ConfigureAwait(false);

        using var channel = await SecureChannel.InitiateAsync(
            network,
            _identity,
            _repository.Config.RepositoryId,
            peer.DeviceId,
            _tuning.StallTimeout,
            cancellationToken).ConfigureAwait(false);

        // From here on the peer has answered as itself, so a failure is a failure of the sync
        // and not of reaching the machine (D-58), and what it sends can be held against it.
        progress.Authenticated = true;

        _log?.Invoke($"{peer.Name}: connected to {channel.PeerDeviceId[..12]}");

        if (Servers is { } servers && servers.IsOwn(channel.PeerDeviceId))
        {
            await ExchangeServerRecordsAsync(channel, servers, peer, cancellationToken).ConfigureAwait(false);
        }

        await ExchangeKeyStatusAsync(channel, peer, cancellationToken).ConfigureAwait(false);
        await FetchDiscoveryKeyAsync(channel, peer, cancellationToken).ConfigureAwait(false);

        await channel.SendAsync(MessageType.HeadRequest, new { }, cancellationToken)
            .ConfigureAwait(false);
        var head = SecureChannel.Decode<HeadResponseMessage>(
            await ExpectAsync(channel, MessageType.HeadResponse, cancellationToken)
                .ConfigureAwait(false));

        var localHead = _repository.GetHead();
        var remoteHead = head.SnapshotId;

        if (remoteHead.IsEmpty)
        {
            return new SyncResult { PeerName = peer.Name, DeviceId = peer.DeviceId, Outcome = SyncOutcome.PeerIsEmpty };
        }

        if (remoteHead == localHead)
        {
            RecordShared(peer, localHead, remoteHead);
            return new SyncResult { PeerName = peer.Name, DeviceId = peer.DeviceId, Outcome = SyncOutcome.AlreadyUpToDate };
        }

        // Asked of the ancestry index and not of the snapshot files. Simple mode deletes
        // every snapshot but the newest, so a peer that is merely behind offers an ID this
        // replica no longer holds as a file — and treating that as new wrote the older
        // version over the newer one (D-39).
        if (_repository.Ancestry.IsAncestorOrSelf(remoteHead, localHead))
        {
            await KeepPeersHeadAsync(channel, peer, remoteHead, cancellationToken).ConfigureAwait(false);
            return new SyncResult { PeerName = peer.Name, DeviceId = peer.DeviceId, Outcome = SyncOutcome.PushedNothing };
        }

        // The peer has a head this replica does not descend from, so there is at least one
        // snapshot to pull. Recorded now so that a pull failing on the next line still
        // reports being behind; refined once the peer's ancestry is known.
        progress.SnapshotsBehind = 1;

        // Keep Alive starts HERE and not one line earlier. Everything above is an idle
        // poll, and ES_SYSTEM_REQUIRED resets the system idle timer every time it is set —
        // so holding it on a poll that runs every 60 seconds would reset the timer forever
        // and quietly stop the machine ever sleeping. A sync daemon that prevents sleep as
        // a side effect of checking whether there is anything to do is a power regression,
        // not a feature. From this point on there is real work: blocks to fetch and files
        // to write, and an interruption leaves the working tree mid-apply.
        using var keepAwake = SleepBlocker.Hold($"syncing {_repository.Config.Name} with {peer.Name}");

        return await PullAsync(channel, peer, localHead, remoteHead, progress, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Fetches a head this replica does not descend from, and fast-forwards onto it or merges
    /// with it.
    /// </summary>
    private async Task<SyncResult> PullAsync(
        SecureChannel channel,
        PeerRecord peer,
        ContentHash localHead,
        ContentHash remoteHead,
        SyncProgress progress,
        CancellationToken cancellationToken)
    {
        var remote = await FetchSnapshotAsync(channel, remoteHead, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.MissingBlock,
                $"The peer offered snapshot {remoteHead.ToShortString()} then could not " +
                "produce it.");

        // A read-only member's change is never taken (the membership rule, not a fault). The
        // head's author is what the rule judges — its signature proved the maker (D-21) — so a
        // read-only machine relaying someone else's snapshot still serves it, and its own
        // saves stop here, before a block moves. Not who is serving: who made it.
        if (ReadOnlyAuthor(remote.DeviceId) is { } readOnly)
        {
            _log?.Invoke($"{peer.Name}: not applied: {readOnly.Name} is read-only in this folder, and this change is its");
            return new SyncResult
            {
                PeerName = peer.Name,
                DeviceId = peer.DeviceId,
                Outcome = SyncOutcome.Held,
                FailureReason =
                    $"the newest change was made by {readOnly.Name}, which is read-only in this folder, so it was " +
                    "not taken. 'sip peer role' changes that",
                SnapshotsBehind = progress.SnapshotsBehind,
            };
        }

        var learned = await FetchAncestryAsync(
            channel, AncestryEntry.For(remoteHead, remote), cancellationToken).ConfigureAwait(false);

        progress.SnapshotsBehind = Math.Max(1, learned.Keys.Count(id => !_repository.Ancestry.Contains(id)));

        var graph = new AncestryGraph(_repository.Ancestry, learned);
        var fastForward = localHead.IsEmpty || graph.IsAncestorOrSelf(localHead, remoteHead);

        var fetched = await FetchMissingBlocksAsync(channel, peer, remote, cancellationToken)
            .ConfigureAwait(false);

        var local = localHead.IsEmpty
            ? null
            : await _repository.GetSnapshotAsync(localHead, cancellationToken).ConfigureAwait(false);

        // A fast-forward is a three-way apply whose base is the local head: anything that
        // differs from the head on disk was changed here while the sync ran, and is kept.
        var found = fastForward
            ? null
            : await FindMergeBaseAsync(channel, peer, graph, localHead, remoteHead, cancellationToken)
                .ConfigureAwait(false);
        var mergeBase = fastForward ? local : found?.Snapshot;

        await channel.SendAsync(MessageType.Goodbye, new { }, cancellationToken).ConfigureAwait(false);

        // The mass-change check (docs/PEER-HEALTH.md): a change that looks like damage is held,
        // kept and not applied, and the person is asked. It cannot be switched off.
        var held = await HoldIfDamageAsync(peer, remote, remoteHead, mergeBase ?? local, graph, progress, cancellationToken)
            .ConfigureAwait(false);
        if (held is not null)
        {
            return held;
        }

        if (BeforeApply is { } beforeApply)
        {
            await beforeApply(cancellationToken).ConfigureAwait(false);
        }

        // From here to the end, the working folder and head change, so the folder's
        // operation lock is held throughout (D-38): not before, because fetching blocks only
        // adds write-once files and can take minutes that `sip save` should not spend
        // waiting. Every step below, the merge's own save included, runs inside this hold.
        using var operation = _repository.HoldOperation(
            await _repository.LockOperationAsync(FolderOperation.Sync, cancellationToken).ConfigureAwait(false));

        // Checked under the lock: head is what the three-way apply measured local changes
        // against. If something else moved it, a 'sip save' or 'sip restore' run by hand or
        // another sync while this pull was on the network, applying against the old head
        // would move head past that change and leave it out of history. A deferral, not a
        // failure of the peer (see SyncWithPeerSafelyAsync).
        if (_repository.GetHead() != localHead)
        {
            throw new WorkingTreeBusyException(
                "this folder's head moved while the sync was running (a save, a restore or " +
                "another sync); nothing was changed, and the next sync will try again.");
        }

        // This machine's ID, not the peer's: the copy that is renamed holds this machine's
        // version, and a conflict name exists to say which machine made the version it holds.
        // It used to be the peer's ID, which labelled every kept copy backwards (D-59).
        var applied = await WorkingTreeMerge.ApplyAsync(
            _repository, mergeBase?.Files, remote, local, _identity.DeviceId, _log, cancellationToken, AfterStaging)
            .ConfigureAwait(false);

        var joined = graph.AnchoredLearnedEntries();

        if (fastForward || local is null)
        {
            // Head moves to the peer's snapshot and nothing is saved here. Whatever was kept
            // because it changed during the sync is an unsaved change on top of the new
            // head, and the next cycle's save records it with the peer's head as its parent.
            await AdoptAsync(peer, remote, joined, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await SettleMergeAsync(peer, local, localHead, remote, remoteHead, found, joined, cancellationToken)
                .ConfigureAwait(false);
        }

        CloseApprovedHold(peer, remoteHead, graph);
        RecordClockSkew(peer, remoteHead, remote);

        return new SyncResult
        {
            PeerName = peer.Name,
            DeviceId = peer.DeviceId,
            Outcome = fastForward ? SyncOutcome.FastForwarded : SyncOutcome.Merged,
            BlocksFetched = fetched,
            FilesWritten = applied.FilesWritten,
            FilesDeleted = applied.FilesDeleted,
            ConflictsRenamed = applied.Conflicts,
        };
    }

    /// <summary>
    /// Holds a change that looks like damage instead of applying it, and asks the person once.
    /// </summary>
    /// <returns>The held result, or null when the change may be applied.</returns>
    /// <remarks>
    /// <para>
    /// Judged against what the folder held before the peer's change: the shared snapshot of a
    /// merge, this machine's head for a fast-forward (<see cref="MassChange"/>). A change the
    /// person answered "That was me" about is applied as it is, and what the peer changed after
    /// it is judged against it, so an approval never covers more than the person was shown.
    /// </para>
    /// <para>
    /// While a change is held and unanswered, the same head is held again without judging it
    /// again, and a newer one is held under the same question: the person is asked once.
    /// </para>
    /// </remarks>
    private async Task<SyncResult?> HoldIfDamageAsync(
        PeerRecord peer,
        Snapshot remote,
        ContentHash remoteHead,
        Snapshot? before,
        AncestryGraph graph,
        SyncProgress progress,
        CancellationToken cancellationToken)
    {
        var heldChanges = _repository.Held;
        var open = heldChanges.OpenFrom(peer.DeviceId);

        if (open is { Answer: HeldAnswer.Unanswered } waiting && waiting.Snapshot == remoteHead)
        {
            Ask(peer, waiting);
            return Held(peer, progress, "it is waiting for your answer: 'sip alerts' asks it");
        }

        IReadOnlyList<FileEntry> baseline = before?.Files ?? [];
        if (open is { Answer: HeldAnswer.ThatWasMe } approved && graph.IsAncestorOrSelf(approved.Snapshot, remoteHead))
        {
            if (approved.Snapshot == remoteHead)
            {
                return null;
            }

            baseline = heldChanges.ReadSnapshot(approved.Snapshot)?.Files ?? baseline;
        }

        var settings = Servers?.Settings ?? HealthSettings.Default;
        var findings = await MassChange.AssessAsync(baseline, remote.Files, ReadHeadAsync, settings, cancellationToken)
            .ConfigureAwait(false);
        if (!findings.Hold)
        {
            return null;
        }

        var what = findings.Describe(peer.Name, _repository.Config.Name);
        var entry = heldChanges.Hold(peer.DeviceId, peer.Name, remoteHead, remote, what, DateTimeOffset.UtcNow);
        Ask(peer, entry);

        _log?.Invoke($"{peer.Name}: HELD, not applied: {what}");
        return Held(peer, progress, $"{string.Join("; ", findings.Reasons)}. 'sip alerts' asks what to do");
    }

    /// <summary>
    /// Raises the alert that asks about a held change, when none has been raised: at the sync
    /// that held it, and again at each later one until the alerts log takes it.
    /// </summary>
    /// <remarks>
    /// An engine with no exchange keeps no alerts, and a change it holds waits for one that has:
    /// the daemon's and the command line's engines always do.
    /// </remarks>
    private void Ask(PeerRecord peer, HeldChange change)
    {
        if (change.Alert is not null || Servers is not { } servers)
        {
            return;
        }

        _repository.Held.Ask(
            peer.DeviceId,
            change.Snapshot,
            () => servers.RaiseHold(
                peer.DeviceId,
                peer.Name,
                _repository.Config.Name,
                _repository.Layout.WorkingRoot,
                change.Snapshot.ToString(),
                change.What)?.Id);
    }

    /// <summary>The read-only member a device belongs to, or null when its changes may be taken.</summary>
    /// <param name="authorDeviceId">The device a snapshot names, and its signature proved, as its maker.</param>
    private PeerRecord? ReadOnlyAuthor(string authorDeviceId) =>
        _repository.Peers.Load().FirstOrDefault(p =>
            p.ReadOnlyMember && string.Equals(p.DeviceId, authorDeviceId, StringComparison.OrdinalIgnoreCase));

    private static SyncResult Held(PeerRecord peer, SyncProgress progress, string reason) =>
        new()
        {
            PeerName = peer.Name,
            DeviceId = peer.DeviceId,
            Outcome = SyncOutcome.Held,
            FailureReason = reason,
            SnapshotsBehind = progress.SnapshotsBehind,
        };

    /// <summary>Closes a change the person approved, once a sync has applied it or something after it.</summary>
    private void CloseApprovedHold(PeerRecord peer, ContentHash remoteHead, AncestryGraph graph)
    {
        if (_repository.Held.OpenFrom(peer.DeviceId) is { Answer: HeldAnswer.ThatWasMe } approved &&
            graph.IsAncestorOrSelf(approved.Snapshot, remoteHead))
        {
            _repository.Held.MarkApplied(peer.DeviceId, DateTimeOffset.UtcNow);
            _log?.Invoke($"{peer.Name}: the change you approved is applied");
        }
    }

    /// <summary>
    /// Reads up to the randomness test's sample of a file from the blocks held here, or answers
    /// null when they are not all here or one does not decrypt: that file is passed over.
    /// </summary>
    private async Task<byte[]?> ReadHeadAsync(FileEntry file, CancellationToken cancellationToken)
    {
        using var head = new MemoryStream();
        foreach (var hash in file.Blocks)
        {
            if (head.Length >= SipEngine.RandomnessSampleBytes)
            {
                break;
            }

            byte[] plaintext;
            try
            {
                plaintext = await _repository.Blobs.GetAsync(hash, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is BlockNotFoundException or CorruptBlockException)
            {
                return null;
            }

            await head.WriteAsync(
                plaintext.AsMemory(0, (int)Math.Min(plaintext.Length, SipEngine.RandomnessSampleBytes - head.Length)),
                cancellationToken).ConfigureAwait(false);
        }

        return head.ToArray();
    }

    /// <summary>
    /// Records a snapshot dated hours ahead of this machine's clock against the peer: strong
    /// evidence, from data it sent, of a wrong clock (docs/PEER-HEALTH.md).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only ahead. A snapshot dated long ago is ordinary history; one from hours in the future
    /// cannot be, and makes conflict copies and history read out of order.
    /// </para>
    /// <para>
    /// Once for each snapshot: when it enters this machine's history, which a snapshot does once.
    /// A pull that is held or fails fetches the same snapshot again at every poll, and counting it
    /// each time would turn one wrong date into a day's worth of faults.
    /// </para>
    /// </remarks>
    private void RecordClockSkew(PeerRecord peer, ContentHash remoteHead, Snapshot remote)
    {
        if (Servers is not { } servers)
        {
            return;
        }

        var ahead = remote.CreatedUtc - DateTimeOffset.UtcNow;
        if (ahead > servers.Settings.ClockSkew)
        {
            servers.RecordFault(
                peer.DeviceId,
                HealthFault.ClockSkew,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"its snapshot {remoteHead.ToShortString()} is dated {remote.CreatedUtc.ToUniversalTime():yyyy-MM-dd HH:mm} UTC, " +
                    $"{ahead.TotalHours:0.#} hours ahead of this machine's clock"),
                _repository.Config.Name,
                peer.Name);
        }
    }

    /// <summary>
    /// Decides what a merge leaves as head, and records a merge snapshot only when neither
    /// side's head already describes the merged folder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the convergence rule, and without it two machines that merge each other at
    /// the same moment write new merge snapshots forever: each merge is a head the other side
    /// does not descend from, so each pull finds another divergence to record.
    /// </para>
    /// <list type="bullet">
    /// <item><description>The merged folder is exactly the peer's snapshot: adopt the peer's
    /// head. Nothing here survived that the peer does not already have.</description></item>
    /// <item><description>It is exactly the local head: keep the local head. The peer will
    /// find the same when it pulls, and adopt ours.</description></item>
    /// <item><description>It is both — identical content under two IDs, which simultaneous
    /// merges produce — take the lexicographically smaller ID, so both machines pick the
    /// same one without having to agree on anything else.</description></item>
    /// <item><description>Otherwise record a merge with this replica's head as the first
    /// parent and the peer's as the second, so the peer finds its own head in our ancestry
    /// and fast-forwards next time (D-27).</description></item>
    /// </list>
    /// </remarks>
    private async Task SettleMergeAsync(
        PeerRecord peer,
        Snapshot local,
        ContentHash localHead,
        Snapshot remote,
        ContentHash remoteHead,
        (ContentHash Id, Snapshot Snapshot)? mergeBase,
        IEnumerable<AncestryEntry> learned,
        CancellationToken cancellationToken)
    {
        // With what a merge snapshot would carry for paths this machine ignores, and settle for
        // paths it could not read, so the folder is compared as the snapshot that would record
        // it (D-56, and SipRepository.SaveWithParentsAsync).
        var scan = await _repository.ScanAsync(storeBlocks: false, remote, local, cancellationToken)
            .ConfigureAwait(false);
        var merged = _repository.CarryIgnored(
            _repository.SettleUnread(scan, local, mergeBase?.Snapshot, remote), remote);

        var matchesRemote = await SameContentAsync(merged, remote.Files, scan, cancellationToken)
            .ConfigureAwait(false);
        var matchesLocal = await SameContentAsync(merged, local.Files, scan, cancellationToken)
            .ConfigureAwait(false);
        var remoteSortsFirst = string.CompareOrdinal(remoteHead.ToString(), localHead.ToString()) < 0;

        if (matchesRemote && (!matchesLocal || remoteSortsFirst))
        {
            _log?.Invoke($"merged folder matches {remoteHead.ToShortString()}; adopting it");
            await AdoptAsync(peer, remote, learned, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (matchesLocal)
        {
            _log?.Invoke($"merged folder matches this head {localHead.ToShortString()}; keeping it");

            // Head stays ours, which the peer's head is not an ancestor of, so the newest
            // snapshot both are known to hold is the base this merge used.
            if (mergeBase is { } shared)
            {
                await _repository.WriteSnapshotAsync(shared.Snapshot, cancellationToken).ConfigureAwait(false);
                RecordShared(peer, shared.Id, remoteHead);
            }

            return;
        }

        _repository.Ancestry.Add(learned);
        await _repository.WriteSnapshotAsync(remote, cancellationToken).ConfigureAwait(false);

        // Before the save, whose trim would otherwise delete the peer's snapshot just written:
        // it is the one both sides now hold, and the base for the next divergence (D-55).
        RecordShared(peer, remoteHead, remoteHead);

        await _repository.SaveWithParentsAsync(
            $"Merge from {remote.DeviceId[..Math.Min(12, remote.DeviceId.Length)]}",
            _identity.DeviceId,
            localHead,
            remoteHead,
            reuseFrom: remote,
            mergeBase: mergeBase?.Snapshot,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Makes the peer's snapshot this replica's head, recording what was learned about its
    /// ancestry first so head never names a snapshot the index cannot place.
    /// </summary>
    private async Task AdoptAsync(
        PeerRecord peer,
        Snapshot remote,
        IEnumerable<AncestryEntry> learned,
        CancellationToken cancellationToken)
    {
        _repository.Ancestry.Add(learned);
        var id = await _repository.WriteSnapshotAsync(remote, cancellationToken).ConfigureAwait(false);
        RecordShared(peer, id, id);
        await _repository.AdvanceHeadAsync(id, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Finds a snapshot both heads descend from and returns it with its ID, from the local
    /// store or from the peer, or null when neither holds any of the candidates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null is not a failure. It makes the apply a two-way merge that never deletes, which
    /// is what every merge was before this existed.
    /// </para>
    /// <para>
    /// It used to be the ordinary result when both sides are in Simple mode, since both had
    /// trimmed everything they once shared (D-55). Each now keeps the last snapshot it shared
    /// with the other, which is the nearest common ancestor unless a nearer one has since
    /// been shared through a third machine; when the nearest few are all gone, that kept base
    /// is tried last.
    /// </para>
    /// </remarks>
    private async Task<(ContentHash Id, Snapshot Snapshot)?> FindMergeBaseAsync(
        SecureChannel channel,
        PeerRecord peer,
        AncestryGraph graph,
        ContentHash localHead,
        ContentHash remoteHead,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in graph.CommonAncestorsNearestFirst(localHead, remoteHead).Take(MergeBaseAttempts))
        {
            if (_repository.HasSnapshot(candidate))
            {
                return (candidate, await _repository.GetSnapshotAsync(candidate, cancellationToken).ConfigureAwait(false));
            }

            var fromPeer = await FetchSnapshotAsync(channel, candidate, cancellationToken)
                .ConfigureAwait(false);
            if (fromPeer is not null)
            {
                return (candidate, fromPeer);
            }
        }

        if (_repository.Shared.Load().TryGetValue(peer.DeviceId, out var mark) &&
            !mark.Base.IsEmpty && _repository.HasSnapshot(mark.Base) &&
            graph.IsAncestorOrSelf(mark.Base, localHead) && graph.IsAncestorOrSelf(mark.Base, remoteHead))
        {
            return (mark.Base, await _repository.GetSnapshotAsync(mark.Base, cancellationToken).ConfigureAwait(false));
        }

        _log?.Invoke("no shared snapshot is held on either side; merging without deleting anything");
        return null;
    }

    /// <summary>
    /// When the peer is behind, makes sure this replica holds the peer's head as a file, and
    /// records it as the snapshot both share.
    /// </summary>
    /// <remarks>
    /// Usually it is held already: it is the base kept from the last sync. When it is not —
    /// the first sync with this peer since this build, or a Simple replica that has trimmed it
    /// — its file list is fetched, one snapshot and no blocks, so a later divergence from this
    /// point has a base. A peer that cannot produce its own head is not a failure here; the
    /// base recorded before stays.
    /// </remarks>
    private async Task KeepPeersHeadAsync(
        SecureChannel channel,
        PeerRecord peer,
        ContentHash remoteHead,
        CancellationToken cancellationToken)
    {
        if (!_repository.HasSnapshot(remoteHead))
        {
            var snapshot = await FetchSnapshotAsync(channel, remoteHead, cancellationToken).ConfigureAwait(false);
            if (snapshot is not null)
            {
                await _repository.WriteSnapshotAsync(snapshot, cancellationToken).ConfigureAwait(false);
            }
        }

        RecordShared(peer, _repository.HasSnapshot(remoteHead) ? remoteHead : default, remoteHead);
    }

    /// <summary>
    /// Records the snapshot this sync established that both sides hold, and the peer's head.
    /// </summary>
    /// <remarks>
    /// A failure is logged and not raised, as with <see cref="RecordLastSynced"/>: the sync
    /// itself succeeded, and the cost of a mark not written is that the next divergence with
    /// this peer may merge without a base, which keeps both versions.
    /// </remarks>
    private void RecordShared(PeerRecord peer, ContentHash shared, ContentHash peerHead)
    {
        try
        {
            _repository.Shared.Record(peer.DeviceId, shared, peerHead);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log?.Invoke($"{peer.Name}: synced, but the shared snapshot could not be recorded: {ex.Message}");
        }
    }

    /// <summary>
    /// Learns the peer's history back from its head, as far as the first snapshots this
    /// replica already knows.
    /// </summary>
    /// <param name="channel">The open channel.</param>
    /// <param name="head">The peer's head, taken from its verified snapshot.</param>
    /// <param name="cancellationToken">Cancels the walk.</param>
    /// <returns>Every entry learned, keyed by ID, the head included.</returns>
    /// <remarks>
    /// <para>
    /// The walk stops descending at any snapshot this replica's own index knows, because
    /// past that point the peer's history and ours are the same: an ID is the hash of a
    /// snapshot including its parents, so two machines cannot disagree about what lies
    /// behind one. Where the peer's claim about such a snapshot can be checked, it is.
    /// </para>
    /// <para>
    /// Everything the peer sends is bounded. A page longer than was asked for is refused;
    /// the walk as a whole stops at <see cref="SyncTuning.AncestryWalkLimit"/> entries;
    /// every ID is asked about at most once, so a peer that answers with nothing new ends
    /// the walk rather than prolonging it.
    /// </para>
    /// </remarks>
    private async Task<Dictionary<ContentHash, AncestryEntry>> FetchAncestryAsync(
        SecureChannel channel,
        AncestryEntry head,
        CancellationToken cancellationToken)
    {
        var index = _repository.Ancestry;
        var learned = new Dictionary<ContentHash, AncestryEntry> { [head.Id] = head };
        var asked = new HashSet<ContentHash> { head.Id };
        var frontier = new Queue<ContentHash>();
        var limit = FirstAncestryPage;

        void Follow(AncestryEntry entry)
        {
            foreach (var parent in new[] { entry.ParentId, entry.MergeParentId })
            {
                if (!parent.IsEmpty && !learned.ContainsKey(parent) && !asked.Contains(parent) &&
                    !index.Contains(parent))
                {
                    frontier.Enqueue(parent);
                }
            }
        }

        Follow(head);

        while (frontier.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var batch = new List<ContentHash>();
            while (frontier.Count > 0 && batch.Count < AncestryRequestMessage.MaximumRoots)
            {
                var id = frontier.Dequeue();
                if (asked.Add(id))
                {
                    batch.Add(id);
                }
            }

            if (batch.Count == 0)
            {
                break;
            }

            await channel.SendAsync(
                MessageType.AncestryRequest,
                new AncestryRequestMessage { From = batch, Limit = limit },
                cancellationToken).ConfigureAwait(false);

            var page = SecureChannel.Decode<AncestryResponseMessage>(
                await ExpectAsync(channel, MessageType.AncestryResponse, cancellationToken)
                    .ConfigureAwait(false));

            // Null is what "entries": null decodes to, whatever the type says.
            if (page.Entries is null || page.Entries.Count > limit)
            {
                throw new SipProtocolException(
                    SipProtocolFault.MalformedMessage,
                    $"Asked the peer for at most {limit} ancestry entries and it sent " +
                    (page.Entries is null ? "no list at all." : $"{page.Entries.Count}."));
            }

            foreach (var entry in page.Entries)
            {
                if (entry is null || entry.Id.IsEmpty)
                {
                    throw new SipProtocolException(
                        SipProtocolFault.MalformedMessage,
                        "The peer sent an ancestry entry with no snapshot ID.");
                }

                var known = index.TryGet(entry.Id, out var mine) ? mine
                    : learned.TryGetValue(entry.Id, out var claimed) ? claimed
                    : null;

                if (known is not null)
                {
                    if (!known.HasSameParentsAs(entry))
                    {
                        throw new SipProtocolException(
                            SipProtocolFault.InconsistentAncestry,
                            $"The peer says snapshot {entry.Id.ToShortString()} has different " +
                            "parents from the ones its own content names.");
                    }

                    continue;
                }

                if (learned.Count >= _tuning.AncestryWalkLimit)
                {
                    _log?.Invoke(
                        $"stopped learning the peer's history after {learned.Count} snapshots; " +
                        "anything older is treated as unknown");
                    return learned;
                }

                learned[entry.Id] = entry;
                Follow(entry);
            }

            limit = Math.Min(limit * 4, AncestryRequestMessage.MaximumLimit);
        }

        return learned;
    }

    /// <summary>
    /// Records a successful sync against the peer's entry in <c>peers.json</c>, so
    /// <c>sip peer list</c> can say when it last happened.
    /// </summary>
    /// <remarks>
    /// A failure here is logged and not raised. The sync itself succeeded, and turning a
    /// timestamp that could not be written — <c>sip pair</c> holding the file for a moment —
    /// into a failed peer would make the folder report "not synced" about a copy that is.
    /// </remarks>
    private void RecordLastSynced(PeerRecord peer)
    {
        try
        {
            _repository.Peers.RecordSync(peer.DeviceId, DateTimeOffset.UtcNow);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            _log?.Invoke($"{peer.Name}: synced, but the time could not be recorded: {ex.Message}");
        }
    }

    /// <summary>
    /// Connects to a peer at its configured address, then at any address discovery has
    /// heard for it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Configured first, always. A discovered address is a hint from an unauthenticated
    /// broadcast; a configured one is something the user set up. Trying the hint first
    /// would let anyone on the network decide which address gets the first connection
    /// attempt, and a hint that accepts and then stalls costs a full stall deadline before
    /// the real address is reached.
    /// </para>
    /// <para>
    /// Every candidate carries its own connect deadline, so N addresses cost at most
    /// N times the deadline rather than the operating system's idea of how long to wait.
    /// </para>
    /// </remarks>
    private async Task ConnectAnywhereAsync(
        TcpClient client,
        PeerRecord peer,
        CancellationToken cancellationToken)
    {
        try
        {
            await ConnectAsync(client, peer, cancellationToken).ConfigureAwait(false);
            return;
        }
        catch (Exception ex) when (ex is SocketException or PeerStalledException)
        {
            var extra = ExtraAddresses?.Invoke(peer.DeviceId) ?? [];
            if (extra.Count == 0)
            {
                throw;
            }

            foreach (var (host, port) in extra)
            {
                if (string.Equals(host, peer.Host, StringComparison.OrdinalIgnoreCase) &&
                    port == peer.Port)
                {
                    continue;
                }

                try
                {
                    await ConnectAsync(
                        client, peer with { Host = host, Port = port }, cancellationToken)
                        .ConfigureAwait(false);

                    _log?.Invoke($"{peer.Name}: reached at {host}:{port} via local discovery");
                    return;
                }
                catch (Exception retry) when (retry is SocketException or PeerStalledException)
                {
                    // Next candidate. A forged announcement costs exactly one bounded
                    // connection attempt and changes nothing else.
                }
            }

            throw;
        }
    }

    /// <summary>
    /// Connects to a peer under this engine's connect deadline.
    /// </summary>
    /// <remarks>
    /// <see cref="TcpClient.ConnectAsync(string, int, CancellationToken)"/> honours a token
    /// but has no timeout of its own, so without this the deadline is whatever the operating
    /// system decides — about 21 seconds on Windows for an address that drops packets
    /// silently, which is the recycled-DHCP-lease case exactly.
    /// </remarks>
    private async Task ConnectAsync(
        TcpClient client,
        PeerRecord peer,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_tuning.ConnectTimeout);

        try
        {
            await client.ConnectAsync(peer.Host, peer.Port, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new PeerStalledException(
                $"{peer.Host}:{peer.Port} did not accept a connection within " +
                $"{_tuning.ConnectTimeout.TotalSeconds:0.#}s.",
                ex);
        }
    }

    /// <summary>
    /// Fetches one snapshot and checks it is the one that was asked for.
    /// </summary>
    /// <returns>The snapshot, or null when the peer does not hold it.</returns>
    /// <remarks>
    /// <para>
    /// The ID is recomputed from what arrived and compared with the ID requested before the
    /// snapshot is used for anything (D-41). A snapshot used to be filed under the hash of
    /// whatever came back, so a peer asked for one snapshot could hand over another and have
    /// it applied — the one piece of peer data that was trusted by label, in a store where
    /// every block was already checked against its name.
    /// </para>
    /// <para>
    /// Every path is validated the moment the snapshot arrives, before a single block is
    /// fetched or a single file written. Checking at each write would still be correct,
    /// but a snapshot rejected halfway through leaves the working tree part-applied — and a
    /// peer that sends one hostile path among a thousand good ones should cost us nothing at
    /// all, not a partial restore that has to be unpicked.
    /// </para>
    /// </remarks>
    private async Task<Snapshot?> FetchSnapshotAsync(
        SecureChannel channel,
        ContentHash snapshotId,
        CancellationToken cancellationToken)
    {
        await channel.SendAsync(
            MessageType.SnapshotRequest,
            new SnapshotRequestMessage { SnapshotId = snapshotId },
            cancellationToken).ConfigureAwait(false);

        var response = SecureChannel.Decode<SnapshotResponseMessage>(
            await ExpectAsync(channel, MessageType.SnapshotResponse, cancellationToken)
                .ConfigureAwait(false));

        if (response.Snapshot is not { } snapshot)
        {
            return null;
        }

        // A canonical snapshot travels as its header, naming its tree and listing no files; a
        // legacy one lists them, names no tree and carries no signature, because it predates
        // both. Anything else is not a snapshot this build reads: a file list beside a tree
        // would be files its ID does not cover, and a signed legacy snapshot claims something
        // legacy snapshots never had.
        var shaped = snapshot.Format switch
        {
            SnapshotFormat.Legacy => snapshot.Tree.IsEmpty && snapshot.Signature is null,
            SnapshotFormat.Canonical => snapshot.Files.Count == 0 && !snapshot.Tree.IsEmpty,
            _ => false,
        };
        if (!shaped)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                $"The peer sent snapshot {snapshotId.ToShortString()} in a form this build does not read " +
                $"(format {snapshot.Format.ToString(CultureInfo.InvariantCulture)}). Nothing was applied.");
        }

        ContentHash actual;
        try
        {
            actual = SipRepository.ComputeSnapshotId(snapshot);
        }
        catch (ArgumentException ex)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                $"The peer sent snapshot {snapshotId.ToShortString()}, which cannot be encoded: {ex.Message}");
        }

        if (actual != snapshotId)
        {
            throw new SipProtocolException(
                SipProtocolFault.WrongSnapshot,
                $"Asked the peer for snapshot {snapshotId.ToShortString()} and it sent one " +
                $"whose content hashes to {actual.ToShortString()}. Nothing was applied.");
        }

        // The device the snapshot names must have signed it (D-21). The ID covers the claim and
        // the signature covers the ID, so a snapshot claiming a device whose key never signed
        // it is refused here, before a block moves — whoever relayed it. A legacy snapshot
        // predates signing and carries none; the shape check above already refused one that
        // claims otherwise. What the signature proves is the maker, not the maker's welcome:
        // that stays the peer list's decision.
        if (snapshot.Format == SnapshotFormat.Canonical &&
            !SnapshotSigner.Verify(snapshot.DeviceId, snapshotId, snapshot.Signature))
        {
            throw new SipProtocolException(
                SipProtocolFault.WrongSnapshot,
                $"Snapshot {snapshotId.ToShortString()} is not signed by the device it names " +
                $"({DisplayText.Printable(snapshot.DeviceId, 16)}…). Nothing was applied.");
        }

        // The header is the one asked for, and it names the tree; every tree is checked against
        // its own hash, so the files read out of them are the ones the ID covers.
        if (snapshot.Format == SnapshotFormat.Canonical)
        {
            snapshot = snapshot with
            {
                Files = await FetchTreesAsync(channel, snapshotId, snapshot.Tree, cancellationToken).ConfigureAwait(false),
            };
        }

        WorkingTreeMerge.IndexRemote(snapshot, _repository.Layout.WorkingRoot);
        return snapshot;
    }

    /// <summary>
    /// Reads a canonical snapshot's files out of its trees: from this store where held, from
    /// the peer where not (D-23).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A folder whose tree is already here costs nothing to fetch, so after the first pull a
    /// change to one file fetches the trees along the path to it and no others. The walk goes
    /// one level of folders at a time, and asks for each level's missing trees together.
    /// </para>
    /// <para>
    /// A tree from the peer is checked against its hash before it is stored, as a block is; one
    /// that does not match, or is missing, or is not canonical, is the peer's fault. A tree
    /// already held that does not read back is this machine's, and is not blamed on the peer.
    /// </para>
    /// </remarks>
    private async Task<IReadOnlyList<FileEntry>> FetchTreesAsync(
        SecureChannel channel,
        ContentHash snapshotId,
        ContentHash root,
        CancellationToken cancellationToken)
    {
        var trees = new Dictionary<ContentHash, byte[]>();
        var level = new List<ContentHash> { root };

        for (var depth = 0; level.Count > 0; depth++)
        {
            if (depth >= SnapshotTree.MaximumDepth)
            {
                throw new SipProtocolException(
                    SipProtocolFault.MalformedMessage,
                    $"The peer's snapshot {snapshotId.ToShortString()} nests deeper than {SnapshotTree.MaximumDepth} folders.");
            }

            var wanted = level.Where(id => !trees.ContainsKey(id)).Distinct().ToList();
            var fetched = wanted.Where(id => !_repository.Blobs.Contains(id)).ToList();
            await RequestTreesAsync(channel, snapshotId, fetched, cancellationToken).ConfigureAwait(false);

            var next = new List<ContentHash>();
            foreach (var id in wanted)
            {
                byte[] bytes;
                try
                {
                    bytes = await _repository.Blobs.GetAsync(id, cancellationToken).ConfigureAwait(false);
                }
                catch (CorruptBlockException ex) when (!fetched.Contains(id))
                {
                    throw new InvalidDataException(
                        $"This machine's copy of tree {id.ToShortString()} does not read back: {ex.Message}", ex);
                }

                trees[id] = bytes;
                try
                {
                    next.AddRange(SnapshotTree.FoldersOf(bytes));
                }
                catch (FormatException ex)
                {
                    throw new SipProtocolException(
                        SipProtocolFault.MalformedMessage,
                        $"Tree {id.ToShortString()} of the peer's snapshot {snapshotId.ToShortString()} is not canonical: {ex.Message}");
                }
            }

            level = next;
        }

        try
        {
            return SnapshotTree.Materialize(root, trees);
        }
        catch (FormatException ex)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                $"The peer's snapshot {snapshotId.ToShortString()} names trees that are not canonical: {ex.Message}");
        }
    }

    /// <summary>Fetches trees the peer's snapshot names, which this store lacks, and stores each once checked.</summary>
    private async Task RequestTreesAsync(
        SecureChannel channel,
        ContentHash snapshotId,
        List<ContentHash> wanted,
        CancellationToken cancellationToken)
    {
        for (var offset = 0; offset < wanted.Count; offset += BlockRequestBatchSize)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var batch = wanted.Skip(offset).Take(BlockRequestBatchSize).ToList();
            await channel.SendAsync(
                MessageType.BlockRequest,
                new BlockRequestMessage { Hashes = batch },
                cancellationToken).ConfigureAwait(false);

            foreach (var expected in batch)
            {
                var message = await ExpectAsync(channel, MessageType.BlockData, _tuning.IdleTimeout, cancellationToken)
                    .ConfigureAwait(false);

                if (!BlockWire.TryDecode(message.Body, out var hash, out var ciphertext))
                {
                    throw new SipProtocolException(
                        SipProtocolFault.MalformedBlock,
                        $"The peer sent a tree answer of {message.Body.Length} bytes, which is no shape a block has.");
                }

                if (hash != expected)
                {
                    throw new SipProtocolException(
                        SipProtocolFault.WrongBlock,
                        $"Asked the peer for tree {expected.ToShortString()} and it answered " +
                        $"with {hash.ToShortString()}.");
                }

                if (ciphertext is not { } present)
                {
                    throw new SipProtocolException(
                        SipProtocolFault.MissingBlock,
                        $"The peer is missing tree {expected.ToShortString()} that its own snapshot " +
                        $"{snapshotId.ToShortString()} names. Nothing was applied.");
                }

                await Download.WaitAsync(present.Length, cancellationToken).ConfigureAwait(false);

                _ = await _repository.Blobs
                    .PutRawVerifiedAsync(expected, present.ToArray(), cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    /// <summary>How many blocks one transfer must want before other peers are asked to share the work.</summary>
    private const int MultiPeerThreshold = 4 * BlockRequestBatchSize;

    /// <summary>How many other peers one transfer may draw on at once, beside the primary.</summary>
    private const int MaximumAuxiliaryPeers = 2;

    /// <summary>
    /// Fetches every block a snapshot names that this store lacks: pipelined (D-50), as raw
    /// bytes (D-45), paced by the download ceiling (D-29), reported as it goes (D-31), and —
    /// when the transfer is large or the primary lacks a block — drawn from several peers at
    /// once by asking each what it holds first (D-28).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every block must be accounted for before the caller may write the snapshot or touch
    /// the working tree. Skipping one and returning anyway is what turned a clean failure
    /// into a truncated file (D-24), so a block nobody can produce still ends the pull with
    /// <see cref="SipProtocolFault.MissingBlock"/> and nothing applied — the difference is
    /// that "nobody" is now measured across the peers that could be asked, not assumed from
    /// the first.
    /// </para>
    /// <para>
    /// An auxiliary peer is best-effort throughout: one that cannot be reached, refuses, or
    /// fails mid-fetch hands its share back to the primary and costs nothing else. Only the
    /// primary's channel can fail the pull.
    /// </para>
    /// </remarks>
    private async Task<int> FetchMissingBlocksAsync(
        SecureChannel channel,
        PeerRecord peer,
        Snapshot snapshot,
        CancellationToken cancellationToken)
    {
        var wanted = new List<ContentHash>();
        var seen = new HashSet<ContentHash>();

        foreach (var file in snapshot.Files)
        {
            foreach (var hash in file.Blocks)
            {
                if (seen.Add(hash) && !_repository.Blobs.Contains(hash))
                {
                    wanted.Add(hash);
                }
            }
        }

        if (wanted.Count == 0)
        {
            return 0;
        }

        _log?.Invoke($"fetching {wanted.Count} block(s)");

        // Shared progress across every source (D-31): whoever stores a block advances it.
        var total = wanted.Count;
        var done = 0;
        long bytes = 0;
        var storedCount = 0;
        void Advance(int stored, long moved)
        {
            var doneNow = Interlocked.Increment(ref done);
            _ = Interlocked.Add(ref bytes, moved);
            _ = Interlocked.Add(ref storedCount, stored);
            Progress?.Invoke(new TransferProgress
            {
                IsReceiving = true,
                PeerName = peer.Name,
                BlocksDone = doneNow,
                BlocksTotal = total,
                BytesDone = Interlocked.Read(ref bytes),
            });
        }

        Progress?.Invoke(new TransferProgress
        {
            IsReceiving = true, PeerName = peer.Name, BlocksDone = 0, BlocksTotal = total,
        });

        var auxiliaries = AuxiliaryPeers(peer);

        // Large transfers split the work up front: ask each auxiliary what it holds, and
        // give each source the share nobody lighter-loaded could take (D-28).
        var primaryShare = wanted;
        var auxiliaryShares = new List<(PeerRecord Peer, List<ContentHash> Hashes)>();
        if (wanted.Count >= MultiPeerThreshold && auxiliaries.Count > 0)
        {
            (primaryShare, auxiliaryShares) = await PlanSourcesAsync(auxiliaries, wanted, cancellationToken)
                .ConfigureAwait(false);
        }

        // The auxiliaries run beside the primary, each on its own channel behind its own
        // fault boundary; whatever one fails to deliver returns to the primary's pile.
        var returned = new System.Collections.Concurrent.ConcurrentBag<ContentHash>();
        var auxiliaryWork = auxiliaryShares
            .Select(share => FetchFromAuxiliaryAsync(share.Peer, share.Hashes, returned, Advance, cancellationToken))
            .ToList();

        var notHeld = await FetchBlocksPipelinedAsync(channel, primaryShare, Advance, cancellationToken)
            .ConfigureAwait(false);

        await Task.WhenAll(auxiliaryWork).ConfigureAwait(false);

        // Whatever an auxiliary handed back, the primary fetches now; whatever the primary
        // lacked, the auxiliaries are asked for one by one. Both lists are usually empty.
        var secondPass = returned.ToList();
        if (secondPass.Count > 0)
        {
            notHeld.AddRange(await FetchBlocksPipelinedAsync(channel, secondPass, Advance, cancellationToken)
                .ConfigureAwait(false));
        }

        if (notHeld.Count > 0 && auxiliaries.Count > 0)
        {
            notHeld = await FetchFromAnyAuxiliaryAsync(auxiliaries, notHeld, Advance, cancellationToken)
                .ConfigureAwait(false);
        }

        if (notHeld.Count > 0)
        {
            throw new SipProtocolException(
                SipProtocolFault.MissingBlock,
                $"The peer is missing {notHeld.Count} block(s) that its own snapshot refers " +
                $"to, starting with {notHeld[0].ToShortString()}, and no other peer could " +
                "produce them. Nothing was applied.");
        }

        return storedCount;
    }

    /// <summary>
    /// Fetches one list of blocks over one channel, keeping several batches of requests in
    /// flight (D-50), so the peer is never idle between a batch's last block and the next
    /// request's round trip.
    /// </summary>
    /// <param name="channel">The channel.</param>
    /// <param name="hashes">The blocks, each fetched once.</param>
    /// <param name="advance">Told of each block stored, with its wire size (D-31).</param>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    /// <returns>The blocks the peer said it does not hold, in the order asked.</returns>
    /// <remarks>
    /// <para>
    /// The depth is sized from the machine, never from the six processors this was written
    /// on, and drops to one whole batch when a download ceiling is set: with requests deep
    /// in flight, a throttled reader would leave the sender writing into a full window past
    /// its own stall deadline.
    /// </para>
    /// <para>
    /// Reads wait under the idle timeout rather than the stall timeout, because a sender
    /// pacing itself under its own upload ceiling (D-29) is quiet between frames in exactly
    /// the way a peer writing a batch to disk is.
    /// </para>
    /// </remarks>
    private async Task<List<ContentHash>> FetchBlocksPipelinedAsync(
        SecureChannel channel,
        List<ContentHash> hashes,
        Action<int, long> advance,
        CancellationToken cancellationToken)
    {
        var notHeld = new List<ContentHash>();
        if (hashes.Count == 0)
        {
            return notHeld;
        }

        var depth = Download.IsLimited ? 1 : Math.Clamp(Environment.ProcessorCount / 2, 2, 8);
        var pending = new Queue<IReadOnlyList<ContentHash>>();
        var next = 0;

        async Task TopUpAsync()
        {
            while (pending.Count < depth && next < hashes.Count)
            {
                var count = Math.Min(BlockRequestBatchSize, hashes.Count - next);
                var batch = new List<ContentHash>(count);
                for (var i = 0; i < count; i++)
                {
                    batch.Add(hashes[next + i]);
                }

                next += count;
                await channel.SendAsync(
                    MessageType.BlockRequest,
                    new BlockRequestMessage { Hashes = batch },
                    cancellationToken).ConfigureAwait(false);
                pending.Enqueue(batch);
            }
        }

        await TopUpAsync().ConfigureAwait(false);

        while (pending.Count > 0)
        {
            var batch = pending.Dequeue();
            foreach (var expected in batch)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var message = await ExpectAsync(channel, MessageType.BlockData, _tuning.IdleTimeout, cancellationToken)
                    .ConfigureAwait(false);

                if (!BlockWire.TryDecode(message.Body, out var hash, out var ciphertext))
                {
                    throw new SipProtocolException(
                        SipProtocolFault.MalformedBlock,
                        $"The peer sent a block answer of {message.Body.Length} bytes, which is no shape a block has.");
                }

                // Responses come back in request order, so an answer for a hash we did not
                // ask for means the peer is out of step. Storing it would be harmless — the
                // content is verified against its own hash — but the block we actually
                // wanted would then be quietly missing, and the failure would surface much
                // later as an unreadable file.
                if (hash != expected)
                {
                    throw new SipProtocolException(
                        SipProtocolFault.WrongBlock,
                        $"Asked the peer for block {expected.ToShortString()} and it answered " +
                        $"with {hash.ToShortString()}.");
                }

                if (ciphertext is not { } present)
                {
                    notHeld.Add(hash);
                    continue;
                }

                // Politeness before speed (D-29): the machine's ceiling, applied where the
                // bytes actually arrive.
                await Download.WaitAsync(present.Length, cancellationToken).ConfigureAwait(false);

                if (await _repository.Blobs
                    .PutRawVerifiedAsync(hash, present.ToArray(), cancellationToken)
                    .ConfigureAwait(false))
                {
                    advance(1, present.Length);
                }
                else
                {
                    advance(0, present.Length);
                }
            }

            await TopUpAsync().ConfigureAwait(false);
        }

        return notHeld;
    }

    /// <summary>The other peers a fetch may draw on: reachable in principle, and not ruled out.</summary>
    private List<PeerRecord> AuxiliaryPeers(PeerRecord primary)
    {
        var now = DateTimeOffset.UtcNow;
        return [.. _repository.Peers.Load()
            .Where(candidate =>
                !DeviceIdentity.IsSameDevice(candidate.DeviceId, primary.DeviceId) &&
                !candidate.IsExpired(now) &&
                !_repository.IsRevoked(candidate.DeviceId) &&
                Servers?.IsSuspect(candidate.DeviceId) != true)
            .Take(MaximumAuxiliaryPeers)];
    }

    /// <summary>
    /// Asks each auxiliary what it holds (D-28) and splits the wanted blocks across every
    /// source, lightest-loaded first. The primary can produce everything its own snapshot
    /// names, so it takes whatever nobody else should.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "An auxiliary is best-effort by contract: whatever its channel throws, planning falls " +
                        "back to the primary for its share, and the primary's own channel is the only one that " +
                        "may fail the pull.")]
    private async Task<(List<ContentHash> Primary, List<(PeerRecord Peer, List<ContentHash> Hashes)> Auxiliary)>
        PlanSourcesAsync(
            IReadOnlyList<PeerRecord> auxiliaries,
            IReadOnlyList<ContentHash> wanted,
            CancellationToken cancellationToken)
    {
        var holders = new List<(PeerRecord Peer, HashSet<ContentHash> Has)>();

        foreach (var candidate in auxiliaries)
        {
            try
            {
                var has = await AskWhatItHoldsAsync(candidate, wanted, cancellationToken).ConfigureAwait(false);
                if (has.Count > 0)
                {
                    holders.Add((candidate, has));
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"{candidate.Name}: not sharing this fetch: {ex.Message}");
            }
        }

        var primaryShare = new List<ContentHash>();
        var shares = holders.Select(holder => (holder.Peer, Hashes: new List<ContentHash>(), holder.Has)).ToList();

        foreach (var hash in wanted)
        {
            var lightest = shares
                .Where(share => share.Has.Contains(hash))
                .OrderBy(share => share.Hashes.Count)
                .FirstOrDefault();

            // The primary counts as holding everything; it gets the block when it is the
            // lightest source, which keeps the split even instead of starving it.
            if (lightest.Hashes is null || primaryShare.Count <= lightest.Hashes.Count)
            {
                primaryShare.Add(hash);
            }
            else
            {
                lightest.Hashes.Add(hash);
            }
        }

        return (primaryShare, [.. shares.Where(share => share.Hashes.Count > 0).Select(share => (share.Peer, share.Hashes))]);
    }

    /// <summary>Asks one auxiliary which of the wanted blocks it holds, over a short-lived channel.</summary>
    private async Task<HashSet<ContentHash>> AskWhatItHoldsAsync(
        PeerRecord candidate,
        IReadOnlyList<ContentHash> wanted,
        CancellationToken cancellationToken)
    {
        var (client, channel) = await OpenAuxiliaryChannelAsync(candidate, cancellationToken).ConfigureAwait(false);
        using (client)
        using (channel)
        {
            var has = new HashSet<ContentHash>();
            for (var offset = 0; offset < wanted.Count; offset += HaveRequestMessage.MaximumHashes)
            {
                var page = wanted.Skip(offset).Take(HaveRequestMessage.MaximumHashes).ToList();
                await channel.SendAsync(
                    MessageType.HaveRequest, new HaveRequestMessage { Hashes = page }, cancellationToken)
                    .ConfigureAwait(false);

                var answer = SecureChannel.Decode<HaveResponseMessage>(
                    await ExpectAsync(channel, MessageType.HaveResponse, cancellationToken).ConfigureAwait(false));

                if (answer.Present is null || answer.Present.Count != page.Count)
                {
                    throw new SipProtocolException(
                        SipProtocolFault.MalformedMessage,
                        $"The peer answered {answer.Present?.Count ?? 0} flags to {page.Count} hashes.");
                }

                for (var i = 0; i < page.Count; i++)
                {
                    if (answer.Present[i])
                    {
                        _ = has.Add(page[i]);
                    }
                }
            }

            await channel.SendAsync(MessageType.Goodbye, new { }, cancellationToken).ConfigureAwait(false);
            return has;
        }
    }

    /// <summary>Fetches one auxiliary's share; whatever it cannot deliver goes back to the primary.</summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "An auxiliary is best-effort by contract: whatever its channel throws, its share is " +
                        "returned to the primary and the pull goes on. Only the primary's channel may fail it.")]
    private async Task FetchFromAuxiliaryAsync(
        PeerRecord candidate,
        List<ContentHash> share,
        System.Collections.Concurrent.ConcurrentBag<ContentHash> returned,
        Action<int, long> advance,
        CancellationToken cancellationToken)
    {
        var handled = 0;
        try
        {
            var (client, channel) = await OpenAuxiliaryChannelAsync(candidate, cancellationToken).ConfigureAwait(false);
            using (client)
            using (channel)
            {
                _log?.Invoke($"{candidate.Name}: fetching {share.Count} block(s) alongside");

                // One batch at a time on an auxiliary: it shares the link with the primary,
                // and a failed one hands back the least.
                for (; handled < share.Count; handled += BlockRequestBatchSize)
                {
                    var batch = share.Skip(handled).Take(BlockRequestBatchSize).ToList();
                    var missing = await FetchBlocksPipelinedAsync(channel, batch, advance, cancellationToken)
                        .ConfigureAwait(false);
                    foreach (var hash in missing)
                    {
                        returned.Add(hash);
                    }
                }

                await channel.SendAsync(MessageType.Goodbye, new { }, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log?.Invoke($"{candidate.Name}: its share returns to the primary: {ex.Message}");
            for (var i = handled; i < share.Count; i++)
            {
                returned.Add(share[i]);
            }
        }
    }

    /// <summary>
    /// Tries each auxiliary in turn for the blocks the primary could not produce (D-28): the
    /// re-route D-24's fix said needed one more message. What none can produce comes back.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "As every auxiliary path: a failing helper is skipped, and the caller decides what a " +
                        "block nobody produced means.")]
    private async Task<List<ContentHash>> FetchFromAnyAuxiliaryAsync(
        IReadOnlyList<PeerRecord> auxiliaries,
        List<ContentHash> missing,
        Action<int, long> advance,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in auxiliaries)
        {
            if (missing.Count == 0)
            {
                break;
            }

            try
            {
                var has = await AskWhatItHoldsAsync(candidate, missing, cancellationToken).ConfigureAwait(false);
                var here = missing.Where(has.Contains).ToList();
                if (here.Count == 0)
                {
                    continue;
                }

                var (client, channel) = await OpenAuxiliaryChannelAsync(candidate, cancellationToken).ConfigureAwait(false);
                using (client)
                using (channel)
                {
                    _log?.Invoke($"{candidate.Name}: has {here.Count} block(s) the primary lacks");
                    var still = await FetchBlocksPipelinedAsync(channel, here, advance, cancellationToken)
                        .ConfigureAwait(false);
                    await channel.SendAsync(MessageType.Goodbye, new { }, cancellationToken).ConfigureAwait(false);

                    var fetched = here.Except(still).ToHashSet();
                    missing = [.. missing.Where(hash => !fetched.Contains(hash))];
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"{candidate.Name}: could not help with the missing blocks: {ex.Message}");
            }
        }

        return missing;
    }

    /// <summary>Opens a short-lived authenticated channel to an auxiliary peer, for haves and blocks only.</summary>
    private async Task<(TcpClient Client, SecureChannel Channel)> OpenAuxiliaryChannelAsync(
        PeerRecord candidate,
        CancellationToken cancellationToken)
    {
        var client = new TcpClient();
        try
        {
            await ConnectAnywhereAsync(client, candidate, cancellationToken).ConfigureAwait(false);
            var channel = await SecureChannel.InitiateAsync(
                client.GetStream(),
                _identity,
                _repository.Config.RepositoryId,
                candidate.DeviceId,
                _tuning.StallTimeout,
                cancellationToken).ConfigureAwait(false);
            return (client, channel);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static Task<ReceivedMessage> ExpectAsync(
        SecureChannel channel,
        MessageType expected,
        CancellationToken cancellationToken) =>
        ExpectAsync(channel, expected, timeout: null, cancellationToken);

    private static async Task<ReceivedMessage> ExpectAsync(
        SecureChannel channel,
        MessageType expected,
        TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        var message = await channel
            .ReceiveAsync(timeout, cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated,
                $"The peer closed the connection while a {expected} was expected.");

        if (message.Type == MessageType.Error)
        {
            // The peer's own words, which every result, log line and health record repeats: made
            // safe to show where they enter, so none of those can carry an instruction to a terminal.
            var error = SecureChannel.Decode<ErrorMessage>(message);
            throw new SipProtocolException(
                SipProtocolFault.UnexpectedMessage,
                $"The peer refused the request: {DisplayText.Printable(error.Reason ?? string.Empty, 200)}");
        }

        if (message.Type != expected)
        {
            throw new SipProtocolException(
                SipProtocolFault.UnexpectedMessage,
                $"Expected {expected} from the peer but got {message.Type}.");
        }

        return message;
    }

    /// <summary>
    /// Whether a folder just scanned holds exactly the files a recorded snapshot lists.
    /// </summary>
    /// <remarks>
    /// By content, not by block list. The scan splits a file it re-reads with FastCDC, while
    /// the recorded snapshot may still list that file under the fixed-size split every entry
    /// had before D-22, and the same bytes split two ways have two block lists. Compared by
    /// block list, a merged folder that matches a head exactly would read as different, and
    /// the convergence rule would record a merge snapshot nobody needed.
    /// <see cref="ChunkScheme.SameContentAsync"/> compares block lists when the recipes agree
    /// and re-reads the file only when they do not.
    /// </remarks>
    private async Task<bool> SameContentAsync(
        IReadOnlyList<FileEntry> scanned,
        IReadOnlyList<FileEntry> recorded,
        WorkingTreeScan scan,
        CancellationToken cancellationToken)
    {
        if (scanned.Count != recorded.Count)
        {
            return false;
        }

        var byPath = recorded.ToDictionary(f => f.Path, StringComparer.Ordinal);
        foreach (var file in scanned)
        {
            if (!byPath.TryGetValue(file.Path, out var other))
            {
                return false;
            }

            // A carried entry — for an ignored path, or one the scan could not read or found
            // behind a link — describes no file the scan read, so it is compared as recorded
            // and the disk is never read for it.
            if (_repository.Ignore.IsIgnored(file.Path) || scan.Carried.Contains(file.Path))
            {
                if (file.Size != other.Size || !file.Blocks.SequenceEqual(other.Blocks))
                {
                    return false;
                }

                continue;
            }

            if (!SafePath.TryResolve(file.Path, _repository.Layout.WorkingRoot, out var absolute, out _))
            {
                return false;
            }

            if (!await ChunkScheme.SameContentAsync(absolute, file, other, cancellationToken)
                .ConfigureAwait(false))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Tells one of the person's own machines about this one, and takes what it says about
    /// itself: the first exchange on the channel, before anything is synced.
    /// </summary>
    /// <remarks>
    /// A peer on a build that does not know the request answers <see cref="MessageType.Error"/>,
    /// which is taken as "no record": it is logged and the sync goes on as before. A malformed
    /// answer is a malformed message like any other, and ends this sync with the peer.
    /// </remarks>
    private async Task ExchangeServerRecordsAsync(
        SecureChannel channel,
        ServerExchange servers,
        PeerRecord peer,
        CancellationToken cancellationToken)
    {
        await channel.SendAsync(MessageType.ServerRecordRequest, servers.For(channel.PeerDeviceId), cancellationToken)
            .ConfigureAwait(false);

        var answer = await channel.ReceiveAsync(cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated,
                $"The peer closed the connection while a {MessageType.ServerRecordResponse} was expected.");

        if (answer.Type == MessageType.Error)
        {
            _log?.Invoke($"{peer.Name}: does not exchange Server.ID records, so it runs an older SippBucket");
            return;
        }

        if (answer.Type != MessageType.ServerRecordResponse)
        {
            throw new SipProtocolException(
                SipProtocolFault.UnexpectedMessage,
                $"Expected {MessageType.ServerRecordResponse} from the peer but got {answer.Type}.");
        }

        servers.Take(channel.PeerDeviceId, SecureChannel.Decode<ServerExchangeMessage>(answer), _repository.Config.Name);
    }

    /// <summary>
    /// Brings the two machines' key rings level (D-70): learns a rotation the peer made, and
    /// hands the peer one made here, before anything is synced.
    /// </summary>
    /// <remarks>
    /// Runs on every sync, own machines and team members alike: everyone holding the folder
    /// key must learn a rotation, or their next save is under a key the fleet is leaving.
    /// A peer on a build that does not know the request answers <see cref="MessageType.Error"/>,
    /// which is logged and the sync goes on: a folder never rotated loses nothing, and one
    /// that was rotated fails loudly at the blocks that machine cannot serve under keys it
    /// never learned.
    /// </remarks>
    private async Task ExchangeKeyStatusAsync(
        SecureChannel channel,
        PeerRecord peer,
        CancellationToken cancellationToken)
    {
        var mine = _repository.KeyGeneration;
        await channel.SendAsync(
            MessageType.KeyStatusRequest, new KeyStatusRequestMessage { Generation = mine }, cancellationToken)
            .ConfigureAwait(false);

        var answer = await channel.ReceiveAsync(cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated,
                $"The peer closed the connection while a {MessageType.KeyStatusResponse} was expected.");

        if (answer.Type == MessageType.Error)
        {
            _log?.Invoke($"{peer.Name}: does not exchange key rings, so it runs an older SippBucket");
            return;
        }

        if (answer.Type != MessageType.KeyStatusResponse)
        {
            throw new SipProtocolException(
                SipProtocolFault.UnexpectedMessage,
                $"Expected {MessageType.KeyStatusResponse} from the peer but got {answer.Type}.");
        }

        var status = SecureChannel.Decode<KeyStatusResponseMessage>(answer);

        if (status.Update is { Keys: not null, Revoked: not null } update)
        {
            _ = _repository.ApplyKeyUpdate(update.Keys, update.Revoked, _log);
            return;
        }

        if (status.Generation < mine)
        {
            // The peer is behind: hand it this folder's ring, and read its acknowledgement so
            // the channel stays in lockstep.
            await channel.SendAsync(
                MessageType.KeyUpdatePush,
                new KeyUpdateMessage { Keys = _repository.KeyRing, Revoked = _repository.RevokedDevices },
                cancellationToken).ConfigureAwait(false);

            _ = SecureChannel.Decode<KeyStatusResponseMessage>(
                await ExpectAsync(channel, MessageType.KeyStatusResponse, cancellationToken).ConfigureAwait(false));
            _log?.Invoke($"{peer.Name}: given the folder's rotated key ring");
        }
    }

    /// <summary>
    /// Fetches the discovery key this peer minted for this machine (docs/DISCOVERY.md), when
    /// discovery runs here at all. "No key" and an older build's Error are both ordinary.
    /// </summary>
    private async Task FetchDiscoveryKeyAsync(
        SecureChannel channel,
        PeerRecord peer,
        CancellationToken cancellationToken)
    {
        if (DiscoveryKeySink is not { } sink)
        {
            return;
        }

        await channel.SendAsync(MessageType.DiscoveryKeyRequest, new { }, cancellationToken).ConfigureAwait(false);

        var answer = await channel.ReceiveAsync(cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated,
                $"The peer closed the connection while a {MessageType.DiscoveryKeyResponse} was expected.");

        if (answer.Type == MessageType.Error)
        {
            return;
        }

        if (answer.Type != MessageType.DiscoveryKeyResponse)
        {
            throw new SipProtocolException(
                SipProtocolFault.UnexpectedMessage,
                $"Expected {MessageType.DiscoveryKeyResponse} from the peer but got {answer.Type}.");
        }

        if (SecureChannel.Decode<DiscoveryKeyResponseMessage>(answer).KeyBase64 is { } key)
        {
            try
            {
                sink(peer.DeviceId, key);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                _log?.Invoke($"{peer.Name}: its discovery key could not be kept: {ex.Message}");
            }
        }
    }

    /// <summary>What a sync learned before it could fail, for the fault boundary to report.</summary>
    private sealed class SyncProgress
    {
        /// <summary>How many snapshots the peer is known to be ahead by.</summary>
        public int SnapshotsBehind { get; set; }

        /// <summary>
        /// Whether this side of the handshake completed, proving the machine on the other end is
        /// the peer: from then on it was reached (D-58), and what it sends is held against it.
        /// </summary>
        public bool Authenticated { get; set; }
    }
}
