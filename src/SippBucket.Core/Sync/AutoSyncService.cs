using System.Diagnostics.CodeAnalysis;
using SippBucket.Core.Crypto;
using SippBucket.Core.Repository;
using SippBucket.Core.Servers;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Sync;

/// <summary>
/// Keeps one repository always in sync without anyone asking it to: serves peers through the
/// machine's host, saves when the folder changes, and pulls from peers on a timer.
/// </summary>
/// <remarks>
/// <para>
/// This is the always-in-sync feature, and it is the reason the daemon exists. A user is
/// expected to set a folder up once and never think about it again.
/// </para>
/// <para>
/// It does not own a listener. One <see cref="PeerHost"/> serves every folder on the machine
/// from one port (D-40); this registers its repository there on <see cref="Start"/> and
/// unregisters on dispose. Whether the host is listening is a fact about the machine, and this
/// folder's status reports it as its own, because a folder on a machine that serves nobody is
/// served to nobody.
/// </para>
/// <para>
/// File changes are debounced. An application saving a document can touch it several times
/// in a second, and taking a snapshot per touch would fill the store with noise, so changes
/// settle for <see cref="DebounceInterval"/> before a save happens.
/// </para>
/// </remarks>
public sealed class AutoSyncService : IAsyncDisposable
{
    /// <summary>How long file changes must settle before a save is taken.</summary>
    public TimeSpan DebounceInterval => _tuning.DebounceInterval;

    /// <summary>How often peers are polled even when nothing changed locally.</summary>
    public TimeSpan PollInterval => _tuning.PollInterval;

    private readonly SipRepository _repository;
    private readonly DeviceIdentity _identity;
    private readonly Action<string>? _log;
    private readonly SyncTuning _tuning;
    private readonly ServerExchange? _servers;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _stopping = new();

    // Every field from here to _serverFault is written by the sync cycle, the poll loop or
    // the server task, and read by GetStatus on whichever thread the interface refreshes
    // from. They were unsynchronised while the only reader was a thirty-second tooltip
    // timer, which made a collision rare rather than impossible; a window that refreshes
    // every couple of seconds makes it routine. A Dictionary read during an insert can
    // throw or hand back a half-written entry, and a DateTimeOffset? is wider than a machine
    // word, so even a timestamp could be read torn. One lock guards them as a unit, so a
    // status is never assembled from the ends of two different cycles.
    private readonly object _statusLock = new();
    private readonly Dictionary<string, PeerStatus> _peerStatus = new(StringComparer.Ordinal);
    private readonly List<string> _recentConflicts = [];

    private IReadOnlyList<SkippedPath> _notSynced = [];
    private TransferProgress? _transfer;
    private BucketUsage? _lastBucketUsage;
    private DateTimeOffset? _lastSyncUtc;
    private DateTimeOffset? _lastAttemptUtc;
    private string? _lastFailureReason;
    private string? _lastSkipReason;
    private int _consecutiveFailures;
    private string? _serverFault;

    private const int MaxRememberedConflicts = 20;

    private FileSystemWatcher? _watcher;
    private PeerHost? _host;
    private IAsyncDisposable? _registration;
    private Task? _pollTask;
    private DateTimeOffset _changedAt = DateTimeOffset.MinValue;
    private bool _disposed;

    /// <summary>Creates the service for one repository.</summary>
    /// <param name="repository">The repository to keep in sync.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="log">Optional sink for status lines.</param>
    /// <param name="tuning">The deadlines to sync under, or null for the defaults.</param>
    /// <param name="servers">
    /// Server.ID's exchange, names and health records, which each cycle's sync takes part in;
    /// null to sync without them.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public AutoSyncService(
        SipRepository repository,
        DeviceIdentity identity,
        Action<string>? log = null,
        SyncTuning? tuning = null,
        ServerExchange? servers = null)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(identity);

        _repository = repository;
        _identity = identity;
        _log = log;
        _tuning = tuning ?? SyncTuning.Default;
        _servers = servers;

        // The cycle saves before it makes its engine, and an automatic save must be signed
        // like any other (D-21). Whoever opened the repository with another signer keeps it.
        repository.Signer ??= new SnapshotSigner(identity);
    }

    /// <summary>True while the service is running.</summary>
    public bool IsRunning { get; private set; }

    /// <summary>
    /// Extra addresses discovery learned for a peer, or null while discovery is not running:
    /// passed to each cycle's engine (D-32, the piece that was never wired).
    /// </summary>
    /// <remarks>
    /// Additions, never replacements: the engine's own contract. The tray sets this once,
    /// from the daemon's discovery sightings joined to each peer's configured port.
    /// </remarks>
    public Func<string, IReadOnlyList<(string Host, int Port)>>? ExtraAddresses { get; set; }

    /// <summary>Where discovery keys peers mint for this machine are kept, or null (docs/DISCOVERY.md).</summary>
    public Action<string, string>? DiscoveryKeySink { get; set; }

    /// <summary>
    /// The machine's download ceiling for blocks (D-29), shared across every folder so the
    /// machine's link has one budget; unlimited unless the tray sets it from master.json.
    /// </summary>
    public Protocol.RateLimiter DownloadLimit { get; set; } = Protocol.RateLimiter.Unlimited;

    /// <summary>
    /// When every configured peer was last contacted without error. Null until that has
    /// happened once.
    /// </summary>
    /// <remarks>
    /// This is the value the tray turns into "synced 11:47", so it has one job: never to be
    /// set on a cycle that did not actually sync. It previously moved forward whenever a
    /// cycle finished, which meant a cycle where every peer was unreachable still refreshed
    /// the timestamp — the tray read "synced" seconds after the last byte anyone had
    /// exchanged. A repository with no peers counts as synced, because there is nothing it
    /// could be out of date with.
    /// </remarks>
    public DateTimeOffset? LastSyncUtc
    {
        get
        {
            lock (_statusLock)
            {
                return _lastSyncUtc;
            }
        }
    }

    /// <summary>When a cycle last finished, whatever it concluded.</summary>
    public DateTimeOffset? LastAttemptUtc
    {
        get
        {
            lock (_statusLock)
            {
                return _lastAttemptUtc;
            }
        }
    }

    /// <summary>Why the last cycle did not fully sync, or null if it did.</summary>
    public string? LastFailureReason
    {
        get
        {
            lock (_statusLock)
            {
                return _lastFailureReason;
            }
        }
    }

    /// <summary>How many cycles in a row have failed to reach every peer.</summary>
    public int ConsecutiveFailures
    {
        get
        {
            lock (_statusLock)
            {
                return _consecutiveFailures;
            }
        }
    }

    /// <summary>
    /// True when this folder is genuinely in sync: running, and the last cycle reached every
    /// peer. This is what the tray should believe rather than "the service object exists."
    /// </summary>
    /// <remarks>
    /// Both fields are read under one acquisition. Reading them through their own getters
    /// would take the lock twice, and a cycle finishing between the two reads could pair a
    /// failure count from one cycle with a fault from another.
    /// </remarks>
    public bool IsHealthy
    {
        get
        {
            lock (_statusLock)
            {
                return IsRunning && _consecutiveFailures == 0 && ServerFaultLocked() is null;
            }
        }
    }

    /// <summary>
    /// Why this folder is not being served to other peers, or null when it is.
    /// </summary>
    /// <remarks>
    /// Either this folder's own reason, which is another folder on this machine already
    /// serving the same repository, or the machine's: the host's listener could not open its
    /// port, the usual cause being another program on it, or has stopped. Both make this
    /// replica invisible to everyone else while it still appears to be running, so both are
    /// reported here, by every folder the machine-level one affects.
    /// </remarks>
    public string? ServerFault
    {
        get
        {
            lock (_statusLock)
            {
                return ServerFaultLocked();
            }
        }
    }

    /// <summary>
    /// Why the last cycle was skipped rather than run, or why a peer's changes were deferred in
    /// it; null when the last cycle ran and applied everything it was offered.
    /// </summary>
    public string? LastSkipReason
    {
        get
        {
            lock (_statusLock)
            {
                return _lastSkipReason;
            }
        }
    }

    /// <summary>Starts serving through <paramref name="host"/>, watching and polling.</summary>
    /// <param name="host">This machine's host, which serves every folder.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host"/> was null.</exception>
    /// <exception cref="ObjectDisposedException">The service was disposed.</exception>
    public void Start(PeerHost host)
    {
        ArgumentNullException.ThrowIfNull(host);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (IsRunning)
        {
            return;
        }

        lock (_statusLock)
        {
            _host = host;
        }

        try
        {
            _registration = host.Register(_repository);
        }
        catch (RepositoryAlreadyServedException ex)
        {
            var fault = $"not serving peers: {ex.Message}";
            lock (_statusLock)
            {
                _serverFault = fault;
            }

            _log?.Invoke(fault);
        }

        _watcher = new FileSystemWatcher(_repository.Layout.WorkingRoot)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName
                | NotifyFilters.DirectoryName
                | NotifyFilters.LastWrite
                | NotifyFilters.Size,
        };

        _watcher.Changed += OnFileSystemChanged;
        _watcher.Created += OnFileSystemChanged;
        _watcher.Deleted += OnFileSystemChanged;
        _watcher.Renamed += OnFileSystemChanged;
        _watcher.EnableRaisingEvents = true;

        _pollTask = PollLoopAsync(_stopping.Token);
        IsRunning = true;

        _log?.Invoke($"watching {_repository.Layout.WorkingRoot}");
    }

    /// <summary>Saves any pending changes and pulls from every peer, now.</summary>
    /// <param name="cancellationToken">Cancels the cycle.</param>
    /// <returns>One result per configured peer, failures included.</returns>
    public async Task<IReadOnlyList<SyncResult>> RunCycleAsync(
        CancellationToken cancellationToken = default)
    {
        // One cycle at a time. A timer tick and a file change arriving together must not
        // both walk the working tree and race each other into the store.
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // The local save comes first and is deliberately independent of every peer.
            // Taking a snapshot is this machine's own business: it is what makes the history
            // exist and what a later sync has to offer. If it ever waited on the network,
            // an unreachable laptop would cost the desktop its own version history.
            var saved = await _repository
                .SaveAsync("Automatic save", _identity.DeviceId, cancellationToken)
                .ConfigureAwait(false);

            if (saved is not null)
            {
                _log?.Invoke($"saved {saved.SnapshotId.ToShortString()}");
                if (saved.AfterSaveNote is { } note)
                {
                    _log?.Invoke(note);
                }
            }

            RecordSkipped(_repository.LastScanSkipped);

            var engine = new SyncEngine(_repository, _identity, _log, _tuning)
            {
                Servers = _servers,
                ExtraAddresses = ExtraAddresses,
                DiscoveryKeySink = DiscoveryKeySink,
                Download = DownloadLimit,

                // What "Receiving · 812 / 1,284 blocks" is fed by (D-31): the newest report
                // wins, and the cycle's end clears it below whatever happened.
                Progress = progress =>
                {
                    lock (_statusLock)
                    {
                        _transfer = progress;
                    }
                },
            };

            IReadOnlyList<SyncResult> results;
            try
            {
                results = await engine.SyncAllAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                lock (_statusLock)
                {
                    _transfer = null;
                }
            }

            // Once per cycle, on the path that is already doing real work, so the tray can
            // report storage without paying for a store walk every time it redraws. Measured
            // into a local and published with the rest of the cycle's results, because an
            // await cannot sit inside the status lock.
            var usage = await _repository
                .MeasureBucketAsync(cancellationToken).ConfigureAwait(false);

            RecordCycle(results, usage);
            return results;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Everything the interface may say about this folder, as of now.
    /// </summary>
    /// <returns>The current status.</returns>
    /// <remarks>
    /// Computed on demand from a clock rather than pushed on change, and that is the whole
    /// point. The failures this daemon is most likely to have are silent — a wedged read
    /// never returns, so there is no event to publish and nothing to subscribe to. A status
    /// that waits to be told will never be told. Asking produces a fresh answer; not asking
    /// produces a stale one that at least knows it is stale.
    /// </remarks>
    public FolderStatus GetStatus() => GetStatus(DateTimeOffset.UtcNow);

    /// <summary>Everything the interface may say about this folder, at a given moment.</summary>
    /// <param name="nowUtc">The moment to evaluate freshness against.</param>
    /// <returns>The status as it would appear then.</returns>
    /// <remarks>
    /// The time is a parameter because freshness decay is otherwise untestable without
    /// waiting out the real interval, and a decay rule nobody can test is a decay rule
    /// nobody should trust.
    /// </remarks>
    public FolderStatus GetStatus(DateTimeOffset nowUtc)
    {
        // Read from disk outside the lock. The lock guards what the cycle publishes, not the
        // peer list file, and holding it across I/O would make a slow disk stall the cycle.
        var peers = _repository.Peers.Load();

        lock (_statusLock)
        {
            return BuildStatus(peers, nowUtc);
        }
    }

    /// <summary>This folder's serving fault, then the machine's. The caller holds <see cref="_statusLock"/>.</summary>
    private string? ServerFaultLocked() => _serverFault ?? _host?.Fault;

    /// <summary>Assembles the status. The caller holds <see cref="_statusLock"/>.</summary>
    private FolderStatus BuildStatus(IReadOnlyList<PeerRecord> peers, DateTimeOffset nowUtc)
    {
        return new FolderStatus
        {
            FolderName = _repository.Config.Name,
            Freshness = Freshness.Evaluate(_lastSyncUtc, nowUtc, PollInterval, peers.Count > 0),
            LastSyncUtc = _lastSyncUtc,
            LastAttemptUtc = _lastAttemptUtc,
            ConsecutiveFailures = _consecutiveFailures,
            LastFailureReason = _lastFailureReason,
            SkippedReason = _lastSkipReason,
            ServerFault = ServerFaultLocked(),
            Transfer = _transfer,
            Peers = peers
                .Select(p => _peerStatus.TryGetValue(p.DeviceId, out var known)
                    ? known
                    : new PeerStatus { Name = p.Name, IsReachable = true })
                .ToList(),
            RecentConflicts = _recentConflicts.ToList(),
            NotSynced = _notSynced,

            // Refreshed on each cycle rather than measured here. Measuring walks every
            // block in the store, and GetStatus is called by a tooltip timer every thirty
            // seconds — doing the walk on the read path would make looking at the tray cost
            // more than syncing does.
            //
            // It was null until now, which meant "Bucket full" was a state five design
            // boards presented as the daemon's own words and the daemon could not actually
            // emit. Found by an adversarial pass comparing the drawings against the code.
            Bucket = _lastBucketUsage,
            HasPassphrase = _repository.IsLocked,

            // Always true here. This service only exists over an OPEN repository, and
            // opening one is exactly the act of loading its key. A surface describing a
            // folder it could not open reports the other way round.
            IsUnlockedForSession = true,
        };
    }

    /// <summary>
    /// Updates the health fields from what a cycle actually achieved.
    /// </summary>
    private void RecordCycle(IReadOnlyList<SyncResult> results, BucketUsage usage)
    {
        var now = DateTimeOffset.UtcNow;

        lock (_statusLock)
        {
            RecordCycleLocked(results, usage, now);
        }
    }

    /// <summary>Publishes a cycle's results. The caller holds <see cref="_statusLock"/>.</summary>
    /// <remarks>
    /// <para>
    /// A deferred peer (<see cref="SyncOutcome.Deferred"/>) was reached and is recorded as
    /// reachable, with no failure counted against it; and it was not synced, so the folder is
    /// not marked synced either, and freshness keeps decaying on its clock (A1, A2). Why it was
    /// deferred is kept as the skip reason.
    /// </para>
    /// <para>
    /// A peer not tried (<see cref="SyncOutcome.NotTried"/>) was never contacted, so this cycle
    /// changes nothing recorded about it: not its reachability, not its last-seen time, and not
    /// the folder's failure count, which it can neither add to nor forgive. The folder is not
    /// marked synced. Recording it as reached, as a deferral, gave a machine that was switched
    /// off a last-seen time it never had and wiped the failures that said so.
    /// </para>
    /// </remarks>
    private void RecordCycleLocked(IReadOnlyList<SyncResult> results, BucketUsage usage, DateTimeOffset now)
    {
        _lastAttemptUtc = now;
        _lastBucketUsage = usage;

        var notSynced = results
            .Where(r => r.Outcome is SyncOutcome.Deferred or SyncOutcome.NotTried or SyncOutcome.Held)
            .ToList();
        _lastSkipReason = notSynced.Count switch
        {
            0 => null,
            1 => notSynced[0].Summary,
            _ => $"{notSynced.Count} of {results.Count} peers not synced yet: {notSynced[0].FailureReason}",
        };

        foreach (var result in results)
        {
            if (!result.Tried)
            {
                continue;
            }

            // Kept by device, not by name: a peer's name becomes "Server 2 (…)" once Server.ID
            // has numbered it, and a status kept by name would then show it twice.
            //
            // Reached and synced are two facts (D-58). This used to set IsReachable from
            // Succeeded, so a peer that answered and then failed on its data was drawn as off
            // the network. Last seen is when it last answered, whatever the sync then did. Only a
            // failure is a failure: a deferral or a held change is the folder's skip reason.
            _peerStatus[result.DeviceId] = new PeerStatus
            {
                Name = result.PeerName,
                IsReachable = result.PeerReached,
                SyncFailed = result.Outcome == SyncOutcome.Failed,
                LastSeenUtc = result.PeerReached
                    ? now
                    : _peerStatus.TryGetValue(result.DeviceId, out var previous)
                        ? previous.LastSeenUtc
                        : null,
                FailureReason = result.Outcome == SyncOutcome.Failed ? result.FailureReason : null,

                // Non-zero only when the peer was reached, its head learned, and the pull
                // then failed or was deferred: the cases where "behind by N" is both true and
                // known.
                SnapshotsBehind = result.SnapshotsBehind,
            };

            if (result.ConflictsRenamed.Count > 0)
            {
                foreach (var conflict in result.ConflictsRenamed)
                {
                    _recentConflicts.Add(conflict);
                }

                // Conflicts are kept as a recent-history line, not as an ever-growing list.
                // Both versions are on disk regardless; this is only what the folder
                // mentions, and a folder that mentions three hundred things mentions none.
                while (_recentConflicts.Count > MaxRememberedConflicts)
                {
                    _recentConflicts.RemoveAt(0);
                }
            }
        }

        var failed = results.Where(r => r.Outcome == SyncOutcome.Failed).ToList();
        if (failed.Count == 0)
        {
            // Every peer contacted answered. Synced only if every peer was contacted and every
            // answer was also applied.
            if (notSynced.Count == 0)
            {
                _lastSyncUtc = now;
            }

            // A peer not contacted may be the very one that has been failing, so its failures
            // are forgiven only by a cycle that reached it.
            if (results.All(r => r.Tried))
            {
                _lastFailureReason = null;
                _consecutiveFailures = 0;
            }

            return;
        }

        _consecutiveFailures++;
        _lastFailureReason = failed.Count == 1
            ? failed[0].Summary
            : $"{failed.Count} of {results.Count} peers not synced";
    }

    /// <summary>
    /// Publishes what the cycle's save could not read, and logs it when it changes.
    /// </summary>
    /// <remarks>
    /// The scan no longer fails the folder over one entry it cannot read; it skips the entry
    /// and keeps what was last recorded for it (DATA-03). That is only half of the behaviour:
    /// a skipped entry nobody hears about is a file that has quietly stopped syncing. So it
    /// goes into the status the tray draws, and into the log once each time the list changes
    /// rather than on every poll.
    /// </remarks>
    private void RecordSkipped(IReadOnlyList<SkippedPath> skipped)
    {
        bool changed;
        lock (_statusLock)
        {
            changed = !_notSynced.SequenceEqual(skipped);
            _notSynced = skipped;
        }

        if (changed)
        {
            foreach (var entry in skipped)
            {
                _log?.Invoke($"not synced: {entry.Describe()}");
            }
        }
    }

    /// <summary>
    /// Records that a cycle failed outright, as opposed to completing with failed peers.
    /// </summary>
    private void RecordCycleFault(string reason)
    {
        var now = DateTimeOffset.UtcNow;

        lock (_statusLock)
        {
            _lastAttemptUtc = now;
            _consecutiveFailures++;
            _lastFailureReason = reason;
            _lastSkipReason = null;
        }
    }

    /// <summary>
    /// Records that a cycle did not run because another operation held the folder.
    /// </summary>
    /// <remarks>
    /// Not a failure, and deliberately not counted as one: nothing is wrong with this folder
    /// or any peer. <c>sip save</c> run by hand, or another session's SippBucket, was
    /// writing to it (D-38), and the next poll tries again. Nothing is marked as synced
    /// either, so freshness keeps decaying on its clock exactly as it would with no cycle at
    /// all (standard A2), and the reason is kept for the status to show.
    /// </remarks>
    private void RecordCycleSkipped(string reason)
    {
        lock (_statusLock)
        {
            _lastSkipReason = reason;
        }
    }

    private void OnFileSystemChanged(object sender, FileSystemEventArgs e)
    {
        var relative = _repository.ToRelativePath(e.FullPath);
        if (_repository.Ignore.IsIgnored(relative))
        {
            return;
        }

        _changedAt = DateTimeOffset.UtcNow;
    }

    private async Task PollLoopAsync(CancellationToken cancellationToken)
    {
        using var ticker = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var lastPoll = DateTimeOffset.UtcNow;

        try
        {
            while (await ticker.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                var now = DateTimeOffset.UtcNow;
                var settled = _changedAt != DateTimeOffset.MinValue &&
                              now - _changedAt >= DebounceInterval;
                var due = now - lastPoll >= PollInterval;

                if (!settled && !due)
                {
                    continue;
                }

                _changedAt = DateTimeOffset.MinValue;
                lastPoll = now;

                await RunCycleSafelyAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
    }

    /// <summary>
    /// Runs one cycle and survives whatever it throws.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The list this used to hold — IO, access denied, protocol, corrupt block — was a list
    /// of the failures that had been thought of. A <see cref="FormatException"/> from four
    /// bad base64 characters was not on it, and the result was that the loop below ended
    /// permanently: no more polling, no more debounced saves, no log line, no change to the
    /// tray icon. The folder simply stopped being kept in sync and nothing said so.
    /// </para>
    /// <para>
    /// A daemon loop is the one place where catching everything is correct. The cost of
    /// swallowing an unexpected exception is a logged failure and a retry in sixty seconds;
    /// the cost of not catching it is the entire feature, silently, until reboot.
    /// </para>
    /// </remarks>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "The daemon's top-level loop. Any escaping exception permanently " +
                        "stops syncing and local snapshotting; cancellation is rethrown.")]
    internal async Task RunCycleSafelyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await RunCycleAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (FolderBusyException ex)
        {
            // Another operation holds the folder. The cycle is skipped, not failed: see
            // RecordCycleSkipped.
            var reason = $"cycle skipped: {ex.Message}";
            _log?.Invoke(reason);
            RecordCycleSkipped(reason);
        }
        catch (Exception ex)
        {
            // A file being written by another application is the common case. The next cycle
            // picks it up, so this is recorded and retried rather than escalated.
            // A full bucket is not a fault and must not read like one. It is the daemon
            // doing exactly what the user configured, and the message already names the
            // remedy — dressing it up as "cycle failed: BucketFullException" would hide a
            // deliberate limit behind what looks like a crash.
            var reason = ex switch
            {
                BucketFullException => ex.Message,
                IOException or UnauthorizedAccessException => $"cycle deferred: {ex.Message}",
                _ => $"cycle failed: {ex.GetType().Name}: {ex.Message}",
            };

            _log?.Invoke(reason);
            RecordCycleFault(reason);
        }
    }

    /// <summary>
    /// Stops watching and polling, and stops this folder being served. The host itself keeps
    /// running for every other folder.
    /// </summary>
    /// <returns>A task that completes when the folder is no longer served and no cycle is running.</returns>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        IsRunning = false;

        await _stopping.CancelAsync().ConfigureAwait(false);

        if (_watcher is not null)
        {
            _watcher.EnableRaisingEvents = false;
            _watcher.Dispose();
        }

        // First, and waited for: unregistering closes this folder's open connections and
        // waits for them, so the repository can be disposed as soon as this returns.
        if (_registration is not null)
        {
            await _registration.DisposeAsync().ConfigureAwait(false);
        }

        if (_pollTask is not null)
        {
            try
            {
                await _pollTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
        }

        _stopping.Dispose();
        _gate.Dispose();
    }
}

