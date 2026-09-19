using System.Diagnostics.CodeAnalysis;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Discovery;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Messages;
using SippBucket.Core.Network.PortMapping;
using SippBucket.Core.Platform;
using SippBucket.Core.Push;
using SippBucket.Core.Repository;
using SippBucket.Core.Servers;
using SippBucket.Core.Sync;

namespace SippBucket.Tray;

/// <summary>
/// The part of the tray that is the daemon rather than the window: this machine's settings,
/// the one host every folder is served through (D-40), a sync service per folder built on
/// both, and Direct Push beside them.
/// </summary>
/// <remarks>
/// <para>
/// Separate from <see cref="TrayApplication"/> so that it can be built by a test with no
/// icon, no window and no autostart entry. Two reviews of <c>wave2/host</c> found that a tray
/// which built its host some other way, or ran its folders on the default timings rather
/// than <c>master.json</c>'s, still passed every test, because nothing in the suite
/// constructed the tray. Everything the tray does with <c>master.json</c> happens here.
/// </para>
/// <para>
/// It does not own the folders' repositories or services once started: the tray keeps them,
/// stops them when a folder is no longer watched, and disposes this last, which closes the
/// port.
/// </para>
/// </remarks>
internal sealed class TrayDaemon : IAsyncDisposable, IDisposable
{
    private readonly DeviceIdentity _identity;
    private readonly Action<string> _log;
    private readonly Core.Protocol.RateLimiter _downloadLimit;

    /// <summary>Builds the host from this machine's settings. Nothing listens until <see cref="Start"/>.</summary>
    /// <param name="identity">This machine's identity, which every folder is served as.</param>
    /// <param name="machine">This machine's settings, from <c>master.json</c>.</param>
    /// <param name="log">Where status lines go.</param>
    /// <param name="preferences">The person's Direct Push settings, or null for this user's own.</param>
    /// <param name="machines">The person's answers about whose each machine is, or null for this user's own.</param>
    /// <param name="watchedFolders">The folders this person syncs, or null for this user's watch list.</param>
    /// <param name="servers">The directory of the person's servers, or null for this user's own.</param>
    /// <param name="health">The health records and alerts log, or null for this user's own.</param>
    /// <param name="identify">
    /// Works out this machine's Server.ID, or null to read this machine's firmware and files.
    /// </param>
    /// <param name="people">The person's grouping of machines into people, or null for this user's own.</param>
    /// <param name="teamSettings">The person's team settings, or null for this user's own.</param>
    /// <param name="messages">The message store, or null for this user's own.</param>
    /// <param name="onMessage">
    /// Told of each direct message stored, with who from, unless muted: the tray's
    /// notification. Or null.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <remarks>
    /// Every problem the file had is logged here, once, so a fallback to a default is visible
    /// in the window's activity as well as in <c>sip doctor</c>. The tray passes only the first
    /// three and <paramref name="onMessage"/>; a test passes the rest, so that nothing it
    /// starts reads or writes the person's own Direct Push settings, inbox, server directory,
    /// health records, Server.ID value, people, team settings or messages.
    /// </remarks>
    public TrayDaemon(
        DeviceIdentity identity,
        MasterConfig machine,
        Action<string> log,
        PushPreferencesStore? preferences = null,
        KnownMachines? machines = null,
        Func<IReadOnlyList<string>>? watchedFolders = null,
        KnownServers? servers = null,
        PeerHealth? health = null,
        Func<ServerIdentity>? identify = null,
        PeopleStore? people = null,
        TeamSettingsStore? teamSettings = null,
        MessageStore? messages = null,
        Action<PersonScope, string>? onMessage = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(machine);
        ArgumentNullException.ThrowIfNull(log);

        _identity = identity;
        _log = log;
        Machine = machine;

        foreach (var problem in machine.Problems)
        {
            log($"master.json: {problem.Message}");
        }

        var owners = machines ?? KnownMachines.ForThisUser();

        // Server.ID and peer health: one exchange for every folder and for Direct Push, so a
        // server is numbered, named and counted the same whichever connection it came on.
        var deviceId = identity.DeviceId;
        Servers = new ServerExchange(
            identify ?? (() => ServerIdentity.ForThisMachine(deviceId)),
            servers ?? KnownServers.ForThisUser(),
            owners,
            now => SelfReports.ForThisMachine(machine, now),
            health ?? PeerHealth.ForThisUser(),
            machine.Health,
            log);

        Host = PeerHost.ForMachine(identity, machine, log);
        Host.Servers = Servers;

        // Per machine, while pairing is per folder: who may push is whoever any watched folder
        // is paired with, read from the folders' own peer lists on each connection, and named
        // by its server's number once Server.ID knows it.
        var folders = watchedFolders ?? WatchedFolders.Load;
        var peopleStore = people ?? PeopleStore.ForThisUser();
        var messageStore = messages ?? MessageStore.ForThisUser();

        // The team switch, decided fresh at each check from the person's own answers,
        // grouping and settings, and the folders' pairing records.
        Team = new TeamFeatures(
            owners,
            peopleStore,
            teamSettings ?? TeamSettingsStore.ForThisUser(),
            () => PairedMachines.AllDeviceIds(folders()));

        DirectPush = new DirectPushService(
            identity,
            machine,
            preferences ?? PushPreferencesStore.ForThisUser(),
            owners,
            deviceId => PairedMachines.NameOf(folders(), deviceId) is { } paired ? Servers.NameOf(deviceId) ?? paired : null,
            folders,
            log,
            teamFeatures: Team.On,
            servers: Servers,
            people: peopleStore,
            messages: messageStore,
            onMessage: onMessage);

        // Store-and-forward, at the sender: queued messages go out on the tray's timer, to
        // each machine of the person at its pairing record's address and the push port.
        Messages = new MessageDelivery(
            messageStore,
            identity,
            Team.On,
            deviceId => MessageRoutes.To(folders(), deviceId, machine.Push.Port),
            PushTuning.ForMachine(machine),
            log);

        // The router mapping (D-05): held only while network.portMapping is on, refreshed on
        // the same timer, and deleted from the router when the daemon stops.
        PortMapping = new PortMappingService(machine.ListenPort, machine.PortMappingLifetime, log);

        // One download budget for the whole machine (D-29), shared by every folder's engine;
        // the upload budget lives on the host, set by ForMachine.
        _downloadLimit = machine.DownloadLimit;

        // Local discovery (D-32): the token packets, the per-peer keys, and consent per
        // network. Listening always runs - it emits nothing - and announcing needs a network
        // the person allowed, plus at least one peer with a minted key.
        var discoveryKeys = DiscoveryKeys.ForThisUser();
        Consent = new NetworkConsent(System.IO.Path.Combine(UserDataDirectory.Resolve(), "networks.json"));

        Discovery = new LocalDiscovery(
            mintedKeys: () => EligibleMinted(discoveryKeys, owners, folders),
            theirKeys: () => TheirKeysSafely(discoveryKeys),
            isKnownPeer: deviceId => PairedMachines.NameOf(folders(), deviceId) is not null,
            mayAnnounceOn: Consent.MayAnnounceOn,
            log);

        // The announcer's half of the key exchange: a key is served, minting one if none
        // exists, only to a machine the person said is their own. Another person's machine
        // gets none by default (docs/DISCOVERY.md).
        Host.DiscoveryKeyForCaller = deviceId =>
        {
            if (PairedMachines.NameOf(folders(), deviceId) is null || !IsOwnSafely(owners, deviceId))
            {
                return null;
            }

            try
            {
                return discoveryKeys.MintedFor(deviceId);
            }
            catch (InvalidOperationException ex)
            {
                log($"discovery: a key could not be served: {ex.Message}");
                return null;
            }
        };

        // The listener's half, and the addresses: what each folder's engine takes with it.
        DiscoveryKeySink = (deviceId, key) =>
        {
            try
            {
                discoveryKeys.StoreTheirs(deviceId, key);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                log($"discovery: a peer's key could not be kept: {ex.Message}");
            }
        };
        ExtraAddresses = deviceId =>
        {
            var sightings = Discovery.Peers.ExtraAddressesFor(deviceId);
            if (sightings.Count == 0)
            {
                return [];
            }

            // The packet carries no port; the peer's own record has it.
            var port = PairedMachines.Find(folders(), deviceId, out _).Peer?.Port ?? 0;
            return port is <= 0 or > 65535
                ? []
                : [.. sightings.Select(sighting => (sighting.Host, port))];
        };
    }

    /// <summary>The minted keys whose peers may be announced to now: paired, and the person's own.</summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Read on every announce tick over files a person can edit; an unreadable store or answer " +
                        "list announces to nobody, the safe side of a privacy switch, and the cause is logged by " +
                        "the stores' own callers.")]
    private static IReadOnlyList<(string DeviceId, byte[] Key)> EligibleMinted(
        DiscoveryKeys keys,
        KnownMachines owners,
        Func<IReadOnlyList<string>> folders)
    {
        try
        {
            var paired = folders();
            return [.. keys.Minted().Where(pair =>
                PairedMachines.NameOf(paired, pair.DeviceId) is not null && IsOwnSafely(owners, pair.DeviceId))];
        }
        catch (Exception)
        {
            return [];
        }
    }

    private static IReadOnlyList<(string DeviceId, byte[] Key)> TheirKeysSafely(DiscoveryKeys keys)
    {
        try
        {
            return keys.Theirs();
        }
        catch (InvalidOperationException)
        {
            return [];
        }
    }

    private static bool IsOwnSafely(KnownMachines owners, string deviceId)
    {
        try
        {
            return MachineOwnership.IsOwn(owners.OwnerOf(deviceId));
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }

    /// <summary>This machine's settings, as read at start.</summary>
    public MasterConfig Machine { get; }

    /// <summary>The one host every folder on this machine is served through.</summary>
    public PeerHost Host { get; }

    /// <summary>Server.ID's exchange, names and health records, shared by every folder and by Direct Push.</summary>
    public ServerExchange Servers { get; }

    /// <summary>Direct Push: listening while the person has it on, and never otherwise.</summary>
    public DirectPushService DirectPush { get; }

    /// <summary>The team switch: off until a team exists.</summary>
    public TeamFeatures Team { get; }

    /// <summary>Direct Messages' sending side: store-and-forward, run on the tray's timer.</summary>
    public MessageDelivery Messages { get; }

    /// <summary>The router port mapping (D-05): held only while the setting is on.</summary>
    public PortMappingService PortMapping { get; }

    /// <summary>Local discovery (D-32): always listening, announcing only with consent.</summary>
    public LocalDiscovery Discovery { get; }

    /// <summary>Which networks this person allowed announcing on.</summary>
    public NetworkConsent Consent { get; }

    /// <summary>What each folder's engine takes to try discovered addresses after the configured one.</summary>
    public Func<string, IReadOnlyList<(string Host, int Port)>> ExtraAddresses { get; }

    /// <summary>Where each folder's engine puts a discovery key a peer minted for this machine.</summary>
    public Action<string, string> DiscoveryKeySink { get; }

    /// <summary>
    /// Opens the machine's port, and Direct Push's when it is on. A port that cannot be opened is
    /// not thrown: every folder still saves locally, and every folder's status says it is not
    /// being served (<see cref="PeerHost.Fault"/>); Direct Push's state says why it is not listening.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This was disposed.</exception>
    public void Start()
    {
        Host.Start();
        StartDiscovery();
        _ = SettleServerIdAsync();
        _ = RefreshDirectPushAsync();
    }

    /// <summary>
    /// Starts discovery's listener and announcer. A port that cannot be bound - another
    /// program, or another account's SippBucket, holds UDP 28471 exclusively - is logged and
    /// costs only discovery: sync, push and messages run without it.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Binding a UDP port at start; whatever the socket layer throws, losing discovery must " +
                        "not stop the daemon, and the reason is logged.")]
    private void StartDiscovery()
    {
        try
        {
            Discovery.Start();
        }
        catch (Exception ex)
        {
            _log($"discovery could not start, and everything else runs without it: {ex.Message}");
        }
    }

    /// <summary>
    /// Gives this machine its Server.ID number if it has none yet, off the tray's thread: it reads
    /// the firmware's tables and writes <c>servers.json</c>.
    /// </summary>
    /// <returns>A task that completes when it is settled, or has logged why it could not be.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Runs once at start with nobody awaiting it; whatever goes wrong is logged rather than " +
                        "escaping unobserved, and the first exchange with one of the person's machines tries again.")]
    public async Task SettleServerIdAsync()
    {
        try
        {
            await Task.Run(Servers.Settle).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log($"Server.ID could not be settled: {ex.Message}");
        }
    }

    /// <summary>
    /// Brings Direct Push into line with the person's settings: the tray calls this on its timer,
    /// so <c>sip push on</c> takes effect within the interval.
    /// </summary>
    /// <returns>A task that completes when it is in line, or has logged why it cannot be.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Runs from the tray's timer with nobody awaiting it; whatever goes wrong is logged, and the " +
                        "next tick tries again, rather than escaping unobserved.")]
    public async Task RefreshDirectPushAsync()
    {
        try
        {
            await DirectPush.RefreshAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            // Quitting.
        }
        catch (Exception ex)
        {
            _log($"Direct Push could not be brought up to date: {ex.Message}");
        }

        await DeliverMessagesAsync().ConfigureAwait(false);
        await RefreshPortMappingAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Brings the router mapping into line with <c>network.portMapping</c>, on the same timer
    /// as everything else the daemon keeps level. The setting is read fresh, so a change made
    /// with <c>sip config set</c> takes effect within the interval.
    /// </summary>
    /// <returns>A task that completes when the state is settled, or has logged why not.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Runs from the tray's timer with nobody awaiting it; whatever goes wrong is logged, and " +
                        "the next tick tries again, rather than escaping unobserved.")]
    public async Task RefreshPortMappingAsync()
    {
        try
        {
            await PortMapping.RefreshAsync(MasterConfig.Load().PortMappingEnabled).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            // Quitting.
        }
        catch (Exception ex)
        {
            _log($"port mapping could not be brought up to date: {ex.Message}");
        }
    }

    /// <summary>
    /// Tries to deliver every queued direct message: store-and-forward, on the same timer as
    /// Direct Push's refresh, so a message waits at most one interval once its machine is
    /// reachable.
    /// </summary>
    /// <returns>A task that completes when the pass is done, or has logged why it stopped.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Runs from the tray's timer with nobody awaiting it; whatever goes wrong is logged, and the " +
                        "next tick tries again, rather than escaping unobserved.")]
    public async Task DeliverMessagesAsync()
    {
        try
        {
            _ = await Messages.DeliverPendingAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log($"queued messages could not be delivered this pass: {ex.Message}");
        }
    }

    /// <summary>
    /// Starts keeping one open folder in sync: served through <see cref="Host"/>, and saved and
    /// polled on the machine's timings.
    /// </summary>
    /// <param name="repository">The open folder. The caller keeps it, and disposes it after the service.</param>
    /// <returns>The running service. The caller owns it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="repository"/> was null.</exception>
    /// <exception cref="ObjectDisposedException">The host was disposed.</exception>
    public AutoSyncService StartFolder(SipRepository repository)
    {
        ArgumentNullException.ThrowIfNull(repository);

        var service = new AutoSyncService(repository, _identity, _log, Host.Tuning, Servers)
        {
            ExtraAddresses = ExtraAddresses,
            DiscoveryKeySink = DiscoveryKeySink,
            DownloadLimit = _downloadLimit,
        };
        try
        {
            service.Start(Host);
            return service;
        }
        catch
        {
            // A start that failed part way, at the folder watcher say, has already registered
            // the folder with the host, which would then go on routing peers to a folder
            // nothing runs. Disposing unregisters it and closes any connection already routed
            // there, which is prompt. Every wait inside uses ConfigureAwait(false), so blocking
            // on it here, on the tray's thread, cannot deadlock.
            service.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }
    }

    /// <summary>
    /// Stops listening, Direct Push first, waits for every connection to close, and deletes
    /// the router mapping.
    /// </summary>
    /// <returns>A task that completes when nothing is being served or received.</returns>
    public async ValueTask DisposeAsync()
    {
        await Discovery.DisposeAsync().ConfigureAwait(false);
        await DirectPush.DisposeAsync().ConfigureAwait(false);
        await Host.DisposeAsync().ConfigureAwait(false);
        await PortMapping.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>Stops listening and tells every connection to stop, without waiting.</summary>
    /// <remarks>
    /// For a way out other than quitting, when there is no time to wait. The router mapping is
    /// not deleted here — deleting talks to the router, which needs the waiting path — and it
    /// expires on its own lifetime.
    /// </remarks>
    public void Dispose()
    {
        DirectPush.Dispose();
        Host.Dispose();
    }
}
