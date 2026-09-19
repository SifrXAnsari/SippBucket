using System.Text.Json;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Messages;
using SippBucket.Core.Servers;

namespace SippBucket.Core.Push;

/// <summary>What Direct Push is doing on this machine.</summary>
/// <param name="Enabled">Whether the person has it on.</param>
/// <param name="Listening">Whether its port is open now.</param>
/// <param name="Port">The port it listens on, or 0 while it does not.</param>
/// <param name="InboxRoot">The inbox folder in effect.</param>
/// <param name="Fault">Why it is on and not listening, or null.</param>
public sealed record DirectPushState(bool Enabled, bool Listening, int Port, string InboxRoot, string? Fault);

/// <summary>
/// Direct Push in the daemon: listens while the person has it on, and never otherwise
/// (approval condition 5, docs/DIRECT-PUSH.md), with the receiving side behind the listener.
/// </summary>
/// <remarks>
/// <para>
/// <b>When it listens.</b> Only while Direct Push is on in the person's settings, or team features
/// are on, because direct messages will arrive the same way. It is off until the person turns it
/// on. Nothing listens while its port clashes with sync's (<see cref="ConfigProblemKind.PortClash"/>),
/// while the settings cannot be read, or while the inbox sits inside a folder SippBucket syncs or
/// holds one (<see cref="PushInbox.ConflictWithSyncedFolders"/>): each is reported, and none is
/// worked around.
/// </para>
/// <para>
/// <b>Who may push.</b> A machine paired with at least one folder on this machine (Direct Push is
/// per machine, rule 7), and then only one the person answered is their own, until team features
/// are on. A machine never answered about counts as someone else's. The key check itself, and
/// every other refusal, is the listener's.
/// </para>
/// <para>
/// <b>Changes.</b> <see cref="RefreshAsync"/> reads the settings and brings the listener into line:
/// it starts it, stops it, or starts it again over a moved inbox. The daemon calls it at start
/// and on its regular timer, so a change made with <c>sip push on</c> takes effect within that
/// interval without a restart.
/// </para>
/// </remarks>
public sealed class DirectPushService : IAsyncDisposable, IDisposable
{
    private readonly DeviceIdentity _identity;
    private readonly MasterConfig _machine;
    private readonly PushPreferencesStore _preferences;
    private readonly KnownMachines _machines;
    private readonly Func<string, string?> _pairedName;
    private readonly Func<IReadOnlyList<string>> _syncedFolders;
    private readonly Func<bool> _teamFeatures;
    private readonly Action<string>? _log;
    private readonly PushTuning _tuning;
    private readonly ServerExchange? _servers;
    private readonly PeopleStore _people;
    private readonly MessageStore _messages;
    private readonly Action<PersonScope, string>? _onMessage;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private Ssh.PushListener? _listener;
    private string? _listeningInbox;
    private string? _lastReported;
    private DirectPushState _state;
    private bool _disposed;

    /// <summary>Creates the service. Nothing listens until <see cref="RefreshAsync"/> finds Direct Push on.</summary>
    /// <param name="identity">This machine's identity: its device key is the SSH host key. Borrowed.</param>
    /// <param name="machine">This machine's settings, from <c>master.json</c>.</param>
    /// <param name="preferences">The person's Direct Push settings.</param>
    /// <param name="machines">The person's answers about whose each machine is.</param>
    /// <param name="pairedName">
    /// The name this machine knows a device by when any folder here is paired with it, or null when
    /// none is.
    /// </param>
    /// <param name="syncedFolders">Every folder SippBucket syncs on this machine.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="teamFeatures">Whether team features are on, or null while they do not exist yet.</param>
    /// <param name="tuning">The deadlines and limits, or null for the machine's.</param>
    /// <param name="servers">
    /// Where a file that goes to quarantine, a bad message signature or message volume is
    /// recorded against its sender's health, or null to record nothing.
    /// </param>
    /// <param name="people">
    /// The person's grouping of machines into people, for the per-person caps, the message
    /// rate and the conversations; null reads this user's own.
    /// </param>
    /// <param name="messages">The message store direct messages land in; null reads this user's own.</param>
    /// <param name="onMessage">
    /// Told of each direct message stored, with the sender's scope and name, unless muted:
    /// what the tray's notification hangs off. Or null.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public DirectPushService(
        DeviceIdentity identity,
        MasterConfig machine,
        PushPreferencesStore preferences,
        KnownMachines machines,
        Func<string, string?> pairedName,
        Func<IReadOnlyList<string>> syncedFolders,
        Action<string>? log = null,
        Func<bool>? teamFeatures = null,
        PushTuning? tuning = null,
        ServerExchange? servers = null,
        PeopleStore? people = null,
        MessageStore? messages = null,
        Action<PersonScope, string>? onMessage = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(machine);
        ArgumentNullException.ThrowIfNull(preferences);
        ArgumentNullException.ThrowIfNull(machines);
        ArgumentNullException.ThrowIfNull(pairedName);
        ArgumentNullException.ThrowIfNull(syncedFolders);

        _identity = identity;
        _machine = machine;
        _preferences = preferences;
        _machines = machines;
        _pairedName = pairedName;
        _syncedFolders = syncedFolders;
        _log = log;
        _teamFeatures = teamFeatures ?? (static () => false);
        _tuning = tuning ?? PushTuning.ForMachine(machine);
        _servers = servers;
        _people = people ?? PeopleStore.ForThisUser();
        _messages = messages ?? MessageStore.ForThisUser();
        _onMessage = onMessage;
        _state = new DirectPushState(false, false, 0, PushInbox.DefaultRoot(), null);
    }

    /// <summary>What Direct Push is doing now.</summary>
    public DirectPushState State => Volatile.Read(ref _state);

    /// <summary>
    /// Reads the settings and brings the listener into line with them: started while Direct Push
    /// is on, stopped while it is off, and started again over a moved inbox.
    /// </summary>
    /// <param name="cancellationToken">Cancels waiting for another refresh to finish.</param>
    /// <returns>A task that completes when the listener is in line, or has recorded why it cannot be.</returns>
    /// <exception cref="ObjectDisposedException">The service was disposed.</exception>
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            // Disposed while this waited: nothing may start now.
            ObjectDisposedException.ThrowIf(_disposed, this);

            PushPreferences preferences;
            try
            {
                preferences = _preferences.Load();
            }
            catch (JsonException ex)
            {
                await StopAsync().ConfigureAwait(false);
                Settle(new DirectPushState(false, false, 0, PushInbox.DefaultRoot(), ex.Message));
                return;
            }

            if (!preferences.Enabled && !_teamFeatures())
            {
                await StopAsync().ConfigureAwait(false);
                Settle(new DirectPushState(false, false, 0, preferences.InboxRoot, null));
                return;
            }

            if (WhyNotListen(preferences) is { } fault)
            {
                await StopAsync().ConfigureAwait(false);
                Settle(new DirectPushState(true, false, 0, preferences.InboxRoot, fault));
                return;
            }

            if (_listener is not null &&
                string.Equals(_listeningInbox, preferences.InboxRoot, StringComparison.OrdinalIgnoreCase))
            {
                Settle(new DirectPushState(true, _listener.Fault is null, _listener.Port, preferences.InboxRoot, _listener.Fault));
                return;
            }

            await StopAsync().ConfigureAwait(false);
            Settle(await StartAsync(preferences).ConfigureAwait(false));
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Stops listening and waits for every delivery in progress to end.</summary>
    /// <returns>A task that completes when nothing is being received.</returns>
    /// <remarks>The daemon stops refreshing before it disposes this.</remarks>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            _disposed = true;
            await StopAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }

        _gate.Dispose();
    }

    /// <summary>Stops listening and tells every delivery in progress to stop, without waiting.</summary>
    /// <remarks>Prefer <see cref="DisposeAsync"/>, which waits; this is for a way out with no time to wait.</remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _listener?.Dispose();
        _listener = null;
        _gate.Dispose();
    }

    private string? WhyNotListen(PushPreferences preferences)
    {
        if (_machine.Problems.FirstOrDefault(problem => problem.Kind == ConfigProblemKind.PortClash) is { } clash)
        {
            return $"Direct Push is not listening: {clash.Message}";
        }

        if (!PushInbox.IsUsableRoot(preferences.InboxRoot, out var unusable))
        {
            return $"Direct Push is not listening: {unusable}";
        }

        return PushInbox.ConflictWithSyncedFolders(preferences.InboxRoot, _syncedFolders()) is { } conflict
            ? $"Direct Push is not listening: {conflict}. Choose another inbox folder with 'sip inbox folder'."
            : null;
    }

    private async Task<DirectPushState> StartAsync(PushPreferences preferences)
    {
        var inbox = new PushInbox(preferences.InboxRoot);

        try
        {
            inbox.Prepare();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new DirectPushState(
                true, false, 0, preferences.InboxRoot, $"Direct Push is not listening: the inbox {inbox.Root} cannot be written: {ex.Message}");
        }

        var settings = _machine.Push;
        var receiver = new PushReceiver(
            inbox,
            settings,
            CurrentRules,
            _tuning,
            _log,
            onQuarantined: (caller, detail) =>
                _servers?.RecordFault(caller.DeviceId, HealthFault.QuarantinedPush, detail, null, caller.Name),
            scopeOf: _people.ScopeOf);
        var messages = new MessageReceiver(
            _messages,
            settings,
            _identity.DeviceId,
            _teamFeatures,
            _people.ScopeOf,
            _tuning,
            onFault: (deviceId, fault, detail) =>
                _servers?.RecordFault(deviceId, fault, detail, null, _pairedName(deviceId)),
            onMessage: _onMessage,
            log: _log);

        // The first message on a channel says what the delivery is: a file batch or direct
        // messages. Each goes to its own side, with the message it already read in hand.
        async Task Deliver(PushCaller caller, Stream channel, CancellationToken token)
        {
            var first = await PushWire.ReadAsync(channel, _tuning.StallTimeout, token).ConfigureAwait(false);
            if (first is null)
            {
                return;
            }

            if (first is MessageOffer)
            {
                await messages.ReceiveAsync(caller, channel, first, token).ConfigureAwait(false);
            }
            else
            {
                await receiver.ReceiveAsync(caller, channel, first, token).ConfigureAwait(false);
            }
        }

        var listener = new Ssh.PushListener(_identity, settings, LookUp, Deliver, _log, _tuning);

        listener.Start();
        if (listener.Fault is { } fault)
        {
            await listener.DisposeAsync().ConfigureAwait(false);
            return new DirectPushState(true, false, 0, preferences.InboxRoot, fault);
        }

        _listener = listener;
        _listeningInbox = preferences.InboxRoot;
        return new DirectPushState(true, true, listener.Port, preferences.InboxRoot, null);
    }

    private async Task StopAsync()
    {
        if (_listener is null)
        {
            return;
        }

        var listener = _listener;
        _listener = null;
        _listeningInbox = null;
        await listener.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>Records the state, and logs it once each time it changes.</summary>
    private void Settle(DirectPushState state)
    {
        Volatile.Write(ref _state, state);

        var line = state switch
        {
            { Fault: { } fault } => fault,
            { Listening: true } => $"Direct Push is on; the inbox is {state.InboxRoot}",
            { Enabled: false } => "Direct Push is off",
            _ => null,
        };

        if (line is not null && !string.Equals(line, _lastReported, StringComparison.Ordinal))
        {
            _lastReported = line;
            _log?.Invoke(line);
        }
    }

    /// <summary>The person's rules as they are now, read for each file placed.</summary>
    private IReadOnlyList<InboxRule> CurrentRules() => _preferences.Load().Rules;

    /// <summary>Who a key that has proved itself belongs to, and whether it may push here.</summary>
    private PushCaller? LookUp(string deviceId)
    {
        var name = _pairedName(deviceId);
        if (name is null)
        {
            return null;
        }

        MachineOwner owner;
        try
        {
            owner = _machines.OwnerOf(deviceId);
        }
        catch (JsonException ex)
        {
            // Unreadable answers protect the person: every machine counts as someone else's.
            _log?.Invoke($"Direct Push treats {name} as someone else's machine, because {ex.Message}");
            owner = MachineOwner.Unanswered;
        }

        if (!MachineOwnership.IsOwn(owner) && !_teamFeatures())
        {
            _log?.Invoke(owner == MachineOwner.Unanswered
                ? $"Direct Push refused {name}: you have not said whether it is one of your own machines, and other " +
                  $"people's machines can push only once team features are on. If it is yours, say so with " +
                  $"'sip peer owner {name} mine'."
                : $"Direct Push refused {name}: it is someone else's machine, and other people's machines can push " +
                  "only once team features are on.");
            return null;
        }

        return new PushCaller { DeviceId = deviceId, Name = name, Owner = owner };
    }
}
