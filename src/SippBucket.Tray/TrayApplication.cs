using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Drawing;
using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Discovery;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Model;
using SippBucket.Core.Pairing;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;
using SippBucket.Core.Sync;

namespace SippBucket.Tray;

/// <summary>
/// The daemon's home: the tray icon, its menu, and the window it opens. It owns every
/// running folder; the window is a view of what it owns.
/// </summary>
/// <remarks>
/// Headless by default, at the owner's word (taskslist, phase 9): opening SippBucket puts
/// the daemon in the tray with a notification saying so, and nothing else — no window, no
/// console. The window opens from the icon — a click, or the menu — and it is only ever a
/// view: closing it hides it, and the daemon carries on here. The command line opens from
/// the menu too, in a window of its own. The one thing launching the exe never does is
/// nothing: the notification is what makes headless legible.
/// </remarks>
internal sealed class TrayApplication : ApplicationContext, IMainWindowHost
{
    /// <summary>How long "Sync now" waits before telling the user it is stuck.</summary>
    /// <remarks>
    /// A cycle already in progress holds the service's gate, and this menu item waits for
    /// it. With no deadline that wait was unbounded: the one action a worried user reaches
    /// for was also the one that could hang, which made the program look worse exactly when
    /// it was being asked to explain itself. Generous enough for a real cycle to finish,
    /// short enough to answer.
    /// </remarks>
    private static readonly TimeSpan SyncNowTimeout = TimeSpan.FromMinutes(2);

    /// <summary>The shell's limit on a balloon's text, in characters.</summary>
    private const int BalloonTextLimit = 255;

    private readonly NotifyIcon _icon;
    private readonly System.Windows.Forms.Timer _refresh;
    private readonly SingleInstance _instance;

    // The UI thread's own context, captured once. A request from a second launch arrives on
    // a thread-pool thread and is posted here - not through the window, which may have to be
    // rebuilt and so is not something to marshal through.
    private readonly SynchronizationContext _ui;

    // Replaced if it is ever found disposed. See ShowWindow.
    private MainWindow _window;
    private bool _quitting;

    // Made once. The menu is rebuilt on every opening, and a font created per opening would
    // leak a GDI handle every time the icon was right-clicked.
    private readonly Font _menuBold;
    private Icon _currentIcon;
    private MarkState _drawnState;
    private readonly DeviceIdentity _identity;
    private readonly List<RunningFolder> _running = [];

    // This machine's settings, read once at start, and the one server every folder is
    // served through (D-40). A folder registers with the host when it starts and unregisters
    // when it stops; the host outlives them all and stops last. See TrayDaemon for why this
    // is its own class.
    private readonly TrayDaemon _daemon;

    // Written from the services' threads through Log, read by the window on the UI thread.
    // A List is not safe for that, and the window reads it every two seconds.
    private readonly object _logLock = new();
    private readonly List<string> _log = [];

    private bool _announcedStillRunning;

    /// <summary>Starts every watched folder, headless: the tray icon and nothing else.</summary>
    /// <param name="instance">The single-instance guard this process owns.</param>
    /// <param name="openedByPerson">
    /// True when SippBucket was opened by a person, who is told where it went — a program
    /// that seems to do nothing on its first open reads as broken. False when Windows
    /// started it at sign-in, which says nothing. The window itself opens only from the
    /// tray icon, whoever started the process (the owner's rule, taskslist phase 9).
    /// </param>
    public TrayApplication(SingleInstance instance, bool openedByPerson)
    {
        ArgumentNullException.ThrowIfNull(instance);

        _instance = instance;
        _identity = DeviceIdentity.LoadOrCreate(WatchedFolders.DeviceKeyFile);

        // Before any folder starts, so the port is open, or known not to be, by the time the
        // first folder's status is read. A port that cannot be opened is not thrown: every
        // folder still saves locally, and every folder's status says it is not being served.
        // A message notification names the sender and never carries the text, because Windows
        // keeps notification contents in its own database, outside SippBucket's protection
        // (docs/DIRECT-MESSAGES.md).
        _daemon = new TrayDaemon(
            _identity,
            MasterConfig.Load(),
            Log,
            onMessage: (_, who) => NotifyNewMessage(who));
        _daemon.Start();

        // The mark, not SystemIcons.Application. This is the only part of the product most
        // people will ever look at, and it is the surface the whole state-carrying argument
        // was designed for — an icon that could not change was the last place the tray
        // could still be silently wrong.
        _currentIcon = MarkIcon.Render(new MarkState(0, Color.FromArgb(0x1B, 0x1A, 0x17), Color.FromArgb(0xB4, 0x76, 0x2A), false));

        _icon = new NotifyIcon
        {
            Icon = _currentIcon,
            Visible = true,
            Text = "SippBucket",
            ContextMenuStrip = new ContextMenuStrip(),
        };

        _icon.ContextMenuStrip.Opening += OnMenuOpening;
        _menuBold = new Font(_icon.ContextMenuStrip.Font, FontStyle.Bold);

        // Without this the tooltip only refreshes when the user does something, so a folder
        // that stopped syncing an hour ago still reads as fine until it is clicked on. The
        // whole point of the tray is to be believable at a glance.
        _refresh = new System.Windows.Forms.Timer { Interval = 30_000 };
        _refresh.Tick += (_, _) =>
        {
            UpdateTooltip();

            // The same interval picks up a change to Direct Push made with 'sip push on' or
            // off, to network.portMapping, and to which network the machine is on.
            _ = _daemon.RefreshDirectPushAsync();
            AskDiscoveryConsentIfNew();
        };
        _refresh.Start();

        MakeWindow();

        // Creating the first control on this thread installed the Windows Forms context, so
        // this is it. The fallback is only for a host that has switched automatic
        // installation off, which this program does not.
        _ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

        // A left click opens the window. It used to do nothing at all, and a click that
        // does nothing on the only visible part of a program is indistinguishable from a
        // program that is not there.
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                ShowWindow();
            }
        };
        _icon.DoubleClick += (_, _) => ShowWindow();

        _instance.WhenShowRequested(OnAnotherLaunch);

        StartAll();

        AnnounceAutostart(Autostart.AdoptOnFirstStart());

        if (openedByPerson)
        {
            AnnounceInTray();
        }
    }

    /// <summary>
    /// Says where SippBucket went when a person opened it: into the tray, headless. On a
    /// machine with no folders yet, the same notification is the start of the guided first
    /// run — it points at the icon, whose window opens on the setup screen.
    /// </summary>
    private void AnnounceInTray() =>
        _icon.ShowBalloonTip(
            8000,
            "SippBucket is running in the tray",
            Truncate(_running.Count == 0
                ? "Nothing is set up yet. Click this icon to choose your first folder or pair " +
                  "with another machine; right-click it for the menu and the command line."
                : "Your folders are being kept in sync in the background. Click this icon for " +
                  "the window; right-click it for the menu and the command line."),
            ToolTipIcon.Info);

    /// <inheritdoc />
    string IMainWindowHost.DeviceId => _identity.DeviceId;

    /// <inheritdoc />
    string IMainWindowHost.AutostartDescription => Autostart.Describe();

    /// <inheritdoc />
    /// <remarks>The same file the identity was loaded from, and upgraded in, at start.</remarks>
    string IMainWindowHost.DeviceKeyFile => WatchedFolders.DeviceKeyFile;

    /// <inheritdoc />
    TimeSpan IMainWindowHost.PollInterval => _daemon.Host.Tuning.PollInterval;

    /// <inheritdoc />
    IReadOnlyList<WatchedFolderView> IMainWindowHost.Folders() =>
        _running
            .Select(entry => new WatchedFolderView(
                entry.Folder,
                entry.Repository.Config.Name,
                entry.Service.IsRunning ? entry.Service.GetStatus() : null))
            .ToList();

    /// <inheritdoc />
    IReadOnlyList<string> IMainWindowHost.RecentActivity(int count)
    {
        lock (_logLock)
        {
            return _log.TakeLast(count).Reverse().ToList();
        }
    }

    /// <inheritdoc />
    void IMainWindowHost.AddFolder(IWin32Window owner) => AddFolder(owner);

    /// <inheritdoc />
    async Task IMainWindowHost.SyncAllNowAsync()
    {
        var lines = new List<string>();
        var icon = ToolTipIcon.Info;

        foreach (var entry in _running.ToList())
        {
            var (text, severity) = await CycleAsync(entry).ConfigureAwait(true);
            lines.Add($"{entry.Repository.Config.Name}: {FirstLine(text)}");
            icon = Worse(icon, severity);
        }

        if (lines.Count > 0)
        {
            _icon.ShowBalloonTip(4000, "Sync now", Truncate(string.Join(Environment.NewLine, lines)), icon);
        }

        UpdateTooltip();
    }

    /// <inheritdoc />
    Task IMainWindowHost.SyncNowAsync(string folder) =>
        Find(folder) is { } entry ? SyncNowAsync(entry) : Task.CompletedTask;

    /// <inheritdoc />
    void IMainWindowHost.OpenFolder(string folder) => OpenFolder(folder);

    /// <inheritdoc />
    Task IMainWindowHost.StopWatchingAsync(string folder) =>
        Find(folder) is { } entry ? StopWatchingAsync(entry) : Task.CompletedTask;

    /// <inheritdoc />
    void IMainWindowHost.OpenCommandLine(IWin32Window owner) => OpenCommandLine(owner);

    /// <inheritdoc />
    void IMainWindowHost.CopyDeviceId() => CopyDeviceId();

    /// <inheritdoc />
    void IMainWindowHost.Quit() => _ = QuitAsync();

    /// <inheritdoc />
    NetworkConsent IMainWindowHost.Consent => _daemon.Consent;

    /// <inheritdoc />
    int IMainWindowHost.ListenPort => _daemon.Machine.ListenPort;

    /// <inheritdoc />
    IReadOnlyList<(string Path, string Name)> IMainWindowHost.PairableFolders() =>
        _running.Select(entry => (entry.Folder, entry.Repository.Config.Name)).ToList();

    /// <inheritdoc />
    async Task<(BucketUsage? Usage, string? Problem)> IMainWindowHost.MeasureFolderBucketAsync(string folder)
    {
        if (Find(folder) is not { } entry)
        {
            return (null, "This folder is not running here.");
        }

        try
        {
            return (await entry.Repository.MeasureBucketAsync().ConfigureAwait(true), null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (null, ex.Message);
        }
    }

    /// <inheritdoc />
    async Task<(string Summary, bool Failed)> IMainWindowHost.CollectFolderAsync(string folder)
    {
        if (Find(folder) is not { } entry)
        {
            return ("This folder is not running here.", true);
        }

        try
        {
            var result = await entry.Repository.CollectAsync().ConfigureAwait(true);
            return (result.Summary, false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // FolderBusyException lands here too: another operation holds the folder, and
            // its message names it.
            return (ex.Message, true);
        }
    }

    /// <inheritdoc />
    async Task<IReadOnlyList<HistoryLine>> IMainWindowHost.FolderHistoryAsync(string folder, int limit)
    {
        if (Find(folder) is not { } entry)
        {
            return [];
        }

        IReadOnlyList<SaveResult> history;
        try
        {
            history = await entry.Repository.GetHistoryAsync(limit).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SnapshotNotFoundException or CorruptBlockException)
        {
            Log($"{entry.Repository.Config.Name}: history could not be read: {ex.Message}");
            return [];
        }

        var labels = PeerLabels(entry.Repository);
        return [.. history.Select(saved => new HistoryLine(
            saved.SnapshotId.ToShortString(),
            saved.Snapshot.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
            Label(labels, saved.Snapshot.DeviceId),
            string.IsNullOrWhiteSpace(saved.Snapshot.Message) ? "(no message)" : saved.Snapshot.Message,
            saved.Snapshot.Files.Count,
            BucketUsage.Bytes(saved.Snapshot.TotalSize)))];
    }

    /// <inheritdoc />
    FolderFacts? IMainWindowHost.FolderFacts(string folder)
    {
        if (Find(folder) is not { } entry)
        {
            return null;
        }

        var status = entry.Service.IsRunning ? entry.Service.GetStatus() : null;

        int peers;
        try
        {
            peers = entry.Repository.Peers.Load().Count;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            peers = 0;
        }

        return new FolderFacts(
            entry.Repository.Config.Name,
            entry.Repository.Config.Mode.ToString(),
            status?.HasPassphrase ?? false,
            status?.IsUnlockedForSession ?? false,
            entry.Repository.Config.RepositoryId,
            status?.RecentConflicts ?? [],
            peers);
    }

    /// <inheritdoc />
    async Task<string> IMainWindowHost.AnswerAlertAsync(int id, AlertChoice choice)
    {
        AlertAnswering answering;
        try
        {
            answering = AlertLog.ForThisUser().Answer(id, choice, DateTimeOffset.UtcNow);
        }
        catch (IOException ex)
        {
            return $"The answer could not be recorded: {ex.Message}";
        }

        if (answering.Alert is not { } alert)
        {
            return string.Create(CultureInfo.InvariantCulture, $"There is no alert {id}.");
        }

        if (answering.Outcome == AlertAnswerOutcome.DoesNotAsk)
        {
            return string.Create(CultureInfo.InvariantCulture, $"Alert {id} does not ask anything.");
        }

        if (answering is { Outcome: AlertAnswerOutcome.AlreadyAnswered, Answer: { } earlier } &&
            earlier.Choice != choice)
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"Alert {id} was already answered: {AlertLog.Describe(earlier.Choice)}. An answer is never changed.");
        }

        var lines = new List<string>
        {
            string.Create(CultureInfo.InvariantCulture, $"Recorded for alert {id}: {AlertLog.Describe(choice)}."),
        };

        if (alert.Kind == AlertKind.MassChange)
        {
            lines.Add(choice == AlertChoice.NotMe ? KeepOut(alert) : ApplyApproved(alert));
        }

        Log($"alert {id}: {AlertLog.Describe(choice)}");
        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>"Not me": the install is marked suspect and the held change stays out, as the command does.</summary>
    private static string KeepOut(Alert alert)
    {
        try
        {
            var health = PeerHealth.ForThisUser();
            if (!health.IsSuspect(alert.Device))
            {
                health.MarkSuspect(
                    alert.Device,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"you said a change it sent was not you (alert {alert.Id})"),
                    alert.Id,
                    DateTimeOffset.UtcNow);
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return $"{alert.Server} could not be marked suspect: {ex.Message}. " +
                   $"Run 'sip alerts answer {alert.Id} not-me' from a command line.";
        }

        return $"No change from {alert.Server} is taken, in any folder, until you clear it: " +
               $"the held change stays as evidence, never applied.";
    }

    /// <summary>"That was me": the folder's held record is answered and a cycle applies it now.</summary>
    private string ApplyApproved(Alert alert)
    {
        if (alert.FolderPath is not { } path || Find(path) is not { } entry)
        {
            return "The folder it was held in is not running here; run " +
                   $"'sip alerts answer {alert.Id.ToString(CultureInfo.InvariantCulture)} me' in that folder to apply it.";
        }

        try
        {
            entry.Repository.Held.Answer(alert.Id, HeldAnswer.ThatWasMe, DateTimeOffset.UtcNow);
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return $"The folder's held record could not be answered: {ex.Message}";
        }

        _ = SyncNowAsync(entry);
        return $"Applying the held change to '{entry.Repository.Config.Name}' with a sync cycle now.";
    }

    /// <inheritdoc />
    (PairOfferSession? Session, string? Problem) IMainWindowHost.BeginPairOffer(string folder)
    {
        if (Find(folder) is not { } entry)
        {
            return (null, "That folder is not running here.");
        }

        var port = _daemon.Machine.ListenPort;

        // Ownership either transfers into the session, whose DisposeAsync the dialog calls,
        // or is disposed in the one failure arm; CA2000 cannot see through the handoff.
#pragma warning disable CA2000
        var server = new PairingServer(entry.Repository, _identity, null, Log, port);
#pragma warning restore CA2000
        try
        {
            server.Start();
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            _ = server.DisposeAsync().AsTask();
            return (null, ex.Message);
        }

        return (new PairOfferSession(server, LocalAddresses.UsableIPv4(), port), null);
    }

    /// <inheritdoc />
    async Task<PairEnterResult> IMainWindowHost.PairEnterAsync(
        string host, int port, string code, string directory, MachineOwner owner)
    {
        // A list, not a loop-carried nullable set from a lambda: that shape is one
        // CA1508's flow analysis misjudges as never assigned.
        var recorded = new List<PeerRecord>(1);
        var options = new PairingJoinOptions
        {
            Directory = directory,
            ListenPort = _daemon.Machine.ListenPort,
            Recorded = (record, _) => recorded.Add(record),
        };

        SipRepository joined;
        try
        {
            joined = await PairingClient.JoinWithCodeAsync(host, port, code, _identity, options)
                .ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is ArgumentException or RepositoryAlreadyExistsException
                                       or Core.Protocol.SipProtocolException or SocketException
                                       or Core.Protocol.PeerStalledException
                                       or IOException or UnauthorizedAccessException)
        {
            return new PairEnterResult(false, ex.Message, null, null);
        }

        var origin = recorded.FirstOrDefault();

        // The new replica starts syncing here at once, on the repository the join opened.
        // Ownership of both moves into _running, disposed by StopWatchingAsync and QuitAsync,
        // which CA2000 cannot see.
        AutoSyncService service;
        try
        {
#pragma warning disable CA2000
            service = _daemon.StartFolder(joined);
#pragma warning restore CA2000
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            joined.Dispose();
            return new PairEnterResult(
                false,
                $"Joined, but the folder could not be started here: {ex.Message} " +
                "Open it again from Add folder.",
                origin?.DeviceId,
                origin?.Name);
        }

        _running.Add(new RunningFolder(directory, joined, service));
        WatchedFolders.Add(directory);
        Log($"joined '{joined.Config.Name}' by pairing");
        UpdateTooltip();

        var message = $"Joined '{joined.Config.Name}' in {joined.Config.Mode} mode. The other machine " +
                      "recorded this one before it accepted, so there is nothing to add by hand. " +
                      "It syncs from here on its own.";
        var result = new PairEnterResult(true, message, origin?.DeviceId, origin?.Name);

        if (origin is { } from)
        {
            _ = ((IMainWindowHost)this).RecordPairedOwner(from.DeviceId, from.Name, owner);
        }

        return result;
    }

    /// <inheritdoc />
    string IMainWindowHost.RecordPairedOwner(string deviceId, string name, MachineOwner owner)
    {
        if (owner == MachineOwner.Unanswered)
        {
            return "Left unanswered: the machine is treated as another person's until you say otherwise ('sip peer owner').";
        }

        try
        {
            _ = KnownMachines.ForThisUser().Answer(deviceId, owner, name, DateTimeOffset.UtcNow);
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return $"The answer could not be recorded: {ex.Message}. Record it with 'sip peer owner'.";
        }

        return owner == MachineOwner.Mine
            ? $"Recorded: '{name}' is one of your own machines. Server.ID, health records and " +
              "discovery treat it as yours."
            : $"Recorded: '{name}' is someone else's machine. It counts toward the team, and " +
              "the protections for other people's machines apply to it.";
    }

    /// <inheritdoc />
    void IMainWindowHost.AnnounceStillRunning()
    {
        if (_announcedStillRunning)
        {
            return;
        }

        // Once per session. Closing a window normally ends a program, so the first time it
        // does not, say so - and then stop saying so, because a reminder on every close is
        // the program nagging about its own design.
        _announcedStillRunning = true;
        _icon.ShowBalloonTip(
            5000,
            "SippBucket is still running",
            "Your folders are still being kept in sync. Click the icon to open the window " +
            "again; right-click it to quit.",
            ToolTipIcon.Info);
    }

    /// <summary>
    /// One notification per new network, once per session (docs/DISCOVERY.md): whether to
    /// announce presence here is the person's call, and "decide later" records nothing and
    /// sends nothing. The window's consent screen is phase 9's; until then the notification
    /// names the command.
    /// </summary>
    private void AskDiscoveryConsentIfNew()
    {
        var networkId = Core.Discovery.NetworkIdentity.Current();
        if (networkId is null ||
            _consentAskedThisSession.Contains(networkId) ||
            _daemon.Consent.HasBeenAsked(networkId))
        {
            return;
        }

        _ = _consentAskedThisSession.Add(networkId);
        var name = Core.Discovery.NetworkIdentity.CurrentDisplayName() ?? "This network";
        _icon.ShowBalloonTip(
            8000,
            "SippBucket",
            Truncate(
                $"New network: {name}. SippBucket can announce your machine here so your own " +
                "machines find it; until you allow it, nothing is sent. 'sip net allow' allows " +
                "this network, 'sip net deny' says never here."),
            ToolTipIcon.Info);
    }

    private readonly HashSet<string> _consentAskedThisSession = new(StringComparer.Ordinal);

    /// <summary>
    /// "New message from &lt;name&gt;", with no text: Windows keeps notification contents in
    /// its own database, outside SippBucket's protection (docs/DIRECT-MESSAGES.md). Raised
    /// from the listener's thread, so it hops to the tray's own.
    /// </summary>
    private void NotifyNewMessage(string who)
    {
        if (_icon.ContextMenuStrip is { IsHandleCreated: true } menu)
        {
            menu.BeginInvoke(() => _icon.ShowBalloonTip(
                5000, "SippBucket", Truncate($"New message from {who}"), ToolTipIcon.Info));
        }
        else
        {
            _icon.ShowBalloonTip(5000, "SippBucket", Truncate($"New message from {who}"), ToolTipIcon.Info);
        }
    }

    private void StartAll()
    {
        foreach (var folder in WatchedFolders.Load())
        {
            TryStart(folder);
        }

        UpdateTooltip();
    }

    private void TryStart(string folder)
    {
        try
        {
            // Ownership moves to _running: both are disposed in StopWatchingAsync when the
            // user stops watching a folder, and in QuitAsync on exit. CA2000 cannot see
            // through the handoff to the list.
#pragma warning disable CA2000
            var repository = SipRepository.IsLockedAt(folder)
                ? UnlockInteractively(folder)
                : SipRepository.Open(folder);
#pragma warning restore CA2000

            if (repository is null)
            {
                // The user dismissed the prompt. Not an error, and not something to nag
                // about — the folder simply is not watched this session.
                Log($"{Path.GetFileName(folder)}: locked, not unlocked this session");
                return;
            }

            AutoSyncService service;
            try
            {
                // Ownership moves into _running below, with the repository's; CA2000
                // cannot see through the handoff.
#pragma warning disable CA2000
                service = _daemon.StartFolder(repository);
#pragma warning restore CA2000
            }
            catch
            {
                // Not yet handed to _running, so nothing else would close it.
                repository.Dispose();
                throw;
            }

            _running.Add(new RunningFolder(folder, repository, service));
            Log($"watching {repository.Config.Name}");
        }
        catch (RepositoryNotFoundException ex)
        {
            Log($"skipped {folder}: {ex.Message}");
        }
        catch (RepositoryUnreadableException ex)
        {
            // A damaged or too-new config. Its message says which, and it is not "no
            // repository". Before D-66 a hand-edited config.json left this method as a raw
            // JsonException, which none of these arms catches, on the way out of the
            // constructor that starts every folder.
            Log($"skipped {folder}: {ex.Message}");
        }
        catch (IOException ex)
        {
            Log($"skipped {folder}: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            // The folder-protection sentence (P-04), where a Documents-shaped folder under
            // Norton or Controlled folder access reads as a permissions problem.
            Log($"skipped {folder}: {AntivirusShield.ExplainDenied(ex.Message, folder)}");
        }
    }

    /// <summary>
    /// Prompts for a passphrase until it works or the user gives up.
    /// </summary>
    /// <returns>The opened repository, or null if the user declined.</returns>
    /// <remarks>
    /// No attempt limit, and that is the right call here rather than an oversight. This is a
    /// local dialog in front of a key that is already sitting on the disk in wrapped form —
    /// anyone who can brute-force it will do so against the file at their leisure, not by
    /// typing into this box. Locking the user out after three tries would protect nothing
    /// and would strand someone who simply mistypes.
    /// </remarks>
    private SipRepository? UnlockInteractively(string folder)
    {
        var name = Path.GetFileName(folder.TrimEnd(Path.DirectorySeparatorChar));

        using var dialog = new UnlockDialog(name);

        while (dialog.ShowDialog() == DialogResult.OK)
        {
            if (string.IsNullOrEmpty(dialog.Passphrase))
            {
                dialog.ShowError("Enter the passphrase for this folder.");
                continue;
            }

            try
            {
                return SipRepository.Unlock(folder, dialog.Passphrase);
            }
            catch (WrongPassphraseException)
            {
                dialog.ShowError("That passphrase does not open this folder.");
            }
            catch (InvalidKeyWrapException ex)
            {
                // Not a wrong passphrase: the file is damaged or was written by something
                // else, and no amount of retyping will help. Say so and stop asking.
                Log($"{name}: {ex.Message}");
                MessageBox.Show(
                    $"This folder's lock cannot be read.\n\n{ex.Message}\n\n" +
                    "The passphrase is not the problem. The other machine still has a " +
                    "working copy if one is paired.",
                    "SippBucket",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return null;
            }
        }

        return null;
    }

    private void OnMenuOpening(object? sender, CancelEventArgs e)
    {
        var menu = _icon.ContextMenuStrip!;
        menu.Items.Clear();

        // First and bold: the default action, the same one a left click performs. A menu
        // whose top item is the thing the icon itself does is how a tray icon teaches it.
        var open = new ToolStripMenuItem("Open SippBucket") { Font = _menuBold };
        open.Click += (_, _) => ShowWindow();
        menu.Items.Add(open);
        menu.Items.Add(new ToolStripSeparator());

        if (_running.Count == 0)
        {
            menu.Items.Add(new ToolStripMenuItem("No folders yet") { Enabled = false });
        }
        else
        {
            foreach (var entry in _running)
            {
                var item = new ToolStripMenuItem(LabelFor(entry));
                item.DropDownItems.Add("Open folder", null, (_, _) => OpenFolder(entry.Folder));
                item.DropDownItems.Add("Sync now", null, async (_, _) => await SyncNowAsync(entry).ConfigureAwait(true));
                item.DropDownItems.Add("Stop watching", null, async (_, _) => await StopWatchingAsync(entry).ConfigureAwait(true));
                menu.Items.Add(item);
            }
        }

        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Add folder...", null, (_, _) => AddFolder(owner: null));
        menu.Items.Add("Copy device ID", null, (_, _) => CopyDeviceId());

        var autostart = new ToolStripMenuItem("Start with Windows")
        {
            Checked = Autostart.IsEnabled(),
            CheckOnClick = true,
        };

        autostart.Click += (_, _) => ToggleAutostart(autostart);
        menu.Items.Add(autostart);

        // The whole command surface, one right-click away. The tray deliberately exposes a
        // small number of actions - it is glanced at, not worked in - and everything else a
        // power user might want is a command. Hiding that behind "install it and find a
        // prompt" would be hiding the half of the product they were promised.
        menu.Items.Add("Command line...", null, (_, _) => OpenCommandLine(owner: null));

        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Quit", null, async (_, _) => await QuitAsync().ConfigureAwait(true));
    }

    /// <summary>
    /// The one line a user reads to decide whether their work is safe.
    /// </summary>
    /// <remarks>
    /// The tray composes nothing any more. It used to read two loose properties and build a
    /// sentence, which is how "synced" came to mean "the last cycle did not throw" — the
    /// display was doing the reasoning, and it reasoned wrongly because it had almost
    /// nothing to reason from. <see cref="FolderStatus"/> owns the wording now, so every
    /// surface says the same thing and none of them can invent a tenth state.
    /// </remarks>
    private static string LabelFor(RunningFolder entry)
    {
        if (!entry.Service.IsRunning)
        {
            return $"{entry.Repository.Config.Name} - stopped";
        }

        var status = entry.Service.GetStatus();
        return $"{status.FolderName} - {status.Headline}";
    }

    private void AddFolder(IWin32Window? owner)
    {
        using var picker = new FolderBrowserDialog
        {
            Description = "Pick a folder for SippBucket to keep in sync.",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };

        if (picker.ShowDialog(owner) != DialogResult.OK)
        {
            return;
        }

        var folder = picker.SelectedPath;

        // A folder that is not a repository yet is initialised here rather than sending the
        // user to a command line. This is the only setup step the tray asks for.
        if (RepositoryLayout.Discover(folder) is null)
        {
            var answer = MessageBox.Show(
                owner,
                $"{folder} is not a SippBucket folder yet.\n\nSet it up now?",
                "SippBucket",
                MessageBoxButtons.OKCancel,
                MessageBoxIcon.Question);

            if (answer != DialogResult.OK)
            {
                return;
            }

            try
            {
                using var created = SipRepository.Init(folder, RepositoryMode.Power, listenPort: _daemon.Machine.ListenPort);
            }
            catch (RepositoryAlreadyExistsException)
            {
                // Another process won the race. Carry on and open it below.
            }
            catch (IOException ex)
            {
                MessageBox.Show(
                    owner,
                    $"Could not set up that folder.\n\n{ex.Message}",
                    "SippBucket",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }
        }

        // Already watched: say nothing and change nothing. Starting a second service over
        // the same folder in this process would be D-34 from the inside.
        if (Find(folder) is not null)
        {
            return;
        }

        WatchedFolders.Add(folder);
        TryStart(folder);
        UpdateTooltip();
    }

    private static void OpenFolder(string folder)
    {
        using var process = Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
    }

    /// <summary>Turns starting with Windows on or off, and reports it if it fails.</summary>
    /// <remarks>
    /// The checkbox is re-read from the registry afterwards rather than left where the
    /// click put it. A tick that reflects the click rather than the outcome is a status
    /// that can disagree with the thing it describes, which is the failure this whole
    /// project has been about. <see cref="Autostart.Set(bool)"/> also records the choice,
    /// so an installed copy never switches it back on by itself at the next start.
    /// </remarks>
    private void ToggleAutostart(ToolStripMenuItem item)
    {
        var failure = Autostart.Set(item.Checked);

        if (failure is not null)
        {
            Log($"start with Windows: {failure}");
            MessageBox.Show(
                $"That setting could not be changed.\n\n{failure}",
                "SippBucket",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }

        item.Checked = Autostart.IsEnabled();
    }

    /// <summary>Says so when this start changed, or failed to change, the startup list.</summary>
    private void AnnounceAutostart(FirstStartOutcome outcome)
    {
        var notice = NoticeFor(outcome);

        if (notice.LogLine is { } line)
        {
            Log(line);
        }

        if (notice.BalloonTitle is { } title && notice.BalloonText is { } text)
        {
            _icon.ShowBalloonTip(8000, title, Truncate(text), ToolTipIcon.Info);
        }
    }

    /// <summary>What to log, and what to tell the person, about a first start's outcome.</summary>
    /// <param name="outcome">What <see cref="Autostart.AdoptOnFirstStart()"/> did.</param>
    /// <returns>The log line, if any, and the balloon, if any.</returns>
    /// <remarks>
    /// <para>
    /// A program that adds itself to somebody's startup list and does not mention it is
    /// doing something behind their back, however reasonable the default. So the one time
    /// it happens, it says what it did and how to undo it, and the untick is remembered.
    /// </para>
    /// <para>
    /// Keeping it off over a script install (D-67) is said too. Everyone with no startup
    /// entry when the MSI replaced the script install is kept off, and that is two kinds of
    /// people who cannot be told apart: those who switched it off under the script, and those
    /// who never used the script install at all. The second kind were never asked, and
    /// without a word would find after a restart that nothing had synced. It is said at most
    /// once: the notification comes only with a decision that was recorded, and a recorded
    /// decision makes every later start leave it alone.
    /// </para>
    /// <para>
    /// A pure function, so that the tests can hold each outcome to what it tells the person.
    /// </para>
    /// </remarks>
    internal static FirstStartNotice NoticeFor(FirstStartOutcome outcome)
    {
        if (outcome.Failure is { } failure)
        {
            return new FirstStartNotice(
                outcome.Action switch
                {
                    FirstStartAction.Enable => $"start with Windows: could not be turned on for this user: {failure}",
                    FirstStartAction.RecordOffFromScriptInstall =>
                        $"start with Windows: left off for this user, but that could not be recorded, so the next start decides again: {failure}",
                    _ => $"start with Windows: could not record the existing setting: {failure}",
                },
                null,
                null);
        }

        return outcome.Action switch
        {
            FirstStartAction.Enable => new FirstStartNotice(
                "start with Windows: turned on for this user, on first start of the installed copy",
                "SippBucket will start with Windows",
                "It starts quietly in the tray when you sign in. To stop that, right-click " +
                "this icon and untick Start with Windows; the choice is remembered."),

            FirstStartAction.RecordExisting => new FirstStartNotice(
                "start with Windows: already on for this user; recorded as their choice",
                null,
                null),

            FirstStartAction.RecordOffFromScriptInstall => new FirstStartNotice(
                "start with Windows: left off for this user, who had no startup entry when the MSI " +
                "replaced the older script install; recorded as their choice",
                "SippBucket does not start with Windows",
                "It replaced an older install on this PC, where you had no startup entry, so it " +
                "stays off: after a restart, nothing syncs until you open it. To change that, " +
                "right-click this icon and tick Start with Windows."),

            _ => new FirstStartNotice(null, null, null),
        };
    }

    /// <summary>Opens the command line in a window of its own.</summary>
    /// <remarks>
    /// A separate process, not a console allocated here. Closing a console window kills
    /// every process attached to it, so borrowing one in-process would mean that shutting
    /// the command window silently stopped the daemon and every folder it watches — the
    /// exact class of silent failure this project keeps finding.
    /// </remarks>
    private void OpenCommandLine(IWin32Window? owner)
    {
        var failure = ConsoleHost.StartSeparateSession();

        if (failure is null)
        {
            return;
        }

        Log($"command line: {failure}");
        MessageBox.Show(
            owner,
            $"The command line could not be opened.\n\n{failure}",
            "SippBucket",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
    }

    private void CopyDeviceId()
    {
        Clipboard.SetText(_identity.DeviceId);
        _icon.ShowBalloonTip(
            3000,
            "SippBucket",
            $"Device ID copied.\n{_identity.ShortId}...",
            ToolTipIcon.Info);
    }

    private async Task SyncNowAsync(RunningFolder entry)
    {
        var (text, icon) = await CycleAsync(entry).ConfigureAwait(true);
        _icon.ShowBalloonTip(4000, entry.Repository.Config.Name, Truncate(text), icon);
        UpdateTooltip();
    }

    /// <summary>Runs one cycle for a folder now and describes how it went.</summary>
    /// <returns>A description and how serious it is. Never throws.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "A UI action. Any escaping exception crashes the tray and " +
                        "takes every watched folder down with it.")]
    private async Task<(string Text, ToolTipIcon Icon)> CycleAsync(RunningFolder entry)
    {
        using var deadline = new CancellationTokenSource(SyncNowTimeout);

        try
        {
            var results = await entry.Service.RunCycleAsync(deadline.Token).ConfigureAwait(true);

            var summary = results.Count == 0
                ? "No peers are set up for this folder yet."
                : string.Join(Environment.NewLine, results.Select(r => r.Summary));

            return (summary, results.Any(r => !r.Succeeded) ? ToolTipIcon.Warning : ToolTipIcon.Info);
        }
        catch (OperationCanceledException)
        {
            return (
                $"Gave up waiting after {SyncNowTimeout.TotalMinutes:0} minutes. Nothing was " +
                "lost; the automatic cycle will try again. The window shows the last error.",
                ToolTipIcon.Warning);
        }
        catch (FolderBusyException ex)
        {
            // Another program, usually a 'sip' command, is writing to this folder right now
            // (D-38). Not an error: the message says who, and the next cycle runs normally.
            return (ex.Message, ToolTipIcon.Warning);
        }
        catch (Exception ex)
        {
            Log($"sync now failed: {ex.GetType().Name}: {ex.Message}");
            return (ex.Message, ToolTipIcon.Error);
        }
    }

    private async Task StopWatchingAsync(RunningFolder entry)
    {
        await entry.Service.DisposeAsync().ConfigureAwait(true);
        entry.Repository.Dispose();
        _running.Remove(entry);
        WatchedFolders.Remove(entry.Folder);
        UpdateTooltip();
    }

    private RunningFolder? Find(string folder) =>
        _running.FirstOrDefault(r => string.Equals(r.Folder, folder, StringComparison.OrdinalIgnoreCase));

    /// <summary>Labels for devices in one folder: "you", a peer's name, or nothing known.</summary>
    private Dictionary<string, string> PeerLabels(SipRepository repository)
    {
        var labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [_identity.DeviceId] = "you",
        };

        try
        {
            foreach (var peer in repository.Peers.Load())
            {
                if (!string.IsNullOrWhiteSpace(peer.DeviceId) && !labels.ContainsKey(peer.DeviceId))
                {
                    labels[peer.DeviceId] = DisplayText.Printable(peer.Name, 16);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // Labels are a nicety; the IDs still show.
        }

        return labels;
    }

    private static string Label(Dictionary<string, string> labels, string? deviceId) =>
        string.IsNullOrWhiteSpace(deviceId) ? "?"
        : labels.TryGetValue(deviceId, out var label) ? label
        : deviceId[..Math.Min(8, deviceId.Length)];

    /// <summary>Shows the window, rebuilding it first if it has been destroyed.</summary>
    /// <remarks>
    /// The window is only ever meant to be hidden, never closed, until the program quits -
    /// but "only ever" is the kind of promise this project has learned not to rest a crash
    /// on. Windows ending the session closes it, and a session end can be cancelled, which
    /// leaves the tray running with no window. So a destroyed window is rebuilt rather than
    /// shown, and no path to it can reach a disposed form.
    /// </remarks>
    private void ShowWindow()
    {
        if (_quitting)
        {
            return;
        }

        if (_window.IsDisposed)
        {
            MakeWindow();
        }

        _window.Present();
    }

    /// <summary>
    /// Makes the window, hidden, with its handle. Headless, nothing shows the window until the
    /// tray icon does, and a form that has never been shown has no handle: an outside
    /// <c>WM_CLOSE</c> - taskkill without /f, an installer asking running programs to close -
    /// reached only the icon's own hidden window, and SippBucket ran on (D-118). With the
    /// handle, that message arrives as <see cref="CloseReason.TaskManagerClosing"/>, which
    /// quits properly.
    /// </summary>
    [MemberNotNull(nameof(_window))]
    private void MakeWindow()
    {
        _window = new MainWindow(this);
        _window.Disposed += OnWindowDisposed;
        _window.CreateHidden();
    }

    /// <summary>
    /// Rebuilds the window, hidden, when Windows has closed it for a session end that was then
    /// cancelled, so an outside close always has a window to reach.
    /// </summary>
    private void OnWindowDisposed(object? sender, EventArgs e)
    {
        if (_quitting)
        {
            return;
        }

        // Posted: this runs inside the old window's disposal.
        _ui.Post(
            _ =>
            {
                if (!_quitting && _window.IsDisposed)
                {
                    MakeWindow();
                }
            },
            null);
    }

    /// <summary>
    /// Answers a second launch of SippBucket: a notification pointing at the tray icon,
    /// not a window — the window opens only from the icon, however many times the exe is
    /// opened.
    /// </summary>
    /// <remarks>
    /// Runs on a thread-pool thread, so it only posts to the UI thread and never waits on
    /// it - <see cref="SingleInstance.StopListening"/> waits for this callback to finish,
    /// on the UI thread, and a callback that waited back would deadlock shutdown. If the UI
    /// thread has already gone because the application is quitting, there is nothing to
    /// show and nothing to report.
    /// </remarks>
    private void OnAnotherLaunch()
    {
        try
        {
            _ui.Post(_ => AnnounceInTray(), null);
        }
        catch (ObjectDisposedException)
        {
            // Quitting.
        }
        catch (InvalidOperationException)
        {
            // The UI thread's marshalling window is being destroyed: quitting.
        }
        catch (InvalidAsynchronousStateException)
        {
            // The UI thread has ended: quitting.
        }
    }

    private void UpdateTooltip()
    {
        UpdateIcon();

        // NotifyIcon.Text is capped at 63 characters by the shell; anything longer throws.
        var unhealthy = _running.Count(entry =>
            !entry.Service.IsRunning || !entry.Service.GetStatus().IsHealthy);

        var text = unhealthy > 0
            ? $"SippBucket - {unhealthy} folder(s) NOT syncing"
            : _running.Count switch
            {
                0 => "SippBucket - no folders",
                1 => $"SippBucket - {_running[0].Repository.Config.Name}",
                _ => $"SippBucket - {_running.Count} folders",
            };

        _icon.Text = text.Length <= 63 ? text : text[..63];
    }

    /// <summary>
    /// Redraws the tray icon for the worst state present.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Worst, not first or newest. The icon is one glyph for a whole machine, so the only
    /// defensible rule is that it shows the thing that would change what the user does —
    /// which is the same rule <see cref="FolderStatus.Headline"/> applies within a folder,
    /// applied once more across them.
    /// </para>
    /// <para>
    /// The old icon is disposed only after the new one is attached. Disposing first leaves
    /// <see cref="NotifyIcon"/> holding a destroyed handle for the window between the two
    /// assignments, which renders as a brief blank square.
    /// </para>
    /// </remarks>
    private void UpdateIcon()
    {
        var worst = _running
            .Where(entry => entry.Service.IsRunning)
            .Select(entry => MarkIcon.StateFor(entry.Service.GetStatus()))
            .OrderBy(Rank)
            .FirstOrDefault(new MarkState(0, Color.FromArgb(0x1B, 0x1A, 0x17), Color.FromArgb(0xB4, 0x76, 0x2A), false));

        if (worst == _drawnState)
        {
            // Redrawing an unchanged icon thirty times a minute is churn the shell notices.
            return;
        }

        var replacement = MarkIcon.Render(worst);
        var previous = _currentIcon;

        _currentIcon = replacement;
        _icon.Icon = replacement;
        _drawnState = worst;

        previous.Dispose();
    }

    /// <summary>Orders states worst-first, so the tray shows the one that matters.</summary>
    private static int Rank(MarkState state) => state.Level switch
    {
        // Drained and grey: the daemon is not doing its job. Nothing outranks it.
        <= 0.2 when state.Ink.R == 0xA0 => 0,

        // Brimming clay: over quota, so saves are being refused.
        >= 0.99 when state.Liquid.R == 0xA9 => 1,

        // Empty: never synced, or nothing to sync with.
        <= 0.02 => 2,

        // Ageing: the claim is getting old.
        _ when state.Liquid.R == 0xCF => 3,

        // In flight.
        _ when state.Liquid.R == 0xD9 => 4,

        _ => 5,
    };

    private void Log(string line)
    {
        var stamped = string.Create(
            CultureInfo.InvariantCulture,
            $"{DateTimeOffset.Now:HH:mm:ss}  {line}");

        lock (_logLock)
        {
            _log.Add(stamped);
            if (_log.Count > 200)
            {
                _log.RemoveRange(0, _log.Count - 200);
            }
        }
    }

    private async Task QuitAsync()
    {
        // Reachable from the menu and from the window at once. Quitting twice would dispose
        // each service twice and exit the thread twice.
        if (_quitting)
        {
            return;
        }

        _quitting = true;
        _icon.Visible = false;
        _window.PrepareToExit();

        if (!_window.IsDisposed)
        {
            _window.Hide();
        }

        foreach (var entry in _running)
        {
            await entry.Service.DisposeAsync().ConfigureAwait(true);
            entry.Repository.Dispose();
        }

        _running.Clear();

        // Last: every folder has unregistered, and this closes the port.
        await _daemon.DisposeAsync().ConfigureAwait(true);
        ExitThread();
    }

    private static string FirstLine(string text)
    {
        var end = text.IndexOfAny(['\r', '\n']);
        return end < 0 ? text : text[..end];
    }

    private static string Truncate(string text) =>
        text.Length <= BalloonTextLimit ? text : text[..(BalloonTextLimit - 1)] + "…";

    private static ToolTipIcon Worse(ToolTipIcon current, ToolTipIcon candidate) =>
        Severity(candidate) > Severity(current) ? candidate : current;

    private static int Severity(ToolTipIcon icon) => icon switch
    {
        ToolTipIcon.Error => 2,
        ToolTipIcon.Warning => 1,
        _ => 0,
    };

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // First, so that a second launch arriving during shutdown cannot reach a window
            // that is about to stop existing.
            _instance.StopListening();

            _window.PrepareToExit();
            _window.Dispose();
            _refresh.Dispose();
            _icon.Dispose();
            _menuBold.Dispose();
            _currentIcon.Dispose();

            // Already stopped by QuitAsync on the ordinary way out, when this does nothing.
            // On any other way out it closes the port without waiting for connections.
            _daemon.Dispose();
            _identity.Dispose();
        }

        base.Dispose(disposing);
    }

    private sealed record RunningFolder(
        string Folder,
        SipRepository Repository,
        AutoSyncService Service);
}

/// <summary>What a first start logs and tells the person about starting with Windows.</summary>
/// <param name="LogLine">The line for the activity log, or null when there is nothing to log.</param>
/// <param name="BalloonTitle">The notification's title, or null when there is none.</param>
/// <param name="BalloonText">The notification's text, or null when there is none.</param>
internal readonly record struct FirstStartNotice(string? LogLine, string? BalloonTitle, string? BalloonText);
