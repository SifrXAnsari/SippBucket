using System.Drawing;
using System.Globalization;
using SippBucket.Core.Crypto;
using SippBucket.Core.Sync;

namespace SippBucket.Tray;

/// <summary>
/// The SippBucket window: every watched folder in the daemon's own words, the machines it
/// syncs with, and what it has been doing.
/// </summary>
/// <remarks>
/// <para>
/// Built to the Main board on the design canvas. The rules that board sets are kept here
/// rather than restated: the state column is <see cref="FolderStatus.Headline"/> verbatim;
/// the folder list keeps the order folders were added in and never sorts itself worst-first,
/// because a list you navigate by memory must not rearrange when a daemon changes its mind;
/// machine data is monospace and prose is not; and there is no green tick anywhere, because
/// a tick is a two-state claim and it is exactly what rendered while nothing was syncing.
/// </para>
/// <para>
/// <strong>Closing the window does not quit.</strong> The daemon is the product and the
/// window is a view of it, so the close box hides the window and the tray carries on. Quit
/// is on the tray icon's menu, where it has always been.
/// </para>
/// <para>
/// The window asks <see cref="IMainWindowHost"/> for a fresh picture every two seconds while
/// it is visible, and not at all while it is hidden. Status is computed from a clock rather
/// than pushed on change — the failures this daemon is most likely to have are silent, so a
/// view that waited to be told would never be told.
/// </para>
/// </remarks>
internal sealed class MainWindow : Form
{
    private const int ToolbarHeight = 46;
    private const int BandHeight = 26;
    private const int StatusBarHeight = 26;
    private const int MachinesWidth = 300;
    private const int ActivityHeight = 132;
    private const int ActivityLines = 60;

    private readonly IMainWindowHost _host;
    private readonly WindowFonts _fonts = new();
    private readonly ToolTip _tips = new();
    private readonly System.Windows.Forms.Timer _refresh = new();
    private readonly Dictionary<MarkState, Bitmap> _glyphs = [];
    private readonly Dictionary<string, FolderRow> _rows = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<PeerCard> _peerCards = [];
    private readonly ContextMenuStrip _rowMenu = new();
    private readonly Icon _windowIcon;

    private readonly FlowLayoutPanel _folderList = new();
    private readonly Panel _emptyState = new();
    private readonly FlowLayoutPanel _peerList = new();
    private readonly Label _noPeers = new();
    private readonly Label _reachability = new();
    private readonly Label _passphrases = new();
    private readonly Label _passphraseNote = new();
    private readonly Label _machineLines = new();
    private readonly Label _deviceId = new();
    private readonly TextBox _activity = new();
    private readonly Label _statusLeft = new();
    private readonly Label _statusRight = new();
    private readonly FlatActionButton _syncNow;

    private readonly NavRail _nav;
    private readonly Panel _contentHost = new();
    private readonly Dictionary<SectionId, InfoSection> _sections = [];
    private readonly Label _alertsIndicator = new();
    private Control? _foldersView;
    private SectionId _active = SectionId.Folders;

    private string? _selectedPath;
    // Null until the first write, so an empty log is still drawn once. Starting from "" meant
    // an empty log never differed from what was shown and the box stayed blank.
    private string? _activityShown;
    private bool _exiting;
    private bool _fitting;
    private bool _syncing;

    /// <summary>Builds the window. It is not shown until <see cref="Present"/> is called.</summary>
    /// <param name="host">The tray that owns the folders.</param>
    public MainWindow(IMainWindowHost host)
    {
        ArgumentNullException.ThrowIfNull(host);

        _host = host;
        _windowIcon = MarkIcon.Render(MarkIcon.Identity, 32);
        _syncNow = new FlatActionButton("Sync now", _fonts.Ui, quiet: true);
        _nav = new NavRail(_fonts);

        SuspendLayout();

        // Every size below is converted from logical pixels by hand, so automatic scaling is
        // off: letting WinForms scale the same numbers again would double them.
        AutoScaleMode = AutoScaleMode.None;
        Text = "SippBucket";
        Icon = _windowIcon;
        Font = _fonts.Ui;
        BackColor = Palette.Ground;
        ForeColor = Palette.Ink;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(Px(1060), Px(660));
        MinimumSize = new Size(Px(800), Px(520));
        ShowInTaskbar = true;

        _tips.AutoPopDelay = 20000;

        BuildRowMenu();
        Controls.Add(BuildSkeleton());

        _refresh.Interval = 2000;
        _refresh.Tick += (_, _) => RefreshFromHost();

        ResumeLayout(performLayout: true);
    }

    /// <summary>Shows the window and brings it to the front, refreshed.</summary>
    public void Present()
    {
        RefreshFromHost();

        if (!Visible)
        {
            Show();
        }

        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }

        Activate();
    }

    /// <summary>
    /// Gives the window its handle without showing it. A form that has never been shown has no
    /// handle, so it is no window at all, and a close request from outside the program cannot
    /// reach <see cref="OnFormClosing"/>.
    /// </summary>
    public void CreateHidden()
    {
        if (!IsHandleCreated)
        {
            CreateHandle();
        }
    }

    /// <summary>Lets the next close actually close, because the application is quitting.</summary>
    public void PrepareToExit() => _exiting = true;

    /// <remarks>
    /// <para>
    /// Decided by the reason, because the reasons mean different things and one of them was
    /// found the hard way. The close box, Alt+F4 and the taskbar's Close window arrive as
    /// <see cref="CloseReason.UserClosing"/>: the person is done looking, not done syncing,
    /// so the window hides.
    /// </para>
    /// <para>
    /// A <c>WM_CLOSE</c> from outside the program arrives as
    /// <see cref="CloseReason.TaskManagerClosing"/> - it is what Task Manager's End task
    /// sends. The first version of this method only intercepted <c>UserClosing</c>, so that
    /// message closed and disposed the window while the tray carried on, and every later
    /// attempt to open the window reached a disposed form: a second launch showed nothing,
    /// and a click on the tray icon would have thrown on the UI thread. Found by the
    /// end-to-end check, which closes the window exactly that way. Something asking the
    /// program to end means end, so it quits properly - every folder's service stopped
    /// cleanly - rather than hiding and waiting to be killed.
    /// </para>
    /// <para>
    /// Only quitting and Windows shutting down actually close the window.
    /// </para>
    /// </remarks>
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        if (_exiting || e.CloseReason == CloseReason.WindowsShutDown)
        {
            base.OnFormClosing(e);
            return;
        }

        e.Cancel = true;

        if (e.CloseReason == CloseReason.TaskManagerClosing)
        {
            // Posted, not called: this runs inside the close message, and quitting disposes
            // this window.
            BeginInvoke(_host.Quit);
            return;
        }

        // Hide, do not close. The folders are still being kept in sync, and the tray icon is
        // where the daemon lives - closing a window should not stop the product.
        Hide();
        _host.AnnounceStillRunning();
    }

    protected override void OnVisibleChanged(EventArgs e)
    {
        base.OnVisibleChanged(e);

        // Refresh only while someone can see it. A hidden window polling every two seconds
        // would be the daemon paying for a view nobody is looking at.
        _refresh.Enabled = Visible;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _refresh.Dispose();
            _tips.Dispose();
            _rowMenu.Dispose();

            foreach (var glyph in _glyphs.Values)
            {
                glyph.Dispose();
            }

            _glyphs.Clear();

            // Every control this window keeps a field for, disposed by name. Most are also in
            // the tree and would be disposed by the base class anyway - disposing a control
            // twice is harmless - but not all of them always are: the "no peers" note is
            // detached whenever there are peers to list, and a control outside the tree is
            // not reached by the base class at all. Naming them all is the only way that is
            // right for every state rather than for the usual one.
            _noPeers.Dispose();
            _folderList.Dispose();
            _emptyState.Dispose();
            _peerList.Dispose();
            _reachability.Dispose();
            _passphrases.Dispose();
            _passphraseNote.Dispose();
            _machineLines.Dispose();
            _deviceId.Dispose();
            _activity.Dispose();
            _statusLeft.Dispose();
            _alertsIndicator.Dispose();
            _statusRight.Dispose();
            _syncNow.Dispose();
            _nav.Dispose();

            foreach (var section in _sections.Values)
            {
                section.Dispose();
            }

            _sections.Clear();
            _foldersView?.Dispose();
            _contentHost.Dispose();

            // The fonts go last, after nothing can draw with them.
            base.Dispose(disposing);
            _windowIcon.Dispose();
            _fonts.Dispose();
            return;
        }

        base.Dispose(disposing);
    }

    private int Px(int logical) => LogicalToDeviceUnits(logical);

    private TableLayoutPanel BuildSkeleton()
    {
        var root = Grid(columns: 1, rows: 5);
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, Px(ToolbarHeight)));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 1));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 1));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, Px(StatusBarHeight)));

        root.Controls.Add(BuildToolbar(), 0, 0);
        root.Controls.Add(RuleLine(), 0, 1);
        root.Controls.Add(BuildRailAndContent(), 0, 2);
        root.Controls.Add(RuleLine(), 0, 3);
        root.Controls.Add(BuildStatusBar(), 0, 4);

        return root;
    }

    /// <summary>
    /// The left rail and the sections it switches between. The Folders section is the
    /// original board, unchanged; the rest read the same stores the commands read.
    /// </summary>
    private TableLayoutPanel BuildRailAndContent()
    {
        var split = Grid(columns: 3, rows: 1);
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, _nav.PreferredRailWidth));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 1));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        split.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _contentHost.Dock = DockStyle.Fill;
        _contentHost.Margin = Padding.Empty;
        _contentHost.BackColor = Palette.Ground;

        _foldersView = BuildBody();
        _foldersView.Dock = DockStyle.Fill;
        _contentHost.Controls.Add(_foldersView);

        _sections[SectionId.Machine] = new MachineSection(_host, _fonts);
        _sections[SectionId.Alerts] = new AlertsSection(_host, _fonts);
        _sections[SectionId.Inbox] = new InboxSection(_fonts);
        _sections[SectionId.Messages] = new MessagesSection(_host, _fonts);
        _sections[SectionId.Network] = new NetworkSection(_host, _fonts);
        _sections[SectionId.Storage] = new StorageSection(_host, _fonts);
        _sections[SectionId.Settings] = new SettingsSection(_host, _fonts);
        _sections[SectionId.Help] = new HelpSection(_host, _fonts);

        foreach (var section in _sections.Values)
        {
            section.Visible = false;
            _contentHost.Controls.Add(section);
        }

        _nav.SectionChosen += (_, id) => ShowSection(id);

        split.Controls.Add(_nav, 0, 0);
        split.Controls.Add(RuleLine(), 1, 0);
        split.Controls.Add(_contentHost, 2, 0);
        return split;
    }

    /// <summary>Switches to one section, refreshing it as it appears.</summary>
    public void ShowSection(SectionId id)
    {
        _active = id;
        _nav.SetSelected(id);

        _foldersView!.Visible = id == SectionId.Folders;
        foreach (var (which, section) in _sections)
        {
            section.Visible = which == id;
        }

        if (_sections.TryGetValue(id, out var shown))
        {
            shown.RefreshSection();
        }
    }

    private TableLayoutPanel BuildToolbar()
    {
        var bar = Grid(columns: 2, rows: 1);
        bar.BackColor = Palette.Surface;
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        // Pinned to the bar's height. Left to size itself, the row grew to the button
        // panel's preferred height and the count, centred in that taller row, sat visibly
        // low - seen in the first screenshot of the running window.
        bar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        bar.Padding = new Padding(Px(10), 0, Px(14), 0);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(0, Px(9), 0, 0),
            Margin = Padding.Empty,
            BackColor = Palette.Surface,
        };

        var addFolder = new FlatActionButton("Add folder…", _fonts.Ui);
        addFolder.Click += (_, _) => AddFolder();

        var pair = new FlatActionButton("Pair a machine…", _fonts.Ui);
        pair.Click += (_, _) => OpenPairDialog();

        var divider = new Panel
        {
            Width = 1,
            Height = Px(22),
            BackColor = Palette.Rule,
            Margin = new Padding(Px(4), Px(3), Px(10), 0),
        };

        _syncNow.Click += async (_, _) => await SyncAllAsync().ConfigureAwait(true);

        var commandLine = new FlatActionButton("Command line…", _fonts.Ui, quiet: true);
        commandLine.Click += (_, _) => _host.OpenCommandLine(this);

        buttons.Controls.Add(addFolder);
        buttons.Controls.Add(pair);
        buttons.Controls.Add(divider);
        buttons.Controls.Add(_syncNow);
        buttons.Controls.Add(commandLine);

        // No status dot beside the count. A count short of its total is not a green fact,
        // and there is no dot colour that means "partly" - so it states itself.
        Style(_reachability, _fonts.Mono, Palette.Muted);
        _reachability.AutoSize = true;
        _reachability.Anchor = AnchorStyles.Right;
        _reachability.Margin = Padding.Empty;

        bar.Controls.Add(buttons, 0, 0);
        bar.Controls.Add(_reachability, 1, 0);
        return bar;
    }

    private TableLayoutPanel BuildBody()
    {
        var body = Grid(columns: 3, rows: 1);
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 1));
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Px(MachinesWidth)));

        body.Controls.Add(BuildFoldersPane(), 0, 0);
        body.Controls.Add(RuleLine(), 1, 0);
        body.Controls.Add(BuildMachinesPane(), 2, 0);
        return body;
    }

    private TableLayoutPanel BuildFoldersPane()
    {
        var pane = Grid(columns: 1, rows: 5);
        pane.RowStyles.Add(new RowStyle(SizeType.Absolute, Px(BandHeight)));
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 1));
        pane.RowStyles.Add(new RowStyle(SizeType.Absolute, Px(BandHeight)));
        pane.RowStyles.Add(new RowStyle(SizeType.Absolute, Px(ActivityHeight)));

        _folderList.Dock = DockStyle.Fill;
        _folderList.FlowDirection = FlowDirection.TopDown;
        _folderList.WrapContents = false;
        _folderList.AutoScroll = true;
        _folderList.BackColor = Palette.Ground;
        _folderList.Margin = Padding.Empty;
        _folderList.ClientSizeChanged += (_, _) => FitRows();

        BuildEmptyState();

        var listHost = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BackColor = Palette.Ground };
        listHost.Controls.Add(_folderList);
        listHost.Controls.Add(_emptyState);

        _activity.Dock = DockStyle.Fill;
        _activity.Multiline = true;
        _activity.ReadOnly = true;
        _activity.BorderStyle = BorderStyle.None;
        _activity.ScrollBars = ScrollBars.Vertical;

        // Wrapped. A log line is often a full path, and with wrapping off and no horizontal
        // scrollbar its end - usually the part that says what happened - was unreachable.
        _activity.WordWrap = true;
        _activity.Font = _fonts.Mono;
        _activity.BackColor = Palette.Band;
        _activity.ForeColor = Palette.Muted;
        _activity.Margin = new Padding(Px(14), 0, Px(6), Px(8));
        _activity.TabStop = false;

        pane.Controls.Add(Band("FOLDERS"), 0, 0);
        pane.Controls.Add(listHost, 0, 1);
        pane.Controls.Add(RuleLine(), 0, 2);
        pane.Controls.Add(Band("ACTIVITY"), 0, 3);

        var activityHost = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BackColor = Palette.Band };
        activityHost.Padding = new Padding(Px(14), 0, Px(6), Px(8));
        activityHost.Controls.Add(_activity);
        pane.Controls.Add(activityHost, 0, 4);

        return pane;
    }

    private void BuildEmptyState()
    {
        _emptyState.Dock = DockStyle.Fill;
        _emptyState.BackColor = Palette.Ground;
        _emptyState.Visible = false;

        var title = new Label();
        Style(title, _fonts.Title, Palette.Ink);
        title.AutoSize = true;
        title.Text = "No folders yet";

        var body = new Label();
        Style(body, _fonts.Ui, Palette.Muted);
        body.AutoSize = true;
        body.MaximumSize = new Size(Px(460), 0);
        body.Text =
            "The guided first run is two steps. Choose a folder, and SippBucket keeps it the " +
            "same on every machine you pair with this one. Then pair a machine - the dialog " +
            "walks both sides through it with a spoken code. Until you pair one, nothing " +
            "leaves this computer.";

        var add = new FlatActionButton("1.  Add folder…", _fonts.Ui);
        add.Click += (_, _) => AddFolder();

        var pair = new FlatActionButton("2.  Pair a machine…", _fonts.Ui);
        pair.Click += (_, _) => OpenPairDialog();

        var help = new FlatActionButton("What is all this?", _fonts.Ui, quiet: true);
        help.Click += (_, _) => ShowSection(SectionId.Help);

        _emptyState.Controls.Add(title);
        _emptyState.Controls.Add(body);
        _emptyState.Controls.Add(add);
        _emptyState.Controls.Add(pair);
        _emptyState.Controls.Add(help);

        _emptyState.Layout += (_, _) =>
        {
            var left = Px(32);
            var top = Math.Max(Px(24), _emptyState.ClientSize.Height / 4);

            title.Location = new Point(left, top);
            body.Location = new Point(left, title.Bottom + Px(8));
            add.Location = new Point(left, body.Bottom + Px(16));
            pair.Location = new Point(add.Right + Px(10), body.Bottom + Px(16));
            help.Location = new Point(pair.Right + Px(10), body.Bottom + Px(16));
        };
    }

    private TableLayoutPanel BuildMachinesPane()
    {
        var pane = Grid(columns: 1, rows: 4);
        pane.BackColor = Palette.Surface;
        pane.RowStyles.Add(new RowStyle(SizeType.Absolute, Px(BandHeight)));
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 1));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _peerList.Dock = DockStyle.Fill;
        _peerList.FlowDirection = FlowDirection.TopDown;
        _peerList.WrapContents = false;
        _peerList.AutoScroll = true;
        _peerList.BackColor = Palette.Surface;
        _peerList.Margin = Padding.Empty;
        _peerList.ClientSizeChanged += (_, _) => FitPeerCards();

        Style(_noPeers, _fonts.Small, Palette.Muted);
        _noPeers.AutoSize = true;
        _noPeers.MaximumSize = new Size(Px(MachinesWidth - 28), 0);
        _noPeers.Margin = new Padding(Px(14), Px(12), Px(14), 0);
        _noPeers.Text =
            "No peers yet. Pair a machine and it will appear here, with whether it can be " +
            "reached right now.";

        pane.Controls.Add(Band("MACHINES"), 0, 0);
        pane.Controls.Add(_peerList, 0, 1);
        pane.Controls.Add(RuleLine(), 0, 2);
        pane.Controls.Add(BuildThisMachine(), 0, 3);
        return pane;
    }

    private TableLayoutPanel BuildThisMachine()
    {
        var width = Px(MachinesWidth - 28);

        var panel = Grid(columns: 1, rows: 7);
        panel.Dock = DockStyle.Fill;
        panel.AutoSize = true;
        panel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        panel.BackColor = Palette.Band;
        panel.Padding = new Padding(Px(14), Px(10), Px(14), Px(12));

        for (var i = 0; i < 7; i++)
        {
            panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }

        var heading = new Label();
        Style(heading, _fonts.Caps, Palette.Muted);
        heading.AutoSize = true;
        heading.Text = "THIS MACHINE";
        heading.Margin = new Padding(0, 0, 0, Px(6));

        var name = new Label();
        Style(name, _fonts.SmallBold, Palette.Ink);
        name.AutoSize = true;
        name.Text = Environment.MachineName;

        Style(_deviceId, _fonts.Mono, Palette.Muted);
        _deviceId.AutoSize = true;
        _deviceId.Margin = new Padding(0, Px(3), 0, 0);
        _deviceId.Text = SplitDeviceId(_host.DeviceId);

        var copy = new FlatActionButton("Copy device ID", _fonts.Small);
        copy.Margin = new Padding(0, Px(8), 0, Px(10));
        copy.Click += (_, _) => _host.CopyDeviceId();

        Style(_passphrases, _fonts.SmallBold, Palette.Ink);
        _passphrases.AutoSize = true;
        _passphrases.MaximumSize = new Size(width, 0);

        Style(_passphraseNote, _fonts.Small, Palette.Muted);
        _passphraseNote.AutoSize = true;
        _passphraseNote.MaximumSize = new Size(width, 0);
        _passphraseNote.Margin = new Padding(0, Px(2), 0, Px(8));
        _passphraseNote.Text =
            "Where there is none, blocks are encrypted on disk but the key is stored beside " +
            "them, so anyone who can sign in to this PC can read them. sip lock sets a " +
            "passphrase, one folder at a time.";

        Style(_machineLines, _fonts.Small, Palette.Muted);
        _machineLines.AutoSize = true;
        _machineLines.MaximumSize = new Size(width, 0);

        panel.Controls.Add(heading, 0, 0);
        panel.Controls.Add(name, 0, 1);
        panel.Controls.Add(_deviceId, 0, 2);
        panel.Controls.Add(copy, 0, 3);
        panel.Controls.Add(_passphrases, 0, 4);
        panel.Controls.Add(_passphraseNote, 0, 5);
        panel.Controls.Add(_machineLines, 0, 6);
        return panel;
    }

    private TableLayoutPanel BuildStatusBar()
    {
        var bar = Grid(columns: 3, rows: 1);
        bar.BackColor = Palette.Band;
        bar.Padding = new Padding(Px(12), 0, Px(12), 0);
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        Style(_statusLeft, _fonts.Mono, Palette.Muted);
        _statusLeft.Dock = DockStyle.Fill;

        // The alerts indicator (T-03): what waits for an answer, one click from the answer.
        Style(_alertsIndicator, _fonts.Mono, Palette.Faint);
        _alertsIndicator.AutoSize = true;
        _alertsIndicator.Anchor = AnchorStyles.Right;
        _alertsIndicator.Margin = new Padding(0, 0, Px(14), 0);
        _alertsIndicator.Cursor = Cursors.Hand;
        _alertsIndicator.Click += (_, _) => ShowSection(SectionId.Alerts);
        _tips.SetToolTip(_alertsIndicator, "Everything SippBucket has noticed about another machine. Click to open.");

        Style(_statusRight, _fonts.Mono, Palette.Faint);
        _statusRight.AutoSize = true;
        _statusRight.Anchor = AnchorStyles.Right;
        _statusRight.Text = "v" + VersionText();

        bar.Controls.Add(_statusLeft, 0, 0);
        bar.Controls.Add(_alertsIndicator, 1, 0);
        bar.Controls.Add(_statusRight, 2, 0);
        return bar;
    }

    /// <summary>The status bar's alerts figure: never a colour without a count beside it.</summary>
    private void ShowAlertsIndicator(int waiting)
    {
        if (waiting > 0)
        {
            _alertsIndicator.Text = string.Create(
                CultureInfo.CurrentCulture, $"{waiting} alert(s) waiting for your answer");
            _alertsIndicator.ForeColor = Palette.Alert;
            _alertsIndicator.Font = _fonts.SmallBold;
        }
        else
        {
            _alertsIndicator.Text = "alerts: none waiting";
            _alertsIndicator.ForeColor = Palette.Faint;
            _alertsIndicator.Font = _fonts.Mono;
        }
    }

    private void BuildRowMenu()
    {
        _rowMenu.Items.Add("Open folder", null, (_, _) =>
        {
            if (_selectedPath is { } path)
            {
                _host.OpenFolder(path);
            }
        });

        _rowMenu.Items.Add("History, encryption and conflicts…", null, (_, _) =>
        {
            if (_selectedPath is { } path)
            {
                OpenFolderDetail(path);
            }
        });

        _rowMenu.Items.Add("Sync now", null, async (_, _) =>
        {
            if (_selectedPath is { } path)
            {
                await SyncOneAsync(path).ConfigureAwait(true);
            }
        });

        _rowMenu.Items.Add(new ToolStripSeparator());

        _rowMenu.Items.Add("Stop watching…", null, async (_, _) =>
        {
            if (_selectedPath is { } path)
            {
                await ConfirmStopWatchingAsync(path).ConfigureAwait(true);
            }
        });
    }

    /// <summary>Redraws everything from a fresh picture of the tray's state.</summary>
    private void RefreshFromHost()
    {
        var folders = _host.Folders();
        var statuses = folders.Select(f => f.Status).OfType<FolderStatus>().ToList();

        ShowFolders(folders);
        ShowPeers(MachineOverview.Peers(statuses));

        _reachability.Text = MachineOverview.Reachability(statuses);

        _passphrases.Text = MachineOverview.Passphrases(statuses);
        _passphraseNote.Visible = statuses.Any(s => !s.HasPassphrase);

        _machineLines.Text =
            _host.AutostartDescription + Environment.NewLine + DeviceKeyLine(_host.DeviceKeyFile);

        ShowActivity();
        ShowStatusBar(folders, statuses);

        // The alerts log is small - alerts are rare by design - so reading it on the same
        // two-second cadence as everything else keeps the badge honest for the same price.
        var waiting = AlertsSection.Waiting();
        _nav.SetAlertsWaiting(waiting);
        ShowAlertsIndicator(waiting);

        if (_active != SectionId.Folders && _sections.TryGetValue(_active, out var section))
        {
            section.RefreshSection();
        }

        // Hidden when there is nothing to sync, and relabelled while a sync runs - never
        // merely disabled. A disabled flat button draws its text in a tint of its own that
        // on this ground comes out ochre, so "Sync now" looked more clickable when it did
        // nothing than when it worked. Seen in the empty-state screenshot.
        _syncNow.Visible = folders.Count > 0;
        _syncNow.Text = _syncing ? "Syncing…" : "Sync now";
    }

    private void ShowFolders(IReadOnlyList<WatchedFolderView> folders)
    {
        _emptyState.Visible = folders.Count == 0;
        _folderList.Visible = folders.Count > 0;

        var wanted = new HashSet<string>(folders.Select(f => f.Path), StringComparer.OrdinalIgnoreCase);

        _folderList.SuspendLayout();
        try
        {
            foreach (var gone in _rows.Keys.Where(p => !wanted.Contains(p)).ToList())
            {
                var row = _rows[gone];
                _rows.Remove(gone);
                _folderList.Controls.Remove(row);
                row.Dispose();
            }

            for (var index = 0; index < folders.Count; index++)
            {
                var view = folders[index];

                if (!_rows.TryGetValue(view.Path, out var row))
                {
                    row = CreateRow(view.Path);
                    _rows[view.Path] = row;
                    _folderList.Controls.Add(row);
                }

                // Folder order, always. See the remarks on this class.
                _folderList.Controls.SetChildIndex(row, index);

                row.Display(view, GlyphFor(view.Status is { } status
                    ? MarkIcon.StateFor(status)
                    : MarkIcon.NotWatched));
                row.Selected = string.Equals(view.Path, _selectedPath, StringComparison.OrdinalIgnoreCase);
            }

            if (_selectedPath is not null && !wanted.Contains(_selectedPath))
            {
                _selectedPath = null;
            }
        }
        finally
        {
            _folderList.ResumeLayout(performLayout: true);
        }

        FitRows();
    }

    private FolderRow CreateRow(string path)
    {
        var row = new FolderRow(path, _fonts, _tips) { ContextMenuStrip = _rowMenu };

        row.SelectRequested += (_, _) => SelectRow(path);
        row.OpenRequested += (_, _) => OpenFolderDetail(path);
        row.SyncNowRequested += async (_, _) => await SyncOneAsync(path).ConfigureAwait(true);

        return row;
    }

    private void SelectRow(string path)
    {
        _selectedPath = path;

        foreach (var (key, row) in _rows)
        {
            row.Selected = string.Equals(key, path, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>Gives every row the list's width and the height that width needs.</summary>
    /// <remarks>
    /// A row's height depends on its width - the alert strip's explanation wraps - and the
    /// list's width depends on whether it needs a scrollbar, which depends on the rows'
    /// heights. The guard stops that loop from feeding itself through ClientSizeChanged.
    /// </remarks>
    private void FitRows()
    {
        if (_fitting)
        {
            return;
        }

        _fitting = true;
        try
        {
            var width = _folderList.ClientSize.Width;

            foreach (Control control in _folderList.Controls)
            {
                if (control is FolderRow row)
                {
                    row.Size = new Size(width, row.HeightFor(width));
                }
            }
        }
        finally
        {
            _fitting = false;
        }
    }

    private void ShowPeers(IReadOnlyList<PeerOverview> peers)
    {
        _peerList.SuspendLayout();
        try
        {
            while (_peerCards.Count > peers.Count)
            {
                var card = _peerCards[^1];
                _peerCards.RemoveAt(_peerCards.Count - 1);
                _peerList.Controls.Remove(card);
                card.Dispose();
            }

            while (_peerCards.Count < peers.Count)
            {
                var card = new PeerCard(_fonts, _tips);
                _peerCards.Add(card);
                _peerList.Controls.Add(card);
            }

            for (var i = 0; i < peers.Count; i++)
            {
                _peerCards[i].Display(peers[i]);
            }

            if (peers.Count == 0)
            {
                if (!_peerList.Controls.Contains(_noPeers))
                {
                    _peerList.Controls.Add(_noPeers);
                }
            }
            else
            {
                _peerList.Controls.Remove(_noPeers);
            }
        }
        finally
        {
            _peerList.ResumeLayout(performLayout: true);
        }

        FitPeerCards();
    }

    private void FitPeerCards()
    {
        var width = _peerList.ClientSize.Width;

        foreach (var card in _peerCards)
        {
            card.Size = new Size(width, card.PreferredCardHeight);
        }
    }

    private void ShowActivity()
    {
        var text = string.Join(Environment.NewLine, _host.RecentActivity(ActivityLines));

        // Only when it changed. Resetting the text every two seconds would snap the scroll
        // position back to the top under anyone reading further down.
        if (string.Equals(text, _activityShown, StringComparison.Ordinal))
        {
            return;
        }

        _activityShown = text;
        _activity.Text = text.Length > 0 ? text : "Nothing yet.";
    }

    private void ShowStatusBar(IReadOnlyList<WatchedFolderView> folders, List<FolderStatus> statuses)
    {
        var parts = new List<string>
        {
            folders.Count == 1
                ? "1 folder watched"
                : string.Create(CultureInfo.CurrentCulture, $"{folders.Count} folders watched"),
        };

        var notServing = statuses.Count(s => s.ServerFault is not null);
        if (notServing > 0)
        {
            parts.Add(string.Create(CultureInfo.CurrentCulture, $"not serving peers in {notServing} of {statuses.Count}"));
        }

        var notRunning = folders.Count(f => f.Status is null);
        if (notRunning > 0)
        {
            parts.Add(string.Create(CultureInfo.CurrentCulture, $"{notRunning} not being watched"));
        }

        parts.Add(string.Create(
            CultureInfo.CurrentCulture,
            $"poll {_host.PollInterval.TotalSeconds:0} s"));

        _statusLeft.Text = string.Join("  ·  ", parts);
    }

    private Bitmap GlyphFor(MarkState state)
    {
        // Rounded to the nearest twentieth so the cache is bounded. The level is continuous
        // during a transfer, and a bitmap per distinct fraction would grow without limit
        // over a long sync. A twentieth is finer than 16 pixels can show.
        var key = state with { Level = Math.Round(state.Level * 20) / 20 };

        if (_glyphs.TryGetValue(key, out var cached))
        {
            return cached;
        }

        using var icon = MarkIcon.Render(key, Px(16));
        var bitmap = icon.ToBitmap();
        _glyphs[key] = bitmap;
        return bitmap;
    }

    private void AddFolder()
    {
        _host.AddFolder(this);
        RefreshFromHost();
    }

    /// <summary>Pairing in the window (D-90): offer a code, or enter one, with the one question.</summary>
    private void OpenPairDialog()
    {
        using var dialog = new PairDialog(_host, _fonts);
        _ = dialog.ShowDialog(this);
        RefreshFromHost();
    }

    /// <summary>One folder up close: history, encryption and conflicts.</summary>
    private void OpenFolderDetail(string path)
    {
        using var dialog = new FolderDetailDialog(_host, path, _fonts);
        _ = dialog.ShowDialog(this);
    }

    private async Task SyncAllAsync()
    {
        if (_syncing)
        {
            return;
        }

        _syncing = true;
        _syncNow.Text = "Syncing…";
        try
        {
            await _host.SyncAllNowAsync().ConfigureAwait(true);
        }
        finally
        {
            _syncing = false;
            RefreshFromHost();
        }
    }

    private async Task SyncOneAsync(string path)
    {
        await _host.SyncNowAsync(path).ConfigureAwait(true);
        RefreshFromHost();
    }

    private async Task ConfirmStopWatchingAsync(string path)
    {
        var answer = MessageBox.Show(
            this,
            $"Stop keeping this folder in sync on this machine?\n\n{path}\n\n" +
            "Nothing is deleted. The folder, its files and its history stay exactly as they " +
            "are, and it can be added again at any time.",
            "Stop watching",
            MessageBoxButtons.OKCancel,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2);

        if (answer != DialogResult.OK)
        {
            return;
        }

        await _host.StopWatchingAsync(path).ConfigureAwait(true);
        RefreshFromHost();
    }

    private Panel Band(string caption)
    {
        var band = new Panel { Dock = DockStyle.Fill, BackColor = Palette.Band, Margin = Padding.Empty };

        var label = new Label();
        Style(label, _fonts.Caps, Palette.Muted);
        label.Dock = DockStyle.Fill;
        label.Padding = new Padding(Px(12), 0, 0, 0);
        label.Text = caption;

        band.Controls.Add(label);
        return band;
    }

    private static Panel RuleLine() =>
        new() { Dock = DockStyle.Fill, BackColor = Palette.Rule, Margin = Padding.Empty };

    private static TableLayoutPanel Grid(int columns, int rows) => new()
    {
        Dock = DockStyle.Fill,
        ColumnCount = columns,
        RowCount = rows,
        Margin = Padding.Empty,
        Padding = Padding.Empty,
        BackColor = Palette.Ground,
    };

    private static void Style(Label label, Font font, Color colour)
    {
        label.Font = font;
        label.ForeColor = colour;
        label.BackColor = Color.Transparent;
        label.UseMnemonic = false;
        label.TextAlign = ContentAlignment.MiddleLeft;
    }

    /// <summary>The <em>This machine</em> line about the device key, read from the key file.</summary>
    /// <param name="keyFile">The device key file.</param>
    /// <returns>What the file is, with the limit of the claim next to it.</returns>
    /// <remarks>
    /// <para>
    /// From the file, on every refresh. This line used to be chosen by whether the platform
    /// could protect the key, not by whether this key was protected, and it read "Device key
    /// protected by Windows (DPAPI)" on a machine whose key was 32 raw bytes on disk (D-51).
    /// Reading one small file every two seconds, only while the window is open, is a cheap
    /// price for a status line that cannot drift from what it describes.
    /// </para>
    /// <para>
    /// The protected line carries its limit (standard A3). DPAPI stops the file being read
    /// from another ordinary account or on another machine; it does not stop anything running
    /// as this user, an administrator while the user is signed in, or anyone with the user's
    /// password. <see cref="SippBucket.Core.Crypto.DeviceKeyFile"/> has the sources.
    /// </para>
    /// </remarks>
    internal static string DeviceKeyLine(string keyFile) => DeviceKeyFile.Inspect(keyFile) switch
    {
        DeviceKeyState.Protected =>
            "Device key encrypted by Windows (DPAPI) for your account. Programs running as " +
            "you, an administrator while you are signed in, or anyone with your password can " +
            "still read it.",
        DeviceKeyState.Unprotected =>
            "Device key is NOT protected: it is stored on disk as the raw key, readable by " +
            "anyone who can read your files.",
        DeviceKeyState.Missing =>
            "No device key yet. One is made, encrypted by Windows, the first time it is needed.",
        _ => "Device key could not be read, so whether it is protected is unknown.",
    };

    /// <summary>A 64-character device ID as two lines of 32, which is how it is read aloud.</summary>
    private static string SplitDeviceId(string deviceId) =>
        deviceId.Length == 64 ? deviceId[..32] + Environment.NewLine + deviceId[32..] : deviceId;

    private static string VersionText()
    {
        var version = Application.ProductVersion;
        var build = version.IndexOf('+', StringComparison.Ordinal);
        return build > 0 ? version[..build] : version;
    }
}
