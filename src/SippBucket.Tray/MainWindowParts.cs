using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using SippBucket.Core.Storage;
using SippBucket.Core.Sync;

namespace SippBucket.Tray;

/// <summary>The window's colours, taken from the design canvas and nowhere else.</summary>
/// <remarks>
/// Zero new colours. Every value here already appears on the Main board, and each keeps the
/// meaning the canvas gave it: alert clay is for failure only, the advisory tint is for
/// things that are true and not urgent, and there is no verified green anywhere a count is
/// short of its total.
/// </remarks>
internal static class Palette
{
    public static readonly Color Ground = Color.FromArgb(0xF4, 0xF1, 0xEA);
    public static readonly Color Surface = Color.FromArgb(0xFF, 0xFD, 0xF9);
    public static readonly Color Band = Color.FromArgb(0xEF, 0xEB, 0xE1);
    public static readonly Color Rule = Color.FromArgb(0xDD, 0xD7, 0xC9);
    public static readonly Color RowRule = Color.FromArgb(0xE7, 0xE1, 0xD4);
    public static readonly Color ButtonEdge = Color.FromArgb(0xC9, 0xC2, 0xB2);
    public static readonly Color Ink = Color.FromArgb(0x1B, 0x1A, 0x17);
    public static readonly Color Muted = Color.FromArgb(0x5D, 0x58, 0x4E);
    public static readonly Color Faint = Color.FromArgb(0x8A, 0x83, 0x77);
    public static readonly Color Accent = Color.FromArgb(0x8F, 0x5C, 0x1E);
    public static readonly Color Alert = Color.FromArgb(0xA9, 0x3F, 0x25);
    public static readonly Color AlertGround = Color.FromArgb(0xFA, 0xF0, 0xEC);
    public static readonly Color Ok = Color.FromArgb(0x3D, 0x6B, 0x3A);
    public static readonly Color Drained = Color.FromArgb(0xCF, 0xC8, 0xB8);
    public static readonly Color Selected = Color.FromArgb(0xF1, 0xEC, 0xE2);
}

/// <summary>The fonts the window draws with, owned and disposed in one place.</summary>
/// <remarks>
/// Machine data — paths, hashes, device IDs, sizes — is always monospace and prose never is,
/// so a reader can tell at a glance what the computer said from what a person wrote.
/// </remarks>
internal sealed class WindowFonts : IDisposable
{
    public Font Ui { get; } = new("Segoe UI", 9F);

    public Font UiBold { get; } = new("Segoe UI", 9.75F, FontStyle.Bold);

    public Font Small { get; } = new("Segoe UI", 8.25F);

    public Font SmallBold { get; } = new("Segoe UI", 8.25F, FontStyle.Bold);

    public Font Caps { get; } = new("Segoe UI", 7.5F, FontStyle.Bold);

    public Font Title { get; } = new("Segoe UI", 12F, FontStyle.Bold);

    public Font Mono { get; } = new("Consolas", 8.5F);

    public void Dispose()
    {
        Ui.Dispose();
        UiBold.Dispose();
        Small.Dispose();
        SmallBold.Dispose();
        Caps.Dispose();
        Title.Dispose();
        Mono.Dispose();
    }
}

/// <summary>A filled circle, for a peer's reachability.</summary>
internal sealed class Dot : Control
{
    public Dot()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer
            | ControlStyles.UserPaint
            | ControlStyles.SupportsTransparentBackColor,
            true);
        BackColor = Color.Transparent;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var brush = new SolidBrush(ForeColor);
        e.Graphics.FillEllipse(brush, 0, 0, Width - 1, Height - 1);
    }
}

/// <summary>A plain rectangular button in the canvas's style.</summary>
internal sealed class FlatActionButton : Button
{
    public FlatActionButton(string text, Font font, bool quiet = false)
    {
        Text = text;
        Font = font;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        FlatStyle = FlatStyle.Flat;
        UseVisualStyleBackColor = false;
        BackColor = Palette.Surface;
        ForeColor = quiet ? Palette.Muted : Palette.Ink;
        Cursor = Cursors.Hand;
        Padding = new Padding(8, 2, 8, 2);
        Margin = new Padding(0, 0, 6, 0);
        FlatAppearance.BorderColor = quiet ? Palette.Surface : Palette.ButtonEdge;
        FlatAppearance.MouseOverBackColor = Palette.Band;
        FlatAppearance.MouseDownBackColor = Palette.Rule;
    }
}

/// <summary>
/// One watched folder: name and path, size, the daemon's own sentence for its state, and
/// whatever else is true underneath.
/// </summary>
/// <remarks>
/// <para>
/// The state column carries <see cref="FolderStatus.Headline"/> and nothing else — the
/// sentences the daemon can emit, in its own words. What is true but is not the state goes
/// underneath as <see cref="FolderStatus.Detail"/> does in the code: a passphrase or a
/// conflict sits below the state, it does not replace it.
/// </para>
/// <para>
/// Laid out by hand rather than by nested layout panels. The row has to know its own height
/// before it is placed — the alert strip's explanation wraps to however many lines the
/// width allows — and a hand layout is the one that can answer that question exactly, at
/// any DPI, without a second pass.
/// </para>
/// </remarks>
internal sealed class FolderRow : Panel
{
    private const int PadX = 14;
    private const int PadY = 10;
    private const int StateWidth = 270;
    private const int SizeWidth = 76;
    private const int Gap = 10;
    private const int GlyphSize = 16;
    private const int NameHeight = 20;
    private const int PathHeight = 16;
    private const int DetailHeight = 18;
    private const int StripGap = 8;
    private const int StripPad = 8;
    private const int StripTitleHeight = 18;
    private const int StripButtonWidth = 92;
    private const int StripButtonHeight = 26;
    private const int StripAccent = 2;

    private readonly WindowFonts _fonts;
    private readonly ToolTip _tips;
    private readonly Label _name = new();
    private readonly Label _path = new();
    private readonly Label _size = new();
    private readonly PictureBox _glyph = new();
    private readonly Label _state = new();
    private readonly Label _detail = new();
    private readonly Panel _strip = new();
    private readonly Label _stripTitle = new();
    private readonly Label _stripBody = new();
    private readonly FlatActionButton _stripButton;

    private bool _selected;
    private bool _stripOffersSync;

    public FolderRow(string folderPath, WindowFonts fonts, ToolTip tips)
    {
        FolderPath = folderPath;
        _fonts = fonts;
        _tips = tips;

        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Palette.Surface;
        Margin = Padding.Empty;

        Setup(_name, fonts.UiBold, Palette.Ink);
        Setup(_path, fonts.Mono, Palette.Faint);
        Setup(_size, fonts.Mono, Palette.Ink);
        _size.TextAlign = ContentAlignment.MiddleRight;
        Setup(_state, fonts.Ui, Palette.Ink);
        _state.TextAlign = ContentAlignment.MiddleLeft;
        Setup(_detail, fonts.Small, Palette.Muted);

        _glyph.SizeMode = PictureBoxSizeMode.CenterImage;
        _glyph.BackColor = Color.Transparent;

        _strip.BackColor = Palette.AlertGround;
        _strip.Paint += PaintStripAccent;
        Setup(_stripTitle, fonts.SmallBold, Palette.Alert);
        _stripTitle.BackColor = Palette.AlertGround;
        Setup(_stripBody, fonts.Small, Palette.Muted);
        _stripBody.BackColor = Palette.AlertGround;
        _stripBody.AutoEllipsis = false;

        _stripButton = new FlatActionButton("Sync now", fonts.Small)
        {
            AutoSize = false,
            Margin = Padding.Empty,
            Padding = Padding.Empty,
        };
        _stripButton.Click += (_, _) => SyncNowRequested?.Invoke(this, EventArgs.Empty);

        _strip.Controls.Add(_stripTitle);
        _strip.Controls.Add(_stripBody);
        _strip.Controls.Add(_stripButton);

        Controls.Add(_name);
        Controls.Add(_path);
        Controls.Add(_size);
        Controls.Add(_glyph);
        Controls.Add(_state);
        Controls.Add(_detail);
        Controls.Add(_strip);

        WireSelection(this);
    }

    /// <summary>Raised when the row is clicked, so the window can select it.</summary>
    public event EventHandler? SelectRequested;

    /// <summary>Raised when the row is double-clicked.</summary>
    public event EventHandler? OpenRequested;

    /// <summary>Raised by the alert strip's Sync now button.</summary>
    public event EventHandler? SyncNowRequested;

    /// <summary>The folder's path, which identifies the row.</summary>
    public string FolderPath { get; }

    /// <summary>Whether this is the selected row.</summary>
    [Browsable(false)]
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool Selected
    {
        get => _selected;
        set
        {
            if (_selected == value)
            {
                return;
            }

            _selected = value;
            BackColor = value ? Palette.Selected : Palette.Surface;
        }
    }

    /// <summary>Shows a folder's current state.</summary>
    /// <param name="view">The folder.</param>
    /// <param name="glyph">The mark for its state, owned by the caller's cache.</param>
    public void Display(WatchedFolderView view, Image? glyph)
    {
        ArgumentNullException.ThrowIfNull(view);

        SetText(_name, view.Name);
        SetText(_path, view.Path);

        var status = view.Status;

        if (status is null)
        {
            // The service is not running for this folder. Said plainly, in alert ink,
            // because a folder on this list that nothing is watching is the P0 case.
            SetText(_size, "—");
            SetText(_state, "Not being watched");
            _state.ForeColor = Palette.Alert;
            _glyph.Image = glyph;
            SetText(_detail, string.Empty);
            SetStrip(
                "Not being watched",
                "SippBucket is not running a sync service for this folder, so nothing in it is " +
                "being kept in sync. Nothing has been lost: the documents are where you put them.",
                offersSync: false);
            return;
        }

        SetText(_size, status.Bucket is { } bucket ? BucketUsage.Bytes(bucket.UsedBytes) : "—");
        SetText(_state, status.Headline);
        _state.ForeColor = IsAlarm(status) ? Palette.Alert : Palette.Ink;
        _glyph.Image = glyph;
        SetText(_detail, status.Detail ?? string.Empty);

        if (status.ServerFault is not null)
        {
            SetStrip(
                status.Headline,
                "Other machines cannot fetch from this one until this clears, though this " +
                "machine can still fetch from them. A port already in use is the usual cause.",
                offersSync: false);
        }
        else if (status.Bucket is { IsFull: true })
        {
            SetStrip(
                status.Headline,
                "New snapshots are refused until space is freed; sip bucket shows what can be " +
                "reclaimed. The documents themselves are untouched.",
                offersSync: false);
        }
        else if (status.Freshness == SyncFreshness.NotChecking)
        {
            // States what is known and stops. Freshness reaches NotChecking from the age of
            // one timestamp and nothing else, so the program cannot tell a wedged read from
            // a dead peer from a stopped watcher - and so it does not guess.
            SetStrip(
                status.Headline,
                "The reason is not known — that is what this state means. Changes made here " +
                "may not have reached other machines, and theirs may not have arrived here. " +
                "Nothing has been lost: the documents are where you put them.",
                offersSync: true);
        }
        else
        {
            SetStrip(string.Empty, string.Empty, offersSync: false);
        }
    }

    /// <summary>The height this row needs at a given width.</summary>
    /// <param name="width">The width it will be given.</param>
    /// <returns>The height in device pixels.</returns>
    public int HeightFor(int width)
    {
        var height = Scale(PadY) + Scale(NameHeight) + Scale(PathHeight);

        if (_detail.Text.Length > 0)
        {
            height += Scale(DetailHeight);
        }

        if (_strip.Visible)
        {
            height += Scale(StripGap) + StripHeight(width);
        }

        return height + Scale(PadY) + 1;
    }

    protected override void OnLayout(LayoutEventArgs levent)
    {
        base.OnLayout(levent);

        var width = ClientSize.Width;
        var padX = Scale(PadX);
        var stateWidth = Math.Min(Scale(StateWidth), Math.Max(0, width / 2));
        var sizeWidth = Scale(SizeWidth);
        var gap = Scale(Gap);
        var glyph = Scale(GlyphSize);
        var y = Scale(PadY);
        var nameHeight = Scale(NameHeight);

        var stateLeft = width - padX - stateWidth;
        var sizeLeft = stateLeft - gap - sizeWidth;
        var nameWidth = Math.Max(0, sizeLeft - gap - padX);

        _name.SetBounds(padX, y, nameWidth, nameHeight);
        _size.SetBounds(sizeLeft, y, sizeWidth, nameHeight);
        _glyph.SetBounds(stateLeft, y + ((nameHeight - glyph) / 2), glyph, glyph);
        _state.SetBounds(stateLeft + glyph + Scale(6), y, Math.Max(0, stateWidth - glyph - Scale(6)), nameHeight);

        y += nameHeight;
        _path.SetBounds(padX, y, Math.Max(0, width - (2 * padX)), Scale(PathHeight));
        y += Scale(PathHeight);

        _detail.Visible = _detail.Text.Length > 0;
        if (_detail.Visible)
        {
            _detail.SetBounds(padX, y, Math.Max(0, width - (2 * padX)), Scale(DetailHeight));
            y += Scale(DetailHeight);
        }

        if (_strip.Visible)
        {
            y += Scale(StripGap);
            var stripWidth = Math.Max(0, width - (2 * padX));
            _strip.SetBounds(padX, y, stripWidth, StripHeight(width));
            LayoutStrip(stripWidth);
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        using var rule = new Pen(Palette.RowRule);
        e.Graphics.DrawLine(rule, 0, Height - 1, Width, Height - 1);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Named rather than left to the base class, which only reaches controls that are
            // still in the tree. All of these are, today; naming them keeps that from being
            // something a later change has to remember.
            _name.Dispose();
            _path.Dispose();
            _size.Dispose();
            _glyph.Dispose();
            _state.Dispose();
            _detail.Dispose();
            _stripTitle.Dispose();
            _stripBody.Dispose();
            _stripButton.Dispose();
            _strip.Dispose();
        }

        base.Dispose(disposing);
    }
    private static bool IsAlarm(FolderStatus status) =>
        status.ServerFault is not null
        || status.Bucket is { IsFull: true }
        || status.Freshness == SyncFreshness.NotChecking;

    private static void Setup(Label label, Font font, Color colour)
    {
        label.Font = font;
        label.ForeColor = colour;
        label.BackColor = Color.Transparent;
        label.AutoSize = false;
        label.AutoEllipsis = true;
        label.UseMnemonic = false;
        label.TextAlign = ContentAlignment.MiddleLeft;
    }

    private void SetText(Label label, string text)
    {
        if (string.Equals(label.Text, text, StringComparison.Ordinal))
        {
            return;
        }

        label.Text = text;

        // The full sentence is always one hover away. A headline cut short by the column
        // is still the daemon's claim, and the part that was cut may be the time.
        _tips.SetToolTip(label, text);
    }

    private void SetStrip(string title, string body, bool offersSync)
    {
        var visible = title.Length > 0;
        _strip.Visible = visible;
        _stripOffersSync = offersSync;
        _stripButton.Visible = offersSync;

        if (visible)
        {
            SetText(_stripTitle, title);
            _stripBody.Text = body;
        }
    }

    private int StripHeight(int rowWidth)
    {
        var inner = StripInnerWidth(Math.Max(0, rowWidth - (2 * Scale(PadX))));
        var body = TextRenderer.MeasureText(
            _stripBody.Text,
            _stripBody.Font,
            new Size(Math.Max(1, inner), int.MaxValue),
            TextFormatFlags.WordBreak | TextFormatFlags.NoPadding).Height;

        // A couple of pixels over the measurement. A Label draws with its own internal
        // padding, and a strip that measures a hair short clips the last line of the one
        // sentence in it that says nothing has been lost.
        var content = Scale(StripTitleHeight) + body + Scale(2);
        var button = _stripOffersSync ? Scale(StripButtonHeight) : 0;

        return (2 * Scale(StripPad)) + Math.Max(content, button);
    }

    private int StripInnerWidth(int stripWidth)
    {
        var reserved = Scale(StripAccent) + (2 * Scale(StripPad));

        if (_stripOffersSync)
        {
            reserved += Scale(StripButtonWidth) + Scale(StripPad);
        }

        return Math.Max(1, stripWidth - reserved);
    }

    private void LayoutStrip(int stripWidth)
    {
        var left = Scale(StripAccent) + Scale(StripPad);
        var top = Scale(StripPad);
        var inner = StripInnerWidth(stripWidth);
        var titleHeight = Scale(StripTitleHeight);

        _stripTitle.SetBounds(left, top, inner, titleHeight);
        _stripBody.SetBounds(
            left,
            top + titleHeight,
            inner,
            Math.Max(0, _strip.Height - top - titleHeight - Scale(StripPad)));

        if (_stripOffersSync)
        {
            _stripButton.SetBounds(
                stripWidth - Scale(StripPad) - Scale(StripButtonWidth),
                (_strip.Height - Scale(StripButtonHeight)) / 2,
                Scale(StripButtonWidth),
                Scale(StripButtonHeight));
        }
    }

    private void PaintStripAccent(object? sender, PaintEventArgs e)
    {
        using var accent = new SolidBrush(Palette.Alert);
        e.Graphics.FillRectangle(accent, 0, 0, Scale(StripAccent), _strip.Height);
    }

    private int Scale(int logical) => LogicalToDeviceUnits(logical);

    private void WireSelection(Control control)
    {
        foreach (Control child in control.Controls)
        {
            if (child is Button)
            {
                continue;
            }

            WireSelection(child);
        }

        control.MouseDown += (_, e) =>
        {
            // Right as well as left, so a context menu always acts on the row it was opened
            // over rather than on whichever row happened to be selected before.
            if (e.Button is MouseButtons.Left or MouseButtons.Right)
            {
                SelectRequested?.Invoke(this, EventArgs.Empty);
            }
        };

        control.DoubleClick += (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty);
    }
}

/// <summary>One peer, as every watched folder sees it.</summary>
internal sealed class PeerCard : Panel
{
    private const int PadX = 14;
    private const int PadY = 9;
    private const int DotSize = 7;

    private readonly Dot _dot = new();
    private readonly Label _name = new();
    private readonly Label _line = new();
    private readonly ToolTip _tips;

    public PeerCard(WindowFonts fonts, ToolTip tips)
    {
        ArgumentNullException.ThrowIfNull(fonts);

        _tips = tips;
        BackColor = Palette.Surface;
        Margin = Padding.Empty;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);

        foreach (var label in new[] { _name, _line })
        {
            label.AutoSize = false;
            label.AutoEllipsis = true;
            label.UseMnemonic = false;
            label.BackColor = Color.Transparent;
            label.TextAlign = ContentAlignment.MiddleLeft;
        }

        _name.Font = fonts.SmallBold;
        _name.ForeColor = Palette.Ink;
        _line.Font = fonts.Small;
        _line.ForeColor = Palette.Muted;

        Controls.Add(_dot);
        Controls.Add(_name);
        Controls.Add(_line);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _dot.Dispose();
            _name.Dispose();
            _line.Dispose();
        }

        base.Dispose(disposing);
    }
    /// <summary>The height a card needs.</summary>
    public int PreferredCardHeight => LogicalToDeviceUnits((2 * PadY) + 36);

    /// <summary>Shows one peer.</summary>
    /// <param name="peer">The peer.</param>
    public void Display(PeerOverview peer)
    {
        ArgumentNullException.ThrowIfNull(peer);

        // Green only for a peer actually reached by every folder that knows it and synced
        // with. A peer that answered and then failed is the failure colour: it is there, and
        // the problem is in what it served (D-58). Anything else is the drained grey -
        // including "not checked yet", which is not a failure but is not a success either,
        // and must not borrow the colour of one.
        _dot.ForeColor = peer.IsFailing && !peer.IsUnreachable ? Palette.Alert
            : peer.IsReachable ? Palette.Ok
            : Palette.Drained;
        _name.ForeColor = peer.IsReachable ? Palette.Ink : Palette.Muted;
        _name.Text = peer.Name;

        var line = peer.Describe();
        if (peer.FolderCount > 1)
        {
            line = string.Create(CultureInfo.CurrentCulture, $"{line} · {peer.FolderCount} folders");
        }

        _line.Text = line;
        _tips.SetToolTip(_line, peer.FailureReason is { } reason ? $"{line}\n{reason}" : line);
    }

    protected override void OnLayout(LayoutEventArgs levent)
    {
        base.OnLayout(levent);

        var padX = LogicalToDeviceUnits(PadX);
        var padY = LogicalToDeviceUnits(PadY);
        var dot = LogicalToDeviceUnits(DotSize);
        var lineHeight = LogicalToDeviceUnits(18);
        var textLeft = padX + dot + LogicalToDeviceUnits(8);
        var textWidth = Math.Max(0, ClientSize.Width - textLeft - padX);

        _dot.SetBounds(padX, padY + ((lineHeight - dot) / 2), dot, dot);
        _name.SetBounds(textLeft, padY, textWidth, lineHeight);
        _line.SetBounds(textLeft, padY + lineHeight, textWidth, lineHeight);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        using var rule = new Pen(Palette.RowRule);
        e.Graphics.DrawLine(rule, 0, Height - 1, Width, Height - 1);
    }
}
