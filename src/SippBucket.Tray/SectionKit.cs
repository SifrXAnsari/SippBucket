using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.Text;

namespace SippBucket.Tray;

/// <summary>The window's sections, in the order the rail lists them.</summary>
internal enum SectionId
{
    /// <summary>The folders board: the original window, unchanged.</summary>
    Folders,

    /// <summary>This machine: Server.ID, device key, port, team, Direct Push.</summary>
    Machine,

    /// <summary>The permanent alerts log, and the answers it waits for.</summary>
    Alerts,

    /// <summary>Direct Push's inbox and quarantine.</summary>
    Inbox,

    /// <summary>Conversations, and each message's status.</summary>
    Messages,

    /// <summary>Networks, discovery consent, port mapping and the ceilings.</summary>
    Network,

    /// <summary>Each folder's bucket: usage, retention, what can be reclaimed.</summary>
    Storage,

    /// <summary>Modes, locks, this machine's settings, and Direct Push's switch.</summary>
    Settings,

    /// <summary>What everything is, and where the commands are.</summary>
    Help,
}

/// <summary>
/// The left rail: one button per section, the alerts entry carrying a count when answers
/// are waited for.
/// </summary>
internal sealed class NavRail : Panel
{
    private const int RailWidth = 148;
    private const int ButtonHeight = 32;

    private readonly WindowFonts _fonts;
    private readonly Dictionary<SectionId, NavButton> _buttons = [];
    private SectionId _selected;

    public NavRail(WindowFonts fonts)
    {
        ArgumentNullException.ThrowIfNull(fonts);

        _fonts = fonts;
        BackColor = Palette.Band;
        Width = LogicalToDeviceUnits(RailWidth);
        Dock = DockStyle.Fill;
        Margin = Padding.Empty;

        var y = LogicalToDeviceUnits(8);
        foreach (var (id, text) in Entries())
        {
            var button = new NavButton(text, fonts);
            button.Top = y;
            button.Left = 0;
            button.Height = LogicalToDeviceUnits(ButtonHeight);
            button.Click += (_, _) => Choose(id);
            _buttons[id] = button;
            Controls.Add(button);
            y += button.Height;
        }

        Resize += (_, _) =>
        {
            foreach (var button in _buttons.Values)
            {
                button.Width = ClientSize.Width;
            }
        };

        SetSelected(SectionId.Folders);
    }

    /// <summary>Raised when a section is chosen, with which.</summary>
    public event EventHandler<SectionId>? SectionChosen;

    /// <summary>The width the rail wants.</summary>
    public int PreferredRailWidth => LogicalToDeviceUnits(RailWidth);

    /// <summary>Marks one section as the one showing.</summary>
    /// <param name="id">The section.</param>
    public void SetSelected(SectionId id)
    {
        _selected = id;
        foreach (var (which, button) in _buttons)
        {
            button.Selected = which == _selected;
        }
    }

    /// <summary>Shows a count on the Alerts entry: how many answers are waited for.</summary>
    /// <param name="waiting">The count; zero clears it.</param>
    public void SetAlertsWaiting(int waiting) => _buttons[SectionId.Alerts].SetBadge(waiting);

    private void Choose(SectionId id)
    {
        SetSelected(id);
        SectionChosen?.Invoke(this, id);
    }

    private static IEnumerable<(SectionId Id, string Text)> Entries()
    {
        yield return (SectionId.Folders, "Folders");
        yield return (SectionId.Machine, "This machine");
        yield return (SectionId.Alerts, "Alerts");
        yield return (SectionId.Inbox, "Inbox");
        yield return (SectionId.Messages, "Messages");
        yield return (SectionId.Network, "Network");
        yield return (SectionId.Storage, "Storage");
        yield return (SectionId.Settings, "Settings");
        yield return (SectionId.Help, "Help");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var button in _buttons.Values)
            {
                button.Dispose();
            }

            _buttons.Clear();
        }

        base.Dispose(disposing);
    }

    /// <summary>One rail entry, drawn flat with a selection band and an optional count.</summary>
    private sealed class NavButton : Control
    {
        private readonly WindowFonts _fonts;
        private bool _selected;
        private int _badge;
        private bool _hover;

        public NavButton(string text, WindowFonts fonts)
        {
            _fonts = fonts;
            Text = text;
            Cursor = Cursors.Hand;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
            MouseEnter += (_, _) => { _hover = true; Invalidate(); };
            MouseLeave += (_, _) => { _hover = false; Invalidate(); };
        }

        [Browsable(false)]
        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public bool Selected
        {
            get => _selected;
            set
            {
                if (_selected != value)
                {
                    _selected = value;
                    Invalidate();
                }
            }
        }

        public void SetBadge(int count)
        {
            if (_badge != count)
            {
                _badge = count;
                Invalidate();
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            var ground = _selected ? Palette.Surface : _hover ? Palette.Selected : Palette.Band;
            using (var brush = new SolidBrush(ground))
            {
                e.Graphics.FillRectangle(brush, ClientRectangle);
            }

            if (_selected)
            {
                using var accent = new SolidBrush(Palette.Accent);
                e.Graphics.FillRectangle(accent, 0, 0, LogicalToDeviceUnits(3), Height);
            }

            var textLeft = LogicalToDeviceUnits(14);
            TextRenderer.DrawText(
                e.Graphics,
                Text,
                _selected ? _fonts.UiBold : _fonts.Ui,
                new Rectangle(textLeft, 0, Width - textLeft, Height),
                _selected ? Palette.Ink : Palette.Muted,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);

            if (_badge > 0)
            {
                var text = _badge > 99 ? "99+" : _badge.ToString(CultureInfo.InvariantCulture);
                var size = TextRenderer.MeasureText(text, _fonts.SmallBold);
                var pad = LogicalToDeviceUnits(5);
                var width = size.Width + (2 * pad);
                var height = LogicalToDeviceUnits(17);
                var rect = new Rectangle(
                    Width - width - LogicalToDeviceUnits(10),
                    (Height - height) / 2,
                    width,
                    height);

                using var badge = new SolidBrush(Palette.Alert);
                e.Graphics.FillRectangle(badge, rect);
                TextRenderer.DrawText(
                    e.Graphics, text, _fonts.SmallBold, rect, Color.White,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
        }
    }
}

/// <summary>What one piece of a section is.</summary>
internal enum ElementKind
{
    /// <summary>A band heading, in caps.</summary>
    Band,

    /// <summary>A label and a value on one line, the value monospace when it is machine data.</summary>
    Pair,

    /// <summary>A sentence or two, wrapped.</summary>
    Text,

    /// <summary>A machine line: monospace, selectable by tooltip.</summary>
    Mono,

    /// <summary>A row of one or more buttons.</summary>
    Buttons,

    /// <summary>Vertical space.</summary>
    Gap,
}

/// <summary>One declarative piece of a section's content.</summary>
/// <remarks>
/// Sections describe themselves as a list of these, and <see cref="InfoSection.Render"/>
/// turns the list into controls — but only when the list changed, so a refresh tick that
/// finds the same facts leaves the controls alone and nothing flickers.
/// </remarks>
internal sealed record Element
{
    /// <summary>What it is.</summary>
    public required ElementKind Kind { get; init; }

    /// <summary>The heading, label, sentence or line.</summary>
    public string Text { get; init; } = string.Empty;

    /// <summary>The value, for a <see cref="ElementKind.Pair"/>.</summary>
    public string Value { get; init; } = string.Empty;

    /// <summary>True to draw the text or value in alert ink.</summary>
    public bool Alarm { get; init; }

    /// <summary>True to draw a pair's value monospace, for machine data.</summary>
    public bool MonoValue { get; init; }

    /// <summary>The buttons of a <see cref="ElementKind.Buttons"/> row.</summary>
    public IReadOnlyList<(string Text, Action Click)> Buttons { get; init; } = [];

    /// <summary>The part of the element that decides whether a rebuild is needed.</summary>
    public string Signature =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{Kind}|{Text}|{Value}|{Alarm}|{MonoValue}|{string.Join('/', Buttons.Select(b => b.Text))}");
}

/// <summary>
/// A section of the window: a scrolling column of bands, facts, sentences and buttons, in
/// the boards' own style, rebuilt only when its facts change.
/// </summary>
internal abstract class InfoSection : Panel
{
    private const int InnerPad = 18;
    private const int ContentWidth = 560;

    private readonly FlowLayoutPanel _column;
    private string _rendered = string.Empty;

    protected InfoSection(WindowFonts fonts)
    {
        ArgumentNullException.ThrowIfNull(fonts);

        Fonts = fonts;
        Dock = DockStyle.Fill;
        BackColor = Palette.Ground;
        AutoScroll = true;
        Margin = Padding.Empty;

        _column = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Palette.Ground,
            Padding = new Padding(LogicalToDeviceUnits(InnerPad)),
            Margin = Padding.Empty,
        };
        Controls.Add(_column);
    }

    /// <summary>The window's fonts, shared.</summary>
    protected WindowFonts Fonts { get; }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // The column's children go with it; they were made here and nowhere else.
            _column.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary>Reads this section's facts. Called on the UI thread, on each refresh tick.</summary>
    /// <returns>The content, top to bottom.</returns>
    public abstract IReadOnlyList<Element> Describe();

    /// <summary>Rebuilds the controls when <see cref="Describe"/> answers differently.</summary>
    public void RefreshSection()
    {
        IReadOnlyList<Element> elements;
        try
        {
            elements = Describe();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            // A section that cannot read its store says so instead of taking the window down.
            elements =
            [
                new Element { Kind = ElementKind.Band, Text = "THIS SECTION CANNOT BE READ" },
                new Element { Kind = ElementKind.Text, Text = ex.Message, Alarm = true },
            ];
        }

        var signature = new StringBuilder();
        foreach (var element in elements)
        {
            signature.AppendLine(element.Signature);
        }

        var wanted = signature.ToString();
        if (string.Equals(wanted, _rendered, StringComparison.Ordinal))
        {
            return;
        }

        _rendered = wanted;
        Render(elements);
    }

    private void Render(IReadOnlyList<Element> elements)
    {
        _column.SuspendLayout();

        // Snapshot first: disposing a control removes it from its parent's collection, and
        // enumerating the live collection while that happens skips every second control.
        var old = _column.Controls.Cast<Control>().ToList();
        _column.Controls.Clear();
        foreach (var control in old)
        {
            control.Dispose();
        }

        var width = LogicalToDeviceUnits(ContentWidth);
        foreach (var element in elements)
        {
            _column.Controls.Add(Build(element, width));
        }

        _column.ResumeLayout(performLayout: true);
    }

    private Control Build(Element element, int width)
    {
        switch (element.Kind)
        {
            case ElementKind.Band:
            {
                var label = new Label
                {
                    Text = element.Text.ToUpperInvariant(),
                    Font = Fonts.Caps,
                    ForeColor = Palette.Faint,
                    BackColor = Color.Transparent,
                    AutoSize = false,
                    Width = width,
                    Height = LogicalToDeviceUnits(22),
                    TextAlign = ContentAlignment.BottomLeft,
                    Margin = new Padding(0, LogicalToDeviceUnits(14), 0, LogicalToDeviceUnits(4)),
                    UseMnemonic = false,
                };
                return label;
            }

            case ElementKind.Pair:
            {
                var row = new Panel
                {
                    Width = width,
                    Height = LogicalToDeviceUnits(22),
                    BackColor = Color.Transparent,
                    Margin = new Padding(0, 0, 0, LogicalToDeviceUnits(2)),
                };
                var name = new Label
                {
                    Text = element.Text,
                    Font = Fonts.Ui,
                    ForeColor = Palette.Muted,
                    AutoSize = false,
                    Bounds = new Rectangle(0, 0, LogicalToDeviceUnits(160), row.Height),
                    TextAlign = ContentAlignment.MiddleLeft,
                    UseMnemonic = false,
                };
                var value = new Label
                {
                    Text = element.Value,
                    Font = element.MonoValue ? Fonts.Mono : Fonts.Ui,
                    ForeColor = element.Alarm ? Palette.Alert : Palette.Ink,
                    AutoSize = false,
                    Bounds = new Rectangle(name.Width + LogicalToDeviceUnits(8), 0, width - name.Width - LogicalToDeviceUnits(8), row.Height),
                    TextAlign = ContentAlignment.MiddleLeft,
                    AutoEllipsis = true,
                    UseMnemonic = false,
                };
                row.Controls.Add(name);
                row.Controls.Add(value);
                return row;
            }

            case ElementKind.Mono:
            {
                var label = new Label
                {
                    Text = element.Text,
                    Font = Fonts.Mono,
                    ForeColor = element.Alarm ? Palette.Alert : Palette.Ink,
                    BackColor = Color.Transparent,
                    AutoSize = false,
                    Width = width,
                    Height = LogicalToDeviceUnits(18),
                    AutoEllipsis = true,
                    UseMnemonic = false,
                };
                return label;
            }

            case ElementKind.Buttons:
            {
                var row = new FlowLayoutPanel
                {
                    FlowDirection = FlowDirection.LeftToRight,
                    WrapContents = true,
                    AutoSize = true,
                    AutoSizeMode = AutoSizeMode.GrowAndShrink,
                    BackColor = Color.Transparent,
                    Margin = new Padding(0, LogicalToDeviceUnits(6), 0, LogicalToDeviceUnits(2)),
                    MaximumSize = new Size(width, 0),
                };
                foreach (var (text, click) in element.Buttons)
                {
                    var button = new FlatActionButton(text, Fonts.Ui);
                    button.Click += (_, _) => click();
                    row.Controls.Add(button);
                }

                return row;
            }

            case ElementKind.Gap:
                return new Panel
                {
                    Width = width,
                    Height = LogicalToDeviceUnits(8),
                    BackColor = Color.Transparent,
                    Margin = Padding.Empty,
                };

            default:
            {
                var label = new Label
                {
                    Text = element.Text,
                    Font = Fonts.Ui,
                    ForeColor = element.Alarm ? Palette.Alert : Palette.Muted,
                    BackColor = Color.Transparent,
                    AutoSize = true,
                    MaximumSize = new Size(width, 0),
                    Margin = new Padding(0, 0, 0, LogicalToDeviceUnits(4)),
                    UseMnemonic = false,
                };
                return label;
            }
        }
    }
}
