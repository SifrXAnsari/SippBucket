using System.Drawing;
using System.Globalization;
using SippBucket.Core.Machines;
using SippBucket.Core.Pairing;

namespace SippBucket.Tray;

/// <summary>
/// Pairing in the window (D-90): offer a spoken code for one folder, or enter one from
/// another machine, with the one question — whose machine is it — asked where the pairing
/// happens.
/// </summary>
/// <remarks>
/// <para>
/// The same exchange the command line runs, through the same <see cref="IMainWindowHost"/>
/// the tray answers everything else with. The code's protections and its one weakness are
/// said next to the code, at the moment it exists, exactly as <c>sip pair offer</c> says
/// them: a help page nobody opens while holding a live code is the wrong place.
/// </para>
/// <para>
/// The one question is not skippable by accident: the enter side answers it before joining,
/// and the offer side is asked the moment a machine pairs. "Decide later" is a real answer
/// and is recorded as nothing — the machine is treated as another person's until said
/// otherwise, which is the safe side.
/// </para>
/// </remarks>
internal sealed class PairDialog : Form
{
    private readonly IMainWindowHost _host;
    private readonly WindowFonts _fonts;

    private readonly TabControl _tabs = new();
    private readonly ComboBox _offerFolder = new();
    private readonly FlatActionButton _startOffer;
    private readonly Label _code = new();
    private readonly TextBox _offerDetail = new();
    private readonly Panel _question = new();
    private readonly Label _questionText = new();
    private readonly RadioButton _mine = new();
    private readonly RadioButton _someoneElse = new();
    private readonly RadioButton _later = new();
    private readonly FlatActionButton _record;

    private readonly TextBox _enterAddress = new();
    private readonly TextBox _enterCode = new();
    private readonly TextBox _enterFolder = new();
    private readonly FlatActionButton _pickFolder;
    private readonly RadioButton _enterMine = new();
    private readonly RadioButton _enterSomeoneElse = new();
    private readonly FlatActionButton _join;
    private readonly TextBox _enterDetail = new();

    private readonly Font _codeFont = new("Consolas", 16F, FontStyle.Bold);

    private PairOfferSession? _session;
    private string? _pairedDevice;
    private string? _pairedName;
    private bool _joining;

    public PairDialog(IMainWindowHost host, WindowFonts fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(fonts);

        _host = host;
        _fonts = fonts;
        _startOffer = new FlatActionButton("Start offering", fonts.Ui);
        _record = new FlatActionButton("Record the answer", fonts.Ui);
        _pickFolder = new FlatActionButton("Choose empty folder…", fonts.Ui);
        _join = new FlatActionButton("Join", fonts.Ui);

        Text = "Pair a machine";
        Font = fonts.Ui;
        BackColor = Palette.Ground;
        ForeColor = Palette.Ink;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(Px(560), Px(520));

        _tabs.Dock = DockStyle.Fill;
        _tabs.TabPages.Add(BuildOfferPage());
        _tabs.TabPages.Add(BuildEnterPage());
        Controls.Add(_tabs);
    }

    private int Px(int logical) => LogicalToDeviceUnits(logical);

    private TabPage BuildOfferPage()
    {
        var page = new TabPage("Offer this folder") { BackColor = Palette.Ground };

        var intro = WrappedLabel(
            "The other machine gets a full copy of one folder and the key to it, and both " +
            "machines record each other. Pick the folder, read the code out, and on the other " +
            "machine open Pair a machine and enter it.");
        intro.Location = new Point(Px(14), Px(12));
        page.Controls.Add(intro);

        _offerFolder.DropDownStyle = ComboBoxStyle.DropDownList;
        _offerFolder.Font = _fonts.Ui;
        _offerFolder.SetBounds(Px(14), Px(76), Px(340), Px(24));
        foreach (var (path, name) in _host.PairableFolders())
        {
            _offerFolder.Items.Add(new FolderChoice(path, name));
        }

        if (_offerFolder.Items.Count > 0)
        {
            _offerFolder.SelectedIndex = 0;
        }

        page.Controls.Add(_offerFolder);

        _startOffer.Location = new Point(Px(364), Px(74));
        _startOffer.Click += async (_, _) => await StartOfferAsync().ConfigureAwait(true);
        page.Controls.Add(_startOffer);

        _code.Font = _codeFont;
        _code.ForeColor = Palette.Accent;
        _code.BackColor = Palette.Ground;
        _code.AutoSize = false;
        _code.SetBounds(Px(14), Px(108), Px(520), Px(34));
        _code.TextAlign = ContentAlignment.MiddleLeft;
        _code.UseMnemonic = false;
        page.Controls.Add(_code);

        _offerDetail.Multiline = true;
        _offerDetail.ReadOnly = true;
        _offerDetail.BorderStyle = BorderStyle.None;
        _offerDetail.BackColor = Palette.Band;
        _offerDetail.ForeColor = Palette.Muted;
        _offerDetail.Font = _fonts.Mono;
        _offerDetail.ScrollBars = ScrollBars.Vertical;
        _offerDetail.WordWrap = true;
        _offerDetail.TabStop = false;
        _offerDetail.SetBounds(Px(14), Px(148), Px(520), Px(200));
        page.Controls.Add(_offerDetail);

        BuildQuestion();
        _question.SetBounds(Px(14), Px(356), Px(520), Px(120));
        page.Controls.Add(_question);

        return page;
    }

    private void BuildQuestion()
    {
        _question.BackColor = Palette.Surface;
        _question.Visible = false;

        _questionText.Font = _fonts.UiBold;
        _questionText.ForeColor = Palette.Ink;
        _questionText.BackColor = Color.Transparent;
        _questionText.AutoSize = false;
        _questionText.SetBounds(Px(10), Px(8), Px(500), Px(20));
        _questionText.UseMnemonic = false;

        Setup(_mine, "My own machine — Server.ID, health records and discovery treat it as mine", Px(32));
        Setup(_someoneElse, "Someone else's — it counts toward the team, with the protections that brings", Px(54));
        Setup(_later, "Decide later — treated as someone else's until I say", Px(76));
        _later.Checked = true;

        _record.Location = new Point(Px(10), Px(96));
        _record.Visible = false;
        _record.Click += (_, _) => RecordOwner();

        _question.Controls.Add(_questionText);
        _question.Controls.Add(_mine);
        _question.Controls.Add(_someoneElse);
        _question.Controls.Add(_later);
        _question.Controls.Add(_record);

        void Setup(RadioButton radio, string text, int top)
        {
            radio.Text = text;
            radio.Font = _fonts.Small;
            radio.ForeColor = Palette.Muted;
            radio.BackColor = Color.Transparent;
            radio.AutoSize = false;
            radio.SetBounds(Px(10), top, Px(500), Px(20));
            radio.UseMnemonic = false;
        }
    }

    private TabPage BuildEnterPage()
    {
        var page = new TabPage("Enter a code") { BackColor = Palette.Ground };

        var intro = WrappedLabel(
            "On the machine that has the folder, open Pair a machine and start an offer. Then " +
            "enter here the address it shows, the code, and an empty folder to hold the copy.");
        intro.Location = new Point(Px(14), Px(12));
        page.Controls.Add(intro);

        page.Controls.Add(FieldLabel("Address", Px(72)));
        _enterAddress.Font = _fonts.Mono;
        _enterAddress.PlaceholderText = string.Create(
            CultureInfo.InvariantCulture, $"192.168.1.98:{_host.ListenPort}");
        _enterAddress.SetBounds(Px(120), Px(70), Px(240), Px(24));
        page.Controls.Add(_enterAddress);

        page.Controls.Add(FieldLabel("Code", Px(102)));
        _enterCode.Font = _fonts.Mono;
        _enterCode.SetBounds(Px(120), Px(100), Px(240), Px(24));
        page.Controls.Add(_enterCode);

        page.Controls.Add(FieldLabel("Empty folder", Px(132)));
        _enterFolder.Font = _fonts.Mono;
        _enterFolder.ReadOnly = true;
        _enterFolder.SetBounds(Px(120), Px(130), Px(240), Px(24));
        page.Controls.Add(_enterFolder);

        _pickFolder.Location = new Point(Px(368), Px(128));
        _pickFolder.Click += (_, _) => PickFolder();
        page.Controls.Add(_pickFolder);

        var whose = new Label
        {
            Text = "Whose machine is the one offering?",
            Font = _fonts.UiBold,
            ForeColor = Palette.Ink,
            BackColor = Color.Transparent,
            AutoSize = false,
            Bounds = new Rectangle(Px(14), Px(166), Px(500), Px(20)),
            UseMnemonic = false,
        };
        page.Controls.Add(whose);

        SetupRadio(_enterMine, "My own machine", Px(188));
        SetupRadio(_enterSomeoneElse, "Someone else's", Px(210));
        _enterMine.Checked = true;
        page.Controls.Add(_enterMine);
        page.Controls.Add(_enterSomeoneElse);

        _join.Location = new Point(Px(14), Px(240));
        _join.Click += async (_, _) => await JoinAsync().ConfigureAwait(true);
        page.Controls.Add(_join);

        _enterDetail.Multiline = true;
        _enterDetail.ReadOnly = true;
        _enterDetail.BorderStyle = BorderStyle.None;
        _enterDetail.BackColor = Palette.Band;
        _enterDetail.ForeColor = Palette.Muted;
        _enterDetail.Font = _fonts.Small;
        _enterDetail.ScrollBars = ScrollBars.Vertical;
        _enterDetail.WordWrap = true;
        _enterDetail.TabStop = false;
        _enterDetail.SetBounds(Px(14), Px(276), Px(520), Px(200));
        page.Controls.Add(_enterDetail);

        return page;

        void SetupRadio(RadioButton radio, string text, int top)
        {
            radio.Text = text;
            radio.Font = _fonts.Ui;
            radio.ForeColor = Palette.Muted;
            radio.BackColor = Color.Transparent;
            radio.AutoSize = false;
            radio.SetBounds(Px(24), top, Px(300), Px(20));
            radio.UseMnemonic = false;
        }
    }

    private Label FieldLabel(string text, int top) => new()
    {
        Text = text,
        Font = _fonts.Ui,
        ForeColor = Palette.Muted,
        BackColor = Color.Transparent,
        AutoSize = false,
        Bounds = new Rectangle(Px(14), top, Px(100), Px(20)),
        UseMnemonic = false,
    };

    private Label WrappedLabel(string text) => new()
    {
        Text = text,
        Font = _fonts.Ui,
        ForeColor = Palette.Muted,
        BackColor = Color.Transparent,
        AutoSize = false,
        Size = new Size(Px(520), Px(54)),
        UseMnemonic = false,
    };

    private async Task StartOfferAsync()
    {
        if (_session is not null)
        {
            return;
        }

        if (_offerFolder.SelectedItem is not FolderChoice choice)
        {
            _offerDetail.Text = "Add a folder first: pairing offers one folder.";
            return;
        }

        var (session, problem) = _host.BeginPairOffer(choice.Path);
        if (session is null)
        {
            _offerDetail.Text = problem ?? "The offer could not be started.";
            return;
        }

        _session = session;
        _startOffer.Enabled = false;
        _offerFolder.Enabled = false;
        _code.Text = session.Code;

        var lines = new List<string>
        {
            "On the other machine, enter the code with whichever of these addresses it can",
            "reach. Those with a gateway come first.",
            string.Empty,
        };
        if (session.Addresses.Count == 0)
        {
            lines.Add("  (no usable network address was found on this machine)");
        }
        else
        {
            lines.AddRange(session.Addresses.Select(address => string.Create(
                CultureInfo.InvariantCulture, $"  {address}:{session.Port}")));
        }
        lines.Add(string.Empty);
        lines.Add("The code never crosses the network: someone recording the traffic learns");
        lines.Add("nothing they could test it against. What that cannot protect against is");
        lines.Add("someone who HEARS it. Whoever uses it first, within ten minutes, pairs");
        lines.Add("instead of your machine and gets the key to every document in this folder.");
        lines.Add("Say it only to the person at the other machine.");
        lines.Add(string.Empty);
        lines.Add("Waiting... it stops working in ten minutes, after one machine uses it, or");
        lines.Add("after five wrong answers. Closing this window stops the offer.");
        _offerDetail.Text = string.Join(Environment.NewLine, lines);

        try
        {
            var (outcome, deviceId, name) = await session.WaitAsync().ConfigureAwait(true);
            ReportOffer(outcome, deviceId, name);
        }
        catch (ObjectDisposedException)
        {
            // The dialog closed and disposed the session mid-wait.
        }
    }

    private void ReportOffer(PairingClosure outcome, string? deviceId, string? name)
    {
        if (IsDisposed)
        {
            return;
        }

        switch (outcome)
        {
            case PairingClosure.Used when deviceId is not null:
                _pairedDevice = deviceId;
                _pairedName = name ?? "the new machine";
                _offerDetail.Text =
                    $"Paired with '{_pairedName}'. It records this machine as its peer as it " +
                    "finishes joining; from then on the daemons sync it on their own." +
                    Environment.NewLine + Environment.NewLine +
                    "One question, and pairing is done:";
                _questionText.Text = $"Whose machine is '{_pairedName}'?";
                _question.Visible = true;
                _record.Visible = true;
                break;

            case PairingClosure.Used:
                _offerDetail.Text =
                    "The code was accepted, but the exchange failed before the other machine " +
                    "received the folder. Close this and start a new offer.";
                break;

            case PairingClosure.TooManyAttempts:
                _offerDetail.Text = "Five failed attempts - the code was burnt. Close this and start a new offer.";
                break;

            default:
                _offerDetail.Text = "The code expired. Close this and start a new offer.";
                break;
        }
    }

    private void RecordOwner()
    {
        if (_pairedDevice is not { } device)
        {
            return;
        }

        var owner = _mine.Checked ? MachineOwner.Mine
            : _someoneElse.Checked ? MachineOwner.SomeoneElse
            : MachineOwner.Unanswered;

        _offerDetail.Text = _host.RecordPairedOwner(device, _pairedName ?? device, owner);
        _record.Visible = false;
    }

    private void PickFolder()
    {
        using var picker = new FolderBrowserDialog
        {
            Description = "Pick an empty folder to hold the copy.",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };

        if (picker.ShowDialog(this) == DialogResult.OK)
        {
            _enterFolder.Text = picker.SelectedPath;
        }
    }

    private async Task JoinAsync()
    {
        if (_joining)
        {
            return;
        }

        var address = _enterAddress.Text.Trim();
        var code = _enterCode.Text.Trim();
        var folder = _enterFolder.Text.Trim();

        if (address.Length == 0 || code.Length == 0 || folder.Length == 0)
        {
            _enterDetail.Text = "The address, the code and an empty folder are all needed.";
            return;
        }

        var host = address;
        var port = _host.ListenPort;
        var colon = address.LastIndexOf(':');
        if (colon > 0)
        {
            if (!int.TryParse(address[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port)
                || port is < 1 or > 65535)
            {
                _enterDetail.Text = "The address's port is not a port. Use host, or host:port.";
                return;
            }

            host = address[..colon];
        }

        _joining = true;
        _join.Enabled = false;
        _enterDetail.Text = "Joining... nothing is written until the exchange finishes, so a " +
                            "refusal leaves the folder exactly as it was.";

        var owner = _enterMine.Checked ? MachineOwner.Mine : MachineOwner.SomeoneElse;
        var result = await _host.PairEnterAsync(host, port, code, folder, owner).ConfigureAwait(true);

        _enterDetail.Text = result.Message;
        _joining = false;
        _join.Enabled = !result.Succeeded;
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        base.OnFormClosed(e);

        if (_session is { } session)
        {
            _session = null;
            _ = session.DisposeAsync().AsTask();
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _tabs.Dispose();
            _offerFolder.Dispose();
            _startOffer.Dispose();
            _code.Dispose();
            _codeFont.Dispose();
            _offerDetail.Dispose();
            _questionText.Dispose();
            _mine.Dispose();
            _someoneElse.Dispose();
            _later.Dispose();
            _record.Dispose();
            _question.Dispose();
            _enterAddress.Dispose();
            _enterCode.Dispose();
            _enterFolder.Dispose();
            _pickFolder.Dispose();
            _enterMine.Dispose();
            _enterSomeoneElse.Dispose();
            _join.Dispose();
            _enterDetail.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary>A folder in the offer list: shown by name, offered by path.</summary>
    private sealed record FolderChoice(string Path, string Name)
    {
        public override string ToString() => Name;
    }
}
