using System.Drawing;
using System.Globalization;
using System.Text;

namespace SippBucket.Tray;

/// <summary>
/// One folder up close: its history, its encryption, and the conflicts it kept both
/// versions of. Opened by double-clicking the folder's row.
/// </summary>
/// <remarks>
/// A view, like everything in the window: it reads through <see cref="IMainWindowHost"/>
/// and changes nothing. The history is the same walk <c>sip log</c> prints, with the same
/// honesty about Simple mode showing only what is kept.
/// </remarks>
internal sealed class FolderDetailDialog : Form
{
    private readonly IMainWindowHost _host;
    private readonly string _folder;

    private readonly Label _facts = new();
    private readonly TextBox _history = new();

    public FolderDetailDialog(IMainWindowHost host, string folder, WindowFonts fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        ArgumentNullException.ThrowIfNull(fonts);

        _host = host;
        _folder = folder;

        Text = "Folder detail";
        Font = fonts.Ui;
        BackColor = Palette.Ground;
        ForeColor = Palette.Ink;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(Px(640), Px(480));
        MinimumSize = new Size(Px(480), Px(360));

        _facts.Font = fonts.Ui;
        _facts.ForeColor = Palette.Muted;
        _facts.BackColor = Palette.Ground;
        _facts.AutoSize = false;
        _facts.Dock = DockStyle.Top;
        _facts.Height = Px(118);
        _facts.Padding = new Padding(Px(14), Px(10), Px(14), 0);
        _facts.UseMnemonic = false;

        _history.Multiline = true;
        _history.ReadOnly = true;
        _history.BorderStyle = BorderStyle.None;
        _history.BackColor = Palette.Band;
        _history.ForeColor = Palette.Muted;
        _history.Font = fonts.Mono;
        _history.ScrollBars = ScrollBars.Vertical;
        _history.WordWrap = false;
        _history.TabStop = false;
        _history.Dock = DockStyle.Fill;

        Controls.Add(_history);
        Controls.Add(_facts);

        Shown += async (_, _) => await LoadAsync().ConfigureAwait(true);
    }

    private int Px(int logical) => LogicalToDeviceUnits(logical);

    private async Task LoadAsync()
    {
        var facts = _host.FolderFacts(_folder);
        if (facts is null)
        {
            _facts.Text = "This folder is not running here.";
            return;
        }

        Text = $"{facts.Name} — history, encryption and conflicts";

        var lines = new StringBuilder();
        lines.AppendLine(CultureInfo.InvariantCulture, $"{facts.Name}  ·  {facts.Mode} mode  ·  {facts.PeerCount} peer(s)");
        lines.AppendLine(CultureInfo.InvariantCulture, $"Repository {facts.RepositoryId}");
        lines.AppendLine(
            "Every block and snapshot is encrypted at rest with the folder's key; only paired " +
            "machines hold it.");
        lines.AppendLine(facts.HasPassphrase
            ? facts.UnlockedForSession
                ? "Passphrase set on this machine's copy · unlocked for this session."
                : "Locked on this machine · contents unreadable until unlocked."
            : "No passphrase on this machine's copy ('sip lock' sets one; it is per machine).");
        lines.Append(facts.Conflicts.Count switch
        {
            0 => "No recent conflicts: nothing has needed keeping under both versions.",
            1 => $"1 file kept under both versions: {facts.Conflicts[0]}",
            _ => string.Create(
                CultureInfo.InvariantCulture,
                $"{facts.Conflicts.Count} files kept under both versions; the newest is {facts.Conflicts[0]}"),
        });
        _facts.Text = lines.ToString();

        _history.Text = "Reading history...";
        var history = await _host.FolderHistoryAsync(_folder, 40).ConfigureAwait(true);
        if (IsDisposed)
        {
            return;
        }

        if (history.Count == 0)
        {
            _history.Text = "No snapshots yet, or the history could not be read; the activity log says which.";
            return;
        }

        var text = new StringBuilder();
        text.AppendLine("  snapshot      when              who         files  size");
        foreach (var entry in history)
        {
            text.AppendLine(string.Create(
                CultureInfo.InvariantCulture,
                $"  {entry.ShortId,-12}  {entry.WhenLocal,-16}  {Fit(entry.Who, 10),-10}  {entry.Files,5}  {entry.Size,-9} {Fit(entry.Message, 60)}"));
        }

        text.AppendLine();
        text.AppendLine("  'sip show <snapshot>' has any one in full; 'sip restore <snapshot>' goes back.");
        _history.Text = text.ToString();
    }

    private static string Fit(string text, int width) =>
        text.Length <= width ? text : text[..(width - 1)] + "…";

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _facts.Dispose();
            _history.Dispose();
        }

        base.Dispose(disposing);
    }
}
