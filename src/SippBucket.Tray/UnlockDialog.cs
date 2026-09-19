using System.Drawing;
using System.Windows.Forms;

namespace SippBucket.Tray;

/// <summary>
/// Asks for a folder's passphrase, and says plainly what unlocking it does and does not do.
/// </summary>
/// <remarks>
/// <para>
/// The honesty here is the feature, not decoration around it. A padlock reads as "this is
/// protected" and nobody reads it as "protected on this machine only, while the machine is
/// switched off, and every machine you pair with has the key anyway". All three of those are
/// true, and a screen that lets the first impression stand is worse than no screen — it
/// manufactures confidence the design cannot support. (The third used to read "anyone
/// holding an invite", when invites carried the key in clear; they no longer do, D-49.)
/// </para>
/// <para>
/// So the boundary text is not a tooltip or a help link. It is on the dialog, unavoidable,
/// in the same size as everything else.
/// </para>
/// </remarks>
internal sealed class UnlockDialog : Form
{
    private readonly TextBox _passphrase;
    private readonly Label _error;

    /// <summary>Creates the dialog for one folder.</summary>
    /// <param name="folderName">The folder being unlocked.</param>
    /// <remarks>
    /// CA2000 cannot see WinForms' ownership rule: a control added to
    /// <see cref="Control.Controls"/> is owned by its parent and disposed with it. Disposing
    /// them here would destroy the dialog before it is shown. The two fields are disposed
    /// explicitly in <see cref="Dispose(bool)"/> so the analyser can verify the ones it can
    /// actually follow.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "Controls are owned by the form once added to Controls and are " +
                        "disposed with it.")]
    public UnlockDialog(string folderName)
    {
        Text = "SippBucket";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(440, 268);
        Font = new Font("Segoe UI", 9f);
        BackColor = Color.FromArgb(0xF4, 0xF1, 0xEA);

        var heading = new Label
        {
            Text = $"Unlock “{folderName}”",
            Font = new Font("Segoe UI", 12f, FontStyle.Bold),
            Location = new Point(18, 16),
            Size = new Size(404, 26),
            ForeColor = Color.FromArgb(0x1B, 0x1A, 0x17),
        };

        var prompt = new Label
        {
            Text = "This copy is locked on this machine.",
            Location = new Point(18, 44),
            Size = new Size(404, 20),
            ForeColor = Color.FromArgb(0x5D, 0x58, 0x4E),
        };

        _passphrase = new TextBox
        {
            UseSystemPasswordChar = true,
            Location = new Point(18, 70),
            Size = new Size(404, 24),
        };

        _error = new Label
        {
            Location = new Point(18, 98),
            Size = new Size(404, 18),
            ForeColor = Color.FromArgb(0xA9, 0x3F, 0x25),
            Text = string.Empty,
        };

        // The boundary. Worded as what an attacker can and cannot do, because "keep this
        // secret" is advice nobody reads and "your filenames are legible to anyone with your
        // disk" is a fact somebody acts on.
        var covers = new Label
        {
            Text = "What this covers\n"
                 + "•  Another account on this PC reading the folder's data\n"
                 + "•  The folder being copied to a backup, USB stick or cloud drive\n"
                 + "\n"
                 + "What it does not\n"
                 + "•  Other machines — each one is locked separately\n"
                 + "•  Machines you pair with, which are sent the key\n"
                 + "•  This PC while you are logged in and it is unlocked",
            Location = new Point(18, 120),
            Size = new Size(404, 108),
            ForeColor = Color.FromArgb(0x5D, 0x58, 0x4E),
        };

        var ok = new Button
        {
            Text = "Unlock",
            DialogResult = DialogResult.OK,
            Location = new Point(266, 234),
            Size = new Size(76, 26),
        };

        var cancel = new Button
        {
            Text = "Not now",
            DialogResult = DialogResult.Cancel,
            Location = new Point(348, 234),
            Size = new Size(74, 26),
        };

        Controls.AddRange([heading, prompt, _passphrase, _error, covers, ok, cancel]);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    /// <summary>What was typed.</summary>
    public string Passphrase => _passphrase.Text;

    /// <summary>Shows that the last attempt was wrong and lets the user try again.</summary>
    /// <param name="message">What to say.</param>
    public void ShowError(string message)
    {
        _error.Text = message;
        _passphrase.SelectAll();
        _passphrase.Focus();
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Clear the box before it goes. The passphrase is a string and therefore not
            // reliably erasable from managed memory at all - this removes the copy that
            // would otherwise sit in a live control - so it is a tidy-up, not a guarantee,
            // and nothing should be documented as though it were one.
            _passphrase.Clear();
            _passphrase.Dispose();
            _error.Dispose();
        }

        base.Dispose(disposing);
    }
}
