using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using SippBucket.Core.Sync;

namespace SippBucket.Tray;

/// <summary>
/// Draws the SIP UP! mark — a padlock that is also a bucket — as a tray icon that carries
/// state.
/// </summary>
/// <remarks>
/// <para>
/// The identity system's central claim is that the mark is a <em>function</em> of state
/// rather than a picture with variants. This is that function, in the only place it
/// actually matters: the 16-pixel square that is the only part of this product most people
/// will ever look at.
/// </para>
/// <para>
/// Generated at runtime rather than shipped as a <c>.ico</c>, for two reasons that are not
/// convenience. The level is continuous — 812 of 1,284 blocks is a fill of 0.632, not the
/// nearest of five sprites — and a binary asset in the repository is a thing that drifts
/// from the vector source with nobody noticing. Here the source <em>is</em> the drawing.
/// </para>
/// <para>
/// Three shapes survive at 16 px: the shackle, the vessel, and the liquid. Everything the
/// icon says, it says with those. Colour is a second channel and never the only one — the
/// failure states drain <em>and</em> grey, because a hue is gone at one bit and a silhouette
/// is not.
/// </para>
/// </remarks>
internal static class MarkIcon
{
    private static readonly Color Ink = Color.FromArgb(0x1B, 0x1A, 0x17);
    private static readonly Color Liquid = Color.FromArgb(0xB4, 0x76, 0x2A);
    private static readonly Color InFlight = Color.FromArgb(0xD9, 0xA5, 0x5E);
    private static readonly Color Alert = Color.FromArgb(0xA9, 0x3F, 0x25);
    private static readonly Color DormantInk = Color.FromArgb(0xA0, 0x9A, 0x8E);
    private static readonly Color DormantLiquid = Color.FromArgb(0xCF, 0xC8, 0xB8);
    private static readonly Color Paper = Color.FromArgb(0xFF, 0xFD, 0xF9);

    /// <summary>
    /// The mark as identity rather than status: full, ochre and closed, whatever the folders
    /// are doing.
    /// </summary>
    /// <remarks>
    /// For the window's own icon. A status there would be a second, coarser claim competing
    /// with the per-folder rows, which can qualify theirs with a time and a consequence. The
    /// tray icon is the surface that has to summarise, because it is the only thing on
    /// screen when the window is closed.
    /// </remarks>
    public static MarkState Identity => new(1.0, Ink, Liquid, true);

    /// <summary>
    /// The mark for a folder that is listed but has no service running: drained and grey.
    /// </summary>
    /// <remarks>
    /// The same silhouette as <see cref="SyncFreshness.NotChecking"/>, because to the person
    /// reading it the two mean the same thing - nothing is keeping this folder in sync.
    /// </remarks>
    public static MarkState NotWatched => new(0.18, DormantInk, DormantLiquid, false);

    /// <summary>How the mark should be drawn for a folder's status.</summary>
    /// <param name="status">The status to depict.</param>
    /// <returns>The level, the colours, and whether the shackle is closed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="status"/> was null.</exception>
    public static MarkState StateFor(FolderStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);

        // Ordered exactly as FolderStatus.Headline orders itself. The icon and the sentence
        // must never disagree about which fact won, so they read the same list.
        if (status.ServerFault is not null)
        {
            return new MarkState(0.18, DormantInk, DormantLiquid, status.HasPassphrase);
        }

        if (status.Bucket is { IsFull: true })
        {
            // Brimming, in alert clay. The mark IS a bucket, so drawing a full one as empty
            // would be the only actually false picture available - and it still changes
            // silhouette rather than only hue, so it survives one bit.
            return new MarkState(1.0, Alert, Alert, status.HasPassphrase);
        }

        if (status.Freshness == SyncFreshness.NotChecking)
        {
            return new MarkState(0.18, DormantInk, DormantLiquid, status.HasPassphrase);
        }

        if (status.Transfer is { } transfer)
        {
            return new MarkState(
                Math.Clamp(transfer.Fraction, 0.05, 0.95), Ink, InFlight, status.HasPassphrase);
        }

        if (status.Freshness is SyncFreshness.NeverSynced or SyncFreshness.NothingToSyncWith)
        {
            return new MarkState(0.0, Ink, Liquid, status.HasPassphrase);
        }

        return status.Freshness == SyncFreshness.Ageing
            ? new MarkState(0.55, Ink, DormantLiquid, status.HasPassphrase)
            : new MarkState(1.0, Ink, Liquid, status.HasPassphrase);
    }

    /// <summary>Renders the mark as an icon.</summary>
    /// <param name="state">What to draw.</param>
    /// <param name="size">Edge length in pixels. 16 is the tray.</param>
    /// <returns>An icon the caller owns and must dispose.</returns>
    public static Icon Render(MarkState state, int size = 16)
    {
        using var bitmap = RenderBitmap(state, size);

        // Icon.FromHandle does not own the HICON, so it is destroyed explicitly rather than
        // left to a finalizer that does not exist. Cloning first gives the caller an icon
        // whose lifetime is its own.
        var handle = bitmap.GetHicon();
        try
        {
            using var borrowed = Icon.FromHandle(handle);
            return (Icon)borrowed.Clone();
        }
        finally
        {
            NativeMethods.DestroyIcon(handle);
        }
    }

    /// <summary>Renders the mark as a 32-bit ARGB bitmap with a transparent ground.</summary>
    /// <param name="state">What to draw.</param>
    /// <param name="size">Edge length in pixels, 8 or more.</param>
    /// <returns>A bitmap the caller owns and must dispose.</returns>
    /// <remarks>
    /// The one drawing, for every surface: the tray icon above, and the installer's icon,
    /// which the MSI build writes from this method rather than from a picture kept in the
    /// repository (see <c>sample/tools/SippBucket.MarkExport</c>).
    /// </remarks>
    public static Bitmap RenderBitmap(MarkState state, int size)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(size, 8);

        Bitmap? bitmap = null;
        try
        {
            bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bitmap))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                Draw(g, state, size);
            }

            var drawn = bitmap;
            bitmap = null;
            return drawn;
        }
        finally
        {
            bitmap?.Dispose();
        }
    }

    private static void Draw(Graphics g, MarkState state, int size)
    {
        // The 64-unit grid the vector art is drawn on, scaled to whatever is asked for.
        var u = size / 64f;

        // Stroke weight is redrawn per size rather than scaled, because a scaled 4.6-unit
        // stroke is under one pixel at 16 and disappears. This is the whole reason the
        // design boards draw the mark at each size instead of resizing one drawing.
        var stroke = size <= 16 ? 1.6f
            : size <= 24 ? 2.2f
            : size <= 32 ? 2.8f
            : 4.6f * u;

        using var inkPen = new Pen(state.Ink, stroke)
        {
            StartCap = LineCap.Round,
            EndCap = LineCap.Round,
            LineJoin = LineJoin.Round,
        };

        using var liquidBrush = new SolidBrush(state.Liquid);
        using var paperBrush = new SolidBrush(Paper);

        // The shackle: a true circle of radius 10 centred on the vertical axis, never
        // eyeballed. Closed when locked; swung clear and tilted when there is no passphrase.
        if (state.Closed)
        {
            g.DrawArc(inkPen, 22 * u, 8 * u, 20 * u, 20 * u, 180, 180);
            g.DrawLine(inkPen, 22 * u, 18 * u, 22 * u, 30 * u);
            g.DrawLine(inkPen, 42 * u, 18 * u, 42 * u, 30 * u);
        }
        else
        {
            // Tilted 55 degrees and lifted clear of the rim, so it reads as a straw laid
            // across the vessel rather than a shackle that merely failed to close.
            var saved = g.Save();
            g.TranslateTransform(43 * u, 5 * u);
            g.RotateTransform(55, MatrixOrder.Prepend);
            g.DrawArc(inkPen, 0, 0, 16 * u, 16 * u, 180, 180);
            g.DrawLine(inkPen, 0, 8 * u, 0, 20 * u);
            g.DrawLine(inkPen, 16 * u, 8 * u, 16 * u, 20 * u);
            g.Restore(saved);
        }

        // The vessel: 42 wide at the rim, 30 at the base. A rectangle is a padlock; the
        // taper is what makes it a bucket, and that one difference is the whole identity.
        using var vessel = new GraphicsPath();
        vessel.AddLine(11 * u, 29 * u, 53 * u, 29 * u);
        vessel.AddLine(53 * u, 29 * u, 47.5f * u, 55.5f * u);
        vessel.AddLine(47.5f * u, 55.5f * u, 43.6f * u, 59 * u);
        vessel.AddLine(43.6f * u, 59 * u, 20.4f * u, 59 * u);
        vessel.AddLine(20.4f * u, 59 * u, 16.5f * u, 55.5f * u);
        vessel.CloseFigure();

        g.FillPath(paperBrush, vessel);

        if (state.Level > 0.02)
        {
            // The surface narrows as the level drops, because the walls converge. A
            // rectangle would float off them at the bottom and overhang them at the top.
            var surfaceY = Math.Max(29f, Math.Min(55.5f, 59f - ((float)state.Level * 30f)));
            var k = (surfaceY - 29f) / 26.5f;
            var left = 11f + (5.5f * k);
            var right = 53f - (5.5f * k);

            using var liquid = new GraphicsPath();
            liquid.AddLine(left * u, surfaceY * u, right * u, surfaceY * u);
            liquid.AddLine(right * u, surfaceY * u, 47.5f * u, 55.5f * u);
            liquid.AddLine(47.5f * u, 55.5f * u, 43.6f * u, 59 * u);
            liquid.AddLine(43.6f * u, 59 * u, 20.4f * u, 59 * u);
            liquid.AddLine(20.4f * u, 59 * u, 16.5f * u, 55.5f * u);
            liquid.CloseFigure();

            g.FillPath(liquidBrush, liquid);
        }

        g.DrawPath(inkPen, vessel);

        // The left leg keeps going past the rim, into the liquid. That is the straw, and it
        // is the only part of the drawing doing a second job. Dropped below 16 px, where a
        // fourth shape stops being legible and starts being noise.
        if (state.Closed && size >= 16)
        {
            g.DrawLine(inkPen, 22 * u, 30 * u, 22 * u, 45 * u);
        }
    }

    private static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        [System.Runtime.InteropServices.DefaultDllImportSearchPaths(
            System.Runtime.InteropServices.DllImportSearchPath.System32)]
        [return: System.Runtime.InteropServices.MarshalAs(
            System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool DestroyIcon(IntPtr handle);
    }
}

/// <summary>What the mark looks like for one status.</summary>
/// <param name="Level">Liquid level, 0 to 1.</param>
/// <param name="Ink">Stroke colour.</param>
/// <param name="Liquid">Fill colour.</param>
/// <param name="Closed">
/// Whether the shackle is closed. Closed means a passphrase is set; open means the honest
/// default, which is that most installs have none.
/// </param>
internal readonly record struct MarkState(double Level, Color Ink, Color Liquid, bool Closed);
