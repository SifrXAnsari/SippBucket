using System.Diagnostics;

namespace SippBucket.Core.Platform;

/// <summary>
/// Recognises the folder-protection features that block writes into Documents-shaped
/// folders — Norton's Data Protector, Windows Defender's Controlled folder access — so a
/// refused write can be explained instead of shrugged at (P-04).
/// </summary>
/// <remarks>
/// <para>
/// <b>What these features do.</b> They watch the profile's own folders — Documents,
/// Desktop, Pictures — and refuse writes from programs they do not trust, as
/// <c>ERROR_ACCESS_DENIED</c>. To SippBucket that is indistinguishable from a permissions
/// problem: a save cannot write blocks into <c>.sip</c>, an apply cannot move a staged
/// file into place, and both fail with a message that sends the person to look at ACLs
/// that are fine. The one thing this class adds is the sentence that says what is actually
/// happening and what to do about it.
/// </para>
/// <para>
/// <b>Without getting in its way.</b> Nothing here fights the protection: SippBucket never
/// retries into a denial beyond the ordinary bounded retry, never elevates, never touches
/// the antivirus's own state, and the quarantine stays unencrypted precisely so the
/// antivirus can read every byte of it. Detection only reads: the process list for the
/// products' own names, and one registry value for Defender's switch. If the person wants
/// SippBucket allowed, they allow it in the protection's own settings, where that decision
/// belongs.
/// </para>
/// <para>
/// Detection is a heuristic and says so: a product list is never complete, and a missing
/// detection only costs the extra sentence, never a behaviour.
/// </para>
/// </remarks>
public static class AntivirusShield
{
    /// <summary>Process names that mean a product with folder protection is running.</summary>
    /// <remarks>
    /// Norton's are the ones this project can test on (the laptop runs Norton 360, whose
    /// Data Protector is exactly this feature). Compared without extension, ordinal,
    /// ignoring case.
    /// </remarks>
    private static readonly (string Process, string Product)[] KnownProducts =
    [
        ("NortonSecurity", "Norton"),
        ("nsWscSvc", "Norton"),
        ("NortonUI", "Norton"),
        ("ns", "Norton"),
        ("ccSvcHst", "Norton"),
    ];

    /// <summary>
    /// The folder-protection product running, or null when none is recognised. Never throws.
    /// </summary>
    /// <returns>"Norton", "Windows Defender's Controlled folder access", or null.</returns>
    public static string? DetectedProduct()
    {
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    foreach (var (name, product) in KnownProducts)
                    {
                        if (string.Equals(process.ProcessName, name, StringComparison.OrdinalIgnoreCase))
                        {
                            return product;
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // The process list is a nicety; a refusal to read it costs one sentence.
        }

        return ControlledFolderAccessOn() ? "Windows Defender's Controlled folder access" : null;
    }

    /// <summary>Whether Defender's Controlled folder access is switched on. Never throws.</summary>
    private static bool ControlledFolderAccessOn()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            var value = Microsoft.Win32.Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
                "EnableControlledFolderAccess",
                null);
            return value is int enabled && enabled == 1;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether a path lies in the profile folders these products watch: Documents, Desktop,
    /// Pictures, Videos, Music.
    /// </summary>
    /// <param name="path">The folder asked about.</param>
    public static bool IsProtectedShape(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException)
        {
            return false;
        }

        foreach (var special in new[]
                 {
                     Environment.SpecialFolder.MyDocuments,
                     Environment.SpecialFolder.Desktop,
                     Environment.SpecialFolder.MyPictures,
                     Environment.SpecialFolder.MyVideos,
                     Environment.SpecialFolder.MyMusic,
                 })
        {
            var root = Environment.GetFolderPath(special);
            if (root.Length > 0 &&
                (full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(full, root, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The sentence worth adding to an access-denied failure in a folder, or null when
    /// nothing recognised makes it likely.
    /// </summary>
    /// <param name="path">The folder the write failed in.</param>
    /// <returns>The advice, or null.</returns>
    public static string? Advice(string? path)
    {
        if (!IsProtectedShape(path) || DetectedProduct() is not { } product)
        {
            return null;
        }

        return product.StartsWith("Norton", StringComparison.Ordinal)
            ? "Norton is running and this folder is the kind its Data Protector watches. If " +
              "Norton is blocking SippBucket here, allow it: Norton > Settings > Antivirus > " +
              "Scans and Risks > Exclusions/Low Risks, add SippBucket.exe (or the folder) - " +
              "or keep the synced folder outside Documents, Desktop and Pictures. Nothing " +
              "was lost; the documents are where you put them."
            : $"{product} is on, and this folder is the kind it watches. If it is blocking " +
              "SippBucket here, allow the app: Windows Security > Virus & threat protection > " +
              "Ransomware protection > Allow an app through Controlled folder access - or " +
              "keep the synced folder outside Documents, Desktop and Pictures. Nothing was " +
              "lost; the documents are where you put them.";
    }

    /// <summary>An access-denied message with the folder-protection sentence when it applies.</summary>
    /// <param name="message">The failure as thrown.</param>
    /// <param name="path">The folder the write failed in.</param>
    public static string ExplainDenied(string message, string? path) =>
        Advice(path) is { } advice ? $"{message}{Environment.NewLine}{advice}" : message;
}
