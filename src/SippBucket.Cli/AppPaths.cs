using SippBucket.Core.Platform;

namespace SippBucket.Cli;

/// <summary>
/// Where SippBucket keeps machine-wide state, as opposed to per-repository state.
/// </summary>
internal static class AppPaths
{
    /// <summary>
    /// The per-user data directory. Deliberately under ApplicationData rather than a
    /// protected folder such as Documents, where a background daemon writing files is the
    /// profile that folder-protection features act on.
    /// </summary>
    /// <remarks>
    /// An earlier version of this comment named Windows Controlled Folder Access as the
    /// reason. That was measured and is wrong on both of this project's target machines:
    /// Norton 360 has displaced Defender into passive mode on each of them
    /// (<c>AMRunningMode = Not running</c>), so CFA is not running and its state cannot
    /// even be read — <c>Get-MpPreference</c> fails with 0x800106ba. The guard that has
    /// actually fired on Documents here is Norton's own Data Protector.
    ///
    /// The choice of ApplicationData is unchanged and still correct; only the stated reason
    /// was wrong. Worth keeping the distinction, because the two behave differently: CFA
    /// has a scriptable allow-list, Norton's has no queryable policy surface at all, so
    /// code cannot detect in advance whether a destination folder is guarded. See P-04 and
    /// P-08 in DEBT.md.
    /// </remarks>
    public static string DataDirectory => UserDataDirectory.Resolve();

    /// <summary>The Ed25519 private key identifying this machine.</summary>
    public static string DeviceKeyFile => Path.Combine(DataDirectory, "device.key");
}
