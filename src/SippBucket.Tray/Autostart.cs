using System.Diagnostics;
using System.Globalization;
using Microsoft.Win32;

namespace SippBucket.Tray;

/// <summary>
/// Makes the tray come back after a reboot.
/// </summary>
/// <remarks>
/// <para>
/// The second stated priority of this product is "set it and forget it", and a daemon that
/// does not survive a restart cannot be forgotten — it has to be remembered, daily, which is
/// the opposite. This is the smallest thing that closes that gap.
/// </para>
/// <para>
/// <strong>Per user, under <c>HKEY_CURRENT_USER</c>, and deliberately not a service.</strong>
/// The installer asks for administrator rights because it writes to Program Files; the
/// daemon does not have them and must not. It syncs <em>this person's</em> documents, needs
/// exactly their filesystem rights, and would gain nothing from running as SYSTEM except a
/// larger blast radius and a folder-protection prompt nobody can answer because nobody is
/// logged in to see it.
/// </para>
/// <para>
/// A service would also be the wrong shape for the tray: there is no session to draw an
/// icon in, and the unlock prompt for a locked folder has nowhere to appear.
/// </para>
/// <para>
/// <strong>Who registers it.</strong> <c>Install.ps1</c> writes the entry itself, into the
/// hive of the person who ran it. The MSI cannot: it installs per machine, it must not write
/// the installing administrator's <c>HKEY_CURRENT_USER</c> (that is somebody else's startup
/// list on a shared machine), and it does not know who will use the program. So the MSI
/// records where it installed, and the installed copy registers itself the first time each
/// person starts it — see <see cref="AdoptOnFirstStart()"/>. Every change, automatic or
/// from the menu, records the decision, so a person who unticks it stays unticked.
/// </para>
/// <para>
/// <strong>The script install before 1.1 recorded nothing (D-67).</strong> It registered the
/// Run value, and the tray's untick of that time deleted the value and wrote no decision. A
/// person who had switched it off is left with no Run value and no recorded choice, which the
/// MSI's first start used to read as "undecided" and switch on — against a choice they had
/// made. The MSI now notes when it was installed over a script install, and the first start
/// reads "script install was here, no Run value, no recorded choice" as a recorded off.
/// </para>
/// </remarks>
internal static class Autostart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "SippBucket";

    /// <summary>Per-user settings: the recorded decision lives here.</summary>
    internal const string SettingsKey = @"Software\SippBucket";

    /// <summary>
    /// A DWORD: 1 when this person last chose to start with Windows, 0 when they chose not
    /// to. Absent means nobody has decided yet.
    /// </summary>
    internal const string DecisionValue = "StartWithWindows";

    /// <summary>
    /// Written by the MSI under <c>HKEY_LOCAL_MACHINE</c>, 64-bit view: the directory it
    /// installed into. Removed with the product.
    /// </summary>
    internal const string InstallKey = @"Software\SippBucket";

    /// <summary>The value under <see cref="InstallKey"/> naming the install directory.</summary>
    internal const string InstallDirectoryValue = "InstallDir";

    /// <summary>
    /// A DWORD under <see cref="InstallKey"/>, 1 when the MSI was installed over the older
    /// script install. Removed with the product.
    /// </summary>
    /// <remarks>
    /// Only the installer can know this. What the script leaves behind that outlives an untick
    /// is machine-wide - its executable in Program Files, the PATH entry, the all-users Start
    /// Menu shortcut - and the MSI installs over every one of them. So the package looks
    /// before it installs, and writes this (<c>ScriptInstallRecord</c> in
    /// <c>install\msi\SippBucket.wxs</c>). <c>Test-Msi.ps1</c> checks that the package writes
    /// the name spelled here.
    /// </remarks>
    internal const string ReplacedScriptInstallValue = "ReplacedScriptInstall";

    /// <summary>
    /// Passed by the startup entry so a sign-in starts the daemon without opening its window.
    /// </summary>
    /// <remarks>
    /// Opening SippBucket shows the window; signing in does not. A window at every boot would
    /// turn the second stated priority, set it and forget it, into a daily dismissal. The
    /// installer writes the same argument, so the two can never disagree about what login
    /// does.
    /// </remarks>
    public const string BackgroundArgument = "--background";

    /// <summary>Whether this executable is registered to start with Windows.</summary>
    /// <returns>True when the Run entry points at this exact executable.</returns>
    /// <remarks>
    /// Compares the path rather than merely checking the value exists, so that a stale entry
    /// left by a copy that has since been deleted or moved reads as "not registered" and the
    /// user is offered the switch rather than shown a tick for something that does not run.
    /// </remarks>
    public static bool IsEnabled() => IsEnabled(Registry.CurrentUser, ExecutablePath());

    /// <summary>Whether <paramref name="executable"/> is registered under a user hive.</summary>
    /// <param name="user">The hive: <see cref="Registry.CurrentUser"/>, or a test's scratch key.</param>
    /// <param name="executable">The executable the entry should point at.</param>
    /// <returns>True when the Run entry points at exactly that executable.</returns>
    internal static bool IsEnabled(RegistryKey user, string executable)
    {
        ArgumentNullException.ThrowIfNull(user);

        try
        {
            using var key = user.OpenSubKey(RunKey, writable: false);
            if (key?.GetValue(ValueName) is not string stored)
            {
                return false;
            }

            return string.Equals(
                ExecutableIn(stored),
                executable,
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Whether a user hive has a SippBucket startup entry at all, for any copy.</summary>
    /// <param name="user">The hive: <see cref="Registry.CurrentUser"/>, or a test's scratch key.</param>
    /// <returns>True when the Run key holds a value by this program's name.</returns>
    /// <remarks>
    /// Not <see cref="IsEnabled(RegistryKey, string)"/>: an entry that names another copy -
    /// the first script install's <c>SippBucket.Tray.exe</c>, say - still says this person
    /// had SippBucket starting with Windows. Only no entry at all can mean they switched it
    /// off. An unreadable Run key reads as no entry, the direction that never switches
    /// autostart on.
    /// </remarks>
    internal static bool HasRunValue(RegistryKey user)
    {
        ArgumentNullException.ThrowIfNull(user);

        try
        {
            using var key = user.OpenSubKey(RunKey, writable: false);
            return key?.GetValue(ValueName) is not null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Turns starting with Windows on or off, and records that it was chosen.</summary>
    /// <param name="enabled">Whether to start automatically.</param>
    /// <returns>Null on success, or why it could not be changed.</returns>
    /// <remarks>
    /// Returns the failure rather than throwing, because the caller is a menu item and the
    /// correct response to a locked-down registry is to tell the user, not to take down the
    /// tray.
    /// </remarks>
    public static string? Set(bool enabled) => Set(Registry.CurrentUser, ExecutablePath(), enabled);

    /// <summary>Turns starting with Windows on or off under a user hive.</summary>
    /// <param name="user">The hive: <see cref="Registry.CurrentUser"/>, or a test's scratch key.</param>
    /// <param name="executable">The executable to register.</param>
    /// <param name="enabled">Whether to start automatically.</param>
    /// <returns>Null on success, or why it could not be changed.</returns>
    /// <remarks>
    /// The decision is written <em>before</em> the Run entry, and the order carries the
    /// safety. Of the two halves, the recorded decision is the one that protects the person:
    /// it is what stops a later first start from switching autostart back on. Written second,
    /// an untick whose decision failed to save would leave no decision and no entry — exactly
    /// the state in which an installed copy turns autostart on by itself, against the choice
    /// just made. Written first, a failure leaves the Run entry as it was and the menu re-reads
    /// it, so what the tick shows is still true.
    /// </remarks>
    internal static string? Set(RegistryKey user, string executable, bool enabled)
    {
        ArgumentNullException.ThrowIfNull(user);

        try
        {
            Record(user, enabled);

            using var key = user.CreateSubKey(RunKey, writable: true);

            if (enabled)
            {
                // Quoted: the path contains spaces under Program Files, and an unquoted
                // value there is the classic unquoted-service-path problem in miniature.
                key.SetValue(
                    ValueName,
                    $"\"{executable}\" {BackgroundArgument}",
                    RegistryValueKind.String);
            }
            else
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
            }

            return null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                       or UnauthorizedAccessException
                                       or IOException)
        {
            return ex.Message;
        }
    }

    /// <summary>The decision recorded under a user hive, if any.</summary>
    /// <param name="user">The hive.</param>
    /// <returns>True for on, false for off, null when nothing has been decided.</returns>
    /// <remarks>
    /// A value that is present but is not the DWORD this program writes reads as "off". A
    /// decision that exists but cannot be understood is not permission to change somebody's
    /// startup list.
    /// </remarks>
    internal static bool? RecordedDecision(RegistryKey user)
    {
        ArgumentNullException.ThrowIfNull(user);

        try
        {
            using var key = user.OpenSubKey(SettingsKey, writable: false);
            return key?.GetValue(DecisionValue) switch
            {
                null => null,
                int value => value != 0,
                _ => false,
            };
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            // Unreadable: treated like an unreadable value, as a decision not to be overridden.
            return false;
        }
    }

    /// <summary>
    /// Registers this installed copy to start with Windows the first time this person starts
    /// it, unless they have already decided.
    /// </summary>
    /// <returns>What was done, and why it failed if it did.</returns>
    /// <remarks>
    /// This only names what to work on - this person's hive, the machine's
    /// (<see cref="OpenMachineHive"/>), this executable and the sandbox - and reads nothing
    /// itself. Everything read from the hives is read by the overload the tests drive, with a
    /// scratch key in the machine's place. When this entry point read the MSI's values
    /// itself, it could ignore the script-install record (D-67) and every test still passed.
    /// What no test can check is that it names the real hives; it cannot be run against them
    /// without touching this person's real startup list.
    /// </remarks>
    public static FirstStartOutcome AdoptOnFirstStart()
    {
        using var machine = OpenMachineHive();
        return AdoptOnFirstStart(Registry.CurrentUser, machine, ExecutablePath(), DataDirectories.IsSandboxed);
    }

    /// <summary>The first-start rule, reading the MSI's install record from a machine hive.</summary>
    /// <param name="user">The hive: <see cref="Registry.CurrentUser"/>, or a test's scratch key.</param>
    /// <param name="machine">
    /// The 64-bit <c>HKEY_LOCAL_MACHINE</c>, or a test's scratch key; null when it could not
    /// be opened.
    /// </param>
    /// <param name="executable">The running executable.</param>
    /// <param name="sandboxed">Whether this process runs against a sandbox data directory.</param>
    /// <returns>What was done, and why it failed if it did.</returns>
    /// <remarks>
    /// Both values the MSI writes - where it installed, and whether it replaced a script
    /// install - come from one key, so they are readable together or not at all. A record
    /// that cannot be read is treated as no record: this copy is then not the installed one,
    /// and <see cref="Decide"/> leaves the startup list alone.
    /// </remarks>
    internal static FirstStartOutcome AdoptOnFirstStart(
        RegistryKey user,
        RegistryKey? machine,
        string executable,
        bool sandboxed)
    {
        var (installDirectory, replacedScriptInstall) = InstallRecord(machine);
        return AdoptOnFirstStart(user, executable, installDirectory, replacedScriptInstall, sandboxed);
    }

    /// <summary>Both values of the MSI's install record, or neither.</summary>
    /// <param name="machine">The machine hive, or null when it could not be opened.</param>
    /// <returns>The install directory and the script-install record; (null, false) for no record.</returns>
    private static (string? Directory, bool ReplacedScriptInstall) InstallRecord(RegistryKey? machine)
    {
        if (machine is null)
        {
            return (null, false);
        }

        try
        {
            return (InstalledDirectory(machine), ReplacedScriptInstall(machine));
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                       or UnauthorizedAccessException
                                       or IOException)
        {
            return (null, false);
        }
    }

    /// <summary>The first-start rule, against a given hive and install record.</summary>
    /// <param name="user">The hive: <see cref="Registry.CurrentUser"/>, or a test's scratch key.</param>
    /// <param name="executable">The running executable.</param>
    /// <param name="installDirectory">Where the MSI recorded installing, or null.</param>
    /// <param name="replacedScriptInstall">The MSI recorded installing over a script install.</param>
    /// <param name="sandboxed">Whether this process runs against a sandbox data directory.</param>
    /// <returns>What was done, and why it failed if it did.</returns>
    internal static FirstStartOutcome AdoptOnFirstStart(
        RegistryKey user,
        string executable,
        string? installDirectory,
        bool replacedScriptInstall,
        bool sandboxed)
    {
        var action = Decide(
            IsInstalledCopy(installDirectory, executable),
            sandboxed,
            RecordedDecision(user),
            IsEnabled(user, executable),
            replacedScriptInstall,
            HasRunValue(user));

        var failure = action switch
        {
            FirstStartAction.Enable => Set(user, executable, enabled: true),
            FirstStartAction.RecordExisting => TryRecord(user, enabled: true),
            FirstStartAction.RecordOffFromScriptInstall => TryRecord(user, enabled: false),
            _ => null,
        };

        return new FirstStartOutcome(action, failure);
    }

    /// <summary>What a start should do about autostart. A pure function of its inputs.</summary>
    /// <param name="installedCopy">This executable is the one the MSI installed.</param>
    /// <param name="sandboxed">This process runs against a sandbox data directory.</param>
    /// <param name="recorded">The person's recorded decision, or null if none.</param>
    /// <param name="enabled">The Run entry already points at this executable.</param>
    /// <param name="replacedScriptInstall">The MSI recorded installing over a script install.</param>
    /// <param name="runValuePresent">The Run key has an entry by this program's name, for any copy.</param>
    /// <returns>The action to take.</returns>
    /// <remarks>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Sandboxed:</strong> leave alone. A sandbox exists so a run touches none of the
    /// person's real state, and the startup list is real state.
    /// </description></item>
    /// <item><description>
    /// <strong>Not the installed copy:</strong> leave alone. A copy run from Downloads or a
    /// build folder must never put itself in the startup list; that is opt-in, from the menu.
    /// </description></item>
    /// <item><description>
    /// <strong>A decision is recorded:</strong> leave alone, whichever way it went.
    /// </description></item>
    /// <item><description>
    /// <strong>Already registered</strong> (by <c>Install.ps1</c>, or an earlier build):
    /// record that, and change nothing.
    /// </description></item>
    /// <item><description>
    /// <strong>A script install was here, and this person has no Run entry at all</strong>
    /// (D-67): record "off", and register nothing. The script registered the person who ran
    /// it unless told not to, so for them a missing entry is an untick, or
    /// <c>-NoAutostart</c>, that the script's era had no way to record. Anyone else on the
    /// machine never had an entry either and cannot be told apart, so they are kept off too,
    /// one tick away from on. An entry naming another copy is not this case: that person had
    /// it on.
    /// </description></item>
    /// <item><description>
    /// <strong>Otherwise:</strong> register, and record it.
    /// </description></item>
    /// </list>
    /// </remarks>
    internal static FirstStartAction Decide(
        bool installedCopy,
        bool sandboxed,
        bool? recorded,
        bool enabled,
        bool replacedScriptInstall,
        bool runValuePresent)
    {
        if (sandboxed || !installedCopy || recorded is not null)
        {
            return FirstStartAction.LeaveAlone;
        }

        if (enabled)
        {
            return FirstStartAction.RecordExisting;
        }

        if (replacedScriptInstall && !runValuePresent)
        {
            return FirstStartAction.RecordOffFromScriptInstall;
        }

        return FirstStartAction.Enable;
    }

    /// <summary>Whether <paramref name="executable"/> sits in the recorded install directory.</summary>
    /// <param name="installDirectory">The MSI's record, or null when there is none.</param>
    /// <param name="executable">The running executable's full path.</param>
    /// <returns>True only for the executable directly in that directory.</returns>
    /// <remarks>
    /// Compared by directory, not by "somewhere under Program Files", because the install
    /// directory can be changed at install time and a copy elsewhere under Program Files is
    /// not the installed one.
    /// </remarks>
    internal static bool IsInstalledCopy(string? installDirectory, string executable)
    {
        if (string.IsNullOrWhiteSpace(installDirectory) || string.IsNullOrWhiteSpace(executable))
        {
            return false;
        }

        var directory = Path.GetDirectoryName(executable);
        return !string.IsNullOrEmpty(directory) && DataDirectories.Same(directory, installDirectory);
    }

    /// <summary>The machine hive the MSI writes its install record to.</summary>
    /// <returns>The 64-bit <c>HKEY_LOCAL_MACHINE</c>, or null when it cannot be opened.</returns>
    /// <remarks>
    /// The 64-bit view explicitly, because that is where an x64 package writes and this
    /// executable is x64 only; naming the view means the answer cannot depend on which
    /// process bitness asked.
    /// </remarks>
    internal static RegistryKey? OpenMachineHive()
    {
        try
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                       or UnauthorizedAccessException
                                       or IOException)
        {
            return null;
        }
    }

    /// <summary>The install directory recorded under a machine hive.</summary>
    /// <param name="machine">The hive: the 64-bit <c>HKEY_LOCAL_MACHINE</c>, or a test's scratch key.</param>
    /// <returns>The directory, or null when there is no record.</returns>
    internal static string? InstalledDirectory(RegistryKey machine)
    {
        ArgumentNullException.ThrowIfNull(machine);

        using var key = machine.OpenSubKey(InstallKey, writable: false);
        return key?.GetValue(InstallDirectoryValue) as string;
    }

    /// <summary>Whether a machine hive records that the MSI replaced a script install.</summary>
    /// <param name="machine">The hive: the 64-bit <c>HKEY_LOCAL_MACHINE</c>, or a test's scratch key.</param>
    /// <returns>True for a non-zero DWORD or any other value by that name; false when absent or 0.</returns>
    /// <remarks>
    /// The package writes a DWORD 1. A value of another type is not something it writes, and
    /// like an unreadable decision (<see cref="RecordedDecision"/>) it is not read as
    /// permission to change somebody's startup list.
    /// </remarks>
    internal static bool ReplacedScriptInstall(RegistryKey machine)
    {
        ArgumentNullException.ThrowIfNull(machine);

        using var key = machine.OpenSubKey(InstallKey, writable: false);
        return key?.GetValue(ReplacedScriptInstallValue) switch
        {
            null => false,
            int value => value != 0,
            _ => true,
        };
    }

    /// <summary>The executable a startup command line runs, without its arguments.</summary>
    /// <param name="command">A Run value, quoted or not, with or without arguments.</param>
    /// <returns>The executable path.</returns>
    /// <remarks>
    /// Reads both shapes this program has ever written: the older bare quoted path, and the
    /// current quoted path followed by <see cref="BackgroundArgument"/>. An entry written by
    /// the previous build must still read as enabled, or upgrading would silently untick the
    /// box while leaving the entry in place.
    /// </remarks>
    internal static string ExecutableIn(string command)
    {
        var trimmed = command.Trim();

        if (trimmed.StartsWith('"'))
        {
            var close = trimmed.IndexOf('"', 1);
            return close > 0 ? trimmed[1..close] : trimmed.Trim('"');
        }

        var argument = trimmed.IndexOf(" --", StringComparison.Ordinal);
        return argument > 0 ? trimmed[..argument] : trimmed;
    }

    /// <summary>The full path of the running executable.</summary>
    /// <returns>The path, or an empty string when it cannot be determined.</returns>
    public static string ExecutablePath()
    {
        // Environment.ProcessPath is the host executable, which is what the Run key needs.
        // Assembly.Location is empty for a single-file publish, which is exactly how this
        // ships, so it is not an option here.
        var path = Environment.ProcessPath;

        if (!string.IsNullOrEmpty(path))
        {
            return path;
        }

        using var process = Process.GetCurrentProcess();
        return process.MainModule?.FileName ?? string.Empty;
    }

    /// <summary>A one-line description of the current state, for the Status dialog.</summary>
    /// <returns>What will happen at the next sign-in.</returns>
    public static string Describe() =>
        IsEnabled()
            ? string.Create(
                CultureInfo.CurrentCulture,
                $"Starts with Windows · {ExecutablePath()}")
            : "Does NOT start with Windows — after a restart, nothing syncs until SippBucket is opened";

    private static void Record(RegistryKey user, bool enabled)
    {
        using var settings = user.CreateSubKey(SettingsKey, writable: true);
        settings.SetValue(DecisionValue, enabled ? 1 : 0, RegistryValueKind.DWord);
    }

    private static string? TryRecord(RegistryKey user, bool enabled)
    {
        try
        {
            Record(user, enabled);
            return null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                       or UnauthorizedAccessException
                                       or IOException)
        {
            return ex.Message;
        }
    }
}

/// <summary>What a start did about autostart.</summary>
internal enum FirstStartAction
{
    /// <summary>Nothing: sandboxed, not the installed copy, or already decided.</summary>
    LeaveAlone,

    /// <summary>It was already registered; that is now recorded as the decision.</summary>
    RecordExisting,

    /// <summary>It was registered to start with Windows, and that was recorded.</summary>
    Enable,

    /// <summary>
    /// A script install was here and left this person no startup entry: recorded as their
    /// decision to stay off, and nothing registered (D-67).
    /// </summary>
    RecordOffFromScriptInstall,
}

/// <summary>The outcome of <see cref="Autostart.AdoptOnFirstStart()"/>.</summary>
/// <param name="Action">What was attempted.</param>
/// <param name="Failure">Null on success, otherwise why it could not be done.</param>
internal readonly record struct FirstStartOutcome(FirstStartAction Action, string? Failure);
