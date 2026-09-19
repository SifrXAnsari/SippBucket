using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using SippBucket.Core.Configuration;

namespace SippBucket.Cli;

/// <summary>
/// <c>sip config</c>: shows, checks and sets the machine's <c>master.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// There is no window, tray menu or settings page for this file, on purpose
/// (docs/MASTER-CONFIG.md): that is the "hidden" half. The other half is that nothing here is
/// secret. <c>show</c> prints every setting and where its value came from, <c>check</c>
/// reports everything in the file that was not used as written, and <c>sip doctor</c> lists
/// every value that differs from its default.
/// </para>
/// <para>
/// <c>set</c> needs an administrator, because the file does. It never runs elevated in this
/// process; it starts this same program again through UAC for the one write, waits for it,
/// and reads the file back to say what is now in effect.
/// </para>
/// </remarks>
internal static class MachineConfig
{
    /// <summary>Marks the copy of this program started elevated to do one write.</summary>
    /// <remarks>
    /// Only ever added by <see cref="RelaunchElevatedAsync"/>. Its one effect is that a copy
    /// carrying it which finds itself still not elevated refuses instead of asking again, so
    /// a machine where UAC cannot elevate does not prompt in a loop.
    /// </remarks>
    private const string ElevatedRelaunch = "--elevated-write";

    /// <summary>What Windows reports when the person declines the UAC prompt.</summary>
    /// <remarks>
    /// <c>ERROR_CANCELLED</c>, 1223, "The operation was canceled by the user"
    /// (https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-).
    /// </remarks>
    private const int ErrorCancelled = 1223;

    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary>Runs <c>sip config</c>.</summary>
    /// <param name="args">The arguments after <c>config</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> RunAsync(string[] args)
    {
        var sub = args.Length == 0 ? "SHOW" : args[0].ToUpperInvariant();

        return sub switch
        {
            "SHOW" when args.Length <= 1 => Show(MasterConfig.Load()),
            "CHECK" when args.Length <= 1 => Check(MasterConfig.Load()),
            "SET" => await SetAsync(args[1..]).ConfigureAwait(false),
            "SHOW" or "CHECK" => Usage($"sip config {args[0]} takes no arguments."),
            _ => Usage($"'{args[0]}' is not a subcommand of sip config. Use show, check or set."),
        };
    }

    /// <summary>
    /// Says, on standard error, when <c>master.json</c> had entries that were not used, for
    /// the commands that run long enough for a quiet fallback to matter.
    /// </summary>
    /// <param name="config">The settings just loaded.</param>
    public static void WarnAboutProblems(MasterConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (config.Problems.Count == 0)
        {
            return;
        }

        var count = config.Problems.Count;
        Console.Error.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"sip: {count} {(count == 1 ? "entry" : "entries")} in {config.Path} fell back or were ignored. Run 'sip config check' to see which."));
    }

    private static int Show(MasterConfig config)
    {
        PrintLocation(config);
        Console.WriteLine();

        var width = MasterSettings.All.Max(setting => setting.Key.Length);
        foreach (var value in config.Values)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"  {value.Setting.Key.PadRight(width)}  {value.Value,6}  {DescribeSource(value)}"));
        }

        if (config.Problems.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Run 'sip config check' for everything in the file that was not used as written.");
        }

        return ExitSuccess;
    }

    private static int Check(MasterConfig config)
    {
        PrintLocation(config);
        Console.WriteLine();

        if (config.Problems.Count == 0)
        {
            Console.WriteLine(config.FileExists
                ? "Every entry was used as written."
                : "Nothing to check: with no file, every setting is at its default.");
            return ExitSuccess;
        }

        foreach (var problem in config.Problems)
        {
            Console.WriteLine($"  {problem.Message}");
        }

        Console.WriteLine();
        Console.WriteLine("None of these stops SippBucket: each falls back to a default, as 'sip help config' describes.");
        return ExitFailure;
    }

    private static async Task<int> SetAsync(string[] args)
    {
        var relaunched = args.Length == 3 && string.Equals(args[2], ElevatedRelaunch, StringComparison.Ordinal);
        if (args.Length != 2 && !relaunched)
        {
            return Usage("sip config set <key> <value>. Run 'sip help config' for the keys.");
        }

        var setting = MasterSettings.Find(args[0]);
        if (setting is null)
        {
            return Usage(
                $"'{args[0]}' is not a setting. The settings are: " +
                string.Join(", ", MasterSettings.All.Select(s => s.Key)) + ".");
        }

        if (setting.TryParse(args[1], out var value) is not null)
        {
            return Usage(
                $"{setting.Key} takes a whole number from {setting.DescribeLimits()}, and '{args[1]}' is not one. " +
                "Nothing was changed.");
        }

        // Environment.IsPrivilegedProcess is, on Windows, the token's TokenElevation: whether
        // this process runs elevated, not whether the account could be. Its documentation does
        // not say so; the runtime's source does (IsPrivilegedProcessCore in
        // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Environment.Windows.cs).
        var path = MasterConfig.ResolvePath();
        var route = MasterConfigWriter.Route(
            MasterConfig.IsLocationOverridden(), Environment.IsPrivilegedProcess, relaunched);

        switch (route)
        {
            case ConfigWriteRoute.WriteHere:
                // Elevated, the location is checked before anything is read or written: see
                // MasterConfigLocation. In the sandbox this process has no rights to misuse.
                MasterConfigWriter.Set(path, setting, value, writingAsAdministrator: Environment.IsPrivilegedProcess);
                return relaunched ? ExitSuccess : Report(path, setting);

            case ConfigWriteRoute.Refuse:
                return Fail(
                    "This copy was started to change master.json with administrator rights and does not " +
                    "have them. Nothing was changed.");

            default:
                return await RelaunchElevatedAsync(path, setting, value).ConfigureAwait(false);
        }
    }

    /// <summary>Starts this program again, elevated through UAC, to make the one change.</summary>
    /// <remarks>
    /// The <c>runas</c> verb "Launches an application as Administrator. User Account Control
    /// (UAC) will prompt the user for consent to run the application elevated or enter the
    /// credentials of an administrator account used to run the application" (Launching
    /// Applications, Object Verbs: https://learn.microsoft.com/en-us/windows/win32/shell/launch).
    /// Verbs need the shell, so <see cref="ProcessStartInfo.UseShellExecute"/> is on. The
    /// elevated copy is told only the key and the value, both already checked, and finds the
    /// file itself: it never writes to a path this unelevated process chose.
    /// </remarks>
    private static async Task<int> RelaunchElevatedAsync(string path, MasterSetting setting, int value)
    {
        if (!OperatingSystem.IsWindows() || Environment.ProcessPath is not { } executable)
        {
            return Fail(
                $"{path} can only be changed by an administrator, and this program cannot ask for " +
                "administrator rights here. Nothing was changed.");
        }

        Console.WriteLine("master.json can only be changed by an administrator. Windows will ask for");
        Console.WriteLine("permission to make this one change.");

        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            Arguments = string.Create(
                CultureInfo.InvariantCulture, $"config set {setting.Key} {value} {ElevatedRelaunch}"),
        };

        try
        {
            using var elevated = Process.Start(start);
            if (elevated is null)
            {
                return Fail("Windows did not start the administrator copy. Nothing was changed.");
            }

            await elevated.WaitForExitAsync().ConfigureAwait(false);

            if (elevated.ExitCode != ExitSuccess)
            {
                var code = elevated.ExitCode.ToString(CultureInfo.InvariantCulture);
                return Fail(
                    $"The administrator copy could not change master.json (exit code {code}). " +
                    "Run 'sip config check' to see the file as it is.");
            }
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            return Fail("Administrator rights were not given, so master.json was not changed.");
        }

        return Report(path, setting);
    }

    /// <summary>Reads the file back and says what is now in effect, rather than what was asked for.</summary>
    private static int Report(string path, MasterSetting setting)
    {
        var after = MasterConfig.Load(path);
        var value = after.Values.Single(v => v.Setting == setting);

        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{setting.Key} is now {value.Value} ({DescribeSource(value)}), in {path}."));
        Console.WriteLine("SippBucket reads this file when it starts: quit and reopen it, and restart any");
        Console.WriteLine("'sip serve', for the change to take effect.");

        if (setting == MasterSettings.ListenPort)
        {
            Console.WriteLine();
            Console.WriteLine("Other machines reach this one on the port they recorded when they paired.");
            Console.WriteLine("Update each of them with 'sip peer add', or they will not find this one.");
        }

        return ExitSuccess;
    }

    private static void PrintLocation(MasterConfig config)
    {
        Console.WriteLine($"master.json  {config.Path}");

        if (MasterConfig.IsLocationOverridden())
        {
            Console.WriteLine("             (read from SIPPBUCKET_DATA_DIR, not ProgramData)");
        }

        if (!config.FileExists)
        {
            Console.WriteLine("             not present: every setting is at its default");
        }
    }

    private static string DescribeSource(SettingValue value) => value.Source switch
    {
        SettingSource.File => "set in master.json",
        SettingSource.FellBack => $"default: {value.Problem}",
        _ => "default",
    };

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitFailure;
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitUsage;
    }
}
