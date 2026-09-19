using SippBucket.Cli;

namespace SippBucket.Tray;

/// <summary>
/// The one entry point. SippBucket is a single executable that is both the tray application
/// and the command line.
/// </summary>
/// <remarks>
/// <para>
/// Three ways in:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>No arguments</strong> - opened by a person: the daemon, headless, in the tray —
/// no window and no console. The owner's rule (taskslist, phase 9): everything runs in the
/// background, and the window and the command line open only from the tray icon. A
/// notification says where it went, so the first open is never a program that seemed to do
/// nothing.
/// </description></item>
/// <item><description>
/// <strong><see cref="Autostart.BackgroundArgument"/></strong> - started by Windows at sign-in:
/// the same, silently, because a notification at every boot is the opposite of set it and
/// forget it.
/// </description></item>
/// <item><description>
/// <strong>Anything else</strong> - the command line, same commands and exit codes as
/// <c>sip</c>, because both call the same <see cref="CommandLine.RunAsync"/>.
/// <see cref="ConsoleHost.InteractiveVerb"/> is the one special case, used by the tray to
/// open a command line in a window of its own.
/// </description></item>
/// </list>
/// <para>
/// Only the two tray paths take the single-instance guard. Opening SippBucket while it is
/// already running tells the running copy, which points at its tray icon instead of a
/// second daemon starting over the same folders; a sign-in start while it is already
/// running simply exits.
/// </para>
/// </remarks>
internal static class Program
{
    /// <summary>The exit code for "this copy cannot run", matching the command line's failure code.</summary>
    private const int ExitCannotRun = 1;

    [STAThread]
    internal static int Main(string[] args)
    {
        var background = args.Length == 1 &&
            args[0].Equals(Autostart.BackgroundArgument, StringComparison.OrdinalIgnoreCase);

        var interactive = args.Length == 1 &&
            args[0].Equals(ConsoleHost.InteractiveVerb, StringComparison.OrdinalIgnoreCase);

        // Before anything else. The tray reaches cryptography before it has a window, and so
        // do most commands; see NativeDependencies for the crash this replaces. A copy that
        // cannot load libsodium, or its own native engine, is a broken install, so it is
        // refused on every path, `help` included, rather than failing somewhere later.
        if ((NativeDependencies.SodiumProblem() ?? NativeDependencies.EngineProblem()) is { } problem)
        {
            return CannotRun(problem, windowed: args.Length == 0 || background || interactive);
        }

        if (args.Length == 0)
        {
            return RunTray(openedByPerson: true);
        }

        if (background)
        {
            return RunTray(openedByPerson: false);
        }

        if (interactive)
        {
            return ConsoleHost.RunInteractiveAsync().GetAwaiter().GetResult();
        }

        // A windowed process has no standard output until it takes one. Without this the
        // command runs correctly and prints into nothing, which reads as a hang.
        ConsoleHost.Attach();

        return CommandLine.RunAsync(args).GetAwaiter().GetResult();
    }

    /// <summary>Says why this copy cannot run, where the person will see it.</summary>
    /// <remarks>
    /// A message box for the paths a person reaches by clicking - including a sign-in start,
    /// because a copy that silently fails to start at every sign-in is the "nothing syncs and
    /// nothing says so" failure. Standard error for a command, where a script can read it.
    /// </remarks>
    private static int CannotRun(string problem, bool windowed)
    {
        if (windowed)
        {
            MessageBox.Show(problem, "SippBucket", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        else
        {
            ConsoleHost.Attach();
            Console.Error.WriteLine(problem);
        }

        return ExitCannotRun;
    }

    private static int RunTray(bool openedByPerson)
    {
        // Disposed on this thread, after the message loop ends: the mutex belongs to the
        // thread that acquired it and can only be released there.
        using var instance = new SingleInstance(InstanceNames.ForThisProcess());

        if (!instance.TryAcquire())
        {
            // Already running. Opened by a person: tell the running copy, which points at
            // its tray icon — the window opens only from there. Started at sign-in: there
            // is nothing to do, and no reason to show anything.
            if (openedByPerson)
            {
                instance.RequestShow();
            }

            return 0;
        }

        ApplicationConfiguration.Initialize();

        using var context = new TrayApplication(instance, openedByPerson);
        Application.Run(context);
        return 0;
    }
}
