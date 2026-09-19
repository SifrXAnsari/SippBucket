using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using SippBucket.Cli;

namespace SippBucket.Tray;

/// <summary>
/// Gives the windowed executable a console when it is asked to behave as the command line.
/// </summary>
/// <remarks>
/// <para>
/// SippBucket ships as one executable. It is a <c>WinExe</c>, because a console application
/// flashes a black window every time Windows starts it at login, and the tray is what most
/// people will ever see. The cost of that choice is that a <c>WinExe</c> has no standard
/// output at all, so the command surface has to acquire one.
/// </para>
/// <para>
/// Two different acquisitions, and they are not interchangeable. Run from an existing
/// prompt, <see cref="Attach"/> joins that console so output lands where the user typed.
/// Run from the tray, there is no parent console to join, so one is allocated.
/// </para>
/// <para>
/// <strong>The tray never allocates a console in its own process.</strong> Closing a console
/// window terminates every process attached to it, so a user shutting the command window
/// would silently stop the daemon and every folder it watches. The tray therefore starts a
/// <em>separate</em> instance in <see cref="Interactive"/> mode, which owns its own console
/// and can be closed freely.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class ConsoleHost
{
    /// <summary>The verb that asks for an interactive console session.</summary>
    internal const string InteractiveVerb = "console";

    /// <summary>Passed to <c>AttachConsole</c> to mean the parent process's console.</summary>
    private const uint AttachParentProcess = 0xFFFFFFFF;

    /// <summary>
    /// Acquires a console: the caller's if there is one, otherwise a fresh window.
    /// </summary>
    /// <returns>True when a console is available for writing.</returns>
    internal static bool Attach()
    {
        // Already going somewhere - a pipe, a file, another program's stdin. There is
        // nothing to acquire, and allocating a console here would pop an empty window and
        // leave the redirect orphaned. Found by running `SippBucket id | ...`, not by
        // compiling it.
        if (Console.IsOutputRedirected)
        {
            return true;
        }

        var acquired = AttachConsole(AttachParentProcess) || AllocConsole();

        if (acquired)
        {
            Rebind();
        }

        return acquired;
    }

    /// <summary>
    /// Runs commands typed into a console of this process's own, until the user leaves.
    /// </summary>
    /// <returns>The exit code, which is always success — quitting a shell is not a failure.</returns>
    internal static async Task<int> RunInteractiveAsync()
    {
        // AllocConsole fails when this process already has one, which happens when the verb
        // is typed at a prompt rather than chosen from the tray. Either way there is a
        // console afterwards and the streams have to be pointed at it.
        AllocConsole();
        Rebind();

        Console.Title = "SippBucket - command line";
        Console.WriteLine("SippBucket command line. The same commands as 'sip'.");
        Console.WriteLine("Type 'help' for the list, 'exit' to close. Closing this window");
        Console.WriteLine("does not stop SippBucket: the tray keeps running.");
        Console.WriteLine();

        while (true)
        {
            Console.Write("sip> ");

            var line = Console.ReadLine();

            // Null means the input stream ended - Ctrl+Z, or the window closing. Treat it
            // exactly as 'exit' rather than spinning on a stream that will never produce
            // another line, which would peg a core until the process is killed.
            if (line is null)
            {
                return 0;
            }

            var args = Split(line);

            if (args.Length == 0)
            {
                continue;
            }

            if (IsLeaving(args[0]))
            {
                return 0;
            }

            // The command surface is shared with the standalone shim, so anything typed
            // here behaves identically to typing it at a prompt - including exit codes,
            // which are printed rather than swallowed because a shell that hides failure
            // is the thing this project keeps finding and fixing.
            var code = await CommandLine.RunAsync(args).ConfigureAwait(false);

            if (code != 0)
            {
                Console.WriteLine($"[exit {code}]");
            }

            Console.WriteLine();
        }
    }

    /// <summary>Starts a second instance of this program owning its own console.</summary>
    /// <returns>Null on success, or a message describing why it could not start.</returns>
    /// <remarks>
    /// A separate process on purpose - see the type's remarks. <c>UseShellExecute</c> is
    /// false so the child is a direct descendant and inherits nothing of the tray's window
    /// station beyond what it needs.
    /// </remarks>
    internal static string? StartSeparateSession()
    {
        var executable = Environment.ProcessPath;

        if (string.IsNullOrEmpty(executable))
        {
            return "The running executable's path could not be determined.";
        }

        try
        {
            using var started = Process.Start(new ProcessStartInfo(executable, InteractiveVerb)
            {
                UseShellExecute = false,
            });

            return started is null ? "The command line did not start." : null;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return ex.Message;
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }
    }

    private static bool IsLeaving(string word) =>
        word.Equals("exit", StringComparison.OrdinalIgnoreCase) ||
        word.Equals("quit", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Points <see cref="Console"/> at the console just acquired.
    /// </summary>
    /// <remarks>
    /// A <c>WinExe</c> starts with its standard handles bound to nothing, and .NET caches
    /// that at first use. Attaching a console afterwards does not undo the caching, so
    /// without this every write goes nowhere and the command line looks like it hung.
    /// </remarks>
    private static void Rebind()
    {
        // UTF-8 with NO byte-order mark. Encoding.UTF8 emits one, and a StreamWriter writes
        // it at the head of the stream - so `SippBucket id` printed a BOM before the device
        // ID and anything parsing that output got three bytes it did not ask for. The `sip`
        // shim, being a console application, never had the problem; the combined executable
        // acquired it along with the console. Caught by piping the output and looking at it.
        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        // Ownership moves to Console, which holds these for the life of the process and
        // closes them at exit. Disposing them here would close the console's own handles
        // and every subsequent write would throw - the analyser cannot see the handoff.
#pragma warning disable CA2000
        var output = new StreamWriter(Console.OpenStandardOutput(), utf8)
        {
            AutoFlush = true,
        };

        var error = new StreamWriter(Console.OpenStandardError(), utf8)
        {
            AutoFlush = true,
        };

        Console.SetOut(output);
        Console.SetError(error);
        Console.SetIn(new StreamReader(Console.OpenStandardInput(), utf8));
#pragma warning restore CA2000
    }

    /// <summary>
    /// Splits a typed line into arguments, honouring double quotes.
    /// </summary>
    /// <remarks>
    /// Deliberately small. It exists because a folder path with a space in it is the normal
    /// case on Windows, not an edge case, and splitting on whitespace alone would break
    /// <c>sip init "C:\My Documents\notes"</c> - which is the first thing anyone types.
    /// </remarks>
    private static string[] Split(string line)
    {
        var args = new List<string>();
        var current = new StringBuilder();
        var quoted = false;

        foreach (var c in line)
        {
            if (c == '"')
            {
                quoted = !quoted;
                continue;
            }

            if (!quoted && char.IsWhiteSpace(c))
            {
                if (current.Length > 0)
                {
                    args.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            current.Append(c);
        }

        if (current.Length > 0)
        {
            args.Add(current.ToString());
        }

        return [.. args];
    }

    /// <remarks>
    /// DllImport rather than the source-generated LibraryImport, for the reason given in
    /// <c>SleepBlocker</c>: LibraryImport needs <c>AllowUnsafeBlocks</c> across the whole
    /// project, and these take no arguments worth marshalling. The search path is pinned to
    /// System32 so a <c>kernel32.dll</c> dropped beside the executable is never loaded.
    /// </remarks>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint processId);

    /// <inheritdoc cref="AttachConsole"/>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();
}
