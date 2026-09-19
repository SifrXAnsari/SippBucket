using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SippBucket.Core.Platform;

/// <summary>
/// Keep Alive: stops Windows idling into sleep while a transfer is actually moving data.
/// </summary>
/// <remarks>
/// <para>
/// A sync that is halfway through a large folder and gets interrupted by the machine
/// sleeping has to be picked up again later; on the receiving side it leaves a working tree
/// that matches neither snapshot until the next cycle repairs it. Windows documents this
/// exact case: applications such as "fax servers, answering machines, backup agents, and
/// network management applications must use both ES_SYSTEM_REQUIRED and ES_CONTINUOUS when
/// they process events". SippBucket is a backup agent by any reasonable reading.
/// </para>
/// <para>
/// <b>Only ES_SYSTEM_REQUIRED is used.</b> Not ES_DISPLAY_REQUIRED, because a background
/// sync has no business lighting up someone's screen. Not ES_AWAYMODE_REQUIRED either —
/// the documentation is explicit that applications running on portable computers should not
/// enable away mode, since it stops the machine entering true sleep.
/// </para>
/// <para>
/// <b>Why a dedicated thread.</b> The execution state is a property of the CALLING THREAD.
/// In async code the thread after an <c>await</c> is generally not the thread before it, so
/// acquiring on a pool thread and releasing on whichever thread happens to resume would
/// release the wrong thread's state and leave the first one holding it. Rather than rely on
/// what the operating system does when a pool thread is recycled — which the documentation
/// does not state — one dedicated thread acquires, waits, and explicitly releases. Nothing
/// here depends on implicit cleanup.
/// </para>
/// <para>
/// <b>What this cannot do,</b> stated plainly because the feature is called Keep Alive and
/// the name promises more than the API delivers: it prevents the machine idling into sleep.
/// It cannot prevent deliberate sleep. Closing the lid or pressing the power button still
/// sleeps the machine, and the documentation says so outright. It also does not stop the
/// screen saver.
/// </para>
/// </remarks>
public static class SleepBlocker
{
    /// <summary>The state remains in effect until the next call that uses it.</summary>
    private const uint EsContinuous = 0x80000000;

    /// <summary>Resets the system idle timer, keeping the machine in the working state.</summary>
    private const uint EsSystemRequired = 0x00000001;

    private static readonly Lock Gate = new();
    private static int _holdCount;
    private static long _holdsTaken;
    private static ManualResetEventSlim? _release;
    private static string? _reason;
    private static bool _lastCallFailed;

    /// <summary>True while at least one hold is outstanding.</summary>
    public static bool IsHeld
    {
        get
        {
            lock (Gate)
            {
                return _holdCount > 0;
            }
        }
    }

    /// <summary>Why the machine is currently being kept awake, or null when it is not.</summary>
    public static string? Reason
    {
        get
        {
            lock (Gate)
            {
                return _holdCount > 0 ? _reason : null;
            }
        }
    }

    /// <summary>
    /// How many holds have been taken since the process started.
    /// </summary>
    /// <remarks>
    /// Diagnostic, and load-bearing for one test. The property that matters most about this
    /// feature is a negative one — that an idle poll does NOT take a hold, because taking
    /// one every 60 seconds would reset the system idle timer forever and stop the machine
    /// sleeping at all. A counter is the only way to observe that a code path took no hold,
    /// since <see cref="IsHeld"/> reads false both before and after.
    /// </remarks>
    public static long HoldsTaken
    {
        get
        {
            lock (Gate)
            {
                return _holdsTaken;
            }
        }
    }

    /// <summary>
    /// True when the last call into the operating system reported failure. Kept as a flag
    /// rather than thrown: failing to stop sleep should never fail a sync.
    /// </summary>
    public static bool LastCallFailed
    {
        get
        {
            lock (Gate)
            {
                return _lastCallFailed;
            }
        }
    }

    /// <summary>
    /// Asks the system to stay awake until the returned token is disposed.
    /// </summary>
    /// <param name="reason">
    /// A short description of the work in flight, for display. Not passed to the operating
    /// system — this API takes no reason string, unlike the newer power-request APIs.
    /// </param>
    /// <returns>
    /// A token that releases the hold when disposed. Holds nest: the machine is released
    /// only when the last outstanding token is disposed. On a non-Windows platform this is
    /// a no-op token, so callers need no platform check of their own.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="reason"/> was null or blank.</exception>
    public static IDisposable Hold(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        if (!OperatingSystem.IsWindows())
        {
            // Counted even here: the test that an idle poll takes no hold is about the
            // calling code's behaviour, not about whether this platform can honour it.
            lock (Gate)
            {
                _holdsTaken++;
            }

            return new Token(active: false);
        }

        lock (Gate)
        {
            _reason = reason;
            _holdCount++;
            _holdsTaken++;

            if (_holdCount == 1)
            {
                _release = new ManualResetEventSlim(initialState: false);
                var release = _release;

                // Background so it can never keep the process alive on shutdown. The
                // operating system drops the request when the process exits anyway; the
                // explicit release below is for the ordinary case.
                var holder = new Thread(() => HoldUntilReleased(release))
                {
                    IsBackground = true,
                    Name = "sippbucket-keepalive",
                };
                holder.Start();
            }
        }

        return new Token(active: true);
    }

    private static void HoldUntilReleased(ManualResetEventSlim release)
    {
        try
        {
            SetState(EsContinuous | EsSystemRequired);
            release.Wait();
        }
        finally
        {
            // Always runs on the same thread that acquired, which is the entire point of
            // this thread existing.
            SetState(EsContinuous);
            release.Dispose();
        }
    }

    private static void SetState(uint flags)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var previous = SetThreadExecutionState(flags);

        lock (Gate)
        {
            // Documented: the return is the previous state on success, NULL on failure.
            _lastCallFailed = previous == 0;
        }
    }

    private static void ReleaseOne()
    {
        lock (Gate)
        {
            if (_holdCount == 0)
            {
                return;
            }

            _holdCount--;

            if (_holdCount == 0)
            {
                _reason = null;
                _release?.Set();
                _release = null;
            }
        }
    }

    /// <remarks>
    /// DllImport rather than the source-generated LibraryImport, deliberately.
    /// LibraryImport requires <c>AllowUnsafeBlocks</c> on the whole project, and enabling
    /// unsafe code across a library that handles other people's documents — to satisfy a
    /// generator for a call that takes one <c>uint</c> and returns one <c>uint</c> — is the
    /// wrong trade. There is nothing to marshal here: both types are blittable, so the
    /// generated stub would do no work that the runtime does not already do.
    /// </remarks>
    /// <remarks>
    /// The search path is pinned to System32 rather than left to the default DLL search
    /// order, which would consider the application directory first. A daemon that syncs
    /// folders between machines is an unusually good delivery vehicle for a planted
    /// <c>kernel32.dll</c> sitting next to the executable, so this is not a theoretical
    /// hardening for this program in particular.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern uint SetThreadExecutionState(uint esFlags);

    /// <summary>
    /// One outstanding hold. Disposing more than once is harmless and releases only once.
    /// </summary>
    private sealed class Token : IDisposable
    {
        private readonly bool _active;
        private bool _disposed;

        public Token(bool active) => _active = active;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            if (_active)
            {
                ReleaseOne();
            }
        }
    }
}
