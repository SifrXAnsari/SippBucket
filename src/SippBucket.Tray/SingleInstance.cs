using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SippBucket.Tray;

/// <summary>
/// Keeps the tray to one copy per signed-in session, and lets a second launch bring the
/// first copy's window forward instead of starting another daemon.
/// </summary>
/// <remarks>
/// <para>
/// Without this, opening SippBucket while it was already running — a Start Menu click after
/// it had started with Windows, say — started a second daemon over the same folders. Blob
/// writes are content-addressed and survive that; the working tree does not, and nothing
/// stopped both sync loops restoring into one folder at once (D-34). With a window, the
/// failure also becomes visible and baffling: two windows, two tray icons, one set of files.
/// </para>
/// <para>
/// <strong>The tray path only.</strong> The command line stays multi-instance, and so does
/// the <c>console</c> verb, because the tray's own <em>Command line…</em> deliberately
/// starts a second <c>SippBucket.exe</c> so that closing the console cannot take the daemon
/// down with it. A guard over the whole process would break that feature.
/// </para>
/// <para>
/// <strong>The show event is created before the mutex is tried</strong>, and the order is
/// the point. A second launch signals the event and exits at once. If it were the one to
/// create the event, its handle would be the only one, the kernel object would be destroyed
/// the moment it exited, and the signal would be lost. Because the first instance created
/// the event before it could possibly hold the mutex, the object is guaranteed to outlive
/// any second launch — and an auto-reset event stays signalled until someone waits on it,
/// so a signal sent before the first instance has finished starting is delivered, not lost.
/// </para>
/// <para>
/// Names are in the <c>Local\</c> namespace, which is per logon session, so two people
/// signed in to one PC each get their own tray — correct for a daemon that syncs one
/// person's documents. Within a session they are per data directory; see
/// <see cref="InstanceNames"/>.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class SingleInstance : IDisposable
{
    /// <summary>ASFW_ANY: any process may take the foreground once.</summary>
    private const uint AllowAnyProcess = 0xFFFFFFFF;

    private readonly EventWaitHandle? _showRequested;
    private readonly Mutex? _mutex;
    private RegisteredWaitHandle? _registration;
    private bool _owned;

    /// <summary>Opens, or creates, the named objects shared between launches.</summary>
    /// <param name="names">
    /// The objects' names: <see cref="InstanceNames.ForThisProcess"/> in the product.
    /// </param>
    public SingleInstance(InstanceNames names)
    {
        _showRequested = CreateOrNull(
            () => new EventWaitHandle(false, EventResetMode.AutoReset, names.ShowEventName));
        _mutex = CreateOrNull(() => new Mutex(false, names.MutexName));
    }

    /// <summary>Becomes the one tray instance, if no other copy already is.</summary>
    /// <returns>True when this process now owns the tray.</returns>
    /// <remarks>
    /// Must be called on the thread that will later dispose this object. A mutex belongs to
    /// the thread that acquired it and can only be released there.
    /// </remarks>
    public bool TryAcquire()
    {
        if (_mutex is null)
        {
            // The name exists and this process may not open it. The likeliest owner is a copy
            // running elevated in this same session, whose objects carry a DACL an ordinary
            // process cannot open. Starting alongside it is exactly what this class prevents,
            // so this is treated as "another instance is running", not as "no guard".
            return false;
        }

        try
        {
            _owned = _mutex.WaitOne(TimeSpan.Zero);
        }
        catch (AbandonedMutexException)
        {
            // The previous tray died without releasing it - a crash, or ended from Task
            // Manager. Windows hands ownership to the next waiter along with this exception,
            // so this process owns it now and simply carries on as the one instance.
            _owned = true;
        }

        return _owned;
    }

    /// <summary>Asks the running instance to show its window.</summary>
    /// <remarks>
    /// The launching process is the one the user just clicked, so it is the process Windows
    /// will let hand out foreground rights. Without passing them on, focus-stealing
    /// protection would flash the running instance's taskbar button instead of raising its
    /// window, and the click would look like it did nothing - the very complaint this
    /// window exists to answer.
    /// </remarks>
    public void RequestShow()
    {
        if (_showRequested is null)
        {
            return;
        }

        AllowSetForegroundWindow(AllowAnyProcess);
        _showRequested.Set();
    }

    /// <summary>Runs <paramref name="onShow"/> whenever another launch asks to be shown.</summary>
    /// <param name="onShow">
    /// Called on a thread-pool thread. It must marshal to the UI thread itself, and it must
    /// tolerate being called while the application is shutting down.
    /// </param>
    public void WhenShowRequested(Action onShow)
    {
        ArgumentNullException.ThrowIfNull(onShow);

        if (_showRequested is null || _registration is not null)
        {
            return;
        }

        _registration = ThreadPool.RegisterWaitForSingleObject(
            _showRequested,
            (_, _) => onShow(),
            state: null,
            Timeout.Infinite,
            executeOnlyOnce: false);
    }

    /// <summary>Stops listening for show requests, and waits for one already running.</summary>
    /// <remarks>
    /// Called before the window is torn down, so that a request arriving during shutdown
    /// cannot reach a window that no longer exists.
    /// </remarks>
    public void StopListening()
    {
        if (_registration is null)
        {
            return;
        }

        using var finished = new ManualResetEvent(false);

        if (_registration.Unregister(finished))
        {
            // Bounded, because this runs on the UI thread during shutdown and a callback
            // only ever posts a message, so it has no reason to take longer than this.
            finished.WaitOne(TimeSpan.FromSeconds(2));
        }

        _registration = null;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        StopListening();

        if (_owned && _mutex is not null)
        {
            _mutex.ReleaseMutex();
            _owned = false;
        }

        _mutex?.Dispose();
        _showRequested?.Dispose();
    }

    private static T? CreateOrNull<T>(Func<T> create)
        where T : class
    {
        try
        {
            return create();
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            return null;
        }
    }

    /// <remarks>
    /// DllImport rather than LibraryImport, for the reason given in <c>SleepBlocker</c>: the
    /// source generator needs unsafe code across the whole project, for a call that takes one
    /// integer. The search path is pinned to System32.
    /// </remarks>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(uint processId);
}
