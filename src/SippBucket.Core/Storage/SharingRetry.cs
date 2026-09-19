using System.Diagnostics;

namespace SippBucket.Core.Storage;

/// <summary>
/// Runs a file operation again, for a bounded time, when it failed only because another
/// program had the file open.
/// </summary>
/// <remarks>
/// <para>
/// Windows refuses an open whose sharing mode conflicts with a handle someone else already
/// holds: <c>ERROR_SHARING_VIOLATION</c> (32), "The process cannot access the file because
/// it is being used by another process", or <c>ERROR_LOCK_VIOLATION</c> (33) for a locked
/// range (https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).
/// An open that asks to share nothing fails against <em>any</em> other handle, however
/// politely that handle was opened.
/// </para>
/// <para>
/// Programs this one does not control open files it has just written: an antivirus scanner
/// or a search indexer may read a file for a moment after every write. The test that has
/// the daemon's server read <c>peers.json</c> while its sync engine records a sync failed 2
/// times in 38 on the desktop, both times on a handle outside this process, whose owner was
/// not identified. In the daemon that is a sync time not recorded, or a peer's connection
/// dropped, for no reason the person could act on. SippBucket must not interfere with
/// antivirus software, and it must not fall over when antivirus software does its job.
/// </para>
/// <para>
/// So the operation is tried again, with a growing pause, for at most
/// <see cref="Patience"/>, and only for those two errors. Anything else, and a violation
/// that outlasts the patience, is thrown to the caller exactly as before: a program that
/// holds the file for longer is not a moment's scan, and waiting on it indefinitely would
/// hang the daemon.
/// </para>
/// <para>
/// <b>Where it is used, and where it deliberately is not (D-69).</b> Every open, rename and
/// delete of these files goes through here: in <c>.sip</c>, the config (including the
/// in-place overwrite), head, the peer list, snapshots and their final rename, the ancestry
/// index, blocks and their final rename, the merge's staged files and its staging folder, and
/// the operation lock's holder note; in the working folder, <c>.sipignore</c>; for the
/// machine, the device key, network consent, <c>master.json</c> and the tray's list of
/// watched folders. Two places wait on purpose in another way or not at all. The merge's
/// pre-flight check never waits: it holds a view of the working folder, and two seconds spent
/// waiting is two seconds in which that view goes stale, so a file held there defers the whole
/// sync to the next cycle instead. The operation lock (<see cref="Repository.OperationLock"/>)
/// has a patience of its own, longer than this one, because its holder is usually another
/// SippBucket operation rather than a scanner.
/// </para>
/// <para>
/// Public so that the tray, which keeps the watch list, waits exactly the same way; nothing
/// about it is specific to the files it has been used on.
/// </para>
/// </remarks>
public static class SharingRetry
{
    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;

    private static readonly TimeSpan FirstPause = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan LongestPause = TimeSpan.FromMilliseconds(250);

    /// <summary>The longest this waits for another program to let go of a file.</summary>
    public static TimeSpan Patience { get; } = TimeSpan.FromSeconds(2);

    /// <summary>Runs <paramref name="operation"/>, again on a sharing violation.</summary>
    /// <typeparam name="T">What the operation returns.</typeparam>
    /// <param name="operation">A file operation that is safe to repeat from the start.</param>
    /// <returns>What the operation returned.</returns>
    /// <exception cref="IOException">
    /// Any I/O failure other than a sharing or lock violation, or one that lasted longer
    /// than <see cref="Patience"/>.
    /// </exception>
    public static T Run<T>(Func<T> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);

        var elapsed = Stopwatch.StartNew();
        var pause = FirstPause;
        while (true)
        {
            try
            {
                return operation();
            }
            catch (IOException ex) when (IsSharingViolation(ex) && elapsed.Elapsed + pause < Patience)
            {
                Thread.Sleep(pause);
                pause = pause * 2 < LongestPause ? pause * 2 : LongestPause;
            }
        }
    }

    /// <summary>Runs <paramref name="operation"/>, again on a sharing violation.</summary>
    /// <param name="operation">A file operation that is safe to repeat from the start.</param>
    /// <exception cref="IOException">
    /// Any I/O failure other than a sharing or lock violation, or one that lasted longer
    /// than <see cref="Patience"/>.
    /// </exception>
    public static void Run(Action operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        _ = Run(() =>
        {
            operation();
            return true;
        });
    }

    /// <summary>
    /// Runs <paramref name="operation"/>, again on a sharing violation, pausing without
    /// holding a thread.
    /// </summary>
    /// <typeparam name="T">What the operation returns.</typeparam>
    /// <param name="operation">An asynchronous file operation that is safe to repeat from the start.</param>
    /// <param name="cancellationToken">Cancels the pauses, and is passed to the operation.</param>
    /// <returns>What the operation returned.</returns>
    /// <exception cref="IOException">
    /// Any I/O failure other than a sharing or lock violation, or one that lasted longer
    /// than <see cref="Patience"/>.
    /// </exception>
    /// <remarks>
    /// The same rule as <see cref="Run{T}(Func{T})"/>, for the paths that are already
    /// asynchronous: a block or snapshot read while serving a peer should not park a
    /// thread-pool thread in <see cref="Thread.Sleep(TimeSpan)"/> for two seconds.
    /// </remarks>
    public static async Task<T> RunAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);

        var elapsed = Stopwatch.StartNew();
        var pause = FirstPause;
        while (true)
        {
            try
            {
                return await operation(cancellationToken).ConfigureAwait(false);
            }
            catch (IOException ex) when (IsSharingViolation(ex) && elapsed.Elapsed + pause < Patience)
            {
                await Task.Delay(pause, cancellationToken).ConfigureAwait(false);
                pause = pause * 2 < LongestPause ? pause * 2 : LongestPause;
            }
        }
    }

    /// <summary>Runs <paramref name="operation"/>, again on a sharing violation.</summary>
    /// <param name="operation">An asynchronous file operation that is safe to repeat from the start.</param>
    /// <param name="cancellationToken">Cancels the pauses, and is passed to the operation.</param>
    /// <returns>A task that completes when the operation has.</returns>
    /// <exception cref="IOException">
    /// Any I/O failure other than a sharing or lock violation, or one that lasted longer
    /// than <see cref="Patience"/>.
    /// </exception>
    public static Task RunAsync(Func<CancellationToken, Task> operation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return RunAsync(
            async token =>
            {
                await operation(token).ConfigureAwait(false);
                return true;
            },
            cancellationToken);
    }

    /// <summary>Whether an I/O failure was another handle's sharing mode or byte-range lock.</summary>
    /// <param name="exception">The failure.</param>
    /// <returns>True for <c>ERROR_SHARING_VIOLATION</c> and <c>ERROR_LOCK_VIOLATION</c>.</returns>
    /// <remarks>
    /// .NET reports a Win32 error from a file API as an <see cref="IOException"/> whose
    /// <see cref="Exception.HResult"/> is the error wrapped as <c>0x8007xxxx</c>, so the
    /// Win32 code is its low 16 bits.
    /// </remarks>
    public static bool IsSharingViolation(IOException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return (exception.HResult & 0xFFFF) is ErrorSharingViolation or ErrorLockViolation;
    }
}
