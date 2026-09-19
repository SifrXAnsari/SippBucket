using System.Diagnostics;

namespace SippBucket.Core.Storage;

/// <summary>
/// A lock any process can take, by opening a file sharing nothing, for the stores that are not a
/// folder's: Direct Push's inbox and quarantine, which the daemon writes as files arrive and
/// <c>sip</c> writes when the person releases or deletes one.
/// </summary>
/// <remarks>
/// The mechanism <see cref="Repository.OperationLock"/> uses and documents: the lock is the open
/// handle, never the file, so a crash cannot leave it held, because Windows closes every handle
/// a process holds when it ends. It is held for one change at a time, never while a file
/// streams in, so the command line stays usable while deliveries arrive. A process refused it
/// waits up to its patience, longer than <see cref="SharingRetry.Patience"/> so a scanner
/// glancing at the file is waited out too, and then fails with an <see cref="IOException"/>
/// saying nothing was changed.
/// </remarks>
internal sealed class FileLock : IDisposable
{
    private static readonly TimeSpan FirstPause = TimeSpan.FromMilliseconds(20);
    private static readonly TimeSpan LongestPause = TimeSpan.FromMilliseconds(250);

    private readonly FileStream _handle;

    private FileLock(FileStream handle)
    {
        _handle = handle;
    }

    /// <summary>How long a refused process waits before giving up.</summary>
    public static TimeSpan DefaultPatience { get; } = TimeSpan.FromSeconds(5);

    /// <summary>Takes the lock, waiting up to <paramref name="patience"/>.</summary>
    /// <param name="path">The lock file. Its folder must exist.</param>
    /// <param name="patience">How long to wait while someone else holds it.</param>
    /// <returns>The held lock. Dispose it to release.</returns>
    /// <exception cref="IOException">Someone else held it for longer than the patience.</exception>
    public static FileLock Acquire(string path, TimeSpan patience)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var elapsed = Stopwatch.StartNew();
        var pause = FirstPause;
        while (true)
        {
            // CA2000 cannot see the ownership transfer: a non-null lock is returned to the
            // caller, whose Dispose releases it, and null is the only other outcome.
#pragma warning disable CA2000
            if (TryOpen(path, elapsed, patience) is { } held)
            {
                return held;
            }
#pragma warning restore CA2000

            Thread.Sleep(pause);
            pause = pause * 2 < LongestPause ? pause * 2 : LongestPause;
        }
    }

    /// <summary>Takes the lock, waiting up to <paramref name="patience"/> without holding a thread.</summary>
    /// <param name="path">The lock file. Its folder must exist.</param>
    /// <param name="patience">How long to wait while someone else holds it.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>The held lock. Dispose it to release.</returns>
    /// <exception cref="IOException">Someone else held it for longer than the patience.</exception>
    public static async Task<FileLock> AcquireAsync(string path, TimeSpan patience, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var elapsed = Stopwatch.StartNew();
        var pause = FirstPause;
        while (true)
        {
            // As in Acquire: the return is the ownership transfer CA2000 cannot see.
#pragma warning disable CA2000
            if (TryOpen(path, elapsed, patience) is { } held)
            {
                return held;
            }
#pragma warning restore CA2000

            await Task.Delay(pause, cancellationToken).ConfigureAwait(false);
            pause = pause * 2 < LongestPause ? pause * 2 : LongestPause;
        }
    }

    /// <summary>Releases the lock.</summary>
    public void Dispose() => _handle.Dispose();

    private static FileLock? TryOpen(string path, Stopwatch elapsed, TimeSpan patience)
    {
        try
        {
            // Asks only to read: the lock is the share mode, whatever access the holder asked for,
            // and nothing is ever written to the file.
            return new FileLock(new FileStream(path, FileMode.OpenOrCreate, FileAccess.Read, FileShare.None));
        }
        catch (IOException ex) when (SharingRetry.IsSharingViolation(ex))
        {
            if (elapsed.Elapsed >= patience)
            {
                throw new IOException(
                    $"Another SippBucket operation has {path} open, and still had it after " +
                    $"{patience.TotalSeconds:0.#}s; nothing was changed. Try again in a moment.",
                    ex);
            }

            return null;
        }
    }
}
