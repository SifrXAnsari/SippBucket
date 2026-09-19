using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>
/// One folder's operation lock: held by whatever is writing to the working folder or to head,
/// by any process, for exactly as long as that write takes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why (D-38).</b> The tray's mutex (D-34) stops a second daemon, and nothing else. A
/// <c>sip save</c>, <c>sip sync</c> or <c>sip restore</c> run by hand while the daemon is part
/// way through a cycle, or a second user session pointed at the same folder, used to drive
/// the same working tree at the same moment. Two writers applying into one folder is how a
/// file gets half written and how a conflict copy gets made twice.
/// </para>
/// <para>
/// <b>What it is.</b> <c>.sip/lock</c>, opened sharing nothing. Windows documents that a share
/// mode of 0 "Prevents subsequent open operations on a file or device if they request delete,
/// read, or write access", and that an open whose sharing conflicts with an existing handle
/// fails with <c>ERROR_SHARING_VIOLATION</c> (CreateFileW, parameter <c>dwShareMode</c>:
/// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew). That
/// is a property of the share mode, whatever access the holder asked for, so the handle asks
/// only to read: the lock never needs the file's contents, and nothing is ever written to it.
/// Sharing is checked per handle, not per process, so a second <see cref="SipRepository"/> in
/// this process is refused exactly as another process is, which is also why a nested
/// operation in the same flow must not open it again (see <see cref="SipRepository"/>).
/// </para>
/// <para>
/// <b>Why a crash cannot leave it stuck.</b> The lock is the open handle, not the file.
/// Windows closes every handle a process holds when it ends, however it ends: "All kernel
/// objects are closed", and "open handles to kernel objects are closed automatically when a
/// process terminates" (Terminating a Process:
/// https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process). The
/// file itself stays behind, empty, and means nothing while nobody has it open.
/// </para>
/// <para>
/// <b>How long, and how it relates to the other locks.</b> It is held for one operation,
/// never for the daemon's lifetime, so the command line stays usable while the tray runs.
/// The in-process locks wave 1 added, on <c>peers.json</c>, <c>.sip/head</c> and the ancestry
/// index, stay: they order single reads and writes of one file between the daemon's server
/// and its sync engine, which this lock deliberately does not cover, because the server
/// reads and never takes it. Reading the store while an operation writes it is safe for the
/// two kinds of file the server reads it for. Blocks and snapshots are write-once under
/// content-addressed names and reach those names only by a rename once they are whole
/// (<see cref="Storage.BlobStore.PutAsync"/>,
/// <see cref="SipRepository.WriteSnapshotAsync(Model.Snapshot, CancellationToken)"/>),
/// so a reader finds all of one or none of it; and the server reads each once and answers
/// "not found" when that read finds nothing (<see cref="Storage.BlobStore.TryGetRawAsync"/>,
/// <see cref="SipRepository.TryGetSnapshotAsync(Hashing.ContentHash, CancellationToken)"/>),
/// so one trimmed or collected away after a
/// peer asked for it costs the peer that one answer, not its connection (D-57).
/// </para>
/// <para>
/// A process refused the lock waits a short, bounded time (<see cref="DefaultPatience"/>),
/// longer than <see cref="SharingRetry.Patience"/> so that a scanner glancing at the file is
/// waited out too, and then fails with <see cref="FolderBusyException"/>, naming the holder
/// from the note holders leave in <c>.sip/lock.holder</c> (<see cref="ReadHolder"/>).
/// </para>
/// </remarks>
public sealed class OperationLock : IDisposable
{
    private static readonly TimeSpan FirstPause = TimeSpan.FromMilliseconds(20);
    private static readonly TimeSpan LongestPause = TimeSpan.FromMilliseconds(250);

    private readonly FileStream _handle;
    private bool _disposed;

    private OperationLock(FileStream handle, OperationHolder holder)
    {
        _handle = handle;
        Holder = holder;
    }

    /// <summary>How long a refused process waits for the lock before giving up.</summary>
    public static TimeSpan DefaultPatience { get; } = TimeSpan.FromSeconds(5);

    /// <summary>What this lock was taken for, and by whom.</summary>
    public OperationHolder Holder { get; }

    /// <summary>Takes a folder's lock, waiting up to <paramref name="patience"/>.</summary>
    /// <param name="layout">The folder.</param>
    /// <param name="operation">What the lock is taken for.</param>
    /// <param name="patience">How long to wait while someone else holds it.</param>
    /// <returns>The held lock. Dispose it to release.</returns>
    /// <exception cref="FolderBusyException">Someone else held it for longer than the patience.</exception>
    internal static OperationLock Acquire(RepositoryLayout layout, FolderOperation operation, TimeSpan patience)
    {
        ArgumentNullException.ThrowIfNull(layout);

        var elapsed = Stopwatch.StartNew();
        var pause = FirstPause;
        while (true)
        {
            if (TryOpen(layout, operation, elapsed, patience, out var held))
            {
                return held;
            }

            Thread.Sleep(pause);
            pause = Grow(pause);
        }
    }

    /// <summary>Takes a folder's lock, waiting up to <paramref name="patience"/> without holding a thread.</summary>
    /// <param name="layout">The folder.</param>
    /// <param name="operation">What the lock is taken for.</param>
    /// <param name="patience">How long to wait while someone else holds it.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>The held lock. Dispose it to release.</returns>
    /// <exception cref="FolderBusyException">Someone else held it for longer than the patience.</exception>
    internal static async Task<OperationLock> AcquireAsync(
        RepositoryLayout layout,
        FolderOperation operation,
        TimeSpan patience,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(layout);

        var elapsed = Stopwatch.StartNew();
        var pause = FirstPause;
        while (true)
        {
            if (TryOpen(layout, operation, elapsed, patience, out var held))
            {
                return held;
            }

            await Task.Delay(pause, cancellationToken).ConfigureAwait(false);
            pause = Grow(pause);
        }
    }

    /// <summary>Reads the note the most recent holder of a folder's lock left.</summary>
    /// <param name="layout">The folder.</param>
    /// <returns>The holder, or null when there is no note, it cannot be read, or its process has ended.</returns>
    /// <remarks>
    /// <para>
    /// Advisory, and treated that way. Every holder brings the note up to date the moment it
    /// has the lock and nothing ever deletes it, so it names the current holder whenever the
    /// lock is held, which is the only time it is read: after an acquisition was refused. Two
    /// exceptions name the previous holder instead: the instant between another process
    /// taking the lock and updating the note, and a holder that could not write the note at
    /// all, which carries on with the lock regardless (<c>TryWriteNote</c>).
    /// </para>
    /// <para>
    /// It is rewritten only when it would change, and it carries no time, so a process doing
    /// the same kind of operation again leaves it alone. Rewriting it on every acquisition was
    /// measured on the build machine to slow a burst of operations several times over: the
    /// test that moves head in a tight loop against a reader fell from passing to under a
    /// hundred moves in two seconds, and passed again with the rewrite removed. It is never
    /// deleted, because a deleted name that anything still has open cannot be created again
    /// until that handle closes: "Subsequent calls to CreateFile to open the file fail with
    /// ERROR_ACCESS_DENIED" (DeleteFileW, Remarks:
    /// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew). A
    /// note naming a process that is no longer running is ignored rather than reported: saying
    /// "SippBucket is syncing" about a process that crashed an hour ago would be the kind of
    /// status this project exists not to show.
    /// </para>
    /// </remarks>
    public static OperationHolder? ReadHolder(RepositoryLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);

        var holder = ReadNote(layout);
        return holder is not null && IsRunning(holder.ProcessId) ? holder : null;
    }

    /// <summary>Releases the lock. The holder's note stays; see <see cref="ReadHolder"/>.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _handle.Dispose();
    }

    private static bool TryOpen(
        RepositoryLayout layout,
        FolderOperation operation,
        Stopwatch elapsed,
        TimeSpan patience,
        out OperationLock held)
    {
        FileStream? handle = null;
        try
        {
            try
            {
                handle = new FileStream(layout.LockFile, FileMode.OpenOrCreate, FileAccess.Read, FileShare.None);
            }
            catch (IOException ex) when (SharingRetry.IsSharingViolation(ex))
            {
                if (elapsed.Elapsed >= patience)
                {
                    throw new FolderBusyException(ReadHolder(layout), ex);
                }

                held = null!;
                return false;
            }

            var holder = new OperationHolder
            {
                Operation = operation,
                Program = ProgramName(),
                ProcessId = Environment.ProcessId,
            };

            if (ReadNote(layout) != holder)
            {
                // Whether it could be written changes nothing about holding the lock.
                _ = TryWriteNote(layout, holder);
            }

            held = new OperationLock(handle, holder);
            handle = null;
            return true;
        }
        finally
        {
            // Non-null only when something above threw after the open: released before the
            // failure goes anywhere, since a lock nobody will dispose stays held until the
            // process ends.
            handle?.Dispose();
        }
    }

    /// <summary>Brings the holder note up to date, if it can be written.</summary>
    /// <returns>True when the note now names this holder.</returns>
    /// <remarks>
    /// Not on the operation's path. The lock is the open handle, already held by now, and the
    /// note only tells a process that is refused who to wait for. Failing a save or a sync
    /// that has the folder because the note could not be written, held longer than
    /// <see cref="SharingRetry.Patience"/> by a cloud client or read-only on a shared folder,
    /// would put the advisory half in charge of the half that carries the safety. The cost of
    /// an unwritten note is a message naming whoever held the lock before, while that process
    /// is still running; <see cref="ReadHolder"/> says so.
    /// </remarks>
    private static bool TryWriteNote(RepositoryLayout layout, OperationHolder holder)
    {
        var note = JsonSerializer.Serialize(holder, SipJson.Readable);

        try
        {
            SharingRetry.Run(() => File.WriteAllText(layout.LockHolderFile, note));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>The note as it is on disk, whoever wrote it, or null when there is none to read.</summary>
    private static OperationHolder? ReadNote(RepositoryLayout layout)
    {
        try
        {
            return SharingRetry.Run(() =>
            {
                using var file = new FileStream(
                    layout.LockHolderFile,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                return JsonSerializer.Deserialize<OperationHolder>(file, SipJson.Readable);
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // FileNotFoundException is an IOException: no note is the ordinary case before a
            // folder's first operation, and a note caught mid-write reads as malformed JSON.
            return null;
        }
    }

    private static TimeSpan Grow(TimeSpan pause) => pause * 2 < LongestPause ? pause * 2 : LongestPause;

    private static string ProgramName() =>
        Environment.ProcessPath is { } path ? Path.GetFileNameWithoutExtension(path) : "another program";

    private static bool IsRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            // GetProcessById's documented answer for "no process has this ID".
            return false;
        }
        catch (InvalidOperationException)
        {
            // It exited between being found and being asked.
            return false;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // It exists and belongs to an account this process may not inspect: another
            // user's session over a shared folder, which is one of the cases the lock is for.
            return true;
        }
    }
}

/// <summary>What an operation that holds a folder's lock is doing.</summary>
public enum FolderOperation
{
    /// <summary>Taking a snapshot.</summary>
    Save,

    /// <summary>Applying a peer's changes and moving head.</summary>
    Sync,

    /// <summary>Putting the folder back to a snapshot.</summary>
    Restore,

    /// <summary>Deleting what the storage policy no longer keeps.</summary>
    Collect,

    /// <summary>Setting or removing this copy's passphrase.</summary>
    Passphrase,

    /// <summary>Changing the folder's retention or quota.</summary>
    StoragePolicy,

    /// <summary>Moving head directly.</summary>
    Head,

    /// <summary>Changing one of the folder's own settings in its config.</summary>
    Settings,
}

/// <summary>The note a lock's holder leaves: what it is doing, and which process it is.</summary>
public sealed record OperationHolder
{
    /// <summary>What the lock was taken for.</summary>
    public required FolderOperation Operation { get; init; }

    /// <summary>The holding program's executable name, such as <c>SippBucket</c> or <c>sip</c>.</summary>
    public required string Program { get; init; }

    /// <summary>The holding process.</summary>
    public required int ProcessId { get; init; }

    /// <summary>What the holder is doing, in words, for a message.</summary>
    /// <returns>For example "SippBucket (process 1234) is syncing this folder".</returns>
    public string Describe()
    {
        var doing = Operation switch
        {
            FolderOperation.Save => "saving this folder",
            FolderOperation.Sync => "syncing this folder",
            FolderOperation.Restore => "restoring this folder",
            FolderOperation.Collect => "clearing out this folder's store",
            FolderOperation.Passphrase => "changing this folder's passphrase",
            FolderOperation.StoragePolicy => "changing this folder's storage policy",
            FolderOperation.Settings => "changing this folder's settings",
            _ => "moving this folder's head",
        };

        return string.Create(CultureInfo.InvariantCulture, $"{Program} (process {ProcessId}) is {doing}");
    }
}

/// <summary>
/// Thrown when a folder's operation lock stayed held by someone else for longer than the
/// wait. Nothing was changed.
/// </summary>
/// <remarks>
/// An <see cref="IOException"/>, like <see cref="Sync.WorkingTreeBusyException"/>, so that
/// anything treating an I/O failure as "try again later" keeps doing so. Its own type because
/// the daemon records a busy folder as a skipped cycle rather than a failed one, and the
/// command line names what holds it rather than calling it a file error.
/// </remarks>
public sealed class FolderBusyException : IOException
{
    /// <summary>Creates the exception for a lock that stayed held.</summary>
    /// <param name="holder">Who holds it, when a live holder left a note.</param>
    /// <param name="innerException">The sharing violation that refused the lock.</param>
    public FolderBusyException(OperationHolder? holder, Exception? innerException)
        : base(Explain(holder), innerException)
    {
        Holder = holder;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public FolderBusyException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public FolderBusyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public FolderBusyException()
        : base(Explain(null))
    {
    }

    /// <summary>Who held the lock, when that is known.</summary>
    public OperationHolder? Holder { get; }

    // Without a note from a running process, nothing says the holder is SippBucket at all: a
    // program reading .sip/lock for longer than the wait looks exactly the same from here.
    private static string Explain(OperationHolder? holder) =>
        holder is null
            ? "Something else has this folder's lock (.sip/lock) open right now, usually another SippBucket " +
              "operation; nothing was changed. Try again in a moment."
            : $"{holder.Describe()}; nothing was changed. Try again in a moment.";
}
