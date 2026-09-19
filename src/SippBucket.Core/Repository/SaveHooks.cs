using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Hashing;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>A hook could not run, or refused the save.</summary>
/// <remarks>
/// An <see cref="IOException"/> so the boundaries that already turn a folder's I/O failure
/// into a reported, non-fatal result treat a hook's failure the same way.
/// </remarks>
public sealed class HookException : IOException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened, ready to print.</param>
    public HookException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with its cause.</summary>
    /// <param name="message">What happened, ready to print.</param>
    /// <param name="innerException">The cause.</param>
    public HookException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no message.</summary>
    public HookException()
    {
    }
}

/// <summary>One hook: the owner's command, and how long it may take.</summary>
public sealed record HookCommand
{
    /// <summary>The command line, run by <c>cmd.exe</c> in the folder being saved.</summary>
    public required string Command { get; init; }

    /// <summary>
    /// Seconds the command may take, 1 to 600. Past it the command and everything it started
    /// are stopped.
    /// </summary>
    public int DeadlineSeconds { get; init; } = SaveHooks.DefaultDeadlineSeconds;
}

/// <summary>
/// The owner's save hooks: commands run around <c>sip save</c>, from <c>.sip/hooks.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Never on by default, and never anyone else's.</b> No file, no hooks. The file lives in
/// <c>.sip</c>, which never syncs and is never written by a snapshot, so a hook runs on a
/// machine only because the owner of that machine wrote it there — a synced folder cannot
/// carry a command onto another machine. Hooks run as the signed-in user, with no elevation,
/// in the folder being saved.
/// </para>
/// <para>
/// <b>When they run.</b> Around a save of this machine's own changes: <c>sip save</c>, and
/// the daemon's automatic saves. The before-save hook runs first, before anything is
/// scanned; a non-zero exit, or running past its deadline, refuses the save — that is what a
/// before-save hook is for. The after-save hook runs once the snapshot is recorded; its
/// failure is reported and changes nothing, because the save has already happened. Neither
/// runs for a merge sync records, a restore's record, or anything else that is bookkeeping
/// rather than the owner saving: a failing hook must never stop two machines converging.
/// </para>
/// <para>
/// <b>The deadline is not optional.</b> Every hook has one, 30 seconds unless the owner sets
/// it, at most 600. Past it the command and every process it started are stopped, so a hook
/// that hangs cannot wedge the daemon's save loop. A stopped before-save hook refuses the
/// save, loudly; remove or fix the hook and save again.
/// </para>
/// <para>
/// The file is read fresh at each save, and a file that exists but cannot be read refuses
/// the save rather than skipping hooks: a hook that silently did not run is the lie this
/// project does not tell.
/// </para>
/// </remarks>
public sealed class SaveHooks
{
    /// <summary>Seconds a hook may take when the owner does not say.</summary>
    public const int DefaultDeadlineSeconds = 30;

    /// <summary>The most seconds a hook may be given.</summary>
    public const int MaximumDeadlineSeconds = 600;

    /// <summary>The most characters of a hook's output carried into a message.</summary>
    private const int OutputTailLength = 2000;

    private const int CurrentSchema = 1;

    private SaveHooks(HookCommand? beforeSave, HookCommand? afterSave)
    {
        BeforeSave = beforeSave;
        AfterSave = afterSave;
    }

    /// <summary>The hook run before a save scans anything, or null.</summary>
    public HookCommand? BeforeSave { get; }

    /// <summary>The hook run once a snapshot is recorded, or null.</summary>
    public HookCommand? AfterSave { get; }

    /// <summary>True when no hook is set.</summary>
    public bool IsEmpty => BeforeSave is null && AfterSave is null;

    /// <summary>Reads the folder's hooks.</summary>
    /// <param name="layout">The folder's layout.</param>
    /// <returns>The hooks; empty when the file does not exist.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="layout"/> was null.</exception>
    /// <exception cref="HookException">The file exists and is not a hooks file.</exception>
    public static SaveHooks Load(RepositoryLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);

        byte[] bytes;
        try
        {
            bytes = SharingRetry.Run(() => File.ReadAllBytes(layout.HooksFile));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new SaveHooks(null, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new HookException(
                $"The hooks file exists and could not be read, so the save was refused rather " +
                $"than run without the hooks: {ex.Message}", ex);
        }

        StoredFile? stored;
        try
        {
            stored = JsonSerializer.Deserialize<StoredFile>(bytes, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new HookException(
                "The hooks file is not readable JSON, so the save was refused rather than run " +
                $"without the hooks: {ex.Message}. Fix .sip\\hooks.json or delete it.", ex);
        }

        if (stored is null)
        {
            throw new HookException("The hooks file holds no hooks object. Fix .sip\\hooks.json or delete it.");
        }

        return new SaveHooks(Validated(stored.BeforeSave, "beforeSave"), Validated(stored.AfterSave, "afterSave"));
    }

    /// <summary>Writes one hook, keeping the other as it is.</summary>
    /// <param name="layout">The folder's layout.</param>
    /// <param name="beforeSave">True for the before-save hook, false for after-save.</param>
    /// <param name="hook">The hook, or null to remove it.</param>
    /// <returns>The hooks as now stored.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="layout"/> was null.</exception>
    /// <exception cref="HookException">
    /// The file exists and is not a hooks file, or the hook given cannot be one.
    /// </exception>
    public static SaveHooks Write(RepositoryLayout layout, bool beforeSave, HookCommand? hook)
    {
        ArgumentNullException.ThrowIfNull(layout);

        var which = beforeSave ? "beforeSave" : "afterSave";
        var current = Load(layout);
        var replaced = beforeSave
            ? new SaveHooks(Validated(hook, which), current.AfterSave)
            : new SaveHooks(current.BeforeSave, Validated(hook, which));

        var path = layout.HooksFile;
        if (replaced.IsEmpty)
        {
            if (File.Exists(path))
            {
                SharingRetry.Run(() => File.Delete(path));
            }

            return replaced;
        }

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new StoredFile
            {
                Schema = CurrentSchema,
                BeforeSave = replaced.BeforeSave,
                AfterSave = replaced.AfterSave,
            },
            SipJson.Readable);

        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);

            if (File.Exists(path))
            {
                SharingRetry.Run(() => File.Replace(temporary, path, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, path));
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }

        return replaced;
    }

    /// <summary>Runs the before-save hook, when there is one.</summary>
    /// <param name="workingRoot">The folder being saved, the command's working directory.</param>
    /// <param name="repositoryName">The folder's name, for <c>SIP_REPOSITORY</c>.</param>
    /// <param name="message">The save's message, for <c>SIP_MESSAGE</c>.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <exception cref="HookException">The hook failed or overran; the save is refused.</exception>
    public async Task RunBeforeSaveAsync(
        string workingRoot,
        string repositoryName,
        string message,
        CancellationToken cancellationToken)
    {
        if (BeforeSave is not { } hook)
        {
            return;
        }

        var run = await RunAsync(hook, workingRoot, repositoryName, message, snapshotId: null, cancellationToken)
            .ConfigureAwait(false);
        if (run is not null)
        {
            throw new HookException(
                $"The before-save hook {run} The save was refused; fix the hook, or remove it " +
                "with 'sip hooks remove before-save'.");
        }
    }

    /// <summary>Runs the after-save hook, when there is one. Never fails the save.</summary>
    /// <param name="workingRoot">The folder saved, the command's working directory.</param>
    /// <param name="repositoryName">The folder's name, for <c>SIP_REPOSITORY</c>.</param>
    /// <param name="snapshotId">The snapshot recorded, for <c>SIP_SNAPSHOT</c>.</param>
    /// <param name="message">The save's message, for <c>SIP_MESSAGE</c>.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>What went wrong, ready to print, or null when it ran clean or is not set.</returns>
    public async Task<string?> RunAfterSaveAsync(
        string workingRoot,
        string repositoryName,
        ContentHash snapshotId,
        string message,
        CancellationToken cancellationToken)
    {
        if (AfterSave is not { } hook)
        {
            return null;
        }

        var run = await RunAsync(hook, workingRoot, repositoryName, message, snapshotId, cancellationToken)
            .ConfigureAwait(false);
        return run is null ? null : $"The after-save hook {run} The save itself stands.";
    }

    /// <summary>
    /// Runs one hook to its deadline.
    /// </summary>
    /// <returns>
    /// Null when it exited zero; otherwise what happened, phrased to follow "The x hook".
    /// </returns>
    private static async Task<string?> RunAsync(
        HookCommand hook,
        string workingRoot,
        string repositoryName,
        string message,
        ContentHash? snapshotId,
        CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            Arguments = $"/d /s /c \"{hook.Command}\"",
            WorkingDirectory = workingRoot,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        info.Environment["SIP_FOLDER"] = workingRoot;
        info.Environment["SIP_REPOSITORY"] = repositoryName;
        info.Environment["SIP_MESSAGE"] = message;
        if (snapshotId is { } id)
        {
            info.Environment["SIP_SNAPSHOT"] = id.ToString();
        }

        using var process = new Process();
        process.StartInfo = info;

        try
        {
            if (!process.Start())
            {
                return "could not be started.";
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return $"could not be started: {ex.Message}.";
        }

        // Both streams are drained while waiting, so a chatty hook can never fill a pipe
        // and deadlock against its own deadline.
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errors = process.StandardError.ReadToEndAsync(cancellationToken);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(hook.DeadlineSeconds));

        try
        {
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Stop(process);
            await DrainAsync(output, errors).ConfigureAwait(false);
            return string.Create(
                CultureInfo.InvariantCulture,
                $"ran past its {hook.DeadlineSeconds}s deadline and was stopped.");
        }
        catch (OperationCanceledException)
        {
            Stop(process);
            await DrainAsync(output, errors).ConfigureAwait(false);
            throw;
        }

        if (process.ExitCode == 0)
        {
            return null;
        }

        var tail = Tail(await errors.ConfigureAwait(false), await output.ConfigureAwait(false));
        return string.Create(
            CultureInfo.InvariantCulture,
            $"exited {process.ExitCode}.{(tail.Length == 0 ? string.Empty : $" It said: {tail}")}");
    }

    /// <summary>
    /// Waits out the stream reads after a kill, so the process is never disposed under them.
    /// The pipes break when the tree dies, so this is brief.
    /// </summary>
    private static async Task DrainAsync(Task<string> output, Task<string> errors)
    {
        try
        {
            _ = await Task.WhenAll(output, errors).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // What a killed hook was saying is not worth anything: the deadline is the story.
        }
    }

    /// <summary>Stops a process and everything it started, tolerating one that just exited.</summary>
    private static void Stop(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Already gone, or going: the deadline's point is made either way.
        }
    }

    /// <summary>The printable tail of what a hook wrote, errors first.</summary>
    private static string Tail(string errors, string output)
    {
        var combined = string.IsNullOrWhiteSpace(errors) ? output : errors;
        combined = combined.Trim();
        if (combined.Length > OutputTailLength)
        {
            combined = combined[^OutputTailLength..];
        }

        return DisplayText.Printable(combined.ReplaceLineEndings(" "), OutputTailLength);
    }

    /// <summary>Checks a hook can be one, and answers it unchanged.</summary>
    /// <exception cref="HookException">It cannot.</exception>
    private static HookCommand? Validated(HookCommand? hook, string which)
    {
        if (hook is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(hook.Command))
        {
            throw new HookException($"The {which} hook has no command.");
        }

        if (hook.DeadlineSeconds is < 1 or > MaximumDeadlineSeconds)
        {
            throw new HookException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The {which} hook's deadline is {hook.DeadlineSeconds}s; it must be 1 to {MaximumDeadlineSeconds}."));
        }

        return hook;
    }

    private sealed record StoredFile
    {
        public required int Schema { get; init; }

        public HookCommand? BeforeSave { get; init; }

        public HookCommand? AfterSave { get; init; }
    }
}
