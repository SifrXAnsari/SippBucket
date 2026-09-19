using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Push;

/// <summary>
/// The person's own Direct Push settings: whether it is on, where the inbox is, and the
/// forwarding rules.
/// </summary>
/// <remarks>
/// The person's settings, kept per user and set with <c>sip push</c> and <c>sip inbox</c> (and
/// later the window), unlike the master config, which is the machine's limits
/// (docs/DIRECT-PUSH.md, rule 5).
/// </remarks>
public sealed record PushPreferences
{
    /// <summary>The schema this build writes.</summary>
    public int Schema { get; init; } = PushPreferencesStore.CurrentSchema;

    /// <summary>Whether Direct Push is on. Off until the person turns it on.</summary>
    public bool Enabled { get; init; }

    /// <summary>The inbox folder the person chose, or null for the default.</summary>
    public string? Inbox { get; init; }

    /// <summary>The forwarding rules, in order: the first that applies wins.</summary>
    public IReadOnlyList<InboxRule> Rules { get; init; } = [];

    /// <summary>The inbox folder in effect: the person's choice, or <c>SippBucket Inbox</c> in their profile.</summary>
    /// <remarks>Worked out, never stored: the default follows the profile it is read in.</remarks>
    [JsonIgnore]
    public string InboxRoot => Inbox ?? PushInbox.DefaultRoot();
}

/// <summary>
/// Reads and writes <c>push.json</c>, the person's Direct Push settings, beside the device key.
/// </summary>
/// <remarks>
/// <para>
/// Missing, it reads as the defaults: off, the default inbox, no rules. A file that cannot be read
/// is reported, never guessed at: <see cref="Load"/> throws a <see cref="JsonException"/> naming
/// it, and the daemon then keeps Direct Push off, which is the safe answer, and says why. A file
/// written by a newer build is read as far as this build understands it and never rewritten by
/// this one, so nothing the newer build recorded is lost.
/// </para>
/// <para>
/// Written beside itself and swapped in whole, like every other settings file here, so it is
/// always the old settings or the new ones.
/// </para>
/// </remarks>
public sealed class PushPreferencesStore
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "push.json";

    /// <summary>The schema this build writes, and the newest it can rewrite without loss.</summary>
    public const int CurrentSchema = 1;

    /// <summary>One gate per file, shared by every store over it in this process.</summary>
    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);

    private readonly object _gate;

    /// <summary>Creates a store over a file.</summary>
    /// <param name="path">Full path to <c>push.json</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public PushPreferencesStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        FilePath = path;
        _gate = Gates.GetOrAdd(Path.GetFullPath(path), static _ => new object());
    }

    /// <summary>The file this store reads and writes.</summary>
    public string FilePath { get; }

    /// <summary>The store for the person running this process.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static PushPreferencesStore ForThisUser() => new(Path.Combine(UserDataDirectory.Resolve(), FileName));

    /// <summary>Reads the settings.</summary>
    /// <returns>The settings; the defaults when there is no file yet.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public PushPreferences Load()
    {
        lock (_gate)
        {
            return Read();
        }
    }

    /// <summary>Changes the settings: reads them, applies a change, and writes the result.</summary>
    /// <param name="change">The change.</param>
    /// <returns>The settings as written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="change"/> was null.</exception>
    /// <exception cref="JsonException">The file cannot be read, so it is not overwritten.</exception>
    /// <exception cref="InvalidOperationException">
    /// The file was written by a newer build, which this one would lose information from by
    /// rewriting it.
    /// </exception>
    public PushPreferences Update(Func<PushPreferences, PushPreferences> change)
    {
        ArgumentNullException.ThrowIfNull(change);

        lock (_gate)
        {
            var current = Read();
            if (current.Schema > CurrentSchema)
            {
                throw new InvalidOperationException(
                    $"{FilePath} was written by a newer SippBucket (schema {current.Schema.ToString(CultureInfo.InvariantCulture)}), " +
                    "and this one would lose what that version recorded by rewriting it. Update SippBucket, then try " +
                    "again. Nothing was changed.");
            }

            var changed = change(current) with { Schema = CurrentSchema };
            Write(changed);
            return changed;
        }
    }

    private PushPreferences Read()
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(FilePath));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new PushPreferences();
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return new PushPreferences();
        }

        PushPreferences? preferences;
        try
        {
            preferences = JsonSerializer.Deserialize<PushPreferences>(json, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new JsonException(
                $"{FilePath} cannot be read ({ex.Message}). Until it is mended or deleted, Direct Push stays off " +
                "and nothing is written to it.",
                ex);
        }

        return preferences is { Rules: not null }
            ? preferences
            : throw new JsonException(
                $"{FilePath} holds no Direct Push settings. Until it is mended or deleted, Direct Push stays off " +
                "and nothing is written to it.");
    }

    private void Write(PushPreferences preferences)
    {
        var directory = Path.GetDirectoryName(FilePath)
            ?? throw new InvalidOperationException($"{FilePath} has no directory.");
        Directory.CreateDirectory(directory);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(preferences, SipJson.Readable);
        var temporary = $"{FilePath}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);

            if (File.Exists(FilePath))
            {
                SharingRetry.Run(() => File.Replace(temporary, FilePath, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, FilePath));
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }
}
