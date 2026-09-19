using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Health;

/// <summary>What kind of thing an alert is about.</summary>
public enum AlertKind
{
    /// <summary>A server's faults of one kind reached the day's threshold.</summary>
    Faults,

    /// <summary>A server sent a change that looked like damage, and it was held; the person is asked.</summary>
    MassChange,
}

/// <summary>An answer to an alert that asked.</summary>
public enum AlertChoice
{
    /// <summary>"That was me": the held change is applied, and nothing else happens.</summary>
    ThatWasMe,

    /// <summary>"Not me — keep them out": the change stays held and the server is marked suspect.</summary>
    NotMe,
}

/// <summary>One alert, as the permanent log keeps it.</summary>
public sealed record Alert
{
    /// <summary>Its number in the log, from 1.</summary>
    public required int Id { get; init; }

    /// <summary>When it was raised, in UTC.</summary>
    public required DateTimeOffset Utc { get; init; }

    /// <summary>What it is about.</summary>
    public required AlertKind Kind { get; init; }

    /// <summary>The server, as it was named then: "Server 2 (Dell Inspiron 15 3511)", or the name the person gave another person's machine.</summary>
    public required string Server { get; init; }

    /// <summary>The server's <c>Server.ID#XXX-XXX-XXX</c>, for the person's own machines only.</summary>
    public string? ServerId { get; init; }

    /// <summary>The install the evidence came from: its device ID.</summary>
    public required string Device { get; init; }

    /// <summary>What was seen, in a sentence.</summary>
    public required string What { get; init; }

    /// <summary>What was done about it, in a sentence.</summary>
    public required string Done { get; init; }

    /// <summary>The folder it concerns, when it concerns one.</summary>
    public string? Folder { get; init; }

    /// <summary>The folder's path, for an alert that holds a change there.</summary>
    public string? FolderPath { get; init; }

    /// <summary>The held snapshot's ID, for a mass change.</summary>
    public string? Held { get; init; }

    /// <summary>Whether it waits for an answer: "That was me" or "Not me".</summary>
    public bool Asks { get; init; }
}

/// <summary>An answer given to an alert.</summary>
public sealed record AlertAnswer
{
    /// <summary>The alert answered.</summary>
    public required int Answers { get; init; }

    /// <summary>When, in UTC.</summary>
    public required DateTimeOffset Utc { get; init; }

    /// <summary>The answer.</summary>
    public required AlertChoice Choice { get; init; }
}

/// <summary>What happened to an answer.</summary>
public enum AlertAnswerOutcome
{
    /// <summary>It was recorded.</summary>
    Answered,

    /// <summary>There is no alert with that number.</summary>
    NotFound,

    /// <summary>The alert does not ask anything.</summary>
    DoesNotAsk,

    /// <summary>The alert was answered before; an answer is never changed.</summary>
    AlreadyAnswered,
}

/// <summary>The result of answering an alert.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Alert">The alert, when there is one by that number.</param>
/// <param name="Answer">The answer recorded now, or the earlier one that stands.</param>
public sealed record AlertAnswering(AlertAnswerOutcome Outcome, Alert? Alert, AlertAnswer? Answer);

/// <summary>Every alert in the log, each with its answer when it has one.</summary>
/// <param name="Alerts">The alerts, oldest first, with their answers.</param>
/// <param name="UnreadableLines">Lines that could not be read, which are counted and never guessed at.</param>
public sealed record AlertHistory(IReadOnlyList<(Alert Alert, AlertAnswer? Answer)> Alerts, int UnreadableLines);

/// <summary>
/// The permanent alerts log: every alert and every answer, appended to <c>alerts.jsonl</c>
/// beside the device key, and never truncated or rotated away (docs/PEER-HEALTH.md).
/// </summary>
/// <remarks>
/// <para>
/// One JSON object per line: an alert, or an answer naming the alert it answers. Nothing is
/// ever rewritten, so an answer is a new line and the alert it answers stays as it was raised.
/// It stays on this machine and is never sent anywhere; <c>sip alerts</c> reads it.
/// </para>
/// <para>
/// Appended under a file lock, so the daemon and a command appending at the same moment never
/// share a number or interleave a line. A line cut short by a crash is counted as unreadable
/// and skipped; the next alert takes the number after the last one read.
/// </para>
/// </remarks>
public sealed class AlertLog
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "alerts.jsonl";

    private readonly string _path;

    /// <summary>Creates a log over a file.</summary>
    /// <param name="path">Full path to <c>alerts.jsonl</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public AlertLog(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    /// <summary>The log for the person running this process.</summary>
    /// <returns>The log in the data directory, honouring its override.</returns>
    public static AlertLog ForThisUser() => new(Path.Combine(UserDataDirectory.Resolve(), FileName));

    /// <summary>The file this log appends to.</summary>
    public string FilePath => _path;

    /// <summary>Appends an alert, giving it the next number.</summary>
    /// <param name="alert">The alert; its <see cref="Alert.Id"/> is replaced.</param>
    /// <returns>The alert as logged.</returns>
    /// <exception cref="IOException">The log could not be locked or written.</exception>
    [SuppressMessage(
        "Design",
        "CA1030:Use events where appropriate",
        Justification = "An alert is raised: that is the domain's own verb (docs/PEER-HEALTH.md). " +
                        "This appends to the permanent log; nothing here is an event source.")]
    public Alert Raise(Alert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);

        using var held = Lock();
        var numbered = alert with { Id = LastId(Read().Alerts) + 1 };
        Append(new LogLine { Alert = numbered });
        return numbered;
    }

    /// <summary>Records an answer to an alert that asked and has not been answered.</summary>
    /// <param name="id">The alert's number.</param>
    /// <param name="choice">The answer.</param>
    /// <param name="nowUtc">When.</param>
    /// <returns>What happened: the alert answered, or why nothing was recorded.</returns>
    /// <exception cref="IOException">The log could not be locked or written.</exception>
    public AlertAnswering Answer(int id, AlertChoice choice, DateTimeOffset nowUtc)
    {
        using var held = Lock();
        var history = Read();

        var found = history.Alerts.FirstOrDefault(entry => entry.Alert.Id == id);
        if (found.Alert is null)
        {
            return new AlertAnswering(AlertAnswerOutcome.NotFound, null, null);
        }

        if (!found.Alert.Asks)
        {
            return new AlertAnswering(AlertAnswerOutcome.DoesNotAsk, found.Alert, null);
        }

        if (found.Answer is { } earlier)
        {
            return new AlertAnswering(AlertAnswerOutcome.AlreadyAnswered, found.Alert, earlier);
        }

        var answer = new AlertAnswer { Answers = id, Utc = nowUtc, Choice = choice };
        Append(new LogLine { Answer = answer });
        return new AlertAnswering(AlertAnswerOutcome.Answered, found.Alert, answer);
    }

    /// <summary>Reads every alert and answer.</summary>
    /// <returns>The history, oldest first.</returns>
    /// <exception cref="IOException">The log exists and could not be read.</exception>
    public AlertHistory Read()
    {
        string text;
        try
        {
            text = SharingRetry.Run(() =>
            {
                using var file = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(file, Encoding.UTF8);
                return reader.ReadToEnd();
            });
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new AlertHistory([], 0);
        }

        var alerts = new List<Alert>();
        var answers = new Dictionary<int, AlertAnswer>();
        var unreadable = 0;

        foreach (var line in text.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            LogLine? parsed;
            try
            {
                parsed = JsonSerializer.Deserialize<LogLine>(line, SipJson.Canonical);
            }
            catch (JsonException)
            {
                unreadable++;
                continue;
            }

            if (parsed?.Alert is { } alert)
            {
                alerts.Add(alert);
            }
            else if (parsed?.Answer is { } answer)
            {
                // The first answer stands; a later one could only come from a hand edit.
                answers.TryAdd(answer.Answers, answer);
            }
            else
            {
                unreadable++;
            }
        }

        return new AlertHistory([.. alerts.Select(alert => (alert, answers.GetValueOrDefault(alert.Id)))], unreadable);
    }

    /// <summary>An answer in words.</summary>
    /// <param name="choice">The answer.</param>
    /// <returns>"That was me" or "Not me — keep them out".</returns>
    public static string Describe(AlertChoice choice) => choice switch
    {
        AlertChoice.ThatWasMe => "That was me",
        _ => "Not me — keep them out",
    };

    private static int LastId(IReadOnlyList<(Alert Alert, AlertAnswer? Answer)> alerts) =>
        alerts.Count == 0 ? 0 : alerts.Max(entry => entry.Alert.Id);

    private FileLock Lock()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path) ?? throw new IOException($"{_path} has no folder."));
        return FileLock.Acquire(_path + ".lock", FileLock.DefaultPatience);
    }

    private void Append(LogLine line)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(line, SipJson.Canonical);
        using var file = new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);

        // A line a crash cut short is ended first, so this one starts a line of its own. Written
        // straight after it, the two would read as one damaged line, and this one would be lost.
        var cutShort = false;
        if (file.Length > 0)
        {
            file.Seek(-1, SeekOrigin.End);
            cutShort = file.ReadByte() != '\n';
        }

        // One write per line, then to the disk, so a crash leaves at most one line cut short.
        var start = cutShort ? 1 : 0;
        var withEnd = new byte[start + bytes.Length + 1];
        if (cutShort)
        {
            withEnd[0] = (byte)'\n';
        }

        bytes.CopyTo(withEnd, start);
        withEnd[^1] = (byte)'\n';
        file.Seek(0, SeekOrigin.End);
        file.Write(withEnd);
        file.Flush(flushToDisk: true);
    }

    /// <summary>One line of the log: an alert or an answer.</summary>
    private sealed record LogLine
    {
        public Alert? Alert { get; init; }

        public AlertAnswer? Answer { get; init; }
    }
}
