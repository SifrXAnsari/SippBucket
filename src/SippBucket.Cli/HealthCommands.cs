using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Repository;
using SippBucket.Core.Servers;
using SippBucket.Core.Sync;

namespace SippBucket.Cli;

/// <summary>
/// Peer health on the command line: <c>sip alerts</c>, <c>sip alerts answer</c> and
/// <c>sip peer health</c> (docs/PEER-HEALTH.md). Every feature ships in <c>sip</c> first; the
/// window's alerts and its status-bar indicator read the same files.
/// </summary>
/// <remarks>
/// Guidance, not authority: nothing here fixes, disables or judges another machine. The one
/// thing an answer changes is whether this machine takes one install's changes.
/// </remarks>
internal static class HealthCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary>How many answered or informational alerts <c>sip alerts</c> lists without <c>--all</c>.</summary>
    private const int RecentAlerts = 20;

    /// <summary>How much of a device ID a listing shows: enough to type back.</summary>
    private const int ShortDevice = 12;

    /// <summary><c>sip alerts [--all]</c>, or <c>sip alerts answer &lt;n&gt; me|not-me</c>.</summary>
    /// <param name="args">What followed <c>alerts</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> AlertsAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length == 0)
        {
            return ListAlerts(all: false);
        }

        if (args.Length == 1 && string.Equals(args[0], "--all", StringComparison.OrdinalIgnoreCase))
        {
            return ListAlerts(all: true);
        }

        if (args.Length == 3 && string.Equals(args[0], "answer", StringComparison.OrdinalIgnoreCase))
        {
            if (!int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id < 1)
            {
                return Usage($"'{args[1]}' is not an alert's number: 'sip alerts' lists them.");
            }

            AlertChoice? choice = args[2].ToUpperInvariant() switch
            {
                "ME" => AlertChoice.ThatWasMe,
                "NOT-ME" => AlertChoice.NotMe,
                _ => null,
            };

            return choice is { } chosen
                ? await AnswerAsync(id, chosen).ConfigureAwait(false)
                : Usage("Answer 'me' (that was me: apply it) or 'not-me' (not me: keep it out).");
        }

        return Usage("sip alerts [--all] | sip alerts answer <number> me|not-me");
    }

    /// <summary><c>sip peer health [&lt;server&gt;]</c>, or <c>sip peer health clear &lt;server&gt;</c>.</summary>
    /// <param name="args">What followed <c>peer health</c>.</param>
    /// <returns>The exit code.</returns>
    public static int Peers(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length == 2 && string.Equals(args[0], "clear", StringComparison.OrdinalIgnoreCase))
        {
            return Clear(args[1]);
        }

        if (args.Length > 1)
        {
            return Usage("sip peer health [<server>] | sip peer health clear <server>");
        }

        var records = PeerHealth.ForThisUser().Load();
        var directory = ServerCommands.LoadDirectory();
        var answers = LoadOwnerAnswers();

        if (args.Length == 1)
        {
            var candidates = Candidates(args[0], directory, answers, records);
            if (candidates.Count == 0)
            {
                return Fail($"No machine matches '{args[0]}': 'sip peer health' lists every record, 'sip id' your servers.");
            }

            var devices = candidates.SelectMany(group => group).ToHashSet(StringComparer.OrdinalIgnoreCase);
            records = [.. records.Where(record => devices.Contains(record.Device))];
            if (records.Count == 0)
            {
                Console.WriteLine($"Nothing is recorded about '{args[0]}': it has sent nothing wrong.");
                return ExitSuccess;
            }
        }

        if (records.Count == 0)
        {
            Console.WriteLine("Nothing is recorded: no machine has sent anything wrong, or said anything about itself worth noting.");
            return ExitSuccess;
        }

        // Grouped by server: the installs of one board sit together, numbered servers first.
        var ordered = records
            .OrderBy(record => directory.ServerOf(record.Device) is { } server ? directory.NumberOf(server.Permanent) ?? int.MaxValue : int.MaxValue)
            .ThenBy(record => Name(record.Device, directory, answers), StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.Device, StringComparer.OrdinalIgnoreCase);

        foreach (var record in ordered)
        {
            PrintRecord(record, directory, answers);
        }

        return ExitSuccess;
    }

    private static int ListAlerts(bool all)
    {
        var log = AlertLog.ForThisUser();
        var history = log.Read();
        if (history.Alerts.Count == 0 && history.UnreadableLines == 0)
        {
            Console.WriteLine("No alerts. Anything SippBucket has to tell you about another machine is kept here, for good.");
            return ExitSuccess;
        }

        var waiting = history.Alerts
            .Where(entry => entry.Alert.Asks && entry.Answer is null)
            .OrderByDescending(entry => entry.Alert.Id)
            .ToList();
        var rest = history.Alerts
            .Where(entry => !entry.Alert.Asks || entry.Answer is not null)
            .OrderByDescending(entry => entry.Alert.Id)
            .ToList();
        var shown = all ? rest : rest.Take(RecentAlerts).ToList();

        if (waiting.Count > 0)
        {
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Waiting for your answer: {waiting.Count}"));
            foreach (var (alert, answer) in waiting)
            {
                PrintAlert(alert, answer);
            }

            Console.WriteLine();
        }

        if (shown.Count > 0)
        {
            Console.WriteLine(all ? "Every other alert, newest first" : "Recent alerts, newest first");
            foreach (var (alert, answer) in shown)
            {
                PrintAlert(alert, answer);
            }
        }

        if (rest.Count > shown.Count)
        {
            Console.WriteLine();
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{rest.Count - shown.Count} older alert(s): 'sip alerts --all' shows every one."));
        }

        if (history.UnreadableLines > 0)
        {
            Console.WriteLine();
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{history.UnreadableLines} line(s) of {log.FilePath} could not be read and are not shown.") +
                " The log is never rewritten, so they are still there to look at.");
        }

        return ExitSuccess;
    }

    private static void PrintAlert(Alert alert, AlertAnswer? answer)
    {
        Console.WriteLine();
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"  {alert.Id,4}  {When(alert.Utc)}  {alert.Server}{(alert.ServerId is null ? string.Empty : "  " + alert.ServerId)}"));
        Console.WriteLine($"        {alert.What}");
        Console.WriteLine($"        {alert.Done}");

        if (answer is not null)
        {
            Console.WriteLine($"        Answered {When(answer.Utc)}: {AlertLog.Describe(answer.Choice)}.");
        }
        else if (alert.Asks)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"        Answer with: sip alerts answer {alert.Id} me    or    sip alerts answer {alert.Id} not-me"));
        }
    }

    /// <summary>Records an answer, then does what it says.</summary>
    /// <remarks>
    /// The answer goes to the permanent log first, and is never changed. Giving the same answer
    /// again finishes whatever a failure left undone the first time, because every step after
    /// the log is safe to repeat.
    /// </remarks>
    private static async Task<int> AnswerAsync(int id, AlertChoice choice)
    {
        var answering = AlertLog.ForThisUser().Answer(id, choice, DateTimeOffset.UtcNow);
        if (answering.Alert is not { } alert)
        {
            return Fail(string.Create(CultureInfo.InvariantCulture, $"There is no alert {id}: 'sip alerts' lists them."));
        }

        if (answering.Outcome == AlertAnswerOutcome.DoesNotAsk)
        {
            return Fail(string.Create(CultureInfo.InvariantCulture, $"Alert {id} does not ask anything, so there is nothing to answer."));
        }

        if (answering is { Outcome: AlertAnswerOutcome.AlreadyAnswered, Answer: { } earlier })
        {
            if (earlier.Choice != choice)
            {
                return Fail(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Alert {id} was answered on {When(earlier.Utc)}: {AlertLog.Describe(earlier.Choice)}. An answer is never changed."));
            }

            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"Alert {id} was answered on {When(earlier.Utc)}: {AlertLog.Describe(choice)}. Finishing anything left undone."));
        }
        else
        {
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Recorded for alert {id}: {AlertLog.Describe(choice)}."));
        }

        if (alert.Kind != AlertKind.MassChange)
        {
            return ExitSuccess;
        }

        return choice == AlertChoice.NotMe
            ? KeepOut(alert)
            : await ApplyAsync(alert).ConfigureAwait(false);
    }

    /// <summary>"Not me": the install is marked suspect, and the change stays held for good.</summary>
    /// <remarks>
    /// Two protections, each tried whatever happens to the other: the mark stops every change
    /// from the install in every folder, and the held change's answer keeps that one change out
    /// even while the mark cannot be written.
    /// </remarks>
    private static int KeepOut(Alert alert)
    {
        var failed = false;
        var health = PeerHealth.ForThisUser();
        try
        {
            if (!health.IsSuspect(alert.Device))
            {
                var reason = alert.Folder is { } folder
                    ? string.Create(CultureInfo.InvariantCulture, $"you said the change it sent to '{folder}' was not you (alert {alert.Id})")
                    : string.Create(CultureInfo.InvariantCulture, $"you said a change it sent was not you (alert {alert.Id})");
                health.MarkSuspect(alert.Device, reason, alert.Id, DateTimeOffset.UtcNow);
            }

            Console.WriteLine($"No change from {alert.Server} is taken, in any folder, until you say otherwise:");
            Console.WriteLine($"  sip peer health clear {Short(alert.Device)}");
            Console.WriteLine("Your other machines go on syncing with each other and with this one.");
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            Console.Error.WriteLine($"sip: {alert.Server} could not be marked suspect: {ex.Message}");
            failed = true;
        }

        if (alert.FolderPath is not { } folderPath || !Directory.Exists(folderPath))
        {
            Console.WriteLine($"The folder the change was held in, {alert.FolderPath ?? alert.Folder}, is not there any more.");
            return failed ? ExitFailure : ExitSuccess;
        }

        try
        {
            using var repository = CommandLine.OpenFolder(folderPath);
            repository.Held.Answer(alert.Id, HeldAnswer.NotMe, DateTimeOffset.UtcNow);
            var change = repository.Held.Load().LastOrDefault(held => held.Alert == alert.Id);
            if (change is { Answer: HeldAnswer.NotMe })
            {
                Console.WriteLine($"The change stays in '{repository.Config.Name}' as it was held: kept as evidence, and never applied.");
            }
            else
            {
                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{repository.Config.Name}' has no change waiting on alert {alert.Id} any more."));
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            Console.Error.WriteLine($"sip: the answer could not be recorded in {folderPath}: {ex.Message}");
            failed = true;
        }

        if (failed)
        {
            Console.Error.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"sip: once the problem is mended, 'sip alerts answer {alert.Id} not-me' again finishes the rest."));
            return ExitFailure;
        }

        return ExitSuccess;
    }

    /// <summary>"That was me": the change is applied, now if its server answers, or at the next sync with it.</summary>
    private static async Task<int> ApplyAsync(Alert alert)
    {
        if (alert.FolderPath is not { } folderPath || !Directory.Exists(folderPath))
        {
            return Fail($"The folder the change was held in, {alert.FolderPath ?? alert.Folder}, is not there any more, so there is nothing to apply.");
        }

        using var repository = CommandLine.OpenFolder(folderPath);
        var name = repository.Config.Name;
        repository.Held.Answer(alert.Id, HeldAnswer.ThatWasMe, DateTimeOffset.UtcNow);

        var change = repository.Held.Load().LastOrDefault(held => held.Alert == alert.Id);
        if (change is null)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"'{name}' has no change waiting on alert {alert.Id} any more. If a newer one was held, 'sip alerts' asks about it."));
            return ExitSuccess;
        }

        if (change.AppliedUtc is { } applied)
        {
            Console.WriteLine($"It was applied to '{name}' on {When(applied)}.");
            return ExitSuccess;
        }

        if (change.Answer != HeldAnswer.ThatWasMe)
        {
            return Fail(string.Create(
                CultureInfo.InvariantCulture,
                $"{repository.Layout.HeldFile} records a different answer to alert {alert.Id}, so nothing is applied."));
        }

        var peer = repository.Peers.Load().FirstOrDefault(candidate => DeviceIdentity.IsSameDevice(candidate.DeviceId, change.Device));
        if (peer is null)
        {
            return Fail(
                $"{alert.Server} is not paired with '{name}' any more, so its change cannot be fetched. " +
                "The answer is kept: it applies if the two are paired again.");
        }

        Console.WriteLine($"Applying it to '{name}' now.");
        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
        var machine = MasterConfig.Load();
        var engine = new SyncEngine(repository, identity, Console.WriteLine, machine.Sync)
        {
            Servers = ServerCommands.Exchange(identity, machine),
        };

        var result = await engine.SyncOneAsync(peer).ConfigureAwait(false);
        Console.WriteLine(result.Summary);
        if (result.Outcome == SyncOutcome.Held)
        {
            Console.WriteLine("'sip alerts' shows what is waiting.");
        }
        else if (!result.Succeeded)
        {
            Console.WriteLine("The answer stands: the change is applied at the next sync with that machine.");
        }

        return ExitSuccess;
    }

    private static int Clear(string typed)
    {
        var health = PeerHealth.ForThisUser();
        var directory = ServerCommands.LoadDirectory();
        var answers = LoadOwnerAnswers();

        var candidates = Candidates(typed, directory, answers, health.Load());
        if (candidates.Count == 0)
        {
            return Fail($"No machine matches '{typed}': 'sip peer health' lists every record.");
        }

        // Taking a machine's changes again is never done on a guess.
        if (candidates.Count > 1)
        {
            Console.Error.WriteLine($"sip: '{typed}' matches more than one machine. Name one by its install:");
            foreach (var device in candidates.SelectMany(group => group))
            {
                Console.Error.WriteLine($"  {Short(device)}  {Name(device, directory, answers)}");
            }

            return ExitFailure;
        }

        var cleared = 0;
        foreach (var device in candidates[0])
        {
            if (health.ClearSuspect(device) is { } mark)
            {
                cleared++;
                Console.WriteLine($"{Name(device, directory, answers)}: its changes are taken again. It was marked on {When(mark.Since)}: {mark.Reason}.");
            }
        }

        if (cleared == 0)
        {
            Console.WriteLine($"'{typed}' was not marked suspect, so nothing changed.");
            return ExitSuccess;
        }

        Console.WriteLine("A change you said was not you stays held as it was. If it is offered again, you are asked again.");
        return ExitSuccess;
    }

    private static void PrintRecord(PeerHealthRecord record, ServerDirectory directory, IReadOnlyList<KnownMachine> answers)
    {
        var server = directory.ServerOf(record.Device);
        Console.WriteLine();
        Console.WriteLine(
            $"{Name(record.Device, directory, answers)}{(server is null ? string.Empty : "   " + server.Id)}   install {Short(record.Device)}");

        if (record.Suspect is { } suspect)
        {
            Console.WriteLine($"  SUSPECT since {When(suspect.Since)}: {suspect.Reason}.");
            Console.WriteLine($"  No change of its is taken. 'sip peer health clear {Short(record.Device)}' takes them again.");
        }

        if (record.Faults.Count > 0)
        {
            Console.WriteLine("  What it did (strong evidence):");
            var now = DateTimeOffset.UtcNow;
            foreach (var tally in record.Faults.OrderByDescending(tally => tally.Last))
            {
                var lastDay = tally.Recent.Count(when => now - when < TimeSpan.FromDays(1));
                var alerted = HealthFaults.IsAlerted(tally.Fault) ? string.Empty : " (recorded, never alerted)";
                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"    {tally.Count} {HealthFaults.Describe(tally.Fault)}: {lastDay} in the last day, the last on {When(tally.Last)}{alerted}"));
            }

            Console.WriteLine("    The latest:");
            foreach (var latest in Enumerable.Reverse(record.Events.TakeLast(3).ToList()))
            {
                var folder = latest.Folder is null ? string.Empty : $" in '{latest.Folder}'";
                Console.WriteLine($"      {When(latest.Utc)}{folder}: {latest.Detail}");
            }
        }

        if (record.Report is { Findings.Count: > 0 } report)
        {
            Console.WriteLine("  What it says about itself (weak evidence: a machine can be wrong, or lie, about itself):");
            foreach (var finding in report.Findings)
            {
                Console.WriteLine($"    {finding}");
            }

            Console.WriteLine($"    (as of {When(report.Utc)})");
        }
        else if (record.Faults.Count == 0 && record.Suspect is null)
        {
            Console.WriteLine("  Nothing wrong seen, and nothing it says about itself is out of range.");
        }
    }

    /// <summary>
    /// The machines a person's words could mean, one group each: a server's installs, by number,
    /// Server.ID or label; otherwise each device by the name the person gave it or by the start
    /// of its ID.
    /// </summary>
    private static List<string[]> Candidates(
        string typed,
        ServerDirectory directory,
        IReadOnlyList<KnownMachine> answers,
        IReadOnlyList<PeerHealthRecord> records)
    {
        var servers = directory.Find(typed);
        if (servers.Count > 0)
        {
            return [.. servers.Select(server => server.Installs.Select(install => install.Device).ToArray())];
        }

        var byName = answers
            .Where(machine => string.Equals(machine.Name, typed, StringComparison.OrdinalIgnoreCase))
            .Select(machine => machine.DeviceId);
        var byId = typed.Length >= PeerRegistry.MinimumDeviceIdPrefixLength
            ? records.Select(record => record.Device).Where(device => device.StartsWith(typed, StringComparison.OrdinalIgnoreCase))
            : [];

        return [.. byName.Concat(byId).Distinct(StringComparer.OrdinalIgnoreCase).Select(device => new[] { device })];
    }

    private static string Name(string device, ServerDirectory directory, IReadOnlyList<KnownMachine> answers) =>
        directory.NameOf(device) ?? KnownMachines.Find(answers, device)?.Name ?? Short(device);

    private static string Short(string device) => device.Length <= ShortDevice ? device : device[..ShortDevice];

    private static string When(DateTimeOffset utc) =>
        utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    /// <summary>The names the person gave machines, or none, said, when the file cannot be read.</summary>
    /// <remarks>Names only label a listing and widen a match; losing them makes nothing less safe.</remarks>
    private static IReadOnlyList<KnownMachine> LoadOwnerAnswers()
    {
        try
        {
            return KnownMachines.ForThisUser().Load();
        }
        catch (JsonException ex)
        {
            Console.Error.WriteLine($"sip: {ex.Message}");
            return [];
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitFailure;
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitUsage;
    }
}
