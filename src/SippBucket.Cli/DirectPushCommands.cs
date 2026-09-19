using System.Globalization;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Machines;
using SippBucket.Core.Platform;
using SippBucket.Core.Push;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;

namespace SippBucket.Cli;

/// <summary>
/// Direct Push on the command line: <c>sip push</c>, <c>sip inbox</c> and <c>sip quarantine</c>
/// (docs/DIRECT-PUSH.md). Every feature ships in <c>sip</c> first; the window follows.
/// </summary>
/// <remarks>
/// Pushing is per machine, not per folder: the machine named may be paired with any folder this
/// person syncs, the watched folders and the folder the command runs in. Settings changed here are
/// the person's own (<c>push.json</c>) and reach the running daemon on its next timer tick, within
/// half a minute.
/// </remarks>
internal static class DirectPushCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary>One line on Direct Push, for <c>sip status</c>.</summary>
    /// <returns>Whether it is on, and what is in the inbox and the quarantine.</returns>
    public static string StatusLine()
    {
        PushPreferences preferences;
        try
        {
            preferences = PushPreferencesStore.ForThisUser().Load();
        }
        catch (System.Text.Json.JsonException ex)
        {
            return $"Direct Push: {ex.Message}";
        }

        if (!preferences.Enabled)
        {
            return "Direct Push is off. 'sip push on' turns it on.";
        }

        if (!PushInbox.IsUsableRoot(preferences.InboxRoot, out var unusable))
        {
            return $"Direct Push is on, and cannot receive: {unusable}";
        }

        var inbox = new PushInbox(preferences.InboxRoot);
        var waiting = Directory.Exists(inbox.Root) ? Directory.GetFiles(inbox.Root).Length : 0;
        var quarantined = inbox.Quarantine.Inspect().Items.Count(item => item.Present);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"Direct Push is on. Inbox {inbox.Root}: {waiting} file(s), {quarantined} in quarantine.");
    }

    /// <summary><c>sip push</c>: turn Direct Push on or off, show it, or send files.</summary>
    /// <param name="args">What followed <c>push</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> PushAsync(string[] args)
    {
        if (args.Length == 0)
        {
            return Usage("sip push on | off | status | <machine> <file>... [--port <port>] [--anyway]");
        }

        switch (args[0].ToUpperInvariant())
        {
            case "ON" when args.Length == 1:
                return TurnOn();
            case "OFF" when args.Length == 1:
                return TurnOff();
            case "STATUS" when args.Length == 1:
                Console.WriteLine(StatusLine());
                return ExitSuccess;
            default:
                return await SendAsync(args).ConfigureAwait(false);
        }
    }

    /// <summary><c>sip inbox</c>: what arrived, where the inbox is, and the forwarding rules.</summary>
    /// <param name="args">What followed <c>inbox</c>.</param>
    /// <returns>The exit code.</returns>
    public static int Inbox(string[] args)
    {
        var sub = args.Length == 0 ? "LIST" : args[0].ToUpperInvariant();
        return sub switch
        {
            "LIST" when args.Length <= 1 => ListInbox(),
            "FOLDER" => InboxFolder(args[1..]),
            "RULES" => Rules(args[1..]),
            _ => Usage("sip inbox [list] | folder [<path> | --default] | rules [add ... | remove <n>]"),
        };
    }

    /// <summary><c>sip quarantine</c>: list it, release a file from it, or delete one.</summary>
    /// <param name="args">What followed <c>quarantine</c>.</param>
    /// <returns>The exit code.</returns>
    public static int Quarantine(string[] args)
    {
        var sub = args.Length == 0 ? "LIST" : args[0].ToUpperInvariant();
        return sub switch
        {
            "LIST" when args.Length <= 1 => ListQuarantine(),
            "RELEASE" => Release(args[1..]),
            "DELETE" when args.Length == 2 => Delete(args[1]),
            _ => Usage("sip quarantine [list] | release <hash> [--as-sent] [--it-is-a-program] | delete <hash>"),
        };
    }

    private static int TurnOn()
    {
        var preferences = PushPreferencesStore.ForThisUser().Update(current => current with { Enabled = true });
        var machine = MasterConfig.Load();

        Console.WriteLine("Direct Push is on. Your own paired machines can now send files to this one.");
        Console.WriteLine($"  inbox       {preferences.InboxRoot}");
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  port        {machine.Push.Port} (push.sshPort)"));

        if (machine.Problems.FirstOrDefault(problem => problem.Kind == ConfigProblemKind.PortClash) is { } clash)
        {
            Console.WriteLine();
            Console.WriteLine($"It cannot listen yet: {clash.Message}");
        }

        if (PushInbox.ConflictWithSyncedFolders(preferences.InboxRoot, SyncedFolders()) is { } conflict)
        {
            Console.WriteLine();
            Console.WriteLine($"It cannot listen yet: {conflict}. Choose another with 'sip inbox folder <path>'.");
        }

        Console.WriteLine();
        Console.WriteLine("SippBucket picks this up within half a minute. Only machines you said are yours");
        Console.WriteLine("('sip peer owner') can push until team features are on.");
        return ExitSuccess;
    }

    private static int TurnOff()
    {
        PushPreferencesStore.ForThisUser().Update(current => current with { Enabled = false });
        Console.WriteLine("Direct Push is off. SippBucket stops listening for it within half a minute.");
        Console.WriteLine("What is in the inbox and the quarantine stays where it is.");
        return ExitSuccess;
    }

    private static async Task<int> SendAsync(string[] args)
    {
        var machineName = args[0];
        var paths = new List<string>();
        int? port = null;
        var anyway = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i].ToUpperInvariant())
            {
                case "--PORT":
                    if (++i >= args.Length || !int.TryParse(args[i], NumberStyles.None, CultureInfo.InvariantCulture, out var given) ||
                        given is < 1 or > 65535)
                    {
                        return Usage("--port needs the other machine's Direct Push port, 1 to 65535.");
                    }

                    port = given;
                    break;

                case "--ANYWAY":
                    anyway = true;
                    break;

                default:
                    paths.Add(args[i]);
                    break;
            }
        }

        if (paths.Count == 0)
        {
            return Usage("sip push <machine> <file>... : name at least one file to send.");
        }

        var lookup = PairedMachines.FindTarget(SyncedFolders(), ServerCommands.LoadDirectory(), machineName, out var unreadable);
        foreach (var folder in unreadable)
        {
            await Console.Error
                .WriteLineAsync($"sip: the peer list in {folder} cannot be read, so its machines were not searched.")
                .ConfigureAwait(false);
        }

        if (lookup.Outcome == PeerLookupOutcome.Ambiguous)
        {
            await Console.Error
                .WriteLineAsync($"sip: '{machineName}' could mean more than one machine; name one by its device ID:")
                .ConfigureAwait(false);
            foreach (var candidate in lookup.Candidates)
            {
                await Console.Error.WriteLineAsync($"  {candidate.Name,-16} {candidate.DeviceId}").ConfigureAwait(false);
            }

            return ExitUsage;
        }

        if (lookup.Peer is not { } peer)
        {
            return Fail(
                $"'{machineName}' is not a machine paired with any of your folders. 'sip peer list' shows them, " +
                "and 'sip id' your servers by number.");
        }

        var plan = await PushSender.PlanAsync(paths, CancellationToken.None).ConfigureAwait(false);
        foreach (var problem in plan.Problems)
        {
            await Console.Error
                .WriteLineAsync($"sip: {problem.Path} cannot be sent: {problem.Reason}.")
                .ConfigureAwait(false);
        }

        var files = plan.Files.ToList();
        var warned = files.Where(file => file.WillBeQuarantined).ToList();
        if (warned.Count > 0)
        {
            Console.WriteLine($"{peer.Name} will very likely put these in quarantine:");
            foreach (var file in warned)
            {
                Console.WriteLine($"  {file.Name}: {Warning(file.Check)}");
            }

            if (!anyway && !Confirm("Send them anyway?"))
            {
                files.RemoveAll(file => file.WillBeQuarantined);
                Console.WriteLine("They are left out. 'sip push ... --anyway' sends them regardless.");
            }

            Console.WriteLine();
        }

        if (files.Count == 0)
        {
            return plan.Problems.Count > 0 ? ExitFailure : ExitSuccess;
        }

        var target = new PushTarget(peer.Name, peer.DeviceId, peer.Host, port ?? MasterConfig.Load().Push.Port);
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"Pushing {files.Count} file(s), {BucketUsage.Bytes(files.Sum(file => file.Size))}, to {target.Name} ({HostAndPort.Format(target.Host, target.Port)})."));

        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
        var progress = new ProgressLine();
        var batches = await PushSender.SendAsync(
            identity,
            target,
            files,
            PushTuning.ForMachine(MasterConfig.Load()),
            progress,
            result =>
            {
                progress.Clear();
                Console.WriteLine($"  {result.File.Name}: {Describe(result, target.Name)}");
            },
            CancellationToken.None).ConfigureAwait(false);

        progress.Clear();
        return Summarise(batches, target.Name) && plan.Problems.Count == 0 ? ExitSuccess : ExitFailure;
    }

    private static bool Summarise(IReadOnlyList<PushBatchResult> batches, string target)
    {
        var results = batches.SelectMany(batch => batch.Files).ToList();

        if (batches.FirstOrDefault(batch => batch.Refusal != BatchRefusal.None) is { } refused)
        {
            Console.Error.WriteLine($"sip: {target} refused the batch: {refused.Detail}");
        }

        Console.WriteLine();
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{results.Count(r => r.Outcome is FileOutcome.Inbox or FileOutcome.InboxUnrecognised)} in the inbox, " +
            $"{results.Count(r => r.Outcome == FileOutcome.Quarantined)} in quarantine, " +
            $"{results.Count(r => r.Outcome == FileOutcome.Refused)} refused."));

        return batches.All(batch => batch.Refusal == BatchRefusal.None) &&
               results.All(r => r.Outcome != FileOutcome.Refused);
    }

    private static string Describe(PushFileResult result, string target) => result.Outcome switch
    {
        FileOutcome.Inbox => "in the inbox",
        FileOutcome.InboxUnrecognised => "in the inbox, marked type not recognised",
        FileOutcome.Quarantined => $"in quarantine on {target}: {QuarantineWhy(result.Quarantine, result.DetectedType)}",
        _ => $"refused: {PushReceiver.Describe(result.Refusal)}",
    };

    private static string Warning(ContentCheckResult check) => check.Reason switch
    {
        QuarantineReason.ExecutableContent => $"its content is a program ({check.DetectedName})",
        QuarantineReason.ExecutableName => "its name is a type Windows runs or installs",
        QuarantineReason.Mismatch => $"its content is {check.DetectedName}, not what its name says",
        _ => "it will be checked on arrival",
    };

    private static string QuarantineWhy(QuarantineReason reason, uint detected) => reason switch
    {
        QuarantineReason.ExecutableContent => $"its content is a program ({ContentTypes.NameOf(detected)})",
        QuarantineReason.ExecutableName => "its name is a type Windows runs or installs",
        QuarantineReason.Mismatch => $"its content is {ContentTypes.NameOf(detected)}, not what its name says",
        _ => "held for a look",
    };

    private static int ListInbox()
    {
        var preferences = PushPreferencesStore.ForThisUser().Load();
        var inbox = new PushInbox(preferences.InboxRoot);

        Console.WriteLine($"Inbox {inbox.Root}{(preferences.Enabled ? string.Empty : " (Direct Push is off)")}");

        var ledger = inbox.ReadLedger();
        var here = ledger.Entries
            .Where(entry => entry.ForwardedTo is null && File.Exists(Path.Combine(inbox.Root, entry.PlacedName)))
            .GroupBy(entry => entry.PlacedName, StringComparer.OrdinalIgnoreCase)
            .Select(entries => entries.Last())
            .OrderBy(entry => entry.ArrivedUtc)
            .ToList();

        if (here.Count == 0)
        {
            Console.WriteLine("  Nothing that arrived by Direct Push is waiting here.");
        }

        foreach (var entry in here)
        {
            Console.WriteLine(
                $"  {entry.ArrivedUtc.ToLocalTime():yyyy-MM-dd HH:mm}  {entry.PlacedName,-32} from {entry.SenderName,-14} " +
                $"{BucketUsage.Bytes(entry.Size),10}{(entry.Unrecognised ? "  type not recognised" : string.Empty)}");
        }

        var forwarded = ledger.Entries.Count(entry => entry.ForwardedTo is not null);
        if (forwarded > 0)
        {
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  {forwarded} more were forwarded by your rules."));
        }

        if (ledger.UnreadableLines > 0)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"  {ledger.UnreadableLines} line(s) of the inbox's ledger could not be read and are not shown."));
        }

        var quarantined = inbox.Quarantine.Inspect().Items.Count(item => item.Present);
        if (quarantined > 0)
        {
            Console.WriteLine();
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{quarantined} file(s) in quarantine: 'sip quarantine' lists them."));
        }

        return ExitSuccess;
    }

    private static int InboxFolder(string[] args)
    {
        var store = PushPreferencesStore.ForThisUser();

        if (args.Length == 0)
        {
            Console.WriteLine(store.Load().InboxRoot);
            return ExitSuccess;
        }

        if (args.Length != 1)
        {
            return Usage("sip inbox folder [<path> | --default]");
        }

        string? chosen = null;
        if (!string.Equals(args[0], "--default", StringComparison.OrdinalIgnoreCase))
        {
            var full = Path.GetFullPath(args[0]);
            if (!PushInbox.IsUsableRoot(full, out var unusable))
            {
                return Fail(unusable);
            }

            if (PushInbox.ConflictWithSyncedFolders(full, SyncedFolders()) is { } conflict)
            {
                return Fail($"{conflict}. Choose a folder outside every folder SippBucket syncs.");
            }

            chosen = full;
        }

        var preferences = store.Update(current => current with { Inbox = chosen });
        Console.WriteLine($"The inbox is now {preferences.InboxRoot}.");
        Console.WriteLine("Files already in the old inbox, and its quarantine, stay where they are.");
        return ExitSuccess;
    }

    private static int Rules(string[] args)
    {
        var store = PushPreferencesStore.ForThisUser();
        var sub = args.Length == 0 ? "LIST" : args[0].ToUpperInvariant();

        switch (sub)
        {
            case "LIST" when args.Length <= 1:
            {
                var preferences = store.Load();
                var inbox = new PushInbox(preferences.InboxRoot);
                if (preferences.Rules.Count == 0)
                {
                    Console.WriteLine("No forwarding rules: everything that arrives stays in the inbox.");
                    return ExitSuccess;
                }

                for (var index = 0; index < preferences.Rules.Count; index++)
                {
                    var rule = preferences.Rules[index];
                    var broken = InboxRules.IsValid(rule, inbox, out var reason) ? string.Empty : $"  (passed over: {reason})";
                    Console.WriteLine(string.Create(
                        CultureInfo.InvariantCulture,
                        $"  {index + 1}. {DescribeRule(rule)} -> {rule.Destination}{broken}"));
                }

                Console.WriteLine();
                Console.WriteLine("The first rule that matches a file moves it. Other people's files move only by a rule that names them.");
                return ExitSuccess;
            }

            case "ADD":
                return AddRule(store, args[1..]);

            case "REMOVE" when args.Length == 2:
            {
                if (!int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number < 1)
                {
                    return Usage("sip inbox rules remove <n>, where n is the rule's number in 'sip inbox rules'.");
                }

                var removed = false;
                store.Update(current =>
                {
                    if (number > current.Rules.Count)
                    {
                        return current;
                    }

                    removed = true;
                    return current with { Rules = [.. current.Rules.Where((_, index) => index != number - 1)] };
                });

                return removed
                    ? Done(string.Create(CultureInfo.InvariantCulture, $"Removed rule {number}."))
                    : Fail(string.Create(CultureInfo.InvariantCulture, $"There is no rule {number}. 'sip inbox rules' lists them."));
            }

            default:
                return Usage("sip inbox rules [add --to <folder> [--from <machine>] [--type <ext>] [--name <pattern>] | remove <n>]");
        }
    }

    private static int AddRule(PushPreferencesStore store, string[] args)
    {
        string? destination = null, from = null, type = null, pattern = null;

        for (var i = 0; i < args.Length; i++)
        {
            var given = args[i];
            var option = given.ToUpperInvariant();
            if (option is not ("--TO" or "--FROM" or "--TYPE" or "--NAME"))
            {
                return Usage($"'{given}' is not an option of sip inbox rules add.");
            }

            if (++i >= args.Length)
            {
                return Usage($"{given} needs a value.");
            }

            switch (option)
            {
                case "--TO":
                    destination = Path.GetFullPath(args[i]);
                    break;
                case "--FROM":
                    from = args[i];
                    break;
                case "--TYPE":
                    type = args[i].TrimStart('.');
                    break;
                default:
                    pattern = args[i];
                    break;
            }
        }

        if (destination is null)
        {
            return Usage("A rule needs --to <folder>: where the files it matches go.");
        }

        if (from is not null)
        {
            // Stored as the device ID it names, never the name, which two machines can share.
            var lookup = PairedMachines.Find(SyncedFolders(), from, out _);
            if (lookup.Peer is not { } peer)
            {
                return Fail(lookup.Outcome == PeerLookupOutcome.Ambiguous
                    ? $"'{from}' could mean more than one machine; name it by its device ID."
                    : $"'{from}' is not a machine paired with any of your folders.");
            }

            from = peer.DeviceId;
        }

        var rule = new InboxRule { Destination = destination, From = from, Type = type, NamePattern = pattern };
        var preferences = store.Load();
        if (!InboxRules.IsValid(rule, new PushInbox(preferences.InboxRoot), out var reason))
        {
            return Fail($"That rule cannot be kept: {reason}.");
        }

        var updated = store.Update(current => current with { Rules = [.. current.Rules, rule] });
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"Added rule {updated.Rules.Count}: {DescribeRule(rule)} -> {rule.Destination}"));

        if (rule.From is not null && KnownMachines.ForThisUser().OwnerOf(rule.From) != MachineOwner.Mine)
        {
            Console.WriteLine("It names a machine that is not one of your own, so it applies to that person's files too.");
        }

        return ExitSuccess;
    }

    private static string DescribeRule(InboxRule rule)
    {
        var parts = new List<string>();
        if (rule.Type is not null)
        {
            parts.Add($"{rule.Type} files");
        }

        if (rule.NamePattern is not null)
        {
            parts.Add($"named {rule.NamePattern}");
        }

        if (rule.From is not null)
        {
            parts.Add($"from {PairedMachines.NameOf(SyncedFolders(), rule.From) ?? rule.From[..12]}");
        }

        return parts.Count == 0 ? "everything from your own machines" : string.Join(", ", parts);
    }

    private static int ListQuarantine()
    {
        var inbox = new PushInbox(PushPreferencesStore.ForThisUser().Load().InboxRoot);
        var list = inbox.Quarantine.List(DateTimeOffset.UtcNow);

        if (list.Items.Count == 0 && list.UnreadableRecords.Count == 0)
        {
            Console.WriteLine("The quarantine is empty.");
            return ExitSuccess;
        }

        foreach (var item in list.Items)
        {
            var first = item.First;
            Console.WriteLine(
                $"  {item.Record.Hash.ToShortString()}  {first.ArrivedUtc.ToLocalTime():yyyy-MM-dd HH:mm}  {first.SentName,-28} " +
                $"from {first.SenderName,-14} {QuarantineWhy(first.Reason, first.DetectedType)}");

            if (!item.Present)
            {
                Console.WriteLine("                 removed from this machine by something other than SippBucket, most likely the antivirus");
            }
            else if (item.Record.Arrivals.Count > 1)
            {
                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"                 arrived {item.Record.Arrivals.Count} times, the same content each time"));
            }
        }

        foreach (var record in list.UnreadableRecords)
        {
            Console.WriteLine($"  the record {record} cannot be read");
        }

        Console.WriteLine();
        Console.WriteLine("Nothing leaves quarantine by itself. 'sip quarantine release <hash>' brings a file back into");
        Console.WriteLine("the inbox under the name its content matches; 'sip quarantine delete <hash>' removes it for good.");
        return ExitSuccess;
    }

    private static int Release(string[] args)
    {
        string? hash = null;
        var name = ReleaseName.AsDetected;
        var confirmed = false;

        foreach (var arg in args)
        {
            switch (arg.ToUpperInvariant())
            {
                case "--AS-SENT":
                    name = ReleaseName.AsSent;
                    break;
                case "--IT-IS-A-PROGRAM":
                    confirmed = true;
                    break;
                default:
                    if (hash is not null)
                    {
                        return Usage("sip quarantine release <hash> [--as-sent] [--it-is-a-program]");
                    }

                    hash = arg;
                    break;
            }
        }

        if (hash is null)
        {
            return Usage("sip quarantine release <hash> [--as-sent] [--it-is-a-program]");
        }

        var inbox = new PushInbox(PushPreferencesStore.ForThisUser().Load().InboxRoot);
        var result = inbox.Quarantine.Release(hash, name, confirmed, DateTimeOffset.UtcNow);

        return result.Outcome switch
        {
            QuarantineActionOutcome.Done => Done(result.Message),
            QuarantineActionOutcome.NeedsConfirmation => Fail(
                $"{result.Message}{Environment.NewLine}If you are sure, run it again with --it-is-a-program."),
            QuarantineActionOutcome.Ambiguous => Ambiguous(result),
            _ => Fail(result.Message),
        };
    }

    private static int Delete(string hash)
    {
        var inbox = new PushInbox(PushPreferencesStore.ForThisUser().Load().InboxRoot);
        var result = inbox.Quarantine.Delete(hash, DateTimeOffset.UtcNow);

        return result.Outcome switch
        {
            QuarantineActionOutcome.Done => Done(result.Message),
            QuarantineActionOutcome.Ambiguous => Ambiguous(result),
            _ => Fail(result.Message),
        };
    }

    private static int Ambiguous(QuarantineAction result)
    {
        Console.Error.WriteLine($"sip: {result.Message}");
        foreach (var candidate in result.Candidates)
        {
            Console.Error.WriteLine($"  {candidate.Record.Hash}  {candidate.First.SentName}");
        }

        return ExitUsage;
    }

    /// <summary>Every folder this person syncs: the watched folders, and the folder the command runs in.</summary>
    private static List<string> SyncedFolders()
    {
        var folders = WatchedFolders.Load().ToList();

        if (RepositoryLayout.Discover(Directory.GetCurrentDirectory()) is { } here &&
            !folders.Any(folder => string.Equals(FolderPaths.Normalize(folder), FolderPaths.Normalize(here.WorkingRoot), StringComparison.OrdinalIgnoreCase)))
        {
            folders.Add(here.WorkingRoot);
        }

        return folders;
    }

    /// <summary>Asks a yes-or-no question when someone is at the keyboard; with nobody there the answer is no.</summary>
    private static bool Confirm(string question)
    {
        if (Console.IsInputRedirected)
        {
            return false;
        }

        Console.Write($"{question} [y/N] ");
        var answer = Console.ReadLine();
        return string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(answer?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static int Done(string message)
    {
        Console.WriteLine(message);
        return ExitSuccess;
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

    /// <summary>
    /// A progress line redrawn in place at a terminal, and printed at most every few seconds when the
    /// output goes to a file or a pipe, so a log is not a thousand near-identical lines.
    /// </summary>
    private sealed class ProgressLine : IProgress<PushProgress>
    {
        private static readonly TimeSpan Every = TimeSpan.FromSeconds(5);
        private readonly System.Diagnostics.Stopwatch _clock = System.Diagnostics.Stopwatch.StartNew();
        private TimeSpan _last = -Every;
        private int _width;

        public void Report(PushProgress value)
        {
            var percent = value.BytesTotal == 0 ? 100 : (int)(value.BytesSent * 100 / value.BytesTotal);
            var line = string.Create(
                CultureInfo.InvariantCulture,
                $"  {percent,3}%  {BucketUsage.Bytes(value.BytesSent)} of {BucketUsage.Bytes(value.BytesTotal)}  {value.Name}");

            if (Console.IsOutputRedirected)
            {
                if (_clock.Elapsed - _last >= Every || value.BytesSent == value.BytesTotal)
                {
                    _last = _clock.Elapsed;
                    Console.WriteLine(line);
                }

                return;
            }

            Console.Write("\r" + line.PadRight(_width));
            _width = line.Length;
        }

        public void Clear()
        {
            if (_width > 0 && !Console.IsOutputRedirected)
            {
                Console.Write("\r" + new string(' ', _width) + "\r");
                _width = 0;
            }
        }
    }
}
