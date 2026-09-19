using System.Globalization;
using SippBucket.Core.Hashing;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;

namespace SippBucket.Cli;

/// <summary>
/// The power-user commands that act: <c>sip tag</c>, <c>sip bisect</c>, <c>sip verify</c>
/// and <c>sip hooks</c>.
/// </summary>
internal static class PowerCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary>Subcommand words <c>sip tag</c> keeps for itself, so no tag can shadow one.</summary>
    private static readonly string[] ReservedTagWords = ["remove", "list"];

    /// <summary><c>sip tag</c>: list, add, remove.</summary>
    /// <param name="args">What followed <c>tag</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> TagAsync(string[] args)
    {
        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());

        if (args.Length == 0 || (args.Length == 1 && string.Equals(args[0], "list", StringComparison.OrdinalIgnoreCase)))
        {
            return ListTags(repository);
        }

        if (string.Equals(args[0], "remove", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Length != 2)
            {
                return Usage("sip tag remove <name> - one tag by name.");
            }

            return repository.Tags.Remove(args[1])
                ? Say($"Removed tag '{DisplayText.Printable(args[1], TagStore.MaximumNameLength)}'. " +
                      "What it kept is reclaimable at the next collection, unless something else keeps it.")
                : Fail($"There is no tag called '{DisplayText.Printable(args[1], TagStore.MaximumNameLength)}'. 'sip tag' lists them.");
        }

        if (args.Length > 2)
        {
            return Usage("sip tag [<name> [<snapshot>]] | sip tag remove <name>");
        }

        var name = args[0];
        if (ReservedTagWords.Any(word => string.Equals(word, name, StringComparison.OrdinalIgnoreCase)))
        {
            return Usage($"'{name}' is a subcommand of sip tag, so it cannot be a tag's name.");
        }

        if (!TagStore.IsValidName(name, out var why))
        {
            return Fail(why);
        }

        var (id, problem) = await HistoryCommands
            .ResolveAsync(repository, args.Length == 2 ? args[1] : "head")
            .ConfigureAwait(false);
        if (problem is not null)
        {
            return Fail(problem);
        }

        var tag = repository.Tags.Add(name, id, DateTimeOffset.UtcNow);
        Console.WriteLine(
            $"Tagged {tag.SnapshotId.ToShortString()} as '{DisplayText.Printable(tag.Name, TagStore.MaximumNameLength)}'.");
        Console.WriteLine("Tags are per machine and never sync. This snapshot now survives retention here");
        Console.WriteLine("for as long as the tag exists.");
        return ExitSuccess;
    }

    private static int ListTags(SipRepository repository)
    {
        var tags = repository.Tags.Load();
        if (tags.Count == 0)
        {
            Console.WriteLine("No tags. 'sip tag <name> [<snapshot>]' makes one; it defaults to head.");
            return ExitSuccess;
        }

        foreach (var tag in tags)
        {
            var held = repository.HasSnapshot(tag.SnapshotId)
                ? string.Empty
                : "  (snapshot not held here!)";
            Console.WriteLine(
                $"{DisplayText.Printable(tag.Name, TagStore.MaximumNameLength),-24}  " +
                $"{tag.SnapshotId.ToShortString()}  " +
                $"{tag.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}{held}");
        }

        Console.WriteLine();
        Console.WriteLine("Tags are per machine and never sync; a tagged snapshot survives retention here.");
        return ExitSuccess;
    }

    /// <summary><c>sip bisect</c>: find the first snapshot that carries a problem, by halving.</summary>
    /// <param name="args">What followed <c>bisect</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> BisectAsync(string[] args)
    {
        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());
        var store = new BisectStore(repository.Layout.BisectFile);

        var sub = args.Length == 0 ? "STATUS" : args[0].ToUpperInvariant();
        switch (sub)
        {
            case "START":
            {
                if (args.Length != 3)
                {
                    return Usage("sip bisect start <bad> <good> - the snapshot with the problem, then one without.");
                }

                if (store.Load() is not null)
                {
                    return Fail("A bisect is already in progress. 'sip bisect' shows it; 'sip bisect reset' ends it.");
                }

                var (bad, badProblem) = await HistoryCommands.ResolveAsync(repository, args[1]).ConfigureAwait(false);
                if (badProblem is not null)
                {
                    return Fail(badProblem);
                }

                var (good, goodProblem) = await HistoryCommands.ResolveAsync(repository, args[2]).ConfigureAwait(false);
                if (goodProblem is not null)
                {
                    return Fail(goodProblem);
                }

                var state = new BisectState
                {
                    Bad = bad,
                    Good = [good],
                    StartedAtHead = repository.GetHead(),
                    StartedUtc = DateTimeOffset.UtcNow,
                };
                store.Save(state);
                return await PrintPlanAsync(repository, state).ConfigureAwait(false);
            }

            case "GOOD":
            case "BAD":
            {
                if (args.Length != 2)
                {
                    return Usage($"sip bisect {sub.ToLowerInvariant()} <snapshot> - name the snapshot you tested.");
                }

                if (store.Load() is not { } state)
                {
                    return Fail("No bisect is in progress. 'sip bisect start <bad> <good>' begins one.");
                }

                var (id, problem) = await HistoryCommands.ResolveAsync(repository, args[1]).ConfigureAwait(false);
                if (problem is not null)
                {
                    return Fail(problem);
                }

                state = sub == "BAD"
                    ? state with { Bad = id }
                    : state with { Good = [.. state.Good, id] };
                store.Save(state);
                return await PrintPlanAsync(repository, state).ConfigureAwait(false);
            }

            case "RESET":
            {
                // A damaged bisect file is exactly what reset is the remedy for, so the
                // load failing must not stop the delete.
                BisectState? state;
                var damaged = false;
                try
                {
                    state = store.Load();
                }
                catch (FormatException)
                {
                    state = null;
                    damaged = true;
                }

                if (state is null && !damaged)
                {
                    return Fail("No bisect is in progress.");
                }

                _ = store.Clear();
                Console.WriteLine(damaged ? "Bisect ended; its file was damaged and is deleted." : "Bisect ended.");
                if (state is not null && !state.StartedAtHead.IsEmpty)
                {
                    Console.WriteLine(
                        $"Head when it started was {state.StartedAtHead.ToShortString()}; " +
                        $"'sip restore {state.StartedAtHead.ToShortString()}' goes back there.");
                }

                return ExitSuccess;
            }

            case "STATUS":
            {
                if (store.Load() is not { } state)
                {
                    Console.WriteLine("No bisect is in progress. 'sip bisect start <bad> <good>' begins one:");
                    Console.WriteLine("mark the newest snapshot where something is wrong, and any snapshot where");
                    Console.WriteLine("it was still right. Each round names the snapshot to test next.");
                    return ExitSuccess;
                }

                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Bisect started {state.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm}: " +
                    $"bad {state.Bad.ToShortString()}, good {state.Good.Count} mark(s)."));
                return await PrintPlanAsync(repository, state).ConfigureAwait(false);
            }

            default:
                return Usage("sip bisect [status] | start <bad> <good> | good <snapshot> | bad <snapshot> | reset");
        }
    }

    /// <summary>Prints where the marks leave the search, and what to do next.</summary>
    private static async Task<int> PrintPlanAsync(SipRepository repository, BisectState state)
    {
        var plan = Bisect.Plan(repository.Ancestry, repository.HasSnapshot, state);

        if (!plan.Culprit.IsEmpty)
        {
            Console.WriteLine($"First bad snapshot: {plan.Culprit}");
            if (repository.HasSnapshot(plan.Culprit))
            {
                var snapshot = await repository.GetSnapshotAsync(plan.Culprit).ConfigureAwait(false);
                var message = string.IsNullOrWhiteSpace(snapshot.Message) ? "(no message)" : snapshot.Message;
                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"  {snapshot.CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm}  " +
                    $"{snapshot.DeviceId[..Math.Min(8, snapshot.DeviceId.Length)]}  {DisplayText.Printable(message, 200)}"));
            }

            Console.WriteLine("'sip bisect reset' when you are done with it.");
            return ExitSuccess;
        }

        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{plan.Suspects.Count} snapshot(s) suspect; about {plan.StepsLeft} mark(s) to go."));

        if (plan.Next.IsEmpty)
        {
            Console.WriteLine("No suspect but the bad snapshot itself is held on this machine, so the range");
            Console.WriteLine("cannot be narrowed further from here. 'sip bisect reset' ends the search.");
            return ExitFailure;
        }

        var next = plan.Next.ToShortString();
        Console.WriteLine($"Test {next}:");
        Console.WriteLine($"  sip restore {next}");
        Console.WriteLine("  ...check your files...");
        Console.WriteLine($"  sip bisect good {next}   or   sip bisect bad {next}");
        Console.WriteLine("Restoring keeps any unsaved work aside, as it always does.");
        return ExitSuccess;
    }

    /// <summary><c>sip verify</c>: read everything back and check it against its own hashes.</summary>
    /// <param name="args">What followed <c>verify</c>.</param>
    /// <returns>The exit code: 0 when the store is intact.</returns>
    public static async Task<int> VerifyAsync(string[] args)
    {
        if (args.Length != 0)
        {
            return Usage("sip verify takes no options: it always checks everything.");
        }

        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());

        var lastPhase = string.Empty;
        var report = await StoreVerifier.VerifyAsync(
            repository,
            progress =>
            {
                if (!string.Equals(progress.Phase, lastPhase, StringComparison.Ordinal))
                {
                    lastPhase = progress.Phase;
                    Console.WriteLine(string.Create(
                        CultureInfo.InvariantCulture,
                        $"Checking {progress.Total} {progress.Phase}..."));
                }
            }).ConfigureAwait(false);

        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"Checked {report.SnapshotsChecked} snapshot(s) and {report.BlocksChecked} block(s)."));

        if (report.UnreferencedBlocks > 0)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{report.UnreferencedBlocks} block(s) nothing refers to - reclaimable by 'sip bucket collect', not damage."));
        }

        if (report.IsClean)
        {
            Console.WriteLine("Everything reads back as what its name promises.");
            return ExitSuccess;
        }

        Console.WriteLine();
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{report.Problems.Count} problem(s):"));
        foreach (var problem in report.Problems.Take(100))
        {
            Console.WriteLine($"  {problem.What}");
        }

        if (report.Problems.Count > 100)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"  ... and {report.Problems.Count - 100} more"));
        }

        Console.WriteLine();
        Console.WriteLine("Nothing was repaired: the repair for a damaged block is fetching it again from");
        Console.WriteLine("a peer at the next sync, and a damaged snapshot is worth keeping as evidence.");
        return ExitFailure;
    }

    /// <summary><c>sip hooks</c>: show, set, remove and test the owner's save hooks.</summary>
    /// <param name="args">What followed <c>hooks</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> HooksAsync(string[] args)
    {
        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());

        if (args.Length == 0)
        {
            return ShowHooks(repository);
        }

        switch (args[0].ToUpperInvariant())
        {
            case "SET":
            {
                if (args.Length < 3 || WhichHook(args[1]) is not { } before)
                {
                    return Usage("sip hooks set before-save|after-save <command...> [--deadline <seconds>]");
                }

                var deadline = SaveHooks.DefaultDeadlineSeconds;
                var parts = new List<string>();
                for (var i = 2; i < args.Length; i++)
                {
                    if (string.Equals(args[i], "--deadline", StringComparison.OrdinalIgnoreCase))
                    {
                        if (++i >= args.Length ||
                            !int.TryParse(args[i], CultureInfo.InvariantCulture, out deadline))
                        {
                            return Usage("--deadline needs a number of seconds.");
                        }
                    }
                    else
                    {
                        parts.Add(args[i]);
                    }
                }

                if (parts.Count == 0)
                {
                    return Usage("sip hooks set needs the command to run.");
                }

                var hook = new HookCommand
                {
                    Command = string.Join(' ', parts),
                    DeadlineSeconds = deadline,
                };
                _ = SaveHooks.Write(repository.Layout, before, hook);

                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"The {args[1].ToLowerInvariant()} hook now runs: {DisplayText.Printable(hook.Command, 500)}"));
                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Deadline {hook.DeadlineSeconds}s. It runs as you, in this folder, on 'sip save' and the"));
                Console.WriteLine("daemon's automatic saves - never on a merge sync records. 'sip hooks test' tries it now.");
                return ExitSuccess;
            }

            case "REMOVE":
            {
                if (args.Length != 2 || WhichHook(args[1]) is not { } before)
                {
                    return Usage("sip hooks remove before-save|after-save");
                }

                var had = before ? SaveHooks.Load(repository.Layout).BeforeSave : SaveHooks.Load(repository.Layout).AfterSave;
                if (had is null)
                {
                    return Fail($"No {args[1].ToLowerInvariant()} hook is set.");
                }

                _ = SaveHooks.Write(repository.Layout, before, null);
                Console.WriteLine($"Removed the {args[1].ToLowerInvariant()} hook.");
                return ExitSuccess;
            }

            case "TEST":
            {
                if (args.Length != 2 || WhichHook(args[1]) is not { } before)
                {
                    return Usage("sip hooks test before-save|after-save");
                }

                var hooks = SaveHooks.Load(repository.Layout);
                if ((before ? hooks.BeforeSave : hooks.AfterSave) is null)
                {
                    return Fail($"No {args[1].ToLowerInvariant()} hook is set.");
                }

                if (before)
                {
                    await hooks.RunBeforeSaveAsync(
                        repository.Layout.WorkingRoot, repository.Config.Name, "hook test", CancellationToken.None)
                        .ConfigureAwait(false);
                    Console.WriteLine("The before-save hook ran clean; a save would have gone ahead.");
                    return ExitSuccess;
                }

                var note = await hooks.RunAfterSaveAsync(
                    repository.Layout.WorkingRoot, repository.Config.Name, repository.GetHead(), "hook test",
                    CancellationToken.None).ConfigureAwait(false);
                Console.WriteLine(note ?? "The after-save hook ran clean.");
                return note is null ? ExitSuccess : ExitFailure;
            }

            default:
                return Usage("sip hooks [set|remove|test] - 'sip help hooks' explains them.");
        }
    }

    private static int ShowHooks(SipRepository repository)
    {
        var hooks = SaveHooks.Load(repository.Layout);
        if (hooks.IsEmpty)
        {
            Console.WriteLine("No hooks: nothing runs around a save unless you set it up.");
            Console.WriteLine("'sip hooks set before-save <command>' refuses the save when the command fails;");
            Console.WriteLine("'sip hooks set after-save <command>' runs once a snapshot is recorded.");
            return ExitSuccess;
        }

        PrintHook("before-save", hooks.BeforeSave);
        PrintHook("after-save", hooks.AfterSave);
        Console.WriteLine();
        Console.WriteLine("Hooks are this machine's only - .sip never syncs - and run as you, in this");
        Console.WriteLine("folder, on 'sip save' and the daemon's automatic saves.");
        return ExitSuccess;
    }

    private static void PrintHook(string which, HookCommand? hook)
    {
        Console.WriteLine(hook is null
            ? $"{which,-11}  (not set)"
            : string.Create(
                CultureInfo.InvariantCulture,
                $"{which,-11}  {DisplayText.Printable(hook.Command, 500)}  (deadline {hook.DeadlineSeconds}s)"));
    }

    /// <summary>True for before-save, false for after-save, null for neither.</summary>
    private static bool? WhichHook(string word) =>
        word.ToUpperInvariant() switch
        {
            "BEFORE-SAVE" => true,
            "AFTER-SAVE" => false,
            _ => null,
        };

    private static int Say(string message)
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
}
