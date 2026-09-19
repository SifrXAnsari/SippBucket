using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Machines;
using SippBucket.Core.Model;
using SippBucket.Core.Pairing;
using SippBucket.Core.Platform;
using SippBucket.Core.Protocol;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;
using SippBucket.Core.Sync;

namespace SippBucket.Cli;

/// <summary>Command dispatch for SippBucket's command line.</summary>
/// <remarks>
/// Shared deliberately: the standalone <c>sip</c> shim and the combined SippBucket
/// application both call <see cref="RunAsync"/>, so there is one command surface and it
/// cannot drift from the help text that documents it.
/// </remarks>
public static class CommandLine
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary>Runs one command and returns the process exit code.</summary>
    /// <param name="args">The command and its arguments, without the executable name.</param>
    /// <returns>0 on success, 1 on failure, 2 on a usage error.</returns>
    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length == 0)
        {
            Help.PrintOverview();
            return ExitUsage;
        }

        try
        {
            return await DispatchAsync(args).ConfigureAwait(false);
        }
        catch (RepositoryNotFoundException ex)
        {
            return Fail(ex.Message);
        }
        catch (RepositoryUnreadableException ex)
        {
            // Not "no repository here": there is one, and the next step is to leave it
            // alone and fix or update something. The message says which (D-66).
            return ex.Reason == RepositoryUnreadableReason.NewerFormat
                ? Fail(ex.Message)
                : FailWithHint(
                    ex.Message,
                    "Only this machine's .sip/config.json is affected: .sip is never synced, " +
                    "so every other machine has its own.");
        }
        catch (RepositoryAlreadyExistsException ex)
        {
            return Fail(ex.Message);
        }
        catch (RepositoryLockedException ex)
        {
            // Worth its own arm rather than falling through to a generic failure: the user's
            // next action is specific and nothing else produces this.
            return FailWithHint(
                ex.Message,
                "Run 'sip unlock' first, or 'sip lock --off' to remove it.");
        }
        catch (WrongPassphraseException ex)
        {
            return Fail(ex.Message);
        }
        catch (InvalidKeyWrapException ex)
        {
            // Deliberately distinguished from a wrong passphrase: retyping will not help,
            // and telling someone to try again when it cannot work is its own small cruelty.
            return FailWithHint(
                ex.Message,
                "The passphrase is not the problem; the stored lock is damaged.");
        }
        catch (BucketFullException ex)
        {
            // Its message already names the way out, so there is no hint to add — the
            // exception was built to carry the remedy rather than only the problem.
            return Fail(ex.Message);
        }
        catch (JsonException ex)
        {
            // Was missing entirely. A hand-edited or truncated config.json escaped every arm
            // of this chain and surfaced as an unhandled crash with a stack trace, which is
            // the least useful possible way to tell somebody their file has a typo in it.
            return Fail($"A SippBucket file could not be read: {ex.Message}");
        }
        catch (SnapshotNotFoundException ex)
        {
            return Fail(ex.Message);
        }
        catch (CorruptBlockException ex)
        {
            return Fail(ex.Message);
        }
        catch (BlockNotFoundException ex)
        {
            // Was missing: a restore over a snapshot whose block is gone ended in a stack
            // trace. The restore stages every file before touching the folder, so this is
            // also a promise that nothing there changed.
            return Fail($"{ex.Message} Nothing in the folder was changed.");
        }
        catch (UnsafeSnapshotPathException ex)
        {
            return Fail(ex.Message);
        }
        catch (SipProtocolException ex)
        {
            return Fail(ex.Message);
        }
        catch (SocketException ex)
        {
            return Fail($"Network error: {ex.SocketErrorCode}.");
        }
        catch (PeerStalledException ex)
        {
            // Before the IOException arm it derives from, which would call a silent peer a
            // "file error" - the first thing a pairing that timed out would have printed.
            return Fail($"Network error: {ex.Message}");
        }
        catch (FolderBusyException ex)
        {
            // Also an IOException, and also not a file error: another operation, usually the
            // tray mid-cycle, holds this folder (D-38). The message names what holds it.
            return Fail(ex.Message);
        }
        catch (HookException ex)
        {
            // An IOException too, and not a file error: the owner's own hook failed or
            // refused the save, and its message says which and what it said.
            return Fail(ex.Message);
        }
        catch (Core.Push.PushException ex)
        {
            // An IOException too, and a Direct Push connection's failure rather than a file's.
            // Its message says what happened and to which machine.
            return Fail(ex.Message);
        }
        catch (IOException ex)
        {
            return Fail($"File error: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            // With the folder-protection sentence when Norton or Controlled folder access
            // is watching this kind of folder (P-04): "access denied" alone sends a person
            // to permissions that are fine.
            return Fail(AntivirusShield.ExplainDenied(
                $"Access denied: {ex.Message}", Directory.GetCurrentDirectory()));
        }
        catch (ArgumentException ex)
        {
            return Fail(ex.Message);
        }
        catch (FormatException ex)
        {
            return Fail(ex.Message);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine();
            Console.WriteLine("Stopped.");
            return ExitSuccess;
        }
    }

    private static async Task<int> DispatchAsync(string[] args)
    {
        var command = args[0].ToUpperInvariant();
        var rest = args[1..];

        return command switch
        {
            "INIT" => Init(rest),
            "STATUS" => await StatusAsync().ConfigureAwait(false),
            "SAVE" => await SaveAsync(rest).ConfigureAwait(false),
            "LOG" => await LogAsync(rest).ConfigureAwait(false),
            "SHOW" => await HistoryCommands.ShowAsync(rest).ConfigureAwait(false),
            "DIFF" => await HistoryCommands.DiffAsync(rest).ConfigureAwait(false),
            "BLAME" => await HistoryCommands.BlameAsync(rest).ConfigureAwait(false),
            "TAG" => await PowerCommands.TagAsync(rest).ConfigureAwait(false),
            "BISECT" => await PowerCommands.BisectAsync(rest).ConfigureAwait(false),
            "VERIFY" => await PowerCommands.VerifyAsync(rest).ConfigureAwait(false),
            "HOOKS" => await PowerCommands.HooksAsync(rest).ConfigureAwait(false),
            "RESTORE" => await RestoreAsync(rest).ConfigureAwait(false),
            "PEER" => Peer(rest),
            "INVITE" => await InviteAsync(rest).ConfigureAwait(false),
            "JOIN" => await JoinAsync(rest).ConfigureAwait(false),
            "SYNC" => await SyncAsync().ConfigureAwait(false),
            "SERVE" => await ServeAsync().ConfigureAwait(false),
            "ID" => ServerCommands.Id(rest),
            "LOCK" => Lock(rest),
            "UNLOCK" => Unlock(rest),
            "BUCKET" => await BucketAsync(rest).ConfigureAwait(false),
            "DOCTOR" => await DoctorAsync().ConfigureAwait(false),
            "PAIR" => await PairAsync(rest).ConfigureAwait(false),
            "PUSH" => await DirectPushCommands.PushAsync(rest).ConfigureAwait(false),
            "ALERTS" => await HealthCommands.AlertsAsync(rest).ConfigureAwait(false),
            "INBOX" => DirectPushCommands.Inbox(rest),
            "QUARANTINE" => DirectPushCommands.Quarantine(rest),
            "TEAM" => TeamCommands.Run(rest),
            "DM" => await MessageCommands.DmAsync(rest).ConfigureAwait(false),
            "MESSAGES" => MessageCommands.Messages(rest),
            "PAGES" => await WikiCommands.PagesAsync(rest).ConfigureAwait(false),
            "SEARCH" => await WikiCommands.SearchAsync(rest).ConfigureAwait(false),
            "COMMENTS" => await WikiCommands.CommentsAsync(rest).ConfigureAwait(false),
            "NET" => NetCommands.Run(rest),
            "CONFIG" => await MachineConfig.RunAsync(rest).ConfigureAwait(false),
            "HELP" or "--HELP" or "-H" => PrintHelp(rest),
            _ => Unknown(args[0]),
        };
    }

    private static int Init(string[] args)
    {
        var mode = RepositoryMode.Power;
        string? name = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i].ToUpperInvariant())
            {
                case "--MODE":
                    if (++i >= args.Length)
                    {
                        return Usage("--mode needs a value: power or simple.");
                    }

                    if (!Enum.TryParse(args[i], ignoreCase: true, out mode))
                    {
                        return Usage($"'{args[i]}' is not a mode. Use power or simple.");
                    }

                    break;

                case "--NAME":
                    if (++i >= args.Length)
                    {
                        return Usage("--name needs a value.");
                    }

                    name = args[i];
                    break;

                case "--PORT":
                    return PortIsMachineWide("sip init");

                default:
                    return Usage($"'{args[i]}' is not an option of sip init.");
            }
        }

        var port = MasterConfig.Load().ListenPort;

        using var repository = SipRepository.Init(
            Directory.GetCurrentDirectory(), mode, name, port);

        Console.WriteLine($"Initialised '{repository.Config.Name}' in {mode} mode.");
        Console.WriteLine($"  repository  {repository.Config.RepositoryId}");
        Console.WriteLine($"  port        {port}, this machine's port for every folder (server.listenPort)");
        Console.WriteLine();
        Console.WriteLine("Next: sip save -m \"first\"");
        return ExitSuccess;
    }

    private static async Task<int> StatusAsync()
    {
        using var repository = Open();
        var status = await repository.GetStatusAsync().ConfigureAwait(false);

        Console.WriteLine($"Repository '{repository.Config.Name}' ({repository.Config.Mode} mode)");

        var head = repository.GetHead();
        Console.WriteLine(head.IsEmpty
            ? "No snapshots yet."
            : $"Head is {head.ToShortString()}.");
        Console.WriteLine();

        PrintSkipped(status.Skipped);

        if (status.IsClean)
        {
            Console.WriteLine($"Nothing has changed. {status.UnchangedCount} file(s) tracked.");
            Console.WriteLine();
            Console.WriteLine(DirectPushCommands.StatusLine());
            return ExitSuccess;
        }

        foreach (var path in status.Added)
        {
            Console.WriteLine($"  added     {path}");
        }

        foreach (var path in status.Modified)
        {
            Console.WriteLine($"  modified  {path}");
        }

        foreach (var path in status.Removed)
        {
            Console.WriteLine($"  removed   {path}");
        }

        Console.WriteLine();
        Console.WriteLine(
            $"{status.ChangeCount} change(s), {status.UnchangedCount} file(s) unchanged.");
        Console.WriteLine();
        Console.WriteLine(DirectPushCommands.StatusLine());
        Console.WriteLine(MessageCommands.StatusLine());
        return ExitSuccess;
    }

    private static async Task<int> SaveAsync(string[] args)
    {
        var message = string.Empty;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "-m" or "--message")
            {
                if (++i >= args.Length)
                {
                    return Usage("-m needs a message.");
                }

                message = args[i];
            }
            else
            {
                return Usage($"'{args[i]}' is not an option of sip save.");
            }
        }

        using var repository = Open();
        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
        repository.Signer = new SnapshotSigner(identity);

        var result = await repository.SaveAsync(message, identity.DeviceId).ConfigureAwait(false);
        PrintSkipped(repository.LastScanSkipped);

        if (result is null)
        {
            Console.WriteLine("Nothing to save; the folder matches the newest snapshot.");
            return ExitSuccess;
        }

        Console.WriteLine(
            $"Saved {result.SnapshotId.ToShortString()} - " +
            $"{result.Snapshot.Files.Count} file(s), {Bytes(result.Snapshot.TotalSize)}.");

        if (result.AfterSaveNote is { } note)
        {
            Console.WriteLine(note);
        }

        if (repository.Config.Mode == RepositoryMode.Simple)
        {
            Console.WriteLine("Simple mode: older snapshots were discarded.");
        }

        return ExitSuccess;
    }

    private static async Task<int> LogAsync(string[] args)
    {
        var limit = 20;
        string? path = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "-n" or "--number")
            {
                if (++i >= args.Length ||
                    !int.TryParse(args[i], CultureInfo.InvariantCulture, out limit))
                {
                    return Usage("-n needs a number.");
                }
            }
            else if (path is null && !args[i].StartsWith('-'))
            {
                path = args[i];
            }
            else
            {
                return Usage($"'{args[i]}' is not an option of sip log.");
            }
        }

        if (path is not null)
        {
            using var one = Open();
            return await HistoryCommands.FileHistoryAsync(one, path, limit).ConfigureAwait(false);
        }

        using var repository = Open();
        var history = await repository.GetHistoryAsync(limit).ConfigureAwait(false);

        if (history.Count == 0)
        {
            Console.WriteLine("No snapshots yet. Run 'sip save'.");
            return ExitSuccess;
        }

        foreach (var entry in history)
        {
            var when = entry.Snapshot.CreatedUtc.ToLocalTime()
                .ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            var who = entry.Snapshot.DeviceId[..Math.Min(8, entry.Snapshot.DeviceId.Length)];
            var what = string.IsNullOrWhiteSpace(entry.Snapshot.Message)
                ? "(no message)"
                : entry.Snapshot.Message;

            Console.WriteLine($"{entry.SnapshotId.ToShortString()}  {when}  {who}  {what}");
            Console.WriteLine(
                $"{new string(' ', 12)}  {entry.Snapshot.Files.Count} file(s), " +
                $"{Bytes(entry.Snapshot.TotalSize)}");
        }

        return ExitSuccess;
    }

    private static async Task<int> RestoreAsync(string[] args)
    {
        if (args.Length != 1)
        {
            return Usage("sip restore needs exactly one snapshot: an ID, an ID prefix, a tag, or head.");
        }

        using var repository = Open();
        var (snapshotId, problem) = await HistoryCommands.ResolveAsync(repository, args[0]).ConfigureAwait(false);
        if (problem is not null)
        {
            return Fail(problem);
        }

        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
        repository.Signer = new SnapshotSigner(identity);
        var before = repository.GetHead();
        var result = await repository.RestoreAsync(snapshotId, identity.DeviceId).ConfigureAwait(false);
        Console.WriteLine(
            $"Restored {snapshotId.ToShortString()} - " +
            $"{result.FilesWritten} file(s) written, {result.FilesDeleted} deleted" +
            (result.FilesRenamed > 0 ? $", {result.FilesRenamed} renamed to the snapshot's casing." : "."));

        foreach (var kept in result.KeptAside)
        {
            Console.WriteLine($"  kept the version that was here as {kept}");
        }

        foreach (var kept in result.KeptReadOnly)
        {
            Console.WriteLine($"  kept {kept}: it is read-only, so it was not deleted");
        }

        PrintSkipped(repository.LastScanSkipped);

        Console.WriteLine(result.SnapshotId.IsEmpty
            ? "The folder already matched the newest snapshot, so nothing new was recorded."
            : $"Recorded as {result.SnapshotId.ToShortString()}, a new snapshot on top of " +
              $"{before.ToShortString()}. It syncs to your other machines like any other save.");

        return ExitSuccess;
    }

    /// <summary>Lists what a scan did not read, before anything else the command says.</summary>
    private static void PrintSkipped(IReadOnlyList<SkippedPath> skipped)
    {
        if (skipped.Count == 0)
        {
            return;
        }

        Console.WriteLine("Not read, so not synced from here:");
        foreach (var entry in skipped)
        {
            Console.WriteLine($"  {entry.Describe()}");
        }

        Console.WriteLine();
    }

    private static int Peer(string[] args)
    {
        if (args.Length == 0)
        {
            return Usage("sip peer needs a subcommand: add, list, remove, owner, role, expire, health or port-updated.");
        }

        // Per machine, not per folder: it needs no folder open.
        if (string.Equals(args[0], "health", StringComparison.OrdinalIgnoreCase))
        {
            return HealthCommands.Peers(args[1..]);
        }

        using var repository = OpenPossiblyLocked();

        switch (args[0].ToUpperInvariant())
        {
            case "LIST":
            {
                var peers = repository.Peers.Inspect();
                if (peers.Usable.Count == 0 && peers.Skipped.Count == 0)
                {
                    Console.WriteLine(
                        "No peers yet. Pair a machine with 'sip pair offer' or 'sip invite', " +
                        "or add one by hand with 'sip peer add'.");
                    return ExitSuccess;
                }

                var answers = LoadOwnerAnswers();
                foreach (var peer in peers.Usable)
                {
                    var synced = peer.LastSyncedUtc is null
                        ? "never synced"
                        : $"last synced {peer.LastSyncedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm}";
                    var owner = MachineOwnership.Describe(
                        KnownMachines.Find(answers, peer.DeviceId)?.Owner ?? MachineOwner.Unanswered);
                    var membership = string.Concat(
                        peer.ReadOnlyMember ? "  read-only" : string.Empty,
                        peer.ExpiresUtc is { } expires
                            ? peer.IsExpired(DateTimeOffset.UtcNow)
                                ? $"  membership ended {expires.UtcDateTime:yyyy-MM-dd}"
                                : $"  until {expires.UtcDateTime:yyyy-MM-dd}"
                            : string.Empty);
                    Console.WriteLine($"{peer.Name,-16} {HostAndPort.Format(peer.Host, peer.Port),-22} " +
                                      $"{ShortDeviceId(peer.DeviceId)}  {owner,-15} {synced}{membership}");
                }

                PrintSkipped(peers.Skipped, repository.Peers.FilePath);
                return ExitSuccess;
            }

            case "OWNER":
            {
                if (args.Length != 3 || !MachineOwnership.TryParse(args[2], out var answer))
                {
                    return Usage("sip peer owner <device-id | id-prefix | name> mine|someone-else");
                }

                var found = repository.Peers.Find(args[1]);
                switch (found.Outcome)
                {
                    case PeerLookupOutcome.Found when found.Peer is { } peer:
                        return OwnerQuestion.Record(peer.DeviceId, peer.Name, repository.Config.Name, answer)
                            ? ExitSuccess
                            : ExitFailure;

                    case PeerLookupOutcome.Ambiguous:
                        Console.Error.WriteLine(
                            $"sip: '{args[1]}' matches {found.Candidates.Count} peers, so nothing was recorded:");
                        foreach (var candidate in found.Candidates)
                        {
                            Console.Error.WriteLine(
                                $"       {candidate.Name,-16} {HostAndPort.Format(candidate.Host, candidate.Port),-22} " +
                                $"{ShortDeviceId(candidate.DeviceId)}");
                        }

                        Console.Error.WriteLine("     Name one by its ID: sip peer owner <id from the list> mine|someone-else");
                        return ExitFailure;

                    default:
                        return FailWithHint(
                            $"No peer of this folder matches '{args[1]}'. Nothing was recorded.",
                            "Run 'sip peer list' to see the names and IDs.");
                }
            }

            case "ADD":
            {
                if (args.Length != 4)
                {
                    return Usage("sip peer add <name> <device-id> <host>[:<port>]");
                }

                // With no port given, the other machine is taken to serve on the same port as
                // this one: both read it from their own master.json (D-40).
                if (!HostAndPort.TryParse(args[3], MasterConfig.Load().ListenPort, out var address, out var problem))
                {
                    return Usage(problem);
                }

                if (!DeviceIdentity.TryImportPublicKey(args[2], out _))
                {
                    return Fail($"'{args[2]}' is not a valid device ID. Run 'sip id' on that machine.");
                }

                using (var own = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile))
                {
                    if (DeviceIdentity.IsSameDevice(args[2], own.DeviceId))
                    {
                        return Fail(
                            $"'{args[2][..12]}…' is this machine's own device ID. A machine cannot be its own peer; " +
                            "run 'sip id' on the other machine and add that ID.");
                    }
                }

                var replaced = repository.Peers.AddOrReplace(new PeerRecord
                {
                    Name = args[1],
                    DeviceId = args[2],
                    Host = address.Host,
                    Port = address.Port,
                });

                Console.WriteLine($"Added peer '{args[1]}' at {address}.");

                // Said, because it used to happen silently: one record per device, so adding
                // a device that is already listed overwrites the name and address somebody
                // chose for it.
                PrintReplaced(replaced);

                Console.WriteLine("That machine must add this one too before they will talk.");
                return ExitSuccess;
            }

            case "REMOVE":
            {
                if (args.Length != 2)
                {
                    return Usage("sip peer remove <device-id | id-prefix | name>");
                }

                var removal = repository.Peers.Remove(args[1]);

                switch (removal.Outcome)
                {
                    case PeerRemovalOutcome.Removed:
                        foreach (var peer in removal.Removed)
                        {
                            Console.WriteLine(
                                $"Removed peer '{peer.Name}' at {HostAndPort.Format(peer.Host, peer.Port)} " +
                                $"({ShortDeviceId(peer.DeviceId)}).");
                        }

                        // Removal means it (D-70): the folder key rotates, so nothing written
                        // from now on is readable to the removed machine, and the revocation
                        // travels to the other machines at their next sync.
                        try
                        {
                            var generation = repository.RotateKey([.. removal.Removed.Select(peer => peer.DeviceId)]);
                            Console.WriteLine(string.Create(
                                CultureInfo.InvariantCulture,
                                $"The folder's key was rotated (generation {generation}).") +
                                " Everything written from now on is under a key that machine never receives, " +
                                "and your other machines learn the new key at their next sync.");
                            Console.WriteLine(
                                "What rotation cannot do: un-share the past. That machine holds, or could have " +
                                "copied, everything written before this moment.");
                        }
                        catch (InvalidOperationException ex)
                        {
                            Console.Error.WriteLine(
                                $"The peer was removed, and the key was NOT rotated: {ex.Message}");
                            return ExitFailure;
                        }

                        return ExitSuccess;

                    case PeerRemovalOutcome.Ambiguous:
                        // Nothing was removed. Listing the candidates the way 'peer list'
                        // does gives the user the short IDs they need for the next command.
                        Console.Error.WriteLine(
                            $"sip: '{args[1]}' matches {removal.Candidates.Count} peers, " +
                            "so none was removed:");
                        foreach (var peer in removal.Candidates)
                        {
                            Console.Error.WriteLine(
                                $"       {peer.Name,-16} {HostAndPort.Format(peer.Host, peer.Port),-22} " +
                                $"{ShortDeviceId(peer.DeviceId)}");
                        }

                        Console.Error.WriteLine(
                            "     Remove one by its ID: sip peer remove <id from the list>");
                        return ExitFailure;

                    default:
                        return FailWithHint(
                            $"No peer matches '{args[1]}'. Nothing was removed.",
                            args[1].Length < PeerRegistry.MinimumDeviceIdPrefixLength &&
                            args[1].All(char.IsAsciiHexDigit)
                                ? $"An ID prefix needs at least {PeerRegistry.MinimumDeviceIdPrefixLength} " +
                                  "characters. 'sip peer list' prints 12."
                                : "Run 'sip peer list' to see the names and IDs.");
                }
            }

            case "ROLE":
            {
                if (args.Length != 3 ||
                    args[2].ToUpperInvariant() is not ("READ-ONLY" or "READ-WRITE"))
                {
                    return Usage("sip peer role <device-id | id-prefix | name> read-only|read-write");
                }

                var wantReadOnly = string.Equals(args[2], "read-only", StringComparison.OrdinalIgnoreCase);
                return WithOnePeer(repository, args[1], peer =>
                {
                    _ = repository.Peers.AddOrReplace(peer with { ReadOnlyMember = wantReadOnly });
                    Console.WriteLine(wantReadOnly
                        ? $"'{peer.Name}' is read-only in this folder: it can still read everything - it holds the " +
                          "key, and pretending otherwise would be a lie - and no change it makes is taken here. " +
                          "Set the same role on your other machines; peer settings are per machine."
                        : $"'{peer.Name}' can write to this folder again.");
                    return ExitSuccess;
                });
            }

            case "EXPIRE":
            {
                if (args.Length != 3)
                {
                    return Usage("sip peer expire <device-id | id-prefix | name> <yyyy-mm-dd | never>");
                }

                DateTimeOffset? until;
                if (string.Equals(args[2], "never", StringComparison.OrdinalIgnoreCase))
                {
                    until = null;
                }
                else if (DateTimeOffset.TryParseExact(
                             args[2], "yyyy-MM-dd", CultureInfo.InvariantCulture,
                             DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                             out var parsed))
                {
                    until = parsed;
                }
                else
                {
                    return Usage($"'{args[2]}' is not a date. Use yyyy-mm-dd, or never.");
                }

                return WithOnePeer(repository, args[1], peer =>
                {
                    _ = repository.Peers.AddOrReplace(peer with { ExpiresUtc = until });
                    Console.WriteLine(until is null
                        ? $"'{peer.Name}' has no end date."
                        : $"'{peer.Name}' is a member until {until.Value.UtcDateTime:yyyy-MM-dd} (UTC). From then it is " +
                          "neither served nor dialled from this machine. Expiry cuts off what comes after it; " +
                          "'sip peer remove' also rotates the folder key. Set it on your other machines too.");
                    return ExitSuccess;
                });
            }

            case "PORT-UPDATED":
            {
                if (args.Length != 1)
                {
                    return Usage("sip peer port-updated");
                }

                var port = MasterConfig.Load().ListenPort;
                var given = repository.RecordPortGivenToPeers(port);

                Console.WriteLine(given == port
                    ? $"Nothing to record: this folder was set up on port {port}, the port it is served on."
                    : $"Recorded: the machines paired with this folder now reach it on port {port}, not {given}. " +
                      "'sip doctor' stops warning about it.");
                return ExitSuccess;
            }

            default:
                return Usage($"'{args[0]}' is not a peer subcommand. Use add, list, remove, owner, role, expire, health or port-updated.");
        }
    }

    /// <summary>Runs one action over the single peer an argument names, or says why it cannot.</summary>
    private static int WithOnePeer(SipRepository repository, string typed, Func<PeerRecord, int> action)
    {
        var found = repository.Peers.Find(typed);
        switch (found.Outcome)
        {
            case PeerLookupOutcome.Found when found.Peer is { } peer:
                return action(peer);

            case PeerLookupOutcome.Ambiguous:
                Console.Error.WriteLine($"sip: '{typed}' matches {found.Candidates.Count} peers, so nothing was changed:");
                foreach (var candidate in found.Candidates)
                {
                    Console.Error.WriteLine(
                        $"       {candidate.Name,-16} {HostAndPort.Format(candidate.Host, candidate.Port),-22} " +
                        $"{ShortDeviceId(candidate.DeviceId)}");
                }

                Console.Error.WriteLine("     Name one by its ID from the list.");
                return ExitFailure;

            default:
                return FailWithHint(
                    $"No peer of this folder matches '{typed}'. Nothing was changed.",
                    "Run 'sip peer list' to see the names and IDs.");
        }
    }

    /// <summary>The person's answers about their paired machines, for listing.</summary>
    /// <returns>The answers, or none when the file cannot be read, which is said.</returns>
    /// <remarks>
    /// A list is not a safety decision, so a damaged file does not stop it: every machine is
    /// shown as not answered, which is how everything that protects the person treats it too,
    /// and the problem is named so it can be mended.
    /// </remarks>
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

    /// <summary>
    /// Opens a pairing window for a pasted invitation, prints the <c>sip2_</c> string, and
    /// waits for one machine to use it.
    /// </summary>
    /// <remarks>
    /// This used to print a <c>sip1_</c> string holding the repository key and exit (D-49).
    /// Now it is the pasteable form of <c>sip pair offer</c>: the same window, the same ten
    /// minutes and five attempts, the same CPace exchange — with a 128-bit secret in place
    /// of the spoken code, because pasting costs nothing per character.
    /// </remarks>
    private static async Task<int> InviteAsync(string[] args)
    {
        var given = new List<string>();
        MachineOwner? owner = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--host")
            {
                if (++i >= args.Length)
                {
                    return Usage("--host needs a value.");
                }

                given.Add(args[i]);
            }
            else if (args[i] is "--owner")
            {
                if (OwnerQuestion.TryRead(++i < args.Length ? args[i] : null, out var answered) is { } wrong)
                {
                    return Usage(wrong);
                }

                owner = answered;
            }
            else
            {
                return Usage($"'{args[i]}' is not an option of sip invite.");
            }
        }

        using var repository = Open();

        // The port the window opens beside and the invite carries: this machine's, which serves
        // every folder (D-40), not the port the folder's config recorded when it was set up.
        var syncPort = MasterConfig.Load().ListenPort;

        // Read as addresses, not copied in as typed. The invite carries hosts and one port,
        // and a --host value went into it whole, so "[fe80::1]" or "desk:8471" reached the
        // other machine as a host name it could never resolve (D-63).
        var hosts = new List<string>();
        foreach (var text in given)
        {
            if (!TryReadOfferedHost(text, syncPort, "sip invite --host", out var host, out var problem))
            {
                return Usage(problem);
            }

            hosts.Add(host);
        }

        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);

        if (hosts.Count == 0)
        {
            hosts.AddRange(LocalAddresses.UsableIPv4());
        }

        if (hosts.Count == 0)
        {
            return FailWithHint(
                "This machine has no usable network address to put in an invite.",
                "Pass the address the other machine should use: sip invite --host <address>");
        }

        var server = new PairingServer(
            repository, identity, PairingSession.ForInvitation(), Console.WriteLine, syncPort);
        await using var _ = server.ConfigureAwait(false);

        server.Start();

        var invitation = new PairingInvitation
        {
            Hosts = hosts,
            Port = syncPort,
            DeviceId = identity.DeviceId,
            Secret = server.Code,
        };

        Console.WriteLine();
        Console.WriteLine($"Invite to '{repository.Config.Name}', for one machine, for ten minutes:");
        Console.WriteLine();
        Console.WriteLine(invitation.Encode());
        Console.WriteLine();
        Console.WriteLine("On the other machine, in an empty folder:  sip join <that string>");
        Console.WriteLine();

        // Said here, at the moment the string exists, rather than in a help page nobody opens
        // while holding a live one. What it holds, what it does not, and the limit.
        Console.WriteLine($"  It holds {string.Join(", ", hosts)}, this machine's device ID and a");
        Console.WriteLine("  one-time secret. It does NOT hold the folder's key: the key is sent only");
        Console.WriteLine("  to the machine that proves it has the secret, encrypted to that machine.");
        Console.WriteLine();
        Console.WriteLine("  But whoever uses it first is the one who joins. Anyone who gets it within");
        Console.WriteLine("  the ten minutes can join instead of your machine and read every document");
        Console.WriteLine("  in the folder. Send it privately, and let it expire if it went astray.");
        Console.WriteLine();
        Console.WriteLine("  It stops working after ten minutes, after one machine uses it, or after");
        Console.WriteLine("  five failed attempts. Ctrl+C to stop waiting.");
        Console.WriteLine();

        var outcome = await server.WaitForOutcomeAsync().ConfigureAwait(false);
        return ReportOffer(server, outcome, "sip invite", repository.Config.Name, owner);
    }

    /// <summary>Joins a repository from a pasted <c>sip2_</c> invitation.</summary>
    private static async Task<int> JoinAsync(string[] args)
    {
        if (args.Length == 0)
        {
            return Usage("sip join needs an invite. Run 'sip invite' on the other machine.");
        }

        var mode = RepositoryMode.Power;
        var name = "origin";
        MachineOwner? owner = null;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i].ToUpperInvariant())
            {
                case "--MODE":
                    if (++i >= args.Length ||
                        !Enum.TryParse(args[i], ignoreCase: true, out mode))
                    {
                        return Usage("--mode needs a value: power or simple.");
                    }

                    break;

                case "--PORT":
                    return PortIsMachineWide("sip join");

                case "--NAME":
                    if (++i >= args.Length)
                    {
                        return Usage("--name needs a value.");
                    }

                    name = args[i];
                    break;

                case "--OWNER":
                    if (OwnerQuestion.TryRead(++i < args.Length ? args[i] : null, out var answered) is { } wrong)
                    {
                        return Usage(wrong);
                    }

                    owner = answered;
                    break;

                default:
                    return Usage($"'{args[i]}' is not an option of sip join.");
            }
        }

        // A sip1_ string is refused here, by Decode, with the explanation of why. There is
        // no path that reads one.
        var invitation = PairingInvitation.Decode(args[0]);
        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);

        var recorded = new RecordedOrigin();
        SipRepository joined;
        try
        {
            joined = await PairingClient.JoinWithInvitationAsync(
                invitation,
                identity,
                new PairingJoinOptions
                {
                    Directory = Directory.GetCurrentDirectory(),
                    Mode = mode,
                    PeerName = name,
                    ListenPort = MasterConfig.Load().ListenPort,
                    Recorded = recorded.Keep,
                }).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            return FailWithHint(
                $"Could not reach the inviting machine at {string.Join(", ", invitation.Hosts)} " +
                $"(port {invitation.Port + PairingServer.PortOffset}): {ex.SocketErrorCode}.",
                "Is 'sip invite' still waiting there? The invite lasts ten minutes. If it is, " +
                "a firewall on that machine may be blocking the port.");
        }

        using (joined)
        {
            PrintJoined(joined, recorded, owner);
        }

        return ExitSuccess;
    }

    /// <summary>What a newly joined replica is told, true of both pairing routes.</summary>
    /// <remarks>
    /// The offering machine's record comes from what the join reported writing. It used to be
    /// <c>Peers.Load().Single()</c>, which threw on a folder whose left-over peer list already
    /// held other records, after the join had succeeded.
    /// </remarks>
    private static void PrintJoined(SipRepository joined, RecordedOrigin recorded, MachineOwner? owner)
    {
        Console.WriteLine($"Joined '{joined.Config.Name}' in {joined.Config.Mode} mode.");

        if (recorded.Origin is { } origin)
        {
            Console.WriteLine(
                $"  peer '{origin.Name}' at {HostAndPort.Format(origin.Host, origin.Port)} " +
                $"({ShortDeviceId(origin.DeviceId)})");
        }

        // D-64. Only a folder holding a left-over .sip/peers.json can get here with one.
        PrintReplaced(recorded.Replaced);
        PrintLeftOver(joined, recorded.Origin?.DeviceId);
        Console.WriteLine();

        // The instructions that used to be here told the user to 'sip peer add' this
        // machine on the other end. The other end already had, and now it provably has:
        // "accepted" is only sent once the offering machine has recorded this one.
        Console.WriteLine("The other machine recorded this one as its peer before it accepted, so");
        Console.WriteLine("there is nothing to add by hand on either side.");
        Console.WriteLine();
        Console.WriteLine("Next: sip sync   (or run the tray on both machines; it syncs on its own)");

        if (recorded.Origin is { } offering)
        {
            OwnerQuestion.Settle(offering.DeviceId, offering.Name, joined.Config.Name, owner);
        }
    }

    /// <summary>
    /// Lists every other record a new replica's peer list already held, which joining kept.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A folder holding a <c>.sip</c> left from an earlier repository, a <c>peers.json</c> and
    /// no <c>config.json</c>, is joined into, and <see cref="SipRepository"/>'s join adds the
    /// offering machine to that list rather than starting a new one. Every other machine in
    /// it is then one this replica dials to sync, and a known peer if it dials in. This used
    /// to print the list with
    /// <c>Peers.Load().Single()</c>, which at least threw on such a folder; when that throw
    /// went, keeping them became silent. Now each is named, with how to remove it.
    /// </para>
    /// <para>
    /// Listed, not refused or dropped. A record from another repository cannot sync with this
    /// one, because the handshake carries the repository's ID and a machine without it is
    /// refused; one from this same repository, left by a copy that was set up here before, is
    /// a machine the person already trusted with it. Dropping them would be a write nobody
    /// asked for, and refusing the join would stop the one case where keeping them is right.
    /// </para>
    /// </remarks>
    private static void PrintLeftOver(SipRepository joined, string? originDeviceId)
    {
        var list = joined.Peers.Inspect();
        var others = list.Usable
            .Where(p => !string.Equals(p.DeviceId, originDeviceId, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (others.Count == 0 && list.Skipped.Count == 0)
        {
            return;
        }

        Console.WriteLine();
        Console.WriteLine($"This folder's .sip already held a peer list, at {joined.Peers.FilePath},");
        Console.WriteLine("and joining kept it. Besides the machine above, it lists:");

        foreach (var peer in others)
        {
            Console.WriteLine(
                $"  peer '{peer.Name}' at {HostAndPort.Format(peer.Host, peer.Port)} " +
                $"({ShortDeviceId(peer.DeviceId)})");
        }

        Console.WriteLine("This copy will try to sync with each. Remove any you do not want: sip peer remove <name>");
        PrintSkipped(list.Skipped, joined.Peers.FilePath);
    }

    /// <summary>What the offering machine says once its window has closed.</summary>
    /// <remarks>
    /// On success it asks the one question about the machine that joined, unless
    /// <paramref name="owner"/> answered it already or an earlier pairing did.
    /// </remarks>
    private static int ReportOffer(
        PairingServer server,
        PairingClosure outcome,
        string again,
        string folderName,
        MachineOwner? owner)
    {
        Console.WriteLine();

        switch (outcome)
        {
            case PairingClosure.Used when server.PairedPeer is { } peer:
                Console.WriteLine(
                    $"Paired with '{peer.Name}' ({ShortDeviceId(peer.DeviceId)}), recorded here at " +
                    $"{HostAndPort.Format(peer.Host, peer.Port)}.");

                // D-64: a machine paired again replaces its record, and this is where the
                // name and address it had are said rather than lost.
                PrintReplaced(server.ReplacedPeer);

                Console.WriteLine("It records this machine as its peer when it finishes joining. Run");
                Console.WriteLine("'sip sync' on either machine, or run the tray on both.");

                OwnerQuestion.Settle(peer.DeviceId, peer.Name, folderName, owner);
                return ExitSuccess;

            case PairingClosure.Used:
                Console.WriteLine("The code was accepted, but the exchange failed before the other");
                Console.WriteLine("machine received the folder. It may already be listed here as a peer;");
                Console.WriteLine($"pairing it again replaces that entry. Run '{again}' for a new code.");
                PrintReplaced(server.ReplacedPeer);
                return ExitFailure;

            case PairingClosure.TooManyAttempts:
                Console.WriteLine($"Five failed attempts - the code was burnt. Run '{again}' for a new one.");
                return ExitFailure;

            default:
                Console.WriteLine($"The code expired. Run '{again}' for a new one.");
                return ExitFailure;
        }
    }

    private static async Task<int> SyncAsync()
    {
        using var repository = Open();
        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);

        var peers = repository.Peers.Inspect();
        if (peers.Usable.Count == 0)
        {
            // "No peers configured" would be untrue of a peers.json holding records that
            // cannot be used, and would send the person to pair a machine they already have.
            return peers.Skipped.Count == 0
                ? Fail(
                    "No peers configured. Pair a machine with 'sip pair offer' or 'sip invite', " +
                    "or add one by hand with 'sip peer add'.")
                : FailWithHint(
                    $"No usable peers: peers.json has {peers.Skipped.Count} record(s) and none can be used.",
                    "Run 'sip peer list' to see which, and why.");
        }

        if (peers.Skipped.Count > 0)
        {
            Console.WriteLine(
                $"Skipping {peers.Skipped.Count} record(s) in peers.json that cannot be used; " +
                "'sip peer list' says why.");
        }

        var machine = MasterConfig.Load();
        var progressGate = new object();
        var lastShown = 0;
        var engine = new SyncEngine(repository, identity, Console.WriteLine, machine.Sync)
        {
            Servers = ServerCommands.Exchange(identity, machine),
            Download = machine.DownloadLimit,

            // Every 32 blocks, and the last one, so a big pull shows life without a line per
            // block (D-31). Under a gate: sources sharing a fetch report from their own tasks.
            Progress = progress =>
            {
                lock (progressGate)
                {
                    if (progress.BlocksDone - lastShown >= 32 || progress.BlocksDone == progress.BlocksTotal)
                    {
                        lastShown = progress.BlocksDone;
                        Console.WriteLine(progress.Describe());
                    }
                }
            },
        };
        var results = await engine.SyncAllAsync().ConfigureAwait(false);

        Console.WriteLine();
        foreach (var result in results)
        {
            Console.WriteLine(result.Summary);
            foreach (var conflict in result.ConflictsRenamed)
            {
                Console.WriteLine($"  kept your version as {conflict}");
            }
        }

        // A failed peer is a non-zero exit, so a script that runs 'sip sync' before shutting
        // a machine down can tell that it did not actually sync. Printing the failure and
        // returning success would be the same lie the tray used to tell, in a place where
        // something automated is relying on the answer.
        var failed = results.Count(result => !result.Succeeded);
        if (failed > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"{failed} of {results.Count} peer(s) did NOT sync.");
            return ExitFailure;
        }

        return ExitSuccess;
    }

    /// <summary>Runs a host for the current repository until Ctrl+C.</summary>
    /// <remarks>
    /// The same <see cref="PeerHost"/> the tray runs for every folder, here with one folder
    /// registered, on the machine's port rather than any port the folder's config records
    /// (D-40). So it cannot run beside a tray on this machine: both want the one port, and
    /// the second is told so rather than serving from somewhere unexpected.
    /// </remarks>
    private static async Task<int> ServeAsync()
    {
        var machine = MasterConfig.Load();
        MachineConfig.WarnAboutProblems(machine);

        using var repository = Open();
        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
        var server = PeerHost.ForMachine(identity, machine, Console.WriteLine);
        server.Servers = ServerCommands.Exchange(identity, machine);
        await using var _ = server.ConfigureAwait(false);
        await using var registration = server.Register(repository).ConfigureAwait(false);
        using var stopping = new CancellationTokenSource();

        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopping.Cancel();
        };

        Console.WriteLine("Serving. Press Ctrl+C to stop.");
        Console.WriteLine(
            OperatingSystem.IsWindows()
                ? "Keep Alive is on: this machine stays awake while blocks are moving, " +
                  "and only then. See 'sip help keep-alive'."
                : "Keep Alive is a Windows feature and is inactive on this platform.");

        await server.RunAsync(stopping.Token).ConfigureAwait(false);

        if (SleepBlocker.LastCallFailed)
        {
            await Console.Error.WriteLineAsync(
                "sip: Keep Alive could not be set at least once. Transfers still ran, but " +
                "this machine may have been free to sleep during one.").ConfigureAwait(false);
        }

        return ExitSuccess;
    }

    private static int PrintHelp(string[] args)
    {
        if (args.Length == 0)
        {
            Help.PrintOverview();
            return ExitSuccess;
        }

        if (Help.PrintCommand(args[0]))
        {
            return ExitSuccess;
        }

        return Usage($"There is no command called '{args[0]}'.");
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"sip: '{command}' is not a command.");
        Console.Error.WriteLine("Run 'sip help' to see what is.");
        return ExitUsage;
    }

    /// <summary>
    /// Opens the repository in the current directory, asking for a passphrase if this
    /// machine's copy is locked.
    /// </summary>
    /// <remarks>
    /// Every command that opens a repository needs the key — they all read blocks or
    /// snapshots — so the prompt belongs here rather than in a separate helper that each
    /// command has to remember to call. It was a separate helper for about twenty minutes,
    /// and in that time <c>sip status</c> and <c>sip log</c> failed on a locked folder
    /// <em>even with the correct passphrase supplied</em>, because they were still calling
    /// the plain one. Found by running the commands, not by reading them.
    /// </remarks>
    private static SipRepository Open() => OpenPossiblyLocked();

    /// <summary>Offers a pairing code, or enters one from another machine.</summary>
    private static async Task<int> PairAsync(string[] args)
    {
        var sub = args.Length == 0 ? "OFFER" : args[0].ToUpperInvariant();

        switch (sub)
        {
            case "OFFER":
            {
                using var repository = Open();
                using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);

                var port = MasterConfig.Load().ListenPort;

                // D-43. With no host argument this used to be "127.0.0.1", printed into the
                // command the other machine ran — which then recorded this machine as itself.
                // Nothing here is handed to the other machine now; the addresses are printed
                // so a person can read the right one out, and the other machine records
                // whichever one it actually reached.
                string? typedHost = null;
                MachineOwner? owner = null;
                for (var i = 1; i < args.Length; i++)
                {
                    if (string.Equals(args[i], "--owner", StringComparison.OrdinalIgnoreCase))
                    {
                        if (OwnerQuestion.TryRead(++i < args.Length ? args[i] : null, out var answered) is { } wrong)
                        {
                            return Usage(wrong);
                        }

                        owner = answered;
                    }
                    else if (typedHost is null && !args[i].StartsWith('-'))
                    {
                        typedHost = args[i];
                    }
                    else
                    {
                        return Usage($"'{args[i]}' is not an option of sip pair offer.");
                    }
                }

                IReadOnlyList<string> hosts;
                if (typedHost is not null)
                {
                    if (!TryReadOfferedHost(typedHost, port, "sip pair offer", out var given, out var problem))
                    {
                        return Usage(problem);
                    }

                    hosts = [given];
                }
                else
                {
                    hosts = LocalAddresses.UsableIPv4();
                }

                var server = new PairingServer(repository, identity, null, Console.WriteLine, port);
                await using var _ = server.ConfigureAwait(false);

                server.Start();

                Console.WriteLine();
                Console.WriteLine($"  {server.Code}");
                Console.WriteLine();

                if (hosts.Count == 0)
                {
                    Console.WriteLine("  No usable network address was found on this machine. On the other");
                    Console.WriteLine("  machine, in an empty folder, use whatever address reaches this one:");
                    Console.WriteLine($"    sip pair enter <address>:{port} <code>");
                }
                else if (typedHost is not null || hosts.Count == 1)
                {
                    Console.WriteLine("  On the other machine, in an empty folder, run:");
                    Console.WriteLine($"    sip pair enter {HostAndPort.Format(hosts[0], port)} <code>");
                }
                else
                {
                    Console.WriteLine("  On the other machine, in an empty folder, run this with whichever of");
                    Console.WriteLine("  this machine's addresses it can reach. Those with a gateway come first.");

                    foreach (var host in hosts)
                    {
                        Console.WriteLine($"    sip pair enter {HostAndPort.Format(host, port)} <code>");
                    }
                }

                Console.WriteLine();

                // Said here, at the moment the code is created, rather than in a help page
                // nobody opens while they are holding a live code. What it protects, and the
                // limit, next to each other.
                Console.WriteLine("  The code never crosses the network: someone recording the traffic learns");
                Console.WriteLine("  nothing they could test it against. What that cannot protect against is");
                Console.WriteLine("  someone who HEARS it. Whoever uses it first, within ten minutes, pairs");
                Console.WriteLine("  instead of your machine and gets the key to every document in this folder.");
                Console.WriteLine("  Say it only to the person at the other machine; do not paste it into a chat.");
                Console.WriteLine();
                Console.WriteLine("  It stops working in ten minutes, after one machine uses it, or after");
                Console.WriteLine("  five wrong answers. Ctrl+C to stop waiting.");
                Console.WriteLine();

                // Waits for the exchange to FINISH, not merely to be decided. Polling
                // IsOpen tore the server down mid-handshake — see WaitForOutcomeAsync.
                var outcome = await server.WaitForOutcomeAsync().ConfigureAwait(false);
                return ReportOffer(server, outcome, "sip pair offer", repository.Config.Name, owner);
            }

            case "ENTER":
            {
                if (args.Length < 3)
                {
                    return Usage(
                        "sip pair enter <host[:port]> <code> [--mode power|simple] [--name <peer-name>] " +
                        "[--owner mine|someone-else]");
                }

                // With no port given, the other machine is taken to serve on the same port as
                // this one, as 'sip peer add' takes it: both read it from their own master.json,
                // and a port moved on one is normally moved on both.
                var machine = MasterConfig.Load();
                if (!HostAndPort.TryParse(args[1], machine.ListenPort, out var address, out var problem))
                {
                    return Usage(problem);
                }

                // The code may arrive as one argument or, typed with spaces, as three; the
                // same options as 'sip join' may follow it.
                var codeParts = new List<string>();
                var recorded = new RecordedOrigin();
                MachineOwner? owner = null;
                var options = new PairingJoinOptions
                {
                    Directory = Directory.GetCurrentDirectory(),
                    ListenPort = machine.ListenPort,
                    Recorded = recorded.Keep,
                };

                for (var i = 2; i < args.Length; i++)
                {
                    switch (args[i].ToUpperInvariant())
                    {
                        case "--MODE":
                            if (++i >= args.Length ||
                                !Enum.TryParse<RepositoryMode>(args[i], ignoreCase: true, out var mode))
                            {
                                return Usage("--mode needs a value: power or simple.");
                            }

                            options = options with { Mode = mode };
                            break;

                        case "--NAME":
                            if (++i >= args.Length)
                            {
                                return Usage("--name needs a value.");
                            }

                            options = options with { PeerName = args[i] };
                            break;

                        case "--PORT":
                            return PortIsMachineWide("sip pair enter");

                        case "--OWNER":
                            if (OwnerQuestion.TryRead(++i < args.Length ? args[i] : null, out var answered) is { } wrong)
                            {
                                return Usage(wrong);
                            }

                            owner = answered;
                            break;

                        default:
                            codeParts.Add(args[i]);
                            break;
                    }
                }

                using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);

                using var joined = await PairingClient.JoinWithCodeAsync(
                    address.Host, address.Port, string.Join(' ', codeParts), identity, options)
                    .ConfigureAwait(false);

                PrintJoined(joined, recorded, owner);
                return ExitSuccess;
            }

            default:
                return Usage($"'{args[0]}' is not a subcommand of sip pair. Use offer or enter.");
        }
    }

    /// <summary>Checks this repository against the minimum standards.</summary>
    private static async Task<int> DoctorAsync()
    {
        using var repository = Open();
        return await Doctor.RunAsync(repository, AppPaths.DeviceKeyFile, MasterConfig.Load())
            .ConfigureAwait(false);
    }

    /// <summary>Shows storage use, sets retention, and reclaims space.</summary>
    private static async Task<int> BucketAsync(string[] args)
    {
        using var repository = Open();

        var sub = args.Length == 0 ? "SHOW" : args[0].ToUpperInvariant();

        switch (sub)
        {
            case "SHOW":
            {
                var usage = await repository.MeasureBucketAsync().ConfigureAwait(false);
                var policy = repository.Bucket;

                Console.WriteLine($"Bucket for '{repository.Config.Name}'");
                Console.WriteLine();
                Console.WriteLine($"  used         {usage.Describe()}");

                if (usage.Fraction is { } fraction)
                {
                    Console.WriteLine(string.Create(
                        CultureInfo.InvariantCulture,
                        $"  of quota     {fraction * 100:0.#}%{(usage.IsFull ? "  FULL" : string.Empty)}"));
                }

                Console.WriteLine($"  blocks       {usage.BlockCount}");
                Console.WriteLine($"  snapshots    {usage.SnapshotCount}");
                Console.WriteLine();

                // Reported whether or not anything is wrong. A number that only appears at
                // the moment of failure is a number nobody ever gets to act on.
                Console.WriteLine($"  reclaimable  {BucketUsage.Bytes(usage.ReclaimableBytes)}");
                Console.WriteLine(
                    $"               {usage.UnreferencedBlockCount} block(s) nothing refers to, " +
                    $"{usage.PrunableSnapshotCount} snapshot(s) past the policy");
                Console.WriteLine();
                Console.WriteLine($"  policy       {Describe(policy)}");

                if (usage.HasReclaimable)
                {
                    Console.WriteLine();
                    Console.WriteLine("Run 'sip bucket collect' to reclaim it.");
                }

                return ExitSuccess;
            }

            case "COLLECT":
            {
                var result = await repository.CollectAsync().ConfigureAwait(false);
                Console.WriteLine(result.Summary);
                return ExitSuccess;
            }

            case "KEEP":
            {
                if (args.Length < 2)
                {
                    return Usage("sip bucket keep needs a value: all, <n>, or <n>d.");
                }

                var value = args[1];
                BucketPolicy policy;

                if (value.Equals("all", StringComparison.OrdinalIgnoreCase))
                {
                    policy = repository.Bucket with { KeepSnapshots = null, KeepDays = null };
                }
                else if (value.EndsWith('d') &&
                         int.TryParse(value[..^1], CultureInfo.InvariantCulture, out var days))
                {
                    policy = repository.Bucket with { KeepSnapshots = null, KeepDays = days };
                }
                else if (int.TryParse(value, CultureInfo.InvariantCulture, out var count))
                {
                    policy = repository.Bucket with { KeepSnapshots = count, KeepDays = null };
                }
                else
                {
                    return Usage($"'{value}' is not a retention value. Use all, <n>, or <n>d.");
                }

                repository.SetBucketPolicy(policy);
                Console.WriteLine($"Retention: {Describe(policy)}");

                var after = await repository.MeasureBucketAsync().ConfigureAwait(false);
                if (after.HasReclaimable)
                {
                    Console.WriteLine(
                        $"{BucketUsage.Bytes(after.ReclaimableBytes)} could now be reclaimed. " +
                        "Run 'sip bucket collect'.");
                }

                return ExitSuccess;
            }

            case "QUOTA":
            {
                if (args.Length < 2)
                {
                    return Usage("sip bucket quota needs a size, or 'none'.");
                }

                long? quota = null;
                if (!args[1].Equals("none", StringComparison.OrdinalIgnoreCase))
                {
                    if (!TryParseSize(args[1], out var parsed))
                    {
                        return Usage($"'{args[1]}' is not a size. Try 3GiB, 500MiB or none.");
                    }

                    quota = parsed;
                }

                repository.SetBucketPolicy(repository.Bucket with { QuotaBytes = quota });

                Console.WriteLine(quota is { } bytes
                    ? $"Quota: {BucketUsage.Bytes(bytes)}"
                    : "Quota: none");

                return ExitSuccess;
            }

            default:
                return Usage($"'{args[0]}' is not a subcommand of sip bucket.");
        }
    }

    private static string Describe(BucketPolicy policy)
    {
        var parts = new List<string>
        {
            policy.KeepSnapshots is { } keep
                ? $"keep {keep} snapshot(s)"
                : policy.KeepDays is { } days
                    ? $"keep {days} day(s)"
                    : "keep everything",
            policy.QuotaBytes is { } quota ? $"quota {BucketUsage.Bytes(quota)}" : "no quota",
        };

        return string.Join(", ", parts);
    }

    /// <summary>Parses a size like 3GiB, 500MiB or 1024.</summary>
    /// <remarks>
    /// Binary units only, and the suffix is required to be binary. Accepting "GB" and
    /// quietly treating it as GiB is how storage tools end up disagreeing with the disk.
    /// </remarks>
    private static bool TryParseSize(string value, out long bytes)
    {
        bytes = 0;

        var multipliers = new (string Suffix, long Scale)[]
        {
            ("TIB", 1L << 40),
            ("GIB", 1L << 30),
            ("MIB", 1L << 20),
            ("KIB", 1L << 10),
        };

        var upper = value.ToUpperInvariant();

        foreach (var (suffix, scale) in multipliers)
        {
            if (upper.EndsWith(suffix, StringComparison.Ordinal) &&
                double.TryParse(
                    upper[..^suffix.Length], CultureInfo.InvariantCulture, out var scaled))
            {
                bytes = (long)(scaled * scale);
                return bytes > 0;
            }
        }

        return long.TryParse(upper, CultureInfo.InvariantCulture, out bytes) && bytes > 0;
    }

    /// <summary>Puts this machine's copy behind a passphrase, or takes it back off.</summary>
    private static int Lock(string[] args)
    {
        var removing = args.Length > 0 &&
                       args[0].Equals("--off", StringComparison.OrdinalIgnoreCase);

        var directory = Directory.GetCurrentDirectory();

        if (removing)
        {
            using var locked = OpenPossiblyLocked();

            if (!locked.IsLocked)
            {
                Console.WriteLine("This copy is not locked.");
                return ExitSuccess;
            }

            var current = ReadPassphrase("Current passphrase: ");
            if (current is null)
            {
                return CannotPrompt();
            }

            locked.RemovePassphrase(current);

            Console.WriteLine("Lock removed. The key is stored in the clear again.");
            return ExitSuccess;
        }

        using var repository = SipRepository.Open(directory);

        if (repository.IsLocked)
        {
            return Fail("This copy is already locked. Use 'sip lock --off' first.");
        }

        var first = ReadPassphrase("New passphrase: ");
        if (first is null)
        {
            return CannotPrompt();
        }

        if (string.IsNullOrEmpty(first))
        {
            return Usage("A passphrase is required.");
        }

        // Confirmation is skipped when the passphrase came from the environment: there is
        // nothing to mistype, and asking twice for the same variable is theatre.
        if (Environment.GetEnvironmentVariable(PassphraseVariable) is null &&
            !string.Equals(first, ReadPassphrase("Again: "), StringComparison.Ordinal))
        {
            return Fail("Those did not match. Nothing was changed.");
        }

        repository.SetPassphrase(first);

        Console.WriteLine();
        Console.WriteLine($"'{repository.Config.Name}' is now locked on this machine.");
        Console.WriteLine();

        // Said at the moment of locking, not buried in a help page, because this is exactly
        // when someone forms a belief about what they have just done.
        Console.WriteLine("  This covers    another account on this PC reading .sip,");
        Console.WriteLine("                 and .sip being copied elsewhere.");
        Console.WriteLine("  It does not    cover other machines - each is locked separately, and");
        Console.WriteLine("                 pairing sends the key to each new one - or this PC");
        Console.WriteLine("                 while unlocked.");
        Console.WriteLine();
        Console.WriteLine("  There is no recovery. Lose the passphrase and this copy is lost;");
        Console.WriteLine("  a paired machine would still have the documents.");

        return ExitSuccess;
    }

    /// <summary>Reports whether this copy is locked, and checks a passphrase opens it.</summary>
    private static int Unlock(string[] args)
    {
        _ = args;

        var directory = Directory.GetCurrentDirectory();

        if (!SipRepository.IsLockedAt(directory))
        {
            Console.WriteLine("This copy is not locked; no passphrase is needed.");
            return ExitSuccess;
        }

        using var repository = OpenPossiblyLocked();

        Console.WriteLine($"'{repository.Config.Name}' unlocked.");
        Console.WriteLine();

        // The honest limit of a one-shot CLI unlock, stated rather than implied. The daemon
        // holds its key for as long as it runs; this process is about to exit.
        Console.WriteLine("  Note: this unlocked the folder for THIS command only.");
        Console.WriteLine("  The tray holds the key for as long as it is running.");

        return ExitSuccess;
    }

    /// <summary>
    /// Opens the repository, prompting for a passphrase if this machine's copy is locked.
    /// </summary>
    /// <remarks>
    /// Non-interactive callers get a clear failure rather than a prompt they cannot answer,
    /// which is what stops a scheduled task hanging forever on an invisible question.
    /// </remarks>
    private static SipRepository OpenPossiblyLocked() => OpenFolder(Directory.GetCurrentDirectory());

    /// <summary>
    /// Opens the repository in a folder, asking for a passphrase if this machine's copy is
    /// locked: what every command that opens a folder does, for a folder named rather than the
    /// current one.
    /// </summary>
    /// <param name="directory">The folder.</param>
    /// <returns>The open repository.</returns>
    internal static SipRepository OpenFolder(string directory)
    {
        if (!SipRepository.IsLockedAt(directory))
        {
            return SipRepository.Open(directory);
        }

        while (true)
        {
            // Returns null when nobody is there to answer. Without that check a scheduled
            // task hangs on an invisible prompt forever, which is indistinguishable from
            // the daemon wedging - the exact failure this project has just spent a day
            // removing from the network path.
            var passphrase = ReadPassphrase("Passphrase: ");

            if (string.IsNullOrEmpty(passphrase))
            {
                throw new RepositoryLockedException(directory);
            }

            try
            {
                return SipRepository.Unlock(directory, passphrase);
            }
            catch (WrongPassphraseException)
            {
                // A supplied passphrase will not become correct by being asked for again,
                // and looping on it would spin forever in a script. Rethrow without a
                // message here: the top-level handler prints one, and two lines saying the
                // same thing reads like two separate failures.
                if (Environment.GetEnvironmentVariable(PassphraseVariable) is not null)
                {
                    throw;
                }

                Console.Error.WriteLine("sip: that passphrase does not open this folder.");
            }
        }
    }

    /// <summary>The environment variable a non-interactive run supplies a passphrase through.</summary>
    private const string PassphraseVariable = "SIP_PASSPHRASE";

    /// <summary>
    /// Obtains a passphrase: from the environment when set, otherwise by prompting.
    /// </summary>
    /// <returns>The passphrase, or null when there is no way to obtain one.</returns>
    /// <remarks>
    /// <para>
    /// <see cref="Console.ReadKey(bool)"/> throws outright when input is redirected, which
    /// is how the first version of this crashed with an unhandled exception the moment
    /// anything piped into it — found by running the command rather than by reading it.
    /// Compiling proved nothing about this.
    /// </para>
    /// <para>
    /// The environment variable exists because a tool with no non-interactive path makes
    /// people invent worse ones. Borg does the same thing for the same reason. It is not
    /// free: an environment variable is visible to other processes of the same user and
    /// tends to end up in shell history and CI logs, so the help says so plainly rather
    /// than presenting it as the convenient option.
    /// </para>
    /// </remarks>
    private static string? ReadPassphrase(string prompt)
    {
        var supplied = Environment.GetEnvironmentVariable(PassphraseVariable);
        if (!string.IsNullOrEmpty(supplied))
        {
            return supplied;
        }

        if (Console.IsInputRedirected)
        {
            return null;
        }

        Console.Write(prompt);

        var typed = new System.Text.StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return typed.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (typed.Length > 0)
                {
                    typed.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                typed.Append(key.KeyChar);
            }
        }
    }

    /// <summary>The message shown when a passphrase is needed and cannot be asked for.</summary>
    private static int CannotPrompt() =>
        FailWithHint(
            "A passphrase is needed, but input is redirected so it cannot be asked for.",
            $"Set {PassphraseVariable} for unattended use - see 'sip help lock'.");

    /// <summary>The twelve-character short form 'sip peer list' prints.</summary>
    /// <remarks>
    /// Bounded rather than sliced blindly, because a hand-edited peers.json can hold a
    /// device ID shorter than twelve characters, or none at all, and failing to print a peer
    /// is a poor way to report one (D-65). Every place that prints a device ID from the peer
    /// list goes through here.
    /// </remarks>
    private static string ShortDeviceId(string? deviceId) =>
        deviceId is null ? "no device ID" : deviceId[..Math.Min(12, deviceId.Length)];

    /// <summary>
    /// Reads an address a person gives for the other machine to reach this one by, in
    /// <c>sip pair offer [host]</c> and <c>sip invite --host</c>.
    /// </summary>
    /// <param name="text">What was typed.</param>
    /// <param name="port">This folder's sync port, which pairing is offered next to.</param>
    /// <param name="command">The command and option, for the messages.</param>
    /// <param name="host">The host, without brackets or port, when this returns true.</param>
    /// <param name="problem">What is wrong with it, when this returns false.</param>
    /// <returns>True when it is a host this machine can be reached at.</returns>
    /// <remarks>
    /// Stricter than an address for <c>sip peer add</c>, which records where another machine
    /// is. These say where THIS one is, and this one listens on IPv4 only (D-05), so an IPv6
    /// address offered here could never answer. Refused, saying why, rather than handed on to
    /// fail at the other machine as a connection that timed out. A port is refused unless it
    /// is the folder's own: pairing is offered next to it, and the invite carries it.
    /// </remarks>
    private static bool TryReadOfferedHost(string text, int port, string command, out string host, out string problem)
    {
        host = string.Empty;

        if (!HostAndPort.TryParse(text, port, out var address, out problem))
        {
            return false;
        }

        if (System.Net.IPAddress.TryParse(address.Host, out var literal) &&
            literal.AddressFamily == AddressFamily.InterNetworkV6)
        {
            problem = "SippBucket does not listen on IPv6 yet, so another machine cannot reach this " +
                      $"one at {address.Host}. Give '{command}' a host name or an IPv4 address.";
            return false;
        }

        if (address.Port != port)
        {
            problem = $"This folder pairs through its sync port, {port}; give '{command}' an " +
                      "address without a port.";
            return false;
        }

        host = address.Host;
        return true;
    }

    /// <summary>Says which record a new one replaced, when it replaced one.</summary>
    /// <remarks>
    /// One sentence for every command that records a peer: 'sip peer add', both ends of
    /// 'sip pair' and of 'sip invite' and 'sip join' (D-25, D-64). The record keeps its place
    /// in the list and when it last synced; what changes is the name and address, so those
    /// are what is said.
    /// </remarks>
    private static void PrintReplaced(PeerRecord? replaced)
    {
        if (replaced is null)
        {
            return;
        }

        Console.WriteLine(
            $"That device was already listed; replaced '{replaced.Name}' at " +
            $"{HostAndPort.Format(replaced.Host, replaced.Port)}.");
    }

    /// <summary>Lists the records in peers.json that are skipped, and how to deal with them.</summary>
    /// <remarks>
    /// Printed by 'sip peer list' under the peers in use. The file is meant to be edited by
    /// hand, so a typo is shown to the person who made it, with the record's position and
    /// what is wrong, rather than crashing the listing (D-65) or vanishing from it.
    /// </remarks>
    private static void PrintSkipped(IReadOnlyList<SkippedPeerRecord> skipped, string peersFile)
    {
        if (skipped.Count == 0)
        {
            return;
        }

        Console.WriteLine();
        Console.WriteLine(
            $"{skipped.Count} record(s) in peers.json cannot be used, so nothing syncs with them:");

        foreach (var record in skipped)
        {
            var name = string.IsNullOrWhiteSpace(record.Name) ? "(no name)" : $"'{record.Name}'";
            Console.WriteLine($"  record {record.Position}  {name}: {record.Describe()}");
        }

        Console.WriteLine($"Fix them in {peersFile}, or remove one: sip peer remove <name>");
    }

    /// <summary>What a join reported recording for the offering machine.</summary>
    private sealed class RecordedOrigin
    {
        /// <summary>The record written for the offering machine.</summary>
        public PeerRecord? Origin { get; private set; }

        /// <summary>The record it replaced, if the folder's peer list already had one.</summary>
        public PeerRecord? Replaced { get; private set; }

        /// <summary>The <see cref="PairingJoinOptions.Recorded"/> callback.</summary>
        public void Keep(PeerRecord origin, PeerRecord? replaced)
        {
            Origin = origin;
            Replaced = replaced;
        }
    }

    private static string Bytes(long count)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        double size = count;
        var unit = 0;

        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{count} B"
            : string.Create(CultureInfo.InvariantCulture, $"{size:0.#} {units[unit]}");
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitFailure;
    }

    /// <summary>Fails with a second line naming what to do about it.</summary>
    /// <remarks>
    /// For the failures where the user's next action is specific and knowable. An error that
    /// says only what went wrong leaves someone to guess at the remedy; these three know it.
    /// </remarks>
    private static int FailWithHint(string message, string hint)
    {
        Console.Error.WriteLine($"sip: {message}");
        Console.Error.WriteLine($"     {hint}");
        return ExitFailure;
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitUsage;
    }

    /// <summary>Refuses a <c>--port</c> option that no longer means anything.</summary>
    /// <remarks>
    /// These commands used to take the port this folder would be served on. Since D-40 one
    /// port serves every folder on the machine, so a per-folder port can only be ignored, and
    /// an option silently ignored is a promise broken quietly. Refused, with where the port
    /// is set now.
    /// </remarks>
    private static int PortIsMachineWide(string command) =>
        Usage(
            $"{command} no longer takes --port: one port now serves every folder on this machine. " +
            $"It is {MasterConfig.Load().ListenPort}; change it with " +
            $"'sip config set {MasterSettings.ListenPort.Key} <port>'.");
}

