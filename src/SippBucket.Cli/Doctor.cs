using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Platform;
using SippBucket.Core.Protocol;
using SippBucket.Core.Push;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;
using SippBucket.Core.Sync;

namespace SippBucket.Cli;

/// <summary>
/// Checks this repository against the minimum standards in <c>STANDARDS.md</c>.
/// </summary>
/// <remarks>
/// <para>
/// A standards document nobody can run is a wish list. This runs the subset that can be
/// checked mechanically, and — more importantly — <em>prints the ones that cannot</em>
/// rather than quietly omitting them. A tool that reports "all checks passed" while
/// silently skipping the four rules it has no way to verify is committing the exact
/// offence the first standard exists to prevent.
/// </para>
/// <para>
/// Everything here reads. Nothing is repaired, because a doctor that fixes things while
/// reporting on them cannot be run to find out what is wrong.
/// </para>
/// </remarks>
internal static class Doctor
{
    /// <summary>One rule's verdict.</summary>
    private enum Verdict
    {
        Pass,
        Warn,
        Fail,
        NeedsAHuman,
        Note,
    }

    private sealed record Check(string Rule, Verdict Verdict, string Detail);

    /// <summary>Runs every check and prints the report.</summary>
    /// <param name="repository">The repository to examine.</param>
    /// <param name="deviceKeyFile">This machine's device key file.</param>
    /// <param name="machine">This machine's settings, from <c>master.json</c>.</param>
    /// <param name="cancellationToken">Cancels the run.</param>
    /// <returns>Zero when nothing failed, one otherwise.</returns>
    public static async Task<int> RunAsync(
        SipRepository repository,
        string deviceKeyFile,
        MasterConfig machine,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceKeyFile);
        ArgumentNullException.ThrowIfNull(machine);

        var checks = new List<Check>();

        checks.AddRange(MachineChecks(machine));
        checks.Add(PortCheck(repository, machine));
        checks.AddRange(NetworkChecks(machine));
        checks.AddRange(PortMappingChecks(machine));
        checks.AddRange(await DirectPushChecksAsync(machine, cancellationToken).ConfigureAwait(false));
        checks.Add(LockCheck(repository));
        checks.Add(DeviceKeyCheck(deviceKeyFile));
        checks.AddRange(await StorageChecksAsync(repository, cancellationToken).ConfigureAwait(false));
        checks.AddRange(SnapshotChecks(repository));
        checks.AddRange(OwnerFileChecks(repository));
        checks.AddRange(AntivirusChecks(repository));
        checks.AddRange(NotMechanicallyCheckable());

        Console.WriteLine($"sip doctor — '{repository.Config.Name}'");
        Console.WriteLine();

        foreach (var check in checks)
        {
            var mark = check.Verdict switch
            {
                Verdict.Pass => "  ok  ",
                Verdict.Warn => " warn ",
                Verdict.Fail => " FAIL ",
                Verdict.Note => " note ",
                _ => "  --  ",
            };

            Console.WriteLine($"{mark}{check.Rule,-8}{check.Detail}");
        }

        var failures = checks.Count(c => c.Verdict == Verdict.Fail);
        var warnings = checks.Count(c => c.Verdict == Verdict.Warn);
        var human = checks.Count(c => c.Verdict == Verdict.NeedsAHuman);
        var notes = checks.Count(c => c.Verdict == Verdict.Note);

        Console.WriteLine();
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{checks.Count - human - notes} checked · {failures} failed · {warnings} warned · " +
            $"{human} need a person"));

        if (human > 0)
        {
            // Said explicitly. The alternative - printing only what was checked - would let
            // "sip doctor is clean" come to mean more than it does, which is rule A1.
            Console.WriteLine();
            Console.WriteLine("The rules marked -- cannot be checked by a program. A clean run");
            Console.WriteLine("here does not mean they hold. See STANDARDS.md.");
        }

        return failures == 0 ? 0 : 1;
    }

    /// <summary>
    /// The machine's <c>master.json</c>: every value that differs from its default, and every
    /// entry that fell back or was ignored.
    /// </summary>
    /// <remarks>
    /// Listed whether or not anything is wrong, because that is the promise the file is kept
    /// on (docs/MASTER-CONFIG.md): it is hidden from the window, not from anyone who looks,
    /// and a machine tuned away from its defaults says so here. A value that differs is a
    /// note, not a warning; somebody chose it. An entry that fell back is a warning, because
    /// somebody chose something and did not get it.
    /// </remarks>
    private static IEnumerable<Check> MachineChecks(MasterConfig machine)
    {
        if (!machine.FileExists)
        {
            yield return new Check("CFG", Verdict.Pass, $"no {MasterConfig.FileName}; every machine setting is at its default");
        }

        foreach (var value in machine.Values.Where(v => v.DiffersFromDefault))
        {
            yield return new Check("CFG", Verdict.Note, string.Create(
                CultureInfo.InvariantCulture,
                $"{value.Setting.Key} is {value.Value}, not the default {value.Setting.Default}"));
        }

        foreach (var problem in machine.Problems)
        {
            yield return new Check("CFG", Verdict.Warn, problem.Message);
        }

        if (machine.FileExists && machine.Problems.Count == 0 && !machine.Values.Any(v => v.DiffersFromDefault))
        {
            yield return new Check("CFG", Verdict.Pass, $"{MasterConfig.FileName} sets nothing different from the defaults");
        }
    }

    /// <summary>
    /// Whether this folder was set up on the port the machine now serves it on.
    /// </summary>
    /// <remarks>
    /// Before D-40 each folder was served on the port in its own config, and <c>sip init</c>,
    /// <c>sip join</c> and <c>sip pair enter</c> took <c>--port</c>. Every folder is served on
    /// the machine's port now, so a folder set up on another port stopped being reachable at
    /// the address its peers were given, and nothing said so. The config's port is the only
    /// record of what they were given. Once every paired machine has the new port,
    /// <c>sip peer port-updated</c> records that, and this line passes; before that command
    /// existed the warning could only be cleared by moving the port back.
    /// </remarks>
    private static Check PortCheck(SipRepository repository, MasterConfig machine)
    {
        var recorded = repository.Config.ListenPort.ToString(CultureInfo.InvariantCulture);
        var served = machine.ListenPort.ToString(CultureInfo.InvariantCulture);

        return repository.Config.ListenPort == machine.ListenPort
            ? new Check("CFG", Verdict.Pass, $"this folder is served on port {served}, the port it was set up with")
            : new Check(
                "CFG",
                Verdict.Warn,
                $"this folder was set up on port {recorded} and is served on port {served}, the machine's " +
                $"server.listenPort. Machines paired with it were given {recorded}: on each, run 'sip peer add' " +
                $"with port {served}, then run 'sip peer port-updated' here; or set this machine back with " +
                $"'sip config set server.listenPort {recorded}'.");
    }

    private static IEnumerable<Check> NetworkChecks(MasterConfig machine)
    {
        var stall = machine.Sync.StallTimeout;

        yield return stall > TimeSpan.Zero
            ? new Check("C1", Verdict.Pass,
                $"every read and write carries a {stall.TotalSeconds:0}s stall deadline")
            : new Check("C1", Verdict.Fail, "no stall deadline is configured");

        // Asserts the RELATIONSHIP, not either number. Someone tidying the two constants
        // into one would reintroduce the amplification exactly, and a check on either value
        // alone would not notice.
        var ratio = Framing.MaximumFrameSize / (double)Framing.HandshakeFrameSize;

        yield return ratio >= 1000
            ? new Check("C2", Verdict.Pass, string.Create(
                CultureInfo.InvariantCulture,
                $"pre-auth frames capped at {Framing.HandshakeFrameSize / 1024} KiB, " +
                $"{ratio:0} times below the authenticated ceiling"))
            : new Check("C2", Verdict.Fail, string.Create(
                CultureInfo.InvariantCulture,
                $"pre-auth ceiling is only {ratio:0.#} times below the authenticated one"));
    }

    /// <summary>
    /// Direct Push on this machine: whether it is on, and when it is, whether it can work.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per machine rather than per folder, and printed with every folder's report for that reason.
    /// Whether anything answers on the port is found by connecting to it once and reading the SSH
    /// version line a SippBucket SSH server sends first; the daemon's log records that connection
    /// as one that ended during the handshake.
    /// </para>
    /// <para>
    /// Reads only, like the rest of the doctor: a quarantined file something else removed is shown
    /// here, and recorded as removed only by <c>sip quarantine</c>.
    /// </para>
    /// </remarks>
    private static async Task<IEnumerable<Check>> DirectPushChecksAsync(MasterConfig machine, CancellationToken cancellationToken)
    {
        var checks = new List<Check>();

        PushPreferences preferences;
        try
        {
            preferences = PushPreferencesStore.ForThisUser().Load();
        }
        catch (JsonException ex)
        {
            checks.Add(new Check("PUSH", Verdict.Fail, ex.Message));
            return checks;
        }

        var settings = machine.Push;
        var port = settings.Port.ToString(CultureInfo.InvariantCulture);

        if (!preferences.Enabled)
        {
            checks.Add(new Check("PUSH", Verdict.Pass, $"Direct Push is off, so nothing listens on port {port}; 'sip push on' turns it on"));
            return checks;
        }

        if (machine.Problems.FirstOrDefault(problem => problem.Kind == ConfigProblemKind.PortClash) is { } clash)
        {
            checks.Add(new Check("PUSH", Verdict.Fail, $"Direct Push is on and cannot listen: {clash.Message}"));
        }

        if (!PushInbox.IsUsableRoot(preferences.InboxRoot, out var unusable))
        {
            checks.Add(new Check("PUSH", Verdict.Fail, unusable));
            return checks;
        }

        if (PushInbox.ConflictWithSyncedFolders(preferences.InboxRoot, WatchedFolders.Load()) is { } conflict)
        {
            checks.Add(new Check("PUSH", Verdict.Fail, $"Direct Push is on and cannot listen: {conflict}"));
        }

        checks.Add(await AnswersAsSshAsync(settings.Port, cancellationToken).ConfigureAwait(false)
            ? new Check("PUSH", Verdict.Pass, $"Direct Push is on and listening on port {port}")
            : new Check("PUSH", Verdict.Warn,
                $"Direct Push is on, and nothing answers on port {port}: SippBucket may not be running, or cannot " +
                "open the port. The activity in its window says which."));

        var inbox = new PushInbox(preferences.InboxRoot);
        checks.Add(DiskCheck(inbox));

        var quarantined = inbox.Quarantine.Inspect();
        var used = inbox.Quarantine.UsedBytes();
        checks.Add(used * 10 >= settings.QuarantineCapBytes * 9
            ? new Check("PUSH", Verdict.Warn,
                $"the quarantine holds {BucketUsage.Bytes(used)} of its {BucketUsage.Bytes(settings.QuarantineCapBytes)}; " +
                "once it is full, a file that belongs there is refused. 'sip quarantine' lists what is in it")
            : new Check("PUSH", Verdict.Pass,
                $"the quarantine holds {quarantined.Items.Count(item => item.Present)} file(s), " +
                $"{BucketUsage.Bytes(used)} of its {BucketUsage.Bytes(settings.QuarantineCapBytes)}"));

        var removed = quarantined.Items.Count(item => !item.Present);
        if (removed > 0)
        {
            checks.Add(new Check("PUSH", Verdict.Note, string.Create(
                CultureInfo.InvariantCulture,
                $"{removed} quarantined file(s) were removed by something other than SippBucket, most likely the antivirus")));
        }

        foreach (var record in quarantined.UnreadableRecords)
        {
            checks.Add(new Check("PUSH", Verdict.Warn, $"the quarantine record {record} cannot be read"));
        }

        for (var index = 0; index < preferences.Rules.Count; index++)
        {
            if (!InboxRules.IsValid(preferences.Rules[index], inbox, out var reason))
            {
                checks.Add(new Check("PUSH", Verdict.Warn, string.Create(
                    CultureInfo.InvariantCulture,
                    $"forwarding rule {index + 1} is passed over, because {reason}")));
            }
        }

        checks.AddRange(TeamChecks());
        return checks;
    }

    /// <summary>The router mapping's setting (D-05): the doctor reads settings, never the router.</summary>
    private static IEnumerable<Check> PortMappingChecks(MasterConfig machine)
    {
        if (!machine.PortMappingEnabled)
        {
            yield return new Check(
                "NET", Verdict.Pass,
                "port mapping is off: the router is not asked to forward the sync port. " +
                "'sip config set network.portMapping 1' turns it on");
            yield break;
        }

        yield return new Check(
            "NET", Verdict.Pass,
            string.Create(
                CultureInfo.InvariantCulture,
                $"port mapping is on: the daemon asks the router to forward TCP {machine.ListenPort} here for {(int)machine.PortMappingLifetime.TotalMinutes} minute(s) at a time, renewing while it runs.") +
            " The daemon's activity says what the router answered");
        yield return new Check(
            "NET", Verdict.Note,
            "a forwarded port is visible to the whole internet. Only machines in your peer lists can sync, and a " +
            "stranger is dropped at the handshake's fixed deadline; the port's existence is what is exposed");
    }

    /// <summary>The team switch and the message store: what 'sip dm' rests on.</summary>
    private static IEnumerable<Check> TeamChecks()
    {
        var decision = Core.Machines.TeamFeatures
            .ForThisUser(() => PairedMachines.AllDeviceIds(WatchedFolders.Load()))
            .Decide();
        yield return new Check("TEAM", Verdict.Pass, decision.Why);

        if (!decision.On)
        {
            yield break;
        }

        _ = Core.Messages.MessageStore.ForThisUser().Load(out var unreadable);
        if (unreadable > 0)
        {
            yield return new Check("TEAM", Verdict.Warn, string.Create(
                CultureInfo.InvariantCulture,
                $"{unreadable} stored message file(s) cannot be read; they may belong to another account or a newer build"));
        }

        if (!Core.Messages.MessageStore.ProtectionAvailable)
        {
            yield return new Check("TEAM", Verdict.Warn,
                "this platform cannot protect stored messages at rest; they are stored plain");
        }
    }

    /// <summary>The inbox's drive: pushes are refused when it would fall below its reserve.</summary>
    private static Check DiskCheck(PushInbox inbox)
    {
        long free;
        try
        {
            free = new DriveInfo(Path.GetPathRoot(inbox.Root)!).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new Check("PUSH", Verdict.Fail, $"the free space on the inbox's drive cannot be read, so every push is refused: {ex.Message}");
        }

        return free < PushSettings.DiskReserveBytes
            ? new Check("PUSH", Verdict.Fail,
                $"the inbox's drive has {BucketUsage.Bytes(free)} free, under the {BucketUsage.Bytes(PushSettings.DiskReserveBytes)} " +
                "it must keep, so every push is refused until space is freed")
            : new Check("PUSH", Verdict.Pass,
                $"the inbox's drive has {BucketUsage.Bytes(free)} free; every push leaves at least " +
                $"{BucketUsage.Bytes(PushSettings.DiskReserveBytes)}");
    }

    /// <summary>Whether something on this machine's port answers with an SSH version line.</summary>
    private static async Task<bool> AnswersAsSshAsync(int port, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port, deadline.Token).ConfigureAwait(false);

            var line = new byte[8];
            await client.GetStream().ReadExactlyAsync(line, deadline.Token).ConfigureAwait(false);
            return Encoding.ASCII.GetString(line) == "SSH-2.0-";
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    private static Check LockCheck(SipRepository repository) =>
        repository.IsLocked
            ? new Check("D4", Verdict.Pass, "this machine's copy is locked with a passphrase")
            : new Check("D4", Verdict.Warn,
                "this machine's copy is NOT locked — the key is in config.json beside the data");

    /// <summary>What the device key file is on disk.</summary>
    /// <remarks>
    /// <para>
    /// <see cref="DeviceKeyFile"/>'s remarks said this check existed, and it did not (D-51).
    /// It reads the file, not the platform, for the same reason the window now does.
    /// </para>
    /// <para>
    /// A plain key on Windows fails rather than warns. The repository lock above is a choice
    /// the person makes, so its absence is a warning; the device key's protection is not
    /// optional, so a plain file means the protection did not happen. Doctor repairs
    /// nothing, so it says what will: the next command that loads the key rewrites it.
    /// </para>
    /// </remarks>
    private static Check DeviceKeyCheck(string deviceKeyFile) =>
        DeviceKeyFile.Inspect(deviceKeyFile) switch
        {
            DeviceKeyState.Protected => new Check("D4", Verdict.Pass,
                "device key is encrypted by Windows (DPAPI) for this account; programs running " +
                "as you, an administrator while you are signed in, or anyone with your password " +
                "can still read it"),

            DeviceKeyState.Missing => new Check("D4", Verdict.Pass,
                "no device key on this machine yet; one is made, encrypted, when first needed"),

            DeviceKeyState.Unprotected when DeviceKeyFile.IsProtectionAvailable => new Check("D4", Verdict.Fail,
                $"device key is stored UNPROTECTED at {deviceKeyFile}. Any command that uses " +
                "it, 'sip id' for one, encrypts it; if this stays, that rewrite is failing"),

            DeviceKeyState.Unprotected => new Check("D4", Verdict.Warn,
                $"device key is stored unprotected at {deviceKeyFile}: this platform has no DPAPI"),

            _ => new Check("D4", Verdict.Warn,
                $"device key at {deviceKeyFile} could not be read, so its protection is unknown"),
        };

    private static async Task<IEnumerable<Check>> StorageChecksAsync(
        SipRepository repository,
        CancellationToken cancellationToken)
    {
        var usage = await repository.MeasureBucketAsync(cancellationToken).ConfigureAwait(false);
        var checks = new List<Check>();

        checks.Add(usage.UnreferencedBlockCount == 0
            ? new Check("F1", Verdict.Pass,
                $"no orphaned blocks · {usage.BlockCount} block(s), {usage.Describe()}")
            : new Check("F1", Verdict.Warn,
                $"{usage.UnreferencedBlockCount} block(s) nothing refers to, " +
                $"{BucketUsage.Bytes(usage.ReclaimableBytes)} reclaimable · run 'sip bucket collect'"));

        if (usage.IsFull)
        {
            checks.Add(new Check("F2", Verdict.Fail,
                $"bucket is full at {usage.Describe()} — saves will be refused"));
        }
        else if (usage.IsNearlyFull)
        {
            checks.Add(new Check("F2", Verdict.Warn, $"bucket is nearly full at {usage.Describe()}"));
        }
        else
        {
            checks.Add(new Check("F2", Verdict.Pass,
                usage.QuotaBytes is null
                    ? "no quota set · usage is reported but never refused"
                    : $"within quota at {usage.Describe()}"));
        }

        return checks;
    }

    private static IEnumerable<Check> SnapshotChecks(SipRepository repository)
    {
        if (repository.LegacySnapshotsLeftPlaintext > 0)
        {
            yield return new Check("D3", Verdict.Fail,
                $"{repository.LegacySnapshotsLeftPlaintext} snapshot(s) could not be encrypted " +
                "and still have filenames readable on disk");
        }
        else if (repository.LegacySnapshotsEncrypted > 0)
        {
            yield return new Check("D3", Verdict.Pass,
                $"{repository.LegacySnapshotsEncrypted} plaintext snapshot(s) were encrypted on open");
        }
        else
        {
            yield return new Check("D3", Verdict.Pass, "snapshots are encrypted at rest");
        }

        // A file the reader cannot parse at all has no records to report one by one, and it
        // used to end the whole report with the reader's error. Said as this check's failure
        // instead, with the rest of the report still printed: nothing syncs until it is mended.
        PeerList? peers = null;
        string? unreadable = null;
        try
        {
            peers = repository.Peers.Inspect();
        }
        catch (JsonException ex)
        {
            unreadable = ex.Message;
        }

        if (peers is null)
        {
            yield return new Check("A1", Verdict.Fail, $"the peer list cannot be read: {unreadable}");
            yield break;
        }

        yield return peers.Usable.Count == 0
            ? new Check("A1", Verdict.Warn,
                "no peers configured — this folder is not synced with anything")
            : new Check("A1", Verdict.Pass, $"{peers.Usable.Count} peer(s) configured");

        // Each one said, not counted into the line above: a record the person wrote and
        // believes is a peer, which nothing syncs with, is the gap between what they think is
        // configured and what is (D-65).
        foreach (var skipped in peers.Skipped)
        {
            yield return new Check("A1", Verdict.Warn,
                $"peers.json record {skipped.Position}{NameOf(skipped)} is skipped: " +
                $"{skipped.Describe()}. Nothing syncs with it until it is fixed or removed");
        }
    }

    private static string NameOf(SkippedPeerRecord skipped) =>
        string.IsNullOrWhiteSpace(skipped.Name) ? string.Empty : $" ('{skipped.Name}')";

    /// <summary>
    /// The owner's own .sip files - tags and hooks - said only when they exist: a damaged
    /// tags file quietly stops every trim and collection (that is its fail-shut promise), and
    /// a damaged hooks file refuses every save, so both are worth a line before either bites.
    /// </summary>
    private static IEnumerable<Check> OwnerFileChecks(SipRepository repository)
    {
        IReadOnlyList<TagRecord>? tags = null;
        string? tagsProblem = null;
        try
        {
            tags = repository.Tags.Exists ? repository.Tags.Load() : null;
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            tagsProblem = ex.Message;
        }

        if (tagsProblem is not null)
        {
            yield return new Check("TAGS", Verdict.Fail,
                $"the tags file cannot be read, so nothing is trimmed or collected until it is mended: {tagsProblem}");
        }
        else if (tags is not null)
        {
            var missing = tags.Count(tag => !repository.HasSnapshot(tag.SnapshotId));
            yield return missing == 0
                ? new Check("TAGS", Verdict.Pass, string.Create(
                    CultureInfo.InvariantCulture,
                    $"{tags.Count} tag(s); every tagged snapshot is held"))
                : new Check("TAGS", Verdict.Warn, string.Create(
                    CultureInfo.InvariantCulture,
                    $"{missing} of {tags.Count} tag(s) name a snapshot this machine does not hold; 'sip tag' lists them"));
        }

        SaveHooks? hooks = null;
        string? hooksProblem = null;
        try
        {
            hooks = SaveHooks.Load(repository.Layout);
        }
        catch (HookException ex)
        {
            hooksProblem = ex.Message;
        }

        if (hooksProblem is not null)
        {
            yield return new Check("HOOKS", Verdict.Fail, hooksProblem);
        }
        else if (hooks is not null && !hooks.IsEmpty)
        {
            yield return new Check("HOOKS", Verdict.Pass,
                $"save hooks are set{(hooks.BeforeSave is null ? string.Empty : "; a failing before-save hook refuses the save, which is its job")}. 'sip hooks' shows them");
        }
    }

    /// <summary>
    /// Folder protection (P-04): said before it bites, because a save refused by Norton's
    /// Data Protector or Controlled folder access reads as a permissions problem and sends
    /// the person to ACLs that are fine. Detection is a heuristic and the line says so.
    /// </summary>
    private static IEnumerable<Check> AntivirusChecks(SipRepository repository)
    {
        if (!AntivirusShield.IsProtectedShape(repository.Layout.WorkingRoot))
        {
            yield break;
        }

        if (AntivirusShield.DetectedProduct() is not { } product)
        {
            yield break;
        }

        yield return new Check("AV", Verdict.Note,
            $"this folder sits where {product}'s folder protection watches (Documents, Desktop, " +
            "Pictures...). If saves or syncs here ever fail with access denied while the " +
            "permissions look fine, allow SippBucket in that protection's own settings, or keep " +
            "the synced folder elsewhere. SippBucket never fights it: the quarantine stays " +
            "unencrypted so the antivirus can read every byte, and a refused write is reported, " +
            "not retried into");
    }

    /// <summary>
    /// The rules a program cannot check, printed so their absence is visible.
    /// </summary>
    private static IEnumerable<Check> NotMechanicallyCheckable()
    {
        yield return new Check("A3", Verdict.NeedsAHuman,
            "does every screen state the limit next to the claim?");

        yield return new Check("A4", Verdict.NeedsAHuman,
            "does every quotation resolve to a source that contains it?");

        yield return new Check("B1", Verdict.NeedsAHuman,
            "was each claim measured with the instrument for that property?");

        yield return new Check("B2", Verdict.NeedsAHuman,
            "has each regression test been seen to fail with its fix reverted?");

        yield return new Check("E4", Verdict.NeedsAHuman,
            "the handshake is Noise XK and matches published vectors; its mapping onto SippBucket is unreviewed");
    }
}
