using System.Buffers;
using System.Globalization;
using NSec.Cryptography;
using SippBucket.Core.Hashing;
using SippBucket.Core.Machines;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Push;

/// <summary>
/// The receiving side of a delivery: answers the offer, takes each accepted file into the
/// staging area, checks it, and places it in the inbox, in quarantine, or nowhere, with a
/// receipt for each (docs/DIRECT-PUSH.md, rules 4, 5 and 7).
/// </summary>
/// <remarks>
/// <para>
/// <b>Decided before anything moves.</b> Every file offered is judged when the offer arrives, and
/// refused there, costing nothing to transfer, when its name may not be written as it is
/// (<see cref="PushName"/>), when it is larger than <c>push.largestFileMiB</c>, when it would
/// take another person past their space here (<c>push.personInboxMiB</c>, counting what their
/// files already take), or when writing it would leave the inbox's disk with less than
/// <see cref="PushSettings.DiskReserveBytes"/> free. Deliveries arriving at the same time count
/// against each other: what one has been promised, another cannot be.
/// </para>
/// <para>
/// <b>Staged, checked, then placed.</b> Each file streams into the hidden staging area, hashed
/// as it comes, its first bytes kept for the content check, so neither needs a second read.
/// What arrives must hash to what was offered. Then the content check decides: the inbox, the
/// inbox marked <em>type not recognised</em>, or quarantine, which has a cap of its own. Only
/// then is the file moved, under the inbox's lock, and never over anything already there.
/// </para>
/// <para>
/// <b>Forwarding.</b> A file placed in the inbox is offered to the person's rules
/// (<see cref="InboxRules"/>); the first that applies moves it. A file in quarantine is never
/// offered to them. A forward that fails leaves the file in the inbox and says why in the log.
/// </para>
/// <para>
/// <b>What it trusts.</b> The caller has proved its key and been accepted by the listener; what
/// it sends is still untrusted. Every message is read under the stall deadline and checked field
/// by field (<see cref="PushWire"/>), every name before anything is written, every byte against
/// the offered hash. The sender's own content check, if any, counts for nothing here.
/// </para>
/// </remarks>
public sealed class PushReceiver
{
    /// <summary>How much of a file is copied from the channel to the disk at a time.</summary>
    private const int CopyBuffer = 128 * 1024;

    /// <summary>
    /// How much of a file is written between flushes to the disk. A file is flushed before it is
    /// placed, so that a file in the inbox is whole even after a crash; flushing as it goes keeps
    /// that last flush short, so the sender waiting for its receipt is never left waiting on
    /// gigabytes still in the cache.
    /// </summary>
    private const long FlushEvery = 256L * 1024 * 1024;

    private readonly PushInbox _inbox;
    private readonly PushSettings _settings;
    private readonly TimeSpan _stallTimeout;
    private readonly Func<IReadOnlyList<InboxRule>> _rules;
    private readonly Action<string>? _log;
    private readonly Action<PushCaller, string>? _onQuarantined;
    private readonly TimeProvider _time;
    private readonly Func<string, Machines.PersonScope> _scopeOf;

    // Bytes promised to deliveries still arriving, in all and for each sending person.
    // Keyed by the person's scope key, so one person's machines share one cap. Under _gate.
    private readonly Lock _gate = new();
    private readonly Dictionary<string, long> _promisedBySender = new(StringComparer.OrdinalIgnoreCase);
    private long _promised;

    /// <summary>Creates the receiving side over an inbox.</summary>
    /// <param name="inbox">The inbox, prepared before the listener starts.</param>
    /// <param name="settings">The <c>push</c> limits.</param>
    /// <param name="rules">The person's forwarding rules, read for each file placed, so an edit applies at once.</param>
    /// <param name="tuning">The deadlines, or null for the defaults.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="time">The clock, or null for the system's.</param>
    /// <param name="onQuarantined">
    /// Told of each file that goes to quarantine, with who sent it and what it was, for the
    /// sender's health record (docs/PEER-HEALTH.md: a quarantined push is a fault); or null.
    /// </param>
    /// <param name="scopeOf">
    /// The person scope a sender's space is counted under: all of one person's machines share
    /// one cap once they are grouped (docs/DIRECT-MESSAGES.md, "A person, not a machine").
    /// Null counts each machine on its own, which is the rule until people are known.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public PushReceiver(
        PushInbox inbox,
        PushSettings settings,
        Func<IReadOnlyList<InboxRule>> rules,
        PushTuning? tuning = null,
        Action<string>? log = null,
        TimeProvider? time = null,
        Action<PushCaller, string>? onQuarantined = null,
        Func<string, Machines.PersonScope>? scopeOf = null)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(rules);

        var chosen = tuning ?? PushTuning.Default;
        chosen.Validate(nameof(tuning));

        _inbox = inbox;
        _settings = settings;
        _rules = rules;
        _stallTimeout = chosen.StallTimeout;
        _log = log;
        _time = time ?? TimeProvider.System;
        _onQuarantined = onQuarantined;
        _scopeOf = scopeOf ?? Machines.PeopleStore.SoleScope;
    }

    /// <summary>Receives one batch over an authenticated channel.</summary>
    /// <param name="caller">Who is sending, as the listener's key check found it.</param>
    /// <param name="channel">The delivery channel.</param>
    /// <param name="cancellationToken">Stops receiving.</param>
    /// <returns>A task that completes when the batch receipt has been sent, or the batch was refused.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <exception cref="PushException">The sender broke the format, or ended the channel part way.</exception>
    /// <exception cref="Protocol.PeerStalledException">The sender stopped making progress.</exception>
    /// <exception cref="IOException">A file could not be written or placed; the delivery stops there.</exception>
    public async Task ReceiveAsync(PushCaller caller, Stream channel, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(channel);

        var offer = await ExpectAsync<PushOffer>(channel, "an offer", cancellationToken).ConfigureAwait(false);
        await ReceiveAsync(caller, channel, offer, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Receives one batch whose offer the dispatcher already read: the daemon reads the first
    /// message to tell a file batch from a direct message, then hands each to its own side.
    /// </summary>
    /// <param name="caller">Who is sending, as the listener's key check found it.</param>
    /// <param name="channel">The delivery channel.</param>
    /// <param name="first">The first message read from the channel.</param>
    /// <param name="cancellationToken">Stops receiving.</param>
    /// <returns>A task that completes when the batch receipt has been sent, or the batch was refused.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <exception cref="PushException">The sender broke the format, or ended the channel part way.</exception>
    /// <exception cref="Protocol.PeerStalledException">The sender stopped making progress.</exception>
    /// <exception cref="IOException">A file could not be written or placed; the delivery stops there.</exception>
    public async Task ReceiveAsync(PushCaller caller, Stream channel, PushMessage first, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(first);

        if (first is not PushOffer offer)
        {
            throw new PushException(
                PushFault.UnexpectedMessage,
                $"The sender sent {first.GetType().Name} where an offer was due.");
        }

        if (offer.Version != PushWire.Version)
        {
            await RefuseAsync(
                channel,
                BatchRefusal.UnsupportedVersion,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"This machine speaks version {PushWire.Version} of the delivery format, and was offered version {offer.Version}."),
                cancellationToken).ConfigureAwait(false);
            Log($"{caller.Name}: refused a batch in version {offer.Version} of the delivery format");
            return;
        }

        if (offer.FileCount > PushWire.MaximumFiles)
        {
            await RefuseAsync(
                channel,
                BatchRefusal.TooManyFiles,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"A batch holds at most {PushWire.MaximumFiles} files, and this one offered {offer.FileCount}."),
                cancellationToken).ConfigureAwait(false);
            Log(string.Create(CultureInfo.InvariantCulture, $"{caller.Name}: refused a batch of {offer.FileCount} files"));
            return;
        }

        var files = new List<PushFileOffer>(offer.FileCount);
        for (var index = 0; index < offer.FileCount; index++)
        {
            var file = await ExpectAsync<PushFileOffer>(channel, "a file offer", cancellationToken).ConfigureAwait(false);
            if (file.Index != index)
            {
                throw new PushException(
                    PushFault.UnexpectedMessage,
                    string.Create(CultureInfo.InvariantCulture, $"File offer {file.Index} arrived where offer {index} was due."));
            }

            files.Add(file);
        }

        try
        {
            _inbox.EnsureFolders();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await RefuseAsync(
                channel,
                BatchRefusal.Unavailable,
                "The receiving machine's inbox folder cannot be written right now.",
                cancellationToken).ConfigureAwait(false);
            Log($"{caller.Name}: refused a batch, because the inbox {_inbox.Root} cannot be written: {ex.Message}");
            return;
        }

        var scope = ScopeOfSafely(caller);
        var decisions = Decide(caller, scope, files);

        // Which files still hold a promise of space: every accepted one, until it has arrived.
        var promised = decisions.Select(decision => decision == FileRefusal.None).ToArray();
        try
        {
            await PushWire.WriteAsync(
                channel,
                new PushAnswer(PushWire.Version, BatchRefusal.None, string.Empty, decisions),
                _stallTimeout,
                cancellationToken).ConfigureAwait(false);

            int delivered = 0, quarantined = 0, refused = 0;
            for (var index = 0; index < files.Count; index++)
            {
                if (decisions[index] != FileRefusal.None)
                {
                    refused++;
                    Log($"{caller.Name}: refused '{files[index].Name}' before it was sent ({Describe(decisions[index])})");
                    continue;
                }

                var receipt = await ReceiveFileAsync(caller, channel, files[index], cancellationToken).ConfigureAwait(false);

                // It has arrived, whatever became of it: the space it takes is real now, or free.
                promised[index] = false;
                Unpromise(scope.Key, files[index].Size);

                switch (receipt.Outcome)
                {
                    case FileOutcome.Inbox or FileOutcome.InboxUnrecognised:
                        delivered++;
                        break;
                    case FileOutcome.Quarantined:
                        quarantined++;
                        _onQuarantined?.Invoke(
                            caller,
                            $"'{files[index].Name}' went to quarantine ({receipt.Quarantine}, its content {ContentTypes.NameOf(receipt.DetectedType)})");
                        break;
                    default:
                        refused++;
                        break;
                }

                await PushWire.WriteAsync(channel, receipt, _stallTimeout, cancellationToken).ConfigureAwait(false);
            }

            await PushWire.WriteAsync(
                channel,
                new PushBatchReceipt(delivered, quarantined, refused),
                _stallTimeout,
                cancellationToken).ConfigureAwait(false);

            Log(string.Create(
                CultureInfo.InvariantCulture,
                $"{caller.Name}: batch done, {delivered} in the inbox, {quarantined} in quarantine, {refused} refused"));
        }
        finally
        {
            // Whatever was promised and never arrived is free again.
            for (var index = 0; index < files.Count; index++)
            {
                if (promised[index])
                {
                    Unpromise(scope.Key, files[index].Size);
                }
            }
        }
    }

    /// <summary>The sender's person scope; an unreadable grouping counts the machine alone, the tightest cap.</summary>
    private Machines.PersonScope ScopeOfSafely(PushCaller caller)
    {
        try
        {
            return _scopeOf(caller.DeviceId);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException)
        {
            Log($"the people list could not be read, so {caller.Name} counts alone: {ex.Message}");
            return Machines.PeopleStore.SoleScope(caller.DeviceId);
        }
    }

    /// <summary>Judges every file offered, and promises the space for those accepted.</summary>
    private FileRefusal[] Decide(PushCaller caller, Machines.PersonScope scope, List<PushFileOffer> files)
    {
        var own = MachineOwnership.IsOwn(caller.Owner);

        // The cap is per person: what any of their machines already sent counts against it
        // together, once they are grouped, and each machine alone until then.
        var alreadyHere = own ? 0 : scope.Devices.Sum(_inbox.SpaceUsedBy);
        var free = FreeSpace();
        var decisions = new FileRefusal[files.Count];

        lock (_gate)
        {
            var promisedToSender = _promisedBySender.GetValueOrDefault(scope.Key);
            long accepted = 0;

            for (var index = 0; index < files.Count; index++)
            {
                var file = files[index];
                decisions[index] =
                    !PushName.IsAcceptable(file.Name, out _) ? FileRefusal.BadName
                    : file.Size > _settings.LargestFileBytes ? FileRefusal.TooLarge
                    : !own && alreadyHere + promisedToSender + accepted + file.Size > _settings.PersonInboxCapBytes ? FileRefusal.OverPersonCap
                    : free - _promised - accepted - file.Size < PushSettings.DiskReserveBytes ? FileRefusal.NoSpace
                    : FileRefusal.None;

                if (decisions[index] == FileRefusal.None)
                {
                    accepted += file.Size;
                }
            }

            _promised += accepted;
            _promisedBySender[scope.Key] = promisedToSender + accepted;
        }

        return decisions;
    }

    private void Unpromise(string scopeKey, long bytes)
    {
        lock (_gate)
        {
            _promised -= bytes;

            var left = _promisedBySender.GetValueOrDefault(scopeKey) - bytes;
            if (left <= 0)
            {
                _promisedBySender.Remove(scopeKey);
            }
            else
            {
                _promisedBySender[scopeKey] = left;
            }
        }
    }

    /// <summary>The inbox's drive's free space, or 0 when it cannot be read, which refuses everything.</summary>
    private long FreeSpace()
    {
        try
        {
            return new DriveInfo(Path.GetPathRoot(_inbox.Root)!).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Log($"the free space on the inbox's drive could not be read, so nothing is accepted: {ex.Message}");
            return 0;
        }
    }

    private async Task<PushFileReceipt> ReceiveFileAsync(
        PushCaller caller,
        Stream channel,
        PushFileOffer file,
        CancellationToken cancellationToken)
    {
        var staged = _inbox.NewStagingPath();
        var head = new byte[(int)Math.Min(ContentCheck.HeadBytes, file.Size)];

        try
        {
            var hash = await StageAsync(channel, staged, file.Size, head, cancellationToken).ConfigureAwait(false);
            if (hash != file.Hash)
            {
                Log($"{caller.Name}: refused '{file.Name}': what arrived does not hash to what was offered");
                return Refused(file.Index, FileRefusal.HashMismatch, ContentTypes.Unknown);
            }

            var check = ContentCheck.Check(head, file.Size, file.Name);
            var now = _time.GetUtcNow();

            using (await _inbox.LockAsync(cancellationToken).ConfigureAwait(false))
            {
                return check.Verdict == ContentVerdict.Quarantine
                    ? TakeIntoQuarantine(caller, file, staged, hash, check, now)
                    : Place(caller, file, staged, hash, check, now);
            }
        }
        catch (FileNotFoundException) when (!File.Exists(staged))
        {
            // Something on this machine removed the file between its last byte and its placing:
            // the antivirus, doing its job.
            Log($"{caller.Name}: '{file.Name}' was removed as it arrived, most likely by this machine's antivirus");
            return Refused(file.Index, FileRefusal.Removed, ContentTypes.Unknown);
        }
        finally
        {
            if (File.Exists(staged))
            {
                SharingRetry.Run(() => File.Delete(staged));
            }
        }
    }

    /// <summary>Streams exactly one file's bytes into the staging area, hashing them and keeping the first.</summary>
    private static async Task<ContentHash> StageAsync(
        Stream channel,
        string staged,
        long size,
        byte[] head,
        CancellationToken cancellationToken)
    {
        IncrementalHash.Initialize(HashAlgorithm.Blake2b_256, out var state);
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBuffer);

        try
        {
            var output = new FileStream(
                staged, FileMode.CreateNew, FileAccess.Write, FileShare.None, bufferSize: 1, FileOptions.Asynchronous);

            await using (output.ConfigureAwait(false))
            {
                long received = 0;
                long unflushed = 0;
                while (received < size)
                {
                    var wanted = (int)Math.Min(buffer.Length, size - received);
                    var read = await channel.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new PushException(
                            PushFault.SessionFailed,
                            string.Create(
                                CultureInfo.InvariantCulture,
                                $"The sender ended the delivery {received} bytes into a file of {size}."));
                    }

                    IncrementalHash.Update(ref state, buffer.AsSpan(0, read));

                    if (received < head.Length)
                    {
                        var kept = (int)Math.Min(read, head.Length - received);
                        buffer.AsSpan(0, kept).CopyTo(head.AsSpan((int)received));
                    }

                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    received += read;
                    unflushed += read;

                    if (unflushed >= FlushEvery)
                    {
                        FlushToDisk(output);
                        unflushed = 0;
                    }
                }

                // On the disk before it is placed, so a file in the inbox is whole even after a crash.
                FlushToDisk(output);
            }

            var digest = new byte[ContentHash.SizeInBytes];
            IncrementalHash.Finalize(ref state, digest);
            return new ContentHash(digest);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Puts what has been written on the disk itself, not merely in the OS cache.</summary>
    /// <remarks>
    /// <c>Flush(flushToDisk: true)</c> has no asynchronous form, and the write-through is the
    /// point: a file in the inbox must be whole even after a crash, and <c>FlushAsync</c>
    /// flushes only SippBucket's buffer, not the OS's.
    /// </remarks>
    private static void FlushToDisk(FileStream output) => output.Flush(flushToDisk: true);

    /// <summary>Moves a checked file into the inbox, records it, and forwards it if a rule says so. The caller holds the lock.</summary>
    private PushFileReceipt Place(
        PushCaller caller,
        PushFileOffer file,
        string staged,
        ContentHash hash,
        ContentCheckResult check,
        DateTimeOffset now)
    {
        var placed = _inbox.Place(staged, file.Name);
        var unrecognised = check.Verdict == ContentVerdict.InboxUnrecognised;

        var entry = new InboxEntry
        {
            ArrivedUtc = now,
            SenderDeviceId = caller.DeviceId,
            SenderName = caller.Name,
            SenderOwner = caller.Owner,
            SentName = file.Name,
            PlacedName = placed,
            Size = file.Size,
            Hash = hash,
            DetectedType = check.DetectedType,
            Unrecognised = unrecognised,
        };

        entry = Forward(entry);
        _inbox.Record(entry);

        var where = entry.ForwardedTo is { } forwarded
            ? $"forwarded to {forwarded}"
            : placed == file.Name ? "in the inbox" : $"in the inbox as '{placed}'";
        Log($"{caller.Name}: '{file.Name}' {where}{(unrecognised ? ", type not recognised" : string.Empty)}");

        return new PushFileReceipt(
            file.Index,
            unrecognised ? FileOutcome.InboxUnrecognised : FileOutcome.Inbox,
            QuarantineReason.None,
            FileRefusal.None,
            check.DetectedType);
    }

    /// <summary>Offers a placed file to the person's rules; the first that applies moves it.</summary>
    private InboxEntry Forward(InboxEntry entry)
    {
        IReadOnlyList<InboxRule> rules;
        try
        {
            rules = _rules();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            Log($"the forwarding rules could not be read, so '{entry.PlacedName}' stays in the inbox: {ex.Message}");
            return entry;
        }

        // A rule that could never have been set, written into the file by hand, is passed over:
        // one sending files into the quarantine or a synced folder's .sip is never followed.
        var usable = rules.Where(rule => InboxRules.IsValid(rule, _inbox, out _)).ToList();
        if (usable.Count < rules.Count)
        {
            Log($"{rules.Count - usable.Count} forwarding rule(s) cannot be followed and were passed over; 'sip doctor' says why");
        }

        if (InboxRules.FirstMatch(usable, entry) is not { } rule)
        {
            return entry;
        }

        try
        {
            return entry with { ForwardedTo = InboxRules.Forward(_inbox, entry.PlacedName, rule) };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log($"'{entry.PlacedName}' could not be forwarded to {rule.Destination}, so it stays in the inbox: {ex.Message}");
            return entry;
        }
    }

    /// <summary>Takes a file into quarantine, or refuses it when the quarantine is full. The caller holds the lock.</summary>
    private PushFileReceipt TakeIntoQuarantine(
        PushCaller caller,
        PushFileOffer file,
        string staged,
        ContentHash hash,
        ContentCheckResult check,
        DateTimeOffset now)
    {
        var arrival = new QuarantineArrival
        {
            ArrivedUtc = now,
            SenderDeviceId = caller.DeviceId,
            SenderName = caller.Name,
            SenderOwner = caller.Owner,
            SentName = file.Name,
            Reason = check.Reason,
            DetectedType = check.DetectedType,
            ClaimedType = check.ClaimedType,
        };

        if (_inbox.Quarantine.Add(staged, hash, file.Size, arrival, _settings.QuarantineCapBytes) == QuarantineAdd.OverCap)
        {
            Log($"{caller.Name}: refused '{file.Name}', which belongs in quarantine, because the quarantine is full");
            return Refused(file.Index, FileRefusal.OverQuarantineCap, check.DetectedType);
        }

        Log($"{caller.Name}: '{file.Name}' went to quarantine ({DescribeReason(check)})");
        return new PushFileReceipt(file.Index, FileOutcome.Quarantined, check.Reason, FileRefusal.None, check.DetectedType);
    }

    private async Task<T> ExpectAsync<T>(Stream channel, string what, CancellationToken cancellationToken)
        where T : PushMessage
    {
        var message = await PushWire.ReadAsync(channel, _stallTimeout, cancellationToken).ConfigureAwait(false);

        return message switch
        {
            T expected => expected,
            null => throw new PushException(PushFault.SessionFailed, $"The sender ended the delivery where {what} was due."),
            _ => throw new PushException(
                PushFault.UnexpectedMessage,
                $"The sender sent {message.GetType().Name} where {what} was due."),
        };
    }

    private Task RefuseAsync(Stream channel, BatchRefusal refusal, string detail, CancellationToken cancellationToken) =>
        PushWire.WriteAsync(channel, new PushAnswer(PushWire.Version, refusal, detail, []), _stallTimeout, cancellationToken);

    private static PushFileReceipt Refused(int index, FileRefusal refusal, uint detectedType) =>
        new(index, FileOutcome.Refused, QuarantineReason.None, refusal, detectedType);

    private static string DescribeReason(ContentCheckResult check) => check.Reason switch
    {
        QuarantineReason.ExecutableContent => $"its content is a program: {check.DetectedName}",
        QuarantineReason.ExecutableName => "its name is a type Windows runs or installs",
        QuarantineReason.Mismatch => $"its content is {check.DetectedName}, not what its name says",
        _ => "quarantined",
    };

    /// <summary>A refusal in words, for logs and the sender's own report.</summary>
    /// <param name="refusal">The refusal.</param>
    /// <returns>A short phrase.</returns>
    public static string Describe(FileRefusal refusal) => refusal switch
    {
        FileRefusal.BadName => "its name cannot be written as it is",
        FileRefusal.TooLarge => "it is larger than this machine accepts",
        FileRefusal.NoSpace => "the inbox's disk would be left too full",
        FileRefusal.OverPersonCap => "the sender's space on this machine is used up",
        FileRefusal.OverQuarantineCap => "it belongs in quarantine, and the quarantine is full",
        FileRefusal.HashMismatch => "what arrived did not match what was offered",
        FileRefusal.Removed => "something on the receiving machine removed it as it arrived",
        _ => "not refused",
    };

    private void Log(string line) => _log?.Invoke(line);
}
