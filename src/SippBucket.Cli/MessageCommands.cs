using System.Globalization;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Machines;
using SippBucket.Core.Messages;
using SippBucket.Core.Platform;
using SippBucket.Core.Push;
using SippBucket.Core.Repository;

namespace SippBucket.Cli;

/// <summary>
/// Direct Messages on the command line: <c>sip dm</c> sends, blocks, mutes and deletes;
/// <c>sip messages</c> reads (docs/DIRECT-MESSAGES.md). Every feature ships in <c>sip</c>
/// first; the window follows.
/// </summary>
/// <remarks>
/// <para>
/// A message goes to a person: every machine of theirs this machine is paired with gets its
/// own signed copy under one message ID, and the status is <em>Delivered</em> from the first
/// machine that confirmed. Until a colleague's machines are grouped (<c>sip team person</c>),
/// each machine is its own person and its own conversation.
/// </para>
/// <para>
/// Statuses never claim more than a receipt proved: <em>Sending</em> covers unreachable, not
/// yet tried, and blocked alike, because the sender cannot tell them apart and must not
/// pretend to. Text is shown as text through the same rule as every peer string; an HTML
/// file travels as an attachment and is never run by SippBucket.
/// </para>
/// </remarks>
internal static class MessageCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary><c>sip dm</c>: send to a person, or manage the conversation.</summary>
    /// <param name="args">What followed <c>dm</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> DmAsync(string[] args)
    {
        if (args.Length == 0)
        {
            return Usage("sip dm <person> <text>... [--attach <file>]... | block|unblock|mute|unmute <person> | delete <message-id>");
        }

        return args[0].ToUpperInvariant() switch
        {
            "BLOCK" when args.Length == 2 => Preference(args[1], block: true, add: true),
            "UNBLOCK" when args.Length == 2 => Preference(args[1], block: true, add: false),
            "MUTE" when args.Length == 2 => Preference(args[1], block: false, add: true),
            "UNMUTE" when args.Length == 2 => Preference(args[1], block: false, add: false),
            "DELETE" when args.Length == 2 => Delete(args[1]),
            _ => await SendAsync(args).ConfigureAwait(false),
        };
    }

    /// <summary><c>sip messages</c>: the conversations, or one person's.</summary>
    /// <param name="args">What followed <c>messages</c>.</param>
    /// <returns>The exit code.</returns>
    public static int Messages(string[] args) => args.Length switch
    {
        0 => Conversations(),
        1 => Conversation(args[0]),
        _ => Usage("sip messages [<person>]"),
    };

    /// <summary>One line on messages, for <c>sip status</c>.</summary>
    /// <returns>The team switch's state, and what is waiting.</returns>
    public static string StatusLine()
    {
        var decision = TeamSwitch().Decide();
        if (!decision.On)
        {
            return decision.Why;
        }

        var messages = MessageStore.ForThisUser().Load(out var unreadable);
        var sending = messages.Count(m => m.Direction == MessageDirection.Sent && m.Status == MessageStatus.Sending);
        var received = messages.Count(m => m.Direction == MessageDirection.Received);

        var line = string.Create(
            CultureInfo.InvariantCulture,
            $"Messages: {received} received, {sending} still sending. 'sip messages' shows them.");
        return unreadable == 0
            ? line
            : line + string.Create(CultureInfo.InvariantCulture, $" ({unreadable} stored file(s) could not be read.)");
    }

    private static async Task<int> SendAsync(string[] args)
    {
        var attachPaths = new List<string>();
        var words = new List<string>();
        string? personTyped = null;

        for (var i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--attach", StringComparison.OrdinalIgnoreCase))
            {
                if (++i >= args.Length)
                {
                    return Usage("--attach needs a file.");
                }

                attachPaths.Add(args[i]);
            }
            else if (personTyped is null)
            {
                personTyped = args[i];
            }
            else
            {
                words.Add(args[i]);
            }
        }

        if (personTyped is null || (words.Count == 0 && attachPaths.Count == 0))
        {
            return Usage("sip dm <person> <text>... [--attach <file>]...");
        }

        var team = TeamSwitch().Decide();
        if (!team.On)
        {
            return Fail(team.Why);
        }

        if (Resolve(personTyped) is not { } who)
        {
            return ExitFailure;
        }

        var routedTargets = who.Scope.Devices
            .Select(device => MessageRoutes.To(SyncedFolders(), device, MasterConfig.Load().Push.Port))
            .Where(route => route is not null)
            .Select(route => route!)
            .ToList();
        var targets = who.Scope.Devices
            .Where(device => routedTargets.Any(route => DeviceIdentity.IsSameDevice(route.DeviceId, device)))
            .ToList();

        if (targets.Count == 0)
        {
            return Fail($"None of {who.Name}'s machines is paired with a folder here, so there is nowhere to send.");
        }

        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);

        // Attachments travel as Direct Push files, pushed to each of the person's machines
        // before the message that names them; the message then ties them down by hash. A push
        // that fails is reported, and the message still goes: the hashes say exactly which
        // bytes were meant, and the files can be pushed again.
        var attachments = new List<DmAttachment>();
        if (attachPaths.Count > 0)
        {
            var plan = await PushSender.PlanAsync(attachPaths, CancellationToken.None).ConfigureAwait(false);
            foreach (var problem in plan.Problems)
            {
                await Console.Error
                    .WriteLineAsync($"cannot attach {problem.Path}: {problem.Reason}")
                    .ConfigureAwait(false);
            }

            if (plan.Problems.Count > 0)
            {
                return ExitFailure;
            }

            foreach (var file in plan.Files)
            {
                if (file.WillBeQuarantined)
                {
                    Console.WriteLine($"note: '{file.Name}' will very likely go to their quarantine ({file.Check.DetectedName}).");
                }

                attachments.Add(new DmAttachment(file.Name, file.Size, file.Hash));
            }

            foreach (var route in routedTargets)
            {
                try
                {
                    _ = await PushSender.SendAsync(
                        identity,
                        new PushTarget(route.Name, route.DeviceId, route.Host, route.Port),
                        plan.Files,
                        tuning: null,
                        progress: null,
                        onFile: null,
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch (PushException ex)
                {
                    await Console.Error
                        .WriteLineAsync($"the attachment(s) did not reach {route.Name} yet: {ex.Message}")
                        .ConfigureAwait(false);
                }
            }
        }

        var delivery = Delivery(identity);
        StoredMessage queued;
        try
        {
            queued = delivery.Queue(who.Scope.Key, targets, string.Join(' ', words), attachments);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException)
        {
            return Fail(ex.Message);
        }

        _ = await delivery.DeliverPendingAsync().ConfigureAwait(false);

        var sent = MessageStore.ForThisUser().Load(out _)
            .FirstOrDefault(m => string.Equals(m.Message.MessageId, queued.Message.MessageId, StringComparison.OrdinalIgnoreCase))
            ?? queued;

        Console.WriteLine($"To {who.Name}: {Describe(sent)}");
        if (sent.Status == MessageStatus.Sending)
        {
            Console.WriteLine("It is queued, and goes as soon as one of their machines can be reached.");
        }

        return ExitSuccess;
    }

    private static int Conversations()
    {
        var decision = TeamSwitch().Decide();
        var messages = MessageStore.ForThisUser().Load(out var unreadable);

        if (messages.Count == 0)
        {
            Console.WriteLine(decision.On
                ? "No messages yet. 'sip dm <person> <text>' starts a conversation."
                : decision.Why);
            return ExitSuccess;
        }

        var preferences = MessageStore.ForThisUser().LoadPreferences(out _);
        foreach (var conversation in messages
                     .GroupBy(m => m.PersonKey, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(c => c.Max(m => m.Message.CreatedUtc)))
        {
            var last = conversation.OrderBy(m => m.Message.CreatedUtc).Last();
            var flags = string.Concat(
                preferences.Blocked.Contains(conversation.Key, StringComparer.OrdinalIgnoreCase) ? " [blocked]" : string.Empty,
                preferences.Muted.Contains(conversation.Key, StringComparer.OrdinalIgnoreCase) ? " [muted]" : string.Empty);

            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{NameOf(conversation.Key),-24} {conversation.Count(),4} message(s)  last {When(last.Message.CreatedUtc)}{flags}"));
        }

        if (unreadable > 0)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{unreadable} stored file(s) could not be read. They may belong to another account or a newer build."));
        }

        return ExitSuccess;
    }

    private static int Conversation(string typed)
    {
        if (Resolve(typed) is not { } who)
        {
            return ExitFailure;
        }

        var messages = MessageStore.ForThisUser().Load(out _)
            .Where(m => string.Equals(m.PersonKey, who.Scope.Key, StringComparison.OrdinalIgnoreCase))
            .OrderBy(m => m.Message.CreatedUtc)
            .ToList();

        if (messages.Count == 0)
        {
            Console.WriteLine($"No messages with {who.Name} yet.");
            return ExitSuccess;
        }

        foreach (var message in messages)
        {
            var arrow = message.Direction == MessageDirection.Sent ? "->" : "<-";
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{When(message.Message.CreatedUtc)}  {arrow} {Describe(message)}  {message.Message.MessageId[..8]}"));
            Console.WriteLine($"    {DisplayText.Printable(message.Message.Text, 2000)}");
            foreach (var attachment in message.Message.Attachments)
            {
                Console.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"    attachment: {DisplayText.Printable(attachment.Name, 100)} ({attachment.Size} bytes).") +
                    " It travelled as a Direct Push file; 'sip inbox' has what arrived.");
            }
        }

        if (!MessageStore.ProtectionAvailable)
        {
            Console.WriteLine();
            Console.WriteLine("This platform cannot protect the stored messages at rest; they are stored plain.");
        }

        return ExitSuccess;
    }

    private static int Preference(string typed, bool block, bool add)
    {
        if (Resolve(typed) is not { } who)
        {
            return ExitFailure;
        }

        try
        {
            _ = MessageStore.ForThisUser().UpdatePreferences(current =>
            {
                var list = block ? current.Blocked : current.Muted;
                IReadOnlyList<string> changed = add
                    ? list.Contains(who.Scope.Key, StringComparer.OrdinalIgnoreCase)
                        ? list
                        : [.. list, who.Scope.Key]
                    : [.. list.Where(key => !string.Equals(key, who.Scope.Key, StringComparison.OrdinalIgnoreCase))];

                return block ? current with { Blocked = changed } : current with { Muted = changed };
            });
        }
        catch (InvalidOperationException ex)
        {
            return Fail(ex.Message);
        }

        Console.WriteLine((block, add) switch
        {
            (true, true) =>
                $"{who.Name} is blocked. Their messages are dropped without an answer, and they are not told; " +
                "they may notice their messages never say Delivered.",
            (true, false) => $"{who.Name} is no longer blocked.",
            (false, true) => $"{who.Name} is muted. Their messages still arrive, without notifications.",
            _ => $"{who.Name} is no longer muted.",
        });
        return ExitSuccess;
    }

    private static int Delete(string messageIdPrefix)
    {
        var store = MessageStore.ForThisUser();
        var matches = store.Load(out _)
            .Where(m => m.Message.MessageId.StartsWith(messageIdPrefix, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count == 0)
        {
            return Fail($"No message here starts with '{messageIdPrefix}'. 'sip messages <person>' shows their IDs.");
        }

        if (matches.DistinctBy(m => m.Message.MessageId, StringComparer.OrdinalIgnoreCase).Count() > 1)
        {
            return Fail($"'{messageIdPrefix}' matches more than one message. Give more of the ID.");
        }

        _ = store.Delete(matches[0].Message.MessageId);
        Console.WriteLine(
            "Deleted from this machine. It does not delete the other person's copy, and like any deleted file " +
            "it is not securely erased from the disk.");
        return ExitSuccess;
    }

    /// <summary>Who a typed name means: a grouped person, or one someone-else machine on its own.</summary>
    private static (PersonScope Scope, string Name)? Resolve(string typed)
    {
        try
        {
            if (PeopleStore.ForThisUser().Find(typed) is { } person)
            {
                return (new PersonScope(person.Key, person.Name, person.Devices), person.Name);
            }
        }
        catch (System.Text.Json.JsonException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return null;
        }

        var found = PairedMachines.Find(SyncedFolders(), typed, out _);
        if (found.Outcome == PeerLookupOutcome.Ambiguous)
        {
            Console.Error.WriteLine($"'{typed}' names more than one machine:");
            foreach (var candidate in found.Candidates)
            {
                Console.Error.WriteLine($"  {candidate.DeviceId[..12]}  {DisplayText.Printable(candidate.Name, 64)}");
            }

            return null;
        }

        if (found.Peer is not { } peer)
        {
            Console.Error.WriteLine(
                $"Nobody here is called '{typed}': no grouped person, and no paired machine. " +
                "'sip team person list' and 'sip peer list' show who there is.");
            return null;
        }

        MachineOwner owner;
        try
        {
            owner = KnownMachines.ForThisUser().OwnerOf(peer.DeviceId);
        }
        catch (System.Text.Json.JsonException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return null;
        }

        if (owner != MachineOwner.SomeoneElse)
        {
            Console.Error.WriteLine(owner == MachineOwner.Mine
                ? $"{DisplayText.Printable(peer.Name, 64)} is one of your own machines. Direct messages travel between people."
                : $"You have not said whose machine {DisplayText.Printable(peer.Name, 64)} is. Answer first: " +
                  $"sip peer owner {peer.Name} someone-else");
            return null;
        }

        try
        {
            var scope = PeopleStore.ForThisUser().ScopeOf(peer.DeviceId);
            return (scope, scope.Name ?? DisplayText.Printable(peer.Name, 64));
        }
        catch (System.Text.Json.JsonException)
        {
            var scope = PeopleStore.SoleScope(peer.DeviceId);
            return (scope, DisplayText.Printable(peer.Name, 64));
        }
    }

    private static MessageDelivery Delivery(DeviceIdentity identity) =>
        new(
            MessageStore.ForThisUser(),
            identity,
            TeamSwitch().On,
            deviceId => MessageRoutes.To(SyncedFolders(), deviceId, MasterConfig.Load().Push.Port));

    private static TeamFeatures TeamSwitch() =>
        TeamFeatures.ForThisUser(() => PairedMachines.AllDeviceIds(SyncedFolders()));

    private static string NameOf(string personKey)
    {
        if (personKey.StartsWith(PeopleStore.DeviceKeyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var device = personKey[PeopleStore.DeviceKeyPrefix.Length..];
            var name = PairedMachines.NameOf(SyncedFolders(), device);
            return name is null
                ? device.Length > 12 ? device[..12] : device
                : DisplayText.Printable(name, 24);
        }

        try
        {
            var person = PeopleStore.ForThisUser().Load()
                .FirstOrDefault(p => string.Equals(p.Key, personKey, StringComparison.OrdinalIgnoreCase));
            return person is null ? personKey : DisplayText.Printable(person.Name, 24);
        }
        catch (System.Text.Json.JsonException)
        {
            return personKey;
        }
    }

    private static string Describe(StoredMessage message) => message.Status switch
    {
        MessageStatus.Sending => "Sending",
        MessageStatus.Delivered => "Delivered",
        MessageStatus.NotAccepted => message.StatusDetail.Length == 0
            ? "Not accepted"
            : $"Not accepted ({DisplayText.Printable(message.StatusDetail, 120)})",
        _ => "Received",
    };

    private static string When(DateTimeOffset time) =>
        time.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

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

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return ExitFailure;
    }

    private static int Usage(string usage)
    {
        Console.Error.WriteLine($"usage: {usage}");
        return ExitUsage;
    }
}
