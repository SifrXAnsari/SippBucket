using System.Globalization;
using SippBucket.Core.Configuration;
using SippBucket.Core.Discovery;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Messages;
using SippBucket.Core.Platform;
using SippBucket.Core.Push;
using SippBucket.Core.Servers;
using SippBucket.Core.Storage;

namespace SippBucket.Tray;

/// <summary>
/// This machine: who it is (Server.ID), its key, its port, its team, and what each of the
/// owner's other machines has done wrong.
/// </summary>
internal sealed class MachineSection : InfoSection
{
    private readonly IMainWindowHost _host;

    public MachineSection(IMainWindowHost host, WindowFonts fonts)
        : base(fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        _host = host;
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe()
    {
        var elements = new List<Element>
        {
            new() { Kind = ElementKind.Band, Text = "This machine" },
        };

        var directory = LoadDirectory();
        var self = directory.Self;
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "Server",
            Value = self is null
                ? "Not yet exchanged with your other machines - it happens as they sync"
                : directory.NumberOf(self.Permanent) is { } number
                    ? ServerDirectory.Describe(number, self.Label)
                    : self.Label ?? "This machine",
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair, Text = "Device ID", Value = _host.DeviceId, MonoValue = true,
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair, Text = "Device key", Value = _host.DeviceKeyFile, MonoValue = true,
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair, Text = "At sign-in", Value = _host.AutostartDescription,
        });

        var machine = MasterConfig.Load();
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "Sync port",
            Value = string.Create(
                CultureInfo.InvariantCulture,
                $"{machine.ListenPort}, one port for every folder (server.listenPort)"),
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Buttons,
            Buttons = [("Copy device ID", _host.CopyDeviceId)],
        });

        elements.Add(new Element { Kind = ElementKind.Band, Text = "Team" });
        var team = TeamFeatures
            .ForThisUser(() => PairedMachines.AllDeviceIds(WatchedFolders.Load()))
            .Decide();
        elements.Add(new Element { Kind = ElementKind.Text, Text = team.Why });
        foreach (var person in team.OtherPeople)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Mono, Text = "  " + DisplayText.Printable(person, 60),
            });
        }

        elements.Add(new Element { Kind = ElementKind.Band, Text = "Each machine's health" });
        var records = LoadHealth();
        if (records.Count == 0)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Text = "Nothing is recorded: no machine has sent anything wrong, or said anything " +
                       "about itself worth noting.",
            });
        }
        else
        {
            foreach (var line in records)
            {
                elements.Add(new Element { Kind = ElementKind.Text, Text = line.Text, Alarm = line.Alarm });
            }

            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Text = "'sip peer health' has every count, and 'sip peer health clear <server>' takes a " +
                       "machine's changes again.",
            });
        }

        return elements;
    }

    private static ServerDirectory LoadDirectory()
    {
        try
        {
            return KnownServers.ForThisUser().Load();
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException)
        {
            _ = ex;
            return ServerDirectory.Empty;
        }
    }

    private static IReadOnlyList<(string Text, bool Alarm)> LoadHealth()
    {
        IReadOnlyList<PeerHealthRecord> records;
        try
        {
            records = PeerHealth.ForThisUser().Load();
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException)
        {
            return [(ex.Message, true)];
        }

        var directory = LoadDirectory();
        return [.. records
            .OrderByDescending(record => record.Suspect is not null)
            .Take(12)
            .Select(record =>
            {
                var name = directory.NameOf(record.Device)
                    ?? record.Device[..Math.Min(12, record.Device.Length)];
                return record.Suspect is { } suspect
                    ? ($"{name}: SUSPECT - {suspect.Reason}. No change from it is taken.", true)
                    : ($"{name}: {DescribeFaults(record)}", false);
            })];
    }

    private static string DescribeFaults(PeerHealthRecord record) =>
        record.Faults.Count == 0
            ? "nothing held against it"
            : string.Join(", ", record.Faults
                .OrderByDescending(fault => fault.Count)
                .Take(3)
                .Select(fault => string.Create(
                    CultureInfo.InvariantCulture,
                    $"{fault.Fault}: {fault.Count}")));
}

/// <summary>
/// The alerts: the permanent log, the answers it waits for, and the two buttons each
/// waiting one carries.
/// </summary>
internal sealed class AlertsSection : InfoSection
{
    private readonly IMainWindowHost _host;
    private string _lastOutcome = string.Empty;

    public AlertsSection(IMainWindowHost host, WindowFonts fonts)
        : base(fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        _host = host;
    }

    /// <summary>How many alerts wait for an answer, for the rail's badge. Never throws.</summary>
    public static int Waiting()
    {
        try
        {
            var history = AlertLog.ForThisUser().Read();
            return history.Alerts.Count(entry => entry.Alert.Asks && entry.Answer is null);
        }
        catch (IOException)
        {
            return 0;
        }
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe()
    {
        var elements = new List<Element>
        {
            new() { Kind = ElementKind.Band, Text = "Alerts" },
            new()
            {
                Kind = ElementKind.Text,
                Text = "Everything SippBucket has noticed about another machine, kept for good in " +
                       "alerts.jsonl and never sent anywhere. An answer is never changed once given.",
            },
        };

        if (_lastOutcome.Length > 0)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = _lastOutcome });
            elements.Add(new Element { Kind = ElementKind.Gap });
        }

        var log = AlertLog.ForThisUser();
        var history = log.Read();

        var waiting = history.Alerts
            .Where(entry => entry.Alert.Asks && entry.Answer is null)
            .OrderByDescending(entry => entry.Alert.Id)
            .ToList();
        var rest = history.Alerts
            .Where(entry => !entry.Alert.Asks || entry.Answer is not null)
            .OrderByDescending(entry => entry.Alert.Id)
            .Take(20)
            .ToList();

        if (waiting.Count == 0 && rest.Count == 0)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = "No alerts." });
        }

        if (waiting.Count > 0)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Band,
                Text = string.Create(CultureInfo.InvariantCulture, $"Waiting for your answer: {waiting.Count}"),
            });
            foreach (var (alert, _) in waiting)
            {
                AddAlert(elements, alert, answered: null);
                var id = alert.Id;
                elements.Add(new Element
                {
                    Kind = ElementKind.Buttons,
                    Buttons =
                    [
                        ("That was me - apply it", () => Answer(id, AlertChoice.ThatWasMe)),
                        ("Not me - keep them out", () => Answer(id, AlertChoice.NotMe)),
                    ],
                });
                elements.Add(new Element { Kind = ElementKind.Gap });
            }
        }

        if (rest.Count > 0)
        {
            elements.Add(new Element { Kind = ElementKind.Band, Text = "Recent, newest first" });
            foreach (var (alert, answer) in rest)
            {
                AddAlert(elements, alert, answer);
            }
        }

        if (history.UnreadableLines > 0)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Alarm = true,
                Text = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{history.UnreadableLines} line(s) of the log could not be read and are not shown.") +
                    " The log is never rewritten, so they are still there to look at.",
            });
        }

        return elements;
    }

    private static void AddAlert(List<Element> elements, Alert alert, AlertAnswer? answered)
    {
        elements.Add(new Element
        {
            Kind = ElementKind.Mono,
            Text = string.Create(
                CultureInfo.InvariantCulture,
                $"#{alert.Id}  {alert.Utc.ToLocalTime():yyyy-MM-dd HH:mm}  {alert.Server}"),
            Alarm = alert.Asks && answered is null,
        });
        elements.Add(new Element { Kind = ElementKind.Text, Text = alert.What });
        elements.Add(new Element
        {
            Kind = ElementKind.Text,
            Text = answered is { } answer
                ? $"{alert.Done} Answered {answer.Utc.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}: {AlertLog.Describe(answer.Choice)}."
                : alert.Done,
        });
    }

    private void Answer(int id, AlertChoice choice)
    {
        _ = AnswerAsync(id, choice);
    }

    private async Task AnswerAsync(int id, AlertChoice choice)
    {
        _lastOutcome = await _host.AnswerAlertAsync(id, choice).ConfigureAwait(true);
        RefreshSection();
    }
}

/// <summary>Direct Push's inbox and quarantine, and the forwarding rules.</summary>
internal sealed class InboxSection : InfoSection
{
    private string _lastOutcome = string.Empty;

    public InboxSection(WindowFonts fonts)
        : base(fonts)
    {
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe()
    {
        var elements = new List<Element> { new() { Kind = ElementKind.Band, Text = "Inbox" } };

        PushPreferences preferences;
        try
        {
            preferences = PushPreferencesStore.ForThisUser().Load();
        }
        catch (System.Text.Json.JsonException ex)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = ex.Message, Alarm = true });
            return elements;
        }

        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "Direct Push",
            Value = preferences.Enabled
                ? "on: your other machines can send files here"
                : "off: nothing can be pushed to this machine ('sip push on', or Settings)",
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair, Text = "Inbox folder", Value = preferences.InboxRoot, MonoValue = true,
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Buttons,
            Buttons = [("Open inbox folder", () => OpenFolder(preferences.InboxRoot))],
        });

        elements.Add(new Element { Kind = ElementKind.Band, Text = "Forwarding rules" });
        if (preferences.Rules.Count == 0)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Text = "None: everything stays in the inbox. 'sip inbox rules add' makes one.",
            });
        }
        else
        {
            foreach (var rule in preferences.Rules)
            {
                elements.Add(new Element
                {
                    Kind = ElementKind.Mono,
                    Text = DisplayText.Printable(DescribeRule(rule), 200),
                });
            }
        }

        elements.Add(new Element { Kind = ElementKind.Band, Text = "Quarantine" });
        elements.Add(new Element
        {
            Kind = ElementKind.Text,
            Text = "What arrived and was held back: a program whatever it is called, or a file " +
                   "that is not what its name says. Stored exactly as it arrived, unencrypted, " +
                   "so the antivirus can scan it; released only by hand.",
        });

        if (_lastOutcome.Length > 0)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = _lastOutcome });
        }

        var inbox = new PushInbox(preferences.InboxRoot);
        var list = inbox.Quarantine.Inspect();
        if (list.Items.Count == 0)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = "Nothing is quarantined." });
        }

        foreach (var item in list.Items)
        {
            var hash = item.Record.Hash.ToShortString();
            elements.Add(new Element
            {
                Kind = ElementKind.Mono,
                Text = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{hash}  {BucketUsage.Bytes(item.Record.Size)}  from {DisplayText.Printable(item.First.SenderName, 24)}  " +
                    $"as '{DisplayText.Printable(item.First.SentName, 60)}'"),
                Alarm = item.IsProgram,
            });
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Text = (item.IsProgram ? "A program. " : string.Empty) +
                       (item.Present
                           ? "Release and delete need the exact command, which says what it does first:"
                           : "The file itself is gone - removed by something else on this machine, " +
                             "most likely the antivirus; only its record remains."),
            });
            elements.Add(new Element
            {
                Kind = ElementKind.Mono,
                Text = $"  sip quarantine release {hash}     sip quarantine delete {hash}",
            });
        }

        if (list.UnreadableRecords.Count > 0)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Alarm = true,
                Text = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{list.UnreadableRecords.Count} quarantine record(s) could not be read; they were left alone."),
            });
        }

        return elements;
    }

    /// <summary>One rule, in the words the command line uses.</summary>
    private static string DescribeRule(InboxRule rule)
    {
        var parts = new List<string>();
        if (rule.From is { } from)
        {
            parts.Add($"from {from[..Math.Min(12, from.Length)]}");
        }

        if (rule.Type is { } type)
        {
            parts.Add($"type {type}");
        }

        if (rule.NamePattern is { } pattern)
        {
            parts.Add($"name {pattern}");
        }

        var condition = parts.Count == 0 ? "everything from your own machines" : string.Join(" · ", parts);
        return $"{condition}  ->  {rule.Destination}";
    }

    private void OpenFolder(string root)
    {
        try
        {
            Directory.CreateDirectory(root);
            using var process = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(root) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _lastOutcome = $"The inbox folder could not be opened: {ex.Message}";
            RefreshSection();
        }
    }
}

/// <summary>Conversations, and each message's status - never more than this machine verified.</summary>
internal sealed class MessagesSection : InfoSection
{
    private readonly IMainWindowHost _host;

    public MessagesSection(IMainWindowHost host, WindowFonts fonts)
        : base(fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        _host = host;
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe()
    {
        var elements = new List<Element> { new() { Kind = ElementKind.Band, Text = "Messages" } };

        var team = TeamFeatures
            .ForThisUser(() => PairedMachines.AllDeviceIds(WatchedFolders.Load()))
            .Decide();
        if (!team.On)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = team.Why });
            return elements;
        }

        if (!MessageStore.ProtectionAvailable)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Alarm = true,
                Text = "This platform cannot protect stored messages at rest; they are stored plain.",
            });
        }

        var messages = MessageStore.ForThisUser().Load(out var unreadable);
        if (messages.Count == 0)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Text = "No messages yet. 'sip dm <person> <text>' starts a conversation; sending " +
                       "from this window is not built yet, and this screen never claims otherwise.",
            });
        }
        else
        {
            var people = LoadPeople();
            foreach (var conversation in messages
                         .GroupBy(message => message.PersonKey, StringComparer.Ordinal)
                         .OrderByDescending(group => group.Max(message => message.StatusUtc)))
            {
                elements.Add(new Element
                {
                    Kind = ElementKind.Band,
                    Text = NameOf(conversation.Key, people),
                });

                foreach (var message in conversation.OrderBy(message => message.Message.CreatedUtc).TakeLast(6))
                {
                    var arrow = message.Direction == MessageDirection.Sent ? "->" : "<-";
                    elements.Add(new Element
                    {
                        Kind = ElementKind.Mono,
                        Text = string.Create(
                            CultureInfo.InvariantCulture,
                            $"{message.Message.CreatedUtc.ToLocalTime():MM-dd HH:mm} {arrow} {message.Status}"),
                    });
                    elements.Add(new Element
                    {
                        Kind = ElementKind.Text,
                        Text = DisplayText.Printable(message.Message.Text, 300),
                    });
                }
            }

            elements.Add(new Element { Kind = ElementKind.Gap });
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Text = "Statuses stop at Delivered - the most a sender can verify - and Sending covers " +
                       "unreachable and blocked alike, so nothing here can say you are blocked. " +
                       "'sip dm' replies; 'sip messages' has every message.",
            });
        }

        if (unreadable > 0)
        {
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Alarm = true,
                Text = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{unreadable} stored message file(s) cannot be read; they may belong to another account or a newer build."),
            });
        }

        elements.Add(new Element
        {
            Kind = ElementKind.Buttons,
            Buttons = [("Open command line to reply...", OpenCommandLine)],
        });

        return elements;
    }

    private void OpenCommandLine() => _host.OpenCommandLine(FindForm()!);

    private static IReadOnlyList<Person> LoadPeople()
    {
        try
        {
            return PeopleStore.ForThisUser().Load();
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException)
        {
            _ = ex;
            return [];
        }
    }

    private static string NameOf(string personKey, IReadOnlyList<Person> people)
    {
        if (people.FirstOrDefault(person => string.Equals(person.Key, personKey, StringComparison.Ordinal)) is { } person)
        {
            return DisplayText.Printable(person.Name, 40);
        }

        return personKey.StartsWith(PeopleStore.DeviceKeyPrefix, StringComparison.Ordinal)
            ? personKey[PeopleStore.DeviceKeyPrefix.Length..][..Math.Min(12, personKey.Length - PeopleStore.DeviceKeyPrefix.Length)]
            : DisplayText.Printable(personKey, 24);
    }
}

/// <summary>Networks: where announcing is allowed, port mapping, and the ceilings.</summary>
internal sealed class NetworkSection : InfoSection
{
    private readonly IMainWindowHost _host;

    public NetworkSection(IMainWindowHost host, WindowFonts fonts)
        : base(fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        _host = host;
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe()
    {
        var elements = new List<Element>
        {
            new() { Kind = ElementKind.Band, Text = "This network" },
            new()
            {
                Kind = ElementKind.Text,
                Text = "Your machines find each other by fixed-size packets that identify nothing - " +
                       "to anyone else they are indistinguishable from random noise - and only on " +
                       "networks you have allowed, once each. An unknown network is a refusal.",
            },
        };

        var networkId = NetworkIdentity.Current();
        var name = NetworkIdentity.CurrentDisplayName() ?? "This network";
        if (networkId is null)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = "No network with a gateway right now." });
        }
        else
        {
            var consent = _host.Consent;
            var state = !consent.HasBeenAsked(networkId)
                ? "not decided: nothing is announced here"
                : consent.MayAnnounceOn(networkId)
                    ? "allowed: your machines can find this one here"
                    : "denied: never announced here";
            elements.Add(new Element { Kind = ElementKind.Pair, Text = name, Value = state });

            var id = networkId;
            var display = name;
            elements.Add(new Element
            {
                Kind = ElementKind.Buttons,
                Buttons =
                [
                    ("Allow on this network", () => Decide(id, display, allowed: true)),
                    ("Never here", () => Decide(id, display, allowed: false)),
                ],
            });
        }

        var decisions = _host.Consent.Decisions;
        if (decisions.Count > 0)
        {
            elements.Add(new Element { Kind = ElementKind.Band, Text = "Every network decided" });
            foreach (var decision in decisions.OrderBy(d => d.DisplayName, StringComparer.OrdinalIgnoreCase))
            {
                elements.Add(new Element
                {
                    Kind = ElementKind.Pair,
                    Text = DisplayText.Printable(decision.DisplayName, 40),
                    Value = decision.Allowed ? "allowed" : "denied",
                });
                var forget = decision.NetworkId;
                elements.Add(new Element
                {
                    Kind = ElementKind.Buttons,
                    Buttons = [("Forget - ask again next time", () => Forget(forget))],
                });
            }
        }

        var machine = MasterConfig.Load();
        elements.Add(new Element { Kind = ElementKind.Band, Text = "Reaching this machine" });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "Port mapping",
            Value = machine.PortMappingEnabled
                ? "on: the router is asked to forward the sync port; the activity log says what it answered"
                : "off: the router is not asked to forward anything ('sip config set network.portMapping 1')",
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "Upload ceiling",
            Value = machine.UploadLimit.IsLimited
                ? "set in master.json (network.uploadKiBps)"
                : "none: transfers take what the link gives",
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "Download ceiling",
            Value = machine.DownloadLimit.IsLimited
                ? "set in master.json (network.downloadKiBps)"
                : "none",
        });

        return elements;
    }

    private void Decide(string networkId, string displayName, bool allowed)
    {
        _host.Consent.Record(networkId, displayName, allowed);
        RefreshSection();
    }

    private void Forget(string networkId)
    {
        _ = _host.Consent.Forget(networkId);
        RefreshSection();
    }
}

/// <summary>Each folder's bucket: what it uses, what the policy keeps, what a collect frees.</summary>
internal sealed class StorageSection : InfoSection
{
    private readonly IMainWindowHost _host;
    private readonly Dictionary<string, string> _measured = new(StringComparer.OrdinalIgnoreCase);
    private bool _busy;

    public StorageSection(IMainWindowHost host, WindowFonts fonts)
        : base(fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        _host = host;
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe()
    {
        var elements = new List<Element>
        {
            new() { Kind = ElementKind.Band, Text = "Storage" },
            new()
            {
                Kind = ElementKind.Text,
                Text = "Measuring walks the whole store, so it runs when you ask. The reclaimable " +
                       "figure is a promise: what it projects is what a collect frees.",
            },
        };

        foreach (var view in _host.Folders())
        {
            elements.Add(new Element { Kind = ElementKind.Band, Text = view.Name });

            if (view.Status?.Bucket is { } bucket)
            {
                elements.Add(new Element { Kind = ElementKind.Pair, Text = "Bucket", Value = bucket.Describe() });
            }

            elements.Add(new Element
            {
                Kind = ElementKind.Pair,
                Text = "Measured",
                Value = _measured.TryGetValue(view.Path, out var measured)
                    ? measured
                    : "not yet this session",
            });

            var path = view.Path;
            elements.Add(new Element
            {
                Kind = ElementKind.Buttons,
                Buttons =
                [
                    ("Measure", () => Measure(path)),
                    ("Collect now", () => Collect(path)),
                ],
            });
        }

        if (_host.Folders().Count == 0)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = "No folders yet." });
        }

        elements.Add(new Element
        {
            Kind = ElementKind.Text,
            Text = "Retention and quota are set per folder: 'sip bucket keep 30d', 'sip bucket " +
                   "quota 3GiB', 'sip bucket keep all'. A tagged snapshot survives retention " +
                   "('sip tag').",
        });

        return elements;
    }

    private void Measure(string folder)
    {
        _ = MeasureAsync(folder);
    }

    private async Task MeasureAsync(string folder)
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        _measured[folder] = "measuring...";
        RefreshSection();

        try
        {
            var (usage, problem) = await _host.MeasureFolderBucketAsync(folder).ConfigureAwait(true);
            _measured[folder] = usage is null
                ? problem ?? "could not be measured"
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"{usage.Describe()} · reclaimable {BucketUsage.Bytes(usage.ReclaimableBytes)} " +
                    $"({usage.UnreferencedBlockCount} block(s), {usage.PrunableSnapshotCount} snapshot(s) past the policy)");
        }
        finally
        {
            _busy = false;
        }

        RefreshSection();
    }

    private void Collect(string folder)
    {
        _ = CollectAsync(folder);
    }

    private async Task CollectAsync(string folder)
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        _measured[folder] = "collecting...";
        RefreshSection();

        try
        {
            var (summary, _) = await _host.CollectFolderAsync(folder).ConfigureAwait(true);
            _measured[folder] = summary;
        }
        finally
        {
            _busy = false;
        }

        RefreshSection();
    }
}

/// <summary>Modes, locks, Direct Push's switch, and this machine's settings file.</summary>
internal sealed class SettingsSection : InfoSection
{
    private readonly IMainWindowHost _host;
    private string _lastOutcome = string.Empty;

    public SettingsSection(IMainWindowHost host, WindowFonts fonts)
        : base(fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        _host = host;
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe()
    {
        var elements = new List<Element> { new() { Kind = ElementKind.Band, Text = "Folders" } };

        foreach (var view in _host.Folders())
        {
            var facts = _host.FolderFacts(view.Path);
            var mode = facts?.Mode ?? "?";
            var lockLine = facts is null
                ? "?"
                : facts.HasPassphrase
                    ? facts.UnlockedForSession ? "passphrase set · unlocked for this session" : "locked on this machine"
                    : "no passphrase ('sip lock' sets one; it is per machine)";
            elements.Add(new Element
            {
                Kind = ElementKind.Pair,
                Text = view.Name,
                Value = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{mode} mode · {lockLine}"),
            });
        }

        if (_host.Folders().Count == 0)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = "No folders yet." });
        }

        elements.Add(new Element
        {
            Kind = ElementKind.Text,
            Text = "Power mode keeps every snapshot; Simple keeps the newest and stays small. The " +
                   "mode is chosen at 'sip init' and is not switched afterwards.",
        });

        elements.Add(new Element { Kind = ElementKind.Band, Text = "Direct Push" });
        if (_lastOutcome.Length > 0)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = _lastOutcome });
        }

        try
        {
            var push = PushPreferencesStore.ForThisUser().Load();
            elements.Add(new Element
            {
                Kind = ElementKind.Pair,
                Text = "Direct Push",
                Value = push.Enabled ? "on" : "off: nothing can be pushed to this machine",
            });
            elements.Add(new Element
            {
                Kind = ElementKind.Buttons,
                Buttons =
                [
                    (push.Enabled ? "Turn Direct Push off" : "Turn Direct Push on", () => TogglePush(!push.Enabled)),
                ],
            });
            elements.Add(new Element
            {
                Kind = ElementKind.Text,
                Text = "The daemon notices within half a minute. Forwarding rules are on the Inbox " +
                       "screen; 'sip help push' has the whole design.",
            });
        }
        catch (System.Text.Json.JsonException ex)
        {
            elements.Add(new Element { Kind = ElementKind.Text, Text = ex.Message, Alarm = true });
        }

        elements.Add(new Element { Kind = ElementKind.Band, Text = "This machine's settings" });
        var machine = MasterConfig.Load();
        elements.Add(new Element
        {
            Kind = ElementKind.Text,
            Text = "master.json is the machine's file: every account can read it, only an " +
                   "administrator can change it, and no setting changes what SippBucket tells " +
                   "you. 'sip config show' lists every value and where it came from; " +
                   "'sip config set <key> <value>' changes one.",
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "server.listenPort",
            Value = machine.ListenPort.ToString(CultureInfo.InvariantCulture),
            MonoValue = true,
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "network.portMapping",
            Value = machine.PortMappingEnabled ? "1 (on)" : "0 (off)",
            MonoValue = true,
        });
        elements.Add(new Element
        {
            Kind = ElementKind.Pair,
            Text = "network ceilings",
            Value = string.Create(
                CultureInfo.InvariantCulture,
                $"upload {(machine.UploadLimit.IsLimited ? "capped" : "none")} · download {(machine.DownloadLimit.IsLimited ? "capped" : "none")}"),
            MonoValue = true,
        });

        return elements;
    }

    private void TogglePush(bool enabled)
    {
        try
        {
            _ = PushPreferencesStore.ForThisUser().Update(preferences => preferences with { Enabled = enabled });
            _lastOutcome = enabled
                ? "Direct Push is on. The daemon opens its port within half a minute."
                : "Direct Push is off. The daemon closes its port within half a minute.";
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidOperationException)
        {
            _lastOutcome = $"The setting could not be changed: {ex.Message}";
        }

        RefreshSection();
    }
}

/// <summary>What everything is, in the window's own words, and where the commands are.</summary>
internal sealed class HelpSection : InfoSection
{
    private readonly IMainWindowHost _host;

    public HelpSection(IMainWindowHost host, WindowFonts fonts)
        : base(fonts)
    {
        ArgumentNullException.ThrowIfNull(host);
        _host = host;
    }

    /// <inheritdoc />
    public override IReadOnlyList<Element> Describe() =>
    [
        new Element { Kind = ElementKind.Band, Text = "What SippBucket is" },
        new Element
        {
            Kind = ElementKind.Text,
            Text = "Your documents live on every machine you own. Each machine is a server: they " +
                   "talk to each other directly, over a LAN or over the wire, with no account " +
                   "and no service in the middle. You save, and you sync; there are no branches " +
                   "and no staging area.",
        },
        new Element { Kind = ElementKind.Band, Text = "The first ten minutes" },
        new Element
        {
            Kind = ElementKind.Text,
            Text = "Add a folder on the Folders screen. Pair a machine - the toolbar button walks " +
                   "both sides through it with a spoken code. From then on the daemon keeps the " +
                   "folder the same on both machines, and this window is only a view: closing it " +
                   "changes nothing, and quitting is on the tray icon's menu.",
        },
        new Element { Kind = ElementKind.Band, Text = "Where the rest is" },
        new Element
        {
            Kind = ElementKind.Text,
            Text = "Everything ships in the command line first: history (show, diff, blame), tags, " +
                   "bisect, verify, hooks, the wiki (pages, search, comments), Direct Push, " +
                   "messages, and every setting. 'sip help' lists it all; 'sip help <command>' " +
                   "explains one properly.",
        },
        new Element
        {
            Kind = ElementKind.Buttons,
            Buttons = [("Open command line...", () => _host.OpenCommandLine(FindForm()!))],
        },
        new Element { Kind = ElementKind.Band, Text = "What this window never does" },
        new Element
        {
            Kind = ElementKind.Text,
            Text = "It never shows a green tick for a claim short of its total, never invents a " +
                   "state the daemon cannot emit, and never says 'synced' when it means 'the " +
                   "last try did not fail'. Every headline is the daemon's own sentence.",
        },
    ];
}
