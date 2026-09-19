using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Health;
using SippBucket.Core.Push;
using SippBucket.Core.Repository;
using SippBucket.Core.Sync;

namespace SippBucket.Core.Configuration;

/// <summary>One setting the machine's <c>master.json</c> can hold, with its default and its limits.</summary>
/// <remarks>
/// The limits are the hard limits, and they live here, in code, not in the file
/// (docs/MASTER-CONFIG.md): the file can tune a value within them and can never move them. A
/// value outside them is not clamped to the nearest limit, which would quietly run with a
/// number nobody chose; it is ignored, the default is used, and the fallback is reported.
/// </remarks>
public sealed record MasterSetting
{
    /// <summary>The section the setting lives in, such as <c>server</c>.</summary>
    public required string Section { get; init; }

    /// <summary>The setting's name within its section, such as <c>listenPort</c>.</summary>
    public required string Name { get; init; }

    /// <summary>The dotted key a person types: <c>server.listenPort</c>.</summary>
    public string Key => $"{Section}.{Name}";

    /// <summary>The value when the file does not set it, or sets it badly.</summary>
    public required int Default { get; init; }

    /// <summary>The smallest value accepted.</summary>
    public required int Minimum { get; init; }

    /// <summary>The largest value accepted.</summary>
    public required int Maximum { get; init; }

    /// <summary>What the number counts, for help and reports: <c>seconds</c>, or empty for a port number.</summary>
    public required string Unit { get; init; }

    /// <summary>What the setting does, in a sentence or two, for <c>sip help config</c>.</summary>
    public required string Description { get; init; }

    /// <summary>Checks a value typed by a person, as <c>sip config set</c> receives it.</summary>
    /// <param name="text">The text.</param>
    /// <param name="value">The value, when this returns null.</param>
    /// <returns>Why the text is not an acceptable value, or null when it is.</returns>
    public string? TryParse(string? text, out int value)
    {
        if (!int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value))
        {
            value = Default;
            return $"'{text}' is not a whole number";
        }

        return OutOfRange(value);
    }

    /// <summary>Checks a value as it appears in the file.</summary>
    /// <param name="element">The JSON value.</param>
    /// <param name="value">The value, when this returns null.</param>
    /// <returns>Why the value is not acceptable, or null when it is.</returns>
    internal string? Check(JsonElement element, out int value)
    {
        value = Default;

        if (element.ValueKind != JsonValueKind.Number)
        {
            return $"is {Describe(element.ValueKind)}, not a whole number";
        }

        if (!element.TryGetInt32(out var parsed))
        {
            return $"is {element.GetRawText()}, which is not a whole number";
        }

        var outOfRange = OutOfRange(parsed);
        if (outOfRange is null)
        {
            value = parsed;
        }

        return outOfRange;
    }

    /// <summary>The limits in words, for help and messages.</summary>
    /// <returns>For example "10 to 3600 seconds", or "1 to 65534" for a port.</returns>
    public string DescribeLimits() =>
        string.Create(CultureInfo.InvariantCulture, $"{Minimum} to {Maximum}{(Unit.Length > 0 ? " " : string.Empty)}{Unit}");

    private string? OutOfRange(int value) =>
        value < Minimum || value > Maximum
            ? string.Create(CultureInfo.InvariantCulture, $"is {value}, outside {DescribeLimits()}")
            : null;

    private static string Describe(JsonValueKind kind) => kind switch
    {
        JsonValueKind.String => "text",
        JsonValueKind.True or JsonValueKind.False => "true or false",
        JsonValueKind.Null => "null",
        JsonValueKind.Object => "an object",
        JsonValueKind.Array => "a list",
        _ => "not a value",
    };
}

/// <summary>Every setting <c>master.json</c> can hold.</summary>
/// <remarks>
/// <para>
/// The defaults are not restated here. Each is taken from the constant that already defined
/// it, so the file can only move a value away from the built-in default, never quietly
/// redefine what the default is: the port from <see cref="RepositoryConfig.DefaultListenPort"/>
/// and the sync timings from <see cref="SyncTuning.Default"/>, whose remarks say why each is
/// what it is.
/// </para>
/// <para>
/// The <c>network</c> section holds reaching-the-other-machine settings: the router port
/// mapping switch and its lifetime (D-05). Bandwidth ceilings go here next; until then any
/// other key in it is reported as unknown, like any other.
/// </para>
/// <para>
/// The <c>push</c> section's defaults have no older constant to come from, because Direct Push
/// is new. They are stated here once, and <c>PushSettings</c> is built from them.
/// </para>
/// </remarks>
public static class MasterSettings
{
    /// <summary>The <c>server</c> section.</summary>
    public const string ServerSection = "server";

    /// <summary>The <c>network</c> section, reserved for bandwidth ceilings and discovery defaults.</summary>
    public const string NetworkSection = "network";

    /// <summary>The <c>sync</c> section.</summary>
    public const string SyncSection = "sync";

    /// <summary>The <c>push</c> section: Direct Push and direct messages (docs/DIRECT-PUSH.md).</summary>
    public const string PushSection = "push";

    /// <summary>The <c>health</c> section: peer health's thresholds (docs/PEER-HEALTH.md).</summary>
    public const string HealthSection = "health";

    /// <summary>The TCP port this machine serves every folder on.</summary>
    public static MasterSetting ListenPort { get; } = new()
    {
        Section = ServerSection,
        Name = "listenPort",
        Default = RepositoryConfig.DefaultListenPort,
        Minimum = 1,

        // One below the top, because pairing listens on this port plus one.
        Maximum = 65534,
        Unit = string.Empty,
        Description =
            "The TCP port this machine serves every folder on. Pairing opens the next port " +
            "up, for the ten minutes a code is live. Other machines record the port when they " +
            "pair, so changing it means updating them with 'sip peer add'.",
    };

    /// <summary>How often each folder polls its peers when nothing has changed locally.</summary>
    public static MasterSetting PollInterval { get; } = Seconds(
        SyncSection,
        "pollIntervalSeconds",
        SyncTuning.Default.PollInterval,
        minimum: 10,
        maximum: 3600,
        "How often each folder asks its peers for changes when nothing has changed here. " +
        "A folder's status reads as ageing, and then stale, after multiples of this, so a " +
        "longer interval also means a status that takes longer to call itself out of date.");

    /// <summary>How long file changes must settle before a folder saves.</summary>
    public static MasterSetting DebounceInterval { get; } = Seconds(
        SyncSection,
        "debounceSeconds",
        SyncTuning.Default.DebounceInterval,
        minimum: 1,
        maximum: 300,
        "How long a folder waits after the last change to a file before it saves, so that an " +
        "application writing a document several times in a second makes one snapshot, not ten.");

    /// <summary>How long to wait for a peer to accept a connection.</summary>
    public static MasterSetting ConnectTimeout { get; } = Seconds(
        SyncSection,
        "connectTimeoutSeconds",
        SyncTuning.Default.ConnectTimeout,
        minimum: 1,
        maximum: 120,
        "How long to wait for a peer to accept a connection before trying its next address.");

    /// <summary>How long one read or write may make no progress.</summary>
    public static MasterSetting StallTimeout { get; } = Seconds(
        SyncSection,
        "stallTimeoutSeconds",
        SyncTuning.Default.StallTimeout,
        minimum: 5,
        maximum: 120,
        "How long one read or write may make no progress before the peer is given up on. " +
        "Applies before authentication too. A stranger that has not proved which machine it is " +
        "is also given up on at the handshake's own 15-second deadline, however it sends; that " +
        "deadline is fixed and not set here.");

    /// <summary>How long a served connection may sit idle between requests.</summary>
    public static MasterSetting IdleTimeout { get; } = Seconds(
        SyncSection,
        "idleTimeoutSeconds",
        SyncTuning.Default.IdleTimeout,
        minimum: 120,
        maximum: 3600,
        "How long a connection this machine serves may sit quiet between one request and the " +
        "next, while the other machine writes what it received to disk. Its smallest value " +
        "is the stall timeout's largest, so it can never be set shorter than the stall timeout.");

    /// <summary>The TCP port Direct Push's SSH server listens on.</summary>
    public static MasterSetting PushPort { get; } = new()
    {
        Section = PushSection,
        Name = "sshPort",
        Default = PushSettings.DefaultPort,
        Minimum = 1,
        Maximum = 65535,
        Unit = string.Empty,
        Description =
            "The TCP port Direct Push listens on, for files and direct messages from paired " +
            "machines. Nothing listens on it unless Direct Push, or team features, are on. It " +
            "cannot be the sync port or the pairing port beside it; while it is, Direct Push " +
            "does not start, and says why.",
    };

    /// <summary>How much one transfer may have in flight before the receiver acknowledges it.</summary>
    public static MasterSetting PushWindow { get; } = new()
    {
        Section = PushSection,
        Name = "windowKiB",
        Default = 16384,
        Minimum = 256,

        // The receiving machine holds up to this much per transfer in memory. 64 MiB keeps a
        // handful of senders inside a few hundred MiB whatever the file says.
        Maximum = 65536,
        Unit = "KiB",
        Description =
            "How much one transfer may have in flight before the receiving machine " +
            "acknowledges it. Larger is faster on a fast link, and costs the receiving machine " +
            "that much memory for each transfer arriving at once.",
    };

    /// <summary>The most the quarantine may hold.</summary>
    public static MasterSetting QuarantineCap { get; } = new()
    {
        Section = PushSection,
        Name = "quarantineMiB",
        Default = 8192,
        Minimum = 64,
        Maximum = 1_048_576,
        Unit = "MiB",
        Description =
            "The most the quarantine may hold. A file that would take it past this is refused, " +
            "and the sender is told why; nothing already in quarantine is removed to make room.",
    };

    /// <summary>The most one other person's files may take on this machine.</summary>
    public static MasterSetting PersonInboxCap { get; } = new()
    {
        Section = PushSection,
        Name = "personInboxMiB",
        Default = 2048,
        Minimum = 16,
        Maximum = 1_048_576,
        Unit = "MiB",
        Description =
            "The most one other person's files may take in the inbox and the quarantine " +
            "together, per person, so nobody can fill this machine's disk. Your own machines " +
            "have no such cap. It applies once team features are on.",
    };

    /// <summary>The largest single file Direct Push accepts.</summary>
    public static MasterSetting LargestFile { get; } = new()
    {
        Section = PushSection,
        Name = "largestFileMiB",
        Default = 65536,
        Minimum = 1,
        Maximum = 1_048_576,
        Unit = "MiB",
        Description = string.Create(
            CultureInfo.InvariantCulture,
            $"The largest single file Direct Push accepts. A larger one is refused before any of " +
            $"it is written. A file is also refused if writing it would leave the inbox's disk " +
            $"with less than {PushSettings.DiskReserveBytes / (1024 * 1024 * 1024)} GiB free."),
    };

    /// <summary>The largest direct message accepted.</summary>
    public static MasterSetting LargestMessage { get; } = new()
    {
        Section = PushSection,
        Name = "largestMessageKiB",
        Default = 256,
        Minimum = 1,
        Maximum = 16384,
        Unit = "KiB",
        Description =
            "The largest direct message accepted, not counting its attachments, which travel as " +
            "Direct Push files.",
    };

    /// <summary>How many direct messages one sender may deliver in a minute.</summary>
    public static MasterSetting MessageRate { get; } = new()
    {
        Section = PushSection,
        Name = "messagesPerMinute",
        Default = 30,
        Minimum = 1,
        Maximum = 600,
        Unit = "per minute",
        Description =
            "How many direct messages one sender may deliver in a minute. Any more are not " +
            "accepted, and the sender sees Not accepted. They are recorded against that machine, " +
            "never alerted: a chatty person is not a faulty machine.",
    };

    /// <summary>How many faults of one kind from one server in a day raise an alert.</summary>
    public static MasterSetting FaultsPerDay { get; } = new()
    {
        Section = HealthSection,
        Name = "faultsPerDay",
        Default = HealthSettings.Default.FaultsPerDay,
        Minimum = 1,
        Maximum = 1000,
        Unit = "per day",
        Description =
            "How many faults of one kind from one server in a day raise an alert: bad blocks, wrong " +
            "snapshots, unsafe paths, malformed messages, stalls. One bad block is probably a disk " +
            "error; many in a day is a faulty or compromised machine. Every fault is recorded " +
            "whatever this says; it only decides when you are told.",
    };

    /// <summary>How far a timestamp a server sends may be from this machine's clock.</summary>
    public static MasterSetting ClockSkew { get; } = new()
    {
        Section = HealthSection,
        Name = "clockSkewMinutes",
        Default = (int)HealthSettings.Default.ClockSkew.TotalMinutes,
        Minimum = 5,
        Maximum = 1440,
        Unit = "minutes",
        Description =
            "How far a timestamp another server sends may be from this machine's clock before it " +
            "is recorded as a fault. A clock hours off makes conflict copies and history read out " +
            "of order.",
    };

    /// <summary>The share of a folder's files one incoming change may change or delete before it is held.</summary>
    public static MasterSetting MassChangePercent { get; } = new()
    {
        Section = HealthSection,
        Name = "massChangePercent",
        Default = HealthSettings.Default.MassChangePercent,
        Minimum = 10,
        Maximum = 90,
        Unit = "%",
        Description =
            "The share of a folder's files one incoming change may change or delete before it is " +
            "held and you are asked whether it was you. The hold cannot be switched off: at most " +
            "90%, so a change to every file is always held.",
    };

    /// <summary>How many files a folder must have before the share alone can hold a change.</summary>
    public static MasterSetting MassChangeMinimumFiles { get; } = new()
    {
        Section = HealthSection,
        Name = "massChangeMinimumFiles",
        Default = HealthSettings.Default.MassChangeMinimumFiles,
        Minimum = 5,
        Maximum = 1000,
        Unit = "files",
        Description =
            "How many files a folder must hold before the share of files changed can hold a change " +
            "by itself, so that editing both files of a two-file folder is not a mass change. Files " +
            "turning random-looking, and waves of renames, are looked for in every folder.",
    };

    /// <summary>The share of changed files that may turn random-looking before a change is held.</summary>
    public static MasterSetting RandomChangePercent { get; } = new()
    {
        Section = HealthSection,
        Name = "randomChangePercent",
        Default = HealthSettings.Default.RandomChangePercent,
        Minimum = 5,
        Maximum = 90,
        Unit = "%",
        Description =
            "The share of an incoming change's files whose content turns random-looking, when it " +
            "was not before, that holds the change: what encryption by ransomware looks like. " +
            "Judged before against after, because photos, videos and archives look random anyway.",
    };

    /// <summary>How many files renamed to one new extension hold a change.</summary>
    public static MasterSetting RenameWaveMinimumFiles { get; } = new()
    {
        Section = HealthSection,
        Name = "renameWaveMinimumFiles",
        Default = HealthSettings.Default.RenameWaveMinimumFiles,
        Minimum = 3,
        Maximum = 1000,
        Unit = "files",
        Description =
            "How many files one incoming change may rename to one extension the folder never had " +
            "before it is held, as when ransomware renames everything to .locked.",
    };

    /// <summary>Whether the daemon asks this machine's router to forward the sync port here (D-05).</summary>
    public static MasterSetting PortMappingEnabled { get; } = new()
    {
        Section = NetworkSection,
        Name = "portMapping",
        Default = 0,
        Minimum = 0,
        Maximum = 1,
        Unit = "0 or 1",
        Description =
            "Whether the daemon asks this machine's router to forward the sync port to it, so " +
            "your other machines can reach it from outside this network. 1 asks (PCP first, " +
            "then NAT-PMP, then UPnP); 0, the default, never does. The forwarded port is " +
            "always server.listenPort. Forwarding lets anyone on the internet reach the port; " +
            "only machines in your peer lists can sync, and a stranger is dropped at the " +
            "handshake's own fixed deadline, but the port itself is visible.",
    };

    /// <summary>How long each router mapping is asked to last.</summary>
    public static MasterSetting PortMappingLifetime { get; } = new()
    {
        Section = NetworkSection,
        Name = "portMappingLifetimeMinutes",
        Default = 120,
        Minimum = 2,
        Maximum = 1440,
        Unit = "minutes",
        Description =
            "How long each router forwarding is asked to last. It renews itself before it " +
            "expires while the daemon runs, and is deleted from the router when the daemon " +
            "stops or the setting is switched off.",
    };

    /// <summary>The ceiling on what this machine sends peers as blocks. 0 is no ceiling.</summary>
    public static MasterSetting UploadCeiling { get; } = new()
    {
        Section = NetworkSection,
        Name = "uploadKiBps",
        Default = 0,
        Minimum = 0,
        Maximum = 1_048_576,
        Unit = "KiB/s",
        Description =
            "The most this machine sends other machines as blocks, machine-wide, so a " +
            "background transfer cannot take the whole link mid-video-call. 0, the default, " +
            "is no ceiling. A token bucket with a one-second burst, not congestion control, " +
            "and honest about it.",
    };

    /// <summary>The ceiling on what this machine fetches from peers as blocks. 0 is no ceiling.</summary>
    public static MasterSetting DownloadCeiling { get; } = new()
    {
        Section = NetworkSection,
        Name = "downloadKiBps",
        Default = 0,
        Minimum = 0,
        Maximum = 1_048_576,
        Unit = "KiB/s",
        Description =
            "The most this machine fetches from other machines as blocks, machine-wide. 0, " +
            "the default, is no ceiling.",
    };

    /// <summary>Every setting, in the order help and reports list them.</summary>
    public static IReadOnlyList<MasterSetting> All { get; } =
    [
        ListenPort, PortMappingEnabled, PortMappingLifetime, UploadCeiling, DownloadCeiling,
        PollInterval, DebounceInterval, ConnectTimeout, StallTimeout, IdleTimeout,
        PushPort, PushWindow, QuarantineCap, PersonInboxCap, LargestFile, LargestMessage, MessageRate,
        FaultsPerDay, ClockSkew, MassChangePercent, MassChangeMinimumFiles, RandomChangePercent, RenameWaveMinimumFiles,
    ];

    /// <summary>Every section the file may have, including ones that hold nothing yet.</summary>
    public static IReadOnlyList<string> Sections { get; } = [ServerSection, NetworkSection, SyncSection, PushSection, HealthSection];

    /// <summary>Finds a setting by its dotted key, ignoring case.</summary>
    /// <param name="key">For example <c>server.listenPort</c>.</param>
    /// <returns>The setting, or null when there is none by that key.</returns>
    public static MasterSetting? Find(string? key) =>
        All.FirstOrDefault(setting => string.Equals(setting.Key, key, StringComparison.OrdinalIgnoreCase));

    private static MasterSetting Seconds(
        string section,
        string name,
        TimeSpan builtIn,
        int minimum,
        int maximum,
        string description) =>
        new()
        {
            Section = section,
            Name = name,
            Default = (int)builtIn.TotalSeconds,
            Minimum = minimum,
            Maximum = maximum,
            Unit = "seconds",
            Description = description,
        };
}
