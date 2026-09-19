using System.Text.Json;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;

namespace SippBucket.Core.Servers;

/// <summary>
/// Server.ID's exchange between the person's own machines: what this machine tells a peer
/// about itself, what it takes from what the peer tells it, and how every log line names a
/// server (docs/SERVER-ID.md, "Where it travels").
/// </summary>
/// <remarks>
/// <para>
/// <b>Only between the person's own machines.</b> A peer is told anything only when the person
/// answered that it is theirs (<see cref="MachineOwner.Mine"/>), and anything it says is kept
/// only then. A paired machine never answered about is someone else's here, as it is for every
/// default that protects the person; so is every machine when <c>machines.json</c> cannot be
/// read. Nothing about this reaches discovery's plaintext broadcast, which carries only the run
/// ID.
/// </para>
/// <para>
/// <b>Guidance only, and never in the way.</b> Sync never waits on this and never fails for it:
/// a directory that cannot be read or written is logged once and the record is not kept. A
/// record that is malformed goes to the sender's health record as a malformed message, and what
/// it says about itself is compared as weak evidence.
/// </para>
/// </remarks>
public sealed class ServerExchange
{
    private readonly Lazy<(ServerIdentity? Me, string? Problem)> _me;
    private readonly KnownServers _servers;
    private readonly KnownMachines _owners;
    private readonly Func<DateTimeOffset, SelfReport> _report;
    private readonly PeerHealth? _health;
    private readonly HealthSettings _settings;
    private readonly Action<string>? _log;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private string? _lastProblem;

    /// <summary>Creates the exchange.</summary>
    /// <param name="identify">Works out this machine's identity, once, when first needed.</param>
    /// <param name="servers">The directory of known servers.</param>
    /// <param name="owners">The person's answers about whose each machine is.</param>
    /// <param name="report">Makes this machine's self-report, given the time.</param>
    /// <param name="health">The health records, or null when this process keeps none.</param>
    /// <param name="settings">The health thresholds, or null for the defaults.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="time">The clock, for tests.</param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public ServerExchange(
        Func<ServerIdentity> identify,
        KnownServers servers,
        KnownMachines owners,
        Func<DateTimeOffset, SelfReport> report,
        PeerHealth? health = null,
        HealthSettings? settings = null,
        Action<string>? log = null,
        TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(identify);
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentNullException.ThrowIfNull(owners);
        ArgumentNullException.ThrowIfNull(report);

        _me = new Lazy<(ServerIdentity?, string?)>(() => Identify(identify), LazyThreadSafetyMode.ExecutionAndPublication);
        _servers = servers;
        _owners = owners;
        _report = report;
        _health = health;
        _settings = settings ?? HealthSettings.Default;
        _log = log;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>This machine's identity, or null when it could not be worked out.</summary>
    public ServerIdentity? Me => _me.Value.Me;

    /// <summary>The health thresholds in effect.</summary>
    public HealthSettings Settings => _settings;

    /// <summary>
    /// Whether the person said a change from this install was not them, and has not cleared it:
    /// then no change of its is taken.
    /// </summary>
    /// <param name="deviceId">The install.</param>
    /// <returns>True while it is suspect; false when it is not, or when this process keeps no health records.</returns>
    /// <remarks>
    /// A <c>health.json</c> that cannot be read is logged and read as "not suspect": syncing
    /// goes on, and every change is still judged by the mass-change check, which does not
    /// depend on the file.
    /// </remarks>
    public bool IsSuspect(string deviceId)
    {
        if (_health is null)
        {
            return false;
        }

        try
        {
            return _health.IsSuspect(deviceId);
        }
        catch (JsonException ex)
        {
            Report(ex.Message);
            return false;
        }
    }

    /// <summary>Raises the alert that asks the person about a change held from a server.</summary>
    /// <param name="deviceId">The install that sent it.</param>
    /// <param name="fallbackName">How to name it when it has no number.</param>
    /// <param name="folder">The folder's name.</param>
    /// <param name="folderPath">The folder's path, which the answer needs.</param>
    /// <param name="held">The held snapshot's ID.</param>
    /// <param name="what">What was seen, in a sentence.</param>
    /// <returns>The alert, or null when this process keeps no alerts or the log could not be written.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1030:Use events where appropriate",
        Justification = "An alert is raised: the domain's own verb (docs/PEER-HEALTH.md). This " +
                        "writes the permanent log through AlertLog; nothing here is an event source.")]
    public Alert? RaiseHold(string deviceId, string fallbackName, string folder, string folderPath, string held, string what)
    {
        if (_health is null)
        {
            return null;
        }

        var naming = NamingOf(deviceId, fallbackName);
        try
        {
            return _health.Alerts.Raise(new Alert
            {
                Id = 0,
                Utc = _time.GetUtcNow(),
                Kind = AlertKind.MassChange,
                Server = naming.Display,
                ServerId = naming.ServerId,
                Device = deviceId,
                What = what,
                Done =
                    "The change is kept, not applied and not deleted. \"That was me\" applies it; \"Not me\" keeps it out " +
                    $"for good, and no change from {naming.Display} is taken until you say otherwise. Your other machines " +
                    "go on syncing either way.",
                Folder = folder,
                FolderPath = folderPath,
                Held = held,
                Asks = true,
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Report(ex.Message);
            return null;
        }
    }

    /// <summary>Why this machine's identity could not be worked out, or null.</summary>
    public string? Problem => _me.Value.Problem;

    /// <summary>Whether the person said a device is one of their own machines.</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>True only for <see cref="MachineOwner.Mine"/>; false when unanswered, someone else's, or unreadable.</returns>
    public bool IsOwn(string deviceId)
    {
        try
        {
            return MachineOwnership.IsOwn(_owners.OwnerOf(deviceId));
        }
        catch (JsonException ex)
        {
            Report(ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Gives this machine its number when it has none yet: the daemon does this at start, so the
    /// machine SippBucket was installed on first is the one that keeps Server 1.
    /// </summary>
    public void Settle()
    {
        if (Identity() is not { } me)
        {
            return;
        }

        try
        {
            var (_, notes) = _servers.Describe(me, _time.GetUtcNow());
            foreach (var note in notes)
            {
                _log?.Invoke($"Server.ID: {note}");
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            Report(ex.Message);
        }
    }

    /// <summary>What to tell a peer: this machine's record, report and passed-on claims, or nothing.</summary>
    /// <param name="peerDeviceId">The peer's device ID, as its handshake proved it.</param>
    /// <returns>The message; <see cref="ServerExchangeMessage.Nothing"/> for a machine that is not the person's own.</returns>
    public ServerExchangeMessage For(string peerDeviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerDeviceId);

        if (!IsOwn(peerDeviceId) || Identity() is not { } me)
        {
            return ServerExchangeMessage.Nothing;
        }

        var now = _time.GetUtcNow();
        try
        {
            var (record, notes) = _servers.Describe(me, now);
            foreach (var note in notes)
            {
                _log?.Invoke($"Server.ID: {note}");
            }

            return new ServerExchangeMessage
            {
                Record = record,
                Report = _report(now),
                Others = _servers.ClaimsFor(peerDeviceId),
            };
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            Report(ex.Message);
            return ServerExchangeMessage.Nothing;
        }
    }

    /// <summary>Takes what a peer told this machine, when it is the person's own machine.</summary>
    /// <param name="peerDeviceId">The peer's device ID, as its handshake proved it.</param>
    /// <param name="message">What it sent.</param>
    /// <param name="folder">The folder whose connection it came on, for the health record.</param>
    public void Take(string peerDeviceId, ServerExchangeMessage message, string? folder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerDeviceId);
        ArgumentNullException.ThrowIfNull(message);

        if (!IsOwn(peerDeviceId) || Identity() is not { } me)
        {
            return;
        }

        var now = _time.GetUtcNow();
        ServerReceipt receipt;
        try
        {
            receipt = _servers.Receive(me, peerDeviceId, message, now);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            Report(ex.Message);
            return;
        }

        var name = NameOf(peerDeviceId) ?? Short(peerDeviceId);
        foreach (var note in receipt.Notes)
        {
            _log?.Invoke($"Server.ID: {note}");
        }

        foreach (var problem in receipt.Problems)
        {
            _log?.Invoke($"{name}: its Server.ID record was not kept: {problem}");
            RecordFault(peerDeviceId, HealthFault.MalformedMessage, $"a Server.ID record was refused: {problem}", folder);
        }

        if (_health is not null && SelfReport.IsAcceptable(message.Report))
        {
            var findings = SelfReports.Compare(message.Record, message.Report, now, _settings);
            try
            {
                _health.RecordReport(peerDeviceId, findings, now);
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                Report(ex.Message);
            }
        }
    }

    /// <summary>The directory as it stands, or an empty one when it cannot be read.</summary>
    /// <returns>The directory.</returns>
    public ServerDirectory LoadDirectory()
    {
        try
        {
            return _servers.Load();
        }
        catch (JsonException ex)
        {
            Report(ex.Message);
            return ServerDirectory.Empty;
        }
    }

    /// <summary>A device's server by number and label, for log lines: "Server 2 (Dell Inspiron 15 3511)".</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>The name, or null when the device is not an install of a numbered server of the person's.</returns>
    public string? NameOf(string deviceId) => LoadDirectory().NameOf(deviceId);

    /// <summary>How to name a device's server in an alert.</summary>
    /// <param name="deviceId">The device.</param>
    /// <param name="fallback">The name the person gave it, for a machine with no number.</param>
    /// <returns>The naming: number and Server.ID for the person's own machines, the given name otherwise.</returns>
    public ServerNaming NamingOf(string deviceId, string fallback)
    {
        var directory = LoadDirectory();
        if (IsOwn(deviceId) && directory.NameOf(deviceId) is { } display)
        {
            return new ServerNaming(display, directory.ServerOf(deviceId)?.Id);
        }

        return new ServerNaming(fallback, null);
    }

    /// <summary>Records a fault against a peer in its health record, if this process keeps them.</summary>
    /// <param name="peerDeviceId">The peer.</param>
    /// <param name="fault">The fault.</param>
    /// <param name="detail">What exactly was seen.</param>
    /// <param name="folder">The folder, or null.</param>
    /// <param name="fallbackName">How to name it if it has no number, or null for its short device ID.</param>
    /// <returns>The alert raised, or null.</returns>
    public Alert? RecordFault(string peerDeviceId, HealthFault fault, string detail, string? folder, string? fallbackName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerDeviceId);

        if (_health is null)
        {
            return null;
        }

        try
        {
            return _health.Record(
                peerDeviceId,
                NamingOf(peerDeviceId, fallbackName ?? Short(peerDeviceId)),
                fault,
                detail,
                folder,
                _settings,
                _time.GetUtcNow());
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            Report(ex.Message);
            return null;
        }
    }

    /// <summary>This machine's identity, saying once why when there is none.</summary>
    private ServerIdentity? Identity()
    {
        if (Me is { } me)
        {
            return me;
        }

        Report($"this machine's Server.ID could not be worked out, so no record is exchanged: {Problem}");
        return null;
    }

    private static (ServerIdentity?, string?) Identify(Func<ServerIdentity> identify)
    {
        try
        {
            return (identify(), null);
        }
        catch (IOException ex)
        {
            return (null, ex.Message);
        }
    }

    private static string Short(string deviceId) => deviceId[..Math.Min(12, deviceId.Length)];

    /// <summary>Logs a problem once, however many connections meet it.</summary>
    private void Report(string problem)
    {
        lock (_gate)
        {
            if (string.Equals(problem, _lastProblem, StringComparison.Ordinal))
            {
                return;
            }

            _lastProblem = problem;
        }

        _log?.Invoke($"Server.ID: {problem}");
    }
}
