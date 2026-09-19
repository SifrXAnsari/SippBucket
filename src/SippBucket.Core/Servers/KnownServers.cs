using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Platform;
using SippBucket.Core.Protocol;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Servers;

/// <summary>One server this machine knows of: its record as last heard, and this machine's own notes on it.</summary>
/// <remarks>
/// Keyed by permanent ID, so the two installs of a dual-boot board are one server with two
/// installs. <see cref="FirstPaired"/> and <see cref="LastSeen"/> are this machine's own records
/// and never travel. An entry this machine only heard about from another of the person's
/// servers carries <see cref="HeardFrom"/>: hearsay, used for numbering and nothing else.
/// </remarks>
public sealed record KnownServer
{
    /// <summary>Its permanent ID, 64 lower-case hexadecimal characters.</summary>
    public required string Permanent { get; init; }

    /// <summary>Its <c>Server.ID#XXX-XXX-XXX</c>.</summary>
    public required string Id { get; init; }

    /// <summary>Where its permanent ID came from, by wire name, or null for hearsay.</summary>
    public string? Source { get; init; }

    /// <summary>Its label, such as "Dell Inspiron 15 3511", or null.</summary>
    public string? Label { get; init; }

    /// <summary>Its installs, as its records and the claims passed on have named them.</summary>
    public IReadOnlyList<ServerInstall> Installs { get; init; } = [];

    /// <summary>Its installs' number claims.</summary>
    public IReadOnlyList<HeardClaim> Claims { get; init; } = [];

    /// <summary>The run ID it last reported.</summary>
    public string? Run { get; init; }

    /// <summary>When that run began, as it reported.</summary>
    public DateTimeOffset? Started { get; init; }

    /// <summary>The install that reported <see cref="Run"/>.</summary>
    public string? RunFrom { get; init; }

    /// <summary>Its SippBucket version, as it reported.</summary>
    public string? Version { get; init; }

    /// <summary>Its wire-protocol version, as it reported.</summary>
    public int? Protocol { get; init; }

    /// <summary>What it last said about its clock and settings: weak evidence.</summary>
    public SelfReport? Report { get; init; }

    /// <summary>When this machine first exchanged records with it after pairing.</summary>
    public DateTimeOffset? FirstPaired { get; init; }

    /// <summary>When this machine last heard from it directly.</summary>
    public DateTimeOffset? LastSeen { get; init; }

    /// <summary>The install that passed this entry on, when this machine has not heard from the server itself.</summary>
    public string? HeardFrom { get; init; }
}

/// <summary>A number claim as this machine heard it: from the install itself, or passed on.</summary>
public sealed record HeardClaim
{
    /// <summary>The install that made the claim.</summary>
    public required string Device { get; init; }

    /// <summary>The number claimed.</summary>
    public required int Number { get; init; }

    /// <summary>When the install took it.</summary>
    public required DateTimeOffset Numbered { get; init; }

    /// <summary>Whether it came from the install itself, which outranks any claim passed on.</summary>
    public bool Direct { get; init; }

    /// <summary>When this machine heard it.</summary>
    public DateTimeOffset HeardUtc { get; init; }
}

/// <summary>This install's own part of the directory: its number claim, and when it first ran.</summary>
public sealed record ThisInstall
{
    /// <summary>This install's device ID.</summary>
    public required string Device { get; init; }

    /// <summary>The permanent ID this install last had.</summary>
    public required string Permanent { get; init; }

    /// <summary>The number this install claims for its server; 0 before it has one.</summary>
    public int Number { get; init; }

    /// <summary>When it took that number.</summary>
    public DateTimeOffset? Numbered { get; init; }

    /// <summary>When this install first ran SippBucket's Server.ID.</summary>
    public required DateTimeOffset FirstSeen { get; init; }

    /// <summary>Its board's label, for this machine's own listings.</summary>
    public string? Label { get; init; }
}

/// <summary>What taking a peer's message changed, for the log, and what was wrong with it.</summary>
/// <param name="Notes">What changed, in sentences.</param>
/// <param name="Problems">What in the message was refused, and why: malformed input from a peer.</param>
public sealed record ServerReceipt(IReadOnlyList<string> Notes, IReadOnlyList<string> Problems);

/// <summary>
/// The servers this machine knows, in <c>servers.json</c> beside the device key: every one of
/// the person's own machines it has exchanged Server.ID records with, what they said, their
/// numbers, and this install's own claim (docs/SERVER-ID.md).
/// </summary>
/// <remarks>
/// <para>
/// Guidance, never authority. Nothing here grants trust or wins a conflict: the peer lists in
/// each folder decide who may sync, and the device key proves who is who. A record is kept
/// only when it came from a device its handshake proved, and only from a machine the person
/// said is theirs (<see cref="ServerExchange"/>).
/// </para>
/// <para>
/// Changed under a file lock beside it, so the tray's daemon and a command changing it at the
/// same moment each see the other's change, and written whole, so it is always the old
/// directory or the new one. A file that cannot be read is reported and never guessed at or
/// overwritten; one written by a newer build is read, and never rewritten by this one.
/// </para>
/// </remarks>
public sealed class KnownServers
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "servers.json";

    /// <summary>The schema this build writes.</summary>
    public const int CurrentSchema = 1;

    /// <summary>The most servers the directory keeps; hearsay past this is not taken.</summary>
    public const int MaximumServers = 256;

    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);

    private readonly string _path;
    private readonly object _gate;

    /// <summary>Creates a store over a file.</summary>
    /// <param name="path">Full path to <c>servers.json</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public KnownServers(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        _gate = Gates.GetOrAdd(_path, static _ => new object());
    }

    /// <summary>The store for the person running this process.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static KnownServers ForThisUser() => new(Path.Combine(UserDataDirectory.Resolve(), FileName));

    /// <summary>The file this store reads and writes.</summary>
    public string FilePath => _path;

    /// <summary>Reads the directory.</summary>
    /// <returns>Every server known, with the numbers the rule gives them.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    public ServerDirectory Load()
    {
        lock (_gate)
        {
            var stored = Read();
            return new ServerDirectory(stored.Self, stored.Servers, Numbers(stored));
        }
    }

    /// <summary>This machine's own <c>sippbucket.server/1</c> record, its number settled first.</summary>
    /// <param name="me">This machine.</param>
    /// <param name="nowUtc">The time.</param>
    /// <returns>The record, and anything that changed about this machine's number.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    /// <exception cref="IOException">The file lock could not be taken, or the file written.</exception>
    /// <remarks>
    /// The first call on a new install gives it its first number: 1 when it knows no other
    /// server, the first free one otherwise.
    /// </remarks>
    public (ServerRecord Record, IReadOnlyList<string> Notes) Describe(ServerIdentity me, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(me);

        lock (_gate)
        {
            using var held = Lock();
            var stored = Read();
            var (self, notes) = Settle(stored, me, nowUtc);

            if (self != stored.Self && stored.Schema <= CurrentSchema)
            {
                Write(stored with { Self = self });
            }

            return (RecordOf(me, self, stored.Servers), notes);
        }
    }

    /// <summary>Takes what one of the person's own machines sent about itself and the others.</summary>
    /// <param name="me">This machine.</param>
    /// <param name="senderDeviceId">The device ID the sender's handshake proved.</param>
    /// <param name="message">What it sent.</param>
    /// <param name="nowUtc">The time.</param>
    /// <returns>What changed, and what in the message was refused.</returns>
    /// <exception cref="JsonException">The file cannot be read, so nothing was taken.</exception>
    /// <exception cref="IOException">The file lock could not be taken, or the file written.</exception>
    /// <remarks>
    /// The caller has already decided the sender is the person's own machine; this store never
    /// sees another person's. A record that is malformed or contradicts its sender is refused
    /// whole and named in <see cref="ServerReceipt.Problems"/>, which the health record keeps
    /// as a malformed message.
    /// </remarks>
    public ServerReceipt Receive(ServerIdentity me, string senderDeviceId, ServerExchangeMessage message, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(me);
        ArgumentException.ThrowIfNullOrWhiteSpace(senderDeviceId);
        ArgumentNullException.ThrowIfNull(message);

        var notes = new List<string>();
        var problems = new List<string>();

        lock (_gate)
        {
            using var held = Lock();
            var stored = Read();
            if (stored.Schema > CurrentSchema)
            {
                problems.Add(
                    $"{_path} was written by a newer SippBucket (schema {stored.Schema.ToString(CultureInfo.InvariantCulture)}), " +
                    "which this one would lose information from by rewriting it; the record was not kept");
                return new ServerReceipt(notes, problems);
            }

            var servers = stored.Servers.ToList();

            // The permanent ID rather than the record: comparing against a possibly-null
            // string needs no null test, which is the shape CA1508's flow analysis
            // misjudges when the assignment sits inside a nested condition.
            string? takenPermanent = null;

            if (message.Record is { } record)
            {
                if (ServerRecord.IsAcceptable(record, senderDeviceId, out var problem))
                {
                    TakeRecord(servers, record, SelfReport.IsAcceptable(message.Report) ? message.Report : null, senderDeviceId, nowUtc, notes);
                    takenPermanent = record.Permanent;
                }
                else
                {
                    problems.Add(problem);
                }
            }

            if (message.Others is { } others)
            {
                if (others.Count > ServerExchangeMessage.MaximumOthers)
                {
                    problems.Add(
                        $"it passed on claims for {others.Count} servers, and at most {ServerExchangeMessage.MaximumOthers} are taken");
                }
                else
                {
                    foreach (var entry in others)
                    {
                        if (!ServerClaims.IsAcceptable(entry))
                        {
                            problems.Add("it passed on a malformed number claim");
                            continue;
                        }

                        // Its own record says what its own server is; what it passes on does
                        // not. Equals with a null right side is false, so no record taken
                        // means nothing is skipped.
                        if (string.Equals(entry.Permanent, takenPermanent, StringComparison.Ordinal))
                        {
                            continue;
                        }

                        TakeHearsay(servers, entry, senderDeviceId, me.DeviceId, nowUtc);
                    }
                }
            }

            var updated = stored with { Servers = servers };
            var (self, selfNotes) = Settle(updated, me, nowUtc);
            notes.AddRange(selfNotes);
            Write(updated with { Self = self });
            return new ServerReceipt(notes, problems);
        }
    }

    /// <summary>The number claims to pass on to one of the person's machines.</summary>
    /// <param name="receiverDeviceId">The machine they go to.</param>
    /// <returns>Up to <see cref="ServerExchangeMessage.MaximumOthers"/> servers' claims, those heard from directly first.</returns>
    /// <exception cref="JsonException">The file cannot be read. The message names it.</exception>
    /// <remarks>
    /// A claim the receiver made itself is not sent back to it: its own claim echoed would read
    /// as another install's, and could pull it back to a number it has moved from.
    /// </remarks>
    public IReadOnlyList<ServerClaims> ClaimsFor(string receiverDeviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(receiverDeviceId);

        var directory = Load();
        return directory.Servers
            .OrderBy(server => server.HeardFrom is null ? 0 : 1)
            .ThenByDescending(server => server.LastSeen ?? DateTimeOffset.MinValue)
            .Select(server => new ServerClaims
            {
                Permanent = server.Permanent,
                Label = server.Label,
                Claims = [.. server.Claims
                    .Where(claim => !SameDevice(claim.Device, receiverDeviceId))
                    .Select(claim => new NumberClaim(claim.Device, claim.Number, claim.Numbered))],
            })
            .Where(entry => entry.Claims.Count > 0)
            .Take(ServerExchangeMessage.MaximumOthers)
            .ToList();
    }

    /// <summary>The numbers the rule gives every server in a stored directory, this install's own included.</summary>
    internal static IReadOnlyDictionary<string, int> Numbers(StoredServers stored)
    {
        var servers = new Dictionary<string, IReadOnlyList<NumberClaim>>(StringComparer.Ordinal);
        foreach (var server in stored.Servers)
        {
            servers[server.Permanent] = [.. server.Claims.Select(claim => new NumberClaim(claim.Device, claim.Number, claim.Numbered))];
        }

        if (stored.Self is { } self)
        {
            var own = servers.TryGetValue(self.Permanent, out var known)
                ? known.Where(claim => !SameDevice(claim.Device, self.Device)).ToList()
                : [];

            if (self.Number > 0 && self.Numbered is { } numbered)
            {
                own.Add(new NumberClaim(self.Device, self.Number, numbered));
            }

            servers[self.Permanent] = own;
        }

        return ServerNumbering.Resolve(servers);
    }

    /// <summary>
    /// Brings this install's own part up to date: a new install, a new device key or a new
    /// permanent ID, and the number the rule now gives it.
    /// </summary>
    private static (ThisInstall Self, IReadOnlyList<string> Notes) Settle(StoredServers stored, ServerIdentity me, DateTimeOffset now)
    {
        var notes = new List<string>();
        var self = stored.Self;

        if (self is null || !SameDevice(self.Device, me.DeviceId))
        {
            // A new install, or a new device key in the same data folder, which is a new
            // install to every other machine: it starts with no claim of its own.
            self = new ThisInstall { Device = me.DeviceId, Permanent = me.Permanent.Hex, FirstSeen = now };
        }

        if (!string.Equals(self.Permanent, me.Permanent.Hex, StringComparison.Ordinal))
        {
            notes.Add(
                $"this machine's Server.ID is now {me.Permanent.Fingerprint}: {me.Permanent.Explanation}. A new board, " +
                "or firmware that now gives a real serial number or UUID, changes it; the device key is unchanged");
            self = self with { Permanent = me.Permanent.Hex };
        }

        self = self with { Label = me.Label };

        var resolved = Numbers(stored with { Self = self })[self.Permanent];
        if (resolved != self.Number)
        {
            var board = stored.Servers.FirstOrDefault(server => string.Equals(server.Permanent, self.Permanent, StringComparison.Ordinal));
            var group = (board?.Claims ?? [])
                .Where(claim => !SameDevice(claim.Device, self.Device))
                .Select(claim => new NumberClaim(claim.Device, claim.Number, claim.Numbered))
                .ToList();
            var earliest = ServerNumbering.Earliest(group);

            // The board's number comes from another install when that install claimed before
            // this one: this install then takes whatever the board resolves to.
            var fromBoard = earliest is not null && (self.Numbered is not { } own || earliest.Numbered < own);
            notes.Add(self.Number == 0
                ? $"this machine is Server {resolved}"
                : fromBoard
                    ? $"this machine is now Server {resolved}, the number its board already has from its other install"
                    : $"this machine is now Server {resolved}: another of your servers took Server {self.Number} first");

            // A claim adopted as it stands keeps its time; a number taken because of a clash is
            // taken now, so it never outranks a machine that already held it.
            var numbered = earliest is not null && earliest.Number == resolved ? earliest.Numbered : now;
            self = self with { Number = resolved, Numbered = numbered };
        }

        return (self, notes);
    }

    private static ServerRecord RecordOf(ServerIdentity me, ThisInstall self, IReadOnlyList<KnownServer> servers)
    {
        var board = servers.FirstOrDefault(server => string.Equals(server.Permanent, me.Permanent.Hex, StringComparison.Ordinal));
        var installs = new List<ServerInstall>
        {
            new() { Device = me.DeviceId, Windows = me.Windows, FirstSeen = self.FirstSeen },
        };

        installs.AddRange((board?.Installs ?? [])
            .Where(install => !SameDevice(install.Device, me.DeviceId))
            .Take(ServerRecord.MaximumInstalls - 1));

        return new ServerRecord
        {
            Schema = ServerRecord.CurrentSchema,
            Id = me.Permanent.Fingerprint.ToString(),
            Permanent = me.Permanent.Hex,
            Source = PermanentId.WireName(me.Permanent.Source),
            Number = self.Number,
            Numbered = self.Number > 0 ? self.Numbered : null,
            Label = me.Label,
            Installs = installs,
            Run = RunId.Current,
            Started = RunId.Started,
            Version = BuildVersion.Current,
            Protocol = ChannelWire.ProtocolVersion,
        };
    }

    private static void TakeRecord(
        List<KnownServer> servers,
        ServerRecord record,
        SelfReport? report,
        string sender,
        DateTimeOffset now,
        List<string> notes)
    {
        DateTimeOffset? carriedFirstPaired = null;

        // The sending install may have been known under another permanent ID: a new board, or
        // firmware that now gives a real value. It belongs to the one its record names now.
        for (var i = servers.Count - 1; i >= 0; i--)
        {
            var other = servers[i];
            if (string.Equals(other.Permanent, record.Permanent, StringComparison.Ordinal) ||
                (!other.Installs.Any(install => SameDevice(install.Device, sender)) &&
                 !other.Claims.Any(claim => SameDevice(claim.Device, sender))))
            {
                continue;
            }

            var remaining = other with
            {
                Installs = [.. other.Installs.Where(install => !SameDevice(install.Device, sender))],
                Claims = [.. other.Claims.Where(claim => !SameDevice(claim.Device, sender))],
            };

            if (remaining.Installs.Count == 0)
            {
                servers.RemoveAt(i);
                carriedFirstPaired ??= other.FirstPaired;
                notes.Add(
                    $"install {Short(sender)} now reports {record.Id} where it reported {other.Id}: a new board, or " +
                    "firmware that now gives a real serial number or UUID");
            }
            else
            {
                servers[i] = remaining;
            }
        }

        var index = servers.FindIndex(server => string.Equals(server.Permanent, record.Permanent, StringComparison.Ordinal));
        var existing = index < 0 ? null : servers[index];

        if (existing is { Installs.Count: > 0 } known && !known.Installs.Any(install => SameDevice(install.Device, sender)))
        {
            var windows = record.Installs.FirstOrDefault(install => SameDevice(install.Device, sender))?.Windows;
            notes.Add(
                $"{Name(known)} has another install, {Short(sender)}{(windows is null ? string.Empty : $" ({windows})")}, on the " +
                $"board {known.Id} names, where {string.Join(", ", known.Installs.Select(install => Short(install.Device)))} " +
                $"{(known.Installs.Count == 1 ? "was" : "were")} " +
                (known.LastSeen is { } last ? $"last heard from {last.ToUniversalTime():yyyy-MM-dd HH:mm} UTC" : "known") +
                ". It looks like the same machine reinstalled, or its other Windows: it was paired as a new install, " +
                "and keeps the board's number and history");
        }
        else if (existing is { Run: { } run, RunFrom: { } runFrom } &&
                 SameDevice(runFrom, sender) &&
                 !string.Equals(run, record.Run, StringComparison.Ordinal))
        {
            notes.Add($"{Name(existing)} restarted since it was last heard from");
        }

        var installs = record.Installs.ToList();
        installs.AddRange((existing?.Installs ?? [])
            .Where(install => !installs.Any(listed => SameDevice(listed.Device, install.Device)))
            .Take(ServerRecord.MaximumInstalls - installs.Count));

        var claims = (existing?.Claims ?? []).Where(claim => !SameDevice(claim.Device, sender)).ToList();
        if (record.Number > 0 && record.Numbered is { } numbered)
        {
            claims.Add(new HeardClaim { Device = sender, Number = record.Number, Numbered = numbered, Direct = true, HeardUtc = now });
        }

        var updated = new KnownServer
        {
            Permanent = record.Permanent,
            Id = record.Id,
            Source = record.Source,
            Label = record.Label,
            Installs = installs,
            Claims = claims,
            Run = record.Run,
            Started = record.Started,
            RunFrom = sender,
            Version = record.Version,
            Protocol = record.Protocol,
            Report = report,
            FirstPaired = existing?.FirstPaired ?? carriedFirstPaired ?? now,
            LastSeen = now,
            HeardFrom = null,
        };

        if (index < 0)
        {
            servers.Add(updated);
        }
        else
        {
            servers[index] = updated;
        }
    }

    private static void TakeHearsay(List<KnownServer> servers, ServerClaims entry, string sender, string me, DateTimeOffset now)
    {
        // This install's own claims, passed back, are not news about anyone.
        var relayed = entry.Claims.Where(claim => !SameDevice(claim.Device, me)).ToList();
        if (relayed.Count == 0)
        {
            return;
        }

        var index = servers.FindIndex(server => string.Equals(server.Permanent, entry.Permanent, StringComparison.Ordinal));
        var existing = index < 0 ? null : servers[index];
        if (existing is null && servers.Count >= MaximumServers)
        {
            return;
        }

        var claims = (existing?.Claims ?? []).ToList();
        foreach (var claim in relayed)
        {
            var heard = new HeardClaim { Device = claim.Device, Number = claim.Number, Numbered = claim.Numbered, Direct = false, HeardUtc = now };
            var at = claims.FindIndex(known => SameDevice(known.Device, claim.Device));
            if (at < 0)
            {
                claims.Add(heard);
            }
            else if (!claims[at].Direct)
            {
                // A claim heard from the install itself outranks one passed on.
                claims[at] = heard;
            }
        }

        var installs = (existing?.Installs ?? []).ToList();
        installs.AddRange(relayed
            .Where(claim => !installs.Any(install => SameDevice(install.Device, claim.Device)))
            .Select(claim => new ServerInstall { Device = claim.Device })
            .Take(Math.Max(0, ServerRecord.MaximumInstalls - installs.Count)));

        var updated = existing is null
            ? new KnownServer
            {
                Permanent = entry.Permanent,
                Id = ServerId.FromPermanent(Convert.FromHexString(entry.Permanent)).ToString(),
                Label = entry.Label,
                Installs = installs,
                Claims = claims,
                HeardFrom = sender,
            }
            : existing with
            {
                Installs = installs,
                Claims = claims,
                Label = existing.HeardFrom is null ? existing.Label : entry.Label ?? existing.Label,
                HeardFrom = existing.HeardFrom is null ? null : sender,
            };

        if (index < 0)
        {
            servers.Add(updated);
        }
        else
        {
            servers[index] = updated;
        }
    }

    private static string Name(KnownServer server) =>
        server.Label is null ? server.Id : $"{server.Id} ({server.Label})";

    private static string Short(string deviceId) => deviceId[..Math.Min(12, deviceId.Length)];

    private static bool SameDevice(string? left, string? right) =>
        left is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private FileLock Lock()
    {
        var directory = Path.GetDirectoryName(_path) ?? throw new IOException($"{_path} has no folder.");
        Directory.CreateDirectory(directory);
        return FileLock.Acquire(_path + ".lock", FileLock.DefaultPatience);
    }

    private StoredServers Read()
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(_path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return StoredServers.Empty;
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return StoredServers.Empty;
        }

        StoredServers? file;
        try
        {
            file = JsonSerializer.Deserialize<StoredServers>(json, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new JsonException(
                $"{_path} cannot be read ({ex.Message}). Until it is mended or deleted, Server.ID records are not kept " +
                "and nothing is written to it; syncing is not affected.",
                ex);
        }

        if (file?.Servers is null)
        {
            throw new JsonException(
                $"{_path} holds no list of servers. Until it is mended or deleted, Server.ID records are not kept " +
                "and nothing is written to it; syncing is not affected.");
        }

        return file;
    }

    private void Write(StoredServers stored)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(stored with { Schema = CurrentSchema }, SipJson.Readable);

        // Written beside the file and swapped in whole, as machines.json is.
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);

            if (File.Exists(_path))
            {
                SharingRetry.Run(() => File.Replace(temporary, _path, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, _path));
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }
}

/// <summary><c>servers.json</c> as stored.</summary>
/// <param name="Schema">The schema it was written in.</param>
/// <param name="Self">This install's own part, or null before its first record.</param>
/// <param name="Servers">Every other server known.</param>
internal sealed record StoredServers(int Schema, ThisInstall? Self, IReadOnlyList<KnownServer> Servers)
{
    /// <summary>The directory before anything is known.</summary>
    public static StoredServers Empty { get; } = new(KnownServers.CurrentSchema, null, []);
}
