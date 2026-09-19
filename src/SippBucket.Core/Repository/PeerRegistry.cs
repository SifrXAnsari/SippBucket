using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>
/// Reads and writes the peer list in <c>.sip/peers.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// The file is meant to be edited by hand, so one bad record must not take the others down
/// with it (D-65). Each record is read on its own. One whose device ID is not
/// <see cref="DeviceIdLength"/> hexadecimal characters, which has no name, or which cannot be
/// read as a peer at all is <em>skipped</em>: <see cref="Load"/> leaves it out, so nothing
/// syncs with it, trusts it or shows it as a machine, and <see cref="Inspect"/> reports it
/// with its position and the reason. It used to reach <c>sip peer list</c>, which sliced the
/// device ID, and <see cref="Remove"/>, which called <c>StartsWith</c> on it, and a null or
/// short ID threw from both, including from the command that would have removed it.
/// </para>
/// <para>
/// A skipped record stays in the file. Reading never writes, and a write made for another
/// reason (adding, removing, recording a sync) puts every skipped record back in its place
/// with what it held, an element that could not be read as a peer at all included, so the
/// person who made the typo finds it where they left it. Only the whitespace is the
/// writer's. <see cref="Remove"/> can remove one by its name.
/// </para>
/// </remarks>
public sealed class PeerRegistry
{
    /// <summary>
    /// The shortest device-ID prefix <see cref="Remove"/> accepts in place of a full ID.
    /// </summary>
    /// <remarks>
    /// Eight hex characters, 32 bits: enough that two of one person's machines sharing a
    /// prefix would be a coincidence, and short enough to type. <c>sip peer list</c> prints
    /// twelve. A shorter argument is matched against names only.
    /// </remarks>
    public const int MinimumDeviceIdPrefixLength = 8;

    /// <summary>Length of a device ID: a 32-byte Ed25519 public key, as hex.</summary>
    public const int DeviceIdLength = 64;

    /// <summary>One gate per peers file, shared by every registry over it in this process.</summary>
    /// <remarks>
    /// The daemon's server reads this file on every incoming connection, to decide whether
    /// the caller is a known device, while its sync engine rewrites it after every poll.
    /// Windows refuses a read while a writer holds the file — the reader asks to share
    /// reading only — so without the gate the other machine's connection was dropped part
    /// way through its handshake whenever the two coincided. Found by the test in which both
    /// machines sync each other at once. The gate cannot order another process: a brief hold
    /// by one, such as a scanner reading the file just written, is waited out by
    /// <see cref="SharingRetry"/>, and a longer one is reported, as it always was. The
    /// folder's <see cref="OperationLock"/> does not replace it: that lock orders whole
    /// operations that write the working folder or head, and the server's read of this file
    /// on every connection deliberately takes no part in it.
    /// </remarks>
    private static readonly ConcurrentDictionary<string, object> Gates =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly string _path;
    private readonly object _gate;

    /// <summary>Creates a registry over a peers file.</summary>
    /// <param name="peersFilePath">Full path to <c>peers.json</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public PeerRegistry(string peersFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peersFilePath);
        _path = peersFilePath;
        _gate = Gates.GetOrAdd(Path.GetFullPath(peersFilePath), static _ => new object());
    }

    /// <summary>The file this registry reads and writes.</summary>
    public string FilePath => _path;

    /// <summary>Loads every peer that can be used.</summary>
    /// <returns>
    /// The usable peers in file order, empty when the file does not exist yet. Records that
    /// cannot be used are left out; <see cref="Inspect"/> lists them.
    /// </returns>
    /// <exception cref="JsonException">
    /// The file is not valid JSON, or not a list. The message names the file, and the line
    /// for a syntax error.
    /// </exception>
    public IReadOnlyList<PeerRecord> Load() => Inspect().Usable;

    /// <summary>Reads every record in the file, usable or not.</summary>
    /// <returns>The usable peers, and the skipped records with where they are and why.</returns>
    /// <exception cref="JsonException">
    /// The file is not valid JSON, or not a list. A damaged record is reported, not thrown; a
    /// file whose records cannot be told apart has none to report. The message names the
    /// file, and the line for a syntax error.
    /// </exception>
    /// <remarks>Reads only. The file is never rewritten because it was read.</remarks>
    public PeerList Inspect()
    {
        var stored = Read();

        return new PeerList
        {
            Usable = [.. stored.Where(p => p.Problem is null).Select(p => p.Record!)],
            Skipped = [.. stored.Where(p => p.Problem is not null).Select(p => new SkippedPeerRecord
            {
                Position = p.Position,
                Problem = p.Problem!.Value,
                Name = p.Name,
                DeviceId = p.DeviceId,
                Detail = p.Detail,
            })],
        };
    }

    /// <summary>Replaces the stored peer list.</summary>
    /// <param name="peers">The peers to write.</param>
    /// <exception cref="ArgumentNullException"><paramref name="peers"/> was null.</exception>
    public void Save(IReadOnlyList<PeerRecord> peers)
    {
        ArgumentNullException.ThrowIfNull(peers);
        Write([.. peers.Select((peer, index) => StoredPeer.Of(peer, index + 1))]);
    }

    /// <summary>Adds a peer, replacing any existing entry with the same device ID.</summary>
    /// <param name="peer">The peer to add.</param>
    /// <exception cref="ArgumentNullException"><paramref name="peer"/> was null.</exception>
    /// <remarks>
    /// Behaves exactly as <see cref="AddOrReplace"/> does, without saying what it replaced.
    /// Pairing, joining and <c>sip peer add</c> all call <see cref="AddOrReplace"/> and say
    /// what they replaced (D-25, D-64); this remains for callers with nothing to say.
    /// </remarks>
    public void Add(PeerRecord peer) => _ = AddOrReplace(peer);

    /// <summary>
    /// Adds a peer, replacing any existing entry with the same device ID, and returns the
    /// entry it replaced.
    /// </summary>
    /// <param name="peer">The peer to add.</param>
    /// <returns>The record that was replaced, or null when the device was not listed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="peer"/> was null.</exception>
    /// <remarks>
    /// <para>
    /// Replacing is right: the device ID is the identity, so there is one record per
    /// device. But the replacement used to be silent, so re-pairing a machine or adding it
    /// again by hand overwrote the name, host and port somebody had chosen, and left no
    /// trace of what they had been (D-25). Returning the old record lets the caller say
    /// what it just replaced.
    /// </para>
    /// <para>
    /// The new record takes the old one's place in the list rather than moving to the end.
    /// When the new record has no <see cref="PeerRecord.LastSyncedUtc"/>, the old value
    /// carries over. It records when this device last synced, and a new label or address
    /// does not make that untrue. A value the caller does supply wins.
    /// </para>
    /// <para>
    /// If <c>peers.json</c> lists the device more than once, which only a hand edit can
    /// cause, the later records are dropped and the first is the one returned. A skipped
    /// record for the same device, one with no name for instance, is replaced like any other,
    /// which is how pairing the machine again repairs it. Every other skipped record is
    /// written back where it was.
    /// </para>
    /// </remarks>
    public PeerRecord? AddOrReplace(PeerRecord peer)
    {
        ArgumentNullException.ThrowIfNull(peer);

        // Read and write under one hold of the gate, so the daemon recording a sync between
        // the two cannot be lost, or lose this change. The gate is a monitor, so the reads and
        // writes inside take it again without blocking.
        lock (_gate)
        {
            var peers = new List<StoredPeer>();
            PeerRecord? replaced = null;

            foreach (var existing in Read())
            {
                if (existing.Record is null || !SameDevice(existing.DeviceId, peer.DeviceId))
                {
                    peers.Add(existing);
                }
                else if (replaced is null)
                {
                    replaced = existing.Record;
                    peers.Add(StoredPeer.Of(
                        peer.LastSyncedUtc is null
                            ? peer with { LastSyncedUtc = existing.Record.LastSyncedUtc }
                            : peer,
                        existing.Position));
                }
            }

            if (replaced is null)
            {
                peers.Add(StoredPeer.Of(peer, peers.Count + 1));
            }

            Write(peers);
            return replaced;
        }
    }

    /// <summary>Records when a peer was last synced with successfully.</summary>
    /// <param name="deviceId">The peer's device ID. Matched exactly, ignoring case.</param>
    /// <param name="syncedUtc">When the sync finished.</param>
    /// <returns>True when a registered peer carried that device ID and was updated.</returns>
    /// <exception cref="ArgumentException"><paramref name="deviceId"/> was null or blank.</exception>
    /// <exception cref="IOException">
    /// Another process kept the peer list open for longer than <see cref="SharingRetry.Patience"/>.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Matched by device ID and never by name, because names are labels and two machines can
    /// share one (D-25), while the device ID is the key a sync actually authenticated.
    /// </para>
    /// <para>
    /// The daemon calls this after every successful poll, so unlike <see cref="Add"/> it
    /// reads and rewrites the file through one handle that no other process may open
    /// meanwhile. Read-then-save would open a window in which a peer added by
    /// <c>sip pair</c> in another process is read out and written back without it —
    /// silently un-pairing a machine to record a timestamp. With the handle held, that other
    /// process's read or write meets a sharing violation instead, waits briefly, and reports
    /// it rather than losing the peer. Asking to share nothing also means any other handle
    /// at all refuses this open, so it waits out a brief hold the same way
    /// (<see cref="SharingRetry"/>). The reverse order — another process reading before this
    /// and saving after — can still overwrite the timestamp, which the next poll writes
    /// again. Within this process the gate orders it against every other read and write.
    /// The new contents are written over the old from the start before the file is cut to
    /// length, so a crash mid-write leaves JSON that fails loudly rather than an empty file
    /// that would read as "no peers". Skipped records are written back as they were.
    /// </para>
    /// </remarks>
    public bool RecordSync(string deviceId, DateTimeOffset syncedUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        lock (_gate)
        {
            return SharingRetry.Run(() => RecordSyncLocked(deviceId, syncedUtc));
        }
    }

    private bool RecordSyncLocked(string deviceId, DateTimeOffset syncedUtc)
    {
        if (!File.Exists(_path))
        {
            return false;
        }

        using var file = new FileStream(_path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var existing = new byte[file.Length];
        file.ReadExactly(existing);

        var peers = Parse(existing);

        var updated = false;
        for (var i = 0; i < peers.Count; i++)
        {
            if (peers[i].Record is { } record && SameDevice(record.DeviceId, deviceId))
            {
                peers[i] = StoredPeer.Of(record with { LastSyncedUtc = syncedUtc }, peers[i].Position);
                updated = true;
            }
        }

        if (!updated)
        {
            return false;
        }

        var replacement = Serialize(peers);
        file.Position = 0;
        file.Write(replacement);
        file.SetLength(replacement.Length);
        file.Flush(flushToDisk: true);
        return true;
    }

    /// <summary>Removes one peer, named by device ID, device-ID prefix or name.</summary>
    /// <param name="deviceIdOrName">
    /// A full device ID, a unique device-ID prefix of at least
    /// <see cref="MinimumDeviceIdPrefixLength"/> hex characters, or a peer's name.
    /// </param>
    /// <returns>Whether a peer was removed, nothing matched, or the argument was ambiguous.</returns>
    /// <remarks>
    /// <para>
    /// This used to delete every peer whose device ID <em>or</em> name matched (D-25).
    /// Names are not unique: pairing names a joining machine after its own host name, so
    /// two machines can easily arrive with the same one, and removing "desktop" removed
    /// every desktop. A name is a label for a person to type, not an identity.
    /// </para>
    /// <para>
    /// So the argument has to resolve to exactly one device. A full 64-character device ID,
    /// in either case, names that device and nothing else, even if some other peer has
    /// been given that string as its name. Otherwise the argument is compared with every
    /// name, ignoring case, and, when it is at least
    /// <see cref="MinimumDeviceIdPrefixLength"/> hex characters, with the start of every
    /// device ID. It counts only if everything it matches is one device. When it matches
    /// more than one, nothing is changed and every candidate is returned, so the caller
    /// can show them and ask for a device ID. Refusing costs the user one more command.
    /// Guessing wrong revokes a machine they meant to keep.
    /// </para>
    /// <para>
    /// A skipped record is matched the same way, and also by its device ID typed exactly as
    /// it is written, however short. It is not a device, so it counts as one on its own:
    /// removing it removes that record and nothing else (D-65).
    /// </para>
    /// </remarks>
    public PeerRemoval Remove(string deviceIdOrName)
    {
        if (string.IsNullOrWhiteSpace(deviceIdOrName))
        {
            return new PeerRemoval { Outcome = PeerRemovalOutcome.NotFound };
        }

        // One hold of the gate across the read and the write, as in AddOrReplace.
        lock (_gate)
        {
            var peers = Read();
            var matched = Match(peers, deviceIdOrName);
            var devices = matched.DistinctBy(TrustKey, StringComparer.Ordinal).ToList();

            if (devices.Count == 0)
            {
                return new PeerRemoval { Outcome = PeerRemovalOutcome.NotFound };
            }

            if (devices.Count > 1)
            {
                return new PeerRemoval
                {
                    Outcome = PeerRemovalOutcome.Ambiguous,
                    Candidates = [.. devices.Select(p => p.AsRecord())],
                };
            }

            // Every record for the device, not only the one that matched: removing a peer
            // revokes the device's trust, and a duplicate left behind would keep it trusted.
            var key = TrustKey(devices[0]);
            var removed = peers.Where(p => TrustKey(p) == key).Select(p => p.AsRecord()).ToList();

            Write([.. peers.Where(p => TrustKey(p) != key)]);

            return new PeerRemoval
            {
                Outcome = PeerRemovalOutcome.Removed,
                Removed = removed,
            };
        }
    }

    /// <summary>Finds one usable peer, named the way <see cref="Remove"/> names one.</summary>
    /// <param name="deviceIdOrName">
    /// A full device ID, a unique device-ID prefix of at least
    /// <see cref="MinimumDeviceIdPrefixLength"/> hex characters, or a peer's name.
    /// </param>
    /// <returns>The one machine it names, or why it names none.</returns>
    /// <remarks>
    /// The rule <see cref="Remove"/> applies, without the write: the argument counts only when
    /// everything it matches is one device. A skipped record is not a machine, so it is never
    /// found. Reads only.
    /// </remarks>
    public PeerLookup Find(string deviceIdOrName)
    {
        if (string.IsNullOrWhiteSpace(deviceIdOrName))
        {
            return new PeerLookup { Outcome = PeerLookupOutcome.NotFound };
        }

        var usable = Read().Where(p => p.Problem is null).ToList();
        var devices = Match(usable, deviceIdOrName).DistinctBy(TrustKey, StringComparer.Ordinal).ToList();

        return devices.Count switch
        {
            0 => new PeerLookup { Outcome = PeerLookupOutcome.NotFound },
            1 => new PeerLookup { Outcome = PeerLookupOutcome.Found, Peer = devices[0].Record },
            _ => new PeerLookup
            {
                Outcome = PeerLookupOutcome.Ambiguous,
                Candidates = [.. devices.Select(p => p.AsRecord())],
            },
        };
    }

    /// <summary>Whether a string is a well-formed device ID: 64 hexadecimal characters.</summary>
    /// <param name="deviceId">The candidate.</param>
    /// <returns>True when it is.</returns>
    /// <remarks>
    /// The shape only. Whether the 32 bytes are a valid Ed25519 point is for the handshake
    /// to find out; this is what every reader of the peer list relies on, a string it can
    /// slice and compare.
    /// </remarks>
    public static bool IsWellFormedDeviceId(string? deviceId) =>
        deviceId is { Length: DeviceIdLength } && deviceId.All(char.IsAsciiHexDigit);

    private static List<StoredPeer> Match(IReadOnlyList<StoredPeer> peers, string argument)
    {
        var isHex = argument.All(char.IsAsciiHexDigit);

        if (isHex && argument.Length == DeviceIdLength)
        {
            var exact = peers.Where(p => SameDevice(p.DeviceId, argument)).ToList();
            if (exact.Count > 0)
            {
                return exact;
            }
        }

        var byPrefix = isHex && argument.Length >= MinimumDeviceIdPrefixLength;

        return peers
            .Where(p =>
                string.Equals(p.Name, argument, StringComparison.OrdinalIgnoreCase) ||
                SameDevice(p.DeviceId, argument) ||
                (byPrefix && p.DeviceId is not null &&
                 p.DeviceId.StartsWith(argument, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    /// <summary>
    /// What a removal revokes: a device, for a well-formed ID, and otherwise the one record.
    /// </summary>
    /// <remarks>
    /// Two skipped records with no device ID are two separate typos, not one device, so
    /// removing one by its name must not take the other with it.
    /// </remarks>
    private static string TrustKey(StoredPeer peer) =>
        IsWellFormedDeviceId(peer.DeviceId)
            ? peer.DeviceId!.ToUpperInvariant()
            : $"record {peer.Position}";

    private static bool SameDevice(string? left, string? right) =>
        left is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    /// <summary>Why a record that was read as a peer cannot be used, or null when it can.</summary>
    private static PeerRecordProblem? ProblemWith(PeerRecord record) =>
        record.DeviceId is null ? PeerRecordProblem.MissingDeviceId
        : !IsWellFormedDeviceId(record.DeviceId) ? PeerRecordProblem.MalformedDeviceId
        : record.Name is null ? PeerRecordProblem.MissingName
        : null;

    private List<StoredPeer> Read()
    {
        lock (_gate)
        {
            if (!File.Exists(_path))
            {
                return [];
            }

            return Parse(SharingRetry.Run(() => File.ReadAllBytes(_path)));
        }
    }

    private void Write(IReadOnlyList<StoredPeer> peers)
    {
        lock (_gate)
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var bytes = Serialize(peers);
            SharingRetry.Run(() => File.WriteAllBytes(_path, bytes));
        }
    }

    /// <summary>Reads the file's records one at a time, so one bad record costs only itself.</summary>
    private List<StoredPeer> Parse(byte[] content)
    {
        // A UTF-8 byte order mark, which Notepad has written in front of UTF-8 files for most
        // of its life and which the JSON reader refuses. The file is meant to be hand-edited.
        ReadOnlyMemory<byte> json = content.AsSpan().StartsWith(Utf8Bom) ? content.AsMemory(Utf8Bom.Length) : content;

        if (json.Span.IndexOfAnyExcept(" \t\r\n"u8) < 0)
        {
            return [];
        }

        using var document = ParseDocument(json);
        var root = document.RootElement;

        if (root.ValueKind == JsonValueKind.Null)
        {
            return [];
        }

        if (root.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException(
                $"{_path} should hold a list of peers in square brackets, and it holds a JSON " +
                $"{root.ValueKind.ToString().ToUpperInvariant()} instead.");
        }

        var peers = new List<StoredPeer>();
        var position = 0;

        foreach (var element in root.EnumerateArray())
        {
            position++;

            PeerRecord? record = null;
            string? failure = null;

            try
            {
                record = element.Deserialize<PeerRecord>(SipJson.Readable);
            }
            catch (JsonException ex)
            {
                failure = ex.Message;
            }

            peers.Add(record is null
                ? StoredPeer.Unreadable(element, position, failure ?? "it is null")
                : StoredPeer.Of(record, position));
        }

        return peers;
    }

    /// <summary>Parses the file as JSON, or says which file is broken and where.</summary>
    /// <remarks>
    /// <para>
    /// A syntax error is not a bad record: with a comma missing between two records, the
    /// reader cannot tell where either ends, so there are no records to skip and none can be
    /// removed by command. What can be done is to say which file and which line, so the person
    /// can mend it. The reader's own message gave neither the file nor a line a person would
    /// count to: its <see cref="JsonException.LineNumber"/> is "the zero-based number of lines
    /// read before the exception"
    /// (https://learn.microsoft.com/en-us/dotnet/api/system.text.json.jsonexception.linenumber),
    /// so the line here is one more than that.
    /// </para>
    /// <para>
    /// Still a <see cref="JsonException"/>, which every caller already handles. Nothing is
    /// written: the file is left exactly as the person left it.
    /// </para>
    /// </remarks>
    private JsonDocument ParseDocument(ReadOnlyMemory<byte> json)
    {
        try
        {
            return JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            var where = ex.LineNumber is { } line
                ? string.Create(CultureInfo.InvariantCulture, $" at line {line + 1}")
                : string.Empty;

            throw new JsonException(
                $"{_path} is not valid JSON{where}, so none of its peers can be read and none " +
                $"can be removed by command. It was not changed. Correct it by hand. ({ex.Message})",
                ex.Path,
                ex.LineNumber,
                ex.BytePositionInLine,
                ex);
        }
    }

    private static byte[] Serialize(IReadOnlyList<StoredPeer> peers)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
                   buffer,
                   new JsonWriterOptions { Indented = SipJson.Readable.WriteIndented, Encoder = SipJson.Readable.Encoder }))
        {
            writer.WriteStartArray();

            foreach (var peer in peers)
            {
                if (peer.Record is { } record)
                {
                    JsonSerializer.Serialize(writer, record, SipJson.Readable);
                }
                else
                {
                    peer.Raw.WriteTo(writer);
                }
            }

            writer.WriteEndArray();
        }

        return buffer.ToArray();
    }

    private static ReadOnlySpan<byte> Utf8Bom => [0xEF, 0xBB, 0xBF];

    /// <summary>One element of the file's list, as read.</summary>
    private sealed record StoredPeer
    {
        /// <summary>Where it is in the file, counting from 1.</summary>
        public required int Position { get; init; }

        /// <summary>The record, or null when the element could not be read as a peer.</summary>
        public PeerRecord? Record { get; init; }

        /// <summary>The element as written, kept for an unreadable one so it is written back.</summary>
        public JsonElement Raw { get; init; }

        public string? Name { get; init; }

        public string? DeviceId { get; init; }

        public PeerRecordProblem? Problem { get; init; }

        public string? Detail { get; init; }

        public static StoredPeer Of(PeerRecord record, int position) => new()
        {
            Position = position,
            Record = record,
            Name = record.Name,
            DeviceId = record.DeviceId,
            Problem = ProblemWith(record),
        };

        /// <summary>
        /// An element that is not a peer. Its name and device ID are still read where they are
        /// strings, so it can be reported, and removed, by what the person typed.
        /// </summary>
        public static StoredPeer Unreadable(JsonElement element, int position, string detail) => new()
        {
            Position = position,
            Raw = element.Clone(),
            Name = StringProperty(element, nameof(PeerRecord.Name)),
            DeviceId = StringProperty(element, nameof(PeerRecord.DeviceId)),
            Problem = PeerRecordProblem.Unreadable,
            Detail = detail,
        };

        /// <summary>The record, or as much of one as could be read, for reporting a removal.</summary>
        /// <remarks>
        /// For an unreadable element the fields that could not be read are null, whatever
        /// their declared types say. That is what a hand-edited file can hold, and every
        /// caller that prints a removal already has to cope with it.
        /// </remarks>
        public PeerRecord AsRecord() => Record ?? new PeerRecord
        {
            DeviceId = DeviceId!,
            Name = Name!,
            Host = StringProperty(Raw, nameof(PeerRecord.Host))!,
            Port = 0,
        };

        private static string? StringProperty(JsonElement element, string name)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase) &&
                    property.Value.ValueKind == JsonValueKind.String)
                {
                    return property.Value.GetString();
                }
            }

            return null;
        }
    }
}
