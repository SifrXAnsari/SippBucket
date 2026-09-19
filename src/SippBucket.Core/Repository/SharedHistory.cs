using System.Collections.Concurrent;
using System.Text.Json;
using SippBucket.Core.Hashing;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>
/// What this replica last knew it shared with each peer: the newest snapshot both sides hold,
/// kept as a merge base, and the peer's head when they last synced. <c>.sip/shared</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why it exists (D-55).</b> Simple mode keeps one snapshot. Two Simple replicas that
/// diverge have both trimmed the snapshot they last agreed on, so their merge had no base: it
/// was two-way, which never deletes and keeps both versions of anything that differs. A file
/// deleted on one machine came back from the other. The shared snapshot named here is kept,
/// file list and all, until a newer shared one replaces it, so such a merge is three-way.
/// </para>
/// <para>
/// <b>Why the peer's head too (D-54).</b> Compacting <c>.sip/ancestry</c> keeps the history a
/// sync decision can need, and a peer's last known head is where the decisions about that
/// peer start from. See <see cref="SipRepository.CompactAncestry"/>.
/// </para>
/// <para>
/// Plain JSON, readable, keyed by device ID. It holds peers' device IDs, which
/// <c>peers.json</c> beside it already holds in the clear, and snapshot IDs, which are the file
/// names in <c>.sip/snapshots</c>. It is rewritten only when a mark changes, which is after a
/// sync that moved something, not after every poll.
/// </para>
/// <para>
/// A file that cannot be parsed reads as empty rather than failing a sync: every mark in it is
/// an optimisation, and without one the next merge with that peer is two-way, which keeps
/// both versions. The next sync writes it afresh.
/// </para>
/// </remarks>
public sealed class SharedHistory
{
    /// <summary>One gate per file, shared by every instance over it in this process.</summary>
    private static readonly ConcurrentDictionary<string, object> Gates =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly string _path;
    private readonly object _gate;

    /// <summary>Creates the store over a file.</summary>
    /// <param name="path">Full path to <c>.sip/shared</c>.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public SharedHistory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
        _gate = Gates.GetOrAdd(Path.GetFullPath(path), static _ => new object());
    }

    /// <summary>Every mark, keyed by the peer's device ID.</summary>
    /// <returns>The marks; empty when there are none or the file cannot be read as marks.</returns>
    public IReadOnlyDictionary<string, SharedMark> Load()
    {
        lock (_gate)
        {
            return LoadLocked();
        }
    }

    /// <summary>
    /// Records what a successful sync with a peer established.
    /// </summary>
    /// <param name="deviceId">The peer's device ID.</param>
    /// <param name="shared">
    /// A snapshot both sides now hold and this replica has as a file, or empty to keep the
    /// base recorded before.
    /// </param>
    /// <param name="peerHead">The peer's head as the sync found it.</param>
    /// <returns>True when the file changed.</returns>
    /// <exception cref="ArgumentException"><paramref name="deviceId"/> was null or blank.</exception>
    public bool Record(string deviceId, ContentHash shared, ContentHash peerHead)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        lock (_gate)
        {
            var marks = new Dictionary<string, SharedMark>(LoadLocked(), StringComparer.OrdinalIgnoreCase);
            marks.TryGetValue(deviceId, out var before);

            var after = new SharedMark
            {
                Base = shared.IsEmpty ? before?.Base ?? default : shared,
                PeerHead = peerHead,
            };

            if (after == before)
            {
                return false;
            }

            marks[deviceId] = after;

            var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
            try
            {
                File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(
                    new SortedDictionary<string, SharedMark>(marks, StringComparer.OrdinalIgnoreCase),
                    SipJson.Readable));
                SharingRetry.Run(() => File.Move(temporary, _path, overwrite: true));
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }

            return true;
        }
    }

    private Dictionary<string, SharedMark> LoadLocked()
    {
        if (!File.Exists(_path))
        {
            return new Dictionary<string, SharedMark>(StringComparer.OrdinalIgnoreCase);
        }

        try
        {
            var bytes = SharingRetry.Run(() => File.ReadAllBytes(_path));
            var marks = JsonSerializer.Deserialize<Dictionary<string, SharedMark>>(bytes, SipJson.Readable);
            return new Dictionary<string, SharedMark>(
                (marks ?? []).Where(pair => pair.Value is not null),
                StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            // Damaged by hand or by a crash: no marks, so the next merge with each peer is
            // two-way and keeps both versions, and the next sync writes the file afresh.
            return new Dictionary<string, SharedMark>(StringComparer.OrdinalIgnoreCase);
        }
    }
}

/// <summary>What this replica last knew it shared with one peer.</summary>
public sealed record SharedMark
{
    /// <summary>
    /// The newest snapshot both sides were known to hold, kept as a file as the merge base
    /// for the next divergence. Empty when none is known.
    /// </summary>
    public ContentHash Base { get; init; }

    /// <summary>The peer's head when they last synced successfully.</summary>
    public ContentHash PeerHead { get; init; }
}
