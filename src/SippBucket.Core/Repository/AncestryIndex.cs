using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>
/// Every snapshot this replica has ever made, received or merged onto, with its parents:
/// the history graph without the files.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why it exists.</b> Sync decisions are questions about ancestry — is the peer's head
/// one of mine, is mine one of theirs, where did we last agree — and the snapshot files
/// cannot answer them. Simple mode deletes every snapshot but the newest after each save, so
/// a peer that was merely behind offered an ID this replica no longer held, it looked new,
/// and the older version was written over the newer one (D-39). This file keeps what those
/// questions need after the snapshots are gone, so the answer survives the snapshot.
/// </para>
/// <para>
/// <b>Format.</b> <c>.sip/ancestry</c>: an eight-byte header, then fixed-size records of
/// 104 bytes — the snapshot ID, its parent and its merge parent (32 bytes each, all zero
/// for "none"), then the first eight bytes of the BLAKE2b-256 of those 96 bytes. Between
/// compactions it is only ever appended to. A trailing record torn by a crash is either short, and never parsed,
/// or full length with bytes that were never written, and fails its check; either way it
/// is skipped rather than trusted. The next append first pads the file back to a record
/// boundary, so the torn bytes become one skipped record instead of shifting every record
/// after them.
/// </para>
/// <para>
/// <b>Not encrypted, deliberately.</b> It holds snapshot IDs and nothing else, and those IDs
/// are already readable as the file names in <c>.sip/snapshots</c> and in <c>.sip/head</c>.
/// It does also hold IDs of snapshots this replica learned about while fast-forwarding past
/// them and never fetched — the same kind of value, from the same repository.
/// </para>
/// <para>
/// <b>What it does not do.</b> Two processes appending at the same moment are coordinated
/// only when both are writing under the folder's <see cref="OperationLock"/>, which every
/// save and every sync's apply now are (D-38). An append made outside one, which is the
/// index repairing itself from the snapshot files the first time a process opens it, can
/// still interleave with an append from another process. The worst outcome is a record that fails its check and
/// is skipped, which costs a merge its nearest base and never loses a file, because every
/// sync decision degrades towards keeping both versions when ancestry is unknown. The
/// in-process gate here orders this process's own readers and writers, which the operation
/// lock does not cover.
/// </para>
/// <para>
/// <b>Bounded, not append-only forever.</b> It used to grow by 104 bytes per snapshot for
/// good, Simple mode included (D-54). <see cref="Retain"/> rewrites it with only the entries
/// sync decisions can still need, chosen by <see cref="Needed"/>; the rule and what it gives up
/// are on <see cref="SipRepository.CompactAncestry"/>. Between compactions it is appended to
/// exactly as before.
/// </para>
/// <para>
/// Every open, and the rename that replaces the file on a rebuild, waits out another
/// program's brief hold (D-69).
/// </para>
/// </remarks>
public sealed class AncestryIndex
{
    /// <summary>Size of one record, in bytes.</summary>
    public const int RecordSize = (3 * ContentHash.SizeInBytes) + CheckSize;

    /// <summary>Size of the header that starts the file, in bytes.</summary>
    public const int HeaderSize = 8;

    private const int CheckSize = 8;

    private readonly string _path;
    private readonly Lock _gate = new();
    private readonly Dictionary<ContentHash, (ContentHash Parent, ContentHash Merge)> _entries = [];

    // How much of the file has been parsed: the header plus every whole record read so far.
    // A torn tail stays past this point until an append pads it out.
    private long _parsedLength = HeaderSize;

    private AncestryIndex(string path) => _path = path;

    /// <summary>Marks a file as an ancestry index, and names the record layout.</summary>
    private static ReadOnlySpan<byte> Magic => "SIPANC01"u8;

    /// <summary>How many snapshots the index knows.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                RefreshLocked();
                return _entries.Count;
            }
        }
    }

    /// <summary>Opens an existing index.</summary>
    /// <param name="path">The index file.</param>
    /// <returns>The index, or null when the file is missing or is not an index.</returns>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public static AncestryIndex? TryOpen(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            return null;
        }

        using (var file = OpenShared(path, FileMode.Open, FileAccess.Read))
        {
            Span<byte> header = stackalloc byte[HeaderSize];
            if (file.ReadAtLeast(header, HeaderSize, throwOnEndOfStream: false) < HeaderSize ||
                !header.SequenceEqual(Magic))
            {
                return null;
            }
        }

        var index = new AncestryIndex(path);
        lock (index._gate)
        {
            index.RefreshLocked();
        }

        return index;
    }

    /// <summary>
    /// Writes a new index holding <paramref name="entries"/>, replacing any file already at
    /// <paramref name="path"/> in one step.
    /// </summary>
    /// <param name="path">The index file.</param>
    /// <param name="entries">What it should hold.</param>
    /// <returns>The new index.</returns>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="entries"/> was null.</exception>
    /// <remarks>
    /// Written beside the target and renamed over it, so a crash part way through a rebuild
    /// leaves either no index — rebuilt again on the next open — or a complete one, never a
    /// partial one that would be believed.
    /// </remarks>
    public static AncestryIndex Create(string path, IEnumerable<AncestryEntry> entries)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(entries);

        var unique = new Dictionary<ContentHash, AncestryEntry>();
        foreach (var entry in entries)
        {
            if (!entry.Id.IsEmpty)
            {
                unique.TryAdd(entry.Id, entry);
            }
        }

        var bytes = new byte[HeaderSize + (unique.Count * RecordSize)];
        Magic.CopyTo(bytes);

        var offset = HeaderSize;
        foreach (var entry in unique.Values)
        {
            Encode(entry, bytes.AsSpan(offset, RecordSize));
            offset += RecordSize;
        }

        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        SharingRetry.Run(() => File.WriteAllBytes(temporary, bytes));
        SharingRetry.Run(() => File.Move(temporary, path, overwrite: true));

        var index = new AncestryIndex(path);
        lock (index._gate)
        {
            index.RefreshLocked();
        }

        return index;
    }

    /// <summary>True when the index knows this snapshot.</summary>
    /// <param name="snapshotId">The snapshot to look for.</param>
    /// <returns>True when it has an entry.</returns>
    public bool Contains(ContentHash snapshotId) => TryGet(snapshotId, out _);

    /// <summary>Looks up one snapshot's entry.</summary>
    /// <param name="snapshotId">The snapshot to look for.</param>
    /// <param name="entry">Its entry, when this returns true.</param>
    /// <returns>True when the index knows the snapshot.</returns>
    public bool TryGet(ContentHash snapshotId, [NotNullWhen(true)] out AncestryEntry? entry)
    {
        lock (_gate)
        {
            // Only a miss pays for a look at the file, which is how a record appended by
            // another process — a `sip save` run by hand while the daemon serves — is seen.
            if (!_entries.ContainsKey(snapshotId))
            {
                RefreshLocked();
            }

            return TryGetLocked(snapshotId, out entry);
        }
    }

    /// <summary>Adds entries the index does not already hold.</summary>
    /// <param name="entries">The entries to record.</param>
    /// <returns>How many were new.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="entries"/> was null.</exception>
    public int Add(IEnumerable<AncestryEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        lock (_gate)
        {
            RefreshLocked();

            var fresh = new List<AncestryEntry>();
            foreach (var entry in entries)
            {
                if (!entry.Id.IsEmpty && !_entries.ContainsKey(entry.Id))
                {
                    _entries[entry.Id] = (entry.ParentId, entry.MergeParentId);
                    fresh.Add(entry);
                }
            }

            if (fresh.Count == 0)
            {
                return 0;
            }

            using var file = OpenShared(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite);
            var length = file.Length;

            // A file shorter than its header was cut off before the header landed; start it
            // again rather than appending records to a file nothing will recognise.
            var header = length < HeaderSize ? Magic.Length : 0;
            if (header > 0)
            {
                length = 0;
                file.SetLength(0);
                _parsedLength = HeaderSize;
            }

            var torn = (int)((length - HeaderSize) % RecordSize);
            var padding = length >= HeaderSize && torn != 0 ? RecordSize - torn : 0;

            var bytes = new byte[header + padding + (fresh.Count * RecordSize)];
            Magic[..header].CopyTo(bytes);

            var offset = header + padding;
            foreach (var entry in fresh)
            {
                Encode(entry, bytes.AsSpan(offset, RecordSize));
                offset += RecordSize;
            }

            file.Seek(0, SeekOrigin.End);
            file.Write(bytes);
            file.Flush();

            // _parsedLength is deliberately left where it was. Another process may have
            // appended between the refresh above and this write, and advancing past its
            // records would skip them for good. The next refresh re-reads this region, finds
            // these entries already present, and picks up anyone else's.
            return fresh.Count;
        }
    }

    /// <summary>
    /// True when <paramref name="candidate"/> is <paramref name="descendant"/> or one of its
    /// ancestors, as far as this index knows.
    /// </summary>
    /// <param name="candidate">The snapshot that might be an ancestor.</param>
    /// <param name="descendant">The snapshot to walk back from.</param>
    /// <returns>True when the walk reaches the candidate.</returns>
    public bool IsAncestorOrSelf(ContentHash candidate, ContentHash descendant)
    {
        if (candidate.IsEmpty || descendant.IsEmpty)
        {
            return false;
        }

        lock (_gate)
        {
            RefreshLocked();

            var seen = new HashSet<ContentHash>();
            var pending = new Stack<ContentHash>();
            pending.Push(descendant);

            while (pending.Count > 0)
            {
                var id = pending.Pop();
                if (id == candidate)
                {
                    return true;
                }

                if (id.IsEmpty || !seen.Add(id) || !_entries.TryGetValue(id, out var parents))
                {
                    continue;
                }

                pending.Push(parents.Parent);
                pending.Push(parents.Merge);
            }

            return false;
        }
    }

    /// <summary>
    /// Walks back from <paramref name="roots"/> breadth first and returns up to
    /// <paramref name="limit"/> entries. This is what a peer is served in answer to an
    /// ancestry request.
    /// </summary>
    /// <param name="roots">Where to start. IDs the index does not know contribute nothing.</param>
    /// <param name="limit">The most entries to return.</param>
    /// <returns>The entries, nearest the roots first.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="roots"/> was null.</exception>
    public IReadOnlyList<AncestryEntry> Walk(IEnumerable<ContentHash> roots, int limit)
    {
        ArgumentNullException.ThrowIfNull(roots);

        var result = new List<AncestryEntry>();
        if (limit <= 0)
        {
            return result;
        }

        lock (_gate)
        {
            RefreshLocked();

            var seen = new HashSet<ContentHash>();
            var pending = new Queue<ContentHash>(roots);

            while (pending.Count > 0 && result.Count < limit)
            {
                var id = pending.Dequeue();
                if (id.IsEmpty || !seen.Add(id) || !TryGetLocked(id, out var entry))
                {
                    continue;
                }

                result.Add(entry);
                pending.Enqueue(entry.ParentId);
                pending.Enqueue(entry.MergeParentId);
            }
        }

        return result;
    }

    /// <summary>
    /// The entries that lie on a path from a root back to an anchor, and the roots themselves.
    /// </summary>
    /// <param name="index">The index to choose from.</param>
    /// <param name="roots">Where every walk that matters starts: heads.</param>
    /// <param name="anchors">
    /// Where the walks that matter end: snapshots both sides hold, and snapshot files.
    /// </param>
    /// <returns>The IDs to keep. Roots and anchors the index does not know are left out.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <remarks>
    /// Walks back from the roots to find everything they reach, then forward from each anchor
    /// through what was reached: what both walks meet is on a path from a root to an anchor.
    /// An entry reachable from a root but older than every anchor on its path is not needed.
    /// </remarks>
    public static IReadOnlySet<ContentHash> Needed(
        AncestryIndex index,
        IEnumerable<ContentHash> roots,
        IEnumerable<ContentHash> anchors)
    {
        ArgumentNullException.ThrowIfNull(index);
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(anchors);

        var rootList = roots.ToList();

        lock (index._gate)
        {
            index.RefreshLocked();

            var reached = new HashSet<ContentHash>();
            var children = new Dictionary<ContentHash, List<ContentHash>>();
            var pending = new Stack<ContentHash>(rootList.Where(index._entries.ContainsKey));

            while (pending.Count > 0)
            {
                var id = pending.Pop();
                if (!reached.Add(id))
                {
                    continue;
                }

                var (parent, merge) = index._entries[id];
                foreach (var up in new[] { parent, merge })
                {
                    if (up.IsEmpty || !index._entries.ContainsKey(up))
                    {
                        continue;
                    }

                    if (!children.TryGetValue(up, out var list))
                    {
                        list = [];
                        children[up] = list;
                    }

                    list.Add(id);
                    pending.Push(up);
                }
            }

            var keep = new HashSet<ContentHash>(rootList.Where(reached.Contains));
            var visited = new HashSet<ContentHash>();
            var forward = new Stack<ContentHash>(anchors.Where(reached.Contains));
            while (forward.Count > 0)
            {
                var id = forward.Pop();
                if (!visited.Add(id))
                {
                    continue;
                }

                keep.Add(id);
                if (children.TryGetValue(id, out var below))
                {
                    foreach (var child in below)
                    {
                        forward.Push(child);
                    }
                }
            }

            return keep;
        }
    }

    /// <summary>
    /// Rewrites the file with only the entries in <paramref name="keep"/>, in one step.
    /// </summary>
    /// <param name="keep">The IDs to keep; usually from <see cref="Needed"/>.</param>
    /// <returns>How many entries were dropped.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="keep"/> was null.</exception>
    /// <exception cref="IOException">The file could not be replaced. Nothing was dropped.</exception>
    /// <remarks>
    /// Written beside the file and renamed over it, as <see cref="Create"/> is, so a crash
    /// leaves the old index or the new one. Another process that has this index open sees the
    /// file shrink and reads it again from the start, keeping what it already knew: holding an
    /// entry the file has dropped only ever answers a question more fully. What cannot be
    /// ordered is another process appending while this one rewrites; its record is lost, the
    /// same exposure as two appends colliding, which is D-38's.
    /// </remarks>
    public int Retain(IReadOnlySet<ContentHash> keep)
    {
        ArgumentNullException.ThrowIfNull(keep);

        lock (_gate)
        {
            RefreshLocked();

            var kept = _entries.Where(pair => keep.Contains(pair.Key)).ToList();
            var dropped = _entries.Count - kept.Count;
            if (dropped == 0)
            {
                return 0;
            }

            var bytes = new byte[HeaderSize + (kept.Count * RecordSize)];
            Magic.CopyTo(bytes);

            var offset = HeaderSize;
            foreach (var (id, (parent, merge)) in kept)
            {
                Encode(new AncestryEntry { Id = id, ParentId = parent, MergeParentId = merge }, bytes.AsSpan(offset, RecordSize));
                offset += RecordSize;
            }

            var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
            try
            {
                File.WriteAllBytes(temporary, bytes);
                SharingRetry.Run(() => File.Move(temporary, _path, overwrite: true));
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    SharingRetry.Run(() => File.Delete(temporary));
                }
            }

            _entries.Clear();
            foreach (var (id, parents) in kept)
            {
                _entries[id] = parents;
            }

            _parsedLength = bytes.Length;
            return dropped;
        }
    }

    private bool TryGetLocked(ContentHash snapshotId, [NotNullWhen(true)] out AncestryEntry? entry)
    {
        if (snapshotId.IsEmpty || !_entries.TryGetValue(snapshotId, out var parents))
        {
            entry = null;
            return false;
        }

        entry = new AncestryEntry
        {
            Id = snapshotId,
            ParentId = parents.Parent,
            MergeParentId = parents.Merge,
        };
        return true;
    }

    /// <summary>
    /// Reads whole records appended since the last read, by this process or another one.
    /// The caller holds <see cref="_gate"/>.
    /// </summary>
    private void RefreshLocked()
    {
        // One stat, and nothing opened, when nothing was appended — which is almost every
        // time. Learning a peer's history is a lookup per entry and nearly all of them miss,
        // so opening the file on every miss cost a file open per entry.
        var info = new FileInfo(_path);

        // Shorter than what has been read: another process compacted it (Retain). Read it
        // again from the start; entries already held stay, which only ever knows more.
        if (info.Exists && info.Length < _parsedLength)
        {
            _parsedLength = HeaderSize;
        }

        if (!info.Exists || info.Length < _parsedLength + RecordSize)
        {
            return;
        }

        using var file = OpenShared(_path, FileMode.Open, FileAccess.Read);
        var length = file.Length;
        if (length < _parsedLength + RecordSize)
        {
            return;
        }

        var whole = (length - _parsedLength) / RecordSize;
        var buffer = new byte[whole * RecordSize];

        file.Seek(_parsedLength, SeekOrigin.Begin);
        file.ReadExactly(buffer);

        for (var offset = 0; offset < buffer.Length; offset += RecordSize)
        {
            if (TryDecode(buffer.AsSpan(offset, RecordSize), out var id, out var parent, out var merge))
            {
                _entries.TryAdd(id, (parent, merge));
            }
        }

        _parsedLength += buffer.Length;
    }

    private static void Encode(AncestryEntry entry, Span<byte> record)
    {
        entry.Id.WriteTo(record);
        entry.ParentId.WriteTo(record[ContentHash.SizeInBytes..]);
        entry.MergeParentId.WriteTo(record[(2 * ContentHash.SizeInBytes)..]);
        WriteCheck(record[..(3 * ContentHash.SizeInBytes)], record[(3 * ContentHash.SizeInBytes)..]);
    }

    private static bool TryDecode(
        ReadOnlySpan<byte> record,
        out ContentHash id,
        out ContentHash parent,
        out ContentHash merge)
    {
        var body = record[..(3 * ContentHash.SizeInBytes)];

        Span<byte> expected = stackalloc byte[CheckSize];
        WriteCheck(body, expected);

        id = new ContentHash(body[..ContentHash.SizeInBytes]);
        parent = new ContentHash(body.Slice(ContentHash.SizeInBytes, ContentHash.SizeInBytes));
        merge = new ContentHash(body.Slice(2 * ContentHash.SizeInBytes, ContentHash.SizeInBytes));

        // An all-zero ID never names a snapshot, and it is exactly what a zero-filled tail
        // would decode to if its check ever matched.
        return !id.IsEmpty &&
               BinaryPrimitives.ReadUInt64LittleEndian(expected) ==
               BinaryPrimitives.ReadUInt64LittleEndian(record[(3 * ContentHash.SizeInBytes)..]);
    }

    private static void WriteCheck(ReadOnlySpan<byte> body, Span<byte> destination)
    {
        Span<byte> digest = stackalloc byte[ContentHash.SizeInBytes];
        Blake2.Hash(body).WriteTo(digest);
        digest[..CheckSize].CopyTo(destination);
    }

    private static FileStream OpenShared(string path, FileMode mode, FileAccess access) =>
        SharingRetry.Run(() => new FileStream(path, mode, access, FileShare.ReadWrite | FileShare.Delete));
}
