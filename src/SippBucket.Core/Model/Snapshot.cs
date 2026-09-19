using System.Text.Json.Serialization;
using SippBucket.Core.Hashing;

namespace SippBucket.Core.Model;

/// <summary>
/// A point-in-time record of every file in the repository.
/// </summary>
/// <remarks>
/// <para>
/// Snapshots form a graph through <see cref="ParentId"/> and, for a merge,
/// <see cref="MergeParentId"/>. Most snapshots have one parent. When two machines both
/// saved from a common ancestor, the machine that pulls second reconciles the two file sets
/// against that ancestor and records the result with both heads as parents, so that each
/// side later finds its own head in the other's ancestry and the pair can fast-forward
/// again. A merge never asks anyone to resolve anything: where both sides changed the same
/// file differently, the sync engine keeps both versions and renames the local one.
/// </para>
/// <para>
/// A snapshot's ID depends on its <see cref="Format"/>. One this build saves is in the
/// canonical format: its ID is the BLAKE2b-256 of a header of fixed fields that names the root
/// of its trees, bytes this project defines rather than a serializer (D-12, D-23,
/// docs/SNAPSHOT-FORMAT.md). One saved before is in the legacy format: its ID is the BLAKE2b-256
/// of its canonical JSON, so for those every field here is part of the identity and the
/// serialized form must never move for a snapshot that does not use a newer field.
/// <c>SnapshotFormatTests</c> pins the exact bytes of snapshots written before
/// <see cref="MergeParentId"/> existed; docs/SNAPSHOT-FORMAT.md fixes the canonical format's.
/// </para>
/// </remarks>
public sealed record Snapshot
{
    /// <summary>
    /// The snapshot this one followed. <see cref="ContentHash.IsEmpty"/> is true for the
    /// first snapshot in a repository. For a merge, this is the head of the machine that
    /// made the merge.
    /// </summary>
    public required ContentHash ParentId { get; init; }

    /// <summary>
    /// The other machine's head, when this snapshot records a merge. Empty otherwise.
    /// </summary>
    /// <remarks>
    /// Omitted from the JSON when empty. Every snapshot written before this field existed
    /// is identified by the hash of JSON that does not contain it, and writing
    /// <c>"mergeParentId":""</c> into them would give every existing snapshot in every
    /// existing repository a new ID. <see cref="JsonIgnoreCondition.WhenWritingDefault"/>
    /// compares against <c>default(ContentHash)</c>, which is the all-zero hash that
    /// <see cref="ContentHash.IsEmpty"/> reports, so the condition holds for exactly the
    /// snapshots that are not merges.
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ContentHash MergeParentId { get; init; }

    /// <summary>When the snapshot was taken, in UTC.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>The message given at <c>sip save</c>. May be empty.</summary>
    public required string Message { get; init; }

    /// <summary>
    /// Public key of the device that took the snapshot, in hexadecimal. Used to attribute
    /// a snapshot, and named in the message of a merge that brings it in. Conflict copies are
    /// named after the machine that renamed them, not after this field.
    /// </summary>
    public required string DeviceId { get; init; }

    /// <summary>Every file in the repository at this point, ordered by path.</summary>
    /// <remarks>
    /// For a canonical snapshot as it travels and is stored, empty: its files are in its trees
    /// (<see cref="Tree"/>), and are read out of them before anything uses the snapshot.
    /// </remarks>
    public required IReadOnlyList<FileEntry> Files { get; init; }

    /// <summary>
    /// Which encoding the ID comes from: <see cref="SnapshotFormat.Legacy"/> for a snapshot
    /// saved before the canonical format, <see cref="SnapshotFormat.Canonical"/> for one saved
    /// since.
    /// </summary>
    /// <remarks>
    /// Omitted from the JSON when legacy, and written after every other field, so a legacy
    /// snapshot's JSON, and so its ID, is exactly what it always was.
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyOrder(2)]
    public int Format { get; init; }

    /// <summary>
    /// For a canonical snapshot, the hash of its root tree, which names every file
    /// (<see cref="SnapshotFormat.Canonical"/>). Empty for a legacy one.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyOrder(3)]
    public ContentHash Tree { get; init; }

    /// <summary>
    /// The Ed25519 signature of this snapshot's ID by the device key <see cref="DeviceId"/>
    /// names, as lowercase hexadecimal, under the snapshot signature's own context label
    /// (D-21, docs/SNAPSHOT-FORMAT.md). Null for a legacy snapshot, which is never signed.
    /// </summary>
    /// <remarks>
    /// Not part of the identity: the ID is the hash of the header, and the signature covers the
    /// ID, so it travels and is stored beside the hashed bytes, never inside them. Omitted from
    /// the JSON when null and written after every other field, so a legacy snapshot's JSON, and
    /// so its ID, is exactly what it always was. A canonical snapshot received from a peer must
    /// carry one that verifies; this machine's own saves are signed as they are written.
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyOrder(4)]
    public string? Signature { get; init; }

    /// <summary>Total size of the files in this snapshot, in bytes.</summary>
    public long TotalSize
    {
        get
        {
            long total = 0;
            foreach (var file in Files)
            {
                total += file.Size;
            }

            return total;
        }
    }
}
