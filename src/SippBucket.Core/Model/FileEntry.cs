using System.Text.Json.Serialization;
using SippBucket.Core.Hashing;

namespace SippBucket.Core.Model;

/// <summary>
/// One file as recorded in a snapshot: where it sits, how big it was, and the content
/// hashes of the blocks it was split into.
/// </summary>
/// <remarks>
/// The file's bytes are not held here. They live in the blob store under the hashes in
/// <see cref="Blocks"/>, which is what lets two snapshots share unchanged content and lets
/// a peer ask for only the blocks it is missing.
/// </remarks>
public sealed record FileEntry
{
    /// <summary>
    /// Path relative to the repository root, using forward slashes on every platform so
    /// that a Windows peer and a non-Windows peer agree on the name.
    /// </summary>
    public required string Path { get; init; }

    /// <summary>Length of the file in bytes.</summary>
    public required long Size { get; init; }

    /// <summary>Last write time of the file, in UTC.</summary>
    public required DateTimeOffset ModifiedUtc { get; init; }

    /// <summary>The size the file's blocks were cut to, or aimed at.</summary>
    /// <remarks>
    /// For a fixed-size entry (<see cref="Chunker"/> is null) every block but the last is
    /// exactly this long, from <c>BlockSizer.ForFileSize</c>. For a FastCDC entry it is the
    /// average chunk size of the file's size tier: blocks run from a quarter of it to four
    /// times it, and the last may be shorter. Nothing restores, transfers or allocates by
    /// this number — a file is the concatenation of <see cref="Blocks"/> — it is here so the
    /// split can be made again, which is how an entry chunked one way is compared with one
    /// chunked the other.
    /// </remarks>
    public required int BlockSize { get; init; }

    /// <summary>
    /// Content hashes of the file's blocks, in order. An empty file has no blocks.
    /// </summary>
    public required IReadOnlyList<ContentHash> Blocks { get; init; }

    /// <summary>
    /// The content-defined chunker that split this file, or null for the fixed-size split
    /// every entry written before FastCDC used.
    /// </summary>
    /// <remarks>
    /// Omitted from the JSON when null, and that is load-bearing rather than tidy: a
    /// snapshot's ID is the hash of its canonical JSON, so writing <c>"chunker":null</c>
    /// into a legacy entry would change the ID of every snapshot already on disk and on
    /// every replica. When present it is written after every other field. It is declared
    /// last too, and System.Text.Json writes properties in declaration order, so the order
    /// attribute changes nothing today: it is insurance, so that moving this declaration or
    /// adding a field below it cannot reorder the bytes of a FastCDC snapshot and change its
    /// ID. The name carries a version because the gear table, the masks and the size tiers
    /// fix every boundary; changing any of them is a new chunker.
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyOrder(1)]
    public string? Chunker { get; init; }
}
