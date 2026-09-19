using SippBucket.Core.Hashing;

namespace SippBucket.Core.Model;

/// <summary>
/// The tree objects of a snapshot in the canonical format: one per folder, listing its files
/// and naming the tree of each subfolder (D-23, docs/SNAPSHOT-FORMAT.md).
/// </summary>
/// <remarks>
/// <para>
/// A snapshot used to hold one flat list of every file, so changing one file of fifty thousand
/// wrote and sent fifty thousand entries. A tree is named by the hash of its encoding, so a
/// folder nothing changed in keeps its tree, and a save writes, and a pull fetches, only the
/// trees along the path to what changed.
/// </para>
/// <para>
/// Trees are kept in the block store beside the blocks, as blocks are: encrypted at rest,
/// named by the BLAKE2b-256 of their plaintext, and carried between peers by the block
/// messages. The in-memory <see cref="Snapshot.Files"/> is still the flat list every other part
/// of the program reads; trees are how it is stored and moved.
/// </para>
/// <para>
/// <b>The encoding.</b> The label <see cref="Label"/> as text, the number of entries, then each
/// entry in ascending order of its name's UTF-8 bytes, no name twice: a kind byte, the name as
/// text, then for a file its size, its modification time as UTC ticks, its block size, its
/// chunker as text (empty for the fixed-size split), its block count and its block hashes, and
/// for a folder its tree's hash. Text and integers are as <see cref="CanonicalWriter"/> writes
/// them. A folder's tree is never empty; only the root's can be.
/// </para>
/// </remarks>
internal static class SnapshotTree
{
    /// <summary>The label every tree's encoding starts with.</summary>
    public const string Label = "sippbucket-tree-v2";

    /// <summary>How deep a snapshot's folders may nest: the most segments one path may have.</summary>
    public const int MaximumDepth = 256;

    /// <summary>The longest one name may be, in UTF-8 bytes. NTFS allows 255 UTF-16 units, at most 765 bytes.</summary>
    public const int MaximumNameBytes = 1024;

    private const byte FileKind = 1;
    private const byte FolderKind = 2;
    private const int MaximumChunkerBytes = 64;

    /// <summary>
    /// The fewest bytes one entry can take: a kind byte, a name's length and one byte of it,
    /// and the smaller of a folder's hash and a file's fields.
    /// </summary>
    private const int MinimumEntryBytes = 1 + 4 + 1 + (8 + 8 + 4 + 4 + 4);

    /// <summary>Builds every tree of a file list, bottom up.</summary>
    /// <param name="files">The files, in any order, with paths as snapshots write them.</param>
    /// <returns>The root tree's hash, and every tree by its hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="files"/> was null.</exception>
    /// <exception cref="ArgumentException">
    /// A path is empty, has an empty segment, nests deeper than <see cref="MaximumDepth"/>, is a
    /// file and a folder at once, or is listed twice; or a name or a chunker has no canonical
    /// form.
    /// </exception>
    public static SnapshotTrees Build(IReadOnlyList<FileEntry> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        var root = new Folder();
        foreach (var file in files)
        {
            ArgumentNullException.ThrowIfNull(file);
            CheckFile(file);

            var segments = file.Path.Split('/');
            if (segments.Length > MaximumDepth)
            {
                throw new ArgumentException($"{file.Path} nests deeper than {MaximumDepth} folders.", nameof(files));
            }

            var folder = root;
            for (var i = 0; i < segments.Length - 1; i++)
            {
                var name = segments[i];
                CheckName(name, file.Path);
                if (folder.Files.ContainsKey(name))
                {
                    throw new ArgumentException($"{file.Path} passes through a name that is also a file.", nameof(files));
                }

                if (!folder.Folders.TryGetValue(name, out var child))
                {
                    child = new Folder();
                    folder.Folders[name] = child;
                }

                folder = child;
            }

            var last = segments[^1];
            CheckName(last, file.Path);
            if (folder.Folders.ContainsKey(last) || !folder.Files.TryAdd(last, file))
            {
                throw new ArgumentException($"{file.Path} is listed twice, or is a file and a folder at once.", nameof(files));
            }
        }

        var trees = new Dictionary<ContentHash, byte[]>();
        var rootId = Encode(root, trees);
        return new SnapshotTrees(rootId, trees);
    }

    /// <summary>The root tree's hash for a file list.</summary>
    /// <param name="files">The files.</param>
    /// <returns>The hash.</returns>
    /// <exception cref="ArgumentException">The list cannot be a snapshot's; see <see cref="Build"/>.</exception>
    public static ContentHash RootOf(IReadOnlyList<FileEntry> files) => Build(files).Root;

    /// <summary>
    /// Whether one name can be recorded: not empty, no '/', valid Unicode, and at most
    /// <see cref="MaximumNameBytes"/> bytes of UTF-8.
    /// </summary>
    /// <param name="name">One segment of a path.</param>
    /// <returns>True when a tree can hold it.</returns>
    public static bool CanRecordName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return name.Length > 0 &&
            !name.Contains('/', StringComparison.Ordinal) &&
            CanonicalWriter.IsValidUnicode(name) &&
            CanonicalWriter.StrictUtf8.GetByteCount(name) <= MaximumNameBytes;
    }

    /// <summary>
    /// Whether a path can be recorded: at most <see cref="MaximumDepth"/> segments, each a
    /// name <see cref="CanRecordName"/> accepts.
    /// </summary>
    /// <param name="path">A path as snapshots write it, with forward slashes.</param>
    /// <returns>True when a snapshot can list a file there.</returns>
    /// <remarks>
    /// Every path a scan reads can be; a path a snapshot of the legacy format recorded may not
    /// be, and such an entry cannot be carried into a new snapshot.
    /// </remarks>
    public static bool CanRecord(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var segments = path.Split('/');
        return segments.Length <= MaximumDepth && Array.TrueForAll(segments, CanRecordName);
    }

    /// <summary>The trees one tree names for its subfolders.</summary>
    /// <param name="tree">The tree's encoding.</param>
    /// <returns>Their hashes, in the tree's order.</returns>
    /// <exception cref="FormatException">The encoding is not a canonical tree.</exception>
    public static IReadOnlyList<ContentHash> FoldersOf(ReadOnlySpan<byte> tree) =>
        [.. Decode(tree).Where(entry => entry.File is null).Select(entry => entry.Folder)];

    /// <summary>The flat file list a root tree describes.</summary>
    /// <param name="root">The root tree's hash.</param>
    /// <param name="trees">Every tree under it, by hash.</param>
    /// <returns>The files, ordered by path as <see cref="string.CompareOrdinal(string, string)"/> orders them.</returns>
    /// <exception cref="FormatException">
    /// A tree is missing, does not hash to its name, is not canonical, is a folder's and empty,
    /// or the folders nest deeper than <see cref="MaximumDepth"/>.
    /// </exception>
    public static IReadOnlyList<FileEntry> Materialize(ContentHash root, IReadOnlyDictionary<ContentHash, byte[]> trees)
    {
        ArgumentNullException.ThrowIfNull(trees);

        var files = new List<FileEntry>();
        var pending = new Stack<(ContentHash Id, string Prefix, int Depth)>();
        pending.Push((root, string.Empty, 0));

        while (pending.Count > 0)
        {
            var (id, prefix, depth) = pending.Pop();
            if (!trees.TryGetValue(id, out var bytes))
            {
                throw new FormatException($"Tree {id.ToShortString()} is not held.");
            }

            if (Blake2.Hash(bytes) != id)
            {
                throw new FormatException($"Tree {id.ToShortString()} does not hash to its name.");
            }

            var entries = Decode(bytes);
            if (depth > 0 && entries.Count == 0)
            {
                throw new FormatException($"Tree {id.ToShortString()} is a folder's and is empty, which no snapshot writes.");
            }

            foreach (var entry in entries)
            {
                var path = prefix + entry.Name;
                if (entry.File is { } file)
                {
                    files.Add(file with { Path = path });
                }
                else if (depth + 1 >= MaximumDepth)
                {
                    throw new FormatException($"{path} nests deeper than {MaximumDepth} folders.");
                }
                else
                {
                    pending.Push((entry.Folder, path + "/", depth + 1));
                }
            }
        }

        files.Sort(static (a, b) => string.CompareOrdinal(a.Path, b.Path));
        return files;
    }

    /// <summary>Reads one tree's entries, refusing anything that is not exactly canonical.</summary>
    /// <param name="bytes">The tree's encoding.</param>
    /// <returns>The entries, in order. A file's <see cref="FileEntry.Path"/> is its name alone.</returns>
    /// <exception cref="FormatException">The encoding is not a canonical tree.</exception>
    internal static List<TreeEntry> Decode(ReadOnlySpan<byte> bytes)
    {
        var reader = new CanonicalReader(bytes);
        reader.Label(Label);

        var count = reader.UInt32();
        if (count > (uint)(reader.Remaining / MinimumEntryBytes))
        {
            throw new FormatException($"A tree claims {count} entries, more than its bytes can hold.");
        }

        var entries = new List<TreeEntry>((int)count);
        byte[]? previous = null;
        for (var i = 0u; i < count; i++)
        {
            var kind = reader.Byte();
            var name = reader.Text(MaximumNameBytes);
            if (name.Length == 0 || name.Contains('/', StringComparison.Ordinal))
            {
                throw new FormatException("A tree names an entry with an empty name, or one holding '/'.");
            }

            var nameBytes = CanonicalWriter.StrictUtf8.GetBytes(name);
            if (previous is not null && previous.AsSpan().SequenceCompareTo(nameBytes) >= 0)
            {
                throw new FormatException("A tree's entries are out of order, or a name appears twice.");
            }

            previous = nameBytes;

            switch (kind)
            {
                case FileKind:
                    entries.Add(new TreeEntry(name, ReadFile(ref reader, name), default));
                    break;

                case FolderKind:
                    var folder = reader.Hash();
                    if (folder.IsEmpty)
                    {
                        throw new FormatException($"A tree's folder '{name}' names no tree.");
                    }

                    entries.Add(new TreeEntry(name, null, folder));
                    break;

                default:
                    throw new FormatException($"A tree holds an entry of kind {kind}, which this build does not know.");
            }
        }

        reader.End();
        return entries;
    }

    private static FileEntry ReadFile(ref CanonicalReader reader, string name)
    {
        var size = reader.Int64();
        var modified = reader.Int64();
        var blockSize = reader.Int32();
        var chunker = reader.Text(MaximumChunkerBytes);
        var blockCount = reader.UInt32();

        if (size < 0 || blockSize < 0 || modified < 0 || modified > DateTimeOffset.MaxValue.UtcTicks)
        {
            throw new FormatException($"A tree's file '{name}' has a size, block size or time out of range.");
        }

        if (blockCount > (uint)(reader.Remaining / ContentHash.SizeInBytes))
        {
            throw new FormatException($"A tree's file '{name}' claims more blocks than the tree can hold.");
        }

        var blocks = new ContentHash[blockCount];
        for (var i = 0; i < blocks.Length; i++)
        {
            blocks[i] = reader.Hash();
        }

        return new FileEntry
        {
            Path = name,
            Size = size,
            ModifiedUtc = new DateTimeOffset(modified, TimeSpan.Zero),
            BlockSize = blockSize,
            Blocks = blocks,
            Chunker = chunker.Length == 0 ? null : chunker,
        };
    }

    private static ContentHash Encode(Folder folder, Dictionary<ContentHash, byte[]> trees)
    {
        var entries = new List<(byte[] Bytes, string Name, FileEntry? File, ContentHash Folder)>(
            folder.Files.Count + folder.Folders.Count);
        foreach (var (name, file) in folder.Files)
        {
            entries.Add((NameBytes(name), name, file, default));
        }

        foreach (var (name, child) in folder.Folders)
        {
            entries.Add((NameBytes(name), name, null, Encode(child, trees)));
        }

        entries.Sort(static (a, b) => a.Bytes.AsSpan().SequenceCompareTo(b.Bytes));

        var writer = new CanonicalWriter();
        writer.Text(Label);
        writer.UInt32((uint)entries.Count);
        foreach (var entry in entries)
        {
            if (entry.File is { } file)
            {
                writer.Byte(FileKind);
                writer.Text(entry.Name);
                writer.Int64(file.Size);
                writer.Int64(file.ModifiedUtc.UtcTicks);
                writer.Int32(file.BlockSize);
                writer.Text(file.Chunker ?? string.Empty);
                writer.UInt32((uint)file.Blocks.Count);
                foreach (var block in file.Blocks)
                {
                    writer.Hash(block);
                }
            }
            else
            {
                writer.Byte(FolderKind);
                writer.Text(entry.Name);
                writer.Hash(entry.Folder);
            }
        }

        var bytes = writer.ToArray();
        var id = Blake2.Hash(bytes);
        trees[id] = bytes;
        return id;
    }

    private static void CheckFile(FileEntry file)
    {
        if (string.IsNullOrEmpty(file.Path))
        {
            throw new ArgumentException("A file entry has no path.", nameof(file));
        }

        if (file.Size < 0 || file.BlockSize < 0)
        {
            throw new ArgumentException($"{file.Path} has a negative size or block size.", nameof(file));
        }

        // Empty would read back as the fixed-size split, a different entry with the same bytes.
        if (file.Chunker is { Length: 0 })
        {
            throw new ArgumentException($"{file.Path} names an empty chunker.", nameof(file));
        }
    }

    private static void CheckName(string name, string path)
    {
        if (!CanRecordName(name))
        {
            throw new ArgumentException(
                $"{path} has a segment that is empty, is not valid Unicode, or is longer than {MaximumNameBytes} bytes.",
                nameof(path));
        }
    }

    /// <summary>A name's UTF-8, which orders a tree's entries. Every name reaching it has passed <see cref="CheckName"/>.</summary>
    private static byte[] NameBytes(string name) => CanonicalWriter.StrictUtf8.GetBytes(name);

    /// <summary>One folder while a file list is sorted into folders.</summary>
    private sealed class Folder
    {
        public Dictionary<string, FileEntry> Files { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, Folder> Folders { get; } = new(StringComparer.Ordinal);
    }
}

/// <summary>The trees a file list makes.</summary>
/// <param name="Root">The root tree's hash: what a canonical snapshot's header names.</param>
/// <param name="Trees">Every tree, by hash, the root among them.</param>
internal sealed record SnapshotTrees(ContentHash Root, IReadOnlyDictionary<ContentHash, byte[]> Trees);

/// <summary>One entry of a tree: a file, or a folder's tree.</summary>
/// <param name="Name">The name, one path segment.</param>
/// <param name="File">The file, with <see cref="FileEntry.Path"/> set to the name alone; null for a folder.</param>
/// <param name="Folder">The folder's tree; empty for a file.</param>
internal sealed record TreeEntry(string Name, FileEntry? File, ContentHash Folder);

/// <summary>
/// The files and folders a file list holds so far, which says whether another file can join it
/// and the list still make trees (<see cref="SnapshotTree.Build"/>).
/// </summary>
/// <remarks>
/// A list read from one disk always can. One that joins entries from more than one place, what
/// a scan read and what an earlier snapshot recorded for a path it could not read or ignores,
/// can hold a file at a path another entry passes through as a folder: a folder replaced by a
/// file of the same name since. The caller adds what it trusts most first, and leaves out
/// what no longer fits.
/// </remarks>
internal sealed class TreeShape
{
    private readonly HashSet<string> _files = new(StringComparer.Ordinal);
    private readonly HashSet<string> _folders = new(StringComparer.Ordinal);

    /// <summary>Starts from a list that makes trees, such as one scan's.</summary>
    /// <param name="files">The files.</param>
    /// <exception cref="ArgumentException">Two of them cannot both be listed.</exception>
    public TreeShape(IEnumerable<FileEntry> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        foreach (var file in files)
        {
            if (!TryAdd(file.Path))
            {
                throw new ArgumentException($"{file.Path} cannot be listed beside the files before it.", nameof(files));
            }
        }
    }

    /// <summary>
    /// Adds a file's path when it fits: nothing is listed at that path, as a file or as a folder
    /// another file passes through, and no file is listed at a folder this path passes through.
    /// </summary>
    /// <param name="path">The path, with forward slashes.</param>
    /// <returns>True when it was added; false, and nothing changed, when it does not fit.</returns>
    public bool TryAdd(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (_files.Contains(path) || _folders.Contains(path))
        {
            return false;
        }

        for (var slash = path.IndexOf('/', StringComparison.Ordinal); slash >= 0; slash = path.IndexOf('/', slash + 1))
        {
            if (_files.Contains(path[..slash]))
            {
                return false;
            }
        }

        _files.Add(path);
        for (var slash = path.IndexOf('/', StringComparison.Ordinal); slash >= 0; slash = path.IndexOf('/', slash + 1))
        {
            _folders.Add(path[..slash]);
        }

        return true;
    }
}
