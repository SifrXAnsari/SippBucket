using System.Text.Json;
using SippBucket.Core.Hashing;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>One tag: a name the owner gave one snapshot.</summary>
public sealed record TagRecord
{
    /// <summary>The name, as given.</summary>
    public required string Name { get; init; }

    /// <summary>The snapshot it names.</summary>
    public required ContentHash SnapshotId { get; init; }

    /// <summary>When the tag was made, in UTC.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>
/// The folder's tags: names the owner gives snapshots, kept in <c>.sip/tags.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Per machine, like everything in <c>.sip</c>.</b> Tags do not sync: a tag made on the
/// desktop does not appear on the laptop. That is stated wherever tags are shown rather than
/// discovered by surprise. What a tag promises is local and strong: a tagged snapshot
/// survives retention — Simple mode's trim, <c>sip bucket keep</c>, and collection — for as
/// long as the tag exists on this machine.
/// </para>
/// <para>
/// <b>Names.</b> 1 to 64 characters: letters, digits, <c>.</c>, <c>-</c> and <c>_</c>, not
/// starting with either punctuation mark. A name that reads as a full snapshot ID is refused,
/// because every command resolves an exact ID first and the tag could never be named. A tag
/// that happens to look like a shorter ID prefix wins over the prefix when a command resolves
/// it — the thing the owner named beats the thing that merely matches.
/// </para>
/// <para>
/// The file is rewritten whole and swapped in, as the other <c>.sip</c> stores are, so it is
/// always the old list or the new one. Reading a damaged file throws; retention treats that
/// as "every snapshot might be tagged" and deletes nothing, the same fail-shut reading the
/// kept merge bases get.
/// </para>
/// </remarks>
public sealed class TagStore
{
    /// <summary>The most characters a tag name may have.</summary>
    public const int MaximumNameLength = 64;

    private const int CurrentSchema = 1;

    private readonly string _path;

    /// <summary>Creates a store over one repository's tags file.</summary>
    /// <param name="path">The tags file, <see cref="RepositoryLayout.TagsFile"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="path"/> was null or blank.</exception>
    public TagStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    /// <summary>Whether the tags file exists at all.</summary>
    public bool Exists => File.Exists(_path);

    /// <summary>Reads every tag, ordered by name.</summary>
    /// <returns>The tags; empty when the file does not exist.</returns>
    /// <exception cref="FormatException">The file exists and is not a tags file.</exception>
    /// <exception cref="IOException">The file exists and could not be read.</exception>
    public IReadOnlyList<TagRecord> Load()
    {
        byte[] bytes;
        try
        {
            bytes = SharingRetry.Run(() => File.ReadAllBytes(_path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return [];
        }

        StoredFile? stored;
        try
        {
            stored = JsonSerializer.Deserialize<StoredFile>(bytes, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new FormatException(
                $"The tags file is not readable: {ex.Message} Fix .sip\\tags.json or delete it.", ex);
        }

        if (stored is null)
        {
            throw new FormatException("The tags file holds no tags object. Fix .sip\\tags.json or delete it.");
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var tag in stored.Tags)
        {
            if (!IsValidName(tag.Name, out var problem))
            {
                throw new FormatException($"The tags file holds a name that cannot be a tag: {problem}");
            }

            if (!seen.Add(tag.Name))
            {
                throw new FormatException(
                    $"The tags file names '{DisplayText.Printable(tag.Name, MaximumNameLength)}' twice.");
            }
        }

        return [.. stored.Tags.OrderBy(tag => tag.Name, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>Finds one tag by name, ignoring case.</summary>
    /// <param name="name">The name looked for.</param>
    /// <returns>The tag, or null when there is none by that name.</returns>
    public TagRecord? Find(string? name) =>
        string.IsNullOrEmpty(name)
            ? null
            : Load().FirstOrDefault(tag =>
                string.Equals(tag.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Adds a tag.</summary>
    /// <param name="name">The name to give the snapshot.</param>
    /// <param name="snapshotId">The snapshot it names.</param>
    /// <param name="nowUtc">When, recorded on the tag.</param>
    /// <returns>The tag as recorded.</returns>
    /// <exception cref="ArgumentException">
    /// The name cannot be a tag, or a tag by that name already exists.
    /// </exception>
    public TagRecord Add(string name, ContentHash snapshotId, DateTimeOffset nowUtc)
    {
        if (!IsValidName(name, out var problem))
        {
            throw new ArgumentException(problem);
        }

        var tags = Load();
        if (tags.Any(tag => string.Equals(tag.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(
                $"A tag called '{DisplayText.Printable(name, MaximumNameLength)}' already exists. " +
                "Remove it first: tags move only on purpose.");
        }

        var added = new TagRecord { Name = name, SnapshotId = snapshotId, CreatedUtc = nowUtc };
        Save([.. tags, added]);
        return added;
    }

    /// <summary>Removes a tag by name, ignoring case.</summary>
    /// <param name="name">The name to remove.</param>
    /// <returns>True when a tag by that name existed.</returns>
    public bool Remove(string name)
    {
        var tags = Load();
        var kept = tags
            .Where(tag => !string.Equals(tag.Name, name, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (kept.Count == tags.Count)
        {
            return false;
        }

        Save(kept);
        return true;
    }

    /// <summary>
    /// The tagged snapshot IDs, for retention. Throws when the file exists and cannot be
    /// read, which retention takes as "delete nothing".
    /// </summary>
    /// <exception cref="FormatException">The file exists and is not a tags file.</exception>
    /// <exception cref="IOException">The file exists and could not be read.</exception>
    public IReadOnlySet<ContentHash> TaggedSnapshots() =>
        Load().Select(tag => tag.SnapshotId).ToHashSet();

    /// <summary>Says whether a name can be a tag, and why not when it cannot.</summary>
    /// <param name="name">The name to judge.</param>
    /// <param name="problem">Why not, when the answer is false.</param>
    public static bool IsValidName(string? name, out string problem)
    {
        if (string.IsNullOrEmpty(name))
        {
            problem = "A tag needs a name.";
            return false;
        }

        if (name.Length > MaximumNameLength)
        {
            problem = $"A tag name is at most {MaximumNameLength} characters; this one is {name.Length}.";
            return false;
        }

        foreach (var character in name)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('.' or '-' or '_'))
            {
                problem = "A tag name uses letters, digits, '.', '-' and '_' only.";
                return false;
            }
        }

        if (name[0] is '.' or '-')
        {
            problem = "A tag name cannot start with '.' or '-'.";
            return false;
        }

        if (ContentHash.TryParse(name, out _))
        {
            problem = "That name is a snapshot ID, which every command resolves first; the tag could never be named.";
            return false;
        }

        problem = string.Empty;
        return true;
    }

    private void Save(IReadOnlyList<TagRecord> tags)
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new StoredFile { Schema = CurrentSchema, Tags = tags }, SipJson.Readable);

        // Written beside the file and swapped in whole, so the file is always the old list
        // or the new one, never half of each.
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

    private sealed record StoredFile
    {
        public required int Schema { get; init; }

        public required IReadOnlyList<TagRecord> Tags { get; init; }
    }
}
