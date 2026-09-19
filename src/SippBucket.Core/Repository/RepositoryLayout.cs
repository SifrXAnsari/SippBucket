namespace SippBucket.Core.Repository;

/// <summary>
/// Where everything lives inside a repository. One place for the on-disk layout so no
/// other file has to hardcode a path.
/// </summary>
/// <remarks>
/// The layout is deliberately plain: a power user should be able to open the folder and
/// understand what they are looking at without a tool.
/// </remarks>
public sealed class RepositoryLayout
{
    /// <summary>Name of the metadata directory at the root of a repository.</summary>
    public const string MetadataDirectoryName = ".sip";

    /// <summary>Name of the optional ignore file at the repository root.</summary>
    public const string IgnoreFileName = ".sipignore";

    /// <summary>Creates a layout rooted at a working directory.</summary>
    /// <param name="workingRoot">The folder whose contents the repository tracks.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public RepositoryLayout(string workingRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingRoot);
        WorkingRoot = Path.GetFullPath(workingRoot);
    }

    /// <summary>The folder whose contents are tracked.</summary>
    public string WorkingRoot { get; }

    /// <summary>The <c>.sip</c> directory holding all repository metadata.</summary>
    public string MetadataDirectory => Path.Combine(WorkingRoot, MetadataDirectoryName);

    /// <summary>The repository config file.</summary>
    public string ConfigFile => Path.Combine(MetadataDirectory, "config.json");

    /// <summary>The content-addressed object store.</summary>
    public string ObjectsDirectory => Path.Combine(MetadataDirectory, "objects");

    /// <summary>Directory holding one JSON file per snapshot.</summary>
    public string SnapshotsDirectory => Path.Combine(MetadataDirectory, "snapshots");

    /// <summary>File holding the hash of the newest snapshot.</summary>
    public string HeadFile => Path.Combine(MetadataDirectory, "head");

    /// <summary>
    /// Append-only index of every known snapshot's parents, which outlives the snapshot
    /// files themselves. See <see cref="AncestryIndex"/>.
    /// </summary>
    public string AncestryFile => Path.Combine(MetadataDirectory, "ancestry");

    /// <summary>
    /// Where incoming file versions are written in full before being moved into the working
    /// folder, so a file is only ever replaced whole.
    /// </summary>
    public string IncomingDirectory => Path.Combine(MetadataDirectory, "incoming");

    /// <summary>File listing the peers this repository syncs with.</summary>
    public string PeersFile => Path.Combine(MetadataDirectory, "peers.json");

    /// <summary>
    /// The record of changes peer health held instead of applying, and the answers given. See
    /// <see cref="HeldChanges"/>.
    /// </summary>
    public string HeldFile => Path.Combine(MetadataDirectory, "held.json");

    /// <summary>
    /// A copy of each held snapshot, kept apart from <see cref="SnapshotsDirectory"/> so that no
    /// trim of history removes one and no peer is ever offered one.
    /// </summary>
    public string HeldDirectory => Path.Combine(MetadataDirectory, "held");

    /// <summary>
    /// The operation lock: held open, sharing nothing, for the length of anything that writes
    /// to the working folder or to head. See <see cref="OperationLock"/>.
    /// </summary>
    public string LockFile => Path.Combine(MetadataDirectory, "lock");

    /// <summary>
    /// Who holds <see cref="LockFile"/>, written by the holder so that a process refused the
    /// lock can say what it is waiting for. Advisory only: the lock is the open handle.
    /// </summary>
    public string LockHolderFile => Path.Combine(MetadataDirectory, "lock.holder");

    /// <summary>
    /// What this replica last shared with each peer: the kept merge base and the peer's last
    /// known head. See <see cref="SharedHistory"/>.
    /// </summary>
    public string SharedFile => Path.Combine(MetadataDirectory, "shared");

    /// <summary>
    /// The snapshot the last restore replaced as head, which a Simple replica keeps until the
    /// next restore so that the restore can be undone. See <see cref="SipRepository.RestoreAsync"/>.
    /// </summary>
    public string RestoredFile => Path.Combine(MetadataDirectory, "restored");

    /// <summary>
    /// The folder's tags: names the owner gives snapshots, which retention never deletes.
    /// See <see cref="TagStore"/>.
    /// </summary>
    public string TagsFile => Path.Combine(MetadataDirectory, "tags.json");

    /// <summary>A bisect in progress: the good and bad marks. See <see cref="BisectState"/>.</summary>
    public string BisectFile => Path.Combine(MetadataDirectory, "bisect.json");

    /// <summary>
    /// The owner's save hooks, if any: commands run around <c>sip save</c>. Per machine and
    /// never synced, like everything here. See <see cref="SaveHooks"/>.
    /// </summary>
    public string HooksFile => Path.Combine(MetadataDirectory, "hooks.json");

    /// <summary>The optional ignore file at the repository root.</summary>
    public string IgnoreFile => Path.Combine(WorkingRoot, IgnoreFileName);

    /// <summary>True when this folder already holds a repository.</summary>
    public bool Exists => File.Exists(ConfigFile);

    /// <summary>
    /// Walks up from <paramref name="startDirectory"/> looking for a repository, the way a
    /// version control tool is expected to behave from a subdirectory.
    /// </summary>
    /// <param name="startDirectory">Where to start looking.</param>
    /// <returns>The layout of the repository found, or null when there is none.</returns>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public static RepositoryLayout? Discover(string startDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(startDirectory);

        var current = new DirectoryInfo(Path.GetFullPath(startDirectory));
        while (current is not null)
        {
            var candidate = new RepositoryLayout(current.FullName);
            if (candidate.Exists)
            {
                return candidate;
            }

            current = current.Parent;
        }

        return null;
    }
}
