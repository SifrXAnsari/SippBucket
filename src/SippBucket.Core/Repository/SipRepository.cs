using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using SippBucket.Core.Chunking;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Model;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>
/// A SippBucket repository: a tracked folder, its content-addressed store, and the history
/// of snapshots taken of it.
/// </summary>
/// <remarks>
/// <para>
/// There are no branches to create or delete. A repository has one <c>head</c>, and each
/// snapshot names its parent. History is a straight line until two machines save from the
/// same point without seeing each other; the one that pulls second records a merge whose
/// two parents are both heads, so history is a graph that rejoins itself rather than a
/// line. Nobody is asked to manage that: where git would have you branch, merge and delete
/// the branch, SippBucket has you save and sync.
/// </para>
/// <para>
/// The graph is kept twice. The snapshot files hold it in full, and
/// <see cref="Ancestry"/> holds only the IDs and parents of every snapshot this replica has
/// ever known, because sync decisions need the shape of history long after the snapshots
/// that made it are gone.
/// </para>
/// <para>
/// In <see cref="RepositoryMode.Simple"/> the snapshot files are trimmed whenever head
/// moves, so only the newest survives, which is what makes the simple mode simple: there is
/// never any history to browse. Two things survive the trim: the snapshot last shared with
/// each peer, kept as the base for the next merge (D-55), and the ancestry index, compacted
/// only to what sync decisions still need (D-54), so a Simple replica can still recognise a
/// peer that is behind it.
/// </para>
/// <para>
/// Everything that writes to the working folder or to head (saving, a sync's apply and merge,
/// restoring, collecting, and changing the passphrase or the storage policy) holds the
/// folder's <see cref="OperationLock"/> for its whole length, against every other process and
/// every other <see cref="SipRepository"/> over the same folder (D-38). An operation that
/// calls another, as a save calls <see cref="AdvanceHeadAsync"/>, takes it once: the lock
/// shares nothing, so opening it a second time from the same flow would refuse itself.
/// Reads take nothing.
/// </para>
/// </remarks>
public sealed class SipRepository : IDisposable
{
    private readonly RepositoryCipher _cipher;

    // Kept alongside the cipher because one operation legitimately needs the keys themselves
    // rather than the ability to encrypt with them: handing the ring to a newly paired
    // machine, sealed under the pairing session key (CreateInvite), and handing a rotation
    // to the remaining machines (D-70). Zeroed on dispose. They are no more exposed than the
    // cipher already is - all of it is in this process's memory for as long as the
    // repository is open, which is the documented limit of what the passphrase protects.
    // _keyMaterial is the current key; _previousKeys the older ring, oldest first. Both are
    // read and replaced under _keyGate; the cipher carries the same ring for the hot paths.
    private byte[] _keyMaterial;
    private List<byte[]> _previousKeys;
    private readonly Lock _keyGate = new();

    private readonly Lock _ancestryGate = new();
    private readonly Lock _headGate = new();
    private AncestryIndex? _ancestry;

    // The operation lock this flow holds on this folder, if any. Flow-local rather than
    // per object, so that an operation nested inside another in the same flow reuses the
    // lock, while a second flow over this same object (the tray's "Sync now" arriving during
    // a cycle, were anything to let it) is refused by the file like any other process.
    private readonly AsyncLocal<OperationLock?> _operation = new();

    private bool _disposed;

    private SipRepository(
        RepositoryLayout layout,
        RepositoryConfig config,
        RepositoryCipher cipher,
        byte[] keyMaterial,
        IReadOnlyList<byte[]>? previousKeys = null)
    {
        Layout = layout;
        Config = config;
        _cipher = cipher;
        _keyMaterial = (byte[])keyMaterial.Clone();
        _previousKeys = previousKeys is null
            ? []
            : [.. previousKeys.Select(key => (byte[])key.Clone())];
        Blobs = new BlobStore(layout.ObjectsDirectory, cipher);
        Peers = new PeerRegistry(layout.PeersFile);
        Held = new HeldChanges(layout, cipher);
        Shared = new SharedHistory(layout.SharedFile);
        _ignore = IgnoreRules.Empty;
        RefreshIgnoreRules();
    }

    /// <summary>Where this repository's files and metadata live.</summary>
    public RepositoryLayout Layout { get; }

    /// <summary>The repository's configuration.</summary>
    public RepositoryConfig Config { get; private set; }

    /// <summary>The content-addressed block store.</summary>
    public BlobStore Blobs { get; }

    /// <summary>The peers this repository syncs with.</summary>
    public PeerRegistry Peers { get; }

    /// <summary>
    /// The folder's tags: names the owner gives snapshots, which retention never deletes.
    /// Per machine, like everything in <c>.sip</c>.
    /// </summary>
    public TagStore Tags => new(Layout.TagsFile);

    /// <summary>The changes peer health held in this folder instead of applying (docs/PEER-HEALTH.md).</summary>
    public HeldChanges Held { get; }

    /// <summary>What this replica last shared with each peer.</summary>
    public SharedHistory Shared { get; }

    /// <summary>
    /// Signs this machine's snapshots as they are written (D-21), or null while nothing here
    /// signs.
    /// </summary>
    /// <remarks>
    /// Set by whoever opens the repository with the machine's identity in hand: the command
    /// line, the daemon, and the sync engine, which sets it from its own identity when nothing
    /// has. A repository without one still saves — its own store is its own to trust — but a
    /// peer refuses an unsigned canonical snapshot, so a folder saved without a signer stops
    /// syncing, loudly, at the first pull, naming the unsigned snapshot. No shipped path opens
    /// a folder without one.
    /// </remarks>
    public SnapshotSigner? Signer { get; set; }

    /// <summary>Which files the repository ignores, as of the last scan.</summary>
    /// <remarks>
    /// Read again at the start of every scan when <c>.sipignore</c> has changed, not only
    /// when the repository is opened. The daemon holds a repository open for as long as it
    /// runs, so rules loaded once meant an edit to <c>.sipignore</c> — or one arriving from a
    /// peer — was honoured by <c>sip status</c> and ignored by the daemon until it restarted,
    /// and two machines with the same file disagreed about what it said.
    /// </remarks>
    public IgnoreRules Ignore
    {
        get
        {
            lock (_ignoreGate)
            {
                return _ignore;
            }
        }
    }

    /// <summary>
    /// True when this machine's ignore rules are its own: <c>.sipignore</c> names itself, so
    /// it is never synced and the other machines' rules may differ.
    /// </summary>
    /// <remarks>
    /// Only then does a save carry forward entries for ignored paths (see
    /// <see cref="CarryIgnored"/>). When <c>.sipignore</c> is synced, every machine reads the
    /// same rules, so a path ignored here is ignored there too and needs nothing carried.
    /// </remarks>
    internal bool IgnoreRulesAreLocal => Ignore.IsIgnored(RepositoryLayout.IgnoreFileName);

    private readonly Lock _ignoreGate = new();
    private IgnoreRules _ignore;
    private (bool Exists, long Length, DateTime Modified) _ignoreStamp = (false, -1, default);

    /// <summary>Loads <c>.sipignore</c> again if it has changed since it was last loaded.</summary>
    /// <remarks>
    /// Decided by existence, length and modification time, so an edit that keeps both the
    /// length and the timestamp is not seen until the next one that does not. A file that
    /// cannot be read right now — another program saving it — leaves the rules already
    /// loaded in force, and the next scan tries again. The first load, when the repository is
    /// opened, has no rules to fall back on, so a failure there is thrown as it always was:
    /// scanning with no rules would record every ignored file.
    /// </remarks>
    private void RefreshIgnoreRules()
    {
        var info = new FileInfo(Layout.IgnoreFile);
        var stamp = info.Exists ? (true, info.Length, info.LastWriteTimeUtc) : (false, 0L, default(DateTime));

        lock (_ignoreGate)
        {
            if (stamp == _ignoreStamp)
            {
                return;
            }

            var firstLoad = _ignoreStamp.Length < 0;
            try
            {
                _ignore = IgnoreRules.Load(Layout.IgnoreFile);
                _ignoreStamp = stamp;
            }
            catch (Exception ex) when (!firstLoad && ex is IOException or UnauthorizedAccessException)
            {
                // Keep the rules in force; the stamp is left as it was, so the next scan
                // tries the file again.
            }
        }
    }

    /// <summary>
    /// How long an operation here waits for another holder of this folder's lock before it
    /// gives up with <see cref="FolderBusyException"/>.
    /// </summary>
    /// <remarks>Settable for tests, which cannot wait out the shipping five seconds per case.</remarks>
    internal TimeSpan OperationPatience { get; set; } = OperationLock.DefaultPatience;

    /// <summary>Creates a repository in a folder that does not already have one.</summary>
    /// <param name="directory">The folder to track.</param>
    /// <param name="mode">Whether to keep history.</param>
    /// <param name="name">A label for the repository. Defaults to the folder name.</param>
    /// <param name="listenPort">
    /// Recorded in the config as <see cref="RepositoryConfig.ListenPort"/>, which nothing
    /// listens on any more; pass this machine's <c>server.listenPort</c>.
    /// </param>
    /// <returns>The newly created repository.</returns>
    /// <exception cref="RepositoryAlreadyExistsException">The folder already has one.</exception>
    public static SipRepository Init(
        string directory,
        RepositoryMode mode,
        string? name = null,
        int listenPort = RepositoryConfig.DefaultListenPort)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        var layout = new RepositoryLayout(directory);
        if (layout.Exists)
        {
            throw new RepositoryAlreadyExistsException(layout.WorkingRoot);
        }

        Directory.CreateDirectory(layout.MetadataDirectory);
        Directory.CreateDirectory(layout.ObjectsDirectory);
        Directory.CreateDirectory(layout.SnapshotsDirectory);

        var keyMaterial = RepositoryCipher.CreateKey();
        var config = new RepositoryConfig
        {
            FormatVersion = RepositoryConfig.CurrentFormatVersion,
            RepositoryId = Guid.NewGuid().ToString("N"),
            Name = string.IsNullOrWhiteSpace(name)
                ? new DirectoryInfo(layout.WorkingRoot).Name
                : name,
            Mode = mode,
            EncryptionKey = Convert.ToBase64String(keyMaterial),
            ListenPort = listenPort,
        };

        WriteNewMetadata(layout, config);

        return new SipRepository(layout, config, new RepositoryCipher(keyMaterial), keyMaterial);
    }

    /// <summary>
    /// Creates a replica of an existing repository from a pairing payload, and registers the
    /// inviting machine as a peer at the address it was reached on.
    /// </summary>
    /// <param name="directory">The folder to become the replica.</param>
    /// <param name="invite">The payload from the machine that already has the repository.</param>
    /// <param name="originHost">
    /// The host this machine actually dialled to reach the inviting machine. Never an
    /// address the other machine supplied: that is how D-43 recorded <c>127.0.0.1</c>.
    /// </param>
    /// <param name="mode">Whether this replica keeps history.</param>
    /// <param name="peerName">What to call the inviting machine locally.</param>
    /// <param name="listenPort">
    /// Recorded in the config as <see cref="RepositoryConfig.ListenPort"/>, which nothing
    /// listens on any more; pass this machine's <c>server.listenPort</c>.
    /// </param>
    /// <param name="recorded">
    /// Told the inviting machine's record as written, and the record it replaced, if any.
    /// </param>
    /// <returns>The new replica.</returns>
    /// <exception cref="RepositoryAlreadyExistsException">The folder already has one.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="invite"/> was null.</exception>
    /// <remarks>
    /// <para>
    /// Internal, because its input carries the repository key. Pairing reaches it through
    /// <c>PairingClient</c> once both key confirmations have verified; nothing outside this
    /// assembly can construct a key-bearing payload to hand it.
    /// </para>
    /// <para>
    /// The peer is recorded with <see cref="PeerRegistry.AddOrReplace"/>, and what it replaced
    /// is passed on rather than dropped (D-64). A new replica normally has nothing to
    /// replace. A <c>.sip</c> left behind with a <c>peers.json</c> and no <c>config.json</c>
    /// does: that list is read, not discarded, so whoever joins into it is told what was
    /// there.
    /// </para>
    /// </remarks>
    internal static SipRepository Join(
        string directory,
        RepositoryInvite invite,
        string originHost,
        RepositoryMode mode,
        string peerName = "origin",
        int listenPort = RepositoryConfig.DefaultListenPort,
        Action<PeerRecord, PeerRecord?>? recorded = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(invite);
        ArgumentException.ThrowIfNullOrWhiteSpace(originHost);

        var layout = new RepositoryLayout(directory);
        if (layout.Exists)
        {
            throw new RepositoryAlreadyExistsException(layout.WorkingRoot);
        }

        Directory.CreateDirectory(layout.MetadataDirectory);
        Directory.CreateDirectory(layout.ObjectsDirectory);
        Directory.CreateDirectory(layout.SnapshotsDirectory);

        // The ID and the key ring come from the invite: that is what makes this the same
        // repository rather than a different folder with the same name. The older keys come
        // too (D-70), so a machine joining after a rotation can read what was written before
        // it; the revoked devices come so it never dials or serves the removed.
        var config = new RepositoryConfig
        {
            FormatVersion = RepositoryConfig.CurrentFormatVersion,
            RepositoryId = invite.RepositoryId,
            Name = invite.Name,
            Mode = mode,
            EncryptionKey = invite.EncryptionKey,
            PreviousKeys = invite.PreviousKeys.Count == 0 ? null : invite.PreviousKeys,
            RevokedDevices = invite.RevokedDevices.Count == 0 ? null : invite.RevokedDevices,
            ListenPort = listenPort,
        };

        WriteNewMetadata(layout, config);

        var joinKey = Convert.FromBase64String(invite.EncryptionKey);
        var joinPrevious = ParsePreviousKeys(layout, config);
        var repository = new SipRepository(
            layout, config, new RepositoryCipher(joinKey, joinPrevious), joinKey, joinPrevious);

        var origin = new PeerRecord
        {
            Name = peerName,
            DeviceId = invite.DeviceId,
            Host = originHost,
            Port = invite.Port,
        };

        var replaced = repository.Peers.AddOrReplace(origin);
        recorded?.Invoke(origin, replaced);

        return repository;
    }

    /// <summary>Writes a new repository's config and empty head.</summary>
    private static void WriteNewMetadata(RepositoryLayout layout, RepositoryConfig config)
    {
        var json = JsonSerializer.Serialize(config, SipJson.Readable);
        SharingRetry.Run(() => File.WriteAllText(layout.ConfigFile, json));
        SharingRetry.Run(() => File.WriteAllText(layout.HeadFile, string.Empty));
    }

    /// <summary>
    /// Builds the payload another machine needs to become a replica, for pairing to seal.
    /// </summary>
    /// <param name="deviceId">This machine's device ID.</param>
    /// <param name="syncPort">
    /// The port this machine serves peers on, which the new replica records for it: the
    /// machine's <c>server.listenPort</c>. Null falls back to the port this repository's
    /// config recorded when it was created, for callers with no machine setting to hand.
    /// </param>
    /// <returns>The payload, which holds the repository key.</returns>
    /// <exception cref="ArgumentException">The device ID was null or blank.</exception>
    /// <exception cref="ObjectDisposedException">The repository was disposed.</exception>
    /// <remarks>
    /// Internal, and deliberately so (D-49). This used to be public and returned an object
    /// with an <c>Encode</c> method that printed the key; <c>sip invite</c> called it and put
    /// the result on the screen. Now the only caller is <c>PairingServer</c>, which seals the
    /// result under the CPace session key the moment both confirmations have verified.
    /// </remarks>
    internal RepositoryInvite CreateInvite(string deviceId, int? syncPort = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        lock (_keyGate)
        {
            return new RepositoryInvite
            {
                RepositoryId = Config.RepositoryId,
                Name = Config.Name,
                EncryptionKey = Convert.ToBase64String(_keyMaterial),
                PreviousKeys = [.. _previousKeys.Select(Convert.ToBase64String)],
                RevokedDevices = Config.RevokedDevices ?? [],
                DeviceId = deviceId,
                Port = syncPort ?? Config.ListenPort,
            };
        }
    }

    /// <summary>
    /// Opens the repository containing <paramref name="directory"/>, searching upwards.
    /// </summary>
    /// <param name="directory">A folder inside a repository.</param>
    /// <returns>The opened repository.</returns>
    /// <exception cref="RepositoryNotFoundException">No repository was found.</exception>
    /// <exception cref="RepositoryUnreadableException">
    /// One was found and cannot be opened: its config is damaged or from a newer build.
    /// </exception>
    /// <exception cref="RepositoryLockedException">It needs a passphrase; use <see cref="Unlock"/>.</exception>
    public static SipRepository Open(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        var (layout, config) = ReadConfig(directory);

        if (config.IsLocked)
        {
            throw new RepositoryLockedException(layout.WorkingRoot);
        }

        if (string.IsNullOrEmpty(config.EncryptionKey))
        {
            throw new RepositoryUnreadableException(
                layout.WorkingRoot,
                RepositoryUnreadableReason.MissingKey,
                $"its config file, {layout.ConfigFile}, holds neither the key nor a " +
                "passphrase-wrapped key, so it is damaged. Nothing here was changed.");
        }

        // Checked rather than left to throw from inside the cipher. A hand-edited key used to
        // escape as a FormatException or an ArgumentException, which the tray did not catch.
        var openKey = new byte[RepositoryCipher.KeySize + 3];
        if (!Convert.TryFromBase64String(config.EncryptionKey, openKey, out var keyLength) ||
            keyLength != RepositoryCipher.KeySize)
        {
            CryptographicOperations.ZeroMemory(openKey);
            throw new RepositoryUnreadableException(
                layout.WorkingRoot,
                RepositoryUnreadableReason.DamagedKey,
                $"the key in its config file, {layout.ConfigFile}, is not a " +
                $"{RepositoryCipher.KeySize}-byte repository key, so the file is damaged. " +
                "Nothing here was changed.");
        }

        var key = openKey.AsSpan(0, keyLength).ToArray();
        CryptographicOperations.ZeroMemory(openKey);

        var previous = ParsePreviousKeys(layout, config);
        try
        {
            var repository = new SipRepository(layout, config, new RepositoryCipher(key, previous), key, previous);
            repository.EncryptLegacySnapshots();
            return repository;
        }
        finally
        {
            // The repository keeps its own copies; these were only the decoding buffers.
            CryptographicOperations.ZeroMemory(key);
            foreach (var older in previous)
            {
                CryptographicOperations.ZeroMemory(older);
            }
        }
    }

    /// <summary>The older keys of a config's ring, decoded, oldest first (D-70).</summary>
    /// <exception cref="RepositoryUnreadableException">One of them is not a repository key.</exception>
    private static List<byte[]> ParsePreviousKeys(RepositoryLayout layout, RepositoryConfig config)
    {
        var previous = new List<byte[]>();
        foreach (var stored in config.PreviousKeys ?? [])
        {
            byte[] older;
            try
            {
                older = Convert.FromBase64String(stored ?? string.Empty);
            }
            catch (FormatException)
            {
                older = [];
            }

            if (older.Length != RepositoryCipher.KeySize)
            {
                throw new RepositoryUnreadableException(
                    layout.WorkingRoot,
                    RepositoryUnreadableReason.DamagedKey,
                    $"an older key in its config file, {layout.ConfigFile}, is not a " +
                    $"{RepositoryCipher.KeySize}-byte repository key, so the file is damaged. " +
                    "Nothing here was changed.");
            }

            previous.Add(older);
        }

        return previous;
    }

    /// <summary>Opens a repository whose copy on this machine is locked.</summary>
    /// <param name="directory">A folder inside a repository.</param>
    /// <param name="passphrase">The passphrase that locked it.</param>
    /// <returns>The opened repository, unlocked for as long as it is held.</returns>
    /// <exception cref="RepositoryNotFoundException">No repository was found.</exception>
    /// <exception cref="RepositoryUnreadableException">
    /// One was found and cannot be opened: its config is damaged or from a newer build.
    /// </exception>
    /// <exception cref="WrongPassphraseException">The passphrase did not open it.</exception>
    /// <remarks>
    /// The key lives in this object's memory from here until it is disposed. That is the
    /// only model compatible with a daemon that polls every sixty seconds — the alternative
    /// is prompting on every poll, which nobody would tolerate — and its limit should be
    /// stated wherever the feature is described: it protects a powered-off or logged-out
    /// machine and a copied config file, and it does nothing against anything running as the
    /// user while the session is unlocked.
    /// </remarks>
    public static SipRepository Unlock(string directory, string passphrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        var (layout, config) = ReadConfig(directory);

        if (config.WrappedKey is null)
        {
            // Not locked. Opening it anyway is friendlier than refusing on a technicality —
            // the caller asked for an open repository and there is one.
            return Open(directory);
        }

        var unwrapped = PassphraseLock.Unwrap(config.WrappedKey, passphrase);
        byte[]? keyMaterial = null;
        List<byte[]>? previous = null;

        try
        {
            (keyMaterial, previous) = SplitRing(layout, unwrapped);
            var repository = new SipRepository(
                layout, config, new RepositoryCipher(keyMaterial, previous), keyMaterial, previous);
            repository.EncryptLegacySnapshots();
            return repository;
        }
        finally
        {
            // The repository keeps its own copies; these were only the decoding buffers.
            CryptographicOperations.ZeroMemory(unwrapped);
            if (keyMaterial is not null)
            {
                CryptographicOperations.ZeroMemory(keyMaterial);
            }

            foreach (var older in previous ?? [])
            {
                CryptographicOperations.ZeroMemory(older);
            }
        }
    }

    /// <summary>
    /// Splits an unwrapped ring — every key concatenated, oldest first, current last — back
    /// into its keys. A wrapping from before rotation existed is exactly one key, and splits
    /// to a ring of one.
    /// </summary>
    /// <exception cref="RepositoryUnreadableException">The payload is not whole keys.</exception>
    private static (byte[] Current, List<byte[]> Previous) SplitRing(RepositoryLayout layout, byte[] unwrapped)
    {
        if (unwrapped.Length == 0 || unwrapped.Length % RepositoryCipher.KeySize != 0)
        {
            throw new RepositoryUnreadableException(
                layout.WorkingRoot,
                RepositoryUnreadableReason.DamagedKey,
                $"the passphrase opened its config file, {layout.ConfigFile}, and what is inside is not a " +
                "key ring, so the file is damaged. Nothing here was changed.");
        }

        var keys = new List<byte[]>();
        for (var offset = 0; offset < unwrapped.Length; offset += RepositoryCipher.KeySize)
        {
            keys.Add(unwrapped.AsSpan(offset, RepositoryCipher.KeySize).ToArray());
        }

        var current = keys[^1];
        keys.RemoveAt(keys.Count - 1);
        return (current, keys);
    }

    /// <summary>Reads and validates a repository's config without opening it.</summary>
    /// <remarks>
    /// <para>
    /// Two different failures, two different exceptions: no <c>config.json</c> anywhere
    /// above <paramref name="directory"/> is <see cref="RepositoryNotFoundException"/>, and a
    /// <c>config.json</c> that is there but cannot be used is
    /// <see cref="RepositoryUnreadableException"/>. A JSON error is wrapped rather than left
    /// to escape, because the tray catches repository failures by type and a raw
    /// <see cref="JsonException"/> from a hand-edited config would have crashed it at start.
    /// </para>
    /// <para>
    /// The format version is read on its own, before the rest of the file is bound to this
    /// build's <see cref="RepositoryConfig"/>. A newer build may add a mode or change a
    /// field's type, and binding such a file fails before its version is ever looked at: it
    /// was reported as a damaged config, with the hint that only this machine's copy was
    /// affected, when the remedy was to update SippBucket.
    /// </para>
    /// </remarks>
    private static (RepositoryLayout Layout, RepositoryConfig Config) ReadConfig(string directory)
    {
        var layout = RepositoryLayout.Discover(directory)
            ?? throw new RepositoryNotFoundException(Path.GetFullPath(directory));

        RepositoryConfig? config;
        try
        {
            var text = SharingRetry.Run(() => File.ReadAllText(layout.ConfigFile));

            if (NewerFormatVersion(text) is { } newer)
            {
                throw NewerFormat(layout, newer);
            }

            config = JsonSerializer.Deserialize<RepositoryConfig>(text, SipJson.Readable);
        }
        catch (JsonException ex)
        {
            throw new RepositoryUnreadableException(
                layout.WorkingRoot,
                RepositoryUnreadableReason.DamagedConfig,
                $"its config file, {layout.ConfigFile}, is not valid: {ex.Message} " +
                "Nothing here was changed.",
                ex);
        }

        if (config is null)
        {
            throw new RepositoryUnreadableException(
                layout.WorkingRoot,
                RepositoryUnreadableReason.DamagedConfig,
                $"its config file, {layout.ConfigFile}, holds no settings. Nothing here was changed.");
        }

        if (config.FormatVersion > RepositoryConfig.MaximumReadableFormatVersion)
        {
            throw NewerFormat(layout, config.FormatVersion);
        }

        return (layout, config);
    }

    /// <summary>
    /// The config's <c>formatVersion</c>, when it is a number above what this build reads.
    /// </summary>
    /// <returns>That version, or null: not newer, not a number, or not there to read.</returns>
    /// <exception cref="JsonException">The text is not JSON at all.</exception>
    /// <remarks>
    /// Matched exactly as the serializer matches it, case and all, so that a file this
    /// build would read is never called newer than it is.
    /// </remarks>
    private static long? NewerFormatVersion(string text)
    {
        using var document = JsonDocument.Parse(text);

        return document.RootElement.ValueKind == JsonValueKind.Object &&
               document.RootElement.TryGetProperty("formatVersion", out var version) &&
               version.ValueKind == JsonValueKind.Number &&
               version.TryGetInt64(out var number) &&
               number > RepositoryConfig.MaximumReadableFormatVersion
            ? number
            : null;
    }

    private static RepositoryUnreadableException NewerFormat(RepositoryLayout layout, long version) =>
        new(
            layout.WorkingRoot,
            RepositoryUnreadableReason.NewerFormat,
            $"it was written by a newer SippBucket (format version {version}; " +
            $"this build reads up to {RepositoryConfig.MaximumReadableFormatVersion}). " +
            "Update SippBucket on this machine to open it. Nothing here was changed.");

    /// <summary>Whether this machine's copy of a repository is locked.</summary>
    /// <param name="directory">A folder inside a repository.</param>
    /// <returns>True when a passphrase is needed to open it.</returns>
    /// <exception cref="RepositoryNotFoundException">No repository was found.</exception>
    /// <exception cref="RepositoryUnreadableException">
    /// One was found and its config cannot be read.
    /// </exception>
    public static bool IsLockedAt(string directory) => ReadConfig(directory).Config.IsLocked;

    /// <summary>True while this repository is open with its key in memory.</summary>
    /// <remarks>
    /// Reports that the repository <em>has</em> a passphrase, not that it is currently
    /// sealed — if this object exists, the key is available to it. The interface uses this
    /// to say "locked on this machine" rather than to decide whether it can read anything.
    /// </remarks>
    public bool IsLocked => Config.IsLocked;

    /// <summary>Puts this machine's copy behind a passphrase.</summary>
    /// <param name="passphrase">The passphrase to lock it with.</param>
    /// <exception cref="ArgumentException">The passphrase was empty.</exception>
    /// <exception cref="InvalidOperationException">It is already locked.</exception>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// The repository stays usable afterwards: this object keeps the key it already holds.
    /// Only the file on disk changes, which is the point — the passphrase protects the copy
    /// at rest, not the process that is running.
    /// </remarks>
    public void SetPassphrase(string passphrase)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        using var operation = new OperationScope(this, LockOperation(FolderOperation.Passphrase));

        if (Config.IsLocked)
        {
            throw new InvalidOperationException(
                "This copy is already locked. Remove the existing passphrase first.");
        }

        // The whole ring is sealed, oldest first with the current key last (D-70): older
        // keys left in the clear beside a wrapped current one would leave everything written
        // before the last rotation readable, which is most of the folder.
        var ring = ConcatenatedRing();

        try
        {
            Config = Config with
            {
                FormatVersion = RepositoryConfig.LockedFormatVersion,
                EncryptionKey = null,
                PreviousKeys = null,
                WrappedKey = PassphraseLock.Wrap(ring, passphrase),
            };

            WriteConfigOverwritingInPlace();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ring);
        }
    }

    /// <summary>Every key of the ring concatenated, oldest first, the current key last.</summary>
    private byte[] ConcatenatedRing()
    {
        lock (_keyGate)
        {
            var ring = new byte[(_previousKeys.Count + 1) * RepositoryCipher.KeySize];
            var offset = 0;
            foreach (var older in _previousKeys)
            {
                older.CopyTo(ring.AsSpan(offset));
                offset += RepositoryCipher.KeySize;
            }

            _keyMaterial.CopyTo(ring.AsSpan(offset));
            return ring;
        }
    }

    /// <summary>Takes the passphrase off this machine's copy, storing the key in the clear again.</summary>
    /// <param name="passphrase">The current passphrase, which must be correct.</param>
    /// <exception cref="ArgumentException">The passphrase was empty.</exception>
    /// <exception cref="InvalidOperationException">It is not locked.</exception>
    /// <exception cref="WrongPassphraseException">The passphrase did not open it.</exception>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// The current passphrase is required even though this object already holds the key.
    /// Nothing technical demands it — the check exists so that walking away from an unlocked
    /// machine does not hand a passer-by the ability to silently remove its protection.
    /// </remarks>
    public void RemovePassphrase(string passphrase)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        using var operation = new OperationScope(this, LockOperation(FolderOperation.Passphrase));

        if (Config.WrappedKey is not { } wrapped)
        {
            throw new InvalidOperationException("This copy is not locked.");
        }

        var unwrapped = PassphraseLock.Unwrap(wrapped, passphrase);

        try
        {
            var (current, previous) = SplitRing(Layout, unwrapped);
            Config = Config with
            {
                FormatVersion = RepositoryConfig.CurrentFormatVersion,
                EncryptionKey = Convert.ToBase64String(current),
                PreviousKeys = previous.Count == 0 ? null : [.. previous.Select(Convert.ToBase64String)],
                WrappedKey = null,
            };

            WriteConfigOverwritingInPlace();

            CryptographicOperations.ZeroMemory(current);
            foreach (var older in previous)
            {
                CryptographicOperations.ZeroMemory(older);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(unwrapped);
        }
    }

    /// <summary>How many keys this folder's ring holds: 1 before any rotation (D-70).</summary>
    public int KeyGeneration
    {
        get
        {
            lock (_keyGate)
            {
                return 1 + _previousKeys.Count;
            }
        }
    }

    /// <summary>The whole ring, base64, oldest first, the current key last: what a key update carries.</summary>
    /// <remarks>
    /// Internal on purpose, and a test enforces it: this is the repository key, and the only
    /// callers with any business reading it are the sync paths that carry a key update to
    /// another machine (D-70). Public, it was one property read away from any embedder.
    /// </remarks>
    internal IReadOnlyList<string> KeyRing
    {
        get
        {
            lock (_keyGate)
            {
                return [.. _previousKeys.Select(Convert.ToBase64String), Convert.ToBase64String(_keyMaterial)];
            }
        }
    }

    /// <summary>The devices rotations have revoked here, lowercase hexadecimal.</summary>
    public IReadOnlyList<string> RevokedDevices => Config.RevokedDevices ?? [];

    /// <summary>Whether a device has been revoked from this folder (D-70).</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>True when a rotation revoked it. It is never served or dialled again.</returns>
    public bool IsRevoked(string deviceId) =>
        !string.IsNullOrWhiteSpace(deviceId) &&
        RevokedDevices.Any(revoked => string.Equals(revoked, deviceId, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Rotates this folder's key: a fresh key becomes current, everything written from now on
    /// is under it, and the devices named are revoked for good (D-70).
    /// </summary>
    /// <param name="revokeDeviceIds">The devices this rotation removes. May be empty for a plain rotation.</param>
    /// <returns>The ring's new generation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="revokeDeviceIds"/> was null.</exception>
    /// <exception cref="InvalidOperationException">
    /// This machine's copy is locked: rotating would need the passphrase to reseal the ring.
    /// Unlock first.
    /// </exception>
    /// <remarks>
    /// <para>
    /// What rotation does and does not do, stated because the alternative is implying more: it
    /// stops the removed machines reading anything written <em>after</em> it, once every
    /// remaining machine has learned of it (their next sync). It cannot un-share what was
    /// already shared: the removed machine holds, or could already have copied, everything
    /// written before, and the old keys stay in the ring here precisely because those bytes
    /// are not rewritten.
    /// </para>
    /// <para>
    /// The revoked devices are dropped from this folder's peer list now, and travel with
    /// every key update, so each remaining machine drops them before it stores the new key —
    /// which is what stops a machine that has not heard yet from handing the new key to the
    /// removed one.
    /// </para>
    /// </remarks>
    public int RotateKey(IReadOnlyList<string> revokeDeviceIds)
    {
        ArgumentNullException.ThrowIfNull(revokeDeviceIds);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Config.IsLocked)
        {
            throw new InvalidOperationException(
                "This machine's copy is locked, and rotating the key would need the passphrase to reseal it. " +
                "Unlock this copy ('sip lock --off'), rotate, then lock it again. Nothing was changed.");
        }

        lock (_keyGate)
        {
            var fresh = RepositoryCipher.CreateKey();
            _previousKeys.Add(_keyMaterial);
            _keyMaterial = fresh;

            _cipher.ReplaceRing([.. _previousKeys, _keyMaterial]);

            Config = Config with
            {
                EncryptionKey = Convert.ToBase64String(_keyMaterial),
                PreviousKeys = [.. _previousKeys.Select(Convert.ToBase64String)],
                RevokedDevices = MergedRevoked(revokeDeviceIds),
            };

            WriteConfigOverwritingInPlace();
        }

        foreach (var device in revokeDeviceIds)
        {
            _ = Peers.Remove(device);
        }

        return KeyGeneration;
    }

    /// <summary>What <see cref="ApplyKeyUpdate"/> decided about a ring learned from a peer.</summary>
    public enum KeyUpdateOutcome
    {
        /// <summary>The peer's ring is this folder's ring, or behind it. Nothing changed.</summary>
        Unchanged = 0,

        /// <summary>The peer's ring extends this folder's, and was adopted.</summary>
        Adopted = 1,

        /// <summary>
        /// Two machines rotated at the same time. The rings were merged the same way on both,
        /// so they converge; every key of both stays readable.
        /// </summary>
        Merged = 2,

        /// <summary>
        /// This machine's copy is locked, so the update could not be stored. It is applied at
        /// the first sync after this copy is unlocked.
        /// </summary>
        DeferredLocked = 3,

        /// <summary>The update does not contain this folder's history and was refused.</summary>
        Refused = 4,
    }

    /// <summary>
    /// Takes a key ring learned from a peer (D-70): adopts it when it extends this folder's,
    /// merges when two machines rotated at once, and refuses one that does not contain this
    /// folder's own keys.
    /// </summary>
    /// <param name="keys">The peer's ring, base64, oldest first, current last.</param>
    /// <param name="revoked">The devices the peer's rotations revoked.</param>
    /// <param name="log">Optional sink for one line about what happened.</param>
    /// <returns>What was decided.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <remarks>
    /// <para>
    /// The update is trusted as far as its channel: it arrives only over an authenticated
    /// connection from a machine in this folder's peer list, which already holds every key.
    /// The containment rule — the update must carry this folder's current ring inside it —
    /// stops a confused or hostile peer replacing history it never had; what no rule here can
    /// stop is a machine that is <em>about to be</em> removed racing a rotation of its own,
    /// because until the update lands it is still a member. That is the compromise-window any
    /// shared-key design has, and it is stated rather than hidden.
    /// </para>
    /// <para>
    /// The revoked devices are dropped from the peer list before the new ring is stored, so
    /// this machine can never hand the new key to a machine the rotation removed.
    /// </para>
    /// </remarks>
    public KeyUpdateOutcome ApplyKeyUpdate(IReadOnlyList<string> keys, IReadOnlyList<string> revoked, Action<string>? log)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(revoked);
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Bounded and decoded before anything is compared: the update is a peer's input.
        if (keys.Count is 0 or > Protocol.KeyUpdateMessage.MaximumKeys ||
            revoked.Count > Protocol.KeyUpdateMessage.MaximumRevoked)
        {
            log?.Invoke("a key update was refused: it is outside the bounds a ring can have");
            return KeyUpdateOutcome.Refused;
        }

        var theirs = new List<byte[]>(keys.Count);
        foreach (var stored in keys)
        {
            byte[] key;
            try
            {
                key = Convert.FromBase64String(stored ?? string.Empty);
            }
            catch (FormatException)
            {
                key = [];
            }

            if (key.Length != RepositoryCipher.KeySize)
            {
                log?.Invoke("a key update was refused: it holds something that is not a repository key");
                return KeyUpdateOutcome.Refused;
            }

            theirs.Add(key);
        }

        if (Config.IsLocked)
        {
            log?.Invoke(
                "the folder's key was rotated on another machine, and this machine's copy is locked, so the new " +
                "key waits until it is unlocked");
            return KeyUpdateOutcome.DeferredLocked;
        }

        // The revoked go first, whatever the rings decide: a machine that has heard of the
        // removal at all must never serve or dial the removed again.
        foreach (var device in revoked)
        {
            if (!string.IsNullOrWhiteSpace(device))
            {
                _ = Peers.Remove(device);
            }
        }

        lock (_keyGate)
        {
            var mine = new List<byte[]>(_previousKeys) { _keyMaterial };

            var outcome = MergeRings(mine, theirs, out var merged);
            if (outcome == KeyUpdateOutcome.Refused)
            {
                log?.Invoke(
                    "a key update was refused: it does not contain this folder's own keys, so it is not a " +
                    "rotation of this folder");
                return KeyUpdateOutcome.Refused;
            }

            if (outcome != KeyUpdateOutcome.Unchanged)
            {
                _previousKeys = [.. merged.Take(merged.Count - 1)];
                _keyMaterial = merged[^1];
                _cipher.ReplaceRing(merged);
                log?.Invoke(outcome == KeyUpdateOutcome.Adopted
                    ? "the folder's key was rotated on another machine; this machine now writes under the new key"
                    : "two machines rotated the folder's key at the same time; the rings were merged, and every key stays readable");
            }

            if (outcome != KeyUpdateOutcome.Unchanged || RevokedGrewBy(revoked))
            {
                Config = Config with
                {
                    EncryptionKey = Convert.ToBase64String(_keyMaterial),
                    PreviousKeys = _previousKeys.Count == 0 ? null : [.. _previousKeys.Select(Convert.ToBase64String)],
                    RevokedDevices = MergedRevoked(revoked),
                };
                WriteConfigOverwritingInPlace();
            }

            return outcome;
        }
    }

    /// <summary>Whether a revocation list adds any device this config does not already have.</summary>
    private bool RevokedGrewBy(IReadOnlyList<string> revoked) =>
        revoked.Any(device => !string.IsNullOrWhiteSpace(device) && !IsRevoked(device));

    /// <summary>This config's revoked devices with more added, each once, order kept.</summary>
    private List<string>? MergedRevoked(IReadOnlyList<string> adding)
    {
        var merged = new List<string>(RevokedDevices);
        foreach (var device in adding)
        {
            if (!string.IsNullOrWhiteSpace(device) && !merged.Any(known => string.Equals(known, device, StringComparison.OrdinalIgnoreCase)))
            {
#pragma warning disable CA1308 // Device IDs are identifiers; lowercase hex is their record form.
                merged.Add(device.ToLowerInvariant());
#pragma warning restore CA1308
            }
        }

        return merged.Count == 0 ? null : merged;
    }

    /// <summary>
    /// Decides between two rings that both start from this folder's original key.
    /// </summary>
    /// <param name="mine">This folder's ring, oldest first, current last.</param>
    /// <param name="theirs">The peer's.</param>
    /// <param name="merged">The ring to hold from now on, when anything changes.</param>
    /// <returns>Unchanged, Adopted, Merged, or Refused.</returns>
    /// <remarks>
    /// A ring only ever grows by appending, so two honest rings share a prefix. Theirs equal
    /// to or inside mine changes nothing; mine inside theirs adopts theirs; two rings that
    /// diverge after a shared prefix are two rotations made at the same moment, and both
    /// machines merge them identically — the shared prefix, then every remaining key of
    /// either, ordered by their raw bytes — so the fleet converges on one current key without
    /// anyone coordinating. A ring that does not contain this folder's first keys is not a
    /// rotation of this folder, and is refused.
    /// </remarks>
    private static KeyUpdateOutcome MergeRings(List<byte[]> mine, List<byte[]> theirs, out List<byte[]> merged)
    {
        var shared = 0;
        while (shared < mine.Count && shared < theirs.Count && mine[shared].AsSpan().SequenceEqual(theirs[shared]))
        {
            shared++;
        }

        if (shared == 0)
        {
            merged = mine;
            return KeyUpdateOutcome.Refused;
        }

        if (shared == theirs.Count)
        {
            // Theirs is mine, or inside it: they are behind, and the status answer tells them.
            merged = mine;
            return KeyUpdateOutcome.Unchanged;
        }

        if (shared == mine.Count)
        {
            merged = theirs;
            return KeyUpdateOutcome.Adopted;
        }

        var tails = mine.Skip(shared).Concat(theirs.Skip(shared))
            .DistinctBy(Convert.ToBase64String)
            .OrderBy(key => key, ByteArrayOrder.Instance)
            .ToList();

        merged = [.. mine.Take(shared), .. tails];
        return KeyUpdateOutcome.Merged;
    }

    /// <summary>Raw-byte ordering, so two machines merging the same rings agree without talking.</summary>
    private sealed class ByteArrayOrder : IComparer<byte[]>
    {
        public static ByteArrayOrder Instance { get; } = new();

        public int Compare(byte[]? x, byte[]? y) =>
            x is null ? (y is null ? 0 : -1) : y is null ? 1 : x.AsSpan().SequenceCompareTo(y);
    }

    /// <summary>
    /// Writes the config over the existing file rather than replacing it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately <em>not</em> write-to-temp-and-rename, which is the usual correct
    /// pattern and the wrong one here. A rename leaves the previous file's contents in
    /// whatever blocks the filesystem had allocated to it, and the previous contents of this
    /// particular file are the repository key in clear text. Locking a repository would then
    /// mean the key is no longer in the file but is still on the disk, which is a security
    /// feature that does not do the thing it says.
    /// </para>
    /// <para>
    /// The cost is honest and worth naming: overwriting in place gives up atomicity, so a
    /// crash mid-write can leave a truncated config. That is recoverable — the key also
    /// exists on any other replica, and a truncated config is loudly broken rather than
    /// quietly wrong. A leaked key is neither recoverable nor loud.
    /// </para>
    /// <para>
    /// This does not defeat a copy-on-write filesystem, an SSD's wear levelling, or a prior
    /// backup. It removes the easy recovery, not every recovery, and the help text should
    /// not claim more.
    /// </para>
    /// <para>
    /// Another program's brief hold on the file is waited out (D-69). Only the open can meet
    /// a sharing violation, and nothing has been written by then, so trying it again from the
    /// start is safe.
    /// </para>
    /// </remarks>
    private void WriteConfigOverwritingInPlace()
    {
        var json = JsonSerializer.Serialize(Config, SipJson.Readable);
        var bytes = System.Text.Encoding.UTF8.GetBytes(json);

        using var file = SharingRetry.Run(() => new FileStream(
            Layout.ConfigFile, FileMode.Open, FileAccess.Write, FileShare.None));

        // Pad over whatever the old file held before truncating, so the tail of a longer
        // previous version is overwritten rather than merely orphaned.
        var previousLength = file.Length;
        file.Write(bytes);

        if (previousLength > bytes.Length)
        {
            var padding = new byte[previousLength - bytes.Length];
            Array.Fill(padding, (byte)' ');
            file.Write(padding);
        }

        file.Flush(flushToDisk: true);
        file.SetLength(bytes.Length);
        file.Flush(flushToDisk: true);
    }

    /// <summary>
    /// Rewrites any snapshot still stored as plaintext JSON by an older build.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reading the old format would have been enough to keep working repositories working,
    /// and would have left every filename, size and timestamp they already hold readable on
    /// disk forever. That is the leak, not the format — a fix that only applies to snapshots
    /// taken from now on does not fix anything a user already has.
    /// </para>
    /// <para>
    /// Failures are counted rather than thrown. A snapshot that cannot be rewritten — a file
    /// held open, a folder gone read-only — is still perfectly readable, so failing to open
    /// the repository over it would turn a privacy improvement into an outage. The count is
    /// exposed so that the caller can say so instead of the program deciding silently that
    /// it does not matter.
    /// </para>
    /// </remarks>
    private void EncryptLegacySnapshots()
    {
        if (!Directory.Exists(Layout.SnapshotsDirectory))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFiles(Layout.SnapshotsDirectory, "*.json"))
        {
            byte[] stored;
            try
            {
                stored = SharingRetry.Run(() => File.ReadAllBytes(path));
            }
            catch (IOException)
            {
                LegacySnapshotsLeftPlaintext++;
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                LegacySnapshotsLeftPlaintext++;
                continue;
            }

            if (SnapshotFile.IsEncrypted(stored))
            {
                continue;
            }

            if (!ContentHash.TryParse(Path.GetFileNameWithoutExtension(path), out var id))
            {
                LegacySnapshotsLeftPlaintext++;
                continue;
            }

            try
            {
                // A canonical snapshot found in plaintext is kept whole, so it stays readable
                // whether or not its trees are here; no build writes one, so it is only ever
                // one put back by hand.
                var snapshot = SnapshotFile.Unprotect(stored, id, _cipher);
                var protectedBytes = snapshot.Format == SnapshotFormat.Canonical && snapshot.Files.Count > 0
                    ? SnapshotFile.ProtectWhole(snapshot, id, _cipher)
                    : SnapshotFile.Protect(snapshot, id, _cipher);
                SharingRetry.Run(() => File.WriteAllBytes(path, protectedBytes));
                LegacySnapshotsEncrypted++;
            }
            catch (SnapshotNotFoundException)
            {
                LegacySnapshotsLeftPlaintext++;
            }
            catch (IOException)
            {
                LegacySnapshotsLeftPlaintext++;
            }
            catch (UnauthorizedAccessException)
            {
                LegacySnapshotsLeftPlaintext++;
            }
        }
    }

    /// <summary>How many plaintext snapshots were encrypted when this repository was opened.</summary>
    public int LegacySnapshotsEncrypted { get; private set; }

    /// <summary>
    /// How many plaintext snapshots could not be encrypted on open, and so still have their
    /// filenames, sizes and timestamps readable on disk.
    /// </summary>
    public int LegacySnapshotsLeftPlaintext { get; private set; }

    /// <summary>
    /// The IDs and parents of every snapshot this replica has made, received or merged onto,
    /// including the ones Simple mode or a retention policy has since deleted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Opened on first use rather than when the repository is, so commands that never ask
    /// about history do not pay for it. A repository written before the index existed has no
    /// <c>.sip/ancestry</c>, and one is rebuilt from the snapshot files it does have — which
    /// in Simple mode is only the newest, so the rebuilt index knows only what survived.
    /// </para>
    /// <para>
    /// First use also walks back from head through any snapshot the index does not yet
    /// know. That costs one lookup when the two agree, and it repairs the index after an
    /// older build has saved into this folder without knowing the file exists.
    /// </para>
    /// </remarks>
    public AncestryIndex Ancestry
    {
        get
        {
            lock (_ancestryGate)
            {
                if (_ancestry is null)
                {
                    var index = AncestryIndex.TryOpen(Layout.AncestryFile) ?? RebuildAncestry();
                    IndexBackFromHead(index);
                    _ancestry = index;
                }

                return _ancestry;
            }
        }
    }

    /// <summary>
    /// How many snapshot files could not be read while the ancestry index was being built,
    /// and so are missing from it.
    /// </summary>
    /// <remarks>
    /// Counted rather than thrown. A snapshot that cannot be decrypted or parsed already
    /// fails loudly wherever it is read; refusing to build the index over it would stop the
    /// folder syncing at all, and an index missing one entry costs a merge its nearest base
    /// at worst — every decision made without ancestry keeps both versions.
    /// </remarks>
    public int UnindexedSnapshots { get; private set; }

    /// <summary>Builds the ancestry index from the snapshot files present.</summary>
    private AncestryIndex RebuildAncestry()
    {
        var entries = new List<AncestryEntry>();

        if (Directory.Exists(Layout.SnapshotsDirectory))
        {
            foreach (var path in Directory.EnumerateFiles(Layout.SnapshotsDirectory, "*.json"))
            {
                if (ContentHash.TryParse(Path.GetFileNameWithoutExtension(path), out var id) &&
                    TryReadSnapshotForIndex(id, out var snapshot))
                {
                    entries.Add(AncestryEntry.For(id, snapshot));
                }
            }
        }

        return AncestryIndex.Create(Layout.AncestryFile, entries);
    }

    /// <summary>
    /// Adds head, and every ancestor of it that is present as a file, to the index if the
    /// index does not know them.
    /// </summary>
    private void IndexBackFromHead(AncestryIndex index)
    {
        var missing = new List<AncestryEntry>();
        var seen = new HashSet<ContentHash>();
        var pending = new Stack<ContentHash>();
        pending.Push(GetHead());

        while (pending.Count > 0)
        {
            var id = pending.Pop();
            if (id.IsEmpty || !seen.Add(id) || index.Contains(id) || !HasSnapshot(id) ||
                !TryReadSnapshotForIndex(id, out var snapshot))
            {
                continue;
            }

            missing.Add(AncestryEntry.For(id, snapshot));
            pending.Push(snapshot.ParentId);
            pending.Push(snapshot.MergeParentId);
        }

        index.Add(missing);
    }

    private bool TryReadSnapshotForIndex(ContentHash id, [NotNullWhen(true)] out Snapshot? snapshot)
    {
        try
        {
            var path = SnapshotPath(id);
            snapshot = SnapshotFile.Unprotect(SharingRetry.Run(() => File.ReadAllBytes(path)), id, _cipher);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or SnapshotNotFoundException or CorruptBlockException)
        {
            UnindexedSnapshots++;
            snapshot = null;
            return false;
        }
    }

    /// <summary>The newest snapshot's hash, empty when nothing has been saved yet.</summary>
    /// <returns>The head snapshot ID.</returns>
    public ContentHash GetHead()
    {
        lock (_headGate)
        {
            if (!File.Exists(Layout.HeadFile))
            {
                return default;
            }

            var text = SharingRetry.Run(() => File.ReadAllText(Layout.HeadFile)).Trim();
            return ContentHash.TryParse(text, out var hash) ? hash : default;
        }
    }

    /// <summary>Points head at a snapshot.</summary>
    /// <param name="snapshotId">The snapshot to make current.</param>
    /// <remarks>
    /// Reads and writes of head share one gate. The daemon's server reads head on every poll
    /// it answers while its sync engine moves head at the end of every pull, and Windows
    /// refuses one while the other has the file: a write that lost failed a pull whose files
    /// had already been applied, and a read part way through a write saw an empty head —
    /// which is how a peer that has never saved answers. The gate cannot order another
    /// process: a brief hold by one, such as a scanner reading the file just written, is
    /// waited out by <see cref="SharingRetry"/>, and a longer one is reported.
    /// <para>
    /// This is the primitive, and it does not take the folder's <see cref="OperationLock"/>
    /// itself: every operation that moves head holds it already, <see cref="AdvanceHeadAsync"/>
    /// and <see cref="RestoreAsync"/> included, and those are how anything outside this class
    /// should move head. Taking it here as well was measured to starve this method against a
    /// concurrent reader of head (the ancestry index's head test fell under a hundred moves in
    /// two seconds), because the time spent opening the lock falls between two acquisitions
    /// of the gate, and a reader in a loop takes the gate in that time. The gate stays
    /// alongside the lock because the lock orders writers only, and the gate is what keeps
    /// the server's reads of head from meeting a write half done.
    /// </para>
    /// </remarks>
    public void SetHead(ContentHash snapshotId)
    {
        var text = snapshotId.IsEmpty ? string.Empty : snapshotId.ToString();
        lock (_headGate)
        {
            SharingRetry.Run(() => File.WriteAllText(Layout.HeadFile, text));
        }
    }

    /// <summary>True when a snapshot is present locally.</summary>
    /// <param name="snapshotId">The snapshot to look for.</param>
    /// <returns>True when the snapshot file exists.</returns>
    /// <remarks>
    /// An answer about one instant. In Simple mode a save in another process can trim the
    /// file a moment later, so code that means to read the snapshot should call
    /// <see cref="TryGetSnapshotAsync(ContentHash, CancellationToken)"/> once rather than
    /// asking this first (D-57).
    /// </remarks>
    public bool HasSnapshot(ContentHash snapshotId) => File.Exists(SnapshotPath(snapshotId));

    /// <summary>Reads a snapshot by ID.</summary>
    /// <param name="snapshotId">The snapshot to read.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The snapshot.</returns>
    /// <exception cref="SnapshotNotFoundException">The snapshot is not present.</exception>
    public async Task<Snapshot> GetSnapshotAsync(
        ContentHash snapshotId,
        CancellationToken cancellationToken = default) =>
        await TryGetSnapshotAsync(snapshotId, cancellationToken).ConfigureAwait(false)
        ?? throw new SnapshotNotFoundException(snapshotId);

    /// <summary>Reads a snapshot by ID, or answers null when it is not here.</summary>
    /// <param name="snapshotId">The snapshot to read.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The snapshot, or null when no file holds it.</returns>
    /// <remarks>
    /// <para>
    /// One read, and "not here" decided by that read (D-57). The peer server used to ask
    /// <see cref="HasSnapshot"/> and then read, and a Simple-mode save that trimmed the file
    /// between the two turned a question with an ordinary answer, "I do not have that", into
    /// a dropped connection.
    /// </para>
    /// <para>
    /// What the read finds is whole.
    /// <see cref="WriteSnapshotAsync(Snapshot, CancellationToken)"/> renames a snapshot to its
    /// content hash only once the whole file is written, and a trim cannot delete it part way
    /// through the read, because the read shares no delete access. The one exception is the
    /// one-time encryption of a snapshot an older build stored as plaintext, which rewrites
    /// that file in place when the repository is opened (<c>EncryptLegacySnapshots</c>).
    /// </para>
    /// <para>
    /// A file another program holds for a moment is waited out (D-69).
    /// </para>
    /// <para>
    /// A canonical snapshot's files are read out of its trees in the block store (D-23), each
    /// tree checked against its hash as every block is, so the files returned are the ones its
    /// ID covers. A tree that is missing or damaged is the store's damage, not an absent
    /// snapshot, and is thrown.
    /// </para>
    /// </remarks>
    /// <exception cref="SnapshotNotFoundException">The file is here and is not a readable snapshot, or its trees are not.</exception>
    /// <exception cref="CorruptBlockException">The file, or one of its trees, failed authentication.</exception>
    public Task<Snapshot?> TryGetSnapshotAsync(
        ContentHash snapshotId,
        CancellationToken cancellationToken = default) =>
        TryGetSnapshotAsync(snapshotId, new Dictionary<ContentHash, byte[]>(), cancellationToken);

    /// <summary>
    /// Reads a snapshot, taking its trees from <paramref name="trees"/> where they are already
    /// there and adding those it reads, so a walk over many snapshots reads each shared tree once.
    /// </summary>
    private async Task<Snapshot?> TryGetSnapshotAsync(
        ContentHash snapshotId,
        Dictionary<ContentHash, byte[]> trees,
        CancellationToken cancellationToken)
    {
        var stored = await TryGetStoredSnapshotAsync(snapshotId, cancellationToken).ConfigureAwait(false);
        if (stored is null || stored.Format != SnapshotFormat.Canonical || stored.Files.Count > 0)
        {
            return stored;
        }

        return stored with { Files = await ReadTreesAsync(snapshotId, stored.Tree, trees, cancellationToken).ConfigureAwait(false) };
    }

    /// <summary>
    /// Reads a snapshot as it is stored and as it travels: a canonical one names its tree and
    /// lists no files; a legacy one lists them. Null when it is not here.
    /// </summary>
    /// <param name="snapshotId">The snapshot to read.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The snapshot, or null when no file holds it.</returns>
    /// <exception cref="SnapshotNotFoundException">The file is here and is not a readable snapshot.</exception>
    /// <exception cref="CorruptBlockException">The file failed authentication.</exception>
    /// <remarks>
    /// What the server sends a peer, which fetches the trees it lacks (D-23). A canonical
    /// snapshot kept whole, which only the one-time encryption of a plaintext file writes, is
    /// answered with its header, and its trees are put in the block store first so the peer
    /// can fetch them.
    /// </remarks>
    public async Task<Snapshot?> TryGetStoredSnapshotAsync(
        ContentHash snapshotId,
        CancellationToken cancellationToken = default)
    {
        var path = SnapshotPath(snapshotId);

        byte[] stored;
        try
        {
            stored = await SharingRetry
                .RunAsync(token => File.ReadAllBytesAsync(path, token), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        var snapshot = SnapshotFile.Unprotect(stored, snapshotId, _cipher);
        if (snapshot.Format != SnapshotFormat.Canonical || snapshot.Files.Count == 0)
        {
            return snapshot;
        }

        SnapshotTrees? built;
        try
        {
            built = SnapshotTree.Build(snapshot.Files);
        }
        catch (ArgumentException)
        {
            built = null;
        }

        if (built is null || built.Root != snapshot.Tree)
        {
            throw new SnapshotNotFoundException(
                $"Snapshot {snapshotId.ToShortString()} is stored whole, and its files are not the ones its tree names.");
        }

        await StoreTreesAsync(built, cancellationToken).ConfigureAwait(false);
        return snapshot with { Files = [] };
    }

    /// <summary>Reads a canonical snapshot's files out of its trees, each checked against its hash.</summary>
    /// <param name="snapshotId">The snapshot, for the message when a tree is missing or damaged.</param>
    /// <param name="root">Its root tree.</param>
    /// <param name="trees">
    /// Trees already read, by hash, which are not read again; every tree this reads is added. A
    /// tree's bytes are fixed by its name, so one read for one snapshot serves any other.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <remarks>
    /// Each tree is checked against its hash as the files are read out (<see cref="SnapshotTree.Materialize"/>),
    /// whether it came from the store or from <paramref name="trees"/>. The walk stops at
    /// <see cref="SnapshotTree.MaximumDepth"/>, as a pull's does, whatever the store holds.
    /// </remarks>
    private async Task<IReadOnlyList<FileEntry>> ReadTreesAsync(
        ContentHash snapshotId,
        ContentHash root,
        Dictionary<ContentHash, byte[]> trees,
        CancellationToken cancellationToken)
    {
        var visited = new HashSet<ContentHash>();
        var level = new List<ContentHash> { root };

        try
        {
            for (var depth = 0; level.Count > 0; depth++)
            {
                if (depth >= SnapshotTree.MaximumDepth)
                {
                    throw new FormatException($"Its folders nest deeper than {SnapshotTree.MaximumDepth}.");
                }

                var next = new List<ContentHash>();
                foreach (var id in level)
                {
                    if (!visited.Add(id))
                    {
                        continue;
                    }

                    if (!trees.TryGetValue(id, out var bytes))
                    {
                        bytes = await Blobs.GetAsync(id, cancellationToken).ConfigureAwait(false);
                        trees[id] = bytes;
                    }

                    next.AddRange(SnapshotTree.FoldersOf(bytes));
                }

                level = next;
            }

            return SnapshotTree.Materialize(root, trees);
        }
        catch (Exception ex) when (ex is BlockNotFoundException or FormatException)
        {
            throw new SnapshotNotFoundException(
                $"Snapshot {snapshotId.ToShortString()} is here, and its trees are missing or damaged: {ex.Message}", ex);
        }
    }

    /// <summary>Puts every tree of a snapshot the block store lacks into it.</summary>
    private async Task StoreTreesAsync(SnapshotTrees built, CancellationToken cancellationToken)
    {
        foreach (var (id, bytes) in built.Trees)
        {
            if (!Blobs.Contains(id))
            {
                _ = await Blobs.PutAsync(bytes, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Reads the newest snapshot, or null when nothing has been saved.</summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The head snapshot, or null.</returns>
    public async Task<Snapshot?> GetHeadSnapshotAsync(CancellationToken cancellationToken = default)
    {
        var head = GetHead();
        if (head.IsEmpty)
        {
            return null;
        }

        return await GetSnapshotAsync(head, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Streams one recorded file's bytes out of the block store, each block checked against
    /// its hash as it is read.
    /// </summary>
    /// <param name="file">The file as a snapshot records it.</param>
    /// <param name="destination">Where the bytes go.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <exception cref="BlockNotFoundException">A block of the file is not held here.</exception>
    /// <exception cref="CorruptBlockException">A block failed authentication.</exception>
    /// <remarks>
    /// What <c>sip show</c> prints a file with. Streamed, because the file may be any size
    /// and the caller may be a console pipe; nothing here needs the whole file at once.
    /// </remarks>
    public async Task CopyFileToAsync(
        FileEntry file,
        Stream destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(destination);

        foreach (var hash in file.Blocks)
        {
            var plaintext = await Blobs.GetAsync(hash, cancellationToken).ConfigureAwait(false);
            await destination.WriteAsync(plaintext, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads one recorded file's bytes whole, for a diff or a blame.</summary>
    /// <param name="file">The file as a snapshot records it.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The file's content.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="file"/> was null.</exception>
    /// <exception cref="BlockNotFoundException">A block of the file is not held here.</exception>
    /// <exception cref="CorruptBlockException">A block failed authentication.</exception>
    public async Task<byte[]> ReadFileAsync(FileEntry file, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);

        using var buffer = new MemoryStream(
            file.Size is > 0 and <= int.MaxValue ? (int)file.Size : 0);
        await CopyFileToAsync(file, buffer, cancellationToken).ConfigureAwait(false);
        return buffer.ToArray();
    }

    /// <summary>
    /// Writes a snapshot and returns the ID it was filed under. The ID is the hash of the
    /// snapshot's canonical header, or of its canonical JSON for a legacy one, so an identical
    /// snapshot always has an identical ID.
    /// </summary>
    /// <param name="snapshot">The snapshot to store, with its files.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>The snapshot's content hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="snapshot"/> was null.</exception>
    /// <exception cref="ArgumentException">
    /// A canonical snapshot's files are not the ones its tree names, or cannot be a snapshot's.
    /// </exception>
    /// <remarks>
    /// <para>
    /// A canonical snapshot's trees go into the block store, only those it lacks: a folder
    /// nothing changed in keeps its tree, so a save writes the trees along the path to what
    /// changed and nothing else (D-23). Then its header is filed.
    /// </para>
    /// <para>
    /// The snapshot's parents go into <see cref="Ancestry"/> as well, and stay there after
    /// the file is trimmed. That is recorded even when the file already existed, so an index
    /// that lost a record catches up the next time the snapshot passes through.
    /// </para>
    /// <para>
    /// The file is written whole under a temporary name and then renamed to its content hash,
    /// as blocks are. It used to be written straight to that name, so a reader in another
    /// process, such as the peer server answering a request, could read it half written, and
    /// a crash part way through left a truncated file under a name that claims the whole
    /// snapshot, which nothing would ever rewrite, because a snapshot already present is
    /// never written again.
    /// </para>
    /// </remarks>
    public async Task<ContentHash> WriteSnapshotAsync(
        Snapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var built = snapshot.Format == SnapshotFormat.Canonical ? SnapshotTree.Build(snapshot.Files) : null;
        var (id, _) = await WriteSnapshotAsync(snapshot, built, cancellationToken).ConfigureAwait(false);
        return id;
    }

    /// <summary>Writes a snapshot whose trees the caller has built, so a save builds them once.</summary>
    /// <param name="snapshot">The snapshot, with its files.</param>
    /// <param name="built">Its trees, for a canonical snapshot; null for a legacy one.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>The snapshot's content hash, and the snapshot as filed: tree named, and signed when this machine signs it.</returns>
    private async Task<(ContentHash Id, Snapshot Stored)> WriteSnapshotAsync(
        Snapshot snapshot,
        SnapshotTrees? built,
        CancellationToken cancellationToken)
    {
        if ((snapshot.Format == SnapshotFormat.Canonical) != (built is not null))
        {
            throw new ArgumentException("A canonical snapshot is written with its trees, and only a canonical one.", nameof(built));
        }

        if (built is not null)
        {
            // Trees before the header, so a header on disk always names trees that are here.
            if (!snapshot.Tree.IsEmpty && snapshot.Tree != built.Root)
            {
                throw new ArgumentException("The snapshot's files are not the ones its tree names.", nameof(snapshot));
            }

            snapshot = snapshot with { Tree = built.Root };
            await StoreTreesAsync(built, cancellationToken).ConfigureAwait(false);
        }

        var id = ComputeSnapshotId(snapshot);

        // This machine's own snapshot is signed as it is written (D-21). The signature covers
        // the ID, which the header fixes, so signing after the ID is computed changes nothing
        // the ID covers. A snapshot another machine made keeps the signature it arrived with,
        // which is that machine's; this machine cannot make one for it, and never invents one.
        if (snapshot.Format == SnapshotFormat.Canonical && snapshot.Signature is null &&
            Signer is { } signer && DeviceIdentity.IsSameDevice(snapshot.DeviceId, signer.DeviceId))
        {
            snapshot = snapshot with { Signature = signer.Sign(id) };
        }

        var path = SnapshotPath(id);
        if (!File.Exists(path))
        {
            Directory.CreateDirectory(Layout.SnapshotsDirectory);
            _ = await WriteSnapshotFileAsync(path, SnapshotFile.Protect(snapshot, id, _cipher), cancellationToken)
                .ConfigureAwait(false);
        }

        Ancestry.Add([AncestryEntry.For(id, snapshot)]);
        return (id, snapshot);
    }

    /// <summary>
    /// Test seam: runs after a snapshot has been written to its temporary name and before it
    /// is renamed to its content hash, with the temporary file's path.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only: the one way to show that nothing is readable under a
    /// snapshot's name until the whole of it is written is to look in exactly this window.
    /// Production code never sets it.
    /// </remarks>
    internal Func<string, Task>? AfterSnapshotTemporaryWritten { get; set; }

    /// <summary>Writes a snapshot file under a temporary name and renames it into place.</summary>
    /// <returns>True when this call filed it; false when another writer filed it first.</returns>
    private async Task<bool> WriteSnapshotFileAsync(string path, byte[] stored, CancellationToken cancellationToken)
    {
        // Ends in .tmp, so the "*.json" walks of the snapshot folder never see it.
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        var moved = false;
        try
        {
            await SharingRetry
                .RunAsync(token => File.WriteAllBytesAsync(temporary, stored, token), cancellationToken)
                .ConfigureAwait(false);

            if (AfterSnapshotTemporaryWritten is { } afterWritten)
            {
                await afterWritten(temporary).ConfigureAwait(false);
            }

            // A scanner reading the file just written holds it without sharing delete, which
            // a rename needs (D-69).
            SharingRetry.Run(() => File.Move(temporary, path, overwrite: false));
            moved = true;
            return true;
        }
        catch (IOException) when (File.Exists(path))
        {
            // Another writer filed the same snapshot first. Its name is the hash of its
            // content, so the file there is this one.
            return false;
        }
        finally
        {
            if (!moved && File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    /// <summary>The hash a snapshot would be filed under.</summary>
    /// <param name="snapshot">The snapshot to identify.</param>
    /// <returns>Its content hash: of its canonical header, or of its canonical JSON when it is legacy (D-12).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="snapshot"/> was null.</exception>
    /// <exception cref="ArgumentException">Its format is not one this build knows, or it cannot be encoded.</exception>
    public static ContentHash ComputeSnapshotId(Snapshot snapshot) => SnapshotEncoding.ComputeId(snapshot);

    /// <summary>A new snapshot in the canonical format, naming the root tree of its files.</summary>
    /// <param name="parentId">Its parent.</param>
    /// <param name="mergeParentId">Its second parent, for a merge; empty otherwise.</param>
    /// <param name="message">Its message.</param>
    /// <param name="deviceId">The device taking it.</param>
    /// <param name="files">Its files.</param>
    /// <param name="built">The trees of <paramref name="files"/>.</param>
    /// <returns>The snapshot, not yet written.</returns>
    private static Snapshot NewSnapshot(
        ContentHash parentId,
        ContentHash mergeParentId,
        string? message,
        string deviceId,
        IReadOnlyList<FileEntry> files,
        SnapshotTrees built) =>
        new()
        {
            Format = SnapshotFormat.Canonical,
            ParentId = parentId,
            MergeParentId = mergeParentId,
            CreatedUtc = DateTimeOffset.UtcNow,
            Message = message ?? string.Empty,
            DeviceId = deviceId,
            Files = files,
            Tree = built.Root,
        };

    /// <summary>
    /// Walks the working folder, splits every tracked file into blocks and records their
    /// hashes.
    /// </summary>
    /// <param name="storeBlocks">
    /// When true the block contents are written to the store. <c>sip save</c> passes true;
    /// <c>sip status</c> passes false so that looking never writes.
    /// </param>
    /// <param name="reuseFrom">
    /// An earlier snapshot whose block hashes may be reused for files that have not
    /// changed. Pass null to re-read and re-hash everything.
    /// </param>
    /// <param name="cancellationToken">Cancels the scan.</param>
    /// <returns>
    /// One entry per tracked file, ordered by path. A path the scan could not read carries
    /// <paramref name="reuseFrom"/>'s entry for it, when there is one; see
    /// <see cref="LastScanSkipped"/>.
    /// </returns>
    public async Task<IReadOnlyList<FileEntry>> ScanWorkingTreeAsync(
        bool storeBlocks,
        Snapshot? reuseFrom = null,
        CancellationToken cancellationToken = default) =>
        (await ScanAsync(storeBlocks, reuseFrom, reuseFrom, cancellationToken).ConfigureAwait(false)).Files;

    /// <summary>
    /// How many files the most recent scan reused from a previous snapshot instead of
    /// re-hashing. Exposed for tests and for the daemon to report on.
    /// </summary>
    public int LastScanReusedCount { get; private set; }

    /// <summary>What the most recent scan did not read, and why. Empty when it read everything.</summary>
    public IReadOnlyList<SkippedPath> LastScanSkipped { get; private set; } = [];

    /// <summary>
    /// Asks the filesystem for one folder's entries and nothing below them. Hidden and system
    /// entries are included, because the <see cref="SearchOption"/> overloads this replaced
    /// included them; <see cref="EnumerationOptions"/> skips both unless told otherwise
    /// ("The default is <c>FileAttributes.Hidden | FileAttributes.System</c>",
    /// https://learn.microsoft.com/dotnet/api/system.io.enumerationoptions.attributestoskip).
    /// A folder that cannot be listed throws rather than reading as empty, so it can be
    /// reported and its recorded files carried rather than read as deleted.
    /// </summary>
    private static readonly EnumerationOptions OneFolder = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false,
        MatchType = MatchType.Win32,
    };

    /// <summary>
    /// Walks the working folder one folder at a time, and returns what it read, what it could
    /// not, and which entries stand in for the latter.
    /// </summary>
    /// <param name="storeBlocks">Whether to write blocks to the store.</param>
    /// <param name="reuseFrom">A snapshot whose entries stand in for files that have not changed.</param>
    /// <param name="carryFrom">
    /// The snapshot whose entry is kept for a path the scan could not read: the last thing
    /// this machine recorded about it. Usually the same as <paramref name="reuseFrom"/>; a
    /// merge reuses the peer's entries and carries its own.
    /// </param>
    /// <param name="cancellationToken">Cancels the scan.</param>
    /// <returns>The scan.</returns>
    /// <remarks>
    /// <para>
    /// <b>Links are not followed (DATA-01).</b> The walk used to be one
    /// <see cref="Directory.EnumerateFiles(string, string, SearchOption)"/> over the whole
    /// tree, which descends into junctions and directory symbolic links. A Documents folder
    /// holding the junction a game installer made to <c>E:\</c> therefore snapshotted that
    /// drive's files and sent them to every peer, and a peer's deletion of one, applied
    /// through the same path, deleted it on <c>E:\</c>. An entry is a link when
    /// <see cref="FileSystemInfo.LinkTarget"/> names a target, which it does for "symbolic
    /// links and junctions", and returns null for anything that "doesn't represent a link"
    /// (https://learn.microsoft.com/dotnet/api/system.io.filesysteminfo.linktarget). It is
    /// asked only of entries carrying the reparse-point attribute, which Windows gives to
    /// links and to other reparse points alike (FILE_ATTRIBUTE_REPARSE_POINT,
    /// https://learn.microsoft.com/windows/win32/fileio/file-attribute-constants); a reparse
    /// point that is not a link, such as a cloud file placeholder, is read like any other file.
    /// </para>
    /// <para>
    /// <b>One entry never fails the folder (DATA-03, D-61).</b> A folder that cannot be listed,
    /// a file that cannot be opened or read, and a file that changed during every read are
    /// each skipped and listed, and the walk goes on. Each used to throw out of the whole
    /// scan, so the save, the status and every pull of the folder failed for as long as it
    /// lasted: permanently, for the <c>My Music</c> link Windows puts in every Documents
    /// folder, and all day for a mail file a mail program holds open.
    /// </para>
    /// <para>
    /// <b>A skipped path is carried, never dropped.</b> For each one, the entry
    /// <paramref name="carryFrom"/> recorded — for a skipped folder, every entry under it — is
    /// kept unchanged. A path missing from a snapshot is a path that was deleted, and a
    /// deletion travels, so dropping what could not be read would have deleted it on every
    /// peer. A path with no recorded entry is simply not recorded yet.
    /// </para>
    /// <para>
    /// A failure writing to the store is not a file that could not be read: it still fails
    /// the scan, as it always did.
    /// </para>
    /// </remarks>
    internal Task<WorkingTreeScan> ScanAsync(
        bool storeBlocks,
        Snapshot? reuseFrom,
        Snapshot? carryFrom,
        CancellationToken cancellationToken) =>
        ScanAsync(storeBlocks, reuseFrom, carryFrom, rules: null, cancellationToken);

    /// <summary>
    /// Walks the working folder as <see cref="ScanAsync(bool, Snapshot?, Snapshot?, CancellationToken)"/>
    /// does, judging what is ignored by <paramref name="rules"/> instead of the folder's own.
    /// </summary>
    /// <param name="storeBlocks">Whether to write blocks to the store.</param>
    /// <param name="reuseFrom">A snapshot whose entries stand in for files that have not changed.</param>
    /// <param name="carryFrom">The snapshot whose entry is kept for a path the scan could not read.</param>
    /// <param name="rules">
    /// The rules to judge by, or null for the folder's own. An apply that changes
    /// <c>.sipignore</c> passes the rules that will be in force once it has run.
    /// </param>
    /// <param name="cancellationToken">Cancels the scan.</param>
    /// <returns>The scan.</returns>
    internal async Task<WorkingTreeScan> ScanAsync(
        bool storeBlocks,
        Snapshot? reuseFrom,
        Snapshot? carryFrom,
        IgnoreRules? rules,
        CancellationToken cancellationToken)
    {
        RefreshIgnoreRules();
        var ignore = rules ?? Ignore;

        var entries = new List<FileEntry>();
        var skipped = new List<SkippedPath>();
        var reusable = BuildReuseIndex(reuseFrom);

        // Hoisted so the loop never dereferences reuseFrom. MinValue makes the racy-mtime
        // guard in CanReuse reject everything when there is no snapshot to reuse from,
        // which is the safe direction.
        var reuseCutoff = reuseFrom?.CreatedUtc ?? DateTimeOffset.MinValue;
        var reused = 0;

        var root = new DirectoryInfo(Layout.WorkingRoot);
        var pending = new Stack<DirectoryInfo>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var directory = pending.Pop();
            var isRoot = ReferenceEquals(directory, root);

            List<FileSystemInfo> children;
            try
            {
                children = directory.EnumerateFileSystemInfos("*", OneFolder).ToList();
            }
            catch (Exception ex) when (!isRoot && ex is IOException or UnauthorizedAccessException)
            {
                // The working folder itself failing to list is not one entry: it is the
                // folder gone, and that still fails the scan.
                skipped.Add(new SkippedPath
                {
                    Path = ToRelativePath(directory.FullName) + "/",
                    Reason = SkipReason.Unreadable,
                    Detail = ex.Message,
                });
                continue;
            }

            foreach (var child in children)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var relativePath = ToRelativePath(child.FullName);
                var isDirectory = child is DirectoryInfo;

                if (isDirectory ? ignore.IsIgnoredDirectory(relativePath) : ignore.IsIgnored(relativePath))
                {
                    continue;
                }

                if (!SnapshotTree.CanRecordName(child.Name))
                {
                    skipped.Add(new SkippedPath
                    {
                        Path = isDirectory ? relativePath + "/" : relativePath,
                        Reason = SkipReason.InvalidName,
                        Detail = "its name is not valid Unicode, so a snapshot cannot record it",
                    });
                    continue;
                }

                if (TryGetLinkTarget(child, out var target, out var unreadable))
                {
                    skipped.Add(new SkippedPath
                    {
                        Path = isDirectory ? relativePath + "/" : relativePath,
                        Reason = SkipReason.Link,
                        Detail = target,
                    });
                    continue;
                }

                if (unreadable is not null)
                {
                    skipped.Add(new SkippedPath
                    {
                        Path = isDirectory ? relativePath + "/" : relativePath,
                        Reason = SkipReason.Unreadable,
                        Detail = unreadable,
                    });
                    continue;
                }

                if (isDirectory)
                {
                    // A folder this deep would hold paths longer than a snapshot records (D-23).
                    if (relativePath.AsSpan().Count('/') + 1 >= SnapshotTree.MaximumDepth)
                    {
                        skipped.Add(new SkippedPath
                        {
                            Path = relativePath + "/",
                            Reason = SkipReason.TooDeep,
                            Detail = $"{SnapshotTree.MaximumDepth} folders down",
                        });
                        continue;
                    }

                    pending.Push((DirectoryInfo)child);
                    continue;
                }

                // Unchanged files are the common case for a daemon that polls, so re-reading
                // and re-hashing every byte on every tick is the single most wasteful thing
                // this method can do. Reuse the recorded blocks when size and modification
                // time both still match. The size and time are the ones the directory listing
                // returned, which is the same stat a FileInfo would have made.
                var info = (FileInfo)child;
                FileEntry? previous = null;
                if (reusable is not null &&
                    reusable.TryGetValue(relativePath, out previous) &&
                    CanReuse(previous, info, reuseCutoff))
                {
                    entries.Add(previous);
                    reused++;
                    continue;
                }

                try
                {
                    var read = await ReadEntryAsync(info.FullName, relativePath, previous, storeBlocks, cancellationToken)
                        .ConfigureAwait(false);

                    if (read is null)
                    {
                        skipped.Add(new SkippedPath
                        {
                            Path = relativePath,
                            Reason = SkipReason.KeptChanging,
                            Detail = $"changed on each of {ReadAttempts} reads",
                        });
                        continue;
                    }

                    entries.Add(read);
                }
                catch (Exception ex) when ((ex is IOException or UnauthorizedAccessException) &&
                                           !ex.Data.Contains(StoreWriteFailed))
                {
                    skipped.Add(new SkippedPath
                    {
                        Path = relativePath,
                        Reason = SkipReason.Unreadable,
                        Detail = ex.Message,
                    });
                }
            }
        }

        var carried = CarrySkipped(entries, skipped, carryFrom, ignore);

        entries.Sort(static (a, b) => string.CompareOrdinal(a.Path, b.Path));
        skipped.Sort(static (a, b) => string.CompareOrdinal(a.Path, b.Path));
        LastScanReusedCount = reused;
        LastScanSkipped = skipped;

        return new WorkingTreeScan { Files = entries, Skipped = skipped, Carried = carried };
    }

    /// <summary>
    /// Whether an entry is a link, and if so where it points. An entry whose reparse data
    /// cannot be read is reported through <paramref name="unreadable"/>, and not followed.
    /// </summary>
    private static bool TryGetLinkTarget(FileSystemInfo entry, out string target, out string? unreadable)
    {
        target = string.Empty;
        unreadable = null;

        if ((entry.Attributes & FileAttributes.ReparsePoint) == 0)
        {
            return false;
        }

        try
        {
            if (entry.LinkTarget is { } linkTarget)
            {
                target = linkTarget;
                return true;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            unreadable = ex.Message;
        }

        return false;
    }

    /// <summary>
    /// Adds to <paramref name="entries"/> what <paramref name="carryFrom"/> recorded for every
    /// path the scan skipped, and returns those paths.
    /// </summary>
    /// <remarks>
    /// An entry a snapshot can no longer record is not carried: a path a legacy snapshot
    /// recorded that is not valid Unicode or nests too deep (<see cref="SnapshotTree.CanRecord"/>),
    /// or one that does not fit beside what was read (<see cref="TreeShape"/>). Carried, it
    /// would stop every save of the folder, and what is on disk there is left as it is.
    /// </remarks>
    private static HashSet<string> CarrySkipped(
        List<FileEntry> entries,
        List<SkippedPath> skipped,
        Snapshot? carryFrom,
        IgnoreRules ignore)
    {
        var carried = new HashSet<string>(StringComparer.Ordinal);
        if (carryFrom is null || skipped.Count == 0)
        {
            return carried;
        }

        var shape = new TreeShape(entries);
        foreach (var recorded in carryFrom.Files)
        {
            // An ignored path is not this scan's to carry; a save that carries those does so
            // from its own rule (CarryIgnored).
            if (ignore.IsIgnored(recorded.Path))
            {
                continue;
            }

            var covered = skipped.Exists(s => s.IsFolder
                ? recorded.Path.StartsWith(s.Path, StringComparison.OrdinalIgnoreCase)
                : string.Equals(recorded.Path, s.Path, StringComparison.OrdinalIgnoreCase));

            if (covered && SnapshotTree.CanRecord(recorded.Path) && shape.TryAdd(recorded.Path) && carried.Add(recorded.Path))
            {
                entries.Add(recorded);
            }
        }

        return carried;
    }

    /// <summary>How many times one file is read before a scan gives up on it holding still.</summary>
    private const int ReadAttempts = 3;

    /// <summary>
    /// Test seam: runs once per read of a file, after its first block has been read and
    /// before the rest is.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only. What a scan records when a file changes part way through
    /// being read (D-61) can only be shown by changing it in exactly that window. Production
    /// code never sets it.
    /// </remarks>
    internal Action<string>? DuringFileRead { get; set; }

    /// <summary>
    /// Test seam: runs in every apply to this working folder — a sync or a restore — after
    /// every incoming file is staged and before the pre-flight check and the changes.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only. The pre-flight check exists for what changes on disk
    /// after the plan was made, such as a folder replaced by a link or a file made read-only,
    /// and that can only be shown by changing the disk in exactly that window. Production
    /// code never sets it.
    /// </remarks>
    internal Action? BeforeWorkingTreeChanges { get; set; }

    /// <summary>
    /// Key set in <see cref="Exception.Data"/> on a failure to write a block to the store, so
    /// the scan can tell it from a file it could not read: the first fails the scan, the
    /// second skips the file.
    /// </summary>
    private const string StoreWriteFailed = "SippBucket.StoreWriteFailed";

    /// <summary>
    /// Reads one file that could not be reused by size and time, and returns an entry that
    /// describes one real state of it, or null when it changed during every read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One real state (D-61).</b> The size is the number of bytes actually split, and the
    /// file's length and modification time are taken again after the read. When either moved,
    /// or the bytes read are not the length the file had, the file changed while it was being
    /// read: the blocks may hold the old start and the new end, which is no state the file was
    /// ever in. It is read again, and after <see cref="ReadAttempts"/> reads that each saw it
    /// change, null says so and the scan skips the file, carrying what was recorded for it.
    /// The scan used to take the size from before the read and the blocks from during it; the
    /// first fix for that threw instead, which stopped the whole folder saving and syncing
    /// for as long as one log file kept growing. A rewrite that moves neither the length nor
    /// the timestamp cannot be seen by this check, or by anything else that decides from them.
    /// </para>
    /// <para>
    /// <b>The recorded entry, when the bytes match it (D-60).</b> A file whose recorded entry
    /// was split with the fixed-size recipe of the builds before FastCDC, and whose timestamp
    /// has moved, is first compared with that entry by re-splitting it the same way. When the
    /// bytes are the same, the recorded entry is kept, with the file's current modification
    /// time. Splitting it with FastCDC instead gave the same bytes a different block list, so
    /// <c>sip status</c> called the file modified and the next save wrote an entry for a file
    /// nobody had changed. Tried first rather than after the FastCDC split, so the common case
    /// reads the file once and a save stores no blocks it will not use.
    /// </para>
    /// </remarks>
    private async Task<FileEntry?> ReadEntryAsync(
        string absolutePath,
        string relativePath,
        FileEntry? recorded,
        bool storeBlocks,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            var before = new FileInfo(absolutePath);
            var length = before.Length;
            var modified = before.LastWriteTimeUtc;

            FileEntry? entry = null;
            long bytesRead = 0;

            var scheme = ChunkScheme.ForNewFile(length);
            if (recorded is not null && recorded.Size == length &&
                (!string.Equals(recorded.Chunker, scheme.Chunker, StringComparison.Ordinal) ||
                 recorded.BlockSize != scheme.BlockSize))
            {
                var (same, read) = await ChunkScheme.ReadMatchesAsync(absolutePath, recorded, cancellationToken)
                    .ConfigureAwait(false);
                if (same)
                {
                    entry = recorded with { ModifiedUtc = modified };
                    bytesRead = read;
                }
            }

            if (entry is null)
            {
                (entry, bytesRead) = await SplitFileAsync(
                    absolutePath, relativePath, scheme, length, modified, storeBlocks, cancellationToken)
                    .ConfigureAwait(false);
            }

            var after = new FileInfo(absolutePath);
            if (after.Exists && after.Length == length && after.LastWriteTimeUtc == modified &&
                bytesRead == length)
            {
                return entry;
            }

            if (attempt == ReadAttempts)
            {
                return null;
            }
        }
    }

    /// <summary>Splits one file with FastCDC and returns its entry and the bytes split.</summary>
    /// <remarks>
    /// Content-defined, so an insertion moves only the boundaries next to it rather than
    /// every boundary after it (D-22). The recipe is recorded on the entry, which is what lets
    /// fixed-size entries written by the older build sit beside these in one snapshot.
    /// </remarks>
    private async Task<(FileEntry Entry, long BytesRead)> SplitFileAsync(
        string absolutePath,
        string relativePath,
        ChunkScheme scheme,
        long length,
        DateTime modified,
        bool storeBlocks,
        CancellationToken cancellationToken)
    {
        var blocks = new List<ContentHash>();
        long read = 0;

        var stream = new FileStream(
            absolutePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 0,
            useAsync: true);

        await using (stream.ConfigureAwait(false))
        {
            await foreach (var block in scheme
                .SplitAsync(stream, length, cancellationToken)
                .ConfigureAwait(false))
            {
                read += block.Length;

                if (storeBlocks)
                {
                    ContentHash hash;
                    try
                    {
                        (hash, _) = await Blobs.PutAsync(block, cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // The store failed, not the file: marked so the scan fails rather
                        // than skipping a file it read perfectly well.
                        ex.Data[StoreWriteFailed] = true;
                        throw;
                    }

                    blocks.Add(hash);
                }
                else
                {
                    blocks.Add(Blake2.Hash(block.Span));
                }

                if (blocks.Count == 1)
                {
                    DuringFileRead?.Invoke(relativePath);
                }
            }
        }

        var entry = new FileEntry
        {
            Path = relativePath,
            Size = read,
            ModifiedUtc = modified,
            BlockSize = scheme.BlockSize,
            Blocks = blocks,
            Chunker = scheme.Chunker,
        };

        return (entry, read);
    }

    /// <summary>
    /// When this machine's ignore rules are its own, adds to a scan every entry of
    /// <paramref name="from"/> whose path this machine ignores, unchanged, so a snapshot made
    /// here says nothing new about a path this machine does not track.
    /// </summary>
    /// <param name="scanned">What the scan found. It never holds an ignored path.</param>
    /// <param name="from">The snapshot whose ignored entries travel on, or null for none.</param>
    /// <returns>The scan with those entries, ordered by path.</returns>
    /// <remarks>
    /// <para>
    /// A path one machine ignores used to be missing from every snapshot it made, and to the
    /// other machine a path missing from a snapshot is a path that was deleted. With D-26's
    /// three-way apply a deletion propagates, so a file one machine ignored was deleted on the
    /// machine that did not (D-56). Carried forward, the entry reads as unchanged there.
    /// </para>
    /// <para>
    /// <b>Only for rules that are this machine's own</b> — a <c>.sipignore</c> that names
    /// itself, so it never syncs and the other machines may track what this one ignores (see
    /// <see cref="IgnoreRulesAreLocal"/>). A synced <c>.sipignore</c> is every machine's rules,
    /// so a path it ignores needs nothing carried: it is dropped from the next snapshot, its
    /// blocks are released, and no machine that reads the same file treats the drop as a
    /// deletion. Carrying it anyway, as this first did, kept a path the person had stopped
    /// syncing in every snapshot for good: its blocks were never freed, a restore wrote it
    /// back, and a newly joined machine received it. The moments before a peer has the new
    /// file are covered on the receiving side: the apply leaves alone any path the incoming
    /// snapshot's own <c>.sipignore</c> ignores (see <c>WorkingTreeMerge</c>).
    /// </para>
    /// <para>
    /// <b>Why ignore rules do not travel in the snapshot instead.</b> They already travel as
    /// a file: <c>.sipignore</c> is an ordinary synced file unless it ignores itself, and a
    /// copy of the rules inside each snapshot would be a second statement of them that could
    /// disagree with the file.
    /// </para>
    /// <para>
    /// A save carries from its parent, and a merge from the peer's snapshot, whose entry is
    /// the newest this machine has heard of. A path the parent never listed is never
    /// invented, and a path already dropped by an earlier build stays dropped.
    /// </para>
    /// <para>
    /// <b>What is on disk comes first.</b> An ignored entry that no longer fits beside what the
    /// scan found is not carried: a folder of ignored files replaced by a file of the same
    /// name leaves that file, and the old entries say nothing true about this machine any more
    /// (<see cref="TreeShape"/>). Nor is an entry a snapshot can no longer record
    /// (<see cref="SnapshotTree.CanRecord"/>). Carried, either would stop every save.
    /// </para>
    /// </remarks>
    internal IReadOnlyList<FileEntry> CarryIgnored(IReadOnlyList<FileEntry> scanned, Snapshot? from)
    {
        if (from is null || !IgnoreRulesAreLocal)
        {
            return scanned;
        }

        var ignored = from.Files.Where(f => Ignore.IsIgnored(f.Path)).ToList();
        if (ignored.Count == 0)
        {
            return scanned;
        }

        var shape = new TreeShape(scanned);
        var files = new List<FileEntry>(scanned.Count + ignored.Count);
        files.AddRange(scanned);
        foreach (var entry in ignored)
        {
            if (SnapshotTree.CanRecord(entry.Path) && shape.TryAdd(entry.Path))
            {
                files.Add(entry);
            }
        }

        files.Sort(static (a, b) => string.CompareOrdinal(a.Path, b.Path));
        return files;
    }

    /// <summary>
    /// The files a merge records: every path the scan read as it read it, and for every path it
    /// could not read, the merge rule's answer from this machine's last record of it, the
    /// peer's, and the base the two share.
    /// </summary>
    /// <param name="scan">The scan of the merged folder, carrying from this replica's own head.</param>
    /// <param name="own">This replica's head before the merge, or null.</param>
    /// <param name="mergeBase">The snapshot both sides descend from, or null when none is held.</param>
    /// <param name="theirs">The peer's snapshot.</param>
    /// <returns>The entries, ordered by path.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="scan"/> or <paramref name="theirs"/> was null.</exception>
    /// <remarks>
    /// <para>
    /// A path the scan could not read has no state here that the merge can see: it lies behind
    /// a link, which is never followed, in a folder that cannot be listed, or in a file another
    /// program holds. A save carries this machine's last record of it, the only thing known. A
    /// merge used to do the same, and so recorded this machine's stale entry over the peer's
    /// saved edit: the peer then fast-forwarded to the merge, and its edit was overwritten with
    /// no conflict copy. Behind a link the apply had written nothing; in a folder that cannot
    /// be listed it had written the peer's version, so there the merge contradicted the disk
    /// as well.
    /// </para>
    /// <para>
    /// So each such path takes what the rule takes for every other path: the peer's entry,
    /// unless the peer's matches the base, when this machine's stands. A path the peer deleted
    /// and this machine did not change is left out, as the apply deleted it where it could.
    /// With no base, the peer's entry is taken wherever it has one and this machine's kept
    /// otherwise, which records no deletion, as a merge with no base never deletes.
    /// </para>
    /// <para>
    /// Entries from two snapshots can disagree about what a path is: this machine's file where
    /// the peer made a folder of the same name, both since the base. They cannot both be
    /// recorded (<see cref="TreeShape"/>), and the peer's stand, as the peer's entry stands
    /// wherever the rule is in doubt: this machine's own copy is still on its disk, where the
    /// merge could not reach, and is recorded again once the scan can read it. An entry a
    /// snapshot can no longer record is left out (<see cref="SnapshotTree.CanRecord"/>).
    /// </para>
    /// </remarks>
    internal IReadOnlyList<FileEntry> SettleUnread(WorkingTreeScan scan, Snapshot? own, Snapshot? mergeBase, Snapshot theirs)
    {
        ArgumentNullException.ThrowIfNull(scan);
        ArgumentNullException.ThrowIfNull(theirs);

        if (scan.Skipped.Count == 0)
        {
            return scan.Files;
        }

        var none = new Dictionary<string, FileEntry>(StringComparer.Ordinal);
        var ownByPath = BuildReuseIndex(own) ?? none;
        var baseByPath = BuildReuseIndex(mergeBase) ?? none;
        var theirsByPath = BuildReuseIndex(theirs) ?? none;

        var unread = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var path in ownByPath.Keys.Concat(baseByPath.Keys).Concat(theirsByPath.Keys))
        {
            // An ignored path is not the scan's to settle, as it was not the scan's to carry.
            if (!Ignore.IsIgnored(path) && scan.IsSkipped(path))
            {
                unread.Add(path);
            }
        }

        var files = scan.Files.Where(f => !scan.Carried.Contains(f.Path)).ToList();
        var shape = new TreeShape(files);
        var ownSettled = new List<FileEntry>();
        foreach (var path in unread)
        {
            var mine = ownByPath.GetValueOrDefault(path);
            var peers = theirsByPath.GetValueOrDefault(path);

            var takePeers = mergeBase is null
                ? peers is not null
                : !SameEntry(peers, baseByPath.GetValueOrDefault(path));
            var settled = takePeers ? peers : mine;
            if (settled is null || !SnapshotTree.CanRecord(path))
            {
                continue;
            }

            // The peer's first, so that where the two disagree about what a path is, theirs fit.
            if (!takePeers)
            {
                ownSettled.Add(settled);
            }
            else if (shape.TryAdd(path))
            {
                files.Add(settled);
            }
        }

        foreach (var entry in ownSettled)
        {
            if (shape.TryAdd(entry.Path))
            {
                files.Add(entry);
            }
        }

        files.Sort(static (a, b) => string.CompareOrdinal(a.Path, b.Path));
        return files;
    }

    private static bool SameEntry(FileEntry? left, FileEntry? right) =>
        left is null ? right is null : right is not null && SameBlocks(left, right);

    private static Dictionary<string, FileEntry>? BuildReuseIndex(Snapshot? snapshot)
    {
        if (snapshot is null || snapshot.Files.Count == 0)
        {
            return null;
        }

        var index = new Dictionary<string, FileEntry>(snapshot.Files.Count, StringComparer.Ordinal);
        foreach (var file in snapshot.Files)
        {
            index[file.Path] = file;
        }

        return index;
    }

    /// <summary>
    /// Decides whether a recorded entry can stand in for re-hashing the file on disk.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Size and modification time matching is not by itself proof that content is
    /// unchanged: a file edited in place, to the same length, within the same filesystem
    /// timestamp tick as the snapshot would slip through. That is the classic racy-mtime
    /// problem, and the guard against it is the third condition — the file's modification
    /// time must be older than the snapshot by more than <see cref="RacyWindow"/>. Being wrong
    /// here means a silently stale content hash, which in a content-addressed store means the
    /// change never syncs.
    /// </para>
    /// <para>
    /// The window used to be zero: strictly older than the snapshot was enough. That assumed
    /// a file's time and the snapshot's time come from the same clock, and they do not. The
    /// snapshot is stamped with <see cref="DateTimeOffset.UtcNow"/>, which is precise; a
    /// file's write time is whatever the filesystem recorded, and Windows says only that it
    /// "is correctly reflected when the handle that makes the change is closed", with a write
    /// time resolution of 2 seconds on FAT
    /// (https://learn.microsoft.com/windows/win32/sysinfo/file-times). Measured on this
    /// desktop's NTFS with .NET 10.0.12, 158 of 199 back-to-back rewrites of one file kept the
    /// same write time. So a file saved, then rewritten to the same length a moment later,
    /// had the old write time, older than the precise snapshot, and was reused: the edit was
    /// never recorded until the file changed again. The ancestry compaction test caught it,
    /// intermittently, as a save that found nothing to save.
    /// </para>
    /// </remarks>
    private static bool CanReuse(FileEntry previous, FileInfo current, DateTimeOffset snapshotTakenUtc)
    {
        if (previous.Size != current.Length)
        {
            return false;
        }

        var modified = new DateTimeOffset(current.LastWriteTimeUtc, TimeSpan.Zero);
        if (modified != previous.ModifiedUtc)
        {
            return false;
        }

        return modified < snapshotTakenUtc - RacyWindow;
    }

    /// <summary>
    /// How much older than a snapshot a file's write time must be before the snapshot's entry
    /// is trusted for it without reading it. Two seconds, the coarsest write-time resolution
    /// Windows documents (FAT's); see <see cref="CanReuse"/>.
    /// </summary>
    /// <remarks>
    /// The cost is a re-read of any file written within two seconds before the snapshot the
    /// scan reuses from, on each scan until a newer snapshot is taken. A daemon save that
    /// follows a change waits three seconds after it, which leaves no such file; a save made
    /// sooner — <c>sip save</c> straight after an edit, or a poll falling due just after
    /// one — pays that re-read.
    /// </remarks>
    private static readonly TimeSpan RacyWindow = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Takes a snapshot of the working folder and makes it the new head.
    /// </summary>
    /// <param name="message">A message describing the save. May be empty.</param>
    /// <param name="deviceId">The device ID to attribute the snapshot to.</param>
    /// <param name="cancellationToken">Cancels the save.</param>
    /// <returns>
    /// The new snapshot and its ID, or null when the working folder is unchanged and there
    /// was nothing to save.
    /// </returns>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// A file or folder that could not be read is kept as the parent recorded it, and listed
    /// in <see cref="LastScanSkipped"/>; the save goes ahead with everything else.
    /// </remarks>
    public async Task<SaveResult?> SaveAsync(
        string message,
        string deviceId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        // The owner's hooks, read fresh each save and run outside the operation lock
        // (SaveHooks): before-save first, so what it writes - a formatter's output, say -
        // is what gets scanned, and so a command of the owner's that runs `sip` itself is
        // not deadlocked against this save's own lock. A failing before-save hook refuses
        // the save here, before anything is touched.
        var hooks = SaveHooks.Load(Layout);
        await hooks.RunBeforeSaveAsync(Layout.WorkingRoot, Config.Name, message, cancellationToken)
            .ConfigureAwait(false);

        SaveResult? result;
        using (var operation = new OperationScope(
                   this, await LockOperationAsync(FolderOperation.Save, cancellationToken).ConfigureAwait(false)))
        {
            // Before anything is written, not after. A quota checked once the blocks are on
            // disk is not a quota, it is a report.
            await EnforceQuotaAsync(cancellationToken).ConfigureAwait(false);

            result = await SaveUncheckedAsync(message, deviceId, cancellationToken).ConfigureAwait(false);
        }

        if (result is not null)
        {
            // After the lock is released, for the same two reasons; a failure is reported
            // on the result and fails nothing, because the snapshot is already recorded.
            var note = await hooks
                .RunAfterSaveAsync(Layout.WorkingRoot, Config.Name, result.SnapshotId, message, cancellationToken)
                .ConfigureAwait(false);
            if (note is not null)
            {
                result = result with { AfterSaveNote = note };
            }
        }

        return result;
    }

    /// <summary>A save, once the quota has been checked.</summary>
    private async Task<SaveResult?> SaveUncheckedAsync(
        string message,
        string deviceId,
        CancellationToken cancellationToken)
    {
        var parent = GetHead();

        // Load the parent first so the scan can reuse its block hashes for files that have
        // not changed, rather than re-reading the whole working tree every save.
        Snapshot? previous = null;
        if (!parent.IsEmpty)
        {
            previous = await GetSnapshotAsync(parent, cancellationToken).ConfigureAwait(false);
        }

        var scan = await ScanAsync(storeBlocks: true, previous, previous, cancellationToken).ConfigureAwait(false);
        var files = CarryIgnored(scan.Files, previous);

        if (previous is not null)
        {
            if (SameContent(previous.Files, files))
            {
                return null;
            }
        }
        else if (files.Count == 0)
        {
            return null;
        }

        var built = SnapshotTree.Build(files);
        var snapshot = NewSnapshot(parent, default, message, deviceId, files, built);

        var (id, stored) = await WriteSnapshotAsync(snapshot, built, cancellationToken).ConfigureAwait(false);
        await AdvanceHeadAsync(id, cancellationToken).ConfigureAwait(false);

        return new SaveResult { SnapshotId = id, Snapshot = snapshot with { Signature = stored.Signature } };
    }

    /// <summary>
    /// Takes a snapshot of the working folder with the parents the caller names, and makes it
    /// the new head. This is how a merge is recorded.
    /// </summary>
    /// <param name="message">A message describing the save. May be empty.</param>
    /// <param name="deviceId">The device ID to attribute the snapshot to.</param>
    /// <param name="parentId">The first parent: this replica's head before the merge.</param>
    /// <param name="mergeParentId">The second parent: the head that was merged in.</param>
    /// <param name="reuseFrom">
    /// A snapshot whose block hashes may stand in for re-reading files that still match it,
    /// under the same racy-mtime guard as every other scan, and whose entries for paths this
    /// machine ignores are carried into the merge unchanged (see <see cref="CarryIgnored"/>).
    /// A merge passes the peer's snapshot. Null re-reads everything and carries nothing.
    /// </param>
    /// <param name="mergeBase">
    /// The snapshot both parents descend from, which the merge was applied against, or null
    /// when none is held. It settles what is recorded for paths the scan could not read (see
    /// <see cref="SettleUnread"/>).
    /// </param>
    /// <param name="cancellationToken">Cancels the save.</param>
    /// <returns>The new snapshot and its ID.</returns>
    /// <exception cref="ArgumentException"><paramref name="deviceId"/> was null or blank.</exception>
    /// <exception cref="BucketFullException">The folder is at its quota.</exception>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// <para>
    /// Unlike <see cref="SaveAsync"/> this always writes, even when the tree matches one of
    /// the parents: whether a merge needs recording is the sync engine's decision, made
    /// before it calls this, and a save that silently declined would leave the other side's
    /// head out of this replica's ancestry — the D-27 state this exists to end.
    /// </para>
    /// <para>
    /// A path the scan could not read is recorded as the merge rule decides it, from this
    /// replica's own head, the peer's snapshot and <paramref name="mergeBase"/>, never as this
    /// replica's stale entry alone (<see cref="SettleUnread"/>).
    /// </para>
    /// </remarks>
    public async Task<SaveResult> SaveWithParentsAsync(
        string message,
        string deviceId,
        ContentHash parentId,
        ContentHash mergeParentId,
        Snapshot? reuseFrom,
        Snapshot? mergeBase,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        using var operation = new OperationScope(
            this, await LockOperationAsync(FolderOperation.Save, cancellationToken).ConfigureAwait(false));

        await EnforceQuotaAsync(cancellationToken).ConfigureAwait(false);

        var own = !parentId.IsEmpty && HasSnapshot(parentId)
            ? await GetSnapshotAsync(parentId, cancellationToken).ConfigureAwait(false)
            : null;
        var scan = await ScanAsync(storeBlocks: true, reuseFrom, own, cancellationToken).ConfigureAwait(false);
        var read = reuseFrom is null ? scan.Files : SettleUnread(scan, own, mergeBase, reuseFrom);
        var files = CarryIgnored(read, reuseFrom);

        var built = SnapshotTree.Build(files);
        var snapshot = NewSnapshot(parentId, mergeParentId, message, deviceId, files, built);

        var (id, stored) = await WriteSnapshotAsync(snapshot, built, cancellationToken).ConfigureAwait(false);
        await AdvanceHeadAsync(id, cancellationToken).ConfigureAwait(false);

        return new SaveResult { SnapshotId = id, Snapshot = snapshot with { Signature = stored.Signature } };
    }

    /// <summary>
    /// Points head at a snapshot this replica holds, then applies the folder's storage
    /// policy exactly as a save does.
    /// </summary>
    /// <param name="snapshotId">The snapshot to make current.</param>
    /// <param name="cancellationToken">Cancels the collection that follows.</param>
    /// <returns>A task that completes when head has moved and the store is tidied.</returns>
    /// <exception cref="SnapshotNotFoundException">The snapshot is not present.</exception>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// Every way head moves goes through here — a save, a merge, and a fast-forward onto a
    /// peer's snapshot. The last used to set head and stop, so a Simple replica that only
    /// ever received, and never saved, kept every snapshot it was sent and every block they
    /// named: the mode that promises to stay small grew with each sync.
    /// </remarks>
    public async Task AdvanceHeadAsync(ContentHash snapshotId, CancellationToken cancellationToken = default)
    {
        using var operation = new OperationScope(
            this, await LockOperationAsync(FolderOperation.Head, cancellationToken).ConfigureAwait(false));

        if (!HasSnapshot(snapshotId))
        {
            throw new SnapshotNotFoundException(snapshotId);
        }

        SetHead(snapshotId);

        if (Config.Mode == RepositoryMode.Simple)
        {
            TrimHistoryToHead(snapshotId);

            // The half that was missing. Trimming the chain without sweeping the blocks it
            // referred to is what made Simple mode grow without bound - the opposite of
            // what it promises - so the sweep belongs here, on the same path, rather than
            // in a maintenance command somebody has to remember.
            await CollectAsync(cancellationToken).ConfigureAwait(false);
        }
        else if (Bucket.Prunes)
        {
            await CollectAsync(cancellationToken).ConfigureAwait(false);
        }

        // The same argument for the ancestry index, which grew by a record per snapshot
        // forever (D-54). Compacting rewrites the file, so it waits until enough has been
        // added since the last time to be worth it.
        if (Ancestry.Count >= _ancestryCountAfterCompaction + AncestryCompactionSlack)
        {
            CompactAncestry();
        }
    }

    /// <summary>
    /// How many records the ancestry index gains before head moving compacts it again.
    /// </summary>
    /// <remarks>
    /// A compaction reads and rewrites the whole index, so doing it on every save would cost a
    /// file rewrite per save. Every 256 records is about 26 KiB of growth between rewrites.
    /// Internal and settable only so a test can show the trigger working over a short history
    /// instead of hundreds of saves; production code never sets it.
    /// </remarks>
    internal int AncestryCompactionSlack { get; set; } = 256;

    private int _ancestryCountAfterCompaction;

    /// <summary>
    /// The snapshots kept as merge bases for the configured peers, which trimming and
    /// retention never delete (D-55).
    /// </summary>
    /// <returns>Each base this replica holds as a file.</returns>
    /// <remarks>
    /// <para>
    /// Only for peers still in <c>peers.json</c>: a removed peer's base is released at the
    /// next trim or collection.
    /// </para>
    /// <para>
    /// When <c>peers.json</c> cannot be read — damaged, or held by another program — every
    /// base on record is kept, because there is no telling which peers are gone. This runs on
    /// every save after head has moved, and it used to let the file's
    /// <see cref="JsonException"/> escape: the save reported failure with head already moved,
    /// and a Simple folder never trimmed or collected again while the file stayed damaged.
    /// </para>
    /// </remarks>
    public IReadOnlySet<ContentHash> KeptBases()
    {
        var marks = Shared.Load();
        var kept = new HashSet<ContentHash>();

        IEnumerable<string> peers;
        try
        {
            peers = Peers.Load().Select(peer => peer.DeviceId).ToList();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            peers = marks.Keys;
        }

        foreach (var peer in peers)
        {
            if (marks.TryGetValue(peer, out var mark) && !mark.Base.IsEmpty && HasSnapshot(mark.Base))
            {
                kept.Add(mark.Base);
            }
        }

        return kept;
    }

    /// <summary>
    /// Drops from <c>.sip/ancestry</c> every entry no sync decision can need, and returns how
    /// many were dropped.
    /// </summary>
    /// <returns>How many entries were dropped; zero when nothing could be.</returns>
    /// <remarks>
    /// <para>
    /// <b>What is kept.</b> The roots are this replica's head, and each configured peer's last
    /// known head and kept base. The anchors are the kept bases and every snapshot this
    /// replica holds as a file. Kept: the roots, and every entry on a path from a root back
    /// to an anchor. Every decision sync makes from ancestry (D-39) walks back from a head to
    /// something both sides know, and a peer's head is at or after the last snapshot shared
    /// with it; those walks stay inside what is kept. <c>sip log</c> and the collector walk
    /// from head to snapshot files, and those paths are kept too.
    /// </para>
    /// <para>
    /// <b>What is dropped.</b> Everything older than every anchor on its path: in Simple mode,
    /// the history behind the oldest kept base, which is almost all of it; in Power mode, which
    /// keeps every snapshot as a file, almost nothing. And entries nothing reachable from a
    /// root names.
    /// </para>
    /// <para>
    /// <b>What that costs.</b> For a peer whose head descends from the snapshot last shared
    /// with it, "it is behind", "fast-forward" and the merge base chosen come out as before;
    /// <c>AncestryCompactionTests</c> checks every head such a peer can present over a long
    /// history. Two cases change. A peer whose head moves back to before that snapshot — a
    /// <c>sip restore</c> on that machine — is no longer recognised as behind: the pull becomes
    /// a merge whose base is that peer's head, which changes nothing here and keeps this
    /// replica's head. And where both histories merged in a branch that forked before the
    /// kept base, a common ancestor on that branch that was nearer than the base can no longer
    /// be found, so the merge uses the kept base: further back, which can turn a clean merge
    /// into a kept conflict copy and never loses a file. A peer this replica has not synced
    /// with since this build has no mark, so while any configured peer lacks one nothing is
    /// dropped: there is no telling what it needs.
    /// </para>
    /// <para>
    /// A compaction that cannot rewrite the file — another program holding it for longer than
    /// a moment — drops nothing and is tried again later; it never fails the save it follows.
    /// Nor does one that cannot read <c>peers.json</c>: without the list of peers there is no
    /// telling what any of them needs, so nothing is dropped.
    /// </para>
    /// </remarks>
    public int CompactAncestry()
    {
        var marks = Shared.Load();
        var roots = new List<ContentHash> { GetHead() };
        var anchors = new List<ContentHash>();

        IReadOnlyList<PeerRecord> peers;
        try
        {
            peers = Peers.Load();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return 0;
        }

        foreach (var peer in peers)
        {
            if (!marks.TryGetValue(peer.DeviceId, out var mark) || mark.Base.IsEmpty)
            {
                return 0;
            }

            roots.Add(mark.Base);
            roots.Add(mark.PeerHead);
            anchors.Add(mark.Base);
        }

        anchors.AddRange(PresentSnapshotIds());

        var index = Ancestry;
        var keep = AncestryIndex.Needed(index, roots, anchors);

        try
        {
            var dropped = index.Retain(keep);
            _ancestryCountAfterCompaction = index.Count;
            return dropped;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Another program holds the index. Nothing was dropped and the next head move
            // tries again; a smaller index is never worth a failed save.
            return 0;
        }
    }

    /// <summary>Compares the working folder against the newest snapshot.</summary>
    /// <param name="cancellationToken">Cancels the scan.</param>
    /// <returns>What has been added, modified and removed.</returns>
    /// <remarks>
    /// By block list, which agrees with the merge about what changed because the scan it
    /// compares already holds the recorded entry for any file whose bytes match it, however
    /// that entry was split (see <c>ReadEntryAsync</c>). Before that, a file saved with the
    /// fixed-size recipe and touched since read as modified here while the merge, which
    /// compares by content, treated it as unchanged (D-60).
    /// A path the scan could not read is listed in <see cref="StatusReport.Skipped"/> and
    /// nowhere else: it is not counted as unchanged, because nothing checked that it was.
    /// </remarks>
    public async Task<StatusReport> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var head = await GetHeadSnapshotAsync(cancellationToken).ConfigureAwait(false);
        var scan = await ScanAsync(storeBlocks: false, head, head, cancellationToken).ConfigureAwait(false);
        var current = scan.Files;

        var previous = head?.Files ?? [];
        var previousByPath = previous.ToDictionary(f => f.Path, StringComparer.Ordinal);
        var currentByPath = current.ToDictionary(f => f.Path, StringComparer.Ordinal);

        var added = new List<string>();
        var modified = new List<string>();
        var unchanged = 0;

        foreach (var entry in current)
        {
            if (scan.Carried.Contains(entry.Path))
            {
                continue;
            }

            if (!previousByPath.TryGetValue(entry.Path, out var old))
            {
                added.Add(entry.Path);
            }
            else if (!SameBlocks(old, entry))
            {
                modified.Add(entry.Path);
            }
            else
            {
                unchanged++;
            }
        }

        // A path this machine ignores is not tracked here, so its absence is not a removal:
        // saying so would describe a deletion the next save does not record (D-56).
        var removed = previous
            .Where(f => !currentByPath.ContainsKey(f.Path) && !Ignore.IsIgnored(f.Path))
            .Select(f => f.Path)
            .ToList();

        added.Sort(StringComparer.Ordinal);
        modified.Sort(StringComparer.Ordinal);
        removed.Sort(StringComparer.Ordinal);

        return new StatusReport
        {
            Added = added,
            Modified = modified,
            Removed = removed,
            UnchangedCount = unchanged,
            Skipped = scan.Skipped,
        };
    }

    /// <summary>
    /// Walks history back from head: every snapshot this replica holds that head descends
    /// from, through both parents of a merge.
    /// </summary>
    /// <param name="limit">The most snapshots to return.</param>
    /// <param name="cancellationToken">Cancels the walk.</param>
    /// <returns>Head first, then the rest newest first by the time they were taken.</returns>
    /// <remarks>
    /// <para>
    /// Snapshots this replica does not hold are walked through, not stopped at, using
    /// <see cref="Ancestry"/>. A fast-forward over three saves holds the newest and not the
    /// two between, and a walk that stopped at the first gap lost sight of everything older:
    /// <c>sip log</c> would show one entry, the bucket would count every older snapshot's
    /// blocks as reclaimable, and a collection — which runs on every save once a retention
    /// policy is set — would sweep them while leaving the snapshot files that name them.
    /// </para>
    /// <para>
    /// Head is always first, which the retention policy depends on; after that the newest
    /// snapshot discovered so far comes next. The walk stops as soon as every snapshot file
    /// present has been found. In Simple mode those are head and the merge base kept for each
    /// peer (D-55), so the walk goes back through the index as far as the oldest kept base;
    /// a kept base that head does not descend from is never found, and then the walk covers
    /// everything the index reaches from head.
    /// </para>
    /// </remarks>
    public async Task<IReadOnlyList<SaveResult>> GetHistoryAsync(
        int limit = int.MaxValue,
        CancellationToken cancellationToken = default)
    {
        var history = new List<SaveResult>();
        var head = GetHead();
        if (head.IsEmpty || limit <= 0)
        {
            return history;
        }

        var present = PresentSnapshotIds();
        var newestFirst = new PriorityQueue<SaveResult, DateTimeOffset>(
            Comparer<DateTimeOffset>.Create(static (a, b) => b.CompareTo(a)));
        var seen = new HashSet<ContentHash>();
        var found = 0;

        // One read of each tree for the whole walk: snapshots next to each other share every
        // folder nothing changed in (D-23).
        var trees = new Dictionary<ContentHash, byte[]>();

        async Task DiscoverAsync(ContentHash start)
        {
            var pending = new Stack<ContentHash>();
            pending.Push(start);

            while (pending.Count > 0 && found < present.Count)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var id = pending.Pop();
                if (id.IsEmpty || !seen.Add(id))
                {
                    continue;
                }

                if (present.Contains(id))
                {
                    var snapshot = await TryGetSnapshotAsync(id, trees, cancellationToken).ConfigureAwait(false)
                        ?? throw new SnapshotNotFoundException(id);
                    newestFirst.Enqueue(new SaveResult { SnapshotId = id, Snapshot = snapshot }, snapshot.CreatedUtc);
                    found++;
                }
                else if (Ancestry.TryGet(id, out var entry))
                {
                    pending.Push(entry.ParentId);
                    pending.Push(entry.MergeParentId);
                }
            }
        }

        await DiscoverAsync(head).ConfigureAwait(false);

        while (history.Count < limit && newestFirst.TryDequeue(out var next, out _))
        {
            history.Add(next);
            await DiscoverAsync(next.Snapshot.ParentId).ConfigureAwait(false);
            await DiscoverAsync(next.Snapshot.MergeParentId).ConfigureAwait(false);
        }

        return history;
    }

    /// <summary>The IDs of every snapshot file in the store.</summary>
    private HashSet<ContentHash> PresentSnapshotIds()
    {
        var present = new HashSet<ContentHash>();
        if (!Directory.Exists(Layout.SnapshotsDirectory))
        {
            return present;
        }

        foreach (var path in Directory.EnumerateFiles(Layout.SnapshotsDirectory, "*.json"))
        {
            if (ContentHash.TryParse(Path.GetFileNameWithoutExtension(path), out var id))
            {
                present.Add(id);
            }
        }

        return present;
    }

    /// <summary>
    /// Puts the working folder back to the state of a snapshot without destroying anything
    /// no snapshot holds, and records the result as a new snapshot on top of head.
    /// </summary>
    /// <param name="snapshotId">The snapshot to restore.</param>
    /// <param name="deviceId">
    /// This machine's device ID, named in the file names of unsaved work kept beside the
    /// restored version, and the author of the snapshot that records the restore.
    /// </param>
    /// <param name="cancellationToken">Cancels the restore until the folder starts changing.</param>
    /// <returns>What was written, deleted, renamed and kept, and the snapshot recording it.</returns>
    /// <exception cref="ArgumentException"><paramref name="deviceId"/> was null or blank.</exception>
    /// <exception cref="SnapshotNotFoundException">The snapshot is not present.</exception>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <exception cref="BucketFullException">
    /// The folder is at its quota, so the restore could not be recorded. Nothing in the
    /// folder has changed.
    /// </exception>
    /// <exception cref="BlockNotFoundException">
    /// A block the snapshot needs is missing. Nothing in the folder has changed.
    /// </exception>
    /// <exception cref="Sync.WorkingTreeBusyException">
    /// A file that would change is open in another program or changed during the restore.
    /// Nothing in the folder has changed.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This used to write each file in place with <see cref="FileMode.Create"/>, so a missing
    /// block left a truncated file; then delete every file the snapshot did not list, work
    /// never saved included; and compare names by exact case, so a snapshot naming
    /// <c>Report.txt</c> over <c>report.txt</c> wrote into it and then deleted it (D-53).
    /// It is the command a person reaches for when something has already gone wrong.
    /// </para>
    /// <para>
    /// Now it is the staged apply sync uses: every file is written whole into
    /// <c>.sip/incoming</c> first, every file that will change is checked, and only then is
    /// anything moved into place. The rule for each file is on
    /// <see cref="Sync.WorkingTreeMerge.RestoreAsync"/>; in short, only a file head records and
    /// that still matches head is ever replaced or deleted, and anything else in the way is
    /// kept beside the restored version.
    /// </para>
    /// <para>
    /// <b>Head moves forward, never back (DATA-02).</b> The folder, as the restore leaves it,
    /// is saved as a new snapshot whose parent is the head the restore started from, exactly
    /// as <see cref="SaveAsync"/> would save it — so the files the restore replaced or
    /// deleted, which matched that head, are still in history, one snapshot back. Restore
    /// used to point head at the restored snapshot instead. Head then sat behind history that
    /// had happened: the next sync saw the peer's head as a descendant and fast-forwarded
    /// straight back over the restore, the restore never reached the other machines, the
    /// newer snapshots fell out of <c>sip log</c>, and the next collection swept their blocks
    /// while their snapshot files stayed, naming blocks that were gone. As a new snapshot the
    /// restore is an ordinary change: it syncs, it can be restored away again, and the
    /// retention policy treats it and its parent like any others. When the folder already
    /// matches head, nothing is recorded and head stays.
    /// </para>
    /// <para>
    /// The quota is checked before the folder is touched, not after, so a full bucket refuses
    /// the restore rather than leaving it applied and unrecorded.
    /// </para>
    /// <para>
    /// <b>In Simple mode too.</b> Simple mode keeps only the newest snapshot, and the last one
    /// shared with each peer, so the save recording a restore used to trim the head it
    /// replaced and collect its blocks at once: the only copy of what the restore replaced was
    /// gone, and restoring it again failed. Now the head a restore replaces is recorded in
    /// <c>.sip/restored</c> before the folder changes, and kept, as a merge base is, until the
    /// next restore replaces the record. So a restore can always be undone, at the cost of at
    /// most one more snapshot.
    /// </para>
    /// </remarks>
    public async Task<RestoreResult> RestoreAsync(
        ContentHash snapshotId,
        string deviceId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        using var operation = new OperationScope(
            this, await LockOperationAsync(FolderOperation.Restore, cancellationToken).ConfigureAwait(false));

        var target = await GetSnapshotAsync(snapshotId, cancellationToken).ConfigureAwait(false);
        var headId = GetHead();
        var head = await GetHeadSnapshotAsync(cancellationToken).ConfigureAwait(false);

        await EnforceQuotaAsync(cancellationToken).ConfigureAwait(false);

        // Before anything changes, so a record that cannot be written leaves the folder as it
        // was; a restore that then fails keeps a head that is kept anyway.
        if (Config.Mode == RepositoryMode.Simple && !headId.IsEmpty)
        {
            KeepReplaced(headId);
        }

        var applied = await Sync.WorkingTreeMerge
            .RestoreAsync(this, head, target, deviceId, log: null, cancellationToken)
            .ConfigureAwait(false);

        // The folder has changed; cancelling now would leave the restore unrecorded, which is
        // the state this exists to end. The save below runs to completion.
        var recorded = await SaveUncheckedAsync(
            $"Restore of {snapshotId.ToShortString()}", deviceId, CancellationToken.None).ConfigureAwait(false);

        return new RestoreResult
        {
            FilesWritten = applied.FilesWritten,
            FilesDeleted = applied.FilesDeleted,
            FilesRenamed = applied.FilesRenamed,
            KeptAside = applied.Conflicts,
            KeptReadOnly = applied.KeptReadOnly,
            SnapshotId = recorded?.SnapshotId ?? default,
        };
    }

    /// <summary>Converts an absolute path to the repository-relative form used in snapshots.</summary>
    /// <param name="absolutePath">A path inside the working folder.</param>
    /// <returns>A relative path with forward slashes.</returns>
    public string ToRelativePath(string absolutePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(absolutePath);
        return Path.GetRelativePath(Layout.WorkingRoot, absolutePath).Replace('\\', '/');
    }

    private string SnapshotPath(ContentHash id) =>
        Path.Combine(Layout.SnapshotsDirectory, $"{id}.json");

    /// <summary>
    /// Deletes every snapshot but the newest and the kept merge bases. Used in simple mode,
    /// where history is not kept.
    /// </summary>
    /// <remarks>
    /// This used to carry the comment "blocks are left alone; unreferenced ones are
    /// collected separately", and nothing collected them. So the mode whose entire purpose
    /// is to stay small grew forever — and grew <em>faster</em> than Power mode, because
    /// Power mode at least kept the snapshots that would have made the blocks findable
    /// again. <see cref="CollectAsync"/> now runs after this, which is what makes the
    /// sentence true.
    /// </remarks>
    private void TrimHistoryToHead(ContentHash head)
    {
        // The snapshot the last restore replaced stays, until the next restore: it holds the
        // only copy of what that restore replaced. When the record of it cannot be read, which
        // one it is cannot be told, so nothing is trimmed this time and the next save tries
        // again.
        var replaced = ReplacedByRestore(out var readable);
        if (!readable)
        {
            return;
        }

        // Tagged snapshots survive every trim: that is the tag's one promise. A tags file
        // that cannot be read gets the same fail-shut answer as the restore record — any
        // snapshot might be tagged, so nothing is trimmed this time.
        IReadOnlySet<ContentHash> tagged;
        try
        {
            tagged = Tags.TaggedSnapshots();
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            return;
        }

        // The kept merge bases stay too, one per peer at most (D-55). Without them two Simple
        // replicas that diverge share no snapshot, and their merge is two-way.
        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { $"{head}.json" };
        foreach (var kept in KeptBases())
        {
            keep.Add($"{kept}.json");
        }

        foreach (var kept in tagged)
        {
            keep.Add($"{kept}.json");
        }

        if (replaced is { } replacedId)
        {
            keep.Add($"{replacedId}.json");
        }

        foreach (var file in Directory.EnumerateFiles(Layout.SnapshotsDirectory, "*.json"))
        {
            if (!keep.Contains(Path.GetFileName(file)))
            {
                // Head has already moved, so a delete refused by a scanner's brief hold would
                // fail a save that has in every way that matters succeeded (D-69).
                SharingRetry.Run(() => File.Delete(file));
            }
        }
    }

    /// <summary>The folder's storage policy: what it keeps and how much room it may use.</summary>
    public BucketPolicy Bucket => Config.Bucket ?? BucketPolicy.Unlimited;

    /// <summary>Measures what the store is using and what could be freed.</summary>
    /// <param name="cancellationToken">Cancels the walk.</param>
    /// <returns>Usage against the folder's quota.</returns>
    public Task<BucketUsage> MeasureBucketAsync(CancellationToken cancellationToken = default) =>
        NewBucket().MeasureAsync(Bucket, DateTimeOffset.UtcNow, cancellationToken);

    /// <summary>
    /// Applies the retention policy and deletes every block nothing refers to any more.
    /// </summary>
    /// <param name="cancellationToken">Cancels the collection.</param>
    /// <returns>What was removed.</returns>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    public async Task<CollectionResult> CollectAsync(CancellationToken cancellationToken = default)
    {
        using var operation = new OperationScope(
            this, await LockOperationAsync(FolderOperation.Collect, cancellationToken).ConfigureAwait(false));

        return await NewBucket().CollectAsync(Bucket, DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Replaces this folder's storage policy and writes it to the config.</summary>
    /// <param name="policy">The new policy.</param>
    /// <exception cref="ArgumentNullException"><paramref name="policy"/> was null.</exception>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// Holds the folder's lock because it rewrites <c>config.json</c> in place, which the
    /// passphrase commands also do: two of them at once would each write back the config
    /// they read, and whichever finished last would silently undo the other.
    /// </remarks>
    public void SetBucketPolicy(BucketPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        using var operation = new OperationScope(this, LockOperation(FolderOperation.StoragePolicy));

        Config = Config with { Bucket = policy };
        WriteConfigOverwritingInPlace();
    }

    /// <summary>
    /// Records that every machine paired with this folder now reaches it on
    /// <paramref name="port"/>, the port this machine serves every folder on.
    /// </summary>
    /// <param name="port">This machine's <c>server.listenPort</c>.</param>
    /// <returns>The port the folder recorded before: what its peers had been given.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="port"/> is not a TCP port.</exception>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// <para>
    /// <see cref="RepositoryConfig.ListenPort"/> is the only record of the port this folder's
    /// peers were given, and nothing has listened on it since one listener served every folder
    /// (D-40). <c>sip doctor</c> warns while it differs from the machine's port. After a
    /// deliberate move of that port, once every paired machine has been told the new one, this
    /// is how the person says so, and nothing else could: no command rewrote the recorded port,
    /// so the warning could only be cleared by moving the port back or editing the config by
    /// hand.
    /// </para>
    /// <para>
    /// Nothing about serving changes, because the folder was already served on
    /// <paramref name="port"/>. Holds the folder's lock for the same reason as
    /// <see cref="SetBucketPolicy"/>: it rewrites <c>config.json</c> in place.
    /// </para>
    /// </remarks>
    public int RecordPortGivenToPeers(int port)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        using var operation = new OperationScope(this, LockOperation(FolderOperation.Settings));

        var given = Config.ListenPort;
        if (given != port)
        {
            Config = Config with { ListenPort = port };
            WriteConfigOverwritingInPlace();
        }

        return given;
    }

    /// <summary>
    /// Refuses a save when the folder is already at its quota and nothing can be reclaimed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists because two design boards stated that saves are refused at the cap while
    /// nothing in <c>SaveAsync</c> had ever read <see cref="BucketPolicy.QuotaBytes"/>. Of
    /// the two ways to resolve that, removing the claim was the easy one and enforcing it
    /// was the right one: a limit a user configures and the program ignores is worse than
    /// no limit, because they stop watching the number.
    /// </para>
    /// <para>
    /// <strong>Collect first, refuse second.</strong> Refusing while a gigabyte of
    /// unreferenced blocks sits in the store would be technically correct and useless — the
    /// user is told to free space by a program declining to free the space it is holding.
    /// </para>
    /// <para>
    /// It is a soft ceiling, and the softness is deliberate rather than a gap. The check
    /// runs before the save, so a folder can cross the line <em>during</em> one save and
    /// exceed the quota by that save's worth of new blocks. Checking afterwards would mean
    /// writing the blocks and then refusing, which pays the whole cost for none of the
    /// benefit; checking during would mean a half-written snapshot. Overshooting by one
    /// save and refusing the next is the version with no bad failure mode.
    /// </para>
    /// <para>
    /// Nothing is ever lost by a refusal. The documents are in the working folder, where
    /// they always were; what is refused is a new snapshot of them.
    /// </para>
    /// </remarks>
    private async Task EnforceQuotaAsync(CancellationToken cancellationToken)
    {
        if (Bucket.QuotaBytes is null)
        {
            return;
        }

        var usage = await MeasureBucketAsync(cancellationToken).ConfigureAwait(false);
        if (!usage.IsFull)
        {
            return;
        }

        if (usage.HasReclaimable)
        {
            await CollectAsync(cancellationToken).ConfigureAwait(false);
            usage = await MeasureBucketAsync(cancellationToken).ConfigureAwait(false);

            if (!usage.IsFull)
            {
                return;
            }
        }

        throw new BucketFullException(usage);
    }

    /// <remarks>
    /// <para>
    /// The chain is head's history, then any kept merge base it does not reach; kept bases
    /// are never deleted, and their blocks are live like any other snapshot's (D-55). A base
    /// this replica saved or received whole keeps its blocks that way, at the cost, in Simple
    /// mode, of the blocks changed since the last sync with each peer.
    /// </para>
    /// <para>
    /// A base can also be only a file list. When the peer is behind and its head is not held
    /// here, or a merge's base is fetched from the peer, the snapshot is fetched without its
    /// blocks, which a merge base does not need: it is compared, never written out. Blocks
    /// this store already dropped stay dropped, so <c>sip restore</c> of such a base stops
    /// with a missing block and changes nothing.
    /// </para>
    /// </remarks>
    private VirtualBucket NewBucket()
    {
        // The snapshot the last restore replaced is pinned like a kept base. When the record of
        // it cannot be read, every snapshot is pinned, so no retention policy deletes the one
        // that might be it.
        var kept = new HashSet<ContentHash>(KeptBases());
        var replaced = ReplacedByRestore(out var readable);
        if (replaced is { } replacedId)
        {
            kept.Add(replacedId);
        }

        // Tagged snapshots are pinned the same way (sip tag): whatever the policy says, a
        // snapshot the owner named stays, and its blocks stay live. A tags file that cannot
        // be read pins everything, exactly as an unreadable restore record does.
        try
        {
            kept.UnionWith(Tags.TaggedSnapshots());
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            readable = false;
        }

        Func<ContentHash, bool> isPinned = readable ? kept.Contains : static _ => true;

        return new(
            Blobs,
            async ct =>
            {
                var chain = (await GetHistoryAsync(int.MaxValue, ct).ConfigureAwait(false))
                    .Select(entry => new SnapshotRecord(
                        entry.SnapshotId, entry.Snapshot.CreatedUtc, entry.Snapshot))
                    .ToList();

                foreach (var id in kept.Where(id => chain.TrueForAll(record => record.Id != id)))
                {
                    if (HasSnapshot(id))
                    {
                        var snapshot = await GetSnapshotAsync(id, ct).ConfigureAwait(false);
                        chain.Add(new SnapshotRecord(id, snapshot.CreatedUtc, snapshot));
                    }
                }

                return chain;
            },
            id =>
            {
                var path = SnapshotPath(id);
                if (!File.Exists(path))
                {
                    return false;
                }

                SharingRetry.Run(() => File.Delete(path));
                return true;
            },
            isPinned,
            Held.Kept);
    }

    /// <summary>The snapshot the last restore replaced as head, while this replica holds it.</summary>
    /// <param name="readable">False when the record exists and could not be read.</param>
    /// <returns>Its ID; null when no restore has replaced one here, or it is no longer held.</returns>
    private ContentHash? ReplacedByRestore(out bool readable)
    {
        readable = true;

        string text;
        try
        {
            text = SharingRetry.Run(() => File.ReadAllText(Layout.RestoredFile));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            readable = false;
            return null;
        }

        if (!ContentHash.TryParse(text.Trim(), out var id))
        {
            // Damaged: which snapshot it named cannot be told, so it is treated as unreadable,
            // which keeps everything, and not as absent, which would release the snapshot.
            readable = false;
            return null;
        }

        return HasSnapshot(id) ? id : null;
    }

    /// <summary>Records the head a restore is about to replace, so a Simple replica keeps it.</summary>
    /// <exception cref="IOException">The record could not be written. Nothing has been restored.</exception>
    private void KeepReplaced(ContentHash head)
    {
        var temporary = $"{Layout.RestoredFile}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temporary, head.ToString());
            SharingRetry.Run(() => File.Move(temporary, Layout.RestoredFile, overwrite: true));
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    private static bool SameBlocks(FileEntry left, FileEntry right)
    {
        if (left.Size != right.Size || left.Blocks.Count != right.Blocks.Count)
        {
            return false;
        }

        for (var i = 0; i < left.Blocks.Count; i++)
        {
            if (left.Blocks[i] != right.Blocks[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool SameContent(IReadOnlyList<FileEntry> left, IReadOnlyList<FileEntry> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (var i = 0; i < left.Count; i++)
        {
            if (!string.Equals(left[i].Path, right[i].Path, StringComparison.Ordinal) ||
                !SameBlocks(left[i], right[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Takes this folder's operation lock for the calling flow, or returns null when the flow
    /// already holds it. Pass the result straight to <see cref="HoldOperation"/>.
    /// </summary>
    /// <param name="operation">What the lock is for.</param>
    /// <param name="cancellationToken">Cancels the wait for another holder.</param>
    /// <returns>The lock, or null when this flow already holds one.</returns>
    /// <exception cref="FolderBusyException">Another operation held this folder for too long.</exception>
    /// <remarks>
    /// Internal for operations assembled outside this class, which is a sync's apply: the
    /// sync engine holds the lock from the moment the working folder starts to change until
    /// head has moved. Whatever it calls here meanwhile, such as <see cref="AdvanceHeadAsync"/>,
    /// uses the same hold rather than opening the lock again.
    /// </remarks>
    internal async Task<OperationLock?> LockOperationAsync(
        FolderOperation operation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _operation.Value is not null
            ? null
            : await OperationLock.AcquireAsync(Layout, operation, OperationPatience, cancellationToken)
                .ConfigureAwait(false);
    }

    /// <summary>Marks a lock from <see cref="LockOperationAsync"/> as held by the calling flow.</summary>
    /// <param name="held">The lock, or null when the flow already held one.</param>
    /// <returns>The hold, which releases the lock when disposed.</returns>
    /// <remarks>
    /// A separate, synchronous step because of where the mark has to land. It lives in an
    /// <see cref="AsyncLocal{T}"/>, and a value set inside an async method disappears when
    /// that method returns, so setting it inside <see cref="LockOperationAsync"/> would mark
    /// nothing for the caller. A synchronous call sets it in the caller's own flow, where
    /// everything the caller then awaits can see it.
    /// </remarks>
    internal IDisposable HoldOperation(OperationLock? held) => new OperationScope(this, held);

    private OperationLock? LockOperation(FolderOperation operation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _operation.Value is not null
            ? null
            : OperationLock.Acquire(Layout, operation, OperationPatience);
    }

    /// <summary>One flow's hold on this folder's operation lock.</summary>
    private sealed class OperationScope : IDisposable
    {
        private readonly SipRepository _repository;
        private readonly OperationLock? _held;

        /// <summary>Marks <paramref name="held"/> as this flow's, or marks nothing when it is null.</summary>
        public OperationScope(SipRepository repository, OperationLock? held)
        {
            _repository = repository;
            _held = held;

            if (held is not null)
            {
                repository._operation.Value = held;
            }
        }

        /// <summary>Releases the lock, unless this was an operation nested inside another.</summary>
        public void Dispose()
        {
            if (_held is null)
            {
                return;
            }

            _repository._operation.Value = null;
            _held.Dispose();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _cipher.Dispose();

        // The field comment has always said this happens. It did not, until pairing started
        // reading the key from here and the claim was checked. The older ring keys are the
        // same kind of secret, and go the same way.
        CryptographicOperations.ZeroMemory(_keyMaterial);
        foreach (var older in _previousKeys)
        {
            CryptographicOperations.ZeroMemory(older);
        }

        _disposed = true;
    }
}
