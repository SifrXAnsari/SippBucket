using SippBucket.Core.Crypto;
using SippBucket.Core.Model;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Repository;

/// <summary>
/// The contents of <c>.sip/config.json</c>: what this repository is and how it behaves.
/// </summary>
/// <remarks>
/// <para>
/// Exactly one of <see cref="EncryptionKey"/> and <see cref="WrappedKey"/> is set. Unlocked,
/// the key is here in the clear; locked, it is sealed behind a passphrase and the clear copy
/// is gone. Modelling it as two nullable fields rather than one field plus a boolean is
/// deliberate: a boolean can disagree with the data it describes, and a config claiming to
/// be locked while still holding the key would be the worst possible bug in this file.
/// </para>
/// <para>
/// The lock is per <strong>machine</strong>, not per repository. <c>.sip</c> is never synced,
/// so every replica keeps its own config holding the same key — locking the desktop leaves
/// the laptop wide open, and the documents are equally readable from either. Any interface
/// wording that implies otherwise is a lie.
/// </para>
/// </remarks>
public sealed record RepositoryConfig
{
    /// <summary>The on-disk format this repository was written with.</summary>
    public required int FormatVersion { get; init; }

    /// <summary>Stable identifier for the repository, shared by every replica of it.</summary>
    public required string RepositoryId { get; init; }

    /// <summary>A human-readable name, defaulting to the folder name.</summary>
    public required string Name { get; init; }

    /// <summary>Whether this replica keeps history or only the newest snapshot.</summary>
    public required RepositoryMode Mode { get; init; }

    /// <summary>
    /// The XChaCha20-Poly1305 repository key, base64 encoded. Null when this machine's copy
    /// is locked.
    /// </summary>
    /// <remarks>
    /// Internal, and serialised by <see cref="System.Text.Json.Serialization.JsonIncludeAttribute"/>
    /// so the file format is unchanged: <c>"encryptionKey"</c>, exactly where every existing
    /// <c>config.json</c> has it. It was public, which made it the one public member anywhere
    /// in the library that handed the key out as a string — and, this being a record, made
    /// <see cref="object.ToString"/> of any config print the key, since a record's generated
    /// <c>ToString</c> lists its public properties. D-49 is "no string that leaves the process
    /// may contain the key"; a log line of a config would have been one.
    /// </remarks>
    [System.Text.Json.Serialization.JsonInclude]
    internal string? EncryptionKey { get; init; }

    /// <summary>
    /// The key ring sealed behind a passphrase. Null when this machine's copy is not
    /// locked.
    /// </summary>
    /// <remarks>
    /// The sealed bytes are every key of the ring concatenated, oldest first, the current key
    /// last — 32 bytes exactly for a folder never rotated, which is byte-for-byte what every
    /// wrapping before rotation existed held, so an old locked config unwraps unchanged.
    /// </remarks>
    public WrappedKey? WrappedKey { get; init; }

    /// <summary>
    /// The older keys of the ring, base64 encoded, oldest first: what a rotation (D-70)
    /// leaves behind so everything written before it stays readable. Null or empty for a
    /// folder whose key has never rotated, which keeps such a config byte-compatible with
    /// every build before rotation existed. Null while this machine's copy is locked, when
    /// the whole ring is inside <see cref="WrappedKey"/>.
    /// </summary>
    [System.Text.Json.Serialization.JsonInclude]
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    internal IReadOnlyList<string>? PreviousKeys { get; init; }

    /// <summary>
    /// The devices removals have revoked (D-70), lowercase hexadecimal, so a rotation's
    /// removal propagates: a machine learning of the rotation drops these peers before it
    /// stores the new key, and never serves or dials them again. Null when none.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? RevokedDevices { get; init; }

    /// <summary>
    /// The TCP port recorded when this repository was created. Nothing listens on it: see
    /// the remarks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This used to be the port the daemon served this repository on, one listener per
    /// folder. Every folder the tray created had 8471, so the second folder's listener could
    /// not bind and that folder was never served to anyone (D-40). Since then one listener
    /// serves every folder on the machine, on <c>server.listenPort</c> in the machine's
    /// <c>master.json</c>, and routes each connection by the repository ID in the handshake.
    /// </para>
    /// <para>
    /// The field stays, and is still written, only for compatibility: every existing
    /// <c>config.json</c> has it, and builds before D-40 require it to open a repository at
    /// all. New repositories record the machine's port at the moment they were created. The
    /// daemon, <c>sip serve</c>, pairing and invites all take the port from the machine
    /// setting, never from here.
    /// </para>
    /// </remarks>
    public required int ListenPort { get; init; }

    /// <summary>
    /// What this folder is allowed to keep and how much room it may take. Null means the
    /// defaults: keep everything, cap nothing.
    /// </summary>
    public BucketPolicy? Bucket { get; init; }

    /// <summary>True when this machine's copy needs a passphrase before it can be opened.</summary>
    /// <remarks>
    /// Not serialized. It is derived from <see cref="WrappedKey"/>, and writing a derived
    /// value into the file would create something that can disagree with the data it
    /// describes — a config reading <c>"isLocked": false</c> next to a wrapped key, or the
    /// reverse, with no way to tell which one is lying. Found by looking at a real config
    /// file rather than by reading the code.
    /// </remarks>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsLocked => WrappedKey is not null;

    /// <summary>The format version this build writes for an unlocked repository.</summary>
    public const int CurrentFormatVersion = 1;

    /// <summary>The format version a locked repository is written with.</summary>
    /// <remarks>
    /// The bump is conditional on actually using the feature, which keeps two promises at
    /// once: a repository that never gets locked stays readable by an older build, and one
    /// that does is refused by that build with a clear version message rather than opened
    /// and then crashed on a null key. Raising the floor for everybody to announce a feature
    /// most folders will not use would be the easier change and the worse one.
    /// </remarks>
    public const int LockedFormatVersion = 2;

    /// <summary>The highest format version this build can read.</summary>
    public const int MaximumReadableFormatVersion = LockedFormatVersion;

    /// <summary>
    /// The port the daemon listens on unless <c>master.json</c> says otherwise: the default
    /// of <c>server.listenPort</c>.
    /// </summary>
    public const int DefaultListenPort = 8471;
}
