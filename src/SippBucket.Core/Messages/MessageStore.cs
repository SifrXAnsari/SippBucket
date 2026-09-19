using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Messages;

/// <summary>Which way a stored message travelled.</summary>
public enum MessageDirection
{
    /// <summary>Written here, for someone else.</summary>
    Sent = 0,

    /// <summary>Written by someone else, for this machine.</summary>
    Received = 1,
}

/// <summary>What the sender can honestly say about a sent message (docs/DIRECT-MESSAGES.md).</summary>
public enum MessageStatus
{
    /// <summary>
    /// Not yet confirmed by any of the person's machines. Covers unreachable, not yet tried,
    /// and a sender who has been blocked; it never says which.
    /// </summary>
    Sending = 0,

    /// <summary>
    /// A machine of theirs confirmed, over the authenticated session, that it checked the
    /// signature and saved the message, flushed to disk. Still that machine's own report.
    /// </summary>
    Delivered = 1,

    /// <summary>Refused for a stated reason that was safe to give. Never used for blocking.</summary>
    NotAccepted = 2,

    /// <summary>A received message. It has no delivery to report.</summary>
    Received = 3,
}

/// <summary>One machine a sent message goes to, and how far it has got there.</summary>
/// <param name="DeviceId">The machine.</param>
/// <param name="Delivered">True once that machine confirmed and flushed its copy.</param>
/// <param name="LastError">The last delivery attempt's failure, for the power-user view; null when none.</param>
public sealed record MessageTarget(string DeviceId, bool Delivered, string? LastError);

/// <summary>One message as this machine keeps it.</summary>
public sealed record StoredMessage
{
    /// <summary>The schema this build writes.</summary>
    public int Schema { get; init; } = MessageStore.CurrentSchema;

    /// <summary>Which way it travelled.</summary>
    public required MessageDirection Direction { get; init; }

    /// <summary>Its status: what the sender may honestly claim, or <see cref="MessageStatus.Received"/>.</summary>
    public required MessageStatus Status { get; init; }

    /// <summary>A sentence beside <see cref="MessageStatus.NotAccepted"/>, from the receiving machine; empty otherwise.</summary>
    public string StatusDetail { get; init; } = string.Empty;

    /// <summary>The conversation it belongs to: a person's key, or an ungrouped machine's device scope key.</summary>
    public required string PersonKey { get; init; }

    /// <summary>The message itself, exactly the signed fields.</summary>
    public required DirectMessage Message { get; init; }

    /// <summary>For a received message, the body's signature, kept as provenance. Null for sent.</summary>
    public string? Signature { get; init; }

    /// <summary>For a sent message, every machine it goes to and how far it got. Empty for received.</summary>
    public IReadOnlyList<MessageTarget> Targets { get; init; } = [];

    /// <summary>When the status last changed, in UTC.</summary>
    public required DateTimeOffset StatusUtc { get; init; }
}

/// <summary>This person's own message preferences: who is blocked, who is muted.</summary>
public sealed record MessagePreferences
{
    /// <summary>The schema this build writes.</summary>
    public int Schema { get; init; } = MessageStore.CurrentSchema;

    /// <summary>
    /// The people whose messages are dropped without an answer. Person keys, or an ungrouped
    /// machine's device scope key. The sender is never told (docs/DIRECT-MESSAGES.md).
    /// </summary>
    public IReadOnlyList<string> Blocked { get; init; } = [];

    /// <summary>The people whose messages arrive without notifications.</summary>
    public IReadOnlyList<string> Muted { get; init; } = [];
}

/// <summary>
/// The message store: one folder of protected files with neutral names, per user
/// (docs/DIRECT-MESSAGES.md, "Stored where, and how protected").
/// </summary>
/// <remarks>
/// <para>
/// Each message is one file named by 16 random bytes of hexadecimal — never by the message
/// ID, the sender or the time, so the store's file names say nothing about who wrote to whom
/// or when. The contents are protected with Windows' per-user data protection
/// (<see cref="UserDataProtection"/>) under this store's own entropy. What that protects
/// against, and what it does not — anything running as this user, an administrator while the
/// user is signed in, anyone with the user's password — is <see cref="DeviceKeyFile"/>'s
/// list, and the Messages screen says it at body size. On a platform without DPAPI the files
/// are stored plain, and <see cref="ProtectionAvailable"/> is false so every screen says so.
/// </para>
/// <para>
/// A received message is flushed to the disk before <see cref="SaveReceived"/> returns,
/// because the receipt that makes the sender's status <em>Delivered</em> may only be sent
/// after the saved copy is flushed (docs/DIRECT-MESSAGES.md, "What the sender sees").
/// </para>
/// <para>
/// A file that cannot be read is counted and reported, never guessed at, and never deleted
/// by this class: it may be another account's, a newer build's, or damage worth looking at.
/// Deleting a message is the person's act alone (<see cref="Delete"/>), and like any deleted
/// file it is not securely erased from the disk.
/// </para>
/// </remarks>
public sealed class MessageStore
{
    /// <summary>The store folder's name in the data directory.</summary>
    public const string FolderName = "messages";

    /// <summary>The schema this build writes, and the newest it can rewrite without loss.</summary>
    public const int CurrentSchema = 1;

    /// <summary>A message file's extension.</summary>
    public const string MessageExtension = ".dmsg";

    private const string PreferencesFileName = "messages.json";

    private static ReadOnlySpan<byte> Magic => "SIPDMSG1"u8;

    private static ReadOnlySpan<byte> Entropy => "sippbucket-dm-store-v1"u8;

    /// <summary>One gate per store folder, shared by every store over it in this process.</summary>
    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);

    private readonly object _gate;

    /// <summary>Creates a store over a folder.</summary>
    /// <param name="root">The store folder.</param>
    /// <exception cref="ArgumentException">The root was null or blank.</exception>
    public MessageStore(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        Root = Path.GetFullPath(root);
        _gate = Gates.GetOrAdd(Root, static _ => new object());
    }

    /// <summary>The store folder.</summary>
    public string Root { get; }

    /// <summary>Whether this platform protects the files at rest. False is reported, not hidden.</summary>
    public static bool ProtectionAvailable => UserDataProtection.IsAvailable;

    /// <summary>The store for the person running this process.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static MessageStore ForThisUser() => new(Path.Combine(UserDataDirectory.Resolve(), FolderName));

    /// <summary>Reads every message this store holds.</summary>
    /// <param name="unreadable">How many files could not be read as messages. Reported, never deleted.</param>
    /// <returns>The messages, oldest first by the time they carry.</returns>
    public IReadOnlyList<StoredMessage> Load(out int unreadable)
    {
        lock (_gate)
        {
            return Read(out unreadable);
        }
    }

    /// <summary>
    /// Saves a received message, flushed to the disk before this returns, so the receipt that
    /// follows never claims more than the disk holds.
    /// </summary>
    /// <param name="message">The message, exactly the signed fields.</param>
    /// <param name="signature">The body's signature, kept as provenance.</param>
    /// <param name="personKey">The conversation: the sender's person scope key.</param>
    /// <param name="nowUtc">When it was saved.</param>
    /// <returns>
    /// True when it was stored now; false when a copy with this sender and message ID was
    /// already here, which a retry is, and which is already as durable as this call promises.
    /// </returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="IOException">The store could not be written. Nothing was recorded.</exception>
    public bool SaveReceived(DirectMessage message, string signature, string personKey, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(signature);
        ArgumentException.ThrowIfNullOrWhiteSpace(personKey);

        lock (_gate)
        {
            var existing = Read(out _);
            if (existing.Any(stored =>
                    stored.Direction == MessageDirection.Received &&
                    string.Equals(stored.Message.MessageId, message.MessageId, StringComparison.OrdinalIgnoreCase) &&
                    DeviceIdentity.IsSameDevice(stored.Message.SenderDeviceId, message.SenderDeviceId)))
            {
                return false;
            }

            WriteMessage(new StoredMessage
            {
                Direction = MessageDirection.Received,
                Status = MessageStatus.Received,
                PersonKey = personKey,
                Message = message,
                Signature = signature,
                StatusUtc = nowUtc,
            });
            return true;
        }
    }

    /// <summary>Queues a message written here, to be delivered to every machine named.</summary>
    /// <param name="message">The message, with this machine as the sender. Its recipient device is the first target's.</param>
    /// <param name="personKey">The conversation: the recipient's person scope key.</param>
    /// <param name="targetDevices">Every machine of theirs it goes to.</param>
    /// <param name="nowUtc">When it was queued.</param>
    /// <returns>The stored message, status <see cref="MessageStatus.Sending"/>.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="ArgumentException">No target was named.</exception>
    /// <exception cref="IOException">The store could not be written. Nothing was queued.</exception>
    public StoredMessage QueueSent(
        DirectMessage message,
        string personKey,
        IReadOnlyList<string> targetDevices,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(personKey);
        ArgumentNullException.ThrowIfNull(targetDevices);

        if (targetDevices.Count == 0)
        {
            throw new ArgumentException("A message goes to a person's machines; none were named.", nameof(targetDevices));
        }

        var stored = new StoredMessage
        {
            Direction = MessageDirection.Sent,
            Status = MessageStatus.Sending,
            PersonKey = personKey,
            Message = message,
            Targets = [.. targetDevices.Select(device => new MessageTarget(device, Delivered: false, LastError: null))],
            StatusUtc = nowUtc,
        };

        lock (_gate)
        {
            WriteMessage(stored);
        }

        return stored;
    }

    /// <summary>Applies a change to one sent message: a delivery confirmed, a refusal, an attempt failed.</summary>
    /// <param name="messageId">The message.</param>
    /// <param name="change">The change. Given the message as stored; returns it as it should be.</param>
    /// <returns>The message as written, or null when no sent message has that ID.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="change"/> was null.</exception>
    /// <exception cref="IOException">The store could not be written. The message is unchanged.</exception>
    public StoredMessage? UpdateSent(string messageId, Func<StoredMessage, StoredMessage> change)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        ArgumentNullException.ThrowIfNull(change);

        lock (_gate)
        {
            var found = FindFile(messageId, MessageDirection.Sent);
            if (found is not { } file)
            {
                return null;
            }

            var changed = change(file.Message) with { Schema = CurrentSchema };
            WriteMessageAt(file.Path, changed);
            return changed;
        }
    }

    /// <summary>
    /// Deletes one message from this machine. It does not delete the other person's copy, and
    /// like any deleted file it is not securely erased from the disk.
    /// </summary>
    /// <param name="messageId">The message.</param>
    /// <returns>True when a message was deleted.</returns>
    public bool Delete(string messageId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);

        lock (_gate)
        {
            var deleted = false;
            foreach (var file in MessageFiles().ToList())
            {
                if (TryReadMessage(file) is { } stored &&
                    string.Equals(stored.Message.MessageId, messageId, StringComparison.OrdinalIgnoreCase))
                {
                    SharingRetry.Run(() => File.Delete(file));
                    deleted = true;
                }
            }

            return deleted;
        }
    }

    /// <summary>Reads the preferences: who is blocked, who is muted.</summary>
    /// <returns>The preferences; the defaults when there is no file yet.</returns>
    /// <remarks>
    /// A file that cannot be read comes back as the defaults with <paramref name="damaged"/>
    /// set: nobody blocked. Failing shut here would be failing <em>open</em> for the sender —
    /// silence is what a blocked sender gets — and inventing a block the person never set is
    /// the one wrong this file must never do. The damage is reported instead.
    /// </remarks>
    /// <param name="damaged">Why the file could not be read, or null.</param>
    public MessagePreferences LoadPreferences(out string? damaged)
    {
        lock (_gate)
        {
            return ReadPreferences(out damaged);
        }
    }

    /// <summary>Changes the preferences: reads them, applies a change, and writes the result.</summary>
    /// <param name="change">The change.</param>
    /// <returns>The preferences as written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="change"/> was null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The file cannot be read or was written by a newer build, so it is not overwritten.
    /// </exception>
    public MessagePreferences UpdatePreferences(Func<MessagePreferences, MessagePreferences> change)
    {
        ArgumentNullException.ThrowIfNull(change);

        lock (_gate)
        {
            var current = ReadPreferences(out var damaged);
            if (damaged is not null)
            {
                throw new InvalidOperationException(
                    $"The message preferences cannot be read ({damaged}), so they are not overwritten. " +
                    "Mend or delete the file, then try again. Nothing was changed.");
            }

            if (current.Schema > CurrentSchema)
            {
                throw new InvalidOperationException(
                    "The message preferences were written by a newer SippBucket, and this one would lose what " +
                    "that version recorded by rewriting them. Update SippBucket, then try again. Nothing was changed.");
            }

            var changed = change(current) with { Schema = CurrentSchema };
            WriteProtected(Path.Combine(Root, PreferencesFileName), JsonSerializer.SerializeToUtf8Bytes(changed, SipJson.Readable));
            return changed;
        }
    }

    private List<StoredMessage> Read(out int unreadable)
    {
        var messages = new List<StoredMessage>();
        var failed = 0;

        foreach (var file in MessageFiles())
        {
            if (TryReadMessage(file) is { } stored)
            {
                messages.Add(stored);
            }
            else
            {
                failed++;
            }
        }

        messages.Sort(static (a, b) => a.Message.CreatedUtc.CompareTo(b.Message.CreatedUtc));
        unreadable = failed;
        return messages;
    }

    private IEnumerable<string> MessageFiles()
    {
        if (!Directory.Exists(Root))
        {
            return [];
        }

        return Directory.EnumerateFiles(Root, "*" + MessageExtension);
    }

    private (string Path, StoredMessage Message)? FindFile(string messageId, MessageDirection direction)
    {
        foreach (var file in MessageFiles())
        {
            if (TryReadMessage(file) is { } stored && stored.Direction == direction &&
                string.Equals(stored.Message.MessageId, messageId, StringComparison.OrdinalIgnoreCase))
            {
                return (file, stored);
            }
        }

        return null;
    }

    private static StoredMessage? TryReadMessage(string path)
    {
        byte[] stored;
        try
        {
            stored = SharingRetry.Run(() => File.ReadAllBytes(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        byte[] plaintext;
        try
        {
            plaintext = Unwrap(stored);
        }
        catch (CryptographicException)
        {
            return null;
        }

        try
        {
            var message = JsonSerializer.Deserialize<StoredMessage>(plaintext, SipJson.Readable);
            return message is { Message: not null } ? message : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private void WriteMessage(StoredMessage message) =>
        WriteMessageAt(Path.Combine(Root, NewFileName()), message);

    private void WriteMessageAt(string path, StoredMessage message) =>
        WriteProtected(path, JsonSerializer.SerializeToUtf8Bytes(message, SipJson.Readable));

    private void WriteProtected(string path, byte[] plaintext)
    {
        Directory.CreateDirectory(Root);

        byte[] wrapped;
        if (OperatingSystem.IsWindows())
        {
            var protectedBytes = UserDataProtection.Protect(plaintext, Entropy);
            wrapped = new byte[Magic.Length + protectedBytes.Length];
            Magic.CopyTo(wrapped);
            protectedBytes.CopyTo(wrapped.AsSpan(Magic.Length));
        }
        else
        {
            // A real reduction, reported rather than hidden: ProtectionAvailable is false and
            // every screen over this store says so.
            wrapped = plaintext;
        }

        // Written whole and flushed under a temporary name, then moved in: the file is always
        // a whole message, and it is on the disk before anyone is told it is.
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        var moved = false;
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(wrapped);
                file.Flush(flushToDisk: true);
            }

            if (File.Exists(path))
            {
                SharingRetry.Run(() => File.Replace(temporary, path, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, path));
            }

            moved = true;
        }
        finally
        {
            if (!moved && File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    private static byte[] Unwrap(byte[] stored)
    {
        if (stored.Length > Magic.Length && stored.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new CryptographicException(
                    "This message was protected on Windows and cannot be read on this platform.");
            }

            return UserDataProtection.Unprotect(stored[Magic.Length..], Entropy);
        }

        return stored;
    }

    private MessagePreferences ReadPreferences(out string? damaged)
    {
        damaged = null;
        var path = Path.Combine(Root, PreferencesFileName);

        byte[] stored;
        try
        {
            stored = SharingRetry.Run(() => File.ReadAllBytes(path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new MessagePreferences();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            damaged = ex.Message;
            return new MessagePreferences();
        }

        try
        {
            var preferences = JsonSerializer.Deserialize<MessagePreferences>(Unwrap(stored), SipJson.Readable);
            if (preferences is null)
            {
                damaged = $"{path} holds no preferences";
                return new MessagePreferences();
            }

            return preferences;
        }
        catch (Exception ex) when (ex is JsonException or CryptographicException)
        {
            damaged = ex.Message;
            return new MessagePreferences();
        }
    }

    private static string NewFileName()
    {
#pragma warning disable CA1308 // The name is an identifier; lowercase hex is its file form.
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant() + MessageExtension;
#pragma warning restore CA1308
    }
}
