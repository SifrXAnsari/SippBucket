using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Platform;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Discovery;

/// <summary>
/// The discovery keys this person's machine holds: those it minted, one per peer it
/// announces to, and those its peers minted for it, which are what let it recognise their
/// announcements (docs/DISCOVERY.md, "Which key").
/// </summary>
/// <remarks>
/// <para>
/// One key per ordered pair of machines, fetched over the authenticated sync channel, never
/// broadcast. The repository key was rejected for this job because every former member keeps
/// it forever; a shared per-machine key was rejected because revoking one peer would mean
/// re-keying every other. With a key per pair, revocation is simply not putting that peer's
/// token in the next packet — and deleting its key here is only tidying.
/// </para>
/// <para>
/// Both stores live in one protected file with a neutral name, wrapped the way the message
/// store wraps its files (<see cref="UserDataProtection"/>): the keys gate only the
/// recognition of presence hints, but a copy of them would let a bystander recognise, or
/// forge, this machine's presence beacons, so they are not left in the clear. On a platform
/// without DPAPI they are stored plain and <see cref="ProtectionAvailable"/> says so.
/// </para>
/// <para>
/// A file that cannot be read means no keys — nothing announced for, nothing recognised —
/// never guessed keys; it is reported by the caller, and answering a peer's fetch mints a
/// fresh key, which repairs the announcer's half by itself.
/// </para>
/// </remarks>
public sealed class DiscoveryKeys
{
    /// <summary>The file's name in the data directory.</summary>
    public const string FileName = "discovery.json";

    /// <summary>The schema this build writes.</summary>
    public const int CurrentSchema = 1;

    private static ReadOnlySpan<byte> Magic => "SIPDISC1"u8;

    private static ReadOnlySpan<byte> Entropy => "sippbucket-discovery-keys-v1"u8;

    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);

    private readonly object _gate;

    /// <summary>Creates a store over a file.</summary>
    /// <param name="path">Full path to the store.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public DiscoveryKeys(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        FilePath = path;
        _gate = Gates.GetOrAdd(Path.GetFullPath(path), static _ => new object());
    }

    /// <summary>The file this store reads and writes.</summary>
    public string FilePath { get; }

    /// <summary>Whether this platform protects the file at rest. False is reported, not hidden.</summary>
    public static bool ProtectionAvailable => UserDataProtection.IsAvailable;

    /// <summary>The store for the person running this process.</summary>
    /// <returns>The store in the data directory, honouring its override.</returns>
    public static DiscoveryKeys ForThisUser() => new(Path.Combine(UserDataDirectory.Resolve(), FileName));

    /// <summary>
    /// The key this machine minted for one peer, minting one if none exists: what a peer's
    /// fetch over the channel is answered with, and what this machine's packets token with.
    /// </summary>
    /// <param name="peerDeviceId">The peer.</param>
    /// <returns>The 32-byte key, base64.</returns>
    /// <exception cref="ArgumentException">The device ID is blank.</exception>
    /// <exception cref="InvalidOperationException">The store cannot be read or written; the message names it.</exception>
    public string MintedFor(string peerDeviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerDeviceId);

        lock (_gate)
        {
            var stored = Read();
            if (Find(stored.Minted, peerDeviceId) is { } existing)
            {
                return existing.KeyBase64;
            }

            var fresh = new StoredKey(Lower(peerDeviceId), Convert.ToBase64String(DiscoveryPacket.NewKey()));
            Write(stored with { Minted = [.. stored.Minted, fresh] });
            return fresh.KeyBase64;
        }
    }

    /// <summary>Every key this machine minted, for building its packets.</summary>
    /// <returns>The peers and their keys. Empty when there is no file yet.</returns>
    /// <exception cref="InvalidOperationException">The store cannot be read; the message names it.</exception>
    public IReadOnlyList<(string DeviceId, byte[] Key)> Minted()
    {
        lock (_gate)
        {
            return Decode(Read().Minted);
        }
    }

    /// <summary>Keeps a key a peer minted for this machine, replacing any earlier one from it.</summary>
    /// <param name="peerDeviceId">The announcer.</param>
    /// <param name="keyBase64">Its key, 32 bytes base64.</param>
    /// <exception cref="ArgumentException">The device ID is blank, or the key is not a discovery key.</exception>
    /// <exception cref="InvalidOperationException">The store cannot be read or written; the message names it.</exception>
    public void StoreTheirs(string peerDeviceId, string keyBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerDeviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyBase64);

        byte[] key;
        try
        {
            key = Convert.FromBase64String(keyBase64);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("A discovery key is base64.", nameof(keyBase64), ex);
        }

        if (key.Length != DiscoveryPacket.KeySize)
        {
            throw new ArgumentException($"A discovery key is {DiscoveryPacket.KeySize} bytes.", nameof(keyBase64));
        }

        lock (_gate)
        {
            var stored = Read();
            var kept = stored.Theirs.Where(entry => !SameDevice(entry.DeviceId, peerDeviceId)).ToList();
            kept.Add(new StoredKey(Lower(peerDeviceId), keyBase64));
            Write(stored with { Theirs = kept });
        }
    }

    /// <summary>Every key peers minted for this machine: what its listener recognises tokens with.</summary>
    /// <returns>The announcers and their keys. Empty when there is no file yet.</returns>
    /// <exception cref="InvalidOperationException">The store cannot be read; the message names it.</exception>
    public IReadOnlyList<(string DeviceId, byte[] Key)> Theirs()
    {
        lock (_gate)
        {
            return Decode(Read().Theirs);
        }
    }

    /// <summary>Forgets everything about one device: on removal, only tidying — see the class remarks.</summary>
    /// <param name="peerDeviceId">The device.</param>
    public void Forget(string peerDeviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerDeviceId);

        lock (_gate)
        {
            var stored = Read();
            Write(stored with
            {
                Minted = [.. stored.Minted.Where(entry => !SameDevice(entry.DeviceId, peerDeviceId))],
                Theirs = [.. stored.Theirs.Where(entry => !SameDevice(entry.DeviceId, peerDeviceId))],
            });
        }
    }

    private static List<(string DeviceId, byte[] Key)> Decode(IReadOnlyList<StoredKey> entries)
    {
        var decoded = new List<(string, byte[])>(entries.Count);
        foreach (var entry in entries)
        {
            byte[] key;
            try
            {
                key = Convert.FromBase64String(entry.KeyBase64);
            }
            catch (FormatException)
            {
                continue;
            }

            if (key.Length == DiscoveryPacket.KeySize && !string.IsNullOrWhiteSpace(entry.DeviceId))
            {
                decoded.Add((entry.DeviceId, key));
            }
        }

        return decoded;
    }

    private static StoredKey? Find(IReadOnlyList<StoredKey> entries, string deviceId) =>
        entries.FirstOrDefault(entry => SameDevice(entry.DeviceId, deviceId));

    private static bool SameDevice(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static string Lower(string deviceId)
    {
#pragma warning disable CA1308 // Device IDs are identifiers; lowercase hex is their record form.
        return deviceId.ToLowerInvariant();
#pragma warning restore CA1308
    }

    private StoredFile Read()
    {
        byte[] stored;
        try
        {
            stored = SharingRetry.Run(() => File.ReadAllBytes(FilePath));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new StoredFile(CurrentSchema, [], []);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"{FilePath} cannot be read ({ex.Message}). Until it is mended or deleted, nothing is announced " +
                "and no announcement is recognised.", ex);
        }

        byte[] plaintext;
        if (stored.Length > Magic.Length && stored.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new InvalidOperationException(
                    $"{FilePath} was protected on Windows and cannot be read on this platform.");
            }

            try
            {
                plaintext = UserDataProtection.Unprotect(stored[Magic.Length..], Entropy);
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException(
                    $"{FilePath} cannot be unprotected ({ex.Message}). Until it is mended or deleted, nothing is " +
                    "announced and no announcement is recognised.", ex);
            }
        }
        else
        {
            plaintext = stored;
        }

        try
        {
            var file = JsonSerializer.Deserialize<StoredFile>(plaintext, SipJson.Readable);
            return file is { Minted: not null, Theirs: not null }
                ? file
                : new StoredFile(CurrentSchema, [], []);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"{FilePath} cannot be read ({ex.Message}). Until it is mended or deleted, nothing is announced " +
                "and no announcement is recognised.", ex);
        }
    }

    private void Write(StoredFile file)
    {
        var directory = Path.GetDirectoryName(FilePath)
            ?? throw new InvalidOperationException($"{FilePath} has no directory.");
        Directory.CreateDirectory(directory);

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(file with { Schema = CurrentSchema }, SipJson.Readable);

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
            wrapped = plaintext;
        }

        var temporary = $"{FilePath}.{Guid.NewGuid():N}.tmp";
        var moved = false;
        try
        {
            File.WriteAllBytes(temporary, wrapped);

            if (File.Exists(FilePath))
            {
                SharingRetry.Run(() => File.Replace(temporary, FilePath, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, FilePath));
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

    /// <summary>One peer's key, as stored.</summary>
    /// <param name="DeviceId">The peer, lowercase hexadecimal.</param>
    /// <param name="KeyBase64">The 32-byte key, base64.</param>
    private sealed record StoredKey(string DeviceId, string KeyBase64);

    /// <summary>The file as stored.</summary>
    /// <param name="Schema">The schema it was written in.</param>
    /// <param name="Minted">Keys this machine minted, one per peer it announces to.</param>
    /// <param name="Theirs">Keys peers minted for this machine.</param>
    private sealed record StoredFile(int Schema, IReadOnlyList<StoredKey> Minted, IReadOnlyList<StoredKey> Theirs);
}
