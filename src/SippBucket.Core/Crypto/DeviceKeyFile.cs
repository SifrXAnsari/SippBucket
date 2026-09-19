using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Crypto;

/// <summary>
/// Protects <c>device.key</c> at rest with the Windows Data Protection API.
/// </summary>
/// <remarks>
/// <para>
/// This closes P1-4. The device key is what opens the authenticated-peer gate: anything
/// holding it can present itself as this machine to every peer that trusts it. It was
/// sitting in <c>%APPDATA%</c> as 32 raw bytes, readable by any process running as the user.
/// </para>
/// <para>
/// DPAPI at current-user scope ties the file to this Windows account's logon credential.
/// Microsoft's own summary is that "Typically, only a user with the same logon credential as
/// the user who encrypted the data can decrypt the data. In addition, the encryption and
/// decryption usually must be done on the same computer"
/// (https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
/// So the file copied on its own to another machine, or read by another ordinary account on
/// this one, yields nothing.
/// </para>
/// <para>
/// <strong>What it does not do, stated because the alternative is implying otherwise.</strong>
/// This paragraph used to say that reading the file from another account yields nothing,
/// full stop. That is not true of three kinds of reader:
/// </para>
/// <list type="bullet">
/// <item>Anything running as this user on this machine, because the whole point is that
/// this user can unwrap it without being asked. Microsoft's DPAPI paper: "all applications
/// running under the same user can access any protected data that they know about"
/// (Windows Data Protection, https://learn.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)).
/// The entropy passed here is written in this program, so it separates nothing.</item>
/// <item>An administrator on this machine while the user is signed in. Administrators hold
/// the Debug programs right by default, which "determines which users can attach to or open
/// any process, even a process they do not own"
/// (https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/debug-programs),
/// and a process running as the user is all it takes to unwrap the key.</item>
/// <item>Anyone who has the user's password and the profile. The same paper: "DPAPI
/// initially generates a strong key called a MasterKey, which is protected by the user's
/// password", and the MasterKey is stored "in the user's profile directory".</item>
/// </list>
/// <para>
/// That is the same limit the repository passphrase has, and for the same reason. A
/// user-supplied secret would close the first and third and would mean typing one before the
/// daemon could sync, which is the trade-off the passphrase already makes explicit
/// elsewhere.
/// </para>
/// <para>
/// The format carries a magic header so the upgrade is unambiguous: a file written by an
/// older build is raw key material, and raw Ed25519 bytes cannot begin with this header
/// except by a 1-in-2^64 accident. A file that is not protected is read anyway and rewritten
/// protected by <see cref="DeviceIdentity.LoadOrCreate"/> the first time it is loaded,
/// through <see cref="UpgradeInPlace"/>, because leaving the old plaintext in place would
/// preserve exactly the leak being closed. For D-51 that call did not exist: nothing
/// outside the tests called <see cref="UpgradeInPlace"/>, so a key written before this
/// class stayed plaintext for ever. The rewrite replaces the file; it cannot scrub the old
/// bytes from the disk's free space, a backup, or a shadow copy taken before it ran.
/// </para>
/// <para>
/// On a platform without DPAPI the bytes are stored as they were. That is a real reduction
/// and it is reported rather than hidden: <c>sip doctor</c> and the window both read the
/// file itself through <see cref="Inspect"/>, never the platform, because the platform can
/// protect a file without this file having been protected (D-51).
/// </para>
/// </remarks>
public static class DeviceKeyFile
{
    private static ReadOnlySpan<byte> Magic => "SIPDKEY1"u8;

    private static ReadOnlySpan<byte> Entropy => "sippbucket-device-key-v1"u8;

    /// <summary>Whether this platform can protect the device key at rest.</summary>
    /// <remarks>
    /// <see cref="OperatingSystem.IsWindows"/> rather than
    /// <c>RuntimeInformation.IsOSPlatform</c>, because only the former is recognised by the
    /// platform-compatibility analyser as a guard. The second form is equally true at run
    /// time and leaves CA1416 firing on every call site, which invites somebody to suppress
    /// the rule rather than satisfy it.
    /// </remarks>
    public static bool IsProtectionAvailable => OperatingSystem.IsWindows();

    /// <summary>Whether a stored file is protected rather than raw key material.</summary>
    /// <param name="stored">The file's bytes.</param>
    /// <returns>True when the protected-file header is present.</returns>
    public static bool IsProtected(ReadOnlySpan<byte> stored) =>
        stored.Length > Magic.Length && stored[..Magic.Length].SequenceEqual(Magic);

    /// <summary>What the key file on disk actually is, read from the file.</summary>
    /// <param name="path">The key file.</param>
    /// <returns>Whether it is protected, stored plain, absent, or could not be read.</returns>
    /// <exception cref="ArgumentException"><paramref name="path"/> was null or blank.</exception>
    /// <remarks>
    /// <para>
    /// The one question every status line about the device key asks, answered from the file
    /// and never from the platform. The window used to print "Device key protected by Windows
    /// (DPAPI)" from <see cref="IsProtectionAvailable"/>, which is
    /// <see cref="OperatingSystem.IsWindows"/>, on a machine whose key was sitting on disk as 32
    /// raw bytes (D-51).
    /// </para>
    /// <para>
    /// Reads only, and zeroes what it read: on a plain file those bytes are the private key.
    /// </para>
    /// </remarks>
    public static DeviceKeyState Inspect(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        byte[] stored;
        try
        {
            if (!File.Exists(path))
            {
                return DeviceKeyState.Missing;
            }

            stored = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return DeviceKeyState.Unreadable;
        }

        try
        {
            return IsProtected(stored) ? DeviceKeyState.Protected : DeviceKeyState.Unprotected;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stored);
        }
    }

    /// <summary>Wraps raw key material for storage.</summary>
    /// <param name="rawKey">The Ed25519 private key.</param>
    /// <returns>The bytes to write.</returns>
    public static byte[] Protect(byte[] rawKey)
    {
        ArgumentNullException.ThrowIfNull(rawKey);

        if (!OperatingSystem.IsWindows())
        {
            return (byte[])rawKey.Clone();
        }

        var wrapped = ProtectWindows(rawKey);
        var file = new byte[Magic.Length + wrapped.Length];
        Magic.CopyTo(file);
        wrapped.CopyTo(file.AsSpan(Magic.Length));

        CryptographicOperations.ZeroMemory(wrapped);
        return file;
    }

    /// <summary>Unwraps stored bytes, tolerating a file written before this existed.</summary>
    /// <param name="stored">The file's bytes.</param>
    /// <returns>The raw key material.</returns>
    /// <exception cref="CryptographicException">The file could not be unprotected.</exception>
    public static byte[] Unprotect(byte[] stored)
    {
        ArgumentNullException.ThrowIfNull(stored);

        if (!IsProtected(stored))
        {
            // Written by a build that predates this. Readable, and rewritten protected by
            // the caller (DeviceIdentity.LoadOrCreate) so the plaintext does not survive.
            return (byte[])stored.Clone();
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new CryptographicException(
                "This device key was protected on Windows and cannot be read on this " +
                "platform. Use the key from the machine that wrote it, or create a new " +
                "identity and re-pair.");
        }

        return UnprotectWindows(stored.AsSpan(Magic.Length).ToArray());
    }

    /// <summary>
    /// Rewrites a device key file so it is protected, if it is not already.
    /// </summary>
    /// <param name="path">The key file.</param>
    /// <returns>True when a plaintext file was upgraded.</returns>
    /// <remarks>
    /// <para>
    /// Same reasoning as the snapshot upgrade: reading the old format forever would preserve
    /// the exact exposure being closed. A file that cannot be rewritten still reads, so this
    /// reports rather than throws, and the next load tries again.
    /// </para>
    /// <para>
    /// The protected form is written beside the file and moved over it; the key file itself
    /// is never opened for writing. This is this machine's identity: a rewrite in place that
    /// was cut short between the truncate and the write would leave neither the old key nor
    /// the new one, and every paired machine would then refuse this one as a stranger. So
    /// until the move, the file under this name is the old key, byte for byte, and after it
    /// the file is a complete protected copy. A test holds the key file open through an
    /// upgrade and reads it back through that handle to show nothing is written into it.
    /// Two processes upgrading at once each move a protected copy of the same key over it,
    /// and either result is correct. Another program holding the file for a moment, as a
    /// scanner may with a file just written, is waited out (see <see cref="MoveOver"/>); one
    /// holding it longer leaves it plain for the next load to try again.
    /// </para>
    /// <para>
    /// <strong>A power cut is a different question, and only half of it is this code's.</strong>
    /// The first version wrote the staging file and renamed it at once, so the rename could
    /// reach the disk before the bytes it names: after a power cut, a key file whose contents
    /// never got there, which is the loss the move was there to prevent. The staged
    /// bytes are now flushed before the move is asked for. <c>FileStream.Flush(true)</c>
    /// "causes any buffered data to be written to the file, and also clears all intermediate
    /// file buffers"
    /// (https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.flush, Flush(Boolean)),
    /// which on Windows calls <c>FlushFileBuffers</c> (<c>FileStreamHelpers.FlushToDisk</c> in
    /// dotnet/runtime, src/libraries/System.Private.CoreLib/src/System/IO/Strategies/
    /// FileStreamHelpers.Windows.cs), and that "writes all the buffered information for a
    /// specified file to the device"
    /// (https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers,
    /// Remarks). The other half, that the rename itself is all or nothing across a power cut,
    /// is the file system's: <c>MoveFileEx</c>'s documentation does not promise it
    /// (https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw),
    /// and no test here can cut the power, so this says only that a rename that did survive
    /// names bytes that were already on the device.
    /// </para>
    /// </remarks>
    public static bool UpgradeInPlace(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!OperatingSystem.IsWindows() || !File.Exists(path))
        {
            return false;
        }

        byte[] stored;
        try
        {
            stored = SharingRetry.Run(() => File.ReadAllBytes(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }

        // Beside the file, so the move is a rename on one volume rather than a copy.
        var staging = $"{path}.{Guid.NewGuid():N}.upgrading";

        try
        {
            if (IsProtected(stored))
            {
                return false;
            }

            WriteDurably(staging, Protect(stored));
            MoveOver(staging, path);
            return true;
        }
        catch (Exception ex) when (ex is IOException
                                       or UnauthorizedAccessException
                                       or CryptographicException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stored);
            DeleteQuietly(staging);
        }
    }

    /// <summary>Writes a new file and flushes it to the device before returning.</summary>
    /// <remarks>
    /// Flushed so that the move which follows cannot reach the disk before these bytes do;
    /// see <see cref="UpgradeInPlace"/>. <see cref="FileMode.CreateNew"/>, because the staging
    /// name is fresh and a file already there would be somebody else's.
    /// </remarks>
    private static void WriteDurably(string path, byte[] bytes)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        file.Write(bytes);
        file.Flush(flushToDisk: true);
    }

    /// <summary>
    /// Moves the staged file over the key file, waiting a moment for another program to let
    /// go of either.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Not <see cref="SharingRetry"/> alone, because the refusal is not the error it waits
    /// for. Replacing a file that another handle has open fails with <c>ERROR_ACCESS_DENIED</c>
    /// (5), surfaced as <see cref="UnauthorizedAccessException"/>, whatever that handle
    /// shares: measured on the desktop with a handle sharing read, read and write, and read,
    /// write and delete, all three refused with 5. <see cref="SharingRetry"/> waits only on
    /// 32 and 33, so a scanner reading the key file for a moment, as one may with any file
    /// just written, defeated the upgrade until the next load.
    /// </para>
    /// <para>
    /// So access denied is waited on here too, for the same patience and no longer. A file
    /// that really is read-only, or whose permissions forbid the replace, costs that wait
    /// once per load and then leaves the key readable and plain, which is reported.
    /// </para>
    /// </remarks>
    private static void MoveOver(string staging, string path)
    {
        var elapsed = Stopwatch.StartNew();
        var pause = TimeSpan.FromMilliseconds(10);

        while (true)
        {
            try
            {
                File.Move(staging, path, overwrite: true);
                return;
            }
            catch (Exception ex) when (
                (ex is UnauthorizedAccessException ||
                 (ex is IOException io && SharingRetry.IsSharingViolation(io))) &&
                elapsed.Elapsed + pause < SharingRetry.Patience)
            {
                Thread.Sleep(pause);
                pause = pause * 2 < MaximumPause ? pause * 2 : MaximumPause;
            }
        }
    }

    private static TimeSpan MaximumPause => TimeSpan.FromMilliseconds(250);

    /// <summary>Removes a staging file that was not moved into place, if there is one.</summary>
    /// <remarks>
    /// It holds the protected form, not the key itself, so one left behind by a failure here
    /// is litter rather than a leak, and failing to remove it is not worth failing the load
    /// for: this runs in a <c>finally</c>, where a throw would replace the upgrade's own
    /// "not upgraded" with an exception out of <see cref="DeviceIdentity.LoadOrCreate"/>.
    /// After a successful move there is nothing at this name and the delete does nothing.
    /// </remarks>
    private static void DeleteQuietly(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Litter, as above. The next upgrade stages under a fresh name.
        }
        catch (UnauthorizedAccessException)
        {
            // Likewise.
        }
    }

    /// <remarks>
    /// The DPAPI call itself lives in <see cref="UserDataProtection"/>, shared with the direct
    /// message store; this file's entropy keeps a device key from being read as anything else.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    private static byte[] ProtectWindows(byte[] rawKey) => UserDataProtection.Protect(rawKey, Entropy);

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectWindows(byte[] wrapped) => UserDataProtection.Unprotect(wrapped, Entropy);
}

/// <summary>What <c>device.key</c> is on disk, as <see cref="DeviceKeyFile.Inspect"/> finds it.</summary>
public enum DeviceKeyState
{
    /// <summary>There is no key file yet. One is created, protected, when first needed.</summary>
    Missing = 0,

    /// <summary>The file is in the DPAPI-protected form.</summary>
    Protected = 1,

    /// <summary>The file is the raw key: written by an older build, or on a platform without DPAPI.</summary>
    Unprotected = 2,

    /// <summary>The file is there and could not be read.</summary>
    Unreadable = 3,
}
