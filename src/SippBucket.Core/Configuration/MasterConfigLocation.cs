using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SippBucket.Core.Configuration;

/// <summary>
/// Decides whether a process with administrator rights may write <c>master.json</c> where it
/// is about to.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why.</b> <c>sip config set</c> writes <c>C:\ProgramData\SippBucket\master.json</c> from a
/// copy of itself elevated through UAC. Until the installer gives that folder permissions of
/// its own (task <c>pack</c>), it inherits ProgramData's, which let any account create a
/// subfolder there (<see cref="MasterConfig"/> has the measurement). So a standard account can
/// make <c>C:\ProgramData\SippBucket</c> before an administrator ever does: as a folder it
/// owns, whose files it can then change at will, or as a junction to anywhere, through which
/// the elevated write would land wherever the junction points. Neither may be written
/// through with an administrator's rights.
/// </para>
/// <para>
/// <b>What is refused.</b> A folder, or an existing <c>master.json</c>, that is a reparse point
/// (a junction, a symbolic link or anything else Windows redirects), whatever it points at.
/// And a folder, or an existing <c>master.json</c>, whose owner is not an administrator: the
/// Administrators group, SYSTEM, or the administrator's own account running elevated. The
/// last is there because under UAC what an administrator creates can be owned by their own
/// account rather than by the group: "User Account Control (UAC) will ensure the user
/// account is being used as owner for all objects created locally" (KB 947721,
/// https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/default-owner-objects-created-members-administrators-group-not-available).
/// It is accepted only for the account this process runs as, and only while this process is
/// in the Administrators role, which an unelevated token is not.
/// </para>
/// <para>
/// <b>What it does not do.</b> It does not make the folder administrator-only: that is the
/// installer's ACL. It checks once, just before the write, so a standard account that could
/// replace what was checked in the moment between would still win; with an administrator as
/// owner and ProgramData's inherited permissions, a standard account cannot delete or rename
/// the folder or an administrator's <c>master.json</c>, so there is nothing for it to
/// replace. And a process that is not elevated is not checked at all: it writes with no more
/// rights than its account already has, which is the <c>SIPPBUCKET_DATA_DIR</c> sandbox.
/// </para>
/// </remarks>
internal static class MasterConfigLocation
{
    /// <summary>
    /// Refuses <paramref name="directory"/> and <paramref name="file"/> for a write made with
    /// administrator rights, or returns when they may be written.
    /// </summary>
    /// <param name="directory">The folder <c>master.json</c> is in; it must exist.</param>
    /// <param name="file">The file itself, which need not exist.</param>
    /// <param name="ownerOf">
    /// Reads a path's owner, or null when it cannot. Tests pass their own, because nothing a
    /// test without administrator rights can create is owned by an administrator.
    /// </param>
    /// <exception cref="UntrustedLocationException">The location is refused.</exception>
    public static void Check(string directory, string file, Func<string, SecurityIdentifier?>? ownerOf = null)
    {
        foreach (var path in Existing(directory, file))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new UntrustedLocationException(
                    UntrustedLocation.LinkedElsewhere,
                    path,
                    $"{path} is a junction or a link to somewhere else, and master.json is never written through one " +
                    "with administrator rights. Remove it, then try again.");
            }
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new UntrustedLocationException(
                UntrustedLocation.OwnerUnknown,
                directory,
                $"Who owns {directory} cannot be checked on this platform, so master.json is not written there " +
                "with administrator rights.");
        }

        var readOwner = ownerOf ?? OwnerOf;
        using var current = WindowsIdentity.GetCurrent();

        foreach (var path in Existing(directory, file))
        {
            var owner = readOwner(path);
            if (owner is null)
            {
                throw new UntrustedLocationException(
                    UntrustedLocation.OwnerUnknown,
                    path,
                    $"Who owns {path} could not be read, so nothing says an administrator made it. " +
                    "master.json was not written.");
            }

            if (!IsAdministratorOwner(owner, current))
            {
                throw new UntrustedLocationException(
                    UntrustedLocation.NotAdministratorOwned,
                    path,
                    $"{path} belongs to {NameOf(owner)}, not to an administrator or SYSTEM, so another account " +
                    "could have made it and could change it later. master.json is not written there with " +
                    "administrator rights. Delete it as an administrator, or reinstall SippBucket, then try again.");
            }
        }
    }

    /// <summary>Whether a path's owner is one an administrator's write may trust.</summary>
    /// <param name="owner">The owner.</param>
    /// <param name="current">The account this process runs as.</param>
    /// <returns>
    /// True for the Administrators group, for SYSTEM, and for this process's own account while
    /// this process holds the Administrators role.
    /// </returns>
    [SupportedOSPlatform("windows")]
    public static bool IsAdministratorOwner(SecurityIdentifier owner, WindowsIdentity current)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(current);

        if (owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
            owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            return true;
        }

        return current.User is { } account &&
               owner.Equals(account) &&
               new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static IEnumerable<string> Existing(string directory, string file)
    {
        yield return directory;

        if (File.Exists(file))
        {
            yield return file;
        }
    }

    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier? OwnerOf(string path)
    {
        try
        {
            FileSystemSecurity security = Directory.Exists(path)
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Owner);

            return security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PrivilegeNotHeldException)
        {
            // Reported by the caller as an owner that could not be read, and refused.
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string NameOf(SecurityIdentifier owner)
    {
        try
        {
            return owner.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return owner.Value;
        }
    }
}

/// <summary>Why a write of <c>master.json</c> with administrator rights refused its location.</summary>
public enum UntrustedLocation
{
    /// <summary>The folder, or the file, is a junction, symbolic link or other reparse point.</summary>
    LinkedElsewhere,

    /// <summary>The folder, or the file, belongs to an account that is not an administrator.</summary>
    NotAdministratorOwned,

    /// <summary>Who owns the folder or the file could not be read.</summary>
    OwnerUnknown,
}

/// <summary>
/// Thrown when <c>sip config set</c>, running with administrator rights, refuses to write
/// <c>master.json</c> where it is. Nothing was written.
/// </summary>
/// <remarks>
/// An <see cref="UnauthorizedAccessException"/>, because that is what it is to anything that
/// already handles a write it may not make.
/// </remarks>
public sealed class UntrustedLocationException : UnauthorizedAccessException
{
    /// <summary>Creates the exception for one refused path.</summary>
    /// <param name="reason">Why it was refused.</param>
    /// <param name="path">The folder or file refused.</param>
    /// <param name="message">What happened, for a person.</param>
    public UntrustedLocationException(UntrustedLocation reason, string path, string message)
        : base(message)
    {
        Reason = reason;
        Path = path;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public UntrustedLocationException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public UntrustedLocationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public UntrustedLocationException()
        : base("master.json was not written: its location could not be trusted.")
    {
    }

    /// <summary>Why the location was refused, when known.</summary>
    public UntrustedLocation? Reason { get; }

    /// <summary>The folder or file refused, when known.</summary>
    public string? Path { get; }
}
