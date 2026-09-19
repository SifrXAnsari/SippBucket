using SippBucket.Core.Platform;

namespace SippBucket.Tray;

/// <summary>
/// Tells the data directory a person's own SippBucket uses apart from a sandbox.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="UserDataDirectory"/> honours <c>SIPPBUCKET_DATA_DIR</c> so the program can be
/// run end to end against a throwaway identity and watch list. Two things in the tray must
/// then behave differently for a sandbox, and both would otherwise reach the user's real
/// copy: the single-instance guard, whose fixed name let a harness-launched tray signal the
/// user's window instead of starting, and first-run autostart, which writes the user's
/// real startup list.
/// </para>
/// <para>
/// The test is on the directory, not on whether the variable is set. A relative value is
/// ignored by <see cref="UserDataDirectory.Resolve"/>, and a value naming the default
/// directory points at the real data; in both cases this is the user's own copy, and treating
/// it as a sandbox would let two trays run over one watch list — D-34 from the outside.
/// </para>
/// </remarks>
internal static class DataDirectories
{
    /// <summary>The directory this process uses.</summary>
    public static string Current => UserDataDirectory.Resolve();

    /// <summary>The directory used when nothing overrides it.</summary>
    /// <remarks>
    /// The same fallback <see cref="UserDataDirectory.Resolve"/> applies, restated because Core
    /// does not expose it on its own. Compatibility already fixes it - an installed copy's
    /// device key and watch list live there - and a test pins the two definitions together so
    /// that one cannot move without the other.
    /// </remarks>
    public static string Default =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SippBucket");

    /// <summary>Whether this process runs against a directory other than the default.</summary>
    public static bool IsSandboxed => !Same(Current, Default);

    /// <summary>Whether two directory paths name the same directory.</summary>
    /// <param name="left">A fully qualified path.</param>
    /// <param name="right">Another fully qualified path.</param>
    /// <returns>True when they differ only by case or a trailing separator.</returns>
    /// <remarks>
    /// Case-insensitive because NTFS directories are, by default, and a trailing separator is
    /// ignored because one source of these paths (an MSI directory property) always carries
    /// one and the others never do.
    /// </remarks>
    public static bool Same(string left, string right) =>
        string.Equals(Normalise(left), Normalise(right), StringComparison.OrdinalIgnoreCase);

    /// <summary>A directory path in one canonical spelling, for comparing and hashing.</summary>
    /// <param name="directory">A fully qualified path.</param>
    /// <returns>The full path, without trailing separators, upper-cased invariantly.</returns>
    public static string Normalise(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        var full = Path.GetFullPath(directory);
        var root = Path.GetPathRoot(full) ?? string.Empty;

        // A drive root keeps its separator: "C:" alone means "the current directory on C:".
        var trimmed = full.Length > root.Length
            ? full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            : full;

        return trimmed.ToUpperInvariant();
    }
}
