namespace SippBucket.Core.Platform;

/// <summary>
/// Where SippBucket keeps per-user state that belongs to no single folder: the device key
/// and the tray's list of watched folders.
/// </summary>
/// <remarks>
/// <para>
/// One definition, used by both the command line and the tray. They previously each built
/// the path themselves. That was harmless while the two agreed, but they are one program
/// now — the tray starts its own command line — and two copies of this rule are how the
/// window and the console would come to disagree about which device they are.
/// </para>
/// <para>
/// <see cref="OverrideVariable"/> points everything at another directory. It exists so the
/// program can be run end to end — tray, window and console together — against a
/// throwaway identity and watch list, without reading or writing the real ones. A second
/// directory is also a second device key, and therefore a second device ID, which is the
/// honest way to stand up two instances on one machine. Relative paths are ignored, so a
/// stray value cannot silently redirect the device key into whatever the working directory
/// happens to be.
/// </para>
/// </remarks>
public static class UserDataDirectory
{
    /// <summary>The environment variable that overrides the location.</summary>
    public const string OverrideVariable = "SIPPBUCKET_DATA_DIR";

    /// <summary>The directory to use, honouring <see cref="OverrideVariable"/>.</summary>
    /// <returns>An absolute path. It may not exist yet.</returns>
    public static string Resolve()
    {
        var configured = Environment.GetEnvironmentVariable(OverrideVariable);

        if (!string.IsNullOrWhiteSpace(configured) && System.IO.Path.IsPathFullyQualified(configured))
        {
            return configured;
        }

        return System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SippBucket");
    }
}
