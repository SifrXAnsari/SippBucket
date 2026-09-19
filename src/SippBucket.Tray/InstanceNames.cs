using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SippBucket.Tray;

/// <summary>
/// The names of the kernel objects that keep the tray to one copy per data directory.
/// </summary>
/// <param name="MutexName">The mutex the running tray holds.</param>
/// <param name="ShowEventName">The event a second launch signals to bring the window up.</param>
/// <remarks>
/// <para>
/// One copy per <em>data directory</em>, not per machine, because the data directory is what
/// two trays would fight over: one watch list, one device key, one set of folders restored
/// into at once (D-34).
/// </para>
/// <para>
/// The installed product uses the names it has always used. A sandboxed run - the e2e harness,
/// or anyone pointing <c>SIPPBUCKET_DATA_DIR</c> at a throwaway directory - gets names with a
/// hash of that directory in them. With one fixed name for everything, a harness tray
/// started while the user's own SippBucket was running would find the user's mutex taken,
/// signal the <em>user's</em> window to come forward, and exit: the test would touch the
/// real instance and then measure it. Different directories now never share a name, and the
/// default directory never shares one with a sandbox.
/// </para>
/// </remarks>
internal readonly record struct InstanceNames(string MutexName, string ShowEventName)
{
    /// <summary>The names the installed product has always used, kept exactly.</summary>
    public static InstanceNames Installed { get; } =
        new(@"Local\SippBucket.Tray", @"Local\SippBucket.Tray.Show");

    /// <summary>The names for this process, from its data directory.</summary>
    /// <returns>The installed names, or a sandbox's own.</returns>
    public static InstanceNames ForThisProcess() =>
        For(DataDirectories.Current, DataDirectories.Default);

    /// <summary>The names for a tray running against <paramref name="dataDirectory"/>.</summary>
    /// <param name="dataDirectory">The data directory in use.</param>
    /// <param name="defaultDataDirectory">The data directory used when nothing overrides it.</param>
    /// <returns>
    /// <see cref="Installed"/> for the default directory, however it is spelled; otherwise
    /// names carrying a hash of the directory.
    /// </returns>
    /// <remarks>
    /// The hash is 64 bits of SHA-256 over the normalised path, so it is stable across runs
    /// and processes, which is the whole requirement. Truncated to 64 bits, a collision
    /// between two sandboxes is vanishingly unlikely, and if one ever happened the two would
    /// exclude each other - the safe direction. A sandbox name can never equal an installed
    /// one: the installed names have no hash segment at all.
    /// </remarks>
    public static InstanceNames For(string dataDirectory, string defaultDataDirectory)
    {
        if (DataDirectories.Same(dataDirectory, defaultDataDirectory))
        {
            return Installed;
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(DataDirectories.Normalise(dataDirectory)));
        var tag = Convert.ToHexStringLower(digest.AsSpan(0, 8));

        return new InstanceNames(
            string.Create(CultureInfo.InvariantCulture, $@"Local\SippBucket.Tray.{tag}"),
            string.Create(CultureInfo.InvariantCulture, $@"Local\SippBucket.Tray.{tag}.Show"));
    }
}
