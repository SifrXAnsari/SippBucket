using System.Reflection;

namespace SippBucket.Core.Platform;

/// <summary>This build's SippBucket version, as the Server.ID record and the health summary report it.</summary>
/// <remarks>
/// The one version in <c>Directory.Build.props</c>, read from this assembly's informational
/// version. The build may append the source revision after a <c>+</c>; that is dropped, so the
/// version is what a person installs, and it fits the record's 32 characters.
/// </remarks>
public static class BuildVersion
{
    /// <summary>The version, for example "1.1.0".</summary>
    public static string Current { get; } = Read();

    private static string Read()
    {
        var assembly = typeof(BuildVersion).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        var version = string.IsNullOrWhiteSpace(informational)
            ? assembly.GetName().Version?.ToString(3) ?? "0.0.0"
            : informational;

        var plus = version.IndexOf('+', StringComparison.Ordinal);
        return (plus < 0 ? version : version[..plus]).Trim();
    }
}
