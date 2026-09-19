using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace SippBucket.Core.Servers;

/// <summary>
/// This install's Windows edition and version, for the <c>installs</c> of its
/// <c>sippbucket.server/1</c> record: "Windows 11 Home 25H2, build 26200.6899".
/// </summary>
/// <remarks>
/// <para>
/// Read from <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</c>, which every account may
/// read: <c>ProductName</c>, <c>DisplayVersion</c>, <c>CurrentBuildNumber</c> and <c>UBR</c>.
/// Windows 11 still writes "Windows 10" in <c>ProductName</c>, so from build 22000, Windows 11's
/// first, the name is corrected; that is the one rule applied to what the registry says.
/// </para>
/// <para>
/// Display only: it tells the person which install of a dual-boot board is which. Where the
/// registry cannot be read, the runtime's own description is used instead.
/// </para>
/// </remarks>
public static class WindowsRelease
{
    /// <summary>The longest description a record carries.</summary>
    public const int MaximumLength = 128;

    private const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    private const int FirstWindows11Build = 22000;

    /// <summary>This install's Windows, in words.</summary>
    /// <returns>For example "Windows 11 Home 25H2, build 26200.6899".</returns>
    public static string Describe()
    {
        var description = OperatingSystem.IsWindows() ? FromRegistry() : null;
        description ??= RuntimeInformation.OSDescription.Trim();
        return description.Length <= MaximumLength ? description : description[..MaximumLength];
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? FromRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CurrentVersionKey);
            if (key?.GetValue("ProductName") is not string product || string.IsNullOrWhiteSpace(product))
            {
                return null;
            }

            var buildText = key.GetValue("CurrentBuildNumber") as string;
            var build = int.TryParse(buildText, NumberStyles.None, CultureInfo.InvariantCulture, out var number) ? number : 0;
            if (build >= FirstWindows11Build && product.StartsWith("Windows 10", StringComparison.Ordinal))
            {
                product = string.Concat("Windows 11", product.AsSpan("Windows 10".Length));
            }

            var parts = new List<string> { product.Trim() };
            if (key.GetValue("DisplayVersion") is string display && !string.IsNullOrWhiteSpace(display))
            {
                parts[0] = $"{parts[0]} {display.Trim()}";
            }

            if (build > 0)
            {
                parts.Add(key.GetValue("UBR") is int revision
                    ? string.Create(CultureInfo.InvariantCulture, $"build {build}.{revision}")
                    : string.Create(CultureInfo.InvariantCulture, $"build {build}"));
            }

            return string.Join(", ", parts);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}
