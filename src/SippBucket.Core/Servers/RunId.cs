using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;

namespace SippBucket.Core.Servers;

/// <summary>
/// The ephemeral Server.ID: a random value made fresh each time SippBucket starts, which
/// answers "has that server restarted since I last heard from it?".
/// </summary>
/// <remarks>
/// <para>
/// One of Server.ID's three layers (docs/SERVER-ID.md), and the one that replaced discovery's
/// <c>InstanceId</c> rather than living beside it: one concept, one name. It says nothing about
/// the hardware, so it may appear wherever <c>InstanceId</c> did, local discovery's plaintext
/// announcement included.
/// </para>
/// <para>
/// Per process: every SippBucket process is a run of its own, the tray's daemon and each
/// command alike. 128 random bits, written as 32 lower-case hexadecimal characters.
/// </para>
/// </remarks>
public static class RunId
{
    /// <summary>How many characters a run ID has.</summary>
    public const int Length = 32;

    /// <summary>This process's run ID.</summary>
    public static string Current { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(Length / 2));

    /// <summary>When this run began, in UTC: when the process started, as Windows records it.</summary>
    public static DateTimeOffset Started { get; } = ProcessStart();

    /// <summary>Whether a value has a run ID's form.</summary>
    /// <param name="value">The value.</param>
    /// <returns>True for exactly 32 lower-case hexadecimal characters.</returns>
    public static bool IsWellFormed(string? value) =>
        value is { Length: Length } && value.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');

    private static DateTimeOffset ProcessStart()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            return new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or Win32Exception)
        {
            // Windows would not say. The first moment anything asked is the nearest answer,
            // and the daemon asks at its start.
            return DateTimeOffset.UtcNow;
        }
    }
}
