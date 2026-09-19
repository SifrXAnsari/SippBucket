using SippBucket.Core.Platform;

namespace SippBucket.Core.Push;

/// <summary>
/// Whether a pushed file's name may be written as it is: one name that Windows will open as
/// itself, and nothing more.
/// </summary>
/// <remarks>
/// <para>
/// A pushed file arrives into a flat inbox under the name it was sent with, so the name is
/// attacker-controlled input exactly as a snapshot path is (<see cref="Repository.SafePath"/>),
/// and it is refused rather than tidied up for the same reason: no honest sender produces one
/// that fails, and a sanitiser invites a search for the encoding it misses. The sender applies
/// the same rule before it offers a file, so a refusal on arrival means the sender is not
/// SippBucket, or not an honest one.
/// </para>
/// <para>
/// The rules, each for a way a name can mean something other than itself on Windows: one
/// component, so no separator and no <c>.</c> or <c>..</c>; none of the characters Windows
/// forbids in a name, which includes the colon an alternate data stream rides on; no control
/// characters; no trailing dot or space, which Windows strips, so <c>report.pdf.</c> would land
/// on <c>report.pdf</c>; no device name such as <c>CON</c> or <c>COM1</c>, with any extension;
/// at most 255 characters, NTFS's limit for a name; and no character that reorders how the
/// rest of the name is displayed, so <c>photo[U+202E]gpj.exe</c>, which shows as
/// <c>photoexe.jpg</c>, cannot pass for a picture in the inbox.
/// </para>
/// </remarks>
public static class PushName
{
    /// <summary>The longest name accepted, in UTF-16 code units: NTFS's limit for one name.</summary>
    public const int MaximumLength = 255;

    /// <summary>Names Windows reserves for devices, in any folder and with any extension.</summary>
    /// <remarks>
    /// Windows treats the superscript digits ¹, ² and ³ as digits here, so <c>COM¹</c> is a
    /// device too.
    /// </remarks>
    private static readonly string[] DeviceNames =
    [
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "COM¹", "COM²", "COM³",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "LPT¹", "LPT²", "LPT³",
    ];

    /// <summary>Checks a name.</summary>
    /// <param name="name">The name, as sent.</param>
    /// <param name="reason">Why it is refused, when this returns false.</param>
    /// <returns>True when the name may be written as it is.</returns>
    public static bool IsAcceptable(string? name, out string reason)
    {
        if (string.IsNullOrEmpty(name))
        {
            reason = "the name is empty";
            return false;
        }

        if (name.Length > MaximumLength)
        {
            reason = $"the name is {name.Length} characters long, and a name may be at most {MaximumLength}";
            return false;
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            reason = "the name is only spaces";
            return false;
        }

        if (name is "." or "..")
        {
            reason = "the name is a folder reference, not a file name";
            return false;
        }

        foreach (var character in name)
        {
            if (char.IsControl(character))
            {
                reason = "the name contains a control character";
                return false;
            }

            if (character is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*')
            {
                reason = $"the name contains '{character}', which Windows does not allow in a name";
                return false;
            }

            if (DisplayText.ReordersDisplay(character))
            {
                reason = "the name contains a character that reorders how the rest of it is displayed";
                return false;
            }
        }

        if (HasUnpairedSurrogate(name))
        {
            reason = "the name is not valid Unicode";
            return false;
        }

        if (name.EndsWith(' ') || name.EndsWith('.'))
        {
            reason = "the name ends with a space or a dot, which Windows removes";
            return false;
        }

        var stem = name.Split('.')[0].TrimEnd(' ');
        foreach (var device in DeviceNames)
        {
            if (string.Equals(stem, device, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"'{device}' is a name Windows reserves for a device";
                return false;
            }
        }

        reason = string.Empty;
        return true;
    }

    private static bool HasUnpairedSurrogate(string name)
    {
        for (var i = 0; i < name.Length; i++)
        {
            if (char.IsHighSurrogate(name[i]))
            {
                if (i + 1 >= name.Length || !char.IsLowSurrogate(name[i + 1]))
                {
                    return true;
                }

                i++;
            }
            else if (char.IsLowSurrogate(name[i]))
            {
                return true;
            }
        }

        return false;
    }
}
