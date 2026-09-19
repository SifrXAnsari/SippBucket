using System.Globalization;

namespace SippBucket.Core.Servers;

/// <summary>
/// The servers this machine knows, as read from <see cref="KnownServers"/>, with the numbers the
/// rule gives them: what every listing, log line and lookup names machines by.
/// </summary>
public sealed class ServerDirectory
{
    private readonly IReadOnlyDictionary<string, int> _numbers;

    internal ServerDirectory(ThisInstall? self, IReadOnlyList<KnownServer> servers, IReadOnlyDictionary<string, int> numbers)
    {
        Self = self;
        Servers = servers;
        _numbers = numbers;
    }

    /// <summary>An empty directory, for a machine whose <c>servers.json</c> cannot be read.</summary>
    public static ServerDirectory Empty { get; } = new(null, [], new Dictionary<string, int>());

    /// <summary>This install's own part, or null before its first record.</summary>
    public ThisInstall? Self { get; }

    /// <summary>Every other server known, hearsay included.</summary>
    public IReadOnlyList<KnownServer> Servers { get; }

    /// <summary>The number a server has, by permanent ID.</summary>
    /// <param name="permanent">The permanent ID.</param>
    /// <returns>Its number, or null for a server not known.</returns>
    public int? NumberOf(string permanent) =>
        permanent is not null && _numbers.TryGetValue(permanent, out var number) ? number : null;

    /// <summary>The server a device is an install of.</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>The server heard from directly first, then one only heard about; null when neither.</returns>
    public KnownServer? ServerOf(string deviceId)
    {
        if (string.IsNullOrEmpty(deviceId))
        {
            return null;
        }

        return Servers
            .Where(server => server.Installs.Any(install => string.Equals(install.Device, deviceId, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(server => server.HeardFrom is null ? 0 : 1)
            .FirstOrDefault();
    }

    /// <summary>A device's server by number and label: "Server 2 (Dell Inspiron 15 3511)".</summary>
    /// <param name="deviceId">The device.</param>
    /// <returns>The name, or null when the device is not an install of a numbered server.</returns>
    /// <remarks>
    /// Only the person's own machines are ever in the directory, so another person's machine is
    /// never named by a number here: it keeps the name the person gave it.
    /// </remarks>
    public string? NameOf(string deviceId)
    {
        if (Self is { } self && string.Equals(self.Device, deviceId, StringComparison.OrdinalIgnoreCase))
        {
            return NumberOf(self.Permanent) is { } own ? Describe(own, self.Label) : null;
        }

        return ServerOf(deviceId) is { } server && NumberOf(server.Permanent) is { } number
            ? Describe(number, server.Label)
            : null;
    }

    /// <summary>Finds servers by what a person types: "Server 2", "2", a Server.ID, or a label.</summary>
    /// <param name="text">What was typed.</param>
    /// <returns>Every server it matches, heard-from ones only; one when it is unambiguous.</returns>
    /// <remarks>
    /// Hearsay is never a target: a server this machine has not heard from itself is not one it
    /// can reach.
    /// </remarks>
    public IReadOnlyList<KnownServer> Find(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        var direct = Servers.Where(server => server.HeardFrom is null).ToList();
        var typed = text.Trim();

        if (TryReadNumber(typed, out var number))
        {
            return [.. direct.Where(server => NumberOf(server.Permanent) == number)];
        }

        if (ServerId.TryParse(typed, out var id))
        {
            return [.. direct.Where(server => string.Equals(server.Id, id!.ToString(), StringComparison.Ordinal))];
        }

        return [.. direct.Where(server => string.Equals(server.Label, typed, StringComparison.OrdinalIgnoreCase))];
    }

    /// <summary>A server by number and label, as screens and log lines write it.</summary>
    /// <param name="number">The server's number.</param>
    /// <param name="label">Its label, or null.</param>
    /// <returns>"Server 2 (Dell Inspiron 15 3511)", or "Server 2" with no label.</returns>
    public static string Describe(int number, string? label) =>
        label is null
            ? string.Create(CultureInfo.InvariantCulture, $"Server {number}")
            : string.Create(CultureInfo.InvariantCulture, $"Server {number} ({label})");

    /// <summary>Reads "Server 2", "server2" or "2" as a server number.</summary>
    /// <param name="text">What was typed.</param>
    /// <param name="number">The number, when this returns true.</param>
    /// <returns>True for a number from 1 to <see cref="ServerRecord.MaximumNumber"/>.</returns>
    public static bool TryReadNumber(string? text, out int number)
    {
        number = 0;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var digits = text.Trim();
        if (digits.StartsWith("server", StringComparison.OrdinalIgnoreCase))
        {
            digits = digits["server".Length..].TrimStart();
        }

        return digits.Length is > 0 and <= 3 &&
               digits.All(char.IsAsciiDigit) &&
               int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out number) &&
               number is >= 1 and <= ServerRecord.MaximumNumber;
    }
}
