using SippBucket.Core.Crypto;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;

namespace SippBucket.Cli;

/// <summary>
/// Names for device IDs on screen: "you" for this machine, a peer's name for a paired one,
/// the ID's first characters for anything else.
/// </summary>
internal static class DeviceNames
{
    /// <summary>Builds the label map for one folder's peers and this machine.</summary>
    /// <param name="repository">The folder whose peer names apply.</param>
    /// <returns>Device ID to label; look up with <see cref="Label"/>.</returns>
    public static Dictionary<string, string> For(SipRepository repository)
    {
        var labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (var peer in repository.Peers.Load())
            {
                if (!string.IsNullOrWhiteSpace(peer.DeviceId))
                {
                    labels[peer.DeviceId] = DisplayText.Printable(peer.Name, 16);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            // Labels are a nicety; the IDs still print.
        }

        try
        {
            using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
            labels[identity.DeviceId] = "you";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
        }

        return labels;
    }

    /// <summary>The label for one device, or the ID's first characters.</summary>
    /// <param name="labels">The map from <see cref="For"/>.</param>
    /// <param name="deviceId">The device.</param>
    public static string Label(IReadOnlyDictionary<string, string> labels, string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return "?";
        }

        return labels.TryGetValue(deviceId, out var label)
            ? label
            : deviceId[..Math.Min(8, deviceId.Length)];
    }
}
