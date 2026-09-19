namespace SippBucket.Core.Servers;

/// <summary>
/// Who this machine is, in Server.ID's three layers: the device key that proves it, the
/// permanent ID that names its board, and the run ID of this process (docs/SERVER-ID.md).
/// </summary>
/// <remarks>
/// Worked out once per process, by whoever needs it first: the firmware does not change while
/// Windows runs. The firmware's values stay in memory here, for <c>sip id</c>'s account of
/// where the permanent ID came from; the raw serial number is never written or sent.
/// </remarks>
public sealed class ServerIdentity
{
    /// <summary>Creates an identity from its parts.</summary>
    /// <param name="deviceId">This install's device ID.</param>
    /// <param name="permanent">The board's permanent ID.</param>
    /// <param name="firmware">What the firmware's tables said.</param>
    /// <param name="label">The board's label, or null.</param>
    /// <param name="windows">This install's Windows, in words.</param>
    /// <exception cref="ArgumentException">A required argument was null or blank.</exception>
    public ServerIdentity(string deviceId, PermanentId permanent, FirmwareReading firmware, string? label, string windows)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentNullException.ThrowIfNull(permanent);
        ArgumentNullException.ThrowIfNull(firmware);
        ArgumentException.ThrowIfNullOrWhiteSpace(windows);

        DeviceId = deviceId;
        Permanent = permanent;
        Firmware = firmware;
        Label = label;
        Windows = windows;
    }

    /// <summary>This install's device ID: the only proof of which machine this is.</summary>
    public string DeviceId { get; }

    /// <summary>The board's permanent ID.</summary>
    public PermanentId Permanent { get; }

    /// <summary>What the firmware's tables said, or why they could not be read.</summary>
    public FirmwareReading Firmware { get; }

    /// <summary>The board's label, such as "Dell Inspiron 15 3511", or null.</summary>
    public string? Label { get; }

    /// <summary>This install's Windows, such as "Windows 11 Home 25H2, build 26200.6899".</summary>
    public string Windows { get; }

    /// <summary>Works out this machine's identity.</summary>
    /// <param name="deviceId">This install's device ID, from its device key.</param>
    /// <returns>The identity.</returns>
    /// <exception cref="IOException">
    /// The firmware gives no usable value, no machine-wide value was made at install, and this
    /// account's own value could not be read or made. <c>sip id</c> says so; nothing else stops.
    /// </exception>
    public static ServerIdentity ForThisMachine(string deviceId)
    {
        var firmware = FirmwareTables.Read();
        var permanent = PermanentId.Derive(
            firmware,
            PermanentId.MachineIdPath(),
            Path.Combine(Platform.UserDataDirectory.Resolve(), PermanentId.AccountIdFileName));

        return new ServerIdentity(deviceId, permanent, firmware, MachineLabel.From(firmware.Tables), WindowsRelease.Describe());
    }
}
