using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Servers;

namespace SippBucket.Cli;

/// <summary>
/// Server.ID on the command line: <c>sip id</c>, which shows who this machine is in all three
/// of Server.ID's layers and which of the person's servers it knows (docs/SERVER-ID.md).
/// </summary>
/// <remarks>
/// The normal person never needs this: Server.ID happens during pairing and sync. It is here
/// for the power user who goes looking, and it never shows the firmware's raw values: only
/// whether each is there, and the one-way hash made from them.
/// </remarks>
internal static class ServerCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary><c>sip id</c>: this machine's identity, or with <c>--device</c> its device ID alone.</summary>
    /// <param name="args">What followed <c>id</c>.</param>
    /// <returns>The exit code.</returns>
    public static int Id(string[] args)
    {
        if (args.Length == 1 && string.Equals(args[0], "--device", StringComparison.OrdinalIgnoreCase))
        {
            using var device = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
            Console.WriteLine(device.DeviceId);
            return ExitSuccess;
        }

        if (args.Length > 0)
        {
            return Usage("sip id [--device]");
        }

        using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);

        ServerIdentity me;
        try
        {
            me = ServerIdentity.ForThisMachine(identity.DeviceId);
        }
        catch (IOException ex)
        {
            Console.WriteLine("This machine");
            Console.WriteLine($"  device      {identity.DeviceId}");
            Console.Error.WriteLine($"sip: this machine's Server.ID could not be worked out: {ex.Message}");
            return ExitFailure;
        }

        var store = KnownServers.ForThisUser();
        var (record, notes) = store.Describe(me, DateTimeOffset.UtcNow);
        var directory = store.Load();

        foreach (var note in notes)
        {
            Console.WriteLine($"({note}.)");
        }

        PrintThisMachine(me, record, directory);
        PrintOtherServers(directory);
        return ExitSuccess;
    }

    /// <summary>The directory of the person's servers, or an empty one, said, when it cannot be read.</summary>
    /// <returns>The directory.</returns>
    /// <remarks>A listing or a lookup is not a safety decision, so a damaged file does not stop it.</remarks>
    public static ServerDirectory LoadDirectory()
    {
        try
        {
            return KnownServers.ForThisUser().Load();
        }
        catch (JsonException ex)
        {
            Console.Error.WriteLine($"sip: {ex.Message}");
            return ServerDirectory.Empty;
        }
    }

    /// <summary>The Server.ID exchange a command's sync or server takes part in, as the daemon's does.</summary>
    /// <param name="identity">This machine's device key.</param>
    /// <param name="machine">This machine's settings.</param>
    /// <returns>The exchange, writing its lines to the console.</returns>
    public static ServerExchange Exchange(DeviceIdentity identity, MasterConfig machine)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(machine);

        var deviceId = identity.DeviceId;
        return new ServerExchange(
            () => ServerIdentity.ForThisMachine(deviceId),
            KnownServers.ForThisUser(),
            KnownMachines.ForThisUser(),
            now => SelfReports.ForThisMachine(machine, now),
            PeerHealth.ForThisUser(),
            machine.Health,
            Console.WriteLine);
    }

    private static void PrintThisMachine(ServerIdentity me, ServerRecord record, ServerDirectory directory)
    {
        Console.WriteLine("This machine");
        Console.WriteLine(record.Number > 0
            ? $"  server      {ServerDirectory.Describe(record.Number, record.Label)}"
            : "  server      not numbered yet");
        Console.WriteLine($"  Server.ID   {record.Id}");
        Console.WriteLine($"  source      {record.Source}: {me.Permanent.Explanation}");
        Console.WriteLine($"  permanent   {record.Permanent}");
        Console.WriteLine($"  device      {me.DeviceId}");
        Console.WriteLine("              The device key proves this is this install; it is what other machines pair with.");
        Console.WriteLine($"  run         {record.Run}, started {record.Started.ToLocalTime():yyyy-MM-dd HH:mm}");

        var first = true;
        foreach (var install in record.Installs)
        {
            var who = string.Equals(install.Device, me.DeviceId, StringComparison.OrdinalIgnoreCase)
                ? "this one"
                : install.Device[..Math.Min(12, install.Device.Length)];
            var windows = install.Windows is null ? string.Empty : $": {install.Windows}";
            var seen = install.FirstSeen is { } when ? $"; first seen {when.ToLocalTime():yyyy-MM-dd}" : string.Empty;
            Console.WriteLine($"  {(first ? "installs" : string.Empty),-11} {who}{windows}{seen}");
            first = false;
        }

        Console.WriteLine($"  firmware    {DescribeFirmware(me.Firmware)}");
        Console.WriteLine("              The firmware's values are never shown, stored or sent: only the one-way hash above.");

        if (directory.Self is { Number: > 0, Numbered: { } numbered })
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"  numbered    {numbered.ToLocalTime():yyyy-MM-dd HH:mm}: when this machine's number was taken, which decides a clash"));
        }
    }

    private static void PrintOtherServers(ServerDirectory directory)
    {
        // This board's own entry holds its other installs, which "installs" above already shows.
        var others = directory.Servers
            .Where(server => !string.Equals(server.Permanent, directory.Self?.Permanent, StringComparison.Ordinal))
            .OrderBy(server => directory.NumberOf(server.Permanent) ?? int.MaxValue)
            .ToList();
        var direct = others.Where(server => server.HeardFrom is null).ToList();
        var hearsay = others.Where(server => server.HeardFrom is not null).ToList();

        Console.WriteLine();
        if (direct.Count == 0 && hearsay.Count == 0)
        {
            Console.WriteLine("No other server of yours has exchanged records with this one yet. They do so when they");
            Console.WriteLine("sync, once you have said each is yours ('sip peer owner <machine> mine').");
            return;
        }

        Console.WriteLine("Your other servers");
        foreach (var server in direct)
        {
            var name = directory.NumberOf(server.Permanent) is { } number
                ? ServerDirectory.Describe(number, server.Label)
                : server.Label ?? server.Id;
            var seen = server.LastSeen is { } last ? $"last heard from {last.ToLocalTime():yyyy-MM-dd HH:mm}" : "not heard from";
            var version = server.Version is null ? string.Empty : $", runs {server.Version}";
            Console.WriteLine($"  {name}");
            Console.WriteLine($"    {server.Id}, {seen}{version}");
            Console.WriteLine($"    installs: {string.Join(", ", server.Installs.Select(install => install.Device[..Math.Min(12, install.Device.Length)]))}");
        }

        foreach (var server in hearsay)
        {
            var name = directory.NumberOf(server.Permanent) is { } number
                ? ServerDirectory.Describe(number, server.Label)
                : server.Label ?? server.Id;
            var via = directory.NameOf(server.HeardFrom!) ?? server.HeardFrom![..Math.Min(12, server.HeardFrom!.Length)];
            Console.WriteLine($"  {name}");
            Console.WriteLine($"    {server.Id}, heard of through {via}; not paired with this machine");
        }
    }

    private static string DescribeFirmware(FirmwareReading firmware)
    {
        if (firmware.Tables is not { } tables)
        {
            return $"not read: {firmware.Problem}";
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"SMBIOS {tables.MajorVersion}.{tables.MinorVersion}; system UUID {Word(tables.Uuid)}; " +
            $"board serial number {Word(tables.BoardSerial)}");
    }

    private static string Word(FirmwareValue value) => value.State switch
    {
        FirmwareValueState.Present => "present",
        FirmwareValueState.Placeholder => "a placeholder",
        _ => "absent",
    };

    private static int Usage(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitUsage;
    }
}
