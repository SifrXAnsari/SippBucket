using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SippBucket.Core.Configuration;
using SippBucket.Core.Discovery;
using SippBucket.Core.Platform;

namespace SippBucket.Cli;

/// <summary>
/// The network on the command line: <c>sip net</c> — what this machine can see of its own
/// networks, and the per-network consent local discovery runs under (docs/DISCOVERY.md,
/// docs/NAT-TRAVERSAL.md phase 0). Every feature ships in <c>sip</c> first; the window follows.
/// </summary>
/// <remarks>
/// <c>sip net check</c> only reads this machine: adapters, gateways, the identified network
/// and the settings. It sends nothing — not even to the router, whose port-mapping state is
/// the daemon's to report — so running it costs nothing and reveals nothing.
/// </remarks>
internal static class NetCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary><c>sip net</c>: the check, and consent.</summary>
    /// <param name="args">What followed <c>net</c>.</param>
    /// <returns>The exit code.</returns>
    public static int Run(string[] args)
    {
        if (args.Length == 0)
        {
            return Check();
        }

        return args[0].ToUpperInvariant() switch
        {
            "CHECK" when args.Length == 1 => Check(),
            "LIST" when args.Length == 1 => List(),
            "ALLOW" when args.Length <= 2 => Decide(args.Length == 2 ? args[1] : null, allowed: true),
            "DENY" when args.Length <= 2 => Decide(args.Length == 2 ? args[1] : null, allowed: false),
            "FORGET" when args.Length <= 2 => Forget(args.Length == 2 ? args[1] : null),
            _ => Usage("sip net [check] | list | allow [<network-id>] | deny [<network-id>] | forget [<network-id>]"),
        };
    }

    private static NetworkConsent Consent() =>
        new(Path.Combine(UserDataDirectory.Resolve(), "networks.json"));

    private static int Check()
    {
        var machine = MasterConfig.Load();

        Console.WriteLine("This machine's network, read locally; nothing was sent anywhere.");
        Console.WriteLine();

        var current = NetworkIdentity.Current();
        var name = NetworkIdentity.CurrentDisplayName();
        Console.WriteLine(current is null
            ? "  network      not identified: no adapter with a confirmed IPv4 gateway"
            : $"  network      {name ?? "unnamed"}  ({current})");

        var consent = Consent();
        if (current is not null)
        {
            Console.WriteLine($"  announcing   {(consent.MayAnnounceOn(current)
                ? "allowed on this network"
                : consent.HasBeenAsked(current)
                    ? "denied on this network"
                    : "not decided here: nothing is sent until 'sip net allow'")}");
        }

        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"  sync port    {machine.ListenPort} (server.listenPort)"));
        Console.WriteLine(machine.PortMappingEnabled
            ? string.Create(
                CultureInfo.InvariantCulture,
                $"  mapping      on: the daemon asks the router to forward TCP {machine.ListenPort} here " +
                $"({(int)machine.PortMappingLifetime.TotalMinutes} min at a time). Its activity says what the router answered")
            : "  mapping      off: the router is not asked to forward anything ('sip config set network.portMapping 1')");

        Console.WriteLine();
        Console.WriteLine("  adapters with an IPv4 gateway:");
        var any = false;
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var properties = adapter.GetIPProperties();
            var gateway = properties.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (gateway is null)
            {
                continue;
            }

            var address = properties.UnicastAddresses
                .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;
            var id = NetworkIdentity.ForAdapter(adapter);
            Console.WriteLine(
                $"    {adapter.Name,-20} {address?.ToString() ?? "(no IPv4)",-16} gateway {gateway}" +
                $"{(id is null ? "  (network not identified)" : $"  ({id})")}");
            any = true;
        }

        if (!any)
        {
            Console.WriteLine("    none");
        }

        Console.WriteLine();
        Console.WriteLine("What is announced, when a network is allowed: a fixed-size packet that names");
        Console.WriteLine("nothing - no device ID, no name, no port - and that only machines you gave keys");
        Console.WriteLine("to (your own, at pairing) can even recognise. 'sip help net' has the detail.");
        return ExitSuccess;
    }

    private static int List()
    {
        var consent = Consent();
        var decisions = consent.Decisions;
        if (decisions.Count == 0)
        {
            Console.WriteLine("No network has been decided about. Nothing is announced anywhere.");
            return ExitSuccess;
        }

        foreach (var decision in decisions)
        {
            Console.WriteLine(
                $"{DisplayText.Printable(decision.DisplayName, 32),-32} {decision.NetworkId}  " +
                (decision.Allowed ? "allowed" : "denied"));
        }

        return ExitSuccess;
    }

    private static int Decide(string? typedId, bool allowed)
    {
        var (id, name) = ResolveNetwork(typedId);
        if (id is null)
        {
            return Fail(
                "No network is identified right now, and none was named. 'sip net' shows the current " +
                "network's ID; 'sip net allow <network-id>' names one.");
        }

        Consent().Record(id, name ?? id, allowed);
        Console.WriteLine(allowed
            ? $"Allowed: this machine may announce its presence on {name ?? id}. The daemon starts within a minute. " +
              "What goes out identifies nothing; only machines you gave keys to can recognise it."
            : $"Denied: nothing is announced on {name ?? id}, now or later, until 'sip net forget' asks again.");
        return ExitSuccess;
    }

    private static int Forget(string? typedId)
    {
        var (id, name) = ResolveNetwork(typedId);
        if (id is null)
        {
            return Fail("No network is identified right now, and none was named.");
        }

        return Consent().Forget(id)
            ? Success($"Forgot the decision for {name ?? id}. It counts as undecided: nothing is sent there.")
            : Fail($"No decision was recorded for {name ?? id}.");
    }

    private static (string? Id, string? Name) ResolveNetwork(string? typedId)
    {
        if (!string.IsNullOrWhiteSpace(typedId))
        {
            var known = Consent().Decisions
                .FirstOrDefault(d => string.Equals(d.NetworkId, typedId, StringComparison.OrdinalIgnoreCase));
            return (typedId, known?.DisplayName);
        }

        return (NetworkIdentity.Current(), NetworkIdentity.CurrentDisplayName());
    }

    private static int Success(string message)
    {
        Console.WriteLine(message);
        return ExitSuccess;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return ExitFailure;
    }

    private static int Usage(string usage)
    {
        Console.Error.WriteLine($"usage: {usage}");
        return ExitUsage;
    }
}
