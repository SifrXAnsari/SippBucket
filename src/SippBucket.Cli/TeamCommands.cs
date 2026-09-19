using System.Globalization;
using SippBucket.Core.Machines;
using SippBucket.Core.Platform;
using SippBucket.Core.Push;
using SippBucket.Core.Repository;

namespace SippBucket.Cli;

/// <summary>
/// The team on the command line: <c>sip team</c> — whether team features are on and why, the
/// two-person exception, and grouping other people's machines into people
/// (docs/DIRECT-MESSAGES.md). Every feature ships in <c>sip</c> first; the window follows.
/// </summary>
/// <remarks>
/// A team is people, not machines: all of one person's machines count once, for the team
/// size, the inbox space cap and every conversation. The code cannot know two machines are
/// one colleague until told, so until they are grouped here each counts as a person of its
/// own — the conservative reading, which only ever overcounts, and safety never rests on
/// this count (the safety measures run from the first "someone else's" answer regardless).
/// </remarks>
internal static class TeamCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    /// <summary><c>sip team</c>: the switch, the exception, and the people.</summary>
    /// <param name="args">What followed <c>team</c>.</param>
    /// <returns>The exit code.</returns>
    public static int Run(string[] args)
    {
        if (args.Length == 0)
        {
            return Status();
        }

        return args[0].ToUpperInvariant() switch
        {
            "EXCEPTION" => Exception(args[1..]),
            "PERSON" => Person(args[1..]),
            _ => Usage("sip team | exception on|off | person list | person add <name> <machine>... | person remove <machine>"),
        };
    }

    /// <summary>The team switch, decided the way the daemon decides it.</summary>
    private static TeamFeatures Switch() =>
        TeamFeatures.ForThisUser(() => PairedMachines.AllDeviceIds(SyncedFolders()));

    private static int Status()
    {
        var decision = Switch().Decide();

        Console.WriteLine(decision.Why);
        Console.WriteLine();
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"  people      {decision.PeopleCount} (you, and {decision.OtherPeople.Count} other(s))"));
        Console.WriteLine($"  exception   {(decision.Exception ? "on: 2 people count as a team" : "off: a team is 3 people")}");

        foreach (var other in decision.OtherPeople)
        {
            Console.WriteLine($"    - {DisplayText.Printable(other, 80)}");
        }

        if (!decision.On)
        {
            Console.WriteLine();
            Console.WriteLine("While team features are off, other people's machines cannot push files or send");
            Console.WriteLine("messages to this one, and 'sip dm' does not send. Your own machines are unaffected.");
        }

        return ExitSuccess;
    }

    private static int Exception(string[] args)
    {
        if (args.Length != 1 || args[0].ToUpperInvariant() is not ("ON" or "OFF"))
        {
            return Usage("sip team exception on|off");
        }

        var wanted = string.Equals(args[0], "on", StringComparison.OrdinalIgnoreCase);
        _ = TeamSettingsStore.ForThisUser().Update(current => current with { TwoPersonException = wanted });

        Console.WriteLine(wanted
            ? "The exception is set: a team of 2 people counts as a team."
            : "The exception is off: a team is 3 people.");
        Console.WriteLine(Switch().Decide().Why);
        return ExitSuccess;
    }

    private static int Person(string[] args)
    {
        if (args.Length == 0)
        {
            return List();
        }

        return args[0].ToUpperInvariant() switch
        {
            "LIST" when args.Length == 1 => List(),
            "ADD" when args.Length >= 3 => Add(args[1], args[2..]),
            "REMOVE" when args.Length == 2 => Remove(args[1]),
            _ => Usage("sip team person list | add <name> <machine>... | remove <machine>"),
        };
    }

    private static int List()
    {
        IReadOnlyList<Person> people;
        try
        {
            people = PeopleStore.ForThisUser().Load();
        }
        catch (System.Text.Json.JsonException ex)
        {
            return Fail(ex.Message);
        }

        if (people.Count == 0)
        {
            Console.WriteLine("Nobody is grouped yet. Until they are, each machine counts as its own person.");
            Console.WriteLine("Group a colleague's machines with: sip team person add <name> <machine>...");
            return ExitSuccess;
        }

        foreach (var person in people)
        {
            Console.WriteLine($"{DisplayText.Printable(person.Name, 64)}");
            foreach (var device in person.Devices)
            {
                var name = PairedMachines.NameOf(SyncedFolders(), device);
                Console.WriteLine($"  {Short(device)}  {(name is null ? "(not paired with any folder here)" : DisplayText.Printable(name, 64))}");
            }
        }

        return ExitSuccess;
    }

    private static int Add(string name, string[] machines)
    {
        var devices = new List<string>();
        foreach (var typed in machines)
        {
            var found = PairedMachines.Find(SyncedFolders(), typed, out var unreadable);
            foreach (var folder in unreadable)
            {
                Console.WriteLine($"note: the peer list of {folder} could not be read and was passed over.");
            }

            switch (found.Outcome)
            {
                case PeerLookupOutcome.Found:
                    break;
                case PeerLookupOutcome.Ambiguous:
                    Console.WriteLine($"'{typed}' names more than one machine:");
                    foreach (var candidate in found.Candidates)
                    {
                        Console.WriteLine($"  {Short(candidate.DeviceId)}  {DisplayText.Printable(candidate.Name, 64)}");
                    }

                    return Fail("Name one of them by more of its device ID.");
                default:
                    return Fail($"No paired machine here is named '{typed}'. 'sip peer list' shows them.");
            }

            var device = found.Peer!.DeviceId;
            MachineOwner owner;
            try
            {
                owner = KnownMachines.ForThisUser().OwnerOf(device);
            }
            catch (System.Text.Json.JsonException ex)
            {
                return Fail(ex.Message);
            }

            switch (owner)
            {
                case MachineOwner.Mine:
                    return Fail(
                        $"{DisplayText.Printable(found.Peer.Name, 64)} is one of your own machines. A person groups " +
                        "someone else's.");
                case MachineOwner.Unanswered:
                    return Fail(
                        $"You have not said whose machine {DisplayText.Printable(found.Peer.Name, 64)} is. Answer first: " +
                        $"sip peer owner {found.Peer.Name} someone-else");
                default:
                    devices.Add(device);
                    break;
            }
        }

        Person person;
        IReadOnlyList<string> refused;
        try
        {
            person = PeopleStore.ForThisUser().Add(name, devices, out refused);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.Text.Json.JsonException)
        {
            return Fail(ex.Message);
        }

        foreach (var line in refused)
        {
            Console.WriteLine($"note: {line}.");
        }

        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{DisplayText.Printable(person.Name, 64)} now has {person.Devices.Count} machine(s). One person, " +
            $"one count: their machines share one inbox cap and one conversation."));
        Console.WriteLine(Switch().Decide().Why);
        return refused.Count == 0 ? ExitSuccess : ExitFailure;
    }

    private static int Remove(string typed)
    {
        var found = PairedMachines.Find(SyncedFolders(), typed, out _);
        var device = found.Outcome == PeerLookupOutcome.Found ? found.Peer!.DeviceId : typed;

        Person? person;
        try
        {
            person = PeopleStore.ForThisUser().Remove(device);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Text.Json.JsonException)
        {
            return Fail(ex.Message);
        }

        if (person is null)
        {
            return Fail($"'{typed}' is grouped under nobody.");
        }

        Console.WriteLine($"Removed {Short(device)} from {DisplayText.Printable(person.Name, 64)}. It counts on its own again.");
        Console.WriteLine(Switch().Decide().Why);
        return ExitSuccess;
    }

    private static List<string> SyncedFolders()
    {
        var folders = WatchedFolders.Load().ToList();

        if (RepositoryLayout.Discover(Directory.GetCurrentDirectory()) is { } here &&
            !folders.Any(folder => string.Equals(FolderPaths.Normalize(folder), FolderPaths.Normalize(here.WorkingRoot), StringComparison.OrdinalIgnoreCase)))
        {
            folders.Add(here.WorkingRoot);
        }

        return folders;
    }

    private static string Short(string deviceId) => deviceId.Length > 12 ? deviceId[..12] : deviceId;

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
