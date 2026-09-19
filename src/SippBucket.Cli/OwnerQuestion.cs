using System.Text.Json;
using SippBucket.Core.Machines;

namespace SippBucket.Cli;

/// <summary>
/// The one question at pairing: "Is this another of your machines, or someone else's?"
/// </summary>
/// <remarks>
/// <para>
/// Asked once per machine. An answer already on record, given when the same machine paired
/// with another folder, is used without asking again. <c>--owner mine|someone-else</c> answers
/// it on the command line, and replaces an earlier answer, because the person has just said so.
/// </para>
/// <para>
/// Asked only at a terminal. With input redirected, a script is running the command and
/// nobody can answer, so nothing is guessed: the machine is left unanswered, which is treated
/// as someone else's wherever that protects the person, and the command says how to answer.
/// </para>
/// <para>
/// Pairing has already succeeded when this runs. A store that cannot be written is reported
/// and leaves the machine unanswered; it never fails the pairing, which would only make the
/// person pair again to get the same question.
/// </para>
/// </remarks>
internal static class OwnerQuestion
{
    private const int Attempts = 3;

    /// <summary>Reads <c>--owner</c>'s value.</summary>
    /// <param name="text">What followed <c>--owner</c>.</param>
    /// <param name="owner">The answer, when this returns null.</param>
    /// <returns>Why the value cannot be used, or null when it can.</returns>
    public static string? TryRead(string? text, out MachineOwner owner) =>
        MachineOwnership.TryParse(text, out owner)
            ? null
            : "--owner needs a value: mine or someone-else.";

    /// <summary>
    /// Settles whose machine a newly paired device is, records it, and says what it means.
    /// </summary>
    /// <param name="deviceId">The other machine's device ID.</param>
    /// <param name="name">What this machine calls it.</param>
    /// <param name="folderName">The folder just shared with it.</param>
    /// <param name="given">The answer from <c>--owner</c>, or null when none was given.</param>
    /// <returns>The answer now on record.</returns>
    public static MachineOwner Settle(string deviceId, string name, string folderName, MachineOwner? given)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(folderName);

        var machines = KnownMachines.ForThisUser();
        var shortId = deviceId[..Math.Min(12, deviceId.Length)];

        MachineOwner onRecord;
        try
        {
            onRecord = machines.OwnerOf(deviceId);
        }
        catch (JsonException ex)
        {
            Console.WriteLine();
            Console.WriteLine($"Whose machine '{name}' is could not be looked up: {ex.Message}");
            return MachineOwner.Unanswered;
        }

        Console.WriteLine();

        MachineOwner answer;
        if (given is { } chosen)
        {
            answer = chosen;
        }
        else if (onRecord != MachineOwner.Unanswered)
        {
            answer = onRecord;
            Console.WriteLine($"'{name}' was recorded earlier as {MachineOwnership.Describe(onRecord)}.");
        }
        else
        {
            answer = Console.IsInputRedirected ? MachineOwner.Unanswered : Ask(name);
        }

        if (answer != onRecord && !TryRecord(machines, deviceId, answer, name))
        {
            answer = MachineOwner.Unanswered;
        }

        Explain(answer, name, folderName, shortId);
        return answer;
    }

    /// <summary>Records an answer given with <c>sip peer owner</c>, and says what it means.</summary>
    /// <param name="deviceId">The machine's device ID.</param>
    /// <param name="name">What this machine calls it.</param>
    /// <param name="folderName">The folder the command was run in.</param>
    /// <param name="answer">The answer.</param>
    /// <returns>True when it was recorded.</returns>
    public static bool Record(string deviceId, string name, string folderName, MachineOwner answer)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(folderName);

        if (!TryRecord(KnownMachines.ForThisUser(), deviceId, answer, name))
        {
            return false;
        }

        Console.WriteLine($"'{name}' is now recorded as {MachineOwnership.Describe(answer)}, for every folder.");
        Explain(answer, name, folderName, deviceId[..Math.Min(12, deviceId.Length)]);
        return true;
    }

    private static MachineOwner Ask(string name)
    {
        Console.WriteLine($"Is '{name}' another of your machines, or someone else's?");
        Console.WriteLine("  1  Mine");
        Console.WriteLine("  2  Someone else's");

        for (var attempt = 0; attempt < Attempts; attempt++)
        {
            Console.Write("Type 1 or 2, or press Enter to answer later: ");
            var typed = Console.ReadLine()?.Trim();

            switch (typed)
            {
                case null or "":
                    return MachineOwner.Unanswered;
                case "1":
                    return MachineOwner.Mine;
                case "2":
                    return MachineOwner.SomeoneElse;
                default:
                    if (MachineOwnership.TryParse(typed, out var owner))
                    {
                        return owner;
                    }

                    Console.WriteLine($"'{typed}' is not 1 or 2.");
                    break;
            }
        }

        return MachineOwner.Unanswered;
    }

    private static bool TryRecord(KnownMachines machines, string deviceId, MachineOwner answer, string name)
    {
        try
        {
            machines.Answer(deviceId, answer, name, DateTimeOffset.UtcNow);
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            Console.WriteLine($"Your answer about '{name}' could not be recorded: {ex.Message}");
            return false;
        }
    }

    private static void Explain(MachineOwner answer, string name, string folderName, string shortId)
    {
        switch (answer)
        {
            case MachineOwner.Mine:
                return;

            case MachineOwner.SomeoneElse:
                // Said every time a folder is shared with someone else, because it is about
                // that folder: this is what they now have.
                Console.WriteLine($"'{name}' is someone else's machine. That person can now read everything in");
                Console.WriteLine($"'{folderName}', its whole history included, and removing them later does not");
                Console.WriteLine("take back what they already have.");
                return;

            default:
                Console.WriteLine($"Not answered yet. Until it is, '{name}' is treated as someone else's machine");
                Console.WriteLine("wherever that protects you. To answer:");
                Console.WriteLine($"  sip peer owner {shortId} mine");
                Console.WriteLine($"  sip peer owner {shortId} someone-else");
                return;
        }
    }
}
