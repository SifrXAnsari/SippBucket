namespace SippBucket.Core.Machines;

/// <summary>Whose machine a paired device is, as the person answered at pairing.</summary>
/// <remarks>
/// <para>
/// The code can count devices but cannot tell whose a device is: nothing on the wire carries
/// an owner, and the two answers imply opposite trust defaults, so guessing is worse than
/// asking. SippBucket asks once, at pairing: "Is this another of your machines, or someone
/// else's?" (the team model, decided 2026-09-18; <c>docs/DIRECT-MESSAGES.md</c>).
/// </para>
/// <para>
/// <see cref="Unanswered"/> is treated as <see cref="SomeoneElse"/> for every default that
/// protects the person: forwarding rules, the inbox space cap, and never sending a Server.ID.
/// Only <see cref="Mine"/> relaxes any of them, and only the person can give that answer.
/// </para>
/// </remarks>
public enum MachineOwner
{
    /// <summary>Not answered yet: paired before the question existed, or left for later.</summary>
    Unanswered = 0,

    /// <summary>Another of the person's own machines.</summary>
    Mine = 1,

    /// <summary>Another person's machine.</summary>
    SomeoneElse = 2,
}

/// <summary>What an owner answer means for the protections that depend on it.</summary>
public static class MachineOwnership
{
    /// <summary>
    /// Whether a machine may be treated as the person's own: only when they said so.
    /// </summary>
    /// <param name="owner">The answer on record.</param>
    /// <returns>True for <see cref="MachineOwner.Mine"/> alone.</returns>
    public static bool IsOwn(MachineOwner owner) => owner == MachineOwner.Mine;

    /// <summary>The answer in words, for lists and messages.</summary>
    /// <param name="owner">The answer on record.</param>
    /// <returns>"mine", "someone else's", or "not answered".</returns>
    public static string Describe(MachineOwner owner) => owner switch
    {
        MachineOwner.Mine => "mine",
        MachineOwner.SomeoneElse => "someone else's",
        _ => "not answered",
    };

    /// <summary>Reads an answer as a person types it on the command line.</summary>
    /// <param name="text"><c>mine</c> or <c>someone-else</c>, in any case.</param>
    /// <param name="owner">The answer, when this returns true.</param>
    /// <returns>False for anything else. Nothing is guessed from a near miss.</returns>
    public static bool TryParse(string? text, out MachineOwner owner)
    {
        if (string.Equals(text, "mine", StringComparison.OrdinalIgnoreCase))
        {
            owner = MachineOwner.Mine;
            return true;
        }

        if (string.Equals(text, "someone-else", StringComparison.OrdinalIgnoreCase))
        {
            owner = MachineOwner.SomeoneElse;
            return true;
        }

        owner = MachineOwner.Unanswered;
        return false;
    }
}
