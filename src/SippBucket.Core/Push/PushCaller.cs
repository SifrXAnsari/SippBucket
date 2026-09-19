using SippBucket.Core.Machines;

namespace SippBucket.Core.Push;

/// <summary>
/// A machine allowed to push to this one, as the key check found it: paired, and allowed by
/// Direct Push's rule 7.
/// </summary>
/// <remarks>
/// Whoever runs the listener decides who that is (<see cref="Ssh.PushListener"/> asks it once
/// for each key that has proved itself). The rule the daemon applies: the device is paired with
/// at least one folder on this machine, and it is one of the person's own machines, or team
/// features are on. Pairing is per folder, but Direct Push is per machine.
/// </remarks>
public sealed record PushCaller
{
    /// <summary>The caller's device ID, lowercase hexadecimal, as its key proved.</summary>
    public required string DeviceId { get; init; }

    /// <summary>The name this machine knows it by, from the pairing record.</summary>
    public required string Name { get; init; }

    /// <summary>Whose machine it is, as answered at pairing.</summary>
    /// <remarks>
    /// <see cref="MachineOwner.Unanswered"/> counts as someone else's for every safety default
    /// (<see cref="MachineOwnership.IsOwn"/>); the receiving side's caps and forwarding rules
    /// read this.
    /// </remarks>
    public required MachineOwner Owner { get; init; }
}
