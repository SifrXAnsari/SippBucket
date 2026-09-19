namespace SippBucket.Core.Repository;

/// <summary>What happened when a peer was asked to be removed.</summary>
public enum PeerRemovalOutcome
{
    /// <summary>The argument named exactly one machine, and it was removed.</summary>
    Removed,

    /// <summary>The argument named no machine. Nothing was changed.</summary>
    NotFound,

    /// <summary>The argument could mean more than one machine. Nothing was changed.</summary>
    Ambiguous,
}

/// <summary>The result of <see cref="PeerRegistry.Remove"/>.</summary>
/// <remarks>
/// Three outcomes rather than a bool, because "nothing was removed" has two causes that
/// ask for opposite responses. A name nobody has is a typo. A name two machines share is
/// a question only the user can answer, and they need to see the machines to answer it.
/// </remarks>
public sealed record PeerRemoval
{
    /// <summary>Which of the three things happened.</summary>
    public required PeerRemovalOutcome Outcome { get; init; }

    /// <summary>
    /// The records that were deleted. Empty unless <see cref="Outcome"/> is
    /// <see cref="PeerRemovalOutcome.Removed"/>.
    /// </summary>
    /// <remarks>
    /// Normally one record. It is more than one only when <c>peers.json</c> lists the
    /// same device more than once, which <see cref="PeerRegistry.Add"/> never writes but a
    /// hand edit can. Every record for the device goes, because removing a peer revokes
    /// the device's trust, and a second record left behind would leave it trusted.
    /// </remarks>
    public IReadOnlyList<PeerRecord> Removed { get; init; } = [];

    /// <summary>
    /// The machines the argument could have meant, one record for each. Empty unless
    /// <see cref="Outcome"/> is <see cref="PeerRemovalOutcome.Ambiguous"/>.
    /// </summary>
    public IReadOnlyList<PeerRecord> Candidates { get; init; } = [];
}
