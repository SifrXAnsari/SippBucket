namespace SippBucket.Core.Repository;

/// <summary>What looking a peer up by what a person typed found.</summary>
public enum PeerLookupOutcome
{
    /// <summary>The argument named exactly one machine.</summary>
    Found,

    /// <summary>The argument named no machine.</summary>
    NotFound,

    /// <summary>The argument could mean more than one machine.</summary>
    Ambiguous,
}

/// <summary>The result of <see cref="PeerRegistry.Find"/>.</summary>
/// <remarks>
/// The three outcomes <see cref="PeerRemoval"/> has, for the same reason: a name nobody has is
/// a typo, and a name two machines share is a question only the person can answer, so they
/// need to see the machines.
/// </remarks>
public sealed record PeerLookup
{
    /// <summary>Which of the three things happened.</summary>
    public required PeerLookupOutcome Outcome { get; init; }

    /// <summary>The machine found, when <see cref="Outcome"/> is <see cref="PeerLookupOutcome.Found"/>.</summary>
    public PeerRecord? Peer { get; init; }

    /// <summary>
    /// The machines the argument could have meant, one record for each. Empty unless
    /// <see cref="Outcome"/> is <see cref="PeerLookupOutcome.Ambiguous"/>.
    /// </summary>
    public IReadOnlyList<PeerRecord> Candidates { get; init; } = [];
}
