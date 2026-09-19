namespace SippBucket.Core.Storage;

/// <summary>
/// What a folder is allowed to keep, and how much room it is allowed to take.
/// </summary>
/// <remarks>
/// <para>
/// Retention and quota belong to the same object because they are the same decision seen
/// from two ends. A quota with no retention rule is a wall a user hits with nothing to do
/// about it; a retention rule with no quota is a promise with no consequence attached.
/// </para>
/// <para>
/// The defaults keep everything and cap nothing, because silently discarding a user's
/// history is not a default anyone should get without asking for it.
/// </para>
/// </remarks>
public sealed record BucketPolicy
{
    /// <summary>Keep everything, cap nothing.</summary>
    public static BucketPolicy Unlimited { get; } = new();

    /// <summary>Largest the store may grow, or null for no cap.</summary>
    public long? QuotaBytes { get; init; }

    /// <summary>
    /// How many snapshots to keep, newest first, or null to keep every one.
    /// </summary>
    public int? KeepSnapshots { get; init; }

    /// <summary>
    /// How many days of history to keep, or null to keep it regardless of age.
    /// </summary>
    public int? KeepDays { get; init; }

    /// <summary>
    /// True when this policy could ever discard anything.
    /// </summary>
    public bool Prunes => KeepSnapshots is not null || KeepDays is not null;

    /// <summary>
    /// Whether a snapshot at <paramref name="index"/> from the head, taken at
    /// <paramref name="takenUtc"/>, survives this policy.
    /// </summary>
    /// <param name="index">0 for the head, 1 for its parent, and so on.</param>
    /// <param name="takenUtc">When the snapshot was taken.</param>
    /// <param name="nowUtc">The current time.</param>
    /// <returns>True when the snapshot is kept.</returns>
    /// <remarks>
    /// The head always survives, whatever the numbers say. A policy of "keep 0 snapshots"
    /// or a clock skew that makes the newest snapshot look ancient must not be able to
    /// delete the only record of what is currently in the folder.
    /// </remarks>
    public bool Keeps(int index, DateTimeOffset takenUtc, DateTimeOffset nowUtc)
    {
        if (index <= 0)
        {
            return true;
        }

        if (KeepSnapshots is { } count && index >= count)
        {
            return false;
        }

        return KeepDays is not { } days || (nowUtc - takenUtc).TotalDays <= days;
    }
}
