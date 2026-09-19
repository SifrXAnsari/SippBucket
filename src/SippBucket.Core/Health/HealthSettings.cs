namespace SippBucket.Core.Health;

/// <summary>
/// The thresholds peer health works to, from the master config's <c>health</c> section
/// (docs/PEER-HEALTH.md).
/// </summary>
/// <remarks>
/// The checks themselves cannot be switched off. Every threshold has limits in
/// <c>MasterSettings</c> that keep it within reach: no percentage can be set to 100, and no
/// minimum count above 1,000, so a mass change is always looked for and faults always counted.
/// The defaults are deliberately conservative: a false alarm costs one click on "That was me",
/// and a missed one copies damage to every machine.
/// </remarks>
public sealed record HealthSettings
{
    /// <summary>The built-in thresholds.</summary>
    public static HealthSettings Default { get; } = new();

    /// <summary>How many faults of one kind from one server in a day raise an alert.</summary>
    public int FaultsPerDay { get; init; } = 5;

    /// <summary>How far a timestamp a server sends may be from this machine's clock before it is a fault.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(60);

    /// <summary>The share of a folder's files one incoming change may change or delete before it is held.</summary>
    public int MassChangePercent { get; init; } = 50;

    /// <summary>How many files a folder must have before the share alone can hold a change.</summary>
    public int MassChangeMinimumFiles { get; init; } = 20;

    /// <summary>The share of changed files that may turn random-looking before a change is held.</summary>
    public int RandomChangePercent { get; init; } = 30;

    /// <summary>How many files renamed to one new extension hold a change.</summary>
    public int RenameWaveMinimumFiles { get; init; } = 10;
}
