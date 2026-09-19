namespace SippBucket.Core.Model;

/// <summary>
/// How much history a repository keeps. The mode is chosen at <c>sip init</c> and recorded
/// in the repository config; it is what distinguishes a power user's repository from a
/// simple one.
/// </summary>
/// <remarks>
/// Neither mode has branches. A repository holds one linear chain of snapshots, and the
/// modes differ only in how much of that chain survives.
/// </remarks>
public enum RepositoryMode
{
    /// <summary>
    /// Keeps every snapshot, so any past state can be restored. The behaviour a git user
    /// expects, minus the branching.
    /// </summary>
    Power = 0,

    /// <summary>
    /// Keeps only the newest snapshot. The folder stays in sync across machines with no
    /// history to reason about and nothing to prune.
    /// </summary>
    Simple = 1,
}
