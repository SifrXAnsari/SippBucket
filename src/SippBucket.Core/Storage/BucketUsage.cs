using System.Globalization;

namespace SippBucket.Core.Storage;

/// <summary>
/// What a folder's storage is costing, against what it is allowed.
/// </summary>
/// <remarks>
/// <para>
/// Reported rather than merely enforced. A quota that is only checked at the moment a save
/// fails produces the worst possible interface: a refusal with no warning and no explanation
/// of what would fix it. Usage has to be visible while there is still room, or the limit is
/// a trap rather than a boundary.
/// </para>
/// <para>
/// <see cref="ReclaimableBytes"/> is the number that makes the difference between a dead end and
/// a decision. "Full" on its own leaves the user with nothing to do; "full, and 1.2 GiB is
/// held by snapshots older than your retention window" tells them exactly what the next
/// click is.
/// </para>
/// </remarks>
public sealed record BucketUsage
{
    /// <summary>Bytes currently held by blocks and snapshots.</summary>
    public required long UsedBytes { get; init; }

    /// <summary>The ceiling, or null when the folder is uncapped.</summary>
    public long? QuotaBytes { get; init; }

    /// <summary>Bytes that could be freed without losing anything the policy keeps.</summary>
    public long ReclaimableBytes { get; init; }

    /// <summary>How many blocks are stored.</summary>
    public int BlockCount { get; init; }

    /// <summary>How many snapshots are stored.</summary>
    public int SnapshotCount { get; init; }

    /// <summary>How many stored blocks no live snapshot refers to any more.</summary>
    public int UnreferencedBlockCount { get; init; }

    /// <summary>How many snapshots the retention policy would discard.</summary>
    public int PrunableSnapshotCount { get; init; }

    /// <summary>The fraction of the quota used, or null when uncapped.</summary>
    public double? Fraction =>
        QuotaBytes is > 0 ? Math.Min(1.0, (double)UsedBytes / QuotaBytes.Value) : null;

    /// <summary>True when the quota is reached and a save would be refused.</summary>
    public bool IsFull => QuotaBytes is { } quota && UsedBytes >= quota;

    /// <summary>True when usage is close enough to the quota to be worth saying so.</summary>
    public bool IsNearlyFull => Fraction >= 0.9 && !IsFull;

    /// <summary>Whether anything could be freed by pruning.</summary>
    public bool HasReclaimable => ReclaimableBytes > 0;

    /// <summary>A one-line description of usage against quota.</summary>
    public string Describe() =>
        QuotaBytes is { } quota
            ? $"{Bytes(UsedBytes)} / {Bytes(quota)}"
            : Bytes(UsedBytes);

    /// <summary>Formats a byte count the way a person reads it.</summary>
    /// <param name="bytes">The count to format.</param>
    /// <returns>A short human-readable size.</returns>
    /// <remarks>
    /// Binary units, labelled as binary units. Storage tools that divide by 1024 and print
    /// "GB" are the reason people think their disks are smaller than the box said.
    /// </remarks>
    public static string Bytes(long bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];

        double value = bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? string.Create(CultureInfo.CurrentCulture, $"{bytes} B")
            : string.Create(CultureInfo.CurrentCulture, $"{value:0.#} {units[unit]}");
    }
}
