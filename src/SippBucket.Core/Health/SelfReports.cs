using System.Globalization;
using SippBucket.Core.Configuration;
using SippBucket.Core.Platform;
using SippBucket.Core.Servers;

namespace SippBucket.Core.Health;

/// <summary>
/// The summary a server sends about itself, and the comparison a peer makes of it against the
/// safe ranges: weak evidence (docs/PEER-HEALTH.md, "What a peer says about itself").
/// </summary>
/// <remarks>
/// It catches honest misconfiguration: an old version, a setting outside the range this build
/// allows, a clock hours off. It cannot catch a hacked machine, because a hacked machine can
/// lie about itself, and nothing that shows it may describe it as if it could.
/// </remarks>
public static class SelfReports
{
    /// <summary>The <c>master.json</c> settings a report carries: the ones that matter to the machines a server syncs with.</summary>
    /// <remarks>
    /// Timings that decide whether a long transfer between two machines survives, and the Direct
    /// Push limits that decide what one will accept from the other. Not the ports, which each
    /// machine records for the other when they pair, and nothing about what is stored where.
    /// </remarks>
    public static IReadOnlyList<MasterSetting> Reported { get; } =
    [
        MasterSettings.PollInterval,
        MasterSettings.ConnectTimeout,
        MasterSettings.StallTimeout,
        MasterSettings.IdleTimeout,
        MasterSettings.PushWindow,
        MasterSettings.LargestFile,
        MasterSettings.LargestMessage,
        MasterSettings.MessageRate,
    ];

    /// <summary>This machine's report.</summary>
    /// <param name="machine">This machine's settings.</param>
    /// <param name="nowUtc">Its clock.</param>
    /// <returns>The report to send.</returns>
    public static SelfReport ForThisMachine(MasterConfig machine, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(machine);

        return new SelfReport
        {
            Clock = nowUtc,
            Settings = Reported.ToDictionary(setting => setting.Key, machine.ValueOf, StringComparer.Ordinal),
        };
    }

    /// <summary>Compares what a server says about itself with the safe ranges.</summary>
    /// <param name="record">Its record, for its version; null when it sent none.</param>
    /// <param name="report">Its report.</param>
    /// <param name="nowUtc">This machine's clock when the report arrived.</param>
    /// <param name="settings">This machine's thresholds.</param>
    /// <returns>What is outside the safe ranges, in sentences; empty when nothing is.</returns>
    public static IReadOnlyList<string> Compare(ServerRecord? record, SelfReport report, DateTimeOffset nowUtc, HealthSettings settings)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(settings);

        var findings = new List<string>();

        var skew = report.Clock - nowUtc;
        if (skew.Duration() > settings.ClockSkew)
        {
            findings.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"its clock read {report.Clock.ToUniversalTime():yyyy-MM-dd HH:mm} UTC when this machine's read " +
                $"{nowUtc.ToUniversalTime():yyyy-MM-dd HH:mm} UTC: {skew.Duration().TotalHours:0.#} hours " +
                $"{(skew > TimeSpan.Zero ? "ahead" : "behind")}"));
        }

        if (record is not null &&
            Version.TryParse(record.Version, out var theirs) &&
            Version.TryParse(BuildVersion.Current, out var ours) &&
            theirs < ours)
        {
            findings.Add($"it runs SippBucket {record.Version}; this machine runs {BuildVersion.Current}");
        }

        foreach (var (key, value) in report.Settings.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            // A setting this build does not know belongs to a newer one, which may allow it.
            if (MasterSettings.Find(key) is not { } setting)
            {
                continue;
            }

            if (value < setting.Minimum || value > setting.Maximum)
            {
                findings.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"it says {setting.Key} is {value}, outside the {setting.Minimum} to {setting.Maximum} this build allows"));
            }
        }

        return findings;
    }
}
