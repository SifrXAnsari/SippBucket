using System.Diagnostics.CodeAnalysis;
using SippBucket.Core.Repository;

namespace SippBucket.Core.Servers;

/// <summary>
/// What two of the person's own machines tell each other about themselves, inside the
/// encrypted sync channel: the request of <see cref="Protocol.MessageType.ServerRecordRequest"/>
/// and the answer of <see cref="Protocol.MessageType.ServerRecordResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// Sent in full only to a machine the sender's person said is theirs. To any other, including
/// a paired machine never answered about, every field is empty: a Server.ID is never sent to
/// another person's machine (docs/SERVER-ID.md), and the self-reported summary goes with it.
/// </para>
/// <para>
/// All three parts are self-reported. The record is guidance, the report is weak evidence,
/// and the claims are hearsay about machines the receiver may never have talked to.
/// </para>
/// </remarks>
public sealed record ServerExchangeMessage
{
    /// <summary>The most servers one message may pass on claims for.</summary>
    public const int MaximumOthers = 64;

    /// <summary>The sender's own <c>sippbucket.server/1</c> record, or null.</summary>
    public ServerRecord? Record { get; init; }

    /// <summary>What the sender says about its clock and settings: weak evidence, or null.</summary>
    public SelfReport? Report { get; init; }

    /// <summary>The number claims the sender has heard for the person's other servers, or null.</summary>
    public IReadOnlyList<ServerClaims>? Others { get; init; }

    /// <summary>The message a machine sends one that is not the person's own: nothing at all.</summary>
    public static ServerExchangeMessage Nothing { get; } = new();
}

/// <summary>The number claims one server's installs made, as another server passes them on.</summary>
public sealed record ServerClaims
{
    /// <summary>The server's permanent ID.</summary>
    public required string Permanent { get; init; }

    /// <summary>Its label, as last heard.</summary>
    public string? Label { get; init; }

    /// <summary>Its installs' claims.</summary>
    public required IReadOnlyList<NumberClaim> Claims { get; init; }

    /// <summary>Whether a passed-on entry is within the bounds any real one satisfies.</summary>
    /// <param name="entry">The entry.</param>
    /// <returns>True when it may be kept as hearsay.</returns>
    public static bool IsAcceptable([NotNullWhen(true)] ServerClaims? entry) =>
        entry is not null &&
        ServerRecord.IsPermanentHex(entry.Permanent) &&
        (entry.Label is null || ServerRecord.IsDisplayText(entry.Label, MachineLabel.MaximumLength)) &&
        entry.Claims is { Count: > 0 and <= ServerRecord.MaximumInstalls } &&
        entry.Claims.All(claim =>
            claim is not null &&
            PeerRegistry.IsWellFormedDeviceId(claim.Device) &&
            claim.Number is >= 1 and <= ServerRecord.MaximumNumber);
}

/// <summary>
/// What a server says about itself beyond its record: its clock, and the settings from its
/// <c>master.json</c> that matter to the machines it syncs with (docs/PEER-HEALTH.md, "What a
/// peer says about itself").
/// </summary>
/// <remarks>
/// Weak evidence, and described as that wherever it is shown: it catches honest
/// misconfiguration, an old version, a setting outside the safe range, a wrong clock. It cannot
/// catch a hacked machine, because a hacked machine can lie about itself.
/// </remarks>
public sealed record SelfReport
{
    /// <summary>The most settings one report may carry.</summary>
    public const int MaximumSettings = 32;

    /// <summary>The sender's clock, in UTC, when it made the report.</summary>
    public required DateTimeOffset Clock { get; init; }

    /// <summary>Settings by their dotted <c>master.json</c> key, such as <c>sync.stallTimeoutSeconds</c>.</summary>
    public required IReadOnlyDictionary<string, int> Settings { get; init; }

    /// <summary>Whether a report is within the bounds any real one satisfies.</summary>
    /// <param name="report">The report.</param>
    /// <returns>True when it may be compared.</returns>
    public static bool IsAcceptable([NotNullWhen(true)] SelfReport? report) =>
        report?.Settings is { Count: <= MaximumSettings } settings &&
        settings.Keys.All(key => ServerRecord.IsDisplayText(key, 64));
}
