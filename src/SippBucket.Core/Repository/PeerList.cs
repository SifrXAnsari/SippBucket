using System.Globalization;

namespace SippBucket.Core.Repository;

/// <summary>Why a record in <c>peers.json</c> cannot be used.</summary>
public enum PeerRecordProblem
{
    /// <summary>It has no device ID at all.</summary>
    MissingDeviceId = 0,

    /// <summary>Its device ID is not 64 hexadecimal characters.</summary>
    MalformedDeviceId = 1,

    /// <summary>It has no name. The status and the sync results are keyed by name.</summary>
    MissingName = 2,

    /// <summary>It could not be read as a peer at all: a field is missing or of the wrong kind.</summary>
    Unreadable = 3,
}

/// <summary>A record in <c>peers.json</c> that is kept in the file but not used.</summary>
public sealed record SkippedPeerRecord
{
    /// <summary>Where it is in the file, counting from 1.</summary>
    public required int Position { get; init; }

    /// <summary>Why it is skipped.</summary>
    public required PeerRecordProblem Problem { get; init; }

    /// <summary>Its name, when it has one that could be read.</summary>
    public string? Name { get; init; }

    /// <summary>Its device ID as written, when there is one that could be read.</summary>
    public string? DeviceId { get; init; }

    /// <summary>For <see cref="PeerRecordProblem.Unreadable"/>, what the reader objected to.</summary>
    public string? Detail { get; init; }

    /// <summary>The reason, as a person would read it.</summary>
    /// <returns>One clause, starting lower case.</returns>
    public string Describe() => Problem switch
    {
        PeerRecordProblem.MissingDeviceId => "it has no device ID",
        PeerRecordProblem.MalformedDeviceId when DeviceId?.Length != PeerRegistry.DeviceIdLength =>
            string.Create(
                CultureInfo.InvariantCulture,
                $"its device ID is {DeviceId?.Length ?? 0} characters long, and a device ID is " +
                $"{PeerRegistry.DeviceIdLength} hexadecimal characters"),
        PeerRecordProblem.MalformedDeviceId =>
            "its device ID has characters in it that are not hexadecimal (0-9, a-f)",
        PeerRecordProblem.MissingName => "it has no name",
        _ => $"it could not be read as a peer: {Detail}",
    };
}

/// <summary>Everything in <c>peers.json</c>: the records in use, and the ones skipped.</summary>
/// <remarks>
/// A record is skipped, not dropped: the file is meant to be hand-editable, so a typo in one
/// record is shown to the person who made it, with where it is and why, and stays in the
/// file for them to fix. Reading never rewrites the file (D-65).
/// </remarks>
public sealed record PeerList
{
    /// <summary>The records sync, the server and the status use.</summary>
    public required IReadOnlyList<PeerRecord> Usable { get; init; }

    /// <summary>The records that are in the file and are not used, in file order.</summary>
    public required IReadOnlyList<SkippedPeerRecord> Skipped { get; init; }
}
