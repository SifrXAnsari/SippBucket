using System.Diagnostics.CodeAnalysis;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;

namespace SippBucket.Core.Servers;

/// <summary>
/// The <c>sippbucket.server/1</c> record: one server, as it describes itself to the person's
/// other machines (docs/SERVER-ID.md, "The record").
/// </summary>
/// <remarks>
/// <para>
/// Every field is self-reported and treated as guidance. The only verified fact about the
/// sender is the device ID its handshake proved, and a record is accepted only when that device
/// is one of its <see cref="Installs"/>. The raw serial number is never in it: only the
/// one-way <see cref="Permanent"/> hash.
/// </para>
/// <para>
/// It travels only inside the encrypted sync channel, and only between machines the person
/// said are theirs (<see cref="ServerExchange"/>). <c>firstPaired</c> and <c>lastSeen</c> are
/// the receiving machine's own records and never travel; <see cref="KnownServer"/> holds them.
/// </para>
/// <para>
/// <see cref="Numbered"/> is not in the design page's table: it is when the server took its
/// number, which the rule for two machines claiming one number decides by
/// (<see cref="ServerNumbering"/>). Recorded on the page as decided during implementation.
/// </para>
/// </remarks>
public sealed record ServerRecord
{
    /// <summary>The schema every record of this form names.</summary>
    public const string CurrentSchema = "sippbucket.server/1";

    /// <summary>The highest server number a record may carry.</summary>
    public const int MaximumNumber = 999;

    /// <summary>The most installs one record may list.</summary>
    public const int MaximumInstalls = 16;

    /// <summary>The longest version string a record may carry.</summary>
    public const int MaximumVersionLength = 32;

    /// <summary><c>"sippbucket.server/1"</c>, so the format can evolve.</summary>
    public required string Schema { get; init; }

    /// <summary>The <c>Server.ID#XXX-XXX-XXX</c> fingerprint of <see cref="Permanent"/>.</summary>
    public required string Id { get; init; }

    /// <summary>The permanent ID's full hash, 64 lower-case hexadecimal characters.</summary>
    public required string Permanent { get; init; }

    /// <summary>Where the permanent ID came from, by its wire name (<see cref="PermanentId.WireName"/>).</summary>
    public required string Source { get; init; }

    /// <summary>The server's number, 1, 2, 3 …; 0 while it has none.</summary>
    public int Number { get; init; }

    /// <summary>When the server took its number, which decides between two claims to one number.</summary>
    public DateTimeOffset? Numbered { get; init; }

    /// <summary>A readable description from the firmware, such as "Dell Inspiron 15 3511", or null.</summary>
    public string? Label { get; init; }

    /// <summary>The installs on this board that the sender knows of, itself among them.</summary>
    public required IReadOnlyList<ServerInstall> Installs { get; init; }

    /// <summary>The sender's run ID: random each time it starts.</summary>
    public required string Run { get; init; }

    /// <summary>When the sender's run began, in UTC.</summary>
    public required DateTimeOffset Started { get; init; }

    /// <summary>The sender's SippBucket version.</summary>
    public required string Version { get; init; }

    /// <summary>The sender's wire-protocol version.</summary>
    public required int Protocol { get; init; }

    /// <summary>Checks a record a peer sent before anything of it is kept.</summary>
    /// <param name="record">The record.</param>
    /// <param name="senderDeviceId">The device ID the sender's handshake proved.</param>
    /// <param name="problem">What is wrong, when this returns false.</param>
    /// <returns>True when every field is within its bounds and the record is consistent with itself and its sender.</returns>
    /// <remarks>
    /// Bounded like any other input from a peer. A record whose <see cref="Id"/> is not the
    /// fingerprint of its <see cref="Permanent"/>, or whose installs do not include the device
    /// that sent it, is refused whole: nothing in it is believed, because it contradicts the one
    /// thing that is known.
    /// </remarks>
    public static bool IsAcceptable([NotNullWhen(true)] ServerRecord? record, string senderDeviceId, out string problem)
    {
        if (record is null)
        {
            problem = "it sent no record";
            return false;
        }

        if (!string.Equals(record.Schema, CurrentSchema, StringComparison.Ordinal))
        {
            problem = $"its record's schema is '{Printable(record.Schema)}', not {CurrentSchema}";
            return false;
        }

        if (!IsPermanentHex(record.Permanent))
        {
            problem = "its record's permanent ID is not 64 lower-case hexadecimal characters";
            return false;
        }

        if (!ServerId.TryParse(record.Id, out var id) || id != ServerId.FromPermanent(Convert.FromHexString(record.Permanent)))
        {
            problem = "its record's Server.ID is not the fingerprint of its permanent ID";
            return false;
        }

        if (!PermanentId.TryParseWireName(record.Source, out _))
        {
            problem = $"its record names an unknown source, '{Printable(record.Source)}'";
            return false;
        }

        if (record.Number is < 0 or > MaximumNumber || (record.Number > 0 && record.Numbered is null))
        {
            problem = $"its record's number, {record.Number}, is not one a server can hold";
            return false;
        }

        if (record.Label is not null && !IsDisplayText(record.Label, MachineLabel.MaximumLength))
        {
            problem = "its record's label is not one line of at most 64 characters of plain text";
            return false;
        }

        if (record.Installs is null || record.Installs.Count is 0 or > MaximumInstalls ||
            record.Installs.Any(install => install is null || !PeerRegistry.IsWellFormedDeviceId(install.Device) ||
                                           (install.Windows is not null && !IsDisplayText(install.Windows, WindowsRelease.MaximumLength))) ||
            record.Installs.Select(install => install.Device).Distinct(StringComparer.OrdinalIgnoreCase).Count() != record.Installs.Count)
        {
            problem = $"its record's installs are not between 1 and {MaximumInstalls} distinct, well-formed entries";
            return false;
        }

        if (!record.Installs.Any(install => string.Equals(install.Device, senderDeviceId, StringComparison.OrdinalIgnoreCase)))
        {
            problem = "its record does not list the install that sent it";
            return false;
        }

        if (!RunId.IsWellFormed(record.Run))
        {
            problem = "its record's run ID is not 32 lower-case hexadecimal characters";
            return false;
        }

        if (!IsDisplayText(record.Version, MaximumVersionLength) || record.Protocol is < 1 or > ushort.MaxValue)
        {
            problem = "its record's version or protocol is out of bounds";
            return false;
        }

        problem = string.Empty;
        return true;
    }

    /// <summary>Whether a value is a permanent ID's hash as records carry it.</summary>
    /// <param name="value">The value.</param>
    /// <returns>True for exactly 64 lower-case hexadecimal characters.</returns>
    public static bool IsPermanentHex(string? value) =>
        value is { Length: 64 } && value.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');

    /// <summary>
    /// Whether text is one non-empty line no longer than a limit, with no character that is an
    /// instruction to the display (<see cref="DisplayText"/>).
    /// </summary>
    internal static bool IsDisplayText(string? text, int maximumLength) =>
        text is { Length: > 0 } && text.Length <= maximumLength && !text.Any(DisplayText.IsInstruction) &&
        !string.IsNullOrWhiteSpace(text);

    /// <summary>A peer's text, cut short and made safe to show, for a message.</summary>
    internal static string Printable(string? text) => text is null ? "(none)" : DisplayText.Printable(text, 40);
}

/// <summary>One install on a server's board: one Windows, one device key.</summary>
public sealed record ServerInstall
{
    /// <summary>The install's device ID: its Ed25519 public key in hexadecimal.</summary>
    public required string Device { get; init; }

    /// <summary>Its Windows edition and version, as it reports them.</summary>
    public string? Windows { get; init; }

    /// <summary>When it first ran SippBucket, as it reports it.</summary>
    public DateTimeOffset? FirstSeen { get; init; }
}
