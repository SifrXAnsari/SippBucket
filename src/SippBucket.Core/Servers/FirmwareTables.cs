using System.Text;
using SippBucket.Core.Native;
using SippBucket.Core.Platform;

namespace SippBucket.Core.Servers;

/// <summary>Whether a value from the firmware's SMBIOS tables is there, and real.</summary>
public enum FirmwareValueState
{
    /// <summary>Its structure or field is not in the tables.</summary>
    Absent = 0,

    /// <summary>There, and not a placeholder.</summary>
    Present = 1,

    /// <summary>
    /// There, but a value firmware writes when it has nothing to write: "To be filled by
    /// O.E.M.", "Default string", the field's own name, a UUID of one repeated byte.
    /// </summary>
    Placeholder = 2,
}

/// <summary>How the engine's walk through the tables ended.</summary>
// CA1008 wants a zero member. The engine's numbering starts at 1 on purpose: a zeroed
// ending must read as invalid, never as a way the walk finished.
#pragma warning disable CA1008
public enum FirmwareTableEnding
{
    /// <summary>At the end-of-table structure, as every table should.</summary>
    AtMarker = 1,

    /// <summary>At the end of the data, with no end-of-table structure.</summary>
    AtLength = 2,

    /// <summary>At a structure that was broken: what came before it was read.</summary>
    AtDamage = 3,
}
#pragma warning restore CA1008

/// <summary>One value from the firmware's tables.</summary>
/// <remarks>
/// Deliberately not a record, and <see cref="ToString"/> says only what kind of value it is:
/// the board's serial number is one of these, and "the raw serial number never leaves the
/// machine" (docs/SERVER-ID.md) should not depend on nobody ever logging an object.
/// </remarks>
public sealed class FirmwareValue
{
    private readonly byte[] _bytes;

    private FirmwareValue(FirmwareValueState state, byte[] bytes)
    {
        State = state;
        _bytes = bytes;
    }

    /// <summary>A value the tables do not have.</summary>
    public static FirmwareValue Absent { get; } = new(FirmwareValueState.Absent, []);

    /// <summary>Whether it is there, and real.</summary>
    public FirmwareValueState State { get; }

    /// <summary>Whether it is there and not a placeholder, so it may identify the machine.</summary>
    public bool IsReal => State == FirmwareValueState.Present;

    /// <summary>The value as the tables store it, without the spaces firmware pads text with.</summary>
    public ReadOnlySpan<byte> Bytes => _bytes;

    /// <summary>
    /// The value as text, for a label: UTF-8, as DSP0134 asks strings to be, with anything that
    /// is not valid UTF-8 replaced, and every character that is an instruction to the display
    /// (<see cref="DisplayText"/>) turned into a space.
    /// </summary>
    public string Text
    {
        get
        {
            var decoded = Encoding.UTF8.GetString(_bytes);
            var builder = new StringBuilder(decoded.Length);
            foreach (var c in decoded)
            {
                builder.Append(DisplayText.IsInstruction(c) ? ' ' : c);
            }

            return builder.ToString().Trim();
        }
    }

    /// <summary>Says what the value is, never what it holds.</summary>
    /// <returns>For example "present, 20 bytes".</returns>
    public override string ToString() => State switch
    {
        FirmwareValueState.Present => $"present, {_bytes.Length} bytes",
        FirmwareValueState.Placeholder => $"a placeholder, {_bytes.Length} bytes",
        _ => "absent",
    };

    /// <summary>Takes one value out of the engine's answer.</summary>
    /// <param name="table">The buffer the engine read.</param>
    /// <param name="fields">The engine's fields.</param>
    /// <param name="value">Which value: its <c>SIPE_SMBIOS_*</c> index.</param>
    /// <returns>The value, copied out of the buffer.</returns>
    /// <exception cref="InvalidOperationException">The engine pointed outside the buffer, which would be a defect in it.</exception>
    internal static FirmwareValue From(byte[] table, uint[] fields, int value)
    {
        var at = FirmwareTables.FirstValueField + (3 * value);
        var state = (FirmwareValueState)fields[at];
        var offset = fields[at + 1];
        var length = fields[at + 2];

        if (state == FirmwareValueState.Absent)
        {
            return Absent;
        }

        if (state is not (FirmwareValueState.Present or FirmwareValueState.Placeholder) ||
            (ulong)offset + length > (ulong)table.Length)
        {
            throw new InvalidOperationException(
                $"The engine described SMBIOS value {value} as state {fields[at]} at {offset}+{length} in a " +
                $"{table.Length}-byte table.");
        }

        return new FirmwareValue(state, table.AsSpan((int)offset, (int)length).ToArray());
    }
}

/// <summary>What the firmware's SMBIOS tables say about this machine.</summary>
/// <remarks>
/// <para>
/// Server.ID's permanent ID is made from two of these values: the baseboard's serial number
/// and the system UUID (docs/SERVER-ID.md). The names beside them make the machine's label.
/// The reading and the parsing are the engine's (<c>sipengine</c>, <c>smbios.cpp</c>, which
/// cites the specification and Microsoft's documentation of the call); this is the managed
/// view of its answer.
/// </para>
/// <para>
/// The tables are read with <c>GetSystemFirmwareTable</c>, which needs no administrator rights
/// and no WMI. When a structure appears more than once the first counts, and a damaged table
/// is read as far as the damage.
/// </para>
/// </remarks>
public sealed class FirmwareTables
{
    /// <summary>
    /// The most a table may be before it is not read. SMBIOS 2's tables cannot pass 64 KiB;
    /// SMBIOS 3's may in principle, and no machine's come near a megabyte.
    /// </summary>
    public const int LargestTable = 16 * 1024 * 1024;

    /// <summary><c>SIPE_SMBIOS_FIELD_VALUES</c>: where the first value's three places start.</summary>
    internal const int FirstValueField = 2;

    // The engine's SIPE_SMBIOS_* value indices.
    private const int UuidValue = 0;
    private const int SystemMakerValue = 1;
    private const int SystemProductValue = 2;
    private const int SystemVersionValue = 3;
    private const int BoardMakerValue = 4;
    private const int BoardProductValue = 5;
    private const int BoardSerialValue = 6;

    private FirmwareTables(byte[] table, uint[] fields)
    {
        MajorVersion = (int)(fields[0] >> 8);
        MinorVersion = (int)(fields[0] & 0xFF);
        Ending = (FirmwareTableEnding)fields[1];
        Uuid = FirmwareValue.From(table, fields, UuidValue);
        SystemMaker = FirmwareValue.From(table, fields, SystemMakerValue);
        SystemProduct = FirmwareValue.From(table, fields, SystemProductValue);
        SystemVersion = FirmwareValue.From(table, fields, SystemVersionValue);
        BoardMaker = FirmwareValue.From(table, fields, BoardMakerValue);
        BoardProduct = FirmwareValue.From(table, fields, BoardProductValue);
        BoardSerial = FirmwareValue.From(table, fields, BoardSerialValue);
    }

    /// <summary>The SMBIOS major version the firmware reports.</summary>
    public int MajorVersion { get; }

    /// <summary>The SMBIOS minor version the firmware reports.</summary>
    public int MinorVersion { get; }

    /// <summary>How the walk through the tables ended.</summary>
    public FirmwareTableEnding Ending { get; }

    /// <summary>The system UUID (type 1), 16 bytes as stored.</summary>
    public FirmwareValue Uuid { get; }

    /// <summary>The system's manufacturer (type 1).</summary>
    public FirmwareValue SystemMaker { get; }

    /// <summary>The system's product name (type 1).</summary>
    public FirmwareValue SystemProduct { get; }

    /// <summary>The system's version (type 1), where some makers put the model's name.</summary>
    public FirmwareValue SystemVersion { get; }

    /// <summary>The baseboard's manufacturer (type 2).</summary>
    public FirmwareValue BoardMaker { get; }

    /// <summary>The baseboard's product (type 2).</summary>
    public FirmwareValue BoardProduct { get; }

    /// <summary>The baseboard's serial number (type 2). Never stored, sent or printed.</summary>
    public FirmwareValue BoardSerial { get; }

    /// <summary>Reads this machine's tables.</summary>
    /// <returns>The tables, or why there are none.</returns>
    /// <exception cref="InvalidOperationException">The engine misbehaved, which would be a defect in it.</exception>
    public static FirmwareReading Read()
    {
        var (table, problem) = SipEngine.ReadSmbios(LargestTable);
        if (table is null)
        {
            return new FirmwareReading(null, problem ?? "Windows gave no SMBIOS tables.");
        }

        return Parse(table) is { } tables
            ? new FirmwareReading(tables, null)
            : new FirmwareReading(null, "Windows gave SMBIOS tables that are not laid out as its documentation says.");
    }

    /// <summary>Reads tables from a buffer laid out as <c>RawSMBIOSData</c>.</summary>
    /// <param name="raw">The buffer: the 8-byte header <c>GetSystemFirmwareTable</c> writes, then the structures.</param>
    /// <returns>The tables, or null when the buffer is not a <c>RawSMBIOSData</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="raw"/> was null.</exception>
    /// <exception cref="InvalidOperationException">The engine misbehaved, which would be a defect in it.</exception>
    public static FirmwareTables? Parse(byte[] raw)
    {
        ArgumentNullException.ThrowIfNull(raw);

        var fields = SipEngine.IdentifySmbios(raw);
        return fields is null ? null : new FirmwareTables(raw, fields);
    }
}

/// <summary>The result of reading the firmware's tables.</summary>
/// <param name="Tables">The tables, when Windows gave them.</param>
/// <param name="Problem">Why there are none, when it did not.</param>
public sealed record FirmwareReading(FirmwareTables? Tables, string? Problem);
