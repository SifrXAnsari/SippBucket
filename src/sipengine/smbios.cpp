// smbios.cpp - which physical machine this is, from the firmware's SMBIOS tables.
//
// Server.ID's permanent ID (docs/SERVER-ID.md) is made from two values the firmware keeps:
// the baseboard's serial number and the system UUID. This file finds them, with the
// manufacturer, product and version names a machine's label is made from, and says which of
// them are placeholders: values firmware reports when it has nothing real to report.
//
// The format is DMTF's System Management BIOS Reference Specification, DSP0134. The section
// numbers are that specification's, and the offsets are the ones dmidecode reads under them:
//   6.1.2  every structure starts with a 4-byte header: its type, the length of its formatted
//          area (the header included), and a handle. A length under 4 is broken, and nothing
//          after it can be found.
//   6.1.3  a structure's strings follow its formatted area, each ended by a zero byte, and
//          the set ended by one more. A string field holds a string's number, counted from 1;
//          0 means no string.
//   7.2    type 1, System Information: manufacturer 04h, product name 05h, version 06h,
//          UUID 08h, 16 bytes.
//   7.2.1  the UUID. Its first three fields are stored little-endian from SMBIOS 2.6. All
//          bytes FFh, or all 00h, mean there is no UUID.
//   7.3    type 2, Baseboard Information: manufacturer 04h, product 05h, serial number 07h.
// Type 127 marks the end of the table.
//
// Windows hands the tables over as RawSMBIOSData (GetSystemFirmwareTable's documentation,
// cited in smbios_read.cpp): a byte saying whether SMBIOS 2.0's calling method was used, the
// major and minor version, the DMI revision, a 4-byte little-endian Length, and then Length
// bytes of structures.
//
// When a structure type appears more than once, the first counts, so the answer depends on
// nothing but the table's order.
//
// PLACEHOLDERS (docs/SERVER-ID.md, "Reading the hardware, and when it lies"). Firmware on
// custom boards often fills a field it has nothing for with a word for nothing or with the
// field's own name: "To be filled by O.E.M.", "Default string", "System Serial Number". The
// rules, each tested in selftest.cpp:
//   - Any text: one of PlaceholderTexts below, compared whole and ignoring ASCII case; empty
//     once the spaces at either end are dropped; or beginning "TypeN - ", which names a
//     structure type instead of filling the field.
//   - A serial number, also: ending "serial number"; fewer than four characters that are not
//     spaces, dashes, dots, colons or underscores; or every one of those characters the same,
//     as in "00000000" or "FF-FF-FF-FF".
//   - The UUID: every byte the same, which covers the specification's all 00h and all FFh; or
//     03000200-0400-0500-0006-000700080009, a well-known default.
// A placeholder taken for a real value would let two machines share a permanent ID; a real
// value taken for a placeholder costs only a fallback. So where a rule could go either way, it
// leans the second way.
//
// What this code may do, and why it is safe in native code, are the content check's rules:
// every read goes through Has(), or indexes a span already cut to a checked length; it
// allocates nothing, keeps no state and throws nothing. The self-test reads a table cut at
// every length, and fuzz_smbios.cpp feeds the parser anything, under ASan.

#include "smbios.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace sipengine::smbios {
namespace {

using Bytes = std::span<const std::uint8_t>;

// RawSMBIOSData's header, and every structure's.
constexpr std::size_t RawHeaderSize = 8;
constexpr std::size_t StructureHeaderSize = 4;

// Structure types.
constexpr std::uint32_t SystemInformation = 1;
constexpr std::uint32_t BaseboardInformation = 2;
constexpr std::uint32_t EndOfTable = 127;

// Fields, counted from a structure's first byte.
constexpr std::size_t ManufacturerField = 0x04;
constexpr std::size_t ProductField = 0x05;
constexpr std::size_t VersionField = 0x06;
constexpr std::size_t SerialField = 0x07;
constexpr std::size_t UuidField = 0x08;
constexpr std::size_t UuidSize = 16;

constexpr std::uint8_t Space = 0x20;

// A serial number with fewer characters than this, separators aside, is a placeholder.
constexpr std::size_t MinimumSerialCharacters = 4;

// 03000200-0400-0500-0006-000700080009 as the table stores it, its first three fields
// little-endian.
constexpr std::array<std::uint8_t, UuidSize> DefaultUuid{
    0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09};

// Words for nothing, and field names, that firmware writes where it has no value. Compared
// whole, ignoring ASCII case, after the spaces at either end are dropped. Written in lower
// case, which the static_assert below holds them to. Serial numbers are also held to the
// rules in IsPlaceholderSerial, which catch every "... Serial Number".
constexpr auto PlaceholderTexts = std::to_array<std::string_view>({
    "to be filled by o.e.m.",
    "to be filled by o.e.m",
    "default string",
    "default",
    "system manufacturer",
    "system product name",
    "system version",
    "base board manufacturer",
    "base board product name",
    "base board version",
    "not specified",
    "not applicable",
    "not available",
    "none",
    "n/a",
    "unknown",
    "oem",
    "o.e.m.",
    "invalid",
    "empty",
    "x.x",
    "123456789",
    "0123456789",
    "1234567890",
});

[[nodiscard]] constexpr bool IsLowerCase(std::string_view text) noexcept
{
    return std::none_of(text.begin(), text.end(), [](char c) noexcept { return c >= 'A' && c <= 'Z'; });
}

static_assert(std::all_of(PlaceholderTexts.begin(), PlaceholderTexts.end(), IsLowerCase),
              "placeholders are compared against lower-cased text, so they must be written in lower case");

// ------------------------------------------------------------------------------------------
// Bounded reading, as in content_check.cpp.
// ------------------------------------------------------------------------------------------

[[nodiscard]] constexpr std::uint32_t U(std::uint8_t b) noexcept { return b; }

/// Whether bytes holds count bytes starting at offset. Written so neither sum can wrap.
[[nodiscard]] constexpr bool Has(Bytes bytes, std::size_t offset, std::size_t count) noexcept
{
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

[[nodiscard]] constexpr std::uint32_t LowerAscii(std::uint32_t c) noexcept
{
    return (c >= U('A') && c <= U('Z')) ? c + (U('a') - U('A')) : c;
}

/// Whether text is exactly the lower-case ASCII expected, ignoring ASCII case.
[[nodiscard]] bool EqualsNoCase(Bytes text, std::string_view expected) noexcept
{
    if (text.size() != expected.size()) {
        return false;
    }

    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (LowerAscii(U(text[i])) != U(static_cast<std::uint8_t>(expected[i]))) {
            return false;
        }
    }

    return true;
}

/// Whether text starts with the lower-case ASCII expected, ignoring ASCII case.
[[nodiscard]] bool StartsNoCase(Bytes text, std::string_view expected) noexcept
{
    return Has(text, 0, expected.size()) && EqualsNoCase(text.first(expected.size()), expected);
}

/// Whether text ends with the lower-case ASCII expected, ignoring ASCII case.
[[nodiscard]] bool EndsNoCase(Bytes text, std::string_view expected) noexcept
{
    return Has(text, 0, expected.size()) && EqualsNoCase(text.last(expected.size()), expected);
}

[[nodiscard]] constexpr bool IsDigit(std::uint32_t c) noexcept { return c >= U('0') && c <= U('9'); }

/// The characters a serial number's length and sameness are judged without.
[[nodiscard]] constexpr bool IsSeparator(std::uint32_t c) noexcept
{
    return c == U(' ') || c == U('-') || c == U('.') || c == U(':') || c == U('_');
}

/// Whether text begins "TypeN - ": a structure type's name, describing the field instead of
/// filling it.
[[nodiscard]] bool NamesAStructureType(Bytes text) noexcept
{
    constexpr std::string_view prefix = "type";
    constexpr std::string_view dash = " - ";
    constexpr std::size_t mostDigits = 3;

    if (!StartsNoCase(text, prefix)) {
        return false;
    }

    std::size_t at = prefix.size();
    while (at < text.size() && at - prefix.size() < mostDigits && IsDigit(U(text[at]))) {
        ++at;
    }

    return at > prefix.size() && StartsNoCase(text.subspan(at), dash);
}

// ------------------------------------------------------------------------------------------
// Walking the structures.
// ------------------------------------------------------------------------------------------

/// One structure. Offsets are the table's, which are the caller's buffer's.
struct Structure {
    Bytes table;
    std::size_t offset = 0;      // its first byte
    std::size_t length = 0;      // its formatted area's length, the header included
    std::size_t strings = 0;     // where its strings start
    std::size_t stringsEnd = 0;  // just past the zero byte that closes the set
};

/// The rules a text value is judged by.
enum class Kind : std::uint8_t {
    Name,
    Serial,
};

/// Where the string set starting at offset ends: just past its closing pair of zero bytes.
/// Nothing when the table ends first.
[[nodiscard]] std::optional<std::size_t> StringSetEnd(Bytes table, std::size_t offset) noexcept
{
    for (std::size_t at = offset; Has(table, at, 2); ++at) {
        const Bytes pair = table.subspan(at, 2);
        if (pair[0] == 0U && pair[1] == 0U) {
            return at + 2U;
        }
    }

    return std::nullopt;
}

/// The text at offset without the spaces firmware pads it with, and where what is left starts.
[[nodiscard]] Value Trimmed(Bytes table, std::size_t offset, std::size_t length) noexcept
{
    Bytes text = table.subspan(offset, length);
    std::size_t start = offset;

    while (!text.empty() && text.front() == Space) {
        text = text.subspan(1);
        ++start;
    }

    while (!text.empty() && text.back() == Space) {
        text = text.first(text.size() - 1U);
    }

    return Value{SIPE_SMBIOS_PRESENT, start, text.size()};
}

/// The string a field numbers, trimmed. Nothing when the field is not in the formatted area,
/// holds 0, or numbers a string the set does not have.
[[nodiscard]] std::optional<Value> StringField(const Structure& s, std::size_t field) noexcept
{
    if (field >= s.length) {
        return std::nullopt;
    }

    const std::uint32_t number = U(s.table.subspan(s.offset + field, 1)[0]);
    if (number == 0U) {
        return std::nullopt;
    }

    std::size_t start = s.strings;
    for (std::uint32_t index = 1; start < s.stringsEnd; ++index) {
        const Bytes rest = s.table.subspan(start, s.stringsEnd - start);
        const auto size = static_cast<std::size_t>(std::find(rest.begin(), rest.end(), std::uint8_t{0}) - rest.begin());

        // The empty string is the one that closes the set.
        if (size == 0U) {
            return std::nullopt;
        }

        if (index == number) {
            return Trimmed(s.table, start, size);
        }

        start += size + 1U;
    }

    return std::nullopt;
}

[[nodiscard]] Value TextValue(const Structure& s, std::size_t field, Kind kind) noexcept
{
    const std::optional<Value> found = StringField(s, field);
    if (!found) {
        return Value{};
    }

    Value value = *found;
    const Bytes text = s.table.subspan(value.offset, value.length);
    const bool placeholder = kind == Kind::Serial ? IsPlaceholderSerial(text) : IsPlaceholderText(text);
    if (placeholder) {
        value.state = SIPE_SMBIOS_PLACEHOLDER;
    }

    return value;
}

[[nodiscard]] Value UuidValue(const Structure& s) noexcept
{
    if (s.length < UuidField + UuidSize) {
        return Value{};
    }

    const std::size_t offset = s.offset + UuidField;
    const bool placeholder = IsPlaceholderUuid(s.table.subspan(offset, UuidSize));
    return Value{placeholder ? SIPE_SMBIOS_PLACEHOLDER : SIPE_SMBIOS_PRESENT, offset, UuidSize};
}

void ReadSystem(const Structure& s, Identity& identity) noexcept
{
    identity.values[SIPE_SMBIOS_UUID] = UuidValue(s);
    identity.values[SIPE_SMBIOS_SYSTEM_MAKER] = TextValue(s, ManufacturerField, Kind::Name);
    identity.values[SIPE_SMBIOS_SYSTEM_PRODUCT] = TextValue(s, ProductField, Kind::Name);
    identity.values[SIPE_SMBIOS_SYSTEM_VERSION] = TextValue(s, VersionField, Kind::Name);
}

void ReadBoard(const Structure& s, Identity& identity) noexcept
{
    identity.values[SIPE_SMBIOS_BOARD_MAKER] = TextValue(s, ManufacturerField, Kind::Name);
    identity.values[SIPE_SMBIOS_BOARD_PRODUCT] = TextValue(s, ProductField, Kind::Name);
    identity.values[SIPE_SMBIOS_BOARD_SERIAL] = TextValue(s, SerialField, Kind::Serial);
}

}  // namespace

std::optional<Identity> Parse(Bytes raw) noexcept
{
    if (!Has(raw, 0, RawHeaderSize)) {
        return std::nullopt;
    }

    const Bytes header = raw.first(RawHeaderSize);
    const std::uint32_t length = U(header[4]) | (U(header[5]) << 8U) | (U(header[6]) << 16U) | (U(header[7]) << 24U);
    if (!Has(raw, RawHeaderSize, length)) {
        return std::nullopt;
    }

    Identity identity;
    identity.version = (U(header[1]) << 8U) | U(header[2]);

    const Bytes table = raw.first(RawHeaderSize + length);
    bool haveSystem = false;
    bool haveBoard = false;
    std::size_t at = RawHeaderSize;

    while (Has(table, at, StructureHeaderSize)) {
        const Bytes head = table.subspan(at, StructureHeaderSize);
        const std::uint32_t type = U(head[0]);
        const std::size_t formatted = head[1];

        if (formatted < StructureHeaderSize || !Has(table, at, formatted)) {
            identity.ending = SIPE_SMBIOS_ENDED_AT_DAMAGE;
            return identity;
        }

        if (type == EndOfTable) {
            identity.ending = SIPE_SMBIOS_ENDED_AT_MARKER;
            return identity;
        }

        const std::optional<std::size_t> end = StringSetEnd(table, at + formatted);
        if (!end) {
            identity.ending = SIPE_SMBIOS_ENDED_AT_DAMAGE;
            return identity;
        }

        const Structure structure{table, at, formatted, at + formatted, *end};
        if (type == SystemInformation && !haveSystem) {
            haveSystem = true;
            ReadSystem(structure, identity);
        }
        else if (type == BaseboardInformation && !haveBoard) {
            haveBoard = true;
            ReadBoard(structure, identity);
        }

        at = *end;
    }

    identity.ending = SIPE_SMBIOS_ENDED_AT_LENGTH;
    return identity;
}

bool IsPlaceholderText(Bytes text) noexcept
{
    if (text.empty()) {
        return true;
    }

    const bool listed = std::any_of(PlaceholderTexts.begin(), PlaceholderTexts.end(),
                                    [text](std::string_view placeholder) noexcept { return EqualsNoCase(text, placeholder); });
    return listed || NamesAStructureType(text);
}

bool IsPlaceholderSerial(Bytes text) noexcept
{
    if (IsPlaceholderText(text) || EndsNoCase(text, "serial number")) {
        return true;
    }

    std::size_t significant = 0;
    bool allSame = true;
    std::uint32_t first = 0;
    for (const std::uint8_t b : text) {
        const std::uint32_t c = LowerAscii(U(b));
        if (IsSeparator(c)) {
            continue;
        }

        if (significant == 0U) {
            first = c;
        }
        else if (c != first) {
            allSame = false;
        }

        ++significant;
    }

    return significant < MinimumSerialCharacters || allSame;
}

bool IsPlaceholderUuid(Bytes uuid) noexcept
{
    if (uuid.size() != UuidSize) {
        return true;
    }

    const std::uint8_t first = uuid.front();
    const bool allSame = std::all_of(uuid.begin(), uuid.end(), [first](std::uint8_t b) noexcept { return b == first; });
    return allSame || std::equal(uuid.begin(), uuid.end(), DefaultUuid.begin(), DefaultUuid.end());
}

}  // namespace sipengine::smbios
