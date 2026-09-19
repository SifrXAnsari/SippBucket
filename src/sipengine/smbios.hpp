// smbios.hpp - the SMBIOS reader's C++ surface, shared by the exports and the self-test.
// Nothing here crosses the DLL boundary; sipengine.h is the ABI.

#ifndef SIPENGINE_SMBIOS_HPP
#define SIPENGINE_SMBIOS_HPP

#include "sipengine.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace sipengine::smbios {

/// One value from the tables: whether it is there and real, and where it is in the buffer.
struct Value {
    std::uint32_t state = SIPE_SMBIOS_ABSENT;

    /// Where the value starts, counted from the start of the RawSMBIOSData buffer given, its
    /// header included. 0 when the value is absent.
    std::size_t offset = 0;

    /// Its length in bytes: 16 for the UUID, and for text the length after the spaces at
    /// either end are dropped. 0 when the value is absent.
    std::size_t length = 0;
};

static_assert(SIPE_SMBIOS_FIELDS == SIPE_SMBIOS_FIELD_VALUES + 3U * SIPE_SMBIOS_VALUES,
              "each value takes three places after the version and the ending");

/// What the tables say about the machine.
struct Identity {
    /// The SMBIOS version from the RawSMBIOSData header: major << 8 | minor.
    std::uint32_t version = 0;

    /// How the walk through the structures ended: SIPE_SMBIOS_ENDED_*.
    std::uint32_t ending = SIPE_SMBIOS_ENDED_AT_LENGTH;

    /// Each value, at its SIPE_SMBIOS_* index.
    std::array<Value, SIPE_SMBIOS_VALUES> values{};
};

/// Reads a RawSMBIOSData buffer. Nothing when it is not one: shorter than its 8-byte header,
/// or claiming more table than it holds. See sipe_smbios_identity.
[[nodiscard]] std::optional<Identity> Parse(std::span<const std::uint8_t> raw) noexcept;

/// Whether a text value, with the spaces at either end already dropped, is one firmware
/// reports when it has nothing to report.
[[nodiscard]] bool IsPlaceholderText(std::span<const std::uint8_t> text) noexcept;

/// IsPlaceholderText, and the rules only a serial number is held to.
[[nodiscard]] bool IsPlaceholderSerial(std::span<const std::uint8_t> text) noexcept;

/// Whether 16 UUID bytes, as stored, are a value firmware reports when it has no UUID.
[[nodiscard]] bool IsPlaceholderUuid(std::span<const std::uint8_t> uuid) noexcept;

/// Asks Windows for the firmware's tables. See sipe_smbios_read, whose codes it returns.
[[nodiscard]] std::int32_t Read(std::span<std::uint8_t> out, std::size_t& length, std::uint32_t& osError) noexcept;

}  // namespace sipengine::smbios

#endif  // SIPENGINE_SMBIOS_HPP
