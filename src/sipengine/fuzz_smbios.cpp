// fuzz_smbios.cpp - a libFuzzer entry point for the SMBIOS reader.
//
// Built by build.ps1 -Fuzz with clang-cl's /fsanitize=fuzzer,address, beside fuzz_content.cpp,
// and run for as many seconds as asked. The input is the RawSMBIOSData buffer, header and all.
// Any read outside it stops the run under ASan. A code the export does not give for a table, an
// ending or a state outside the ABI's, or a value that points outside the buffer, stops it here.

#include "sipengine.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    std::array<std::uint32_t, SIPE_SMBIOS_FIELDS> fields{};
    const std::int32_t code =
        sipe_smbios_identity(size == 0U ? nullptr : data, size, fields.data(), fields.size());

    if (code == SIPE_ERR_MALFORMED) {
        return 0;
    }

    const std::uint32_t ending = fields[SIPE_SMBIOS_FIELD_ENDING];
    if (code != SIPE_OK || ending < SIPE_SMBIOS_ENDED_AT_MARKER || ending > SIPE_SMBIOS_ENDED_AT_DAMAGE) {
        std::abort();
    }

    for (std::size_t value = 0; value < SIPE_SMBIOS_VALUES; ++value) {
        const std::size_t at = SIPE_SMBIOS_FIELD_VALUES + (3U * value);
        const std::uint32_t state = fields[at];
        const std::uint32_t offset = fields[at + 1U];
        const std::uint32_t length = fields[at + 2U];

        const bool known = state <= SIPE_SMBIOS_PLACEHOLDER;
        const bool inside = std::uint64_t{offset} + length <= size;
        const bool absentIsEmpty = state != SIPE_SMBIOS_ABSENT || (offset == 0U && length == 0U);
        const bool uuidIsWhole = value != SIPE_SMBIOS_UUID || state == SIPE_SMBIOS_ABSENT || length == 16U;
        if (!known || !inside || !absentIsEmpty || !uuidIsWhole) {
            std::abort();
        }
    }

    return 0;
}
