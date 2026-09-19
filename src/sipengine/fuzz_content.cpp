// fuzz_content.cpp - a libFuzzer entry point for the content check.
//
// Built by build.ps1 -Fuzz with clang-cl's /fsanitize=fuzzer,address, and run for as many
// seconds as asked. The first input byte says how many of the rest are the file's name; the
// rest is the file's head. Any read outside those bytes stops the run under ASan; a verdict
// outside the three the ABI defines, or a detected type the engine cannot name, stops it here.

#include "sipengine.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (data == nullptr || size == 0U) {
        return 0;
    }

    const std::span<const std::uint8_t> input(data, size);
    const std::size_t nameLength = std::min<std::size_t>(input.front(), size - 1U);
    const std::span<const std::uint8_t> name = input.subspan(1, nameLength);
    const std::span<const std::uint8_t> head = input.subspan(1U + nameLength);

    std::array<std::uint32_t, SIPE_CONTENT_FIELDS> fields{};
    const std::int32_t code = sipe_content_check(
        head.empty() ? nullptr : head.data(), head.size(), head.size(),
        name.empty() ? nullptr : name.data(), name.size(),
        fields.data(), fields.size());

    const std::uint32_t verdict = fields[SIPE_FIELD_VERDICT];
    std::size_t length = 0;
    const bool named = sipe_content_type_name(fields[SIPE_FIELD_DETECTED], nullptr, 0, &length) != SIPE_ERR_UNKNOWN;

    if (code != SIPE_OK || verdict < SIPE_VERDICT_INBOX || verdict > SIPE_VERDICT_QUARANTINE || !named) {
        std::abort();
    }

    return 0;
}
