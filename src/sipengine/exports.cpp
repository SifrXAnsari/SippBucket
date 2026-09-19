// exports.cpp - the C ABI in sipengine.h, over the C++ inside.
//
// Each export checks its pointers, wraps them in spans at once, and calls into C++ that
// neither allocates nor throws. Nothing here keeps state between calls.

#include "sipengine.h"

#include "content_check.hpp"
#include "randomness.hpp"
#include "smbios.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>

namespace {

/// Copies text into the caller's buffer, and says how long it is whether or not it fit.
[[nodiscard]] std::int32_t WriteText(std::optional<std::string_view> text,
                                     std::uint8_t* out_utf8,
                                     std::size_t out_capacity,
                                     std::size_t* out_len) noexcept
{
    if (out_len == nullptr || (out_utf8 == nullptr && out_capacity != 0U)) {
        return SIPE_ERR_NULL_ARG;
    }

    if (!text) {
        *out_len = 0U;
        return SIPE_ERR_UNKNOWN;
    }

    *out_len = text->size();
    if (text->size() > out_capacity) {
        return SIPE_ERR_CAPACITY;
    }

    if (!text->empty()) {
        const std::span<std::uint8_t> out(out_utf8, out_capacity);
        std::transform(text->begin(), text->end(), out.begin(),
                       [](char c) noexcept { return static_cast<std::uint8_t>(c); });
    }

    return SIPE_OK;
}

}  // namespace

extern "C" {

SIPE_EXPORT uint32_t SIPE_CALL sipe_abi_version(void) SIPE_NOEXCEPT
{
    return SIPE_ABI_VERSION;
}

SIPE_EXPORT int32_t SIPE_CALL sipe_content_check(const uint8_t *head,
                                                 size_t         head_len,
                                                 uint64_t       total_len,
                                                 const uint8_t *name_utf8,
                                                 size_t         name_len,
                                                 uint32_t      *out_fields,
                                                 size_t         out_capacity) SIPE_NOEXCEPT
{
    if ((head == nullptr && head_len != 0U) || (name_utf8 == nullptr && name_len != 0U) || out_fields == nullptr) {
        return SIPE_ERR_NULL_ARG;
    }

    if (out_capacity < SIPE_CONTENT_FIELDS) {
        return SIPE_ERR_CAPACITY;
    }

    const std::span<const std::uint8_t> headBytes =
        head == nullptr ? std::span<const std::uint8_t>{} : std::span<const std::uint8_t>(head, head_len);
    const std::span<const std::uint8_t> nameBytes =
        name_utf8 == nullptr ? std::span<const std::uint8_t>{} : std::span<const std::uint8_t>(name_utf8, name_len);

    const sipengine::content::Result result = sipengine::content::Check(headBytes, total_len, nameBytes);

    const std::span<std::uint32_t> out(out_fields, out_capacity);
    out[SIPE_FIELD_VERDICT] = result.verdict;
    out[SIPE_FIELD_REASON] = result.reason;
    out[SIPE_FIELD_DETECTED] = static_cast<std::uint32_t>(result.detected);
    out[SIPE_FIELD_CLAIMED] = static_cast<std::uint32_t>(result.claimed);
    return SIPE_OK;
}

SIPE_EXPORT int32_t SIPE_CALL sipe_content_type_name(uint32_t type,
                                                     uint8_t *out_utf8,
                                                     size_t   out_capacity,
                                                     size_t  *out_len) SIPE_NOEXCEPT
{
    return WriteText(sipengine::content::NameOf(type), out_utf8, out_capacity, out_len);
}

SIPE_EXPORT int32_t SIPE_CALL sipe_content_type_extension(uint32_t type,
                                                          uint8_t *out_utf8,
                                                          size_t   out_capacity,
                                                          size_t  *out_len) SIPE_NOEXCEPT
{
    return WriteText(sipengine::content::ExtensionOf(type), out_utf8, out_capacity, out_len);
}

SIPE_EXPORT int32_t SIPE_CALL sipe_smbios_read(uint8_t  *out,
                                               size_t    out_capacity,
                                               size_t   *out_len,
                                               uint32_t *out_os_error) SIPE_NOEXCEPT
{
    if ((out == nullptr && out_capacity != 0U) || out_len == nullptr || out_os_error == nullptr) {
        return SIPE_ERR_NULL_ARG;
    }

    const std::span<std::uint8_t> buffer =
        out == nullptr ? std::span<std::uint8_t>{} : std::span<std::uint8_t>(out, out_capacity);
    return sipengine::smbios::Read(buffer, *out_len, *out_os_error);
}

SIPE_EXPORT int32_t SIPE_CALL sipe_smbios_identity(const uint8_t *raw,
                                                   size_t         raw_len,
                                                   uint32_t      *out_fields,
                                                   size_t         out_capacity) SIPE_NOEXCEPT
{
    if ((raw == nullptr && raw_len != 0U) || out_fields == nullptr) {
        return SIPE_ERR_NULL_ARG;
    }

    if (out_capacity < SIPE_SMBIOS_FIELDS) {
        return SIPE_ERR_CAPACITY;
    }

    // Offsets leave as 32-bit values, and no buffer GetSystemFirmwareTable fills is longer.
    if (raw_len > std::numeric_limits<std::uint32_t>::max()) {
        return SIPE_ERR_MALFORMED;
    }

    const std::span<const std::uint8_t> bytes =
        raw == nullptr ? std::span<const std::uint8_t>{} : std::span<const std::uint8_t>(raw, raw_len);
    const std::optional<sipengine::smbios::Identity> identity = sipengine::smbios::Parse(bytes);
    if (!identity) {
        return SIPE_ERR_MALFORMED;
    }

    const std::span<std::uint32_t> out(out_fields, out_capacity);
    out[SIPE_SMBIOS_FIELD_VERSION] = identity->version;
    out[SIPE_SMBIOS_FIELD_ENDING] = identity->ending;

    std::size_t at = SIPE_SMBIOS_FIELD_VALUES;
    for (const sipengine::smbios::Value& value : identity->values) {
        out[at] = value.state;
        out[at + 1U] = static_cast<std::uint32_t>(value.offset);
        out[at + 2U] = static_cast<std::uint32_t>(value.length);
        at += 3U;
    }

    return SIPE_OK;
}

SIPE_EXPORT int32_t SIPE_CALL sipe_randomness(const uint8_t *sample,
                                              size_t         sample_len,
                                              uint32_t      *out_fields,
                                              size_t         out_capacity) SIPE_NOEXCEPT
{
    if ((sample == nullptr && sample_len != 0U) || out_fields == nullptr) {
        return SIPE_ERR_NULL_ARG;
    }

    if (out_capacity < SIPE_RANDOMNESS_FIELDS) {
        return SIPE_ERR_CAPACITY;
    }

    const std::span<const std::uint8_t> bytes =
        sample == nullptr ? std::span<const std::uint8_t>{} : std::span<const std::uint8_t>(sample, sample_len);
    const sipengine::randomness::Result result = sipengine::randomness::Judge(bytes);

    const std::span<std::uint32_t> out(out_fields, out_capacity);
    out[SIPE_RANDOMNESS_FIELD_VERDICT] = result.verdict;
    out[SIPE_RANDOMNESS_FIELD_ENTROPY] = result.entropyMilli;
    out[SIPE_RANDOMNESS_FIELD_CHI] = result.chiCenti;
    out[SIPE_RANDOMNESS_FIELD_JUDGED] = result.judged;
    return SIPE_OK;
}

}  // extern "C"
