// randomness.hpp - the randomness test's C++ surface, shared by the exports and the self-test.
// Nothing here crosses the DLL boundary; sipengine.h is the ABI.

#ifndef SIPENGINE_RANDOMNESS_HPP
#define SIPENGINE_RANDOMNESS_HPP

#include "sipengine.h"

#include <cstdint>
#include <span>

namespace sipengine::randomness {

/// The test's verdict on one sample, and the figures behind it.
struct Result {
    std::uint32_t verdict = SIPE_RANDOMNESS_TOO_SMALL;
    std::uint32_t entropyMilli = 0;   // thousandths of a bit per byte, 0 to 8000
    std::uint32_t chiCenti = 0;       // the chi-square statistic, in hundredths, capped at 2^32 - 1
    std::uint32_t judged = 0;         // bytes judged
};

/// Judges a sample. See sipe_randomness.
[[nodiscard]] Result Judge(std::span<const std::uint8_t> sample) noexcept;

}  // namespace sipengine::randomness

#endif  // SIPENGINE_RANDOMNESS_HPP
