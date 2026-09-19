// randomness.cpp - whether a sample of a file looks like encrypted data.
//
// Peer health's mass-change hold (docs/PEER-HEALTH.md) looks for files whose content turns
// random-looking when it was not before: what ransomware's encryption does to a folder, and
// what a sync tool then faithfully copies to every machine. This file judges one sample; the
// caller compares a file before and after a change, which is what lets photos, videos and
// archives, random-looking anyway, pass unremarked.
//
// THE TEST. Pearson's chi-square over how often each of the 256 byte values occurs. With n
// bytes, each value is expected n/256 times, and the statistic has 255 degrees of freedom:
// mean 255, standard deviation about 22.6. Uniformly random bytes give a statistic from 150 to
// 400 all but a few times in a hundred million (about 4.6 standard deviations below the mean
// and 6.4 above). A sample is random-looking when its statistic lies in that window: text and
// most file formats lie far above it, and data too even to be random, such as a counter, below.
//
// The statistic is computed exactly, in integers: with the expected count n/256 it reduces to
// 256 * sum(count^2) / n - n, so the verdict never depends on how a compiler rounds. The
// entropy beside it is for people and plays no part in the verdict.
//
// What this code may do is the engine's rule: it reads only inside the caller's buffer,
// allocates nothing, keeps no state and throws nothing.

#include "randomness.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace sipengine::randomness {
namespace {

constexpr std::uint64_t LowestRandom = 150;
constexpr std::uint64_t HighestRandom = 400;
constexpr std::uint64_t ByteValues = 256;

[[nodiscard]] std::uint32_t EntropyMilli(const std::array<std::uint32_t, ByteValues>& counts, std::uint64_t n) noexcept
{
    const auto total = static_cast<double>(n);
    double entropy = 0.0;
    for (const std::uint32_t count : counts) {
        if (count != 0U) {
            const double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
    }

    const double milli = std::clamp(entropy * 1000.0, 0.0, 8000.0);
    return static_cast<std::uint32_t>(std::lround(milli));
}

}  // namespace

Result Judge(std::span<const std::uint8_t> sample) noexcept
{
    const std::span<const std::uint8_t> judged =
        sample.first(std::min<std::size_t>(sample.size(), SIPE_RANDOMNESS_SAMPLE_BYTES));

    Result result;
    result.judged = static_cast<std::uint32_t>(judged.size());
    if (judged.empty()) {
        return result;
    }

    // A byte indexes 256 counts, so no index can leave the array.
    std::array<std::uint32_t, ByteValues> counts{};
    for (const std::uint8_t b : judged) {
        ++counts[b];
    }

    const std::uint64_t n = judged.size();
    std::uint64_t sumOfSquares = 0;
    for (const std::uint32_t count : counts) {
        sumOfSquares += std::uint64_t{count} * count;
    }

    // chi-square = 256 * sum(count^2) / n - n. By Cauchy-Schwarz, 256 * sum(count^2) is at
    // least n^2, so excess (the statistic times n) never wraps.
    const std::uint64_t excess = (ByteValues * sumOfSquares) - (n * n);
    const std::uint64_t centi = (100U * excess) / n;
    result.chiCenti = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(centi, std::numeric_limits<std::uint32_t>::max()));
    result.entropyMilli = EntropyMilli(counts, n);

    if (judged.size() < SIPE_RANDOMNESS_MINIMUM_BYTES) {
        result.verdict = SIPE_RANDOMNESS_TOO_SMALL;
        return result;
    }

    const bool random = excess >= LowestRandom * n && excess <= HighestRandom * n;
    result.verdict = random ? SIPE_RANDOMNESS_RANDOM : SIPE_RANDOMNESS_STRUCTURED;
    return result;
}

}  // namespace sipengine::randomness
