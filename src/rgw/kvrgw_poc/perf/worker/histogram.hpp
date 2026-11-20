// Sparse-able log-linear microsecond histogram; must match the Go implementation
// (controller/internal/stats) and perf/proto/testdata/histogram.json.
#pragma once

#include <bit>
#include <cstdint>

namespace perfw {

inline constexpr uint32_t kLinearLimit = 64;
inline constexpr uint32_t kSubBuckets = 32;
inline constexpr uint32_t kHistBuckets = 64 + 35 * 32;

inline uint32_t hist_index(uint64_t micros)
{
  if (micros < kLinearLimit) {
    return static_cast<uint32_t>(micros);
  }
  const int e = static_cast<int>(std::bit_width(micros)) - 6;
  const uint64_t idx = 64 + static_cast<uint64_t>(e - 1) * 32 + (micros >> e) - 32;
  return idx >= kHistBuckets ? kHistBuckets - 1 : static_cast<uint32_t>(idx);
}

inline uint64_t hist_midpoint(uint32_t idx)
{
  if (idx < kLinearLimit) {
    return idx;
  }
  const uint32_t k = idx - 64;
  const uint32_t e = k / 32 + 1;
  const uint64_t m = k % 32 + 32;
  return (m << e) + (1ULL << (e - 1));
}

}  // namespace perfw
