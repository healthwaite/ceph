// Per-thread windowed statistics (spec section 7). Pure C++ (no proto) so it is unit-testable.
#pragma once

#include "histogram.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace perfw {

enum class Metric : int {
  PutObject,
  ListObjects,
  DeleteMulti,
  ListDeleteMulti,  // one list + delete_multi iteration (run-list-delete-multi)
  KeysListed,   // counter-style
  KeysDeleted,  // counter-style
  kCount
};
inline constexpr int kMetricCount = static_cast<int>(Metric::kCount);
const char *metric_name(Metric m);
inline bool metric_is_counter(Metric m) { return m == Metric::KeysListed || m == Metric::KeysDeleted; }

struct MetricStats {
  uint64_t count = 0;   // successes (or units for counter metrics)
  uint64_t errors = 0;
  uint64_t sum_micros = 0;
  std::map<std::string, uint64_t> error_codes;  // by code name; sums to `errors`
  std::vector<uint64_t> hist;  // empty or kHistBuckets

  void record(uint64_t micros);
  void merge(const MetricStats &o);
  bool empty() const { return count == 0 && errors == 0; }
};

using StatsArray = std::array<MetricStats, kMetricCount>;

// One per benchmark thread. The owning thread records; the reporter calls take_window().
class ThreadStats {
 public:
  void record(Metric m, uint64_t micros);
  void record_error(Metric m, const std::string &code = {});
  void add_units(Metric m, uint64_t n);
  // Swap out the current window.
  StatsArray take_window();

 private:
  std::mutex mu_;
  StatsArray w_;
};

// Process-wide table of error code name -> human-readable text (for reports).
void register_error_text(const std::string &code, const std::string &text);
std::map<std::string, std::string> error_texts();

class StatsHub {
 public:
  explicit StatsHub(int threads);
  ThreadStats &thread(int i) { return *threads_[static_cast<size_t>(i)]; }
  // Collect all threads' windows (merged) and add them to the cumulative totals.
  StatsArray collect_window();
  const StatsArray &cumulative() const { return cum_; }

 private:
  std::vector<std::unique_ptr<ThreadStats>> threads_;
  StatsArray cum_;
};

}  // namespace perfw
