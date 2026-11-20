// Verification by listing + bitset (spec section 5.4). Independent of kvrgw and gRPC so
// it can be tested against an in-memory fake lister.
#pragma once

#include "keys.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace perfw {

struct ListPage {
  std::vector<std::string> keys;
  bool truncated = false;
  std::string next_token;
};

class Lister {
 public:
  virtual ~Lister() = default;
  // Returns an error description, empty on success.
  virtual std::string list(const std::string &prefix, uint32_t max_keys,
                           const std::string &token, ListPage *out) = 0;
};

class AtomicBitset {
 public:
  explicit AtomicBitset(uint64_t nbits = 0) { resize(nbits); }
  void resize(uint64_t nbits);
  uint64_t size() const { return nbits_; }
  // Returns the previous value of the bit (thread safe).
  bool test_and_set(uint64_t i);
  bool test(uint64_t i) const;

 private:
  uint64_t nbits_ = 0;
  mutable std::vector<uint64_t> words_;
};

struct Failures {
  std::atomic<uint64_t> keys_checked{0}, bad_key{0}, out_of_range{0}, unexpected{0},
      duplicate{0}, other{0};
  void sample(const std::string &s);
  std::vector<std::string> samples() const;
  static constexpr size_t kMaxSamples = 20;

 private:
  mutable std::mutex mu_;
  std::vector<std::string> samples_;
};

struct BucketResult {
  std::string bucket;
  uint64_t expected = 0, found = 0, missing = 0;
  std::vector<std::string> missing_keys;  // capped
};
inline constexpr size_t kMaxMissingKeys = 100;

// Scan all prefixes of one bucket with `threads` threads (dynamic balancing), invoking
// on_key(key) for every listed key. List errors are recorded in `f`.
void scan_prefixes(Lister &lister, const std::string &bucket,
                   const std::vector<std::string> &prefixes, int threads, Failures &f,
                   const std::function<void(const std::string &)> &on_key);

struct LoadSpace {
  uint64_t start = 0;  // first id of the bucket
  uint64_t count = 0;
  int padding = 0;
  std::function<bool(uint64_t)> expected_present;  // null => all present
  // Also tolerate (ignore) well-formed run-put-object keys left by earlier runs.
  bool ignore_put_keys = true;
};

BucketResult verify_bucket_load(Lister &lister, const std::string &bucket, const LoadSpace &sp,
                                const std::vector<std::string> &prefixes, int threads,
                                Failures &f);

struct PutSpace {
  uint64_t bucket_index = 0, num_buckets = 0;
  uint64_t ts = 0;  // this run's run_start_unix_s
  int padding = 0;
  const std::vector<uint64_t> *thread_counts = nullptr;  // indexed by gtid
};

BucketResult verify_bucket_put(Lister &lister, const std::string &bucket, const PutSpace &sp,
                               const std::vector<std::string> &prefixes, int threads,
                               Failures &f);

// Versioned-overwrite expected count for window position p given total successful puts and
// window size.
inline uint64_t expected_versions(uint64_t puts, uint64_t window, uint64_t p)
{
  if (window == 0) return 0;
  return puts / window + (p < puts % window ? 1 : 0);
}

}  // namespace perfw
