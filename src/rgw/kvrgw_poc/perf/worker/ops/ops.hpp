// Operation interface and shared run context for the perf worker.
#pragma once

#include "../config.hpp"
#include "../keys.hpp"
#include "../stats.hpp"
#include "../verify.hpp"

#include "service_impl.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace perfw {

using SteadyClock = std::chrono::steady_clock;

struct RunContext {
  Config cfg;
  int worker_index = 0;
  int worker_count = 1;
  int64_t run_start_unix_s = 0;
  // Second in which the synchronised benchmark start falls (from RunControl). Writes made by
  // this run have last_modified >= this, and (unlike run_start_unix_s) it is always later than
  // anything a previous invocation wrote.
  int64_t bench_start_unix_s = 0;
  kvrgw::KvRgwServiceImpl *svc = nullptr;
  kvrgw::tenant_id_t tenant = 0;
  std::string payload;
  std::vector<std::string> bucket_names;  // index = bucket id
  StatsHub *stats = nullptr;

  // Set at RunBenchmark time.
  SteadyClock::time_point start_tp;
  SteadyClock::time_point deadline;

  std::atomic<bool> cancel{false};
  std::atomic<bool> failed{false};
  std::mutex err_mu;
  std::string error;

  int total_threads() const { return cfg.total_threads(); }

  void fail(const std::string &msg)
  {
    {
      std::lock_guard<std::mutex> g(err_mu);
      if (error.empty()) error = msg;
    }
    failed = true;
    cancel = true;
  }
  bool stopped() const { return cancel.load(std::memory_order_relaxed); }
  bool expired() const { return cfg.has_duration() && SteadyClock::now() >= deadline; }
  // Wait until the synchronised start; false if cancelled meanwhile.
  bool wait_start() const;

  const std::string &bucket(uint64_t b) const { return bucket_names[b]; }
  // Number of ops thread `gtid` may perform in --ops mode.
  uint64_t ops_quota(uint64_t gtid) const
  {
    return block_range(gtid, static_cast<uint64_t>(total_threads()), cfg.ops).count;
  }
};

struct VerifyReport {
  std::vector<BucketResult> buckets;
  uint64_t keys_checked = 0, bad_key = 0, out_of_range = 0, unexpected = 0, duplicate = 0,
           other_failures = 0;
  std::vector<std::string> samples;
  void take(Failures &f)
  {
    keys_checked = f.keys_checked;
    bad_key = f.bad_key;
    out_of_range = f.out_of_range;
    unexpected = f.unexpected;
    duplicate = f.duplicate;
    other_failures = f.other;
    samples = f.samples();
  }
};

class Operation {
 public:
  virtual ~Operation() = default;
  // Pre-benchmark setup (bucket creation, precondition checks). Returns error or "".
  virtual std::string init(RunContext &) { return {}; }
  // Benchmark body for local thread `tid`.
  virtual void run_thread(RunContext &ctx, int tid) = 0;
  // Per-local-thread counters reported in RunSummary.
  virtual std::vector<uint64_t> thread_counts() const { return {}; }
  virtual bool has_verify() const { return true; }
  // thread_counts: indexed by global thread id (put_count / delete_progress), may be empty.
  virtual std::string verify(RunContext &ctx, const std::vector<uint64_t> &thread_counts,
                             VerifyReport *out) = 0;
};

std::unique_ptr<Operation> make_operation(const std::string &name);

// ---- shared helpers (ops/common.cpp) ----

// Lister backed by KvRgwServiceImpl::list_objects.
class ServiceLister : public Lister {
 public:
  ServiceLister(kvrgw::KvRgwServiceImpl &svc, kvrgw::tenant_id_t tenant, std::string bucket)
      : svc_(svc), tenant_(tenant), bucket_(std::move(bucket)) {}
  std::string list(const std::string &prefix, uint32_t max_keys, const std::string &token,
                   ListPage *out) override;

 private:
  kvrgw::KvRgwServiceImpl &svc_;
  kvrgw::tenant_id_t tenant_;
  std::string bucket_;
};

// put_object with up to 10 attempts on the same key. Successful attempt is timed and recorded;
// each failure counts as an error. On exhaustion fails the context and returns false.
bool put_with_retry(RunContext &ctx, ThreadStats &ts, const std::string &bucket,
                    const std::string &key);

// Verify every bucket in `buckets` (load-style) using ctx.cfg.verify_threads.
// `range_of_bucket(b)` -> id space; `present` may be null.
std::string verify_load_family(RunContext &ctx, const std::vector<uint64_t> &buckets,
                               const std::function<Range(uint64_t)> &range_of_bucket,
                               const std::function<bool(uint64_t bucket, uint64_t id)> &present,
                               VerifyReport *out);

// Check that all buckets exist (and optionally have versioning enabled).
std::string check_buckets(RunContext &ctx, const std::vector<uint64_t> &buckets,
                          bool require_versioning);

// Abbreviated key for messages: head + "..." + tail (the tail holds the key id).
std::string short_key(const std::string &key);
// "KVRGW_ERR_X (readable text)".
std::string describe_error(kvrgw::KvrgwErrorCode ec);
// Count an error against `m` under the library's code name (and register its text).
void record_op_error(ThreadStats &ts, Metric m, kvrgw::KvrgwErrorCode ec);
// Rate-limited (first 20 per process) stderr log line for a failed operation.
void log_op_error(const std::string &what, const std::string &err);

inline int64_t elapsed_us(SteadyClock::time_point t0)
{
  return std::chrono::duration_cast<std::chrono::microseconds>(SteadyClock::now() - t0).count();
}

}  // namespace perfw
