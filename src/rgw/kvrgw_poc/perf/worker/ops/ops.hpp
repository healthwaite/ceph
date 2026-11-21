// Operation interface and shared run context for the perf worker.
#pragma once

#include "../config.hpp"
#include "../keys.hpp"
#include "../stats.hpp"
#include "../verify.hpp"

#include "async/executor.hpp"
#include "async/task.hpp"
#include "service_impl.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <span>
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
  // User metadata attached to every put: storage plus views into it (built once at init).
  std::vector<std::string> meta_keys, meta_vals;
  std::vector<kvrgw::MetaPair> meta_pairs;
  std::vector<std::string> bucket_names;  // index = bucket id
  StatsHub *stats = nullptr;

  // Set at RunBenchmark time.
  SteadyClock::time_point start_tp;
  SteadyClock::time_point deadline;

  // Verify progress, read by the service while verify() runs. verify_keys_total is the number
  // of keys this worker expects to check (0 until known, or if it can't be known up front).
  std::atomic<uint64_t> verify_keys_checked{0};
  std::atomic<uint64_t> verify_keys_total{0};

  std::atomic<bool> cancel{false};
  std::atomic<bool> failed{false};
  std::mutex err_mu;
  std::string error;

  // Streams per worker (S) and in total; see Config::streams().
  int streams() const { return cfg.streams(); }
  int total_streams() const { return cfg.total_streams(); }
  // Global stream id of local stream `sid`.
  uint64_t gsid(int sid) const
  {
    return static_cast<uint64_t>(worker_index) * static_cast<uint64_t>(streams()) +
           static_cast<uint64_t>(sid);
  }

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
  // Number of ops stream `gsid` may perform in --ops mode.
  uint64_t ops_quota(uint64_t gsid) const
  {
    return block_range(gsid, static_cast<uint64_t>(total_streams()), cfg.ops).count;
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

// A stream: a sequential client with at most one op in flight. In sync mode a
// stream is a thread; in async mode it is a coroutine on one driver executor.
struct Stream {
  int sid = 0;        // local stream id, [0, S)
  uint64_t gsid = 0;  // worker_index * S + sid
  int driver = 0;     // driver thread index (async mode)
  ThreadStats *ts = nullptr;
  kvrgw::async::Executor *exec = nullptr;  // the stream's driver executor
};

class Operation {
 public:
  virtual ~Operation() = default;
  // Pre-benchmark setup (bucket creation, precondition checks). Returns error or "".
  virtual std::string init(RunContext &) { return {}; }
  // Sync mode: benchmark body for local stream `sid`, on its own thread.
  virtual void run_thread(RunContext &ctx, int sid) = 0;
  // Async mode: the same loop as a coroutine on the stream's driver executor,
  // calling the _a ops.
  virtual kvrgw::async::Task<void> run_stream(RunContext &ctx, Stream &s)
  {
    (void)s;
    ctx.fail("driver_mode async is not supported for " + ctx.cfg.operation);
    co_return;
  }
  // Per-local-stream counters reported in RunSummary (indexed by sid).
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

// VersionPager backed by KvRgwServiceImpl::list_object_versions.
class ServiceVersionPager : public VersionPager {
 public:
  ServiceVersionPager(kvrgw::KvRgwServiceImpl &svc, kvrgw::tenant_id_t tenant, std::string bucket)
      : svc_(svc), tenant_(tenant), bucket_(std::move(bucket)) {}
  std::string page(const std::string &prefix, uint32_t max_keys, const std::string &key_marker,
                   const std::string &version_marker, VersionPage *out) override;

 private:
  kvrgw::KvRgwServiceImpl &svc_;
  kvrgw::tenant_id_t tenant_;
  std::string bucket_;
};

// put_object with up to 10 attempts on the same key. Successful attempt is timed and recorded;
// each failure counts as an error. On exhaustion fails the context and returns false.
// If `created_version` is non-null it is set to whether the successful put created a new
// version (the runtime reports a version id only for a put into a versioning-enabled bucket;
// a put that replaced the current object in place reports none).
bool put_with_retry(RunContext &ctx, ThreadStats &ts, const std::string &bucket,
                    const std::string &key, bool *created_version = nullptr);

// Async put_with_retry: same attempts, error recording and log rate limit.
// KVRGW_ERR_QUEUE_FULL is not an attempt: the stream sleeps on its executor
// (100 us x 2^n, capped at 10 ms) and counts it as queue_full on the metric.
// Latency runs from just before the co_await to the stream's resume.
// `bucket` and `key` must outlive the call (the caller's frame holds them).
kvrgw::async::Task<bool> put_with_retry_a(RunContext &ctx, Stream &s, const std::string &bucket,
                                          const std::string &key,
                                          bool *created_version = nullptr);

// Back off after a QUEUE_FULL: 100 us x 2^n, capped at 10 ms.
std::chrono::microseconds queue_full_backoff(int n);

// Verify every bucket in `buckets` (load-style) using ctx.cfg.verify_threads.
// `range_of_bucket(b)` -> id space; `present` may be null. With `scan_versions` the keys are
// listed through list_object_versions and any version history (a version id other than the null
// version, a delete marker, or a key with more than one version) is also a failure.
std::string verify_load_family(RunContext &ctx, const std::vector<uint64_t> &buckets,
                               const std::function<Range(uint64_t)> &range_of_bucket,
                               const std::function<bool(uint64_t bucket, uint64_t id)> &present,
                               VerifyReport *out, bool scan_versions = false);

// What check_buckets requires of each bucket's versioning state.
enum class VersioningCheck {
  kAny,         // only that the bucket exists
  kEnabled,     // versioning must be enabled
  kUnversioned  // versioning must be DISABLED (never enabled; suspended means it once was)
};

// Check that all buckets exist and satisfy `versioning`.
std::string check_buckets(RunContext &ctx, const std::vector<uint64_t> &buckets,
                          VersioningCheck versioning = VersioningCheck::kAny);

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
