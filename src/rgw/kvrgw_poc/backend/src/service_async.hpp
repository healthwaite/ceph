// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * Service-side pieces of the async API: configuration, the backend worker
 * executors, admission (the in-flight op limit), per-op latency recording
 * without thread-locals, and retry_txn (FDB retries through on_error).
 */

#pragma once

#include "async/executor.hpp"
#include "async/frame_pool.hpp"
#include "async/task.hpp"
#include "error_codes.hpp"
#include "fdb_latency.hpp"
#include "kv_store.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>
#include <vector>

namespace kvrgw {

// Backend runtime knobs (environment variables; the perf controller exports
// them from its `kvrgw` section).
struct AsyncConfig {
  int backend_workers{4};            // KVRGW_BACKEND_WORKERS (was KVRGW_BATCH_THREADS)
  int64_t max_inflight_ops{4096};    // KVRGW_MAX_INFLIGHT_OPS
  int txn_max_attempts{3};           // KVRGW_TXN_MAX_ATTEMPTS
  int batch_txn_max_attempts{10};    // KVRGW_BATCH_TXN_MAX_ATTEMPTS
  int64_t txn_timeout_ms{0};         // KVRGW_TXN_TIMEOUT_MS (0 = off)

  static AsyncConfig from_env();
};

// Backend worker executors, each on its own thread. Ops are pinned to one
// worker from switch_to() until completion; no work stealing.
class BackendWorkers {
 public:
  BackendWorkers() = default;
  ~BackendWorkers() { stop(); }
  BackendWorkers(const BackendWorkers&) = delete;
  BackendWorkers& operator=(const BackendWorkers&) = delete;

  void start(int n);
  void stop();
  int size() const noexcept { return static_cast<int>(ex_.size()); }
  async::Executor& at(int i) noexcept { return ex_[static_cast<size_t>(i)]->executor(); }
  // Round-robin choice for a new op.
  async::Executor& next() noexcept {
    const uint32_t i = rr_.fetch_add(1, std::memory_order_relaxed);
    return at(static_cast<int>(i % static_cast<uint32_t>(ex_.size())));
  }
  // Index of the worker the calling thread runs, or -1.
  int current_index() const noexcept;

 private:
  std::vector<std::unique_ptr<async::ExecutorThread>> ex_;
  std::atomic<uint32_t> rr_{0};
};

struct AsyncStats {
  std::atomic<uint64_t> queue_full_rejects{0};
  std::atomic<int64_t> inflight_ops{0};
  std::atomic<int64_t> inflight_ops_peak{0};
};

// Who is calling an _a op: a coroutine caller (may be refused with
// QUEUE_FULL) or a sync wrapper (counted, never refused).
enum class Caller : uint8_t { kAsync, kSync };

// A single process-wide in-flight counter. One op counts once, whatever it
// does inside (a batched PUT, a 1,000-key delete_multi).
class Admission {
 public:
  class Guard {
   public:
    Guard() = default;
    explicit Guard(Admission* a) noexcept : a_(a) {}
    Guard(Guard&& o) noexcept : a_(std::exchange(o.a_, nullptr)) {}
    Guard& operator=(Guard&& o) noexcept {
      if (this != &o) {
        release();
        a_ = std::exchange(o.a_, nullptr);
      }
      return *this;
    }
    ~Guard() { release(); }
    explicit operator bool() const noexcept { return a_ != nullptr; }

   private:
    void release() noexcept {
      if (a_) {
        a_->stats_.inflight_ops.fetch_sub(1, std::memory_order_acq_rel);
        a_ = nullptr;
      }
    }
    Admission* a_{nullptr};
  };

  explicit Admission(AsyncStats& stats) : stats_(stats) {}
  void set_max(int64_t m) noexcept { max_ = m > 0 ? m : 1; }
  int64_t max() const noexcept { return max_; }
  void set_stopping() noexcept { stopping_.store(true, std::memory_order_release); }
  bool stopping() const noexcept { return stopping_.load(std::memory_order_acquire); }
  int64_t inflight() const noexcept { return stats_.inflight_ops.load(std::memory_order_acquire); }

  // KVRGW_ERR_OK and a live guard, KVRGW_ERR_QUEUE_FULL, or KVRGW_ERR_INTERNAL
  // when shutting down.
  KvrgwErrorCode admit(Caller caller, Guard* out) noexcept {
    if (stopping()) return KVRGW_ERR_INTERNAL;
    const int64_t prev = stats_.inflight_ops.fetch_add(1, std::memory_order_acq_rel);
    if (prev >= max_ && caller == Caller::kAsync) {
      stats_.inflight_ops.fetch_sub(1, std::memory_order_acq_rel);
      stats_.queue_full_rejects.fetch_add(1, std::memory_order_relaxed);
      return KVRGW_ERR_QUEUE_FULL;
    }
    int64_t peak = stats_.inflight_ops_peak.load(std::memory_order_relaxed);
    while (prev + 1 > peak &&
           !stats_.inflight_ops_peak.compare_exchange_weak(peak, prev + 1,
                                                           std::memory_order_relaxed)) {
    }
    *out = Guard(this);
    return KVRGW_ERR_OK;
  }

 private:
  AsyncStats& stats_;
  int64_t max_{4096};
  std::atomic<bool> stopping_{false};
};

// Per-op latency for async ops: lives in the op's frame and records once when
// destroyed (the coroutine's locals are destroyed when its body ends). Unlike
// ScopedRequestLatency it does not set the thread-local, which would be wrong
// with many ops interleaved on one worker.
class AsyncRequestLatency {
 public:
  AsyncRequestLatency(LatencyStats& stats, OpType op) noexcept
      : stats_(&stats), op_(op), start_(std::chrono::steady_clock::now()) {}
  AsyncRequestLatency(const AsyncRequestLatency&) = delete;
  AsyncRequestLatency& operator=(const AsyncRequestLatency&) = delete;
  ~AsyncRequestLatency() {
    if (!stats_) return;
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - start_).count();
    stats_->record(op_, us, req_);
  }
  RequestLatency& req() noexcept { return req_; }

 private:
  LatencyStats* stats_;
  OpType op_;
  RequestLatency req_{};
  std::chrono::steady_clock::time_point start_;
};

// ---------------------------------------------------------------------------
// retry_txn
// ---------------------------------------------------------------------------

// What a transaction body reports to retry_txn.
template <class R>
struct OpOutcome {
  fdb_error_t fdb_error{0};          // a read failed: go through on_error
  bool done_without_commit{false};   // read-only success or an app-level error
  R val{};

  R& value() noexcept { return val; }

  // Commit, then (on success) return v.
  static OpOutcome commit(R v) { return OpOutcome{0, false, std::move(v)}; }
  // Return v without committing.
  static OpOutcome done(R v) { return OpOutcome{0, true, std::move(v)}; }
  // A read returned an FDB error: on_error decides whether to retry.
  static OpOutcome fdb(fdb_error_t e) { return OpOutcome{e, false, R{}}; }
};

struct RetryPolicy {
  int max_attempts{3};
  // Stop retrying commit_unknown_result (1021). Off by default: today's code
  // retries it.
  bool no_retry_unknown{false};
  int64_t timeout_ms{0};            // FDB_TR_OPTION_TIMEOUT, 0 = off
  LatencyStats* stats{nullptr};     // txn_retries / txn_hard_failures / txn_max_retries_exceeded
  bool disable_ryw{false};          // set READ_YOUR_WRITES_DISABLE on each attempt
};

// Runs body(tr) in one transaction, committing unless the body says not to,
// and retrying through fdb_transaction_on_error: FDB applies its own backoff
// (about 10 ms doubling to about 1 s), and no thread sleeps.
//
// Body: (KvTransaction&) -> async::Task<OpOutcome<R>>. Called once per
// attempt; the transaction has been reset by on_error between attempts.
//
// Errors: a non-retryable FDB error -> fdb_to_error(err); attempts exhausted on
// a retryable error -> KVRGW_ERR_MAX_RETRIES_EXCEEDED (as today's loops).
template <class R, class Body>
async::Task<std::expected<R, KvrgwErrorCode>> retry_txn(KvStore& store, RetryPolicy pol,
                                                        Body body) {
  auto tr = store.begin_transaction();
  if (!tr) co_return std::unexpected(fdb_to_error(tr.error()));
  KvTransaction& t = **tr;
  if (pol.timeout_ms > 0) (void)t.set_timeout_ms(pol.timeout_ms);
  for (int attempt = 1;; ++attempt) {
    if (pol.disable_ryw) (void)t.disable_ryw();  // best effort, as today
    OpOutcome<R> out = co_await body(t);
    fdb_error_t err = out.fdb_error;
    if (!err && out.done_without_commit) co_return std::move(out.val);
    if (!err) err = co_await t.commit_a();
    if (!err) {
      store.txn_stats().commits.fetch_add(1, std::memory_order_relaxed);
      co_return std::move(out.val);
    }
    const bool retryable = is_retriable(fdb_to_error(err)) ||
                           fdb_error_predicate(FDB_ERROR_PREDICATE_RETRYABLE, err);
    if (!retryable || (pol.no_retry_unknown && err == fdb::kCommitUnknownResult)) {
      if (pol.stats) pol.stats->txn_hard_failures.fetch_add(1, std::memory_order_relaxed);
      co_return std::unexpected(fdb_to_error(err));
    }
    if (attempt >= pol.max_attempts) {
      if (pol.stats) pol.stats->txn_max_retries_exceeded.fetch_add(1, std::memory_order_relaxed);
      co_return std::unexpected(KVRGW_ERR_MAX_RETRIES_EXCEEDED);
    }
    if (fdb_error_t fin = co_await t.on_error_a(err)) {
      if (pol.stats) pol.stats->txn_hard_failures.fetch_add(1, std::memory_order_relaxed);
      co_return std::unexpected(fdb_to_error(fin));
    }
    // on_error reset the transaction and FDB applied its backoff.
    if (pol.stats) pol.stats->txn_retries.fetch_add(1, std::memory_order_relaxed);
  }
}

}  // namespace kvrgw
