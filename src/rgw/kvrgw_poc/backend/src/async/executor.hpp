// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * Executor: one per thread that runs coroutines (backend workers, perf driver
 * threads). An intrusive Vyukov MPSC run queue, an eventfd for cross-thread
 * wake-ups, a timerfd-backed timer heap, and an epoll loop.
 *
 * post() never allocates: the queue node is embedded in whatever awaits (an
 * awaiter in a coroutine frame, a promise, a batch entry). The eventfd is
 * written only on an empty-to-non-empty transition of the queue.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace kvrgw::async {

// Names the calling thread (shown by top -H, ps -L, gdb). Linux keeps the
// first 15 bytes.
void set_thread_name(std::string_view name) noexcept;

// CPU and wall time of one thread since it started; utilisation over an
// interval is delta(cpu_ns) / delta(wall_ns).
struct ThreadCpu {
  uint64_t cpu_ns{0};
  uint64_t wall_ns{0};
};
// CPU time consumed so far by a live thread (0 if it cannot be read).
uint64_t thread_cpu_ns(std::thread::native_handle_type t) noexcept;

// Intrusive queue node. When `fn` is set the executor calls fn(node) instead of
// resuming `h` (used for small non-coroutine tasks such as "arm a timer").
struct MpscNode {
  std::atomic<MpscNode*> next{nullptr};
  void (*fn)(MpscNode*){nullptr};
  std::coroutine_handle<> h{};
};

// Vyukov's intrusive multi-producer / single-consumer queue.
class MpscQueue {
 public:
  MpscQueue() noexcept : head_(&stub_), tail_(&stub_) {}
  MpscQueue(const MpscQueue&) = delete;
  MpscQueue& operator=(const MpscQueue&) = delete;

  void push(MpscNode* n) noexcept {
    n->next.store(nullptr, std::memory_order_relaxed);
    MpscNode* prev = head_.exchange(n, std::memory_order_acq_rel);
    prev->next.store(n, std::memory_order_release);
  }

  // Consumer only. Returns nullptr when empty or when a producer is between its
  // exchange and its link (the caller retries later).
  MpscNode* pop() noexcept {
    MpscNode* tail = tail_;
    MpscNode* next = tail->next.load(std::memory_order_acquire);
    if (tail == &stub_) {
      if (next == nullptr) return nullptr;
      tail_ = next;
      tail = next;
      next = next->next.load(std::memory_order_acquire);
    }
    if (next) {
      tail_ = next;
      return tail;
    }
    MpscNode* head = head_.load(std::memory_order_acquire);
    if (tail != head) return nullptr;
    push(&stub_);
    next = tail->next.load(std::memory_order_acquire);
    if (next) {
      tail_ = next;
      return tail;
    }
    return nullptr;
  }

 private:
  alignas(64) std::atomic<MpscNode*> head_;
  alignas(64) MpscNode* tail_;
  MpscNode stub_;
};

class Executor {
 public:
  explicit Executor(std::string name = {});
  ~Executor();
  Executor(const Executor&) = delete;
  Executor& operator=(const Executor&) = delete;

  // Any thread. Push + eventfd write if the queue was empty.
  void post(MpscNode* n) noexcept;

  // Own thread only: timer heap + timerfd.
  void post_at(std::chrono::steady_clock::time_point tp, MpscNode* n);
  void post_after(std::chrono::nanoseconds d, MpscNode* n) {
    post_at(std::chrono::steady_clock::now() + d, n);
  }

  // Runs until stop(). Sets Executor::current() for the calling thread.
  void run();
  void stop() noexcept;
  bool stopping() const noexcept { return stop_.load(std::memory_order_acquire); }

  static Executor* current() noexcept;
  bool is_current() const noexcept { return current() == this; }
  const std::string& name() const noexcept { return name_; }

  // Awaitables. sleep/sleep_until must be awaited on this executor's thread.
  struct SleepAwaiter {
    Executor* ex;
    std::chrono::steady_clock::time_point tp;
    MpscNode node{};
    bool await_ready() const noexcept { return tp <= std::chrono::steady_clock::now(); }
    void await_suspend(std::coroutine_handle<> h) {
      node.h = h;
      ex->post_at(tp, &node);
    }
    void await_resume() const noexcept {}
  };
  SleepAwaiter sleep(std::chrono::nanoseconds d) {
    return SleepAwaiter{this, std::chrono::steady_clock::now() + d};
  }
  SleepAwaiter sleep_until(std::chrono::steady_clock::time_point tp) {
    return SleepAwaiter{this, tp};
  }

  // Counters (for tests and stats).
  uint64_t wakeup_writes() const noexcept { return wakeup_writes_.load(std::memory_order_relaxed); }
  uint64_t items_run() const noexcept { return items_run_.load(std::memory_order_relaxed); }

 private:
  struct Timer {
    std::chrono::steady_clock::time_point tp;
    uint64_t seq;
    MpscNode* node;
  };
  struct TimerLater {
    bool operator()(const Timer& a, const Timer& b) const noexcept {
      return a.tp != b.tp ? a.tp > b.tp : a.seq > b.seq;
    }
  };

  static void run_node(MpscNode* n) noexcept;
  int drain(int max) noexcept;
  void fire_timers() noexcept;
  void arm_timerfd() noexcept;
  void wake() noexcept;

  std::string name_;
  MpscQueue q_;
  alignas(64) std::atomic<int64_t> count_{0};
  std::atomic<bool> stop_{false};
  int efd_{-1};
  int tfd_{-1};
  int epfd_{-1};
  std::vector<Timer> timers_;  // min-heap, own thread only
  uint64_t timer_seq_{0};
  std::chrono::steady_clock::time_point armed_tp_{};
  bool armed_{false};
  std::atomic<uint64_t> wakeup_writes_{0};
  std::atomic<uint64_t> items_run_{0};
};

// An executor on its own thread.
class ExecutorThread {
 public:
  explicit ExecutorThread(std::string name = {}) : ex_(std::move(name)) {}
  ~ExecutorThread() { stop_and_join(); }
  void start();
  void stop_and_join();
  Executor& executor() noexcept { return ex_; }
  const std::string& name() const noexcept { return ex_.name(); }
  // Zero before start() / after stop_and_join().
  ThreadCpu cpu_usage() noexcept;

 private:
  Executor ex_;
  std::thread t_;
  std::chrono::steady_clock::time_point started_{};
};

// co_await switch_to(ex): suspend, post to ex, resume there. No-op if already on ex.
struct SwitchToAwaiter {
  Executor* target;
  MpscNode node{};
  bool await_ready() const noexcept { return Executor::current() == target; }
  void await_suspend(std::coroutine_handle<> h) noexcept {
    node.h = h;
    target->post(&node);
  }
  void await_resume() const noexcept {}
};
inline SwitchToAwaiter switch_to(Executor& ex) noexcept { return SwitchToAwaiter{&ex}; }

}  // namespace kvrgw::async
