// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
// Unit tests for the coroutine runtime (backend/src/async/). No FDB needed.

#include "async/executor.hpp"
#include "async/frame_pool.hpp"
#include "async/sync_wait.hpp"
#include "async/task.hpp"

#include "async_test_util.hpp"

#include <atomic>
#include <chrono>
#include <latch>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace kvrgw::async;
using namespace std::chrono_literals;

namespace {

// Waits (with a deadline) until pred() holds.
template <class P>
bool wait_until(P pred, std::chrono::milliseconds limit = 10s) {
  const auto end = std::chrono::steady_clock::now() + limit;
  while (!pred()) {
    if (std::chrono::steady_clock::now() > end) return false;
    std::this_thread::sleep_for(100us);
  }
  return true;
}

struct CountingNode {
  MpscNode node;
  std::atomic<int>* runs_total;
  std::atomic<int> runs{0};
  std::thread::id expect_tid;
  std::atomic<int>* wrong_thread;
};

void counting_fn(MpscNode* n) {
  auto* c = reinterpret_cast<CountingNode*>(n);  // node is the first member
  c->runs.fetch_add(1, std::memory_order_relaxed);
  c->runs_total->fetch_add(1, std::memory_order_relaxed);
  if (std::this_thread::get_id() != c->expect_tid) c->wrong_thread->fetch_add(1);
}

}  // namespace

ATEST(executor_posts_from_8_threads_resume_once_on_owner) {
  constexpr int kThreads = 8;
  constexpr int kPerThread = 100000;
  ExecutorThread et("t");
  et.start();
  std::thread::id owner;
  {
    std::latch l(1);
    MpscNode n;
    struct Ctx { std::thread::id* out; std::latch* l; };
    static Ctx* ctxp;
    Ctx ctx{&owner, &l};
    ctxp = &ctx;
    n.fn = [](MpscNode*) { *ctxp->out = std::this_thread::get_id(); ctxp->l->count_down(); };
    et.executor().post(&n);
    l.wait();
  }
  std::atomic<int> total{0}, wrong{0};
  auto nodes = std::make_unique<CountingNode[]>(kThreads * kPerThread);
  for (int i = 0; i < kThreads * kPerThread; ++i) {
    nodes[i].node.fn = counting_fn;
    nodes[i].runs_total = &total;
    nodes[i].expect_tid = owner;
    nodes[i].wrong_thread = &wrong;
  }
  std::vector<std::thread> ps;
  for (int t = 0; t < kThreads; ++t) {
    ps.emplace_back([&, t] {
      for (int i = 0; i < kPerThread; ++i) et.executor().post(&nodes[t * kPerThread + i].node);
    });
  }
  for (auto& p : ps) p.join();
  ACHECK(wait_until([&] { return total.load() == kThreads * kPerThread; }));
  int bad = 0;
  for (int i = 0; i < kThreads * kPerThread; ++i) bad += nodes[i].runs.load() != 1;
  ACHECK_EQ(bad, 0);
  ACHECK_EQ(wrong.load(), 0);
  et.stop_and_join();
}

ATEST(executor_one_wake_per_empty_to_nonempty_transition) {
  ExecutorThread et("w");
  et.start();
  Executor& ex = et.executor();
  // Sequential single posts: each one finds the queue empty -> one write each.
  std::atomic<int> done{0};
  static std::atomic<int>* donep;
  donep = &done;
  MpscNode n;
  n.fn = [](MpscNode*) { donep->fetch_add(1); };
  const uint64_t w0 = ex.wakeup_writes();
  for (int i = 0; i < 100; ++i) {
    ex.post(&n);
    ACHECK(wait_until([&] { return done.load() == i + 1; }));
  }
  ACHECK_EQ(ex.wakeup_writes() - w0, 100u);

  // A burst while the executor is busy: only the first post of the burst writes.
  static std::atomic<bool> release;
  static std::atomic<bool> blocked;
  release = false;
  blocked = false;
  MpscNode blocker;
  blocker.fn = [](MpscNode*) {
    blocked = true;
    while (!release.load()) std::this_thread::yield();
  };
  ex.post(&blocker);
  ACHECK(wait_until([&] { return blocked.load(); }));
  const uint64_t w1 = ex.wakeup_writes();
  std::vector<MpscNode> burst(99);
  done = 0;
  for (auto& b : burst) {
    b.fn = [](MpscNode*) { donep->fetch_add(1); };
    ex.post(&b);
  }
  ACHECK_EQ(ex.wakeup_writes() - w1, 1u);
  release = true;
  ACHECK(wait_until([&] { return done.load() == 99; }));
  et.stop_and_join();
}

namespace {
std::mutex g_order_mu;
std::vector<int> g_order;

Task<void> sleeper(Executor& ex, int ms, std::latch& l) {
  co_await ex.sleep(std::chrono::milliseconds(ms));
  {
    std::lock_guard lk(g_order_mu);
    g_order.push_back(ms);
  }
  l.count_down();
}
}  // namespace

ATEST(timers_fire_in_deadline_order) {
  ExecutorThread et("timers");
  et.start();
  g_order.clear();
  const int delays[] = {50, 10, 40, 20, 30, 5, 45, 15};
  std::latch l(8);
  for (int d : delays) spawn(et.executor(), sleeper(et.executor(), d, l));
  l.wait();
  std::vector<int> sorted(std::begin(delays), std::end(delays));
  std::sort(sorted.begin(), sorted.end());
  ACHECK(g_order == sorted);
  et.stop_and_join();
}

namespace {
Task<int> leaf(int v) { co_return v; }

uintptr_t g_stack_lo, g_stack_hi;
Task<int> leaf_probe(int v) {
  volatile char c = 0;
  const auto a = reinterpret_cast<uintptr_t>(&c);
  if (a < g_stack_lo) g_stack_lo = a;
  if (a > g_stack_hi) g_stack_hi = a;
  co_return v;
}

Task<long> sequential_chain(int n) {
  long sum = 0;
  for (int i = 0; i < n; ++i) sum += co_await leaf_probe(1);
  co_return sum;
}
}  // namespace

ATEST(task_symmetric_transfer_1M_chain_no_stack_growth) {
  g_stack_lo = UINTPTR_MAX;
  g_stack_hi = 0;
  ExecutorThread et("chain");
  et.start();
#if defined(__SANITIZE_THREAD__) || defined(__SANITIZE_ADDRESS__)
  // Sanitizers disable the tail calls that symmetric transfer compiles to, so
  // the stack does grow there; run a shallow chain for the race check only.
  constexpr int kN = 10000;
  constexpr bool kCheckStack = false;
#else
  constexpr int kN = 1000000;
  constexpr bool kCheckStack = true;
#endif
  long r = 0;
  std::latch l(1);
  auto outer = [](int n, long* out, std::latch* l) -> Task<void> {
    *out = co_await sequential_chain(n);
    l->count_down();
  };
  spawn(et.executor(), outer(kN, &r, &l));
  l.wait();
  ACHECK_EQ(r, (long)kN);
  // Every leaf ran at (nearly) the same stack depth.
  if (kCheckStack) ACHECK(g_stack_hi - g_stack_lo < 64 * 1024);
  et.stop_and_join();
}

ATEST(task_cross_executor_resume_posts_to_awaiter_executor) {
  ExecutorThread a("a"), b("b");
  a.start();
  b.start();
  std::thread::id ta, tb, child_tid, resumed_tid;
  std::latch l(1);
  auto child = [](Executor& b, std::thread::id* tid) -> Task<int> {
    co_await switch_to(b);
    *tid = std::this_thread::get_id();
    co_return 7;
  };
  auto parent = [&]() -> Task<void> {
    ta = std::this_thread::get_id();
    const uint64_t before = a.executor().items_run();
    int v = co_await child(b.executor(), &child_tid);
    resumed_tid = std::this_thread::get_id();
    ACHECK_EQ(v, 7);
    ACHECK(a.executor().items_run() > before);  // came back through a's queue
    l.count_down();
  };
  spawn(a.executor(), parent());
  l.wait();
  {
    std::latch l2(1);
    MpscNode n;
    static std::thread::id* tbp;
    static std::latch* l2p;
    tbp = &tb;
    l2p = &l2;
    n.fn = [](MpscNode*) { *tbp = std::this_thread::get_id(); l2p->count_down(); };
    b.executor().post(&n);
    l2.wait();
  }
  ACHECK(child_tid == tb);
  ACHECK(resumed_tid == ta);
  ACHECK(ta != tb);
  a.stop_and_join();
  b.stop_and_join();
}

ATEST(task_exception_rethrows_at_awaiter) {
  auto thrower = []() -> Task<int> {
    throw std::runtime_error("boom");
    co_return 1;
  };
  auto catcher = [&]() -> Task<int> {
    try {
      co_await thrower();
    } catch (const std::runtime_error& e) {
      co_return 42;
    }
    co_return 0;
  };
  ACHECK_EQ(sync_wait(catcher()), 42);
  bool threw = false;
  try {
    sync_wait(thrower());
  } catch (const std::runtime_error&) {
    threw = true;
  }
  ACHECK(threw);
}

ATEST(task_destroy_unstarted_leaks_nothing) {
  auto& c = frame_pool_counters();
  const auto live0 = c.frames_live.load();
  {
    auto t = leaf(5);
    ACHECK_EQ(c.frames_live.load(), live0 + 1);
  }
  ACHECK_EQ(c.frames_live.load(), live0);
}

ATEST(frame_pool_cross_thread_free_returns_to_owner) {
  auto& c = frame_pool_counters();
  const auto live0 = c.frames_live.load();
  const auto x0 = c.cross_thread_frees.load();
  std::vector<Task<int>> made;
  std::thread owner([&] {
    for (int i = 0; i < 100; ++i) made.push_back(leaf(i));
  });
  owner.join();  // owner exited: frees after this go straight to the heap
  ACHECK_EQ(c.frames_live.load(), live0 + 100);
  made.clear();
  ACHECK_EQ(c.frames_live.load(), live0);
  ACHECK(c.cross_thread_frees.load() >= x0 + 100);

  // Owner alive: freed frames come back through its return stack.
  ExecutorThread et("pool");
  et.start();
  std::vector<Task<int>> made2;
  std::latch l(1);
  auto mk = [](std::vector<Task<int>>* v, std::latch* l) -> Task<void> {
    for (int i = 0; i < 100; ++i) v->push_back(leaf(i));
    l->count_down();
    co_return;
  };
  spawn(et.executor(), mk(&made2, &l));
  l.wait();
  made2.clear();  // freed on this thread, owner is et
  std::latch l2(1);
  auto again = [](std::latch* l) -> Task<void> {
    for (int i = 0; i < 100; ++i) (void)co_await leaf(i);  // reclaims
    l->count_down();
  };
  spawn(et.executor(), again(&l2));
  l2.wait();
  et.stop_and_join();
  ACHECK(wait_until([&] { return c.frames_live.load() == live0; }));
}

namespace {
Task<int> big_frame(Executor& ex) {
  char buf[8192];
  for (int i = 0; i < 8192; ++i) buf[i] = static_cast<char>(i);
  co_await switch_to(ex);  // keeps buf alive across a suspension
  int s = 0;
  for (int i = 0; i < 8192; i += 1024) s += buf[i];
  co_return s;
}
}  // namespace

ATEST(frame_pool_oversize_frame_counted) {
  auto& c = frame_pool_counters();
  const auto f0 = c.frames_heap_fallback.load();
  ExecutorThread et("big");
  et.start();
  (void)sync_wait(big_frame(et.executor()));
  ACHECK(c.frames_heap_fallback.load() > f0);
  ACHECK(c.max_frame_size.load() > 4096);
  et.stop_and_join();
}

ATEST(sync_wait_returns_result) {
  ExecutorThread et("sw");
  et.start();
  auto t = [](Executor& ex) -> Task<int> {
    co_await switch_to(ex);
    co_await ex.sleep(1ms);
    co_return 42;
  };
  for (int i = 0; i < 1000; ++i) ACHECK_EQ(sync_wait(t(et.executor())), 42);
  et.stop_and_join();
}

ATEST(sync_wait_on_executor_thread_aborts) {
  const pid_t pid = fork();
  if (pid == 0) {
    // Child: silence and run sync_wait on an executor thread.
    [[maybe_unused]] FILE* f = freopen("/dev/null", "w", stderr);
    Executor ex("x");
    MpscNode n;
    static Executor* exp;
    exp = &ex;
    n.fn = [](MpscNode*) {
      (void)sync_wait([]() -> Task<int> { co_return 1; }());
      exp->stop();
    };
    ex.post(&n);
    ex.run();
    _exit(0);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  ACHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT);
}

int main(int argc, char** argv) { return async_test::run_all(argc, argv); }
