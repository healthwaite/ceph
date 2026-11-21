// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab

#include "async/executor.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define KVRGW_CPU_RELAX() _mm_pause()
#else
#define KVRGW_CPU_RELAX() ((void)0)
#endif

namespace kvrgw::async {

namespace {
thread_local Executor* tl_current = nullptr;

[[noreturn]] void die(const char* what) {
  std::perror(what);
  std::abort();
}
}  // namespace

void set_thread_name(std::string_view name) noexcept {
  char buf[16];
  const size_t n = std::min(name.size(), sizeof(buf) - 1);
  std::memcpy(buf, name.data(), n);
  buf[n] = '\0';
  (void)pthread_setname_np(pthread_self(), buf);
}

Executor* Executor::current() noexcept { return tl_current; }

Executor::Executor(std::string name) : name_(std::move(name)) {
  efd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (efd_ < 0) die("eventfd");
  tfd_ = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (tfd_ < 0) die("timerfd_create");
  epfd_ = ::epoll_create1(EPOLL_CLOEXEC);
  if (epfd_ < 0) die("epoll_create1");
  epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = efd_;
  if (::epoll_ctl(epfd_, EPOLL_CTL_ADD, efd_, &ev) < 0) die("epoll_ctl efd");
  ev.data.fd = tfd_;
  if (::epoll_ctl(epfd_, EPOLL_CTL_ADD, tfd_, &ev) < 0) die("epoll_ctl tfd");
}

Executor::~Executor() {
  if (epfd_ >= 0) ::close(epfd_);
  if (tfd_ >= 0) ::close(tfd_);
  if (efd_ >= 0) ::close(efd_);
}

void Executor::wake() noexcept {
  wakeup_writes_.fetch_add(1, std::memory_order_relaxed);
  uint64_t one = 1;
  [[maybe_unused]] ssize_t r = ::write(efd_, &one, sizeof(one));
}

void Executor::post(MpscNode* n) noexcept {
  // Count first, then link: a consumer that sees count == 0 may sleep, and the
  // producer that takes count from 0 to 1 is the one that wakes it.
  const bool was_empty = count_.fetch_add(1, std::memory_order_acq_rel) == 0;
  q_.push(n);
  if (was_empty) wake();
}

void Executor::stop() noexcept {
  stop_.store(true, std::memory_order_release);
  wake();
}

void Executor::run_node(MpscNode* n) noexcept {
  // Read everything we need before running: the node may live in the frame we
  // are about to resume, which can be destroyed during the resume.
  if (auto fn = n->fn) {
    fn(n);
  } else {
    std::coroutine_handle<> h = n->h;
    h.resume();
  }
}

int Executor::drain(int max) noexcept {
  int ran = 0;
  int spins = 0;
  while (ran < max) {
    MpscNode* n = q_.pop();
    if (n == nullptr) {
      // count_ > 0 with nothing to pop: a producer is between fetch_add and
      // its link. It is a handful of instructions; spin briefly.
      if (count_.load(std::memory_order_acquire) <= 0) break;
      if (++spins < 64) {
        KVRGW_CPU_RELAX();
      } else {
        std::this_thread::yield();
        spins = 0;
      }
      continue;
    }
    spins = 0;
    count_.fetch_sub(1, std::memory_order_acq_rel);
    // Single writer: a plain load/store, no read-modify-write.
    items_run_.store(items_run_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
    run_node(n);
    ++ran;
  }
  return ran;
}

void Executor::arm_timerfd() noexcept {
  if (timers_.empty()) return;
  const auto tp = timers_.front().tp;
  if (armed_ && armed_tp_ == tp) return;
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      tp.time_since_epoch()).count();
  itimerspec its{};
  // steady_clock is CLOCK_MONOTONIC on Linux. A value of 0 would disarm.
  its.it_value.tv_sec = ns > 0 ? ns / 1000000000 : 0;
  its.it_value.tv_nsec = ns > 0 ? ns % 1000000000 : 1;
  if (::timerfd_settime(tfd_, TFD_TIMER_ABSTIME, &its, nullptr) < 0) die("timerfd_settime");
  armed_ = true;
  armed_tp_ = tp;
}

void Executor::post_at(std::chrono::steady_clock::time_point tp, MpscNode* n) {
  timers_.push_back(Timer{tp, timer_seq_++, n});
  std::push_heap(timers_.begin(), timers_.end(), TimerLater{});
  arm_timerfd();
}

void Executor::fire_timers() noexcept {
  if (timers_.empty()) return;
  const auto now = std::chrono::steady_clock::now();
  while (!timers_.empty() && timers_.front().tp <= now) {
    std::pop_heap(timers_.begin(), timers_.end(), TimerLater{});
    MpscNode* n = timers_.back().node;
    timers_.pop_back();
    run_node(n);
  }
  armed_ = false;
  arm_timerfd();
}

void Executor::run() {
  Executor* prev = tl_current;
  tl_current = this;
  epoll_event evs[2];
  while (!stop_.load(std::memory_order_acquire)) {
    const int ran = drain(256);
    fire_timers();
    if (ran == 256 || count_.load(std::memory_order_acquire) > 0) continue;
    if (stop_.load(std::memory_order_acquire)) break;
    if (!timers_.empty() && timers_.front().tp <= std::chrono::steady_clock::now()) continue;
    const int n = ::epoll_wait(epfd_, evs, 2, -1);
    if (n < 0) {
      if (errno == EINTR) continue;
      die("epoll_wait");
    }
    for (int i = 0; i < n; ++i) {
      uint64_t v;
      [[maybe_unused]] ssize_t r = ::read(evs[i].data.fd, &v, sizeof(v));
      if (evs[i].data.fd == tfd_) armed_ = false;
    }
  }
  tl_current = prev;
}

void ExecutorThread::start() {
  t_ = std::thread([this] {
    if (!ex_.name().empty()) set_thread_name(ex_.name());
    ex_.run();
  });
}

void ExecutorThread::stop_and_join() {
  if (t_.joinable()) {
    ex_.stop();
    t_.join();
  }
}

}  // namespace kvrgw::async
