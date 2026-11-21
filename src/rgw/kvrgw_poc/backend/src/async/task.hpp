// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * Task<T>: lazy, single-awaiter, move-only coroutine.
 *
 *  - Nothing runs until the task is awaited or spawn()ed.
 *  - At final suspend it resumes its awaiter: by symmetric transfer when the
 *    awaiter was suspended on the same executor (or on a thread with no
 *    executor), otherwise by posting to the awaiter's executor.
 *  - Exceptions are captured and rethrown from await_resume.
 *  - The Task object owns the frame. spawn() detaches a Task<void>; its frame
 *    is destroyed when it finishes.
 */

#pragma once

#include "async/executor.hpp"
#include "async/frame_pool.hpp"

#include <cassert>
#include <coroutine>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <optional>
#include <type_traits>
#include <utility>

namespace kvrgw::async {

template <class T = void>
class Task;

namespace detail {

struct PooledFrame {
  static void* operator new(std::size_t n) { return frame_alloc(n); }
  static void operator delete(void* p, std::size_t n) noexcept { frame_free(p, n); }
};

struct PromiseBase : PooledFrame {
  std::coroutine_handle<> continuation{};
  Executor* cont_exec{nullptr};
  MpscNode resume_node{};
  std::exception_ptr exc{};

  std::suspend_always initial_suspend() noexcept { return {}; }

  struct FinalAwaiter {
    bool await_ready() const noexcept { return false; }
    template <class P>
    std::coroutine_handle<> await_suspend(std::coroutine_handle<P> h) noexcept {
      PromiseBase& p = h.promise();
      if (!p.continuation) return std::noop_coroutine();
      Executor* target = p.cont_exec;
      if (target == nullptr || target == Executor::current()) {
        return p.continuation;  // symmetric transfer
      }
      p.resume_node.h = p.continuation;
      // After post() the awaiter may resume on its own thread and destroy this
      // frame: touch nothing of ours afterwards.
      target->post(&p.resume_node);
      return std::noop_coroutine();
    }
    void await_resume() const noexcept {}
  };
  FinalAwaiter final_suspend() noexcept { return {}; }

  void unhandled_exception() noexcept { exc = std::current_exception(); }
};

template <class T>
struct Promise : PromiseBase {
  std::optional<T> value;
  Task<T> get_return_object() noexcept;
  template <class U>
  void return_value(U&& v) noexcept(std::is_nothrow_constructible_v<T, U&&>) {
    value.emplace(std::forward<U>(v));
  }
  T take() {
    if (exc) std::rethrow_exception(exc);
    assert(value.has_value());
    return std::move(*value);
  }
};

template <>
struct Promise<void> : PromiseBase {
  Task<void> get_return_object() noexcept;
  void return_void() noexcept {}
  void take() {
    if (exc) std::rethrow_exception(exc);
  }
};

}  // namespace detail

template <class T>
class [[nodiscard]] Task {
 public:
  using promise_type = detail::Promise<T>;
  using handle_type = std::coroutine_handle<promise_type>;
  using value_type = T;

  Task() noexcept = default;
  explicit Task(handle_type h) noexcept : h_(h) {}
  Task(Task&& o) noexcept : h_(std::exchange(o.h_, {})) {}
  Task& operator=(Task&& o) noexcept {
    if (this != &o) {
      if (h_) h_.destroy();
      h_ = std::exchange(o.h_, {});
    }
    return *this;
  }
  Task(const Task&) = delete;
  Task& operator=(const Task&) = delete;
  ~Task() {
    if (h_) h_.destroy();
  }

  explicit operator bool() const noexcept { return static_cast<bool>(h_); }
  bool done() const noexcept { return !h_ || h_.done(); }
  handle_type handle() const noexcept { return h_; }
  handle_type release() noexcept { return std::exchange(h_, {}); }

  struct Awaiter {
    handle_type h;
    bool await_ready() const noexcept { return !h || h.done(); }
    std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
      auto& p = h.promise();
      p.continuation = awaiting;
      p.cont_exec = Executor::current();
      return h;  // start (or continue) the child by symmetric transfer
    }
    T await_resume() { return h.promise().take(); }
  };
  Awaiter operator co_await() & noexcept { return Awaiter{h_}; }
  Awaiter operator co_await() && noexcept { return Awaiter{h_}; }

 private:
  handle_type h_{};
};

namespace detail {
template <class T>
inline Task<T> Promise<T>::get_return_object() noexcept {
  return Task<T>(std::coroutine_handle<Promise<T>>::from_promise(*this));
}
inline Task<void> Promise<void>::get_return_object() noexcept {
  return Task<void>(std::coroutine_handle<Promise<void>>::from_promise(*this));
}

// A fire-and-forget coroutine: starts suspended, destroys itself at the end.
struct Detached {
  struct promise_type : PooledFrame {
    MpscNode node{};
    Detached get_return_object() noexcept {
      return Detached{std::coroutine_handle<promise_type>::from_promise(*this)};
    }
    std::suspend_always initial_suspend() noexcept { return {}; }
    std::suspend_never final_suspend() noexcept { return {}; }
    void return_void() noexcept {}
    void unhandled_exception() noexcept {
      std::fputs("kvrgw::async: unhandled exception in detached task\n", stderr);
      std::abort();
    }
  };
  std::coroutine_handle<promise_type> h;
};

inline Detached run_detached(Task<void> t) { co_await t; }

}  // namespace detail

// Start a Task<void> on `ex` (posted, so it runs on ex's thread). The frame is
// destroyed when the task finishes. Exceptions abort.
inline void spawn(Executor& ex, Task<void> t) {
  auto d = detail::run_detached(std::move(t));
  d.h.promise().node.h = d.h;
  ex.post(&d.h.promise().node);
}

// Start a Task<void> right now on the calling thread; it continues wherever its
// awaits take it.
inline void spawn_inline(Task<void> t) {
  auto d = detail::run_detached(std::move(t));
  d.h.resume();
}

}  // namespace kvrgw::async
