// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * co_await on FDB futures.
 *
 * The callback runs on the FDB network thread and does exactly one thing: post
 * the waiting coroutine back to the executor it suspended on (queue push +
 * eventfd write). No logging, allocation or locks there.
 *
 * If the future is already ready when the callback is installed, libfdb_c may
 * call it at once on the calling thread; that is fine, because post() only
 * enqueues and the coroutine is resumed later by its own executor.
 *
 * Awaiting from a thread with no executor (a plain thread) falls back to
 * fdb_future_block_until_ready and does not suspend.
 */

#pragma once

#include "async/executor.hpp"
#include "fdb.hpp"

#include <coroutine>

namespace kvrgw::async {

// Awaits a raw FDBFuture it does not own; yields fdb_future_get_error().
struct FdbAwait {
  FDBFuture* f;
  Executor* exec{nullptr};
  MpscNode node{};

  explicit FdbAwait(FDBFuture* fut) noexcept : f(fut) {}
  FdbAwait(const FdbAwait&) = delete;
  FdbAwait& operator=(const FdbAwait&) = delete;

  bool await_ready() const noexcept { return fdb_future_is_ready(f); }

  bool await_suspend(std::coroutine_handle<> c) noexcept {
    exec = Executor::current();
    if (exec == nullptr) {
      [[maybe_unused]] fdb_error_t e = fdb_future_block_until_ready(f);
      return false;
    }
    node.h = c;
    if (fdb_future_set_callback(f, &FdbAwait::callback, this) != 0) {
      // Could not install the callback: resume through the queue anyway; the
      // caller will read the future's error.
      exec->post(&node);
    }
    return true;
  }

  fdb_error_t await_resume() const noexcept { return fdb_future_get_error(f); }

  static void callback(FDBFuture*, void* p) noexcept {
    auto* a = static_cast<FdbAwait*>(p);
    a->exec->post(&a->node);  // push + eventfd, nothing else
  }
};

}  // namespace kvrgw::async
