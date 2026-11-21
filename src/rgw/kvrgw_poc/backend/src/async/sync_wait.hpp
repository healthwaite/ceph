// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * sync_wait(Task<T>): run a task to completion from a thread with no executor
 * (C API, gRPC handlers, the perf worker's sync-mode threads, init/verify).
 *
 * Calling it on an executor thread would park that executor, and with it the
 * coroutines that must run to complete the task, so it is refused: debug
 * builds (assert enabled) abort; the service's sync wrappers check
 * can_sync_wait() first and return KVRGW_ERR_INTERNAL instead.
 */

#pragma once

#include "async/task.hpp"

#include <cassert>
#include <exception>
#include <optional>
#include <semaphore>

namespace kvrgw::async {

inline bool can_sync_wait() noexcept { return Executor::current() == nullptr; }

namespace detail {

template <class T>
struct SyncState {
  std::binary_semaphore sem{0};
  std::optional<T> value;
  std::exception_ptr exc;
};
template <>
struct SyncState<void> {
  std::binary_semaphore sem{0};
  std::exception_ptr exc;
};

template <class T>
Detached sync_runner(Task<T>* t, SyncState<T>* st) {
  try {
    if constexpr (std::is_void_v<T>) {
      co_await *t;
    } else {
      st->value.emplace(co_await *t);
    }
  } catch (...) {
    st->exc = std::current_exception();
  }
  // Last touch of *st: the waiting thread may return right after this.
  st->sem.release();
}

}  // namespace detail

template <class T>
T sync_wait(Task<T> t) {
  assert(can_sync_wait() && "sync_wait called on an executor thread");
  if (!can_sync_wait()) std::abort();
  detail::SyncState<T> st;
  auto d = detail::sync_runner<T>(&t, &st);
  d.h.resume();
  st.sem.acquire();
  if (st.exc) std::rethrow_exception(st.exc);
  if constexpr (!std::is_void_v<T>) return std::move(*st.value);
}

}  // namespace kvrgw::async
