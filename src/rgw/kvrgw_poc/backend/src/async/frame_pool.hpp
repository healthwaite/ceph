// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * Pooled coroutine-frame allocation.
 *
 * promise_type::operator new draws from thread-local free lists in size
 * classes of 256, 512, 1024, 2048 and 4096 bytes. Larger frames fall back to
 * ::operator new and are counted. A frame freed on a thread other than the one
 * that allocated it is pushed onto the owner's atomic return stack; the owner
 * reclaims it on its next allocation.
 *
 * The pool is not a limit: the in-flight op cap (admission) is.
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace kvrgw::async {

struct FramePoolCounters {
  std::atomic<int64_t>  frames_live{0};
  std::atomic<uint64_t> frames_heap_fallback{0};
  std::atomic<uint64_t> max_frame_size{0};
  std::atomic<uint64_t> frames_total{0};
  std::atomic<uint64_t> cross_thread_frees{0};
};

FramePoolCounters& frame_pool_counters() noexcept;

// n is the size the compiler asked for (frame size, excluding our header).
void* frame_alloc(std::size_t n);
void  frame_free(void* p, std::size_t n) noexcept;

}  // namespace kvrgw::async
