// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab

#include "async/frame_pool.hpp"

#include <cstdlib>
#include <mutex>
#include <new>
#include <vector>

namespace kvrgw::async {

namespace {

constexpr std::size_t kHeader = 16;  // keeps the frame 16-byte aligned
constexpr std::size_t kClassSize[] = {256, 512, 1024, 2048, 4096};
constexpr int kNumClasses = 5;
constexpr uint32_t kHeapClass = 0xff;
// Per-class cap on cached free frames; beyond it frames go back to the heap.
constexpr int kMaxCachedPerClass = 8192;

struct FreeNode {
  FreeNode* next;
};

struct ThreadPool;

struct alignas(16) Header {
  ThreadPool* owner;  // nullptr for heap-fallback frames
  uint32_t cls;
  uint32_t pad;
};
static_assert(sizeof(Header) == kHeader);

// Marks a pool whose thread has exited: later cross-thread frees go straight to
// the heap.
FreeNode* const kClosed = reinterpret_cast<FreeNode*>(uintptr_t{1});

struct ThreadPool {
  FreeNode* free_[kNumClasses]{};
  int cached_[kNumClasses]{};
  bool closed{false};
  std::atomic<FreeNode*> returned{nullptr};
};

FramePoolCounters g_counters;

// Pools are never freed: a frame may outlive its owning thread, and its header
// still points at the pool. Keeping them in a global list makes them reachable
// (not reported as leaks). There is one per thread that ever ran a coroutine.
std::mutex g_pools_mu;
std::vector<ThreadPool*>* g_pools = nullptr;

inline Header* header_of(void* frame) noexcept {
  return reinterpret_cast<Header*>(static_cast<char*>(frame) - kHeader);
}
inline FreeNode* node_of(Header* h) noexcept {
  return reinterpret_cast<FreeNode*>(reinterpret_cast<char*>(h) + kHeader);
}
inline Header* header_of_node(FreeNode* n) noexcept {
  return reinterpret_cast<Header*>(reinterpret_cast<char*>(n) - kHeader);
}

void close_pool(ThreadPool* p) noexcept;

struct PoolHolder {
  ThreadPool* p{nullptr};
  ~PoolHolder() {
    if (p) close_pool(p);
  }
};

thread_local PoolHolder tl_pool;

ThreadPool* this_pool() {
  if (tl_pool.p == nullptr) {
    auto* p = new ThreadPool();
    {
      std::lock_guard lk(g_pools_mu);
      if (!g_pools) g_pools = new std::vector<ThreadPool*>();
      g_pools->push_back(p);
    }
    tl_pool.p = p;
  }
  return tl_pool.p;
}

void free_list(FreeNode* n) noexcept {
  while (n && n != kClosed) {
    FreeNode* next = n->next;
    ::operator delete(header_of_node(n));
    n = next;
  }
}

void close_pool(ThreadPool* p) noexcept {
  p->closed = true;
  for (int c = 0; c < kNumClasses; ++c) {
    free_list(p->free_[c]);
    p->free_[c] = nullptr;
    p->cached_[c] = 0;
  }
  free_list(p->returned.exchange(kClosed, std::memory_order_acq_rel));
}

void reclaim_returned(ThreadPool* p) noexcept {
  FreeNode* n = p->returned.exchange(nullptr, std::memory_order_acquire);
  while (n) {
    FreeNode* next = n->next;
    Header* h = header_of_node(n);
    n->next = p->free_[h->cls];
    p->free_[h->cls] = n;
    ++p->cached_[h->cls];
    n = next;
  }
}

void update_max(std::size_t n) noexcept {
  uint64_t cur = g_counters.max_frame_size.load(std::memory_order_relaxed);
  while (n > cur &&
         !g_counters.max_frame_size.compare_exchange_weak(cur, n, std::memory_order_relaxed)) {
  }
}

}  // namespace

FramePoolCounters& frame_pool_counters() noexcept { return g_counters; }

void* frame_alloc(std::size_t n) {
  g_counters.frames_live.fetch_add(1, std::memory_order_relaxed);
  g_counters.frames_total.fetch_add(1, std::memory_order_relaxed);
  update_max(n);

  const std::size_t total = n + kHeader;
  int cls = -1;
  for (int c = 0; c < kNumClasses; ++c) {
    if (total <= kClassSize[c]) {
      cls = c;
      break;
    }
  }
  if (cls < 0) {
    g_counters.frames_heap_fallback.fetch_add(1, std::memory_order_relaxed);
    auto* h = static_cast<Header*>(::operator new(total));
    h->owner = nullptr;
    h->cls = kHeapClass;
    return reinterpret_cast<char*>(h) + kHeader;
  }

  ThreadPool* p = this_pool();
  if (p->free_[cls] == nullptr &&
      p->returned.load(std::memory_order_relaxed) != nullptr) {
    reclaim_returned(p);
  }
  Header* h;
  if (FreeNode* f = p->free_[cls]) {
    p->free_[cls] = f->next;
    --p->cached_[cls];
    h = header_of_node(f);
  } else {
    h = static_cast<Header*>(::operator new(kClassSize[cls]));
  }
  h->owner = p;
  h->cls = static_cast<uint32_t>(cls);
  return reinterpret_cast<char*>(h) + kHeader;
}

void frame_free(void* frame, std::size_t) noexcept {
  if (!frame) return;
  g_counters.frames_live.fetch_sub(1, std::memory_order_relaxed);
  Header* h = header_of(frame);
  ThreadPool* owner = h->owner;
  if (owner == nullptr) {
    ::operator delete(h);
    return;
  }
  const uint32_t cls = h->cls;
  FreeNode* n = node_of(h);
  if (owner == tl_pool.p) {
    if (owner->closed || owner->cached_[cls] >= kMaxCachedPerClass) {
      ::operator delete(h);
      return;
    }
    n->next = owner->free_[cls];
    owner->free_[cls] = n;
    ++owner->cached_[cls];
    return;
  }
  g_counters.cross_thread_frees.fetch_add(1, std::memory_order_relaxed);
  FreeNode* head = owner->returned.load(std::memory_order_relaxed);
  do {
    if (head == kClosed) {
      ::operator delete(h);
      return;
    }
    n->next = head;
  } while (!owner->returned.compare_exchange_weak(head, n, std::memory_order_release,
                                                 std::memory_order_relaxed));
}

}  // namespace kvrgw::async
