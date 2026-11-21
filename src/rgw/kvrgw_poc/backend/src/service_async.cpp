// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab

#include "service_async.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace kvrgw {

namespace {
bool env_i64(const char* name, int64_t* out) {
  const char* v = std::getenv(name);
  if (v == nullptr || v[0] == '\0') return false;
  *out = std::atoll(v);
  return true;
}
}  // namespace

AsyncConfig AsyncConfig::from_env() {
  AsyncConfig c;
  int64_t v = 0;
  if (env_i64("KVRGW_BACKEND_WORKERS", &v)) {
    c.backend_workers = static_cast<int>(v);
  } else if (env_i64("KVRGW_BATCH_THREADS", &v)) {
    std::cerr << "kvrgw: KVRGW_BATCH_THREADS is deprecated; read as KVRGW_BACKEND_WORKERS="
              << v << std::endl;
    c.backend_workers = static_cast<int>(v);
  }
  if (env_i64("KVRGW_MAX_INFLIGHT_OPS", &v)) c.max_inflight_ops = v;
  if (env_i64("KVRGW_TXN_MAX_ATTEMPTS", &v)) c.txn_max_attempts = static_cast<int>(v);
  if (env_i64("KVRGW_BATCH_TXN_MAX_ATTEMPTS", &v)) c.batch_txn_max_attempts = static_cast<int>(v);
  if (env_i64("KVRGW_TXN_TIMEOUT_MS", &v)) c.txn_timeout_ms = v;
  if (c.backend_workers < 1) c.backend_workers = 1;
  if (c.max_inflight_ops < 1) c.max_inflight_ops = 1;
  if (c.txn_max_attempts < 1) c.txn_max_attempts = 1;
  if (c.batch_txn_max_attempts < 1) c.batch_txn_max_attempts = 1;
  if (c.txn_timeout_ms < 0) c.txn_timeout_ms = 0;
  return c;
}

void BackendWorkers::start(int n) {
  if (!ex_.empty()) return;
  for (int i = 0; i < n; ++i) {
    ex_.push_back(std::make_unique<async::ExecutorThread>("kvrgw-be-" + std::to_string(i)));
  }
  for (auto& e : ex_) e->start();
}

void BackendWorkers::stop() {
  for (auto& e : ex_) e->stop_and_join();
  ex_.clear();
}

int BackendWorkers::current_index() const noexcept {
  async::Executor* cur = async::Executor::current();
  for (size_t i = 0; i < ex_.size(); ++i) {
    if (&ex_[i]->executor() == cur) return static_cast<int>(i);
  }
  return -1;
}

}  // namespace kvrgw
