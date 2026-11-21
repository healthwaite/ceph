// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
// Async tests that need a live FDB cluster: FdbAwait, retry_txn, admission,
// and the _a service ops against their sync wrappers.

#include "async/executor.hpp"
#include "async/fdb_await.hpp"
#include "async/sync_wait.hpp"
#include "async/task.hpp"
#include "kv_store.hpp"
#include "kvrgw_runtime.hpp"
#include "service_async.hpp"
#include "service_impl.hpp"

#include "async_test_util.hpp"

#include <atomic>
#include <cstdlib>
#include <latch>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace kvrgw;
using namespace kvrgw::async;

namespace {

KvRgwRuntime* g_rt = nullptr;

KvStore& store() { return g_rt->store(); }
KvRgwServiceImpl& svc() { return g_rt->service(); }

std::string test_key(const std::string& s) { return std::string("\xfe/async_fdb_test/") + s; }

Task<void> put_kv(std::string k, std::string v) {
  auto tr = store().begin_transaction();
  (*tr)->kv_put(k, v);
  fdb_error_t e = co_await (*tr)->commit_a();
  ACHECK_EQ(e, 0);
}

// Forces the await_suspend path even for a ready future.
struct ForcedAwait : FdbAwait {
  bool* returned;
  ForcedAwait(FDBFuture* f, bool* r) : FdbAwait(f), returned(r) {}
  bool await_ready() const noexcept { return false; }
  bool await_suspend(std::coroutine_handle<> c) noexcept {
    const bool s = FdbAwait::await_suspend(c);
    *returned = true;  // if the callback had resumed us inline, we'd see false in resume
    return s;
  }
};

}  // namespace

ATEST(fdb_await_ready_future_resumes_through_post) {
  ExecutorThread et("fa");
  et.start();
  sync_wait(put_kv(test_key("ready"), "v"));
  auto body = [](Executor& ex) -> Task<bool> {
    co_await switch_to(ex);
    auto tr = store().begin_transaction();
    FdbFuture f = (*tr)->kv_async_get(test_key("ready"));
    [[maybe_unused]] fdb_error_t e = fdb_future_block_until_ready(f.raw());
    bool returned = false;
    const uint64_t before = ex.items_run();
    fdb_error_t err = co_await ForcedAwait(f.raw(), &returned);
    co_return err == 0 && returned && ex.items_run() > before && Executor::current() == &ex;
  };
  ACHECK(sync_wait(body(et.executor())));
  et.stop_and_join();
}

ATEST(fdb_await_10000_concurrent_gets_resume_on_worker) {
  ExecutorThread et("fa2");
  et.start();
  sync_wait(put_kv(test_key("many"), "value"));
  constexpr int kN = 10000;
  std::atomic<int> ok{0}, wrong_thread{0};
  std::latch done(kN);
  auto one = [&](Executor& ex) -> Task<void> {
    auto tr = store().begin_transaction();
    FdbGetHolder h = (*tr)->get_a(test_key("many"));
    fdb_error_t e = co_await h;
    if (Executor::current() != &ex) wrong_thread.fetch_add(1);
    if (e == 0 && h.present() && h.value() == "value") ok.fetch_add(1);
    done.count_down();
  };
  for (int i = 0; i < kN; ++i) spawn(et.executor(), one(et.executor()));
  done.wait();
  ACHECK_EQ(ok.load(), kN);
  ACHECK_EQ(wrong_thread.load(), 0);
  et.stop_and_join();
}

ATEST(holder_await_from_plain_thread_blocks) {
  // No executor: the awaitable falls back to block_until_ready.
  sync_wait(put_kv(test_key("plain"), "p"));
  auto t = []() -> Task<std::string> {
    auto tr = store().begin_transaction();
    FdbGetHolder h = (*tr)->get_a(test_key("plain"));
    if (co_await h) co_return "";
    co_return std::string(h.value_or_empty());
  };
  ACHECK(sync_wait(t()) == "p");
}

ATEST(retry_txn_conflict_retries_via_on_error_and_succeeds) {
  ExecutorThread et("rt");
  et.start();
  sync_wait(put_kv(test_key("conflict"), "0"));
  auto run = [](Executor& ex) -> Task<std::pair<std::expected<int, KvrgwErrorCode>, int>> {
    co_await switch_to(ex);
    int attempts = 0;
    RetryPolicy pol;
    pol.max_attempts = 3;
    auto r = co_await retry_txn<int>(store(), pol, [&](KvTransaction& tr) -> Task<OpOutcome<int>> {
      ++attempts;
      FdbGetHolder h = tr.get_a(test_key("conflict"));
      if (fdb_error_t e = co_await h) co_return OpOutcome<int>::fdb(e);
      if (attempts == 1) {
        // A concurrent writer commits between our read and our commit.
        auto other = store().begin_transaction();
        (*other)->kv_put(test_key("conflict"), "x");
        ACHECK_EQ(co_await (*other)->commit_a(), 0);
      }
      tr.kv_put(test_key("conflict"), "mine");
      co_return OpOutcome<int>::commit(attempts);
    });
    co_return std::make_pair(r, attempts);
  };
  const auto r0 = svc().latency_stats().txn_retries.load();
  auto [r, attempts] = sync_wait(run(et.executor()));
  ACHECK(r.has_value());
  ACHECK_EQ(attempts, 2);
  (void)r0;
  et.stop_and_join();
}

ATEST(retry_txn_cap_is_honoured) {
  ExecutorThread et("cap");
  et.start();
  sync_wait(put_kv(test_key("cap"), "0"));
  auto run = [](Executor& ex, int cap) -> Task<std::pair<std::expected<int, KvrgwErrorCode>, int>> {
    co_await switch_to(ex);
    int attempts = 0;
    RetryPolicy pol;
    pol.max_attempts = cap;
    pol.stats = &svc().latency_stats();
    auto r = co_await retry_txn<int>(store(), pol, [&](KvTransaction& tr) -> Task<OpOutcome<int>> {
      ++attempts;
      FdbGetHolder h = tr.get_a(test_key("cap"));
      if (fdb_error_t e = co_await h) co_return OpOutcome<int>::fdb(e);
      auto other = store().begin_transaction();
      (*other)->kv_put(test_key("cap"), std::to_string(attempts));
      ACHECK_EQ(co_await (*other)->commit_a(), 0);
      tr.kv_put(test_key("cap"), "mine");
      co_return OpOutcome<int>::commit(0);
    });
    co_return std::make_pair(r, attempts);
  };
  const auto mx0 = svc().latency_stats().txn_max_retries_exceeded.load();
  auto [r, attempts] = sync_wait(run(et.executor(), 4));
  ACHECK(!r.has_value());
  ACHECK(!r.has_value() && r.error() == KVRGW_ERR_MAX_RETRIES_EXCEEDED);
  ACHECK_EQ(attempts, 4);
  ACHECK_EQ(svc().latency_stats().txn_max_retries_exceeded.load(), mx0 + 1);
  et.stop_and_join();
}

ATEST(retry_txn_1021_obeys_no_retry_unknown) {
  ExecutorThread et("cu");
  et.start();
  auto run = [](Executor& ex, bool no_retry) -> Task<std::pair<std::expected<int, KvrgwErrorCode>, int>> {
    co_await switch_to(ex);
    int attempts = 0;
    RetryPolicy pol;
    pol.max_attempts = 3;
    pol.no_retry_unknown = no_retry;
    auto r = co_await retry_txn<int>(store(), pol, [&](KvTransaction&) -> Task<OpOutcome<int>> {
      ++attempts;
      if (attempts == 1) co_return OpOutcome<int>::fdb(fdb::kCommitUnknownResult);
      co_return OpOutcome<int>::done(7);
    });
    co_return std::make_pair(r, attempts);
  };
  {
    auto [r, attempts] = sync_wait(run(et.executor(), false));
    ACHECK(r.has_value() && *r == 7);
    ACHECK_EQ(attempts, 2);
  }
  {
    auto [r, attempts] = sync_wait(run(et.executor(), true));
    ACHECK(!r.has_value() && r.error() == KVRGW_ERR_FDB_COMMIT_UNKNOWN);
    ACHECK_EQ(attempts, 1);
  }
  et.stop_and_join();
}

ATEST(admission_limit_async_refused_sync_counted) {
  AsyncStats st;
  Admission adm(st);
  adm.set_max(4);
  std::vector<Admission::Guard> held(4);
  for (auto& g : held) ACHECK_EQ(adm.admit(Caller::kAsync, &g), KVRGW_ERR_OK);
  Admission::Guard extra;
  ACHECK_EQ(adm.admit(Caller::kAsync, &extra), KVRGW_ERR_QUEUE_FULL);
  ACHECK(!extra);
  ACHECK_EQ(st.queue_full_rejects.load(), 1u);
  Admission::Guard sync_g;
  ACHECK_EQ(adm.admit(Caller::kSync, &sync_g), KVRGW_ERR_OK);
  ACHECK_EQ(st.inflight_ops.load(), 5);
  ACHECK_EQ(st.inflight_ops_peak.load(), 5);
  held.clear();
  sync_g = Admission::Guard();
  ACHECK_EQ(st.inflight_ops.load(), 0);
  adm.set_stopping();
  ACHECK_EQ(adm.admit(Caller::kSync, &sync_g), KVRGW_ERR_INTERNAL);
}

int main(int argc, char** argv) {
  // Small async limits so the admission tests can reach them.
  setenv("KVRGW_MAX_INFLIGHT_OPS", "64", 0);
  KvRgwRuntime rt;
  KvRgwStartOptions opts;
  opts.perf_mode = true;
  if (!rt.start(opts)) {
    std::fprintf(stderr, "runtime start failed (is FDB running?)\n");
    return 1;
  }
  g_rt = &rt;
  int rc = async_test::run_all(argc, argv);
  g_rt = nullptr;
  rt.stop();
  return rc;
}
