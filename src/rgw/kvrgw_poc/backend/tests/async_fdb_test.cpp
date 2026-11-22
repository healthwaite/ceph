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
#include <span>
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

namespace {
tenant_id_t g_tenant = 0;
const char* kBucket = "async-fdb-test-bucket";

void ensure_bucket() {
  if (g_tenant != 0) return;
  bool exists = false;
  svc().resolve_tenant("async-fdb-test", &exists, &g_tenant);
  if (!exists) {
    svc().add_tenant("async-fdb-test", &g_tenant);
  }
  ACHECK_EQ(svc().create_bucket(g_tenant, kBucket), KVRGW_ERR_OK);
}
}  // namespace

ATEST(put_object_a_queue_full_at_limit_sync_wrapper_not_refused) {
  ensure_bucket();
  auto& adm = svc().admission();
  // Saturate the in-flight limit with guards.
  std::vector<Admission::Guard> held(static_cast<size_t>(adm.max()));
  for (auto& g : held) ACHECK_EQ(adm.admit(Caller::kAsync, &g), KVRGW_ERR_OK);
  const std::string body(100, 'x');
  const auto* data = reinterpret_cast<const uint8_t*>(body.data());
  const auto rejects0 = svc().async_stats().queue_full_rejects.load();
  auto r = sync_wait(svc().put_object_a(g_tenant, kBucket, "qf-async", data, body.size(), "", 0,
                                        nullptr, {}, {}));
  ACHECK_EQ(r.error_code, KVRGW_ERR_QUEUE_FULL);
  ACHECK_EQ(svc().async_stats().queue_full_rejects.load(), rejects0 + 1);
  auto r2 = svc().put_object(g_tenant, kBucket, "qf-sync", data, body.size(), "", 0, nullptr,
                             {}, {});
  ACHECK_EQ(r2.error_code, KVRGW_ERR_OK);
  held.clear();
  ACHECK_EQ(svc().admission().inflight(), 0);
}

ATEST(put_object_a_many_concurrent_from_one_executor) {
  ensure_bucket();
  ExecutorThread drv("drv");
  drv.start();
  constexpr int kN = 2000;
  const std::string body(200, 'y');
  std::atomic<int> ok{0}, wrong_thread{0}, other{0};
  std::latch done(kN);
  auto one = [&](int i) -> Task<void> {
    Executor* me = Executor::current();
    const std::string key = "conc-" + std::to_string(i);
    auto r = co_await svc().put_object_a(g_tenant, kBucket, key,
                                         reinterpret_cast<const uint8_t*>(body.data()),
                                         body.size(), "", 0, nullptr, {}, {});
    if (Executor::current() != me) wrong_thread.fetch_add(1);
    if (r.error_code == KVRGW_ERR_OK) ok.fetch_add(1);
    else if (r.error_code != KVRGW_ERR_QUEUE_FULL) other.fetch_add(1);
    done.count_down();
  };
  for (int i = 0; i < kN; ++i) spawn(drv.executor(), one(i));
  done.wait();
  ACHECK_EQ(wrong_thread.load(), 0);
  ACHECK_EQ(other.load(), 0);
  ACHECK(ok.load() > 0);
  drv.stop_and_join();
  // Every successful key is readable through the sync API.
  KvRgwServiceImpl::ListObjectsResult res;
  std::string token;
  int listed = 0;
  do {
    res = {};
    ACHECK_EQ(svc().list_objects(g_tenant, kBucket, "conc-", "", 1000, token, "", &res),
              KVRGW_ERR_OK);
    listed += static_cast<int>(res.objects.size());
    token = res.next_continuation_token;
  } while (res.is_truncated);
  ACHECK(listed >= ok.load());
  ACHECK_EQ(svc().admission().inflight(), 0);
}

namespace {
std::string pattern(size_t n, int seed) {
  std::string s(n, '\0');
  uint32_t x = 2166136261u ^ static_cast<uint32_t>(seed);
  for (size_t i = 0; i < n; ++i) {
    x = x * 16777619u + 7;
    s[i] = static_cast<char>(x >> 24);
  }
  return s;
}

KvRgwServiceImpl::PutObjectResult put_sync(std::string_view bucket, const std::string& key,
                                           const std::string& body,
                                           std::span<const MetaPair> meta = {}) {
  return svc().put_object(g_tenant, bucket, key, reinterpret_cast<const uint8_t*>(body.data()),
                          body.size(), "", 0, nullptr, {}, meta);
}
}  // namespace

ATEST(get_object_a_every_tier_ranges_and_errors) {
  ensure_bucket();
  ExecutorThread drv("get");
  drv.start();
  // inline (<= 256 B), C:D (<= 4 KiB), storage tier, and one with metadata.
  struct Obj { std::string key; std::string body; };
  std::vector<Obj> objs = {{"get-inline", pattern(100, 1)}, {"get-childd", pattern(3000, 2)},
                           {"get-storage", pattern(200000, 3)}, {"get-meta", pattern(1500, 4)}};
  const std::string big_meta(900, 'm');
  const MetaPair meta[] = {{"x-amz-meta-a", "one"}, {"x-amz-meta-big", big_meta}};
  for (auto& o : objs) {
    auto r = o.key == "get-meta" ? put_sync(kBucket, o.key, o.body, meta) : put_sync(kBucket, o.key, o.body);
    ACHECK_EQ(r.error_code, KVRGW_ERR_OK);
  }
  auto get = [&](std::string key, const ByteRange* range, KvRgwServiceImpl::GetObjectResult* out,
                 Executor* where) -> Task<std::pair<KvrgwErrorCode, bool>> {
    auto ec = co_await svc().get_object_a(g_tenant, kBucket, key, std::nullopt, range, 0, out);
    co_return std::make_pair(ec, Executor::current() == where);
  };
  for (auto& o : objs) {
    KvRgwServiceImpl::GetObjectResult res;
    auto [ec, same] = sync_wait([&]() -> Task<std::pair<KvrgwErrorCode, bool>> {
      co_await switch_to(drv.executor());
      co_return co_await get(o.key, nullptr, &res, &drv.executor());
    }());
    ACHECK_EQ(ec, KVRGW_ERR_OK);
    ACHECK(same);  // resumed on the caller's executor
    ACHECK(res.body == o.body);
    ACHECK_EQ(res.value.hdr.size, o.body.size());
    // Range bytes=10-99, on every tier.
    ByteRange rg;
    rg.start = 10;
    rg.end = 99;
    KvRgwServiceImpl::GetObjectResult part;
    ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, kBucket, o.key, std::nullopt, &rg, 0, &part)),
              KVRGW_ERR_OK);
    ACHECK(part.body == o.body.substr(10, 90));
    // The sync wrapper returns the same bytes.
    KvRgwServiceImpl::GetObjectResult s;
    ACHECK_EQ(svc().get_object(g_tenant, kBucket, o.key, std::nullopt, nullptr, 0, &s), KVRGW_ERR_OK);
    ACHECK(s.body == o.body);
  }
  {
    ByteRange bad;
    bad.start = 10000000;
    bad.end = 10000010;
    KvRgwServiceImpl::GetObjectResult r;
    ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, kBucket, "get-childd", std::nullopt, &bad, 0, &r)),
              KVRGW_ERR_INVALID_RANGE);
  }
  KvRgwServiceImpl::GetObjectResult r;
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, kBucket, "get-missing", std::nullopt, nullptr, 0, &r)),
            KVRGW_ERR_NO_SUCH_KEY);
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, "async-no-such-bucket", "k", std::nullopt, nullptr, 0, &r)),
            KVRGW_ERR_NO_SUCH_BUCKET);
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, kBucket, "get-inline", std::nullopt, nullptr, 2, &r)),
            KVRGW_ERR_INVALID_PART);
  drv.stop_and_join();
  ACHECK_EQ(svc().admission().inflight(), 0);
}

ATEST(get_object_a_versions_and_delete_marker) {
  ensure_bucket();
  const char* vb = "async-fdb-test-versioned";
  ACHECK_EQ(svc().create_bucket(g_tenant, vb), KVRGW_ERR_OK);
  ACHECK_EQ(svc().put_bucket_versioning(g_tenant, vb, VERSIONING_ENABLED), KVRGW_ERR_OK);
  const std::string v1 = pattern(3000, 11), v2 = pattern(500000, 12);
  auto r1 = put_sync(vb, "vk", v1);
  auto r2 = put_sync(vb, "vk", v2);
  ACHECK_EQ(r1.error_code, KVRGW_ERR_OK);
  ACHECK_EQ(r2.error_code, KVRGW_ERR_OK);
  KvRgwServiceImpl::GetObjectResult g;
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, vb, "vk", std::nullopt, nullptr, 0, &g)), KVRGW_ERR_OK);
  ACHECK(g.body == v2);
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, vb, "vk", r1.version_id, nullptr, 0, &g)), KVRGW_ERR_OK);
  ACHECK(g.body == v1);  // older version, read from :V:
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, vb, "vk", r2.version_id, nullptr, 0, &g)), KVRGW_ERR_OK);
  ACHECK(g.body == v2);  // current version, by id
  KvRgwServiceImpl::DeleteResult dr;
  ACHECK_EQ(svc().delete_object(g_tenant, vb, "vk", nullptr, &dr), KVRGW_ERR_OK);
  ACHECK(dr.created_dm);
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, vb, "vk", std::nullopt, nullptr, 0, &g)),
            KVRGW_ERR_NO_SUCH_KEY);
  ACHECK(!g.error_detail.empty());  // delete-marker detail is reported
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, vb, "vk", version_id_t{}, nullptr, 0, &g)),
            KVRGW_ERR_NO_SUCH_VERSION);
}

ATEST(get_object_a_many_concurrent_and_queue_full) {
  ensure_bucket();
  const std::string body = pattern(3000, 21);
  ACHECK_EQ(put_sync(kBucket, "get-conc", body).error_code, KVRGW_ERR_OK);
  ExecutorThread drv("getc");
  drv.start();
  constexpr int kN = 2000;
  std::atomic<int> ok{0}, qf{0}, bad{0};
  std::latch done(kN);
  auto one = [&]() -> Task<void> {
    KvRgwServiceImpl::GetObjectResult res;
    auto ec = co_await svc().get_object_a(g_tenant, kBucket, "get-conc", std::nullopt, nullptr, 0, &res);
    if (ec == KVRGW_ERR_OK && res.body == body) ok.fetch_add(1);
    else if (ec == KVRGW_ERR_QUEUE_FULL) qf.fetch_add(1);
    else bad.fetch_add(1);
    done.count_down();
  };
  for (int i = 0; i < kN; ++i) spawn(drv.executor(), one());
  done.wait();
  drv.stop_and_join();
  ACHECK_EQ(bad.load(), 0);
  ACHECK_EQ(ok.load() + qf.load(), kN);
  ACHECK(ok.load() > 0);
  // At the limit an async GET is refused; the sync wrapper is not.
  auto& adm = svc().admission();
  std::vector<Admission::Guard> held(static_cast<size_t>(adm.max()));
  for (auto& g : held) ACHECK_EQ(adm.admit(Caller::kAsync, &g), KVRGW_ERR_OK);
  KvRgwServiceImpl::GetObjectResult res;
  ACHECK_EQ(sync_wait(svc().get_object_a(g_tenant, kBucket, "get-conc", std::nullopt, nullptr, 0, &res)),
            KVRGW_ERR_QUEUE_FULL);
  ACHECK_EQ(svc().get_object(g_tenant, kBucket, "get-conc", std::nullopt, nullptr, 0, &res), KVRGW_ERR_OK);
  ACHECK(res.body == body);
  held.clear();
  ACHECK_EQ(svc().admission().inflight(), 0);
}

int main(int argc, char** argv) {
  // Small async limits so the admission tests can reach them.
  setenv("KVRGW_MAX_INFLIGHT_OPS", "64", 0);
  // A real file data store (perf mode's keeps no blobs), so storage-tier GETs
  // return data.
  char data_dir[] = "/tmp/kvrgw-async-fdb-test-XXXXXX";
  if (mkdtemp(data_dir) == nullptr) return 1;
  setenv("KVRGW_DATA", data_dir, 1);
  KvRgwRuntime rt;
  KvRgwStartOptions opts;
  opts.perf_mode = false;
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
