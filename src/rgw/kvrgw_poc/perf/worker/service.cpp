#include "service.hpp"

#include "async/executor.hpp"
#include "async/task.hpp"
#include "error_codes.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <thread>

using perf::v1::PhaseEvent;

namespace perfw {

namespace {

void fill_hist(const MetricStats &m, perf::v1::Histogram *h)
{
  for (size_t i = 0; i < m.hist.size(); ++i) {
    if (m.hist[i] != 0) {
      h->add_bucket_index(static_cast<uint32_t>(i));
      h->add_bucket_count(m.hist[i]);
    }
  }
}

void fill_stats(const StatsArray &a, google::protobuf::RepeatedPtrField<perf::v1::OpStats> *out)
{
  for (int i = 0; i < kMetricCount; ++i) {
    const auto &m = a[static_cast<size_t>(i)];
    // Always emit (even when empty) so the controller sees every window.
    auto *o = out->Add();
    o->set_operation_type(metric_name(static_cast<Metric>(i)));
    o->set_count(m.count);
    o->set_errors(m.errors);
    o->set_sum_micros(m.sum_micros);
    o->set_queue_full(m.queue_full);
    o->set_missed(m.missed);
    for (const auto &[code, n] : m.error_codes) (*o->mutable_error_codes())[code] = n;
    if (!metric_is_counter(static_cast<Metric>(i))) fill_hist(m, o->mutable_latency());
  }
}

// Runs one stream to completion, then reports it done. A free function so the
// coroutine holds only references whose owners outlive it.
kvrgw::async::Task<void> stream_main(RunContext &ctx, Operation &op, Stream &s,
                                     const std::function<void()> &on_done)
{
  try {
    co_await op.run_stream(ctx, s);
  } catch (const std::exception &e) {
    ctx.fail(std::string("stream exception: ") + e.what());
  }
  on_done();
}

int64_t sys_now_ns()
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

}  // namespace

void WorkerService::fill_server_stats(perf::v1::ServerStats *out)
{
  auto &svc = rt_.service();
  auto &ls = svc.latency_stats();
  for (int i = 0; i < static_cast<int>(kvrgw::OpType::kCount); ++i) {
    auto &s = ls.ops[i];
    auto cnt = s.count.load(std::memory_order_relaxed);
    if (cnt == 0) continue;
    auto *o = out->add_ops();
    o->set_op(kvrgw::op_type_name(static_cast<kvrgw::OpType>(i)));
    o->set_count(static_cast<uint64_t>(cnt));
    o->set_total_us(static_cast<uint64_t>(s.total_us.load(std::memory_order_relaxed)));
    o->set_fdb_us(static_cast<uint64_t>(s.fdb_us.load(std::memory_order_relaxed)));
    o->set_fdb_get_us(static_cast<uint64_t>(s.fdb_get_us.load(std::memory_order_relaxed)));
    o->set_fdb_commit_us(static_cast<uint64_t>(s.fdb_commit_us.load(std::memory_order_relaxed)));
    o->set_fdb_scan_us(static_cast<uint64_t>(s.fdb_scan_us.load(std::memory_order_relaxed)));
    o->set_disk_us(static_cast<uint64_t>(s.disk_us.load(std::memory_order_relaxed)));
  }
  auto &bs = svc.batch_queue().stats();
  out->set_batch_commits(static_cast<uint64_t>(bs.attempted_batch_commits.load()));
  out->set_batch_entries(static_cast<uint64_t>(bs.attempted_total_entries_batch.load()));
  out->set_batch_wait_us_total(static_cast<uint64_t>(bs.attempted_total_wait_us.load()));
  out->set_batch_queue_size_total(static_cast<uint64_t>(bs.total_queue_size_at_extract.load()));
  out->set_batch_conflict_pushbacks(static_cast<uint64_t>(bs.conflict_pushbacks.load()));
  out->set_txn_retries(static_cast<uint64_t>(ls.txn_retries.load()));
  out->set_txn_hard_failures(static_cast<uint64_t>(ls.txn_hard_failures.load()));
  auto &as = svc.async_stats();
  out->set_queue_full_rejects(as.queue_full_rejects.load(std::memory_order_relaxed));
  out->set_inflight_ops_peak(
      static_cast<uint64_t>(as.inflight_ops_peak.load(std::memory_order_relaxed)));
  auto &fp = kvrgw::async::frame_pool_counters();
  out->set_frames_heap_fallback(fp.frames_heap_fallback.load(std::memory_order_relaxed));
  out->set_max_frame_size(fp.max_frame_size.load(std::memory_order_relaxed));
  auto &es = svc.error_stats();
  for (int i = 0; i < kvrgw::KvrgwErrorCode_ARRAYSIZE; ++i) {
    auto c = es.counts[i].load(std::memory_order_relaxed);
    if (c == 0) continue;
    (*out->mutable_errors())[kvrgw::KvrgwErrorCode_Name(static_cast<kvrgw::KvrgwErrorCode>(i))] =
        static_cast<uint64_t>(c);
  }
}

std::string WorkerService::do_init(const perf::v1::InitRequest &req)
{
  auto ctx = std::make_unique<RunContext>();
  if (auto err = parse_config(req.config_json(), req.operation(), req.worker_count(), &ctx->cfg);
      !err.empty()) {
    return err;
  }
  auto op = make_operation(req.operation());
  if (!op) return "unknown operation: " + req.operation();

  ctx->worker_index = req.worker_index();
  ctx->worker_count = req.worker_count();
  ctx->run_start_unix_s = req.run_start_unix_s();
  ctx->svc = &rt_.service();
  auto &svc = *ctx->svc;

  const auto &cfg = ctx->cfg;

  // Tenant: worker 0 creates it if missing; the others wait for it to appear.
  {
    const auto deadline = SteadyClock::now() + std::chrono::seconds(60);
    for (;;) {
      bool exists = false;
      auto ec = svc.resolve_tenant(cfg.tenant_name, &exists, &ctx->tenant);
      if (ec != kvrgw::KVRGW_ERR_OK) return std::string("resolve_tenant: ") + describe_error(ec);
      if (exists && ctx->tenant != 0) break;
      if (ctx->worker_index == 0) {
        kvrgw::tenant_id_t created = 0;
        ec = svc.add_tenant(cfg.tenant_name, &created);
        if (ec != kvrgw::KVRGW_ERR_OK && ec != kvrgw::KVRGW_ERR_TENANT_ALREADY_EXISTS) {
          return std::string("add_tenant: ") + describe_error(ec);
        }
        continue;
      }
      if (SteadyClock::now() > deadline) return "tenant " + cfg.tenant_name + " did not appear";
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
  }

  for (uint64_t b = 0; b < cfg.num_buckets; ++b) {
    ctx->bucket_names.push_back(bucket_name(cfg.bucket_name_prefix, b));
  }
  ctx->payload.resize(cfg.object_size_bytes);
  uint64_t st = 0x1234;
  for (size_t i = 0; i < ctx->payload.size(); ++i) {
    ctx->payload[i] = static_cast<char>(splitmix64_next(st));
  }
  {
    // Same charset as perf_driver (AWS-legal characters); keys are meta000, meta001, ...
    static constexpr std::string_view charset(
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_.!*()'");
    const auto n = static_cast<size_t>(cfg.metadata_count);
    ctx->meta_keys.reserve(n);
    ctx->meta_vals.reserve(n);
    ctx->meta_pairs.reserve(n);
    uint64_t ms = 0x5678;
    for (size_t i = 0; i < n; ++i) {
      char kb[16];
      std::snprintf(kb, sizeof kb, "meta%03zu", i);
      ctx->meta_keys.emplace_back(kb);
      std::string v(static_cast<size_t>(cfg.metadata_size), '\0');
      for (auto &ch : v) ch = charset[splitmix64_next(ms) % charset.size()];
      ctx->meta_vals.push_back(std::move(v));
    }
    // Vectors are fully built before taking views, so the views stay valid.
    for (size_t i = 0; i < n; ++i) ctx->meta_pairs.emplace_back(ctx->meta_keys[i], ctx->meta_vals[i]);
  }
  // One ThreadStats per benchmark thread: a stream's thread in sync mode, a
  // driver thread in async mode (shared by that driver's streams).
  stats_ = std::make_unique<StatsHub>(cfg.async_mode() ? cfg.driver_threads : cfg.streams());
  ctx->stats = stats_.get();

  if (auto err = op->init(*ctx); !err.empty()) return err;
  ctx_ = std::move(ctx);
  op_ = std::move(op);
  benchmark_id_ = req.benchmark_id();
  return {};
}

grpc::Status WorkerService::Init(grpc::ServerContext *, const perf::v1::InitRequest *req,
                                 grpc::ServerWriter<PhaseEvent> *w)
{
  std::lock_guard<std::mutex> g(mu_);
  PhaseEvent ev;
  ev.set_state(PhaseEvent::READY);
  std::string err;
  try {
    err = do_init(*req);
  } catch (const std::exception &e) {
    err = std::string("init exception: ") + e.what();
  }
  if (!err.empty()) {
    std::cerr << "Init failed: " << err << "\n";
    ev.set_error(err);
  }
  w->Write(ev);
  return grpc::Status::OK;
}

grpc::Status WorkerService::RunBenchmark(
    grpc::ServerContext *, grpc::ServerReaderWriter<PhaseEvent, perf::v1::RunControl> *s)
{
  perf::v1::RunControl first;
  if (!s->Read(&first)) return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "no run control");
  if (!ctx_ || !op_ || first.benchmark_id() != benchmark_id_) {
    PhaseEvent ev;
    ev.set_state(PhaseEvent::DONE);
    ev.set_error("RunBenchmark without matching Init");
    s->Write(ev);
    return grpc::Status::OK;
  }
  RunContext &ctx = *ctx_;
  const bool async_mode = ctx.cfg.async_mode();
  // Units that report completion: streams (one thread each in sync mode).
  const int T = ctx.cfg.streams();
  const int64_t interval_ms = first.report_interval_ms();
  const int64_t run_start_ns = first.run_start_unix_ns();
  ctx.bench_start_unix_s = run_start_ns / 1000000000;

  // Map the controller's wall-clock start onto the steady clock.
  const int64_t delta_ns = std::max<int64_t>(0, run_start_ns - sys_now_ns());
  ctx.start_tp = SteadyClock::now() + std::chrono::nanoseconds(delta_ns);
  ctx.deadline = ctx.start_tp + std::chrono::milliseconds(ctx.cfg.duration_ms);

  // Reader thread: watches for Cancel until the client half-closes.
  std::thread reader([&]() {
    perf::v1::RunControl m;
    while (s->Read(&m)) {
      if (m.has_cancel()) ctx.cancel = true;
    }
  });

  std::mutex done_mu;
  std::condition_variable done_cv;
  std::atomic<int> finished{0};
  const std::function<void()> on_done = [&]() {
    if (++finished == T) {
      std::lock_guard<std::mutex> g(done_mu);
      done_cv.notify_all();
    }
  };
  std::vector<std::thread> threads;
  std::vector<std::unique_ptr<kvrgw::async::ExecutorThread>> drivers;
  std::vector<Stream> streams;
  if (!async_mode) {
    // Sync mode: one blocking thread per stream, calling the sync wrappers.
    for (int t = 0; t < T; ++t) {
      threads.emplace_back([&, t]() {
        try {
          op_->run_thread(ctx, t);
        } catch (const std::exception &e) {
          ctx.fail(std::string("worker thread exception: ") + e.what());
        }
        on_done();
      });
    }
  } else {
    // Async mode: driver_threads executors; stream sid runs on driver sid % D.
    const int D = ctx.cfg.driver_threads;
    for (int d = 0; d < D; ++d) {
      drivers.push_back(std::make_unique<kvrgw::async::ExecutorThread>("perf-drv-" + std::to_string(d)));
      drivers.back()->start();
    }
    streams.resize(static_cast<size_t>(T));
    for (int sid = 0; sid < T; ++sid) {
      Stream &st = streams[static_cast<size_t>(sid)];
      st.sid = sid;
      st.gsid = ctx.gsid(sid);
      st.driver = sid % D;
      st.ts = &stats_->thread(st.driver);
      st.exec = &drivers[static_cast<size_t>(st.driver)]->executor();
    }
    // Sleep until the synchronised start (no polling), then start every stream.
    std::this_thread::sleep_until(ctx.start_tp);
    for (auto &st : streams) {
      kvrgw::async::spawn(*st.exec, stream_main(ctx, *op_, st, on_done));
    }
  }

  auto emit_progress = [&](int64_t window, int64_t dur_ns) {
    PhaseEvent ev;
    ev.set_state(PhaseEvent::READY);
    auto *p = ev.mutable_progress();
    p->set_worker_index(ctx.worker_index);
    p->set_window(window);
    p->set_window_duration_ns(dur_ns);
    auto win = stats_->collect_window();
    fill_stats(win, p->mutable_window_stats());
    fill_stats(stats_->cumulative(), p->mutable_cumulative_stats());
    for (const auto &[code, text] : error_texts()) (*p->mutable_error_descriptions())[code] = text;
    p->set_cumulative_as_of_unix_ns(sys_now_ns());
    fill_server_stats(p->mutable_server_stats());
    s->Write(ev);
  };

  if (interval_ms > 0) {
    const auto interval = std::chrono::milliseconds(interval_ms);
    for (int64_t k = 0;; ++k) {
      const auto boundary = ctx.start_tp + interval * (k + 1);
      std::unique_lock<std::mutex> lk(done_mu);
      const bool all_done =
          done_cv.wait_until(lk, boundary, [&] { return finished.load() == T; });
      lk.unlock();
      if (all_done) {
        const auto win_start = ctx.start_tp + interval * k;
        const auto dur = std::max<int64_t>(
            0, std::chrono::duration_cast<std::chrono::nanoseconds>(SteadyClock::now() - win_start)
                   .count());
        emit_progress(k, std::min<int64_t>(dur, interval_ms * 1000000));
        break;
      }
      emit_progress(k, interval_ms * 1000000);
    }
  }
  else {
    // Progress windows disabled: a single report covering the whole run.
    std::unique_lock<std::mutex> lk(done_mu);
    done_cv.wait(lk, [&] { return finished.load() == T; });
    lk.unlock();
    const auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::max(SteadyClock::duration::zero(), SteadyClock::now() - ctx.start_tp))
                         .count();
    emit_progress(0, dur);
  }
  for (auto &t : threads) t.join();
  // Every stream has finished: the driver executors are idle.
  for (auto &d : drivers) d->stop_and_join();

  PhaseEvent done;
  done.set_state(PhaseEvent::DONE);
  done.mutable_run_summary()->set_worker_index(ctx.worker_index);
  for (auto c : op_->thread_counts()) done.mutable_run_summary()->add_thread_counts(c);
  if (ctx.failed) {
    std::lock_guard<std::mutex> g(ctx.err_mu);
    done.set_error(ctx.error);
  }
  s->Write(done);
  reader.join();  // returns once the controller half-closes
  return grpc::Status::OK;
}

grpc::Status WorkerService::Verify(grpc::ServerContext *, const perf::v1::VerifyRequest *req,
                                   grpc::ServerWriter<PhaseEvent> *w)
{
  PhaseEvent ev;
  ev.set_state(PhaseEvent::DONE);
  if (!ctx_ || !op_) {
    ev.set_error("Verify without Init");
    w->Write(ev);
    return grpc::Status::OK;
  }
  if (op_->has_verify()) {
    std::vector<uint64_t> counts(req->thread_counts().begin(), req->thread_counts().end());
    VerifyReport rep;
    std::string err;
    // verify() blocks, so run it on its own thread and stream progress from this one (the
    // ServerWriter must only be used from the RPC thread).
    std::atomic<bool> finished{false};
    std::mutex done_mu;
    std::condition_variable done_cv;
    std::thread vt([&] {
      try {
        err = op_->verify(*ctx_, counts, &rep);
      } catch (const std::exception &e) {
        err = std::string("verify exception: ") + e.what();
      }
      {
        std::lock_guard<std::mutex> g(done_mu);
        finished = true;
      }
      done_cv.notify_one();
    });
    const auto interval = std::chrono::milliseconds(req->report_interval_ms());
    if (interval.count() > 0) {
      std::unique_lock<std::mutex> lk(done_mu);
      while (!done_cv.wait_for(lk, interval, [&] { return finished.load(); })) {
        PhaseEvent pe;
        pe.set_state(PhaseEvent::READY);
        auto *vp = pe.mutable_verify_progress();
        vp->set_worker_index(ctx_->worker_index);
        vp->set_keys_checked(ctx_->verify_keys_checked.load());
        vp->set_keys_total(ctx_->verify_keys_total.load());
        if (!w->Write(pe)) break;  // controller went away; still wait for verify to finish
      }
    }
    vt.join();
    auto *vr = ev.mutable_verify();
    for (const auto &b : rep.buckets) {
      auto *o = vr->add_buckets();
      o->set_bucket(b.bucket);
      o->set_expected(b.expected);
      o->set_found(b.found);
      o->set_missing(b.missing);
      for (const auto &k : b.missing_keys) o->add_missing_keys(k);
    }
    vr->set_keys_checked(rep.keys_checked);
    vr->set_bad_key(rep.bad_key);
    vr->set_out_of_range(rep.out_of_range);
    vr->set_unexpected(rep.unexpected);
    vr->set_duplicate(rep.duplicate);
    vr->set_other_failures(rep.other_failures);
    for (const auto &sm : rep.samples) vr->add_samples(sm);
    if (!err.empty()) ev.set_error(err);
  }
  w->Write(ev);
  return grpc::Status::OK;
}

grpc::Status WorkerService::Cleanup(grpc::ServerContext *, const perf::v1::CleanupRequest *,
                                    grpc::ServerWriter<PhaseEvent> *w)
{
  {
    std::lock_guard<std::mutex> g(mu_);
    op_.reset();
    ctx_.reset();
    stats_.reset();
  }
  PhaseEvent ev;
  ev.set_state(PhaseEvent::DONE);
  w->Write(ev);
  return grpc::Status::OK;
}

}  // namespace perfw
