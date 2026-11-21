#include "ops.hpp"

#include "error_codes.hpp"

namespace perfw {

namespace {

class ListObjectsOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    mine_ = my_buckets(ctx);
    return check_buckets(ctx, mine_);
  }

  void run_thread(RunContext &ctx, int tid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gtid = ctx.gsid(tid);
    ThreadStats &ts = ctx.stats->thread(tid);
    const auto prefixes = prefix_items(ctx.cfg.padding_bytes);
    // Work items: (bucket, prefix) over owned buckets; stream t takes items t, t+S, ...
    const auto items = items_for(ctx, tid, prefixes);
    if (items.empty()) return;
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gtid) : UINT64_MAX;
    uint64_t done = 0;
    size_t cur = 0;
    std::string token;
    while (!ctx.stopped() && done < quota && !ctx.expired()) {
      const auto &[b, prefix] = items[cur];
      kvrgw::KvRgwServiceImpl::ListObjectsResult res;
      auto t0 = SteadyClock::now();
      // list_objects records its own server-side latency (once per call).
      kvrgw::KvrgwErrorCode ec =
          ctx.svc->list_objects(ctx.tenant, ctx.bucket(b), *prefix, "",
                                static_cast<uint32_t>(ctx.cfg.page_size), token, "", &res);
      ++done;
      if (ec != kvrgw::KVRGW_ERR_OK) {
        record_op_error(ts, Metric::ListObjects, ec);
        log_op_error("list_objects " + ctx.bucket(b) + " prefix '" + *prefix + "'", describe_error(ec));
        token.clear();
        cur = (cur + 1) % items.size();
        continue;
      }
      ts.record(Metric::ListObjects, static_cast<uint64_t>(elapsed_us(t0)));
      ts.add_units(Metric::KeysListed, res.objects.size());
      if (res.is_truncated && !res.next_continuation_token.empty()) {
        token = std::move(res.next_continuation_token);
      } else {
        token.clear();
        cur = (cur + 1) % items.size();
      }
    }
  }

  // Work items for local stream `sid` of S: (bucket, prefix) pairs n with n % S == sid.
  std::vector<std::pair<uint64_t, const std::string *>> items_for(
      const RunContext &ctx, int sid, const std::vector<std::string> &prefixes) const
  {
    std::vector<std::pair<uint64_t, const std::string *>> items;
    size_t n = 0;
    for (uint64_t b : mine_) {
      for (const auto &p : prefixes) {
        if (n++ % static_cast<size_t>(ctx.streams()) == static_cast<size_t>(sid)) {
          items.emplace_back(b, &p);
        }
      }
    }
    return items;
  }

  kvrgw::async::Task<void> run_stream(RunContext &ctx, Stream &s) override
  {
    const auto prefixes = prefix_items(ctx.cfg.padding_bytes);
    const auto items = items_for(ctx, s.sid, prefixes);
    if (items.empty()) co_return;
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(s.gsid) : UINT64_MAX;
    uint64_t done = 0;
    size_t cur = 0;
    int queue_full_in_a_row = 0;
    std::string token;
    while (!ctx.stopped() && done < quota && !ctx.expired()) {
      const auto &[b, prefix] = items[cur];
      kvrgw::KvRgwServiceImpl::ListObjectsResult res;
      const auto t0 = SteadyClock::now();
      const kvrgw::KvrgwErrorCode ec = co_await ctx.svc->list_objects_a(
          ctx.tenant, ctx.bucket(b), *prefix, "", static_cast<uint32_t>(ctx.cfg.page_size), token,
          "", &res);
      if (ec == kvrgw::KVRGW_ERR_QUEUE_FULL) {
        s.ts->add_queue_full(Metric::ListObjects);
        co_await s.exec->sleep(queue_full_backoff(queue_full_in_a_row++));
        continue;
      }
      queue_full_in_a_row = 0;
      ++done;
      if (ec != kvrgw::KVRGW_ERR_OK) {
        record_op_error(*s.ts, Metric::ListObjects, ec);
        log_op_error("list_objects " + ctx.bucket(b) + " prefix '" + *prefix + "'", describe_error(ec));
        token.clear();
        cur = (cur + 1) % items.size();
        continue;
      }
      s.ts->record(Metric::ListObjects, static_cast<uint64_t>(elapsed_us(t0)));
      s.ts->add_units(Metric::KeysListed, res.objects.size());
      if (res.is_truncated && !res.next_continuation_token.empty()) {
        token = std::move(res.next_continuation_token);
      } else {
        token.clear();
        cur = (cur + 1) % items.size();
      }
    }
  }

  std::string verify(RunContext &ctx, const std::vector<uint64_t> &, VerifyReport *out) override
  {
    return verify_load_family(
        ctx, mine_,
        [&](uint64_t b) { return bucket_range(b, ctx.cfg.num_buckets, ctx.cfg.num_objects); },
        nullptr, out);
  }

 private:
  static std::vector<uint64_t> my_buckets(const RunContext &ctx)
  {
    if (ctx.cfg.single_thread_mode) {
      return ctx.worker_index == 0 ? std::vector<uint64_t>{0} : std::vector<uint64_t>{};
    }
    return owned_buckets(ctx.worker_index, ctx.worker_count, ctx.cfg.num_buckets);
  }
  std::vector<uint64_t> mine_;
};

}  // namespace

std::unique_ptr<Operation> make_list_objects_op() { return std::make_unique<ListObjectsOp>(); }

}  // namespace perfw
