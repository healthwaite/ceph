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
    const uint64_t gtid = static_cast<uint64_t>(ctx.worker_index * ctx.cfg.threads_per_worker + tid);
    ThreadStats &ts = ctx.stats->thread(tid);
    const auto prefixes = prefix_items(ctx.cfg.padding_bytes);
    // Work items: (bucket, prefix) over owned buckets; thread t takes items t, t+T, ...
    std::vector<std::pair<uint64_t, const std::string *>> items;
    size_t n = 0;
    for (uint64_t b : mine_) {
      for (const auto &p : prefixes) {
        if (n++ % static_cast<size_t>(ctx.cfg.threads_per_worker) == static_cast<size_t>(tid)) {
          items.emplace_back(b, &p);
        }
      }
    }
    if (items.empty()) return;
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gtid) : UINT64_MAX;
    uint64_t done = 0;
    size_t cur = 0;
    std::string token;
    while (!ctx.stopped() && done < quota && !ctx.expired()) {
      const auto &[b, prefix] = items[cur];
      kvrgw::KvRgwServiceImpl::ListObjectsResult res;
      auto t0 = SteadyClock::now();
      kvrgw::KvrgwErrorCode ec;
      {
        kvrgw::ScopedRequestLatency lat(ctx.svc->latency_stats(), kvrgw::OpType::kListObjects);
        ec = ctx.svc->list_objects(ctx.tenant, ctx.bucket(b), *prefix, "",
                                   static_cast<uint32_t>(ctx.cfg.page_size), token, "", &res);
      }
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
