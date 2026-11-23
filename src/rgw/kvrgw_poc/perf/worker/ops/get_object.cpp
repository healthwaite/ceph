#include "ops.hpp"

#include "error_codes.hpp"

namespace perfw {

namespace {

// run-get-object: every stream reads keys picked uniformly at random from the loaded id
// space [0, num_objects). A key that does not exist (or any other failure) is counted as an
// error against get_object; it is not retried and does not stop the run. There is no verify
// stage: the run changes nothing.
class GetObjectOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    std::vector<uint64_t> all;
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) all.push_back(b);
    return check_buckets(ctx, all);
  }

  // Per-stream generator: a distinct, run-dependent seed for every global stream.
  static uint64_t seed_for(const RunContext &ctx, uint64_t gsid)
  {
    return splitmix64_mix(static_cast<uint64_t>(ctx.run_start_unix_s) * 1000003ull + gsid);
  }

  static void pick(const RunContext &ctx, uint64_t &rng, std::string *bucket, std::string *key)
  {
    const uint64_t i = splitmix64_next(rng) % ctx.cfg.num_objects;
    *bucket = ctx.bucket(bucket_for_index(i, ctx.cfg.num_objects, ctx.cfg.num_buckets));
    *key = load_key(i, ctx.cfg.padding_bytes);
  }

  void run_thread(RunContext &ctx, int sid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gsid = ctx.gsid(sid);
    ThreadStats &ts = ctx.stats->thread(sid);
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gsid) : UINT64_MAX;
    uint64_t rng = seed_for(ctx, gsid);
    uint64_t done = 0;
    std::string bucket, key;
    kvrgw::KvRgwServiceImpl::GetObjectResult res;
    while (!ctx.stopped() && done < quota && !ctx.expired()) {
      pick(ctx, rng, &bucket, &key);
      res = {};
      const auto t0 = SteadyClock::now();
      const auto ec = ctx.svc->get_object(ctx.tenant, bucket, key, std::nullopt, nullptr, 0, &res);
      ++done;
      if (ec != kvrgw::KVRGW_ERR_OK) {
        record_op_error(ts, Metric::GetObject, ec);
        log_op_error("get_object " + bucket + "/" + short_key(key), describe_error(ec));
        continue;
      }
      ts.record(Metric::GetObject, static_cast<uint64_t>(elapsed_us(t0)));
    }
  }

  kvrgw::async::Task<void> run_stream(RunContext &ctx, Stream &s) override
  {
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(s.gsid) : UINT64_MAX;
    uint64_t rng = seed_for(ctx, s.gsid);
    uint64_t done = 0;
    int queue_full_in_a_row = 0;
    std::string bucket, key;
    kvrgw::KvRgwServiceImpl::GetObjectResult res;
    bool have_key = false;
    while (!ctx.stopped() && done < quota && !ctx.expired()) {
      // Keep the same key across QUEUE_FULL backoffs (not an op).
      if (!have_key) pick(ctx, rng, &bucket, &key);
      have_key = true;
      res = {};
      const auto t0 = SteadyClock::now();
      const kvrgw::KvrgwErrorCode ec = co_await ctx.svc->get_object_a(
          ctx.tenant, bucket, key, std::nullopt, nullptr, 0, &res);
      if (ec == kvrgw::KVRGW_ERR_QUEUE_FULL) {
        s.ts->add_queue_full(Metric::GetObject);
        co_await s.exec->sleep(queue_full_backoff(queue_full_in_a_row++));
        continue;
      }
      queue_full_in_a_row = 0;
      have_key = false;
      ++done;
      if (ec != kvrgw::KVRGW_ERR_OK) {
        record_op_error(*s.ts, Metric::GetObject, ec);
        log_op_error("get_object " + bucket + "/" + short_key(key), describe_error(ec));
        continue;
      }
      s.ts->record(Metric::GetObject, static_cast<uint64_t>(elapsed_us(t0)));
    }
  }

  bool has_verify() const override { return false; }
  std::string verify(RunContext &, const std::vector<uint64_t> &, VerifyReport *) override
  {
    return {};
  }
};

}  // namespace

std::unique_ptr<Operation> make_get_object_op() { return std::make_unique<GetObjectOp>(); }

}  // namespace perfw
