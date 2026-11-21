#include "ops.hpp"

namespace perfw {

namespace {

class PutObjectOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    counts_.assign(static_cast<size_t>(ctx.streams()), 0);
    std::vector<uint64_t> all;
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) all.push_back(b);
    return check_buckets(ctx, all);
  }

  void run_thread(RunContext &ctx, int sid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gsid = ctx.gsid(sid);
    const std::string &bucket = ctx.bucket(gsid % ctx.cfg.num_buckets);
    ThreadStats &ts = ctx.stats->thread(sid);
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gsid) : UINT64_MAX;
    uint64_t counter = 0;
    while (!ctx.stopped() && counter < quota && !ctx.expired()) {
      if (!put_with_retry(ctx, ts, bucket,
                          put_key(static_cast<uint64_t>(ctx.run_start_unix_s),
                                  static_cast<uint32_t>(gsid), counter, ctx.cfg.padding_bytes))) {
        break;
      }
      ++counter;
      counts_[static_cast<size_t>(sid)] = counter;
    }
  }

  // The run_thread loop with co_await.
  kvrgw::async::Task<void> run_stream(RunContext &ctx, Stream &s) override
  {
    const std::string &bucket = ctx.bucket(s.gsid % ctx.cfg.num_buckets);
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(s.gsid) : UINT64_MAX;
    for (uint64_t n = 0; !ctx.stopped() && n < quota && !ctx.expired();) {
      // Owned by this frame: put_object_a views it until it completes.
      const std::string key = put_key(static_cast<uint64_t>(ctx.run_start_unix_s),
                                      static_cast<uint32_t>(s.gsid), n, ctx.cfg.padding_bytes);
      if (!co_await put_with_retry_a(ctx, s, bucket, key)) break;
      counts_[static_cast<size_t>(s.sid)] = ++n;
    }
  }

  std::vector<uint64_t> thread_counts() const override { return counts_; }

  std::string verify(RunContext &ctx, const std::vector<uint64_t> &counts,
                     VerifyReport *out) override
  {
    if (counts.size() != static_cast<size_t>(ctx.total_streams())) {
      return "verify: thread_counts has wrong length";
    }
    Failures f(ctx.verify_keys_checked);
    auto prefixes = prefix_items(ctx.cfg.padding_bytes);
    for (uint64_t b : owned_buckets(ctx.worker_index, ctx.worker_count, ctx.cfg.num_buckets)) {
      ServiceLister lister(*ctx.svc, ctx.tenant, ctx.bucket(b));
      PutSpace sp;
      sp.bucket_index = b;
      sp.num_buckets = ctx.cfg.num_buckets;
      sp.ts = static_cast<uint64_t>(ctx.run_start_unix_s);
      sp.padding = ctx.cfg.padding_bytes;
      sp.thread_counts = &counts;
      out->buckets.push_back(
          verify_bucket_put(lister, ctx.bucket(b), sp, prefixes, ctx.cfg.verify_threads, f));
    }
    out->take(f);
    return {};
  }

 private:
  std::vector<uint64_t> counts_;  // each element written by one stream only
};

}  // namespace

std::unique_ptr<Operation> make_put_object_op() { return std::make_unique<PutObjectOp>(); }

}  // namespace perfw
