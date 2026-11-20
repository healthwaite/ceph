#include "ops.hpp"

#include "error_codes.hpp"

namespace perfw {

namespace {

class LoadOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    if (ctx.worker_index != 0) return {};
    // KvRgwServiceImpl::create_bucket is idempotent, so detect pre-existing buckets explicitly:
    // load into existing buckets is a hard error (the caller must clean up).
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) {
      bool exists = false;
      auto ec = ctx.svc->bucket_exists(ctx.tenant, ctx.bucket(b), &exists);
      if (ec != kvrgw::KVRGW_ERR_OK) {
        return "bucket_exists " + ctx.bucket(b) + ": " + describe_error(ec);
      }
      if (exists) {
        return "bucket " + ctx.bucket(b) + " already exists (clean up before load)";
      }
    }
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) {
      auto ec = ctx.svc->create_bucket(ctx.tenant, ctx.bucket(b));
      if (ec != kvrgw::KVRGW_ERR_OK) {
        return "create_bucket " + ctx.bucket(b) + ": " + describe_error(ec) +
               (ec == kvrgw::KVRGW_ERR_BUCKET_ALREADY_EXISTS ? " (clean up before load)" : "");
      }
      ec = ctx.svc->put_bucket_versioning(ctx.tenant, ctx.bucket(b), kvrgw::VERSIONING_ENABLED);
      if (ec != kvrgw::KVRGW_ERR_OK) {
        return "put_bucket_versioning " + ctx.bucket(b) + ": " + describe_error(ec);
      }
    }
    return {};
  }

  void run_thread(RunContext &ctx, int tid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gtid = static_cast<uint64_t>(ctx.worker_index * ctx.cfg.threads_per_worker + tid);
    Range r = index_range(gtid, static_cast<uint64_t>(ctx.total_threads()), ctx.cfg.num_objects);
    ThreadStats &ts = ctx.stats->thread(tid);
    for (uint64_t i = r.start; i < r.end() && !ctx.stopped(); ++i) {
      const auto b = bucket_for_index(i, ctx.cfg.num_objects, ctx.cfg.num_buckets);
      if (!put_with_retry(ctx, ts, ctx.bucket(b), load_key(i, ctx.cfg.padding_bytes))) return;
    }
  }

  std::string verify(RunContext &ctx, const std::vector<uint64_t> &, VerifyReport *out) override
  {
    auto mine = owned_buckets(ctx.worker_index, ctx.worker_count, ctx.cfg.num_buckets);
    return verify_load_family(
        ctx, mine,
        [&](uint64_t b) { return bucket_range(b, ctx.cfg.num_buckets, ctx.cfg.num_objects); },
        nullptr, out);
  }
};

}  // namespace

std::unique_ptr<Operation> make_load_op() { return std::make_unique<LoadOp>(); }

}  // namespace perfw
