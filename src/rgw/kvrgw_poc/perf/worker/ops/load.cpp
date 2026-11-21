#include "ops.hpp"

#include "error_codes.hpp"

namespace perfw {

namespace {

class LoadOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    if (ctx.worker_index != 0) return {};
    // KvrgwServiceImpl::create_bucket is idempotent, so detect pre-existing buckets explicitly:
    // load into existing buckets is a hard error (the caller must clean up) unless --force,
    // which keeps them (and their objects, and their versioning state) and only creates the missing ones.
    std::vector<bool> existing(ctx.cfg.num_buckets, false);
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) {
      bool exists = false;
      auto ec = ctx.svc->bucket_exists(ctx.tenant, ctx.bucket(b), &exists);
      if (ec != kvrgw::KVRGW_ERR_OK) {
        return "bucket_exists " + ctx.bucket(b) + ": " + describe_error(ec);
      }
      if (exists && !ctx.cfg.force) {
        return "bucket " + ctx.bucket(b) + " already exists (clean up before load, or use --force)";
      }
      existing[b] = exists;
    }
    // Buckets are left unversioned: run-put-object-overwrite needs never-versioned buckets, and
    // run-put-object-overwrite-versioned enables versioning itself.
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) {
      if (existing[b]) continue;
      auto ec = ctx.svc->create_bucket(ctx.tenant, ctx.bucket(b));
      if (ec != kvrgw::KVRGW_ERR_OK) {
        return "create_bucket " + ctx.bucket(b) + ": " + describe_error(ec) +
               (ec == kvrgw::KVRGW_ERR_BUCKET_ALREADY_EXISTS ? " (clean up before load)" : "");
      }
    }
    return {};
  }

  void run_thread(RunContext &ctx, int sid) override
  {
    if (!ctx.wait_start()) return;
    Range r = index_range(ctx.gsid(sid), static_cast<uint64_t>(ctx.total_streams()), ctx.cfg.num_objects);
    ThreadStats &ts = ctx.stats->thread(sid);
    for (uint64_t i = r.start; i < r.end() && !ctx.stopped(); ++i) {
      const auto b = bucket_for_index(i, ctx.cfg.num_objects, ctx.cfg.num_buckets);
      if (!put_with_retry(ctx, ts, ctx.bucket(b), load_key(i, ctx.cfg.padding_bytes))) return;
    }
  }

  kvrgw::async::Task<void> run_stream(RunContext &ctx, Stream &s) override
  {
    Range r = index_range(s.gsid, static_cast<uint64_t>(ctx.total_streams()), ctx.cfg.num_objects);
    for (uint64_t i = r.start; i < r.end() && !ctx.stopped(); ++i) {
      const auto b = bucket_for_index(i, ctx.cfg.num_objects, ctx.cfg.num_buckets);
      const std::string key = load_key(i, ctx.cfg.padding_bytes);
      if (!co_await put_with_retry_a(ctx, s, ctx.bucket(b), key)) co_return;
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
