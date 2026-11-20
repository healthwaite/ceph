#include "ops.hpp"

#include <algorithm>
#include <atomic>
#include <thread>

namespace perfw {

namespace {

// Shared by run-put-object-overwrite and run-put-object-overwrite-versioned.
//
// Each thread loops over a "window": the first part of its own contiguous slice of the object
// index space, putting the keys in order, round-robin.
//
// - run-put-object-overwrite has no limit: the window is the thread's whole slice, so every
//   loaded key is overwritten. It must run on never-versioned buckets (as `load` creates them),
//   so that each put replaces the object in place: init requires versioning to be DISABLED, every
//   put must report no new version, and verify lists through list_object_versions and fails if
//   any key has more than a single null version (or a delete marker), i.e. if the bucket has ever
//   been versioned.
// - run-put-object-overwrite-versioned limits the windows to num_objects_to_overwrite keys in
//   total across all workers * threads (shared evenly), and the limit matters in two ways.
//   First, the check counts the versions of each key and compares them with the number of times
//   the run wrote it. That is only meaningful if keys are written repeatedly; a window much
//   larger than the number of puts the run can do leaves most keys with 0 or 1 versions and
//   verifies almost nothing. Second, verification makes one list_object_versions call per window
//   key, so the window size bounds how long verification takes. (Verification needs no per-key
//   state: only a put count per thread, from which each key's expected version count follows.)
class OverwriteOp : public Operation {
 public:
  explicit OverwriteOp(bool versioned) : versioned_(versioned) {}

  std::string init(RunContext &ctx) override
  {
    puts_.assign(static_cast<size_t>(ctx.cfg.threads_per_worker), 0);
    std::vector<uint64_t> all;
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) all.push_back(b);
    if (!versioned_) return check_buckets(ctx, all, VersioningCheck::kUnversioned);
    // Versioned: the buckets must exist (load made them, unversioned) and worker 0 enables
    // versioning (the controller has already asked the user to confirm). The other workers
    // need not wait: the controller starts the benchmark only after every worker's init is done.
    if (auto err = check_buckets(ctx, all); !err.empty()) return err;
    if (ctx.worker_index != 0) return {};
    for (uint64_t b : all) {
      auto ec = ctx.svc->put_bucket_versioning(ctx.tenant, ctx.bucket(b), kvrgw::VERSIONING_ENABLED);
      if (ec != kvrgw::KVRGW_ERR_OK) {
        return "put_bucket_versioning " + ctx.bucket(b) + ": " + describe_error(ec);
      }
    }
    return check_buckets(ctx, all, VersioningCheck::kEnabled);
  }

  Range window(const RunContext &ctx, uint64_t gtid) const
  {
    return overwrite_window(gtid, static_cast<uint64_t>(ctx.total_threads()), ctx.cfg.num_objects,
                            versioned_ ? ctx.cfg.num_objects_to_overwrite : 0);
  }

  void run_thread(RunContext &ctx, int tid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gtid = static_cast<uint64_t>(ctx.worker_index * ctx.cfg.threads_per_worker + tid);
    const Range w = window(ctx, gtid);
    if (w.count == 0) return;
    ThreadStats &ts = ctx.stats->thread(tid);
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gtid) : UINT64_MAX;
    uint64_t puts = 0;
    while (!ctx.stopped() && puts < quota && !ctx.expired()) {
      const uint64_t i = w.start + puts % w.count;
      const auto b = bucket_for_index(i, ctx.cfg.num_objects, ctx.cfg.num_buckets);
      bool created_version = false;
      if (!put_with_retry(ctx, ts, ctx.bucket(b), load_key(i, ctx.cfg.padding_bytes),
                          versioned_ ? nullptr : &created_version)) {
        break;
      }
      if (created_version) {
        // The put added a version instead of replacing the object, so this run is not measuring
        // an unversioned overwrite.
        ctx.fail("put_object created a new version in " + ctx.bucket(b) +
                 ": the bucket has versioning enabled; run-put-object-overwrite needs "
                 "never-versioned buckets (use a new bucket_name_prefix and load)");
        break;
      }
      ++puts;
      puts_[static_cast<size_t>(tid)] = puts;
    }
  }

  std::vector<uint64_t> thread_counts() const override { return puts_; }

  std::string verify(RunContext &ctx, const std::vector<uint64_t> &counts,
                     VerifyReport *out) override
  {
    if (!versioned_) {
      auto mine = owned_buckets(ctx.worker_index, ctx.worker_count, ctx.cfg.num_buckets);
      return verify_load_family(
          ctx, mine,
          [&](uint64_t b) { return bucket_range(b, ctx.cfg.num_buckets, ctx.cfg.num_objects); },
          nullptr, out, /*scan_versions=*/true);
    }
    (void)counts;
    return verify_versions(ctx, out);
  }

 private:
  // Point-lookup verification of version counts for this worker's own windows.
  std::string verify_versions(RunContext &ctx, VerifyReport *out)
  {
    const int T = ctx.cfg.threads_per_worker;
    std::vector<uint64_t> cum(static_cast<size_t>(T) + 1, 0);  // prefix sums of window sizes
    for (int t = 0; t < T; ++t) {
      const uint64_t gtid = static_cast<uint64_t>(ctx.worker_index * T + t);
      cum[static_cast<size_t>(t) + 1] = cum[static_cast<size_t>(t)] + window(ctx, gtid).count;
    }
    const uint64_t total = cum.back();
    ctx.verify_keys_total = total;
    Failures f(ctx.verify_keys_checked);
    std::atomic<uint64_t> next{0};
    auto work = [&]() {
      for (;;) {
        const uint64_t n = next.fetch_add(1);
        if (n >= total) return;
        const int t = static_cast<int>(std::upper_bound(cum.begin(), cum.end(), n) - cum.begin()) - 1;
        const uint64_t gtid = static_cast<uint64_t>(ctx.worker_index * T + t);
        const Range w = window(ctx, gtid);
        const uint64_t p = n - cum[static_cast<size_t>(t)];
        const uint64_t id = w.start + p;
        const std::string key = load_key(id, ctx.cfg.padding_bytes);
        const auto &bucket = ctx.bucket(bucket_for_index(id, ctx.cfg.num_objects, ctx.cfg.num_buckets));
        const uint64_t want = expected_versions(puts_[static_cast<size_t>(t)], w.count, p);
        uint64_t got = 0;
        std::string key_marker;
        kvrgw::version_id_t vid_marker{};
        bool err = false;
        for (;;) {
          kvrgw::KvRgwServiceImpl::ListObjectVersionsResult res;
          auto ec = ctx.svc->list_object_versions(ctx.tenant, bucket, key, 1000, key_marker,
                                                  vid_marker, &res);
          if (ec != kvrgw::KVRGW_ERR_OK) {
            ++f.other;
            f.sample("list_object_versions " + key + ": " + describe_error(ec));
            err = true;
            break;
          }
          for (const auto &v : res.versions) {
            if (v.key == key && !v.is_delete_marker &&
                v.last_modified_unix >= ctx.bench_start_unix_s) {
              ++got;
            }
          }
          if (!res.is_truncated) break;
          key_marker = res.next_key_marker;
          vid_marker = res.next_version_id_marker;
        }
        ++f.keys_checked;
        if (!err && got != want) {
          ++f.other;
          f.sample("version count mismatch for " + bucket + "/" + key + ": expected " +
                   std::to_string(want) + " got " + std::to_string(got));
        }
      }
    };
    std::vector<std::thread> ts;
    for (int i = 1; i < ctx.cfg.verify_threads; ++i) ts.emplace_back(work);
    work();
    for (auto &t : ts) t.join();
    out->take(f);
    return {};
  }

  bool versioned_;
  std::vector<uint64_t> puts_;
};

}  // namespace

std::unique_ptr<Operation> make_overwrite_op(bool versioned)
{
  return std::make_unique<OverwriteOp>(versioned);
}

}  // namespace perfw
