// run-list-delete-multi: empty buckets the way a client would. Each thread pages through its
// two-character key prefixes with a continuation token; every page is deleted with delete_multi.
#include "ops.hpp"

#include "error_codes.hpp"

#include <algorithm>
#include <atomic>
#include <memory>

namespace perfw {

namespace {

class ListDeleteMultiOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    if (ctx.cfg.padding_bytes < 2) return "run-list-delete-multi needs padding_bytes >= 2";
    mine_ = my_buckets(ctx);
    deleted_.assign(static_cast<size_t>(ctx.cfg.threads_per_worker), 0);
    deleted_per_bucket_ = std::make_unique<std::atomic<uint64_t>[]>(ctx.cfg.num_buckets);
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) deleted_per_bucket_[b] = 0;
    return check_buckets(ctx, mine_);
  }

  void run_thread(RunContext &ctx, int tid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gtid = static_cast<uint64_t>(ctx.worker_index * ctx.cfg.threads_per_worker + tid);
    ThreadStats &ts = ctx.stats->thread(tid);
    // Work items: (bucket, 2-char prefix); thread t takes items t, t+T, ... so each thread gets
    // an even share of the 70 x 70 prefixes of every owned bucket.
    const auto singles = prefix_items(ctx.cfg.padding_bytes);
    std::vector<std::pair<uint64_t, std::string>> items;
    size_t n = 0;
    for (uint64_t b : mine_) {
      for (const auto &p1 : singles) {
        for (const auto &p2 : singles) {
          if (n++ % static_cast<size_t>(ctx.cfg.threads_per_worker) == static_cast<size_t>(tid)) {
            items.emplace_back(b, p1 + p2);
          }
        }
      }
    }
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gtid) : UINT64_MAX;
    uint64_t iterations = 0, total_deleted = 0;
    size_t cur = 0;
    std::string token;
    std::vector<std::string> keys;
    std::vector<kvrgw::KvRgwServiceImpl::DeleteMultiKeyOutcome> outcomes;
    auto next_prefix = [&] {
      token.clear();
      ++cur;
    };
    while (cur < items.size() && !ctx.stopped() && iterations < quota && !ctx.expired()) {
      const auto &[b, prefix] = items[cur];
      const auto t_iter = SteadyClock::now();
      kvrgw::KvRgwServiceImpl::ListObjectsResult res;
      // The service records its own ListObjects/DeleteMulti stats; the timers here feed the
      // per-thread stats, including the combined list+delete latency.
      auto t0 = SteadyClock::now();
      auto ec = ctx.svc->list_objects(ctx.tenant, ctx.bucket(b), prefix, "",
                                      static_cast<uint32_t>(ctx.cfg.page_size), token, "", &res);
      if (ec != kvrgw::KVRGW_ERR_OK) {
        record_op_error(ts, Metric::ListObjects, ec);
        log_op_error("list_objects " + ctx.bucket(b) + " prefix '" + prefix + "'", describe_error(ec));
        ++iterations;
        next_prefix();  // keys of this prefix are left behind; verify will report them
        continue;
      }
      ts.record(Metric::ListObjects, static_cast<uint64_t>(elapsed_us(t0)));
      ts.add_units(Metric::KeysListed, res.objects.size());
      const bool more = res.is_truncated && !res.next_continuation_token.empty();
      if (res.objects.empty()) {  // empty prefix: nothing to delete, not an iteration
        if (more) token = std::move(res.next_continuation_token); else next_prefix();
        continue;
      }
      keys.clear();
      for (auto &o : res.objects) keys.push_back(std::move(o.key));
      outcomes.clear();
      t0 = SteadyClock::now();
      ec = ctx.svc->delete_multi(ctx.tenant, ctx.bucket(b), keys, {}, &outcomes);
      const auto delete_us = static_cast<uint64_t>(elapsed_us(t0));
      ++iterations;
      std::string bad;
      if (ec != kvrgw::KVRGW_ERR_OK) {
        bad = describe_error(ec);
        record_op_error(ts, Metric::DeleteMulti, ec);
      } else {
        for (const auto &o : outcomes) {
          if (o.status == kvrgw::KvRgwServiceImpl::DeleteMultiKeyOutcome::Status::Error) {
            bad = "key " + o.key + ": " + o.error_code + " (" + o.error_message + ")";
            register_error_text(o.error_code, o.error_message);
            ts.record_error(Metric::DeleteMulti, o.error_code);
            break;
          }
        }
      }
      if (!bad.empty()) {
        ctx.fail("delete_multi " + ctx.bucket(b) + " failed: " + bad);
        break;
      }
      ts.record(Metric::DeleteMulti, delete_us);
      ts.record(Metric::ListDeleteMulti, static_cast<uint64_t>(elapsed_us(t_iter)));
      ts.add_units(Metric::KeysDeleted, keys.size());
      total_deleted += keys.size();
      deleted_[static_cast<size_t>(tid)] = total_deleted;
      deleted_per_bucket_[b].fetch_add(keys.size());
      if (more) token = std::move(res.next_continuation_token); else next_prefix();
    }
  }

  std::vector<uint64_t> thread_counts() const override { return deleted_; }

  // Which keys were deleted is not an id range, so check counts: each bucket must hold exactly
  // (loaded keys - keys this run deleted from it). Every listed key must still be a valid load
  // key (verify_bucket_load checks that), so a wrong count shows as missing or unexpected keys.
  std::string verify(RunContext &ctx, const std::vector<uint64_t> &, VerifyReport *out) override
  {
    Failures f(ctx.verify_keys_checked);
    const auto prefixes = prefix_items(ctx.cfg.padding_bytes);
    uint64_t total = 0;
    for (uint64_t b : mine_) {
      total += bucket_range(b, ctx.cfg.num_buckets, ctx.cfg.num_objects).count -
               deleted_per_bucket_[b].load();
    }
    ctx.verify_keys_total = total;
    for (uint64_t b : mine_) {
      ServiceLister lister(*ctx.svc, ctx.tenant, ctx.bucket(b));
      const Range r = bucket_range(b, ctx.cfg.num_buckets, ctx.cfg.num_objects);
      LoadSpace sp;
      sp.start = r.start;
      sp.count = r.count;
      sp.padding = ctx.cfg.padding_bytes;
      BucketResult res = verify_bucket_load(lister, ctx.bucket(b), sp, prefixes, ctx.cfg.verify_threads, f);
      // verify_bucket_load expects every id; the deleted ones show as "missing". Re-express the
      // result against the expected remaining count.
      const uint64_t deleted = deleted_per_bucket_[b].load();
      res.expected = r.count - std::min(deleted, r.count);
      res.missing = res.expected > res.found ? res.expected - res.found : 0;
      res.missing_keys.clear();  // the deleted set is unknown, so there is nothing useful to list
      if (res.found > res.expected) {
        f.unexpected += res.found - res.expected;
        f.sample("more keys than expected in " + ctx.bucket(b) + ": found " + std::to_string(res.found) +
                 ", expected " + std::to_string(res.expected));
      }
      out->buckets.push_back(std::move(res));
    }
    out->take(f);
    return {};
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
  std::vector<uint64_t> deleted_;  // per local thread
  std::unique_ptr<std::atomic<uint64_t>[]> deleted_per_bucket_;
};

}  // namespace

std::unique_ptr<Operation> make_list_delete_multi_op() { return std::make_unique<ListDeleteMultiOp>(); }

}  // namespace perfw
