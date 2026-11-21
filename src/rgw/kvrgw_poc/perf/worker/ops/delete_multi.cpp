#include "ops.hpp"

#include "error_codes.hpp"

#include <algorithm>

namespace perfw {

namespace {

class DeleteMultiOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    deleted_.assign(static_cast<size_t>(ctx.streams()), 0);
    std::vector<uint64_t> all;
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) all.push_back(b);
    std::string err = check_buckets(ctx, all);
    if (!err.empty()) return err;
    if (ctx.cfg.has_ops()) {
      // Each thread stops at the end of its range, so --ops must not ask any thread for more
      // delete_multi calls than it needs to cover its range.
      for (int t = 0; t < ctx.streams(); ++t) {
        const uint64_t gtid = ctx.gsid(t);
        const uint64_t quota = ctx.ops_quota(gtid);
        const uint64_t need = batches_needed(ctx, thread_range(ctx, gtid));
        if (quota > need) {
          return "ops (" + std::to_string(ctx.cfg.ops) + ") is too large: thread " + std::to_string(gtid) +
                 " would run " + std::to_string(quota) + " delete_multi calls but only " +
                 std::to_string(need) + " cover its keys (page_size " + std::to_string(ctx.cfg.page_size) +
                 "); each call deletes up to page_size keys, so lower --ops";
        }
      }
    }
    return {};
  }

  // delete_multi calls needed to cover range r (batches never cross a bucket boundary).
  static uint64_t batches_needed(const RunContext &ctx, const Range &r)
  {
    uint64_t n = 0;
    for (uint64_t first = r.start; first < r.end(); ++n) {
      const uint64_t bucket = bucket_for_index(first, ctx.cfg.num_objects, ctx.cfg.num_buckets);
      const Range br = bucket_range(bucket, ctx.cfg.num_buckets, ctx.cfg.num_objects);
      first = std::min({r.end(), br.end(), first + static_cast<uint64_t>(ctx.cfg.page_size)});
    }
    return n;
  }

  // Id range deleted by global thread `gtid`.
  static Range thread_range(const RunContext &ctx, uint64_t gtid)
  {
    if (ctx.cfg.single_thread_mode) {
      return gtid == 0 ? bucket_range(0, ctx.cfg.num_buckets, ctx.cfg.num_objects) : Range{};
    }
    return index_range(gtid, static_cast<uint64_t>(ctx.total_streams()), ctx.cfg.num_objects);
  }

  void run_thread(RunContext &ctx, int tid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gtid = ctx.gsid(tid);
    const Range r = thread_range(ctx, gtid);
    if (r.count == 0) return;
    ThreadStats &ts = ctx.stats->thread(tid);
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gtid) : UINT64_MAX;
    uint64_t calls = 0, total_deleted = 0, pos = 0;  // pos: offset in range of the next key
    std::vector<std::string> keys;
    std::vector<kvrgw::KvRgwServiceImpl::DeleteMultiKeyOutcome> outcomes;
    while (!ctx.stopped() && calls < quota && !ctx.expired()) {
      const uint64_t first = r.start + pos;
      const uint64_t bucket = bucket_for_index(first, ctx.cfg.num_objects, ctx.cfg.num_buckets);
      const Range br = bucket_range(bucket, ctx.cfg.num_buckets, ctx.cfg.num_objects);
      const uint64_t last =
          std::min({r.end(), br.end(), first + static_cast<uint64_t>(ctx.cfg.page_size)});
      keys.clear();
      for (uint64_t i = first; i < last; ++i) keys.push_back(load_key(i, ctx.cfg.padding_bytes));
      outcomes.clear();
      auto t0 = SteadyClock::now();
      kvrgw::KvrgwErrorCode ec;
      // The service records its own DeleteMulti stats; no second timer here.
      ec = ctx.svc->delete_multi(ctx.tenant, ctx.bucket(bucket), keys, {}, &outcomes);
      const auto us = static_cast<uint64_t>(elapsed_us(t0));
      ++calls;
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
        ctx.fail("delete_multi " + ctx.bucket(bucket) + " failed: " + bad);
        break;
      }
      ts.record(Metric::DeleteMulti, us);
      ts.add_units(Metric::KeysDeleted, keys.size());
      total_deleted += keys.size();
      deleted_[static_cast<size_t>(tid)] = std::min(total_deleted, r.count);
      pos = last - r.start;
      if (last == r.end()) break;  // whole range deleted: this thread is done
    }
  }

  std::vector<uint64_t> thread_counts() const override { return deleted_; }

  std::string verify(RunContext &ctx, const std::vector<uint64_t> &progress,
                     VerifyReport *out) override
  {
    const uint64_t nthreads = ctx.cfg.single_thread_mode ? 1 : static_cast<uint64_t>(ctx.total_streams());
    if (progress.size() < nthreads) return "verify: delete_progress has wrong length";
    auto present = [&](uint64_t, uint64_t id) {
      uint64_t g = 0;
      if (!ctx.cfg.single_thread_mode) {
        g = block_for_index(id, ctx.cfg.num_objects, nthreads);
      }
      return id - thread_range(ctx, g).start >= progress[g];
    };
    std::vector<uint64_t> mine;
    if (ctx.cfg.single_thread_mode) {
      if (ctx.worker_index == 0) mine = {0};
    } else {
      mine = owned_buckets(ctx.worker_index, ctx.worker_count, ctx.cfg.num_buckets);
    }
    return verify_load_family(
        ctx, mine,
        [&](uint64_t b) { return bucket_range(b, ctx.cfg.num_buckets, ctx.cfg.num_objects); },
        present, out);
  }

 private:
  std::vector<uint64_t> deleted_;
};

}  // namespace

std::unique_ptr<Operation> make_delete_multi_op() { return std::make_unique<DeleteMultiOp>(); }

}  // namespace perfw
