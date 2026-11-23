#include "ops.hpp"

#include "error_codes.hpp"

namespace perfw {

namespace {

// run-mixed-ops: every thread picks one of get_object / put_object (new key) /
// put_object (overwrite) / list_objects / delete_object per op, at random with the configured
// weights, then performs it on a randomly chosen key. Threads share the id space, so
// concurrent writes to one key are possible and there is no verify stage.
//
// - get: random id in [0, num_objects). A missing key is legitimate (counted in get_misses,
//   not an error).
// - put new: the run-put-object convention (put_key(run_ts, gsid, counter) in bucket
//   gsid % num_buckets), retried like run-put-object.
// - overwrite: pops an id from this thread's deleted list if it has one, else a random id in
//   [0, num_objects); puts it with the usual payload.
// - list: one list_objects call (page_size) on a random bucket and key prefix.
// - delete: delete_object on a random id; the id is appended to this thread's deleted list.
//   Deleting a key that is already gone is not an error.
class MixedOp : public Operation {
 public:
  std::string init(RunContext &ctx) override
  {
    std::vector<uint64_t> all;
    for (uint64_t b = 0; b < ctx.cfg.num_buckets; ++b) all.push_back(b);
    return check_buckets(ctx, all);
  }

  enum Kind { kGet, kPutNew, kOverwrite, kList, kDelete, kKinds };

  void run_thread(RunContext &ctx, int sid) override
  {
    if (!ctx.wait_start()) return;
    const uint64_t gsid = ctx.gsid(sid);
    ThreadStats &ts = ctx.stats->thread(sid);
    const uint64_t quota = ctx.cfg.has_ops() ? ctx.ops_quota(gsid) : UINT64_MAX;
    uint64_t rng = splitmix64_mix(static_cast<uint64_t>(ctx.run_start_unix_s) * 1000003ull + gsid);

    // Cumulative weights over the five kinds.
    const double w[kKinds] = {ctx.cfg.get_object_weight, ctx.cfg.put_object_new_weight,
                              ctx.cfg.put_object_overwrite_weight, ctx.cfg.list_objects_weight,
                              ctx.cfg.delete_object_weight};
    double cum[kKinds];
    double total = 0;
    for (int k = 0; k < kKinds; ++k) cum[k] = (total += w[k]);

    const auto prefixes = prefix_items(ctx.cfg.padding_bytes);
    const std::string &new_bucket = ctx.bucket(gsid % ctx.cfg.num_buckets);
    std::vector<uint64_t> deleted;  // ids this thread deleted and has not re-put
    uint64_t new_counter = 0;
    uint64_t done = 0;
    kvrgw::KvRgwServiceImpl::GetObjectResult get_res;

    auto random_id = [&] { return splitmix64_next(rng) % ctx.cfg.num_objects; };
    auto id_bucket = [&](uint64_t id) -> const std::string & {
      return ctx.bucket(bucket_for_index(id, ctx.cfg.num_objects, ctx.cfg.num_buckets));
    };

    while (!ctx.stopped() && done < quota && !ctx.expired()) {
      const double r = static_cast<double>(splitmix64_next(rng) >> 11) * (1.0 / 9007199254740992.0) * total;
      int kind = 0;
      while (kind < kKinds - 1 && r >= cum[kind]) ++kind;
      ++done;
      switch (kind) {
        case kGet: {
          const uint64_t id = random_id();
          const std::string &b = id_bucket(id);
          const std::string key = load_key(id, ctx.cfg.padding_bytes);
          get_res = {};
          const auto t0 = SteadyClock::now();
          const auto ec = ctx.svc->get_object(ctx.tenant, b, key, std::nullopt, nullptr, 0, &get_res);
          if (ec == kvrgw::KVRGW_ERR_OK || ec == kvrgw::KVRGW_ERR_NO_SUCH_KEY) {
            ts.record(Metric::GetObject, static_cast<uint64_t>(elapsed_us(t0)));
            if (ec != kvrgw::KVRGW_ERR_OK) ts.add_units(Metric::GetMisses, 1);
          } else {
            record_op_error(ts, Metric::GetObject, ec);
            log_op_error("get_object " + b + "/" + short_key(key), describe_error(ec));
          }
          break;
        }
        case kPutNew: {
          if (!put_with_retry(ctx, ts, new_bucket,
                              put_key(static_cast<uint64_t>(ctx.run_start_unix_s),
                                      static_cast<uint32_t>(gsid), new_counter,
                                      ctx.cfg.padding_bytes))) {
            return;
          }
          ++new_counter;
          break;
        }
        case kOverwrite: {
          uint64_t id;
          if (!deleted.empty()) {
            id = deleted.back();
            deleted.pop_back();
          } else {
            id = random_id();
          }
          if (!put_with_retry(ctx, ts, id_bucket(id), load_key(id, ctx.cfg.padding_bytes), nullptr,
                              Metric::PutOverwrite)) {
            return;
          }
          break;
        }
        case kList: {
          const std::string &b = ctx.bucket(splitmix64_next(rng) % ctx.cfg.num_buckets);
          const std::string &prefix = prefixes[splitmix64_next(rng) % prefixes.size()];
          kvrgw::KvRgwServiceImpl::ListObjectsResult res;
          const auto t0 = SteadyClock::now();
          const auto ec = ctx.svc->list_objects(ctx.tenant, b, prefix, "",
                                                static_cast<uint32_t>(ctx.cfg.page_size), "", "", &res);
          if (ec != kvrgw::KVRGW_ERR_OK) {
            record_op_error(ts, Metric::ListObjects, ec);
            log_op_error("list_objects " + b + " prefix '" + prefix + "'", describe_error(ec));
          } else {
            ts.record(Metric::ListObjects, static_cast<uint64_t>(elapsed_us(t0)));
            ts.add_units(Metric::KeysListed, res.objects.size());
          }
          break;
        }
        case kDelete: {
          const uint64_t id = random_id();
          const std::string &b = id_bucket(id);
          const std::string key = load_key(id, ctx.cfg.padding_bytes);
          kvrgw::KvRgwServiceImpl::DeleteResult dres;
          const auto t0 = SteadyClock::now();
          const auto ec = ctx.svc->delete_object(ctx.tenant, b, key, nullptr, &dres);
          if (ec == kvrgw::KVRGW_ERR_OK || ec == kvrgw::KVRGW_ERR_NO_SUCH_KEY) {
            ts.record(Metric::DeleteObject, static_cast<uint64_t>(elapsed_us(t0)));
            deleted.push_back(id);
          } else {
            record_op_error(ts, Metric::DeleteObject, ec);
            log_op_error("delete_object " + b + "/" + short_key(key), describe_error(ec));
          }
          break;
        }
      }
    }
  }

  bool has_verify() const override { return false; }
  std::string verify(RunContext &, const std::vector<uint64_t> &, VerifyReport *) override
  {
    return {};
  }
};

}  // namespace

std::unique_ptr<Operation> make_mixed_ops_op() { return std::make_unique<MixedOp>(); }

}  // namespace perfw
