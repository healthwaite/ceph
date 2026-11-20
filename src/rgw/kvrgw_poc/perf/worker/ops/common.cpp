#include "ops.hpp"

#include "error_codes.hpp"

#include <iostream>
#include <thread>

namespace perfw {

std::string short_key(const std::string &key)
{
  // Keys carry a long random prefix; keep the head and the tail (which holds the id).
  if (key.size() <= 48) return key;
  return key.substr(0, 12) + "..." + key.substr(key.size() - 24);
}

std::string describe_error(kvrgw::KvrgwErrorCode ec)
{
  return std::string(kvrgw::KvrgwErrorCode_Name(ec)) + " (" + kvrgw::kvrgw_strerror(ec) + ")";
}

void record_op_error(ThreadStats &ts, Metric m, kvrgw::KvrgwErrorCode ec)
{
  const std::string name = kvrgw::KvrgwErrorCode_Name(ec);
  register_error_text(name, kvrgw::kvrgw_strerror(ec));
  ts.record_error(m, name);
}

void log_op_error(const std::string &what, const std::string &err)
{
  static std::atomic<int> logged{0};
  if (logged.fetch_add(1) < 20) {
    // One write per line: several threads log concurrently.
    const std::string line = what + " failed: " + err + "\n";
    std::cerr.write(line.data(), static_cast<std::streamsize>(line.size()));
    std::cerr.flush();
  }
}

bool RunContext::wait_start() const
{
  while (!stopped()) {
    auto now = SteadyClock::now();
    if (now >= start_tp) return true;
    std::this_thread::sleep_for(std::min<SteadyClock::duration>(start_tp - now,
                                                                std::chrono::milliseconds(50)));
  }
  return false;
}

std::string ServiceLister::list(const std::string &prefix, uint32_t max_keys,
                                const std::string &token, ListPage *out)
{
  kvrgw::KvRgwServiceImpl::ListObjectsResult res;
  auto ec = svc_.list_objects(tenant_, bucket_, prefix, "", max_keys, token, "", &res);
  if (ec != kvrgw::KVRGW_ERR_OK) return describe_error(ec);
  out->keys.clear();
  out->keys.reserve(res.objects.size());
  for (auto &o : res.objects) out->keys.push_back(std::move(o.key));
  out->truncated = res.is_truncated;
  out->next_token = std::move(res.next_continuation_token);
  return {};
}

bool put_with_retry(RunContext &ctx, ThreadStats &ts, const std::string &bucket,
                    const std::string &key)
{
  constexpr int kAttempts = 10;
  kvrgw::KvrgwErrorCode last = kvrgw::KVRGW_ERR_OK;
  for (int a = 0; a < kAttempts && !ctx.stopped(); ++a) {
    auto t0 = SteadyClock::now();
    kvrgw::KvRgwServiceImpl::PutObjectResult res;
    {
      // Server-side stats are recorded by the caller (as perf_driver does).
      kvrgw::ScopedRequestLatency lat(ctx.svc->latency_stats(), kvrgw::OpType::kPutObject);
      res = ctx.svc->put_object(ctx.tenant, bucket, key,
                                reinterpret_cast<const uint8_t *>(ctx.payload.data()),
                                ctx.payload.size(), "application/octet-stream",
                                ctx.payload.size(), nullptr, {}, {});
    }
    if (res.error_code == kvrgw::KVRGW_ERR_OK) {
      ts.record(Metric::PutObject, static_cast<uint64_t>(elapsed_us(t0)));
      return true;
    }
    last = res.error_code;
    record_op_error(ts, Metric::PutObject, last);
    log_op_error("put_object " + bucket + "/" + short_key(key) + " (attempt " + std::to_string(a + 1) + ")",
                 describe_error(last));
  }
  if (!ctx.stopped()) {
    ctx.fail("put_object " + bucket + "/" + short_key(key) + " failed after " + std::to_string(kAttempts) +
             " attempts: " + describe_error(last));
  }
  return false;
}

std::string verify_load_family(RunContext &ctx, const std::vector<uint64_t> &buckets,
                               const std::function<Range(uint64_t)> &range_of_bucket,
                               const std::function<bool(uint64_t, uint64_t)> &present,
                               VerifyReport *out)
{
  Failures f;
  auto prefixes = prefix_items(ctx.cfg.padding_bytes);
  for (uint64_t b : buckets) {
    ServiceLister lister(*ctx.svc, ctx.tenant, ctx.bucket(b));
    Range r = range_of_bucket(b);
    LoadSpace sp;
    sp.start = r.start;
    sp.count = r.count;
    sp.padding = ctx.cfg.padding_bytes;
    if (present) sp.expected_present = [&present, b](uint64_t id) { return present(b, id); };
    out->buckets.push_back(
        verify_bucket_load(lister, ctx.bucket(b), sp, prefixes, ctx.cfg.verify_threads, f));
  }
  out->take(f);
  return {};
}

std::string check_buckets(RunContext &ctx, const std::vector<uint64_t> &buckets,
                          bool require_versioning)
{
  for (uint64_t b : buckets) {
    bool exists = false;
    auto ec = ctx.svc->bucket_exists(ctx.tenant, ctx.bucket(b), &exists);
    if (ec != kvrgw::KVRGW_ERR_OK) {
      return "bucket_exists " + ctx.bucket(b) + ": " + describe_error(ec);
    }
    if (!exists) return "bucket " + ctx.bucket(b) + " does not exist (run load first)";
    if (require_versioning) {
      kvrgw::VersioningState st{};
      ec = ctx.svc->get_bucket_versioning(ctx.tenant, ctx.bucket(b), &st);
      if (ec != kvrgw::KVRGW_ERR_OK) {
        return "get_bucket_versioning " + ctx.bucket(b) + ": " + describe_error(ec);
      }
      if (st != kvrgw::VERSIONING_ENABLED) {
        return "bucket " + ctx.bucket(b) + " does not have versioning enabled";
      }
    }
  }
  return {};
}

}  // namespace perfw
