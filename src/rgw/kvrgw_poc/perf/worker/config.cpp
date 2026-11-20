#include "config.hpp"

#include <nlohmann/json.hpp>

namespace perfw {

namespace {
template <class T>
void get(const nlohmann::json &j, const char *k, T &dst)
{
  if (auto it = j.find(k); it != j.end() && !it->is_null()) {
    dst = it->get<T>();
  }
}
}  // namespace

std::string parse_config(const std::string &json_text, const std::string &operation,
                         int worker_count, Config *out)
{
  Config c;
  try {
    auto j = nlohmann::json::parse(json_text);
    get(j, "num_objects", c.num_objects);
    get(j, "num_buckets", c.num_buckets);
    get(j, "bucket_name_prefix", c.bucket_name_prefix);
    get(j, "padding_bytes", c.padding_bytes);
    get(j, "object_size_bytes", c.object_size_bytes);
    get(j, "threads_per_worker", c.threads_per_worker);
    get(j, "verify_threads", c.verify_threads);
    get(j, "tenant_name", c.tenant_name);
    get(j, "report_interval_ms", c.report_interval_ms);
    get(j, "ops", c.ops);
    get(j, "duration_ms", c.duration_ms);
    get(j, "page_size", c.page_size);
    get(j, "single_thread_mode", c.single_thread_mode);
    get(j, "num_objects_to_overwrite", c.num_objects_to_overwrite);
  } catch (const std::exception &e) {
    return std::string("config parse error: ") + e.what();
  }
  c.operation = operation;
  c.worker_count = worker_count;

  if (c.num_buckets == 0) return "num_buckets must be > 0";
  if (c.num_objects == 0) return "num_objects must be > 0";
  if (c.padding_bytes < 0 || c.padding_bytes > 700) return "padding_bytes out of range";
  if (c.threads_per_worker < 1) return "threads_per_worker must be >= 1";
  if (c.verify_threads < 1) return "verify_threads must be >= 1";
  if (c.page_size < 1) return "page_size must be >= 1";
  if (c.report_interval_ms < 0) return "report_interval_ms must be >= 0";
  if (static_cast<uint64_t>(c.worker_count) * static_cast<uint64_t>(c.threads_per_worker) > 65536) {
    return "worker_count * threads_per_worker must be <= 65536";
  }
  const bool is_run = operation != "load";
  if (is_run) {
    if (c.has_ops() == c.has_duration()) return "exactly one of ops/duration must be set";
  } else if (c.has_ops() || c.has_duration()) {
    return "ops/duration are not valid for load";
  }
  if ((operation == "run-put-object-overwrite" ||
       operation == "run-put-object-overwrite-versioned") &&
      c.num_objects_to_overwrite == 0) {
    return "num_objects_to_overwrite must be > 0";
  }
  *out = std::move(c);
  return {};
}

}  // namespace perfw
