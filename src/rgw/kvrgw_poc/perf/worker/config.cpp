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
    get(j, "metadata_count", c.metadata_count);
    get(j, "metadata_size", c.metadata_size);
    get(j, "threads_per_worker", c.threads_per_worker);
    get(j, "driver_mode", c.driver_mode);
    get(j, "streams_per_worker", c.streams_per_worker);
    get(j, "driver_threads", c.driver_threads);
    get(j, "rate_ops_per_sec", c.rate_ops_per_sec);
    get(j, "arrival", c.arrival);
    get(j, "ramp", c.ramp);
    get(j, "verify_threads", c.verify_threads);
    get(j, "tenant_name", c.tenant_name);
    get(j, "report_interval_ms", c.report_interval_ms);
    get(j, "ops", c.ops);
    get(j, "duration_ms", c.duration_ms);
    get(j, "page_size", c.page_size);
    get(j, "get_object_weight", c.get_object_weight);
    get(j, "put_object_new_weight", c.put_object_new_weight);
    get(j, "put_object_overwrite_weight", c.put_object_overwrite_weight);
    get(j, "list_objects_weight", c.list_objects_weight);
    get(j, "delete_object_weight", c.delete_object_weight);
    get(j, "single_thread_mode", c.single_thread_mode);
    get(j, "num_objects_to_overwrite", c.num_objects_to_overwrite);
    get(j, "force", c.force);
  } catch (const std::exception &e) {
    return std::string("config parse error: ") + e.what();
  }
  c.operation = operation;
  c.worker_count = worker_count;

  if (c.num_buckets == 0) return "num_buckets must be > 0";
  if (c.num_objects == 0) return "num_objects must be > 0";
  if (c.padding_bytes < 0 || c.padding_bytes > 700) return "padding_bytes out of range";
  if (c.metadata_count < 0 || c.metadata_count > 160) return "metadata_count must be in 0..160";
  if (c.metadata_count > 0 && (c.metadata_size < 1 || c.metadata_size > 2048)) {
    return "metadata_size must be in 1..2048 when metadata_count > 0";
  }
  if (c.threads_per_worker < 1) return "threads_per_worker must be >= 1";
  if (c.streams_per_worker <= 0) c.streams_per_worker = c.threads_per_worker;
  if (c.driver_mode != "sync" && c.driver_mode != "async") {
    return "driver_mode must be sync or async";
  }
  if (c.driver_threads < 1) return "driver_threads must be >= 1";
  if (c.rate_ops_per_sec < 0) return "rate_ops_per_sec must be >= 0";
  if (c.arrival != "constant" && c.arrival != "poisson") return "arrival must be constant or poisson";
  if (c.open_loop()) {
    if (!c.async_mode()) return "rate_ops_per_sec (open loop) requires driver_mode: async";
    if (operation != "run-put-object" && operation != "run-put-object-overwrite" &&
        operation != "run-put-object-overwrite-versioned" && operation != "run-delete-multi") {
      return "open loop (rate_ops_per_sec) is not supported for " + operation;
    }
  }
  if (c.verify_threads < 1) return "verify_threads must be >= 1";
  if (c.page_size < 1) return "page_size must be >= 1";
  if (operation == "run-mixed-ops") {
    const double w[] = {c.get_object_weight, c.put_object_new_weight, c.put_object_overwrite_weight,
                        c.list_objects_weight, c.delete_object_weight};
    double sum = 0;
    for (double x : w) {
      if (!(x >= 0)) return "run-mixed-ops weights must be >= 0";
      sum += x;
    }
    if (!(sum > 0)) return "run-mixed-ops needs at least one weight > 0";
  }
  if (c.report_interval_ms < 0) return "report_interval_ms must be >= 0";
  if (static_cast<uint64_t>(c.worker_count) * static_cast<uint64_t>(c.streams()) > 65536) {
    return "worker_count * streams_per_worker must be <= 65536";
  }
  const bool is_run = operation != "load";
  if (is_run) {
    if (c.ramp) {
      if (c.has_ops() || c.has_duration()) return "a ramp takes neither ops nor duration";
      if (!c.open_loop()) return "a ramp needs rate_ops_per_sec > 0";
    } else if (c.has_ops() == c.has_duration()) {
      return "exactly one of ops/duration must be set";
    }
  } else if (c.has_ops() || c.has_duration()) {
    return "ops/duration are not valid for load";
  }
  // run-put-object-overwrite has no limit; the versioned variant overwrites a limited total.
  if (operation == "run-put-object-overwrite-versioned") {
    if (c.num_objects_to_overwrite == 0) return "num_objects_to_overwrite must be > 0";
    if (c.num_objects_to_overwrite > c.num_objects) {
      return "num_objects_to_overwrite must be <= num_objects";
    }
  }
  *out = std::move(c);
  return {};
}

}  // namespace perfw
