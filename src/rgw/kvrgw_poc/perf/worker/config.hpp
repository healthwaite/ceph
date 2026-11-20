// Resolved benchmark config, parsed from InitRequest.config_json (spec 5.1).
#pragma once

#include <cstdint>
#include <string>

namespace perfw {

struct Config {
  std::string operation;
  uint64_t num_objects = 1000000;
  uint64_t num_buckets = 10;
  std::string bucket_name_prefix = "rgwkv";
  int padding_bytes = 16;
  uint64_t object_size_bytes = 8192;
  int worker_count = 1;
  int threads_per_worker = 1;
  int verify_threads = 4;
  std::string tenant_name = "kv-poc";
  int64_t report_interval_ms = 1000;
  // run-* only; exactly one of ops/duration_ms is > 0.
  uint64_t ops = 0;
  int64_t duration_ms = 0;
  int page_size = 1000;
  bool single_thread_mode = false;
  uint64_t num_objects_to_overwrite = 0;

  int total_threads() const { return worker_count * threads_per_worker; }
  bool has_ops() const { return ops > 0; }
  bool has_duration() const { return duration_ms > 0; }
};

// Returns an error string (empty on success).
std::string parse_config(const std::string &json_text, const std::string &operation,
                         int worker_count, Config *out);

}  // namespace perfw
