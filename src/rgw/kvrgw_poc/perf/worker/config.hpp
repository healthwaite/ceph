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
  int metadata_count = 6;  // x-amz-meta-* items per put (0 = none)
  int metadata_size = 64;  // bytes per metadata value
  int worker_count = 1;
  int threads_per_worker = 1;
  // Client model. "sync": one blocking thread per stream calling the sync
  // wrappers (today's model). "async": streams are coroutines on
  // driver_threads executors calling the _a ops.
  std::string driver_mode = "sync";
  // Closed-loop concurrency per worker; 0 in the JSON means threads_per_worker.
  int streams_per_worker = 0;
  int driver_threads = 2;  // async mode only
  // Per-worker target rate; > 0 = open loop (async mode only).
  double rate_ops_per_sec = 0;
  int verify_threads = 4;
  std::string tenant_name = "kv-poc";
  int64_t report_interval_ms = 1000;
  // run-* only; exactly one of ops/duration_ms is > 0.
  uint64_t ops = 0;
  int64_t duration_ms = 0;
  int page_size = 1000;
  bool single_thread_mode = false;
  uint64_t num_objects_to_overwrite = 0;
  bool force = false;  // load: tolerate pre-existing buckets

  bool async_mode() const { return driver_mode == "async"; }
  bool open_loop() const { return rate_ops_per_sec > 0; }
  // Key-space generators per worker: the streams in closed loop, one per
  // driver thread in open loop. Global stream id gsid = worker_index * streams() + sid.
  int streams() const { return open_loop() ? driver_threads : streams_per_worker; }
  int total_streams() const { return worker_count * streams(); }
  bool has_ops() const { return ops > 0; }
  bool has_duration() const { return duration_ms > 0; }
};

// Returns an error string (empty on success).
std::string parse_config(const std::string &json_text, const std::string &operation,
                         int worker_count, Config *out);

}  // namespace perfw
