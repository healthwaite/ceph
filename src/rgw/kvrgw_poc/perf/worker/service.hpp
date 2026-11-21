// gRPC Worker service implementation.
#pragma once

#include "config.hpp"
#include "ops/ops.hpp"
#include "stats.hpp"

#include "async/executor.hpp"
#include "kvrgw_runtime.hpp"
#include "worker.grpc.pb.h"

#include <memory>
#include <mutex>

namespace perfw {

class WorkerService final : public perf::v1::Worker::Service {
 public:
  explicit WorkerService(kvrgw::KvRgwRuntime &rt) : rt_(rt) {}

  grpc::Status Init(grpc::ServerContext *, const perf::v1::InitRequest *req,
                    grpc::ServerWriter<perf::v1::PhaseEvent> *w) override;
  grpc::Status RunBenchmark(
      grpc::ServerContext *,
      grpc::ServerReaderWriter<perf::v1::PhaseEvent, perf::v1::RunControl> *s) override;
  grpc::Status Verify(grpc::ServerContext *, const perf::v1::VerifyRequest *req,
                      grpc::ServerWriter<perf::v1::PhaseEvent> *w) override;
  grpc::Status Cleanup(grpc::ServerContext *, const perf::v1::CleanupRequest *req,
                       grpc::ServerWriter<perf::v1::PhaseEvent> *w) override;

 private:
  std::string do_init(const perf::v1::InitRequest &req);
  // `drivers`: the async driver executors of the running benchmark, if any.
  void fill_server_stats(perf::v1::ServerStats *out,
                         std::vector<std::unique_ptr<kvrgw::async::ExecutorThread>> *drivers = nullptr);

  kvrgw::KvRgwRuntime &rt_;
  std::mutex mu_;  // protects the pointers below (phases are sequential per invocation)
  std::string benchmark_id_;
  std::unique_ptr<RunContext> ctx_;
  std::unique_ptr<Operation> op_;
  std::unique_ptr<StatsHub> stats_;
};

}  // namespace perfw
