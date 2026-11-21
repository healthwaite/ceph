// kvrgw-perf-worker: gRPC server driving the in-process kvrgw service layer.
#include "service.hpp"

#include "async/executor.hpp"
#include "async/frame_pool.hpp"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

namespace {
std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop = true; }
}  // namespace

int main(int argc, char **argv)
{
  std::string listen = "127.0.0.1:19090";
  std::string data_root;
  for (int i = 1; i < argc; ++i) {
    if (!std::strcmp(argv[i], "--listen") && i + 1 < argc) {
      listen = argv[++i];
    } else if (!std::strcmp(argv[i], "--data-root") && i + 1 < argc) {
      data_root = argv[++i];
    } else {
      std::cerr << "usage: kvrgw-perf-worker [--listen host:port] [--data-root dir]\n";
      return 2;
    }
  }

  std::signal(SIGTERM, on_signal);
  std::signal(SIGINT, on_signal);

  // One runtime per process (the FDB network thread is per process).
  kvrgw::KvRgwRuntime runtime;
  kvrgw::KvRgwStartOptions opts;
  opts.perf_mode = true;
  opts.data_root = data_root;
  if (!runtime.start(opts)) {
    std::cerr << "kvrgw runtime failed to start\n";
    return 1;
  }

  perfw::WorkerService service(runtime);
  grpc::ServerBuilder builder;
  builder.AddListeningPort(listen, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
  if (!server) {
    std::cerr << "failed to listen on " << listen << "\n";
    runtime.stop();
    return 1;
  }
  std::cerr << "kvrgw-perf-worker listening on " << listen << std::endl;

  std::thread watcher([&]() {
    kvrgw::async::set_thread_name("perf-sigwatch");
    while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
  });
  server->Wait();
  g_stop = true;
  watcher.join();
  // Shutdown accounting: every async op has finished and every coroutine frame
  // is released (checked by the cancel-under-load test).
  const auto inflight = runtime.service().admission().inflight();
  runtime.stop();
  std::cerr << "kvrgw-perf-worker: shutdown: inflight_ops=" << inflight
            << " frames_live=" << kvrgw::async::frame_pool_counters().frames_live.load()
            << std::endl;
  return 0;
}
