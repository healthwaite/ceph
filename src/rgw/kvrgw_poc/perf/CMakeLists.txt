# kvrgw perf harness (worker + controller). Included from backend/CMakeLists.txt only when
# -DKVRGW_BUILD_PERF_HARNESS=ON. The kvrgw library itself never depends on gRPC.
set(PERF_DIR "${CMAKE_CURRENT_LIST_DIR}")

find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(nlohmann_json REQUIRED)

# ---- C++ stubs generated at build time ----
set(PERF_PROTO "${PERF_DIR}/proto/perf/v1/worker.proto")
set(PERF_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen")
file(MAKE_DIRECTORY "${PERF_GEN_DIR}")
set(PERF_PROTO_SRCS "${PERF_GEN_DIR}/worker.pb.cc" "${PERF_GEN_DIR}/worker.grpc.pb.cc")
set(PERF_PROTO_HDRS "${PERF_GEN_DIR}/worker.pb.h" "${PERF_GEN_DIR}/worker.grpc.pb.h")
find_program(PERF_GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)
add_custom_command(
  OUTPUT ${PERF_PROTO_SRCS} ${PERF_PROTO_HDRS}
  COMMAND protobuf::protoc
          --proto_path "${PERF_DIR}/proto/perf/v1"
          --cpp_out "${PERF_GEN_DIR}"
          --grpc_out "${PERF_GEN_DIR}"
          --plugin=protoc-gen-grpc=${PERF_GRPC_CPP_PLUGIN}
          "${PERF_PROTO}"
  DEPENDS "${PERF_PROTO}"
  COMMENT "Generating C++ gRPC stubs for worker.proto")

add_library(perf_proto STATIC ${PERF_PROTO_SRCS})
target_include_directories(perf_proto PUBLIC "${PERF_GEN_DIR}")
target_link_libraries(perf_proto PUBLIC gRPC::grpc++ protobuf::libprotobuf)

# ---- pure helpers (no kvrgw / gRPC): keys, stats, verify, config ----
add_library(perf_core STATIC
  worker/keys.cpp worker/stats.cpp worker/verify.cpp worker/config.cpp)
target_include_directories(perf_core PUBLIC "${PERF_DIR}/worker")
target_compile_features(perf_core PUBLIC cxx_std_20)
target_link_libraries(perf_core PUBLIC nlohmann_json::nlohmann_json Threads::Threads)

# ---- worker ----
add_executable(kvrgw-perf-worker
  worker/main.cpp worker/service.cpp
  worker/ops/common.cpp worker/ops/factory.cpp worker/ops/load.cpp
  worker/ops/put_object.cpp worker/ops/list_objects.cpp worker/ops/overwrite.cpp
  worker/ops/delete_multi.cpp worker/ops/list_delete_multi.cpp worker/ops/get_object.cpp worker/ops/mixed_ops.cpp)
target_include_directories(kvrgw-perf-worker PRIVATE
  "${CMAKE_SOURCE_DIR}/src" "${CMAKE_SOURCE_DIR}/include" "${PERF_DIR}/worker")
target_link_libraries(kvrgw-perf-worker PRIVATE kvrgw perf_core perf_proto)
set_target_properties(kvrgw-perf-worker PROPERTIES
  BUILD_RPATH "${FDB_LIB_DIR};$ORIGIN"
  INSTALL_RPATH "${FDB_LIB_DIR};$ORIGIN")

# ---- unit tests (plain executables, like the existing tests) ----
foreach(t keys_test histogram_test verify_test stats_test arrival_test)
  add_executable(perf_${t} worker/tests/${t}.cpp)
  target_link_libraries(perf_${t} PRIVATE perf_core)
  target_compile_definitions(perf_${t} PRIVATE
    PERF_TESTDATA_DIR="${PERF_DIR}/proto/testdata")
  add_test(NAME perf_${t} COMMAND perf_${t})
endforeach()

# ---- Go controller (does not link kvrgw) ----
add_custom_target(kvrgw-perf ALL
  COMMAND go build -o "${CMAKE_BINARY_DIR}/kvrgw-perf" ./cmd/kvrgw-perf
  WORKING_DIRECTORY "${PERF_DIR}/controller"
  COMMENT "Building Go perf controller")

# Default config next to the controller binary (found automatically at run time).
configure_file("${PERF_DIR}/kvrgw-perf.yaml" "${CMAKE_BINARY_DIR}/kvrgw-perf.yaml" COPYONLY)
