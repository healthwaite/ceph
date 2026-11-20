#include "histogram.hpp"
#include "test_util.hpp"

#include <fstream>
#include <nlohmann/json.hpp>

using namespace perfw;

int main()
{
  std::ifstream f(std::string(PERF_TESTDATA_DIR) + "/histogram.json");
  CHECK(f.good());
  auto j = nlohmann::json::parse(f);
  CHECK(j["num_buckets"].get<uint32_t>() == kHistBuckets);
  for (auto &e : j["index"]) {
    CHECK(hist_index(e["micros"].get<uint64_t>()) == e["bucket"].get<uint32_t>());
  }
  for (auto &e : j["midpoint"]) {
    CHECK(hist_midpoint(e["bucket"].get<uint32_t>()) == e["mid"].get<uint64_t>());
  }
  // monotonic
  uint32_t prev = 0;
  for (uint64_t m = 0; m < 200000; m += 7) {
    auto i = hist_index(m);
    CHECK(i >= prev);
    prev = i;
  }
  std::puts("histogram_test OK");
}
