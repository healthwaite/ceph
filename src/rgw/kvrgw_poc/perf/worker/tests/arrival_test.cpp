// Unit tests for the open-loop arrival schedule.
#include "arrival.hpp"

#include <cstdio>
#include <cstdlib>

using perfw::ArrivalSchedule;
using Clock = std::chrono::steady_clock;

#define CHECK(c)                                                         \
  do {                                                                   \
    if (!(c)) {                                                          \
      std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #c, __LINE__); \
      std::exit(1);                                                      \
    }                                                                    \
  } while (0)

static double secs(Clock::duration d) { return std::chrono::duration<double>(d).count(); }

int main()
{
  const auto t0 = Clock::time_point{} + std::chrono::seconds(100);
  // Constant, 2 drivers at 1,000 ops/s per worker: driver d at (k*2 + d) / 1000.
  for (int d = 0; d < 2; ++d) {
    ArrivalSchedule s(false, 2, d, 1);
    s.reset(t0, 1000);
    for (int k = 0; k < 1000; ++k) {
      const double want = (k * 2.0 + d) / 1000.0;
      CHECK(std::abs(secs(s.next() - t0) - want) < 1e-6);
      s.advance();
    }
  }
  // No integer-period drift at a rate whose period is not a whole number of ns.
  {
    ArrivalSchedule s(false, 1, 0, 1);
    s.reset(t0, 3e6);  // 333.33 ns period
    for (int k = 0; k < 3000000; ++k) s.advance();
    CHECK(std::abs(secs(s.next() - t0) - 1.0) < 1e-6);  // exactly 1 s later
  }
  // A rate change re-anchors at its effective time.
  {
    ArrivalSchedule s(false, 1, 0, 1);
    s.reset(t0, 10);
    s.advance();
    const auto t1 = t0 + std::chrono::milliseconds(250);
    s.reset(t1, 100);
    CHECK(s.next() == t1);
    s.advance();
    CHECK(std::abs(secs(s.next() - t1) - 0.01) < 1e-9);
  }
  // Poisson: the long-run mean interval is D / rate; seeds differ by generator.
  {
    ArrivalSchedule s(true, 2, 0, 42), o(true, 2, 1, 43);
    s.reset(t0, 5000);
    o.reset(t0, 5000);
    CHECK(s.next() != o.next());
    const int n = 200000;
    for (int k = 0; k < n; ++k) s.advance();
    const double mean = secs(s.next() - t0) / (n + 1);
    CHECK(std::abs(mean - 2.0 / 5000) / (2.0 / 5000) < 0.01);  // within 1%
  }
  std::printf("arrival_test OK\n");
  return 0;
}
