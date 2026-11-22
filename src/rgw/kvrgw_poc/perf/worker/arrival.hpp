// Open-loop arrival schedule of one generator (pure C++, unit-tested).
#pragma once

#include <chrono>
#include <cmath>
#include <cstdint>
#include <random>

namespace perfw {

// The arrival schedule of one generator. Deadlines are anchor + offset, with the
// offset kept in (double) seconds, so there is no integer-period drift; a rate
// change re-anchors at its effective time (no catch-up burst for the old rate).
class ArrivalSchedule {
 public:
  ArrivalSchedule(bool poisson, int drivers, int driver, uint64_t seed)
      : poisson_(poisson), D_(drivers), driver_(driver), rng_(seed) {}

  // Start a new segment at `anchor` with this worker's `rate` (ops/s, all drivers).
  void reset(std::chrono::steady_clock::time_point anchor, double rate)
  {
    anchor_ = anchor;
    rate_ = rate;
    k_ = 0;
    // Constant: driver d's slots are (k*D + d) / rate, interleaving the drivers.
    // Poisson: per-driver rate rate/D, first arrival one sample after the anchor.
    offset_s_ = poisson_ ? sample() : static_cast<double>(driver_) / rate_;
  }
  std::chrono::steady_clock::time_point next() const
  {
    return anchor_ + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                         std::chrono::duration<double>(offset_s_));
  }
  void advance()
  {
    ++k_;
    offset_s_ = poisson_ ? offset_s_ + sample()
                         : static_cast<double>(k_ * static_cast<uint64_t>(D_) +
                                               static_cast<uint64_t>(driver_)) / rate_;
  }

 private:
  double sample()
  {
    // Exponential inter-arrival with mean D / rate: -ln(1 - U) * D / rate.
    const double u = std::uniform_real_distribution<double>(0.0, 1.0)(rng_);
    return -std::log1p(-u) * static_cast<double>(D_) / rate_;
  }

  bool poisson_;
  int D_, driver_;
  std::mt19937_64 rng_;
  std::chrono::steady_clock::time_point anchor_{};
  double rate_ = 1;
  uint64_t k_ = 0;
  double offset_s_ = 0;
};


}  // namespace perfw
