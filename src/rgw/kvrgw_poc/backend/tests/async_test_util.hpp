// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
// Minimal test harness for the async_*_test binaries (no gtest in this tree).

#pragma once

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

namespace async_test {

struct Case {
  const char* name;
  std::function<void()> fn;
};

inline std::vector<Case>& registry() {
  static std::vector<Case> r;
  return r;
}

inline int& failures() {
  static int f = 0;
  return f;
}

struct Registrar {
  Registrar(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};

inline int run_all(int argc, char** argv) {
  const char* only = argc > 1 ? argv[1] : nullptr;
  int ran = 0;
  for (auto& c : registry()) {
    if (only && std::string(c.name).find(only) == std::string::npos) continue;
    const int before = failures();
    c.fn();
    ++ran;
    std::printf("  %s: %s\n", failures() == before ? "PASS" : "FAIL", c.name);
    std::fflush(stdout);
  }
  std::printf("%d cases, %d failed checks\n", ran, failures());
  return failures() == 0 ? 0 : 1;
}

}  // namespace async_test

#define ATEST(name)                                                        \
  static void atest_##name();                                              \
  static async_test::Registrar atest_reg_##name(#name, atest_##name);      \
  static void atest_##name()

#define ACHECK(cond)                                                       \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("    check failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
      ++async_test::failures();                                            \
    }                                                                      \
  } while (0)

#define ACHECK_EQ(a, b)                                                    \
  do {                                                                     \
    const auto _va = (a);                                                  \
    const auto _vb = (b);                                                  \
    if (!(_va == _vb)) {                                                   \
      std::printf("    check failed: %s == %s (%lld vs %lld) (%s:%d)\n", #a, #b, \
                  (long long)_va, (long long)_vb, __FILE__, __LINE__);     \
      ++async_test::failures();                                            \
    }                                                                      \
  } while (0)
