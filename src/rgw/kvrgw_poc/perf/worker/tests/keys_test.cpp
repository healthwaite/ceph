#include "keys.hpp"
#include "test_util.hpp"

#include <initializer_list>
#include <set>

using namespace perfw;

static void test_determinism_and_format()
{
  CHECK(rand_prefix(7, 16) == rand_prefix(7, 16));
  CHECK(rand_prefix(7, 16) != rand_prefix(8, 16));
  for (char c : rand_prefix(123, 500)) CHECK(kCharset.find(c) != std::string_view::npos && c != '/');

  for (uint64_t i : {0ULL, 1ULL, 999999ULL, 123456789012ULL}) {
    auto k = load_key(i, 16);
    CHECK(k.size() == load_key_len(16));
    CHECK(parse_key_id(k) == i);
    CHECK(k == load_key(*parse_key_id(k), 16));
  }
  CHECK(load_key(5, 0).size() == 20);
  CHECK(!parse_key_id("short"));
  CHECK(!parse_key_id(std::string(20, 'x')));

  auto pk = put_key(1700000000, 513, 42, 16);
  CHECK(pk.size() == put_key_len(16));
  CHECK(pk.size() != load_key_len(16));
  auto parsed = parse_put_key(pk, 16);
  CHECK(parsed && parsed->ts == 1700000000 && parsed->gtid == 513 && parsed->counter == 42);
  CHECK(pk == put_key(parsed->ts, parsed->gtid, parsed->counter, 16));
  CHECK(parse_key_id(pk) == 42);
  CHECK(!parse_put_key(load_key(1, 16), 16));
  // Different invocations / threads / counters give different keys.
  CHECK(put_key(1, 0, 0, 16) != put_key(2, 0, 0, 16));
  CHECK(put_key(1, 0, 0, 16) != put_key(1, 1, 0, 16));
  CHECK(put_key(1, 0, 0, 16) != put_key(1, 0, 1, 16));
}

static void test_bucket_for_index()
{
  for (uint64_t n : {1ULL, 7ULL, 10ULL, 11ULL, 100ULL, 103ULL}) {
    for (uint64_t b : {1ULL, 3ULL, 4ULL, 10ULL, 12ULL}) {
      std::vector<uint64_t> counts(b, 0);
      uint64_t prev = 0;
      for (uint64_t i = 0; i < n; ++i) {
        uint64_t x = bucket_for_index(i, n, b);
        CHECK(x < b && x >= prev);  // contiguous blocks
        prev = x;
        ++counts[x];
        auto r = bucket_range(x, b, n);
        CHECK(i >= r.start && i < r.end());
      }
      for (uint64_t x = 0; x < b; ++x) CHECK(counts[x] == bucket_range(x, b, n).count);
    }
  }
  // first n%b buckets get one extra
  CHECK(bucket_range(0, 3, 10).count == 4 && bucket_range(2, 3, 10).count == 3);
}

static void test_index_range()
{
  for (uint64_t n : {0ULL, 1ULL, 5ULL, 16ULL, 17ULL, 1000ULL}) {
    for (uint64_t t : {1ULL, 2ULL, 7ULL, 16ULL, 32ULL}) {
      uint64_t sum = 0, expect_start = 0;
      for (uint64_t g = 0; g < t; ++g) {
        auto r = index_range(g, t, n);
        CHECK(r.start == expect_start);  // contiguous, no overlap
        expect_start += r.count;
        sum += r.count;
      }
      CHECK(sum == n);
    }
  }
  CHECK(index_range(3, 8, 3).count == 0);  // num_objects < total_threads
}

static void test_overwrite_window()
{
  for (uint64_t n : {1ULL, 10ULL, 17ULL, 1000ULL}) {
    for (uint64_t t : {1ULL, 3ULL, 4ULL, 16ULL}) {
      // 0 = no limit: every thread overwrites its whole range.
      uint64_t sum = 0;
      for (uint64_t g = 0; g < t; ++g) {
        auto w = overwrite_window(g, t, n, 0);
        CHECK(w.start == index_range(g, t, n).start && w.count == index_range(g, t, n).count);
        sum += w.count;
      }
      CHECK(sum == n);
      // A total <= n is shared across all threads and never clamped: windows sum to the total.
      for (uint64_t total : std::initializer_list<uint64_t>{1, n / 2 + 1, n}) {
        uint64_t got = 0;
        for (uint64_t g = 0; g < t; ++g) {
          auto w = overwrite_window(g, t, n, total);
          CHECK(w.start == index_range(g, t, n).start);          // starts at its range
          CHECK(w.count <= index_range(g, t, n).count);          // within its range
          CHECK(w.count == block_range(g, t, total).count || total < t);  // even share
          got += w.count;
        }
        CHECK(got == total);
      }
      // A total above num_objects is clamped to the ranges: everything, nothing more.
      uint64_t got = 0;
      for (uint64_t g = 0; g < t; ++g) got += overwrite_window(g, t, n, n * 3).count;
      CHECK(got == n);
    }
  }
  // 1,000,000 shared over 8 workers x 32 threads = 256 threads: 3906 or 3907 keys each.
  CHECK(overwrite_window(0, 256, 10000000, 1000000).count == 3907);
  CHECK(overwrite_window(255, 256, 10000000, 1000000).count == 3906);
}

static void test_ownership()
{
  for (int wc : {1, 2, 3, 4, 7}) {
    for (uint64_t nb : {1ULL, 2ULL, 4ULL, 10ULL}) {
      std::set<uint64_t> seen;
      for (int w = 0; w < wc; ++w) {
        for (auto b : owned_buckets(w, wc, nb)) CHECK(seen.insert(b).second);
      }
      CHECK(seen.size() == nb);
    }
  }
  auto p = prefix_items(16);
  CHECK(p.size() == kCharset.size());
  std::set<std::string> s(p.begin(), p.end());
  CHECK(s.size() == p.size());
  CHECK(prefix_items(0).size() == 1 && prefix_items(0)[0].empty());
}

int main()
{
  test_determinism_and_format();
  test_bucket_for_index();
  test_index_range();
  test_overwrite_window();
  test_ownership();
  std::puts("keys_test OK");
}
