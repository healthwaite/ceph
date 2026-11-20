#include "verify.hpp"
#include "test_util.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <thread>

using namespace perfw;

// In-memory lister over a sorted key set with paging.
class FakeLister : public Lister {
 public:
  std::vector<std::string> keys;  // sorted
  uint32_t page = 3;
  bool fail = false;
  std::string list(const std::string &prefix, uint32_t, const std::string &token,
                   ListPage *out) override
  {
    if (fail) return "boom";
    out->keys.clear();
    auto it = std::lower_bound(keys.begin(), keys.end(), token.empty() ? prefix : token);
    for (; it != keys.end() && it->compare(0, prefix.size(), prefix) == 0; ++it) {
      if (out->keys.size() == page) {
        out->truncated = true;
        out->next_token = *it;
        return {};
      }
      out->keys.push_back(*it);
    }
    out->truncated = false;
    return {};
  }
  void add(const std::string &k) { keys.insert(std::lower_bound(keys.begin(), keys.end(), k), k); }
};

// In-memory pager over (key, version-count) pairs: key k has `n` versions, the first is null
// unless `versioned`. Sorted by key; pages by entry with (key, index) markers.
class FakePager : public VersionPager {
 public:
  struct Item { std::string key; int versions = 1; bool versioned = false; bool marker = false; };
  std::vector<Item> items;  // sorted
  uint32_t page_size = 3;
  std::string page(const std::string &prefix, uint32_t, const std::string &key_marker,
                   const std::string &version_marker, VersionPage *out) override
  {
    // flatten to entries
    struct Flat { std::string key; int idx; bool null_version; bool dm; };
    std::vector<Flat> flat;
    for (const auto &it : items) {
      if (it.key.compare(0, prefix.size(), prefix) != 0) continue;
      for (int i = 0; i < it.versions; ++i) {
        flat.push_back({it.key, i, !it.versioned && i == 0, it.marker && i == it.versions - 1});
      }
    }
    size_t pos = 0;
    if (!key_marker.empty()) {
      const int want = version_marker.empty() ? 0 : std::stoi(version_marker);
      while (pos < flat.size() && !(flat[pos].key == key_marker && flat[pos].idx == want)) ++pos;
    }
    out->entries.clear();
    for (; pos < flat.size() && out->entries.size() < page_size; ++pos) {
      out->entries.push_back({flat[pos].key, flat[pos].null_version, flat[pos].dm});
    }
    out->truncated = pos < flat.size();
    if (out->truncated) {
      out->next_key_marker = flat[pos].key;
      out->next_version_marker = std::to_string(flat[pos].idx);
    }
    return {};
  }
};

static void test_version_scan()
{
  // Clean never-versioned bucket: exactly one null version per key, across page boundaries.
  {
    FakePager p;
    for (auto &k : {"a1", "a2", "a3", "a4", "a5", "a6", "a7"}) p.items.push_back({k});
    Failures f;
    VersionScanLister l(p, f, "b");
    uint64_t n = 0;
    std::string token;
    for (;;) {
      ListPage pg;
      CHECK(l.list("a", 1000, token, &pg).empty());
      n += pg.keys.size();
      if (!pg.truncated) break;
      token = pg.next_token;
    }
    CHECK(n == 7);
    CHECK(f.other == 0);
  }
  // A key with two versions (one non-null) and a delete marker are both flagged, and the
  // multi-version key is yielded twice so verify_bucket_load reports it as a duplicate.
  {
    FakePager p;
    p.items.push_back({"a1"});
    p.items.push_back({"a2", 2, true});          // two real versions
    p.items.push_back({"a3", 1, false, true});   // null version that is a delete marker
    Failures f;
    VersionScanLister l(p, f, "b");
    std::vector<std::string> keys;
    std::string token;
    for (;;) {
      ListPage pg;
      CHECK(l.list("a", 1000, token, &pg).empty());
      keys.insert(keys.end(), pg.keys.begin(), pg.keys.end());
      if (!pg.truncated) break;
      token = pg.next_token;
    }
    CHECK(keys.size() == 4);  // a1, a2, a2, a3
    CHECK(f.other == 3);      // a2 x2 (non-null), a3 (delete marker)
    CHECK(f.samples().size() == 3);
  }
  // Wired into verify_bucket_load: a complete, never-versioned key set verifies; version
  // history (a second version of one key) fails it as a duplicate plus a version-history failure.
  {
    const auto prefixes = prefix_items(8);
    LoadSpace sp;
    sp.start = 100;
    sp.count = 60;
    sp.padding = 8;
    auto make = [&](bool history) {
      FakePager p;
      std::vector<std::string> keys;
      for (uint64_t i = 100; i < 160; ++i) keys.push_back(load_key(i, 8));
      std::sort(keys.begin(), keys.end());
      for (auto &k : keys) p.items.push_back({k});
      if (history) p.items[17].versions = 2;
      return p;
    };
    {
      FakePager p = make(false);
      Failures f;
      VersionScanLister l(p, f, "b");
      auto r = verify_bucket_load(l, "b", sp, prefixes, 3, f);
      CHECK(r.missing == 0 && r.found == 60);
      CHECK(f.duplicate + f.other + f.bad_key + f.out_of_range == 0);
    }
    {
      FakePager p = make(true);
      Failures f;
      VersionScanLister l(p, f, "b");
      verify_bucket_load(l, "b", sp, prefixes, 3, f);
      CHECK(f.duplicate == 1);  // the key with two versions is listed twice
      CHECK(f.other == 1);      // its second version is not the null version
    }
  }
  // Pager errors propagate.
  {
    struct Bad : VersionPager {
      std::string page(const std::string &, uint32_t, const std::string &, const std::string &,
                       VersionPage *) override { return "boom"; }
    } bad;
    Failures f;
    VersionScanLister l(bad, f, "b");
    ListPage pg;
    CHECK(l.list("a", 10, "", &pg) == "boom");
  }
}

static LoadSpace space(uint64_t start, uint64_t count)
{
  LoadSpace s;
  s.start = start;
  s.count = count;
  s.padding = 8;
  return s;
}

static void test_bitset_concurrent()
{
  AtomicBitset b(1000);
  std::atomic<int> wins{0};
  std::vector<std::thread> ts;
  for (int t = 0; t < 8; ++t) {
    ts.emplace_back([&]() {
      for (uint64_t i = 0; i < 1000; ++i) {
        if (!b.test_and_set(i)) ++wins;
      }
    });
  }
  for (auto &t : ts) t.join();
  CHECK(wins == 1000);  // each bit claimed by exactly one thread
  CHECK(b.test(999) && b.test(0));
}

static void test_load_ok_missing_dup()
{
  const auto prefixes = prefix_items(8);
  FakeLister l;
  for (uint64_t i = 100; i < 160; ++i) l.add(load_key(i, 8));
  {
    Failures f;
    auto r = verify_bucket_load(l, "b", space(100, 60), prefixes, 3, f);
    CHECK(r.expected == 60 && r.found == 60 && r.missing == 0);
    CHECK(f.bad_key + f.out_of_range + f.unexpected + f.duplicate + f.other == 0);
    CHECK(f.keys_checked == 60);
  }
  // missing: remove two; extra: out-of-range id; bad key; foreign put key is ignored
  l.keys.erase(std::find(l.keys.begin(), l.keys.end(), load_key(120, 8)));
  l.keys.erase(std::find(l.keys.begin(), l.keys.end(), load_key(121, 8)));
  l.add(load_key(500, 8));
  l.add(std::string(8, 'z') + std::string(20, '7'));  // wrong prefix for id
  l.add(put_key(1700000000, 3, 9, 8));
  {
    Failures f;
    auto r = verify_bucket_load(l, "b", space(100, 60), prefixes, 4, f);
    CHECK(r.missing == 2 && r.found == 58);
    CHECK(r.missing_keys.size() == 2);
    CHECK(f.out_of_range == 1 && f.bad_key == 1 && f.duplicate == 0 && f.unexpected == 0);
  }
  l.add(load_key(130, 8));  // listed twice -> duplicate
  {
    Failures f;
    verify_bucket_load(l, "b", space(100, 60), prefixes, 2, f);
    CHECK(f.duplicate == 1);
  }
  // list error
  l.fail = true;
  Failures f;
  verify_bucket_load(l, "b", space(100, 60), prefixes, 2, f);
  CHECK(f.other > 0);
}

static void test_load_unexpected_for_delete()
{
  const auto prefixes = prefix_items(8);
  FakeLister l;
  for (uint64_t i = 10; i < 20; ++i) l.add(load_key(i, 8));
  LoadSpace sp = space(0, 20);
  sp.expected_present = [](uint64_t id) { return id >= 15; };  // 0..14 should be gone
  Failures f;
  auto r = verify_bucket_load(l, "b", sp, prefixes, 2, f);
  CHECK(f.unexpected == 5);  // ids 10..14 still present
  CHECK(r.expected == 5 && r.found == 5 && r.missing == 0);
}

static void test_put()
{
  const auto prefixes = prefix_items(8);
  std::vector<uint64_t> counts = {4, 3, 5, 2};  // gtid -> put_count; 2 buckets
  FakeLister l;
  const uint64_t ts = 1700000000;
  for (uint64_t g = 0; g < counts.size(); ++g) {
    if (g % 2 != 1) continue;  // bucket 1: gtid 1 and 3
    for (uint64_t c = 0; c < counts[g]; ++c) l.add(put_key(ts, g, c, 8));
  }
  for (uint64_t i = 0; i < 20; ++i) l.add(load_key(i, 8));        // load keys ignored
  l.add(put_key(ts + 5, 1, 0, 8));                                // other run ignored
  PutSpace sp;
  sp.bucket_index = 1;
  sp.num_buckets = 2;
  sp.ts = ts;
  sp.padding = 8;
  sp.thread_counts = &counts;
  {
    Failures f;
    auto r = verify_bucket_put(l, "b1", sp, prefixes, 3, f);
    CHECK(r.expected == 5 && r.found == 5 && r.missing == 0);
    CHECK(f.bad_key + f.out_of_range + f.unexpected + f.duplicate == 0);
  }
  l.keys.erase(std::find(l.keys.begin(), l.keys.end(), put_key(ts, 1, 2, 8)));  // missing
  l.add(put_key(ts, 3, 7, 8));  // counter >= put_count -> unexpected
  l.add(put_key(ts, 0, 0, 8));  // gtid 0 belongs to bucket 0 -> out of range
  Failures f;
  auto r = verify_bucket_put(l, "b1", sp, prefixes, 2, f);
  CHECK(r.missing == 1 && r.missing_keys.size() == 1);
  CHECK(f.unexpected == 1 && f.out_of_range == 1);
}

static void test_versions_formula()
{
  CHECK(expected_versions(0, 5, 0) == 0);        // no puts
  CHECK(expected_versions(5, 5, 4) == 1);        // exactly one full loop, no partial
  CHECK(expected_versions(7, 5, 1) == 2);        // partial loop covered positions 0,1
  CHECK(expected_versions(7, 5, 2) == 1);
  CHECK(expected_versions(12, 5, 1) == 3 && expected_versions(12, 5, 2) == 2);
}

int main()
{
  test_bitset_concurrent();
  test_load_ok_missing_dup();
  test_load_unexpected_for_delete();
  test_put();
  test_versions_formula();
  test_version_scan();
  std::puts("verify_test OK");
}
