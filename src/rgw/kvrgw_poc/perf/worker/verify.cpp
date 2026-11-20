#include "verify.hpp"

#include <algorithm>
#include <atomic>
#include <thread>

namespace perfw {

void AtomicBitset::resize(uint64_t nbits)
{
  nbits_ = nbits;
  words_.assign((nbits + 63) / 64, 0);
}

bool AtomicBitset::test_and_set(uint64_t i)
{
  std::atomic_ref<uint64_t> w(words_[i / 64]);
  const uint64_t mask = 1ULL << (i % 64);
  return (w.fetch_or(mask, std::memory_order_relaxed) & mask) != 0;
}

bool AtomicBitset::test(uint64_t i) const
{
  std::atomic_ref<uint64_t> w(words_[i / 64]);
  return (w.load(std::memory_order_relaxed) >> (i % 64)) & 1;
}

void Failures::sample(const std::string &s)
{
  std::lock_guard<std::mutex> g(mu_);
  if (samples_.size() < kMaxSamples) samples_.push_back(s);
}

std::vector<std::string> Failures::samples() const
{
  std::lock_guard<std::mutex> g(mu_);
  return samples_;
}

std::string VersionScanLister::list(const std::string &prefix, uint32_t max_keys,
                                    const std::string &token, ListPage *out)
{
  // The continuation token carries both markers: key '\0' version marker.
  std::string key_marker, version_marker;
  if (const auto nul = token.find('\0'); nul != std::string::npos) {
    key_marker = token.substr(0, nul);
    version_marker = token.substr(nul + 1);
  } else {
    key_marker = token;
  }
  VersionPage p;
  if (auto err = pager_.page(prefix, max_keys, key_marker, version_marker, &p); !err.empty()) {
    return err;
  }
  out->keys.clear();
  out->keys.reserve(p.entries.size());
  for (auto &e : p.entries) {
    if (!e.null_version || e.delete_marker) {
      ++f_.other;
      f_.sample("bucket " + bucket_ + " has version history: " +
                (e.delete_marker ? "delete marker" : "non-null version") + " for key " + e.key);
    }
    out->keys.push_back(std::move(e.key));
  }
  out->truncated = p.truncated;
  out->next_token = p.next_key_marker;
  out->next_token.push_back('\0');
  out->next_token += p.next_version_marker;
  return {};
}

void scan_prefixes(Lister &lister, const std::string &bucket,
                   const std::vector<std::string> &prefixes, int threads, Failures &f,
                   const std::function<void(const std::string &)> &on_key)
{
  std::atomic<size_t> next{0};
  auto work = [&]() {
    for (;;) {
      const size_t i = next.fetch_add(1);
      if (i >= prefixes.size()) return;
      std::string token;
      for (;;) {
        ListPage page;
        std::string err = lister.list(prefixes[i], 1000, token, &page);
        if (!err.empty()) {
          ++f.other;
          f.sample("list " + bucket + " prefix '" + prefixes[i] + "': " + err);
          break;
        }
        for (const auto &k : page.keys) on_key(k);
        if (!page.truncated) break;
        token = page.next_token;
        if (token.empty()) {
          ++f.other;
          f.sample("list " + bucket + ": truncated without continuation token");
          break;
        }
      }
    }
  };
  const int n = std::max(1, std::min<int>(threads, static_cast<int>(prefixes.size())));
  std::vector<std::thread> ts;
  for (int t = 1; t < n; ++t) ts.emplace_back(work);
  work();
  for (auto &t : ts) t.join();
}

BucketResult verify_bucket_load(Lister &lister, const std::string &bucket, const LoadSpace &sp,
                                const std::vector<std::string> &prefixes, int threads,
                                Failures &f)
{
  BucketResult r;
  r.bucket = bucket;
  AtomicBitset bits(sp.count);
  std::atomic<uint64_t> found{0};
  auto present = [&](uint64_t id) { return !sp.expected_present || sp.expected_present(id); };

  scan_prefixes(lister, bucket, prefixes, threads, f, [&](const std::string &key) {
    ++f.keys_checked;
    if (sp.ignore_put_keys && key.size() == put_key_len(sp.padding)) {
      auto pk = parse_put_key(key, sp.padding);
      if (pk && key == put_key(pk->ts, pk->gtid, pk->counter, sp.padding)) return;
    }
    auto id = parse_key_id(key);
    if (!id || key != load_key(*id, sp.padding)) {
      ++f.bad_key;
      f.sample("bad key in " + bucket + ": " + key);
      return;
    }
    if (*id < sp.start || *id >= sp.start + sp.count) {
      ++f.out_of_range;
      f.sample("out of range id " + std::to_string(*id) + " in " + bucket);
      return;
    }
    if (!present(*id)) {
      ++f.unexpected;
      f.sample("unexpected key (should be absent) in " + bucket + ": " + key);
      return;
    }
    if (bits.test_and_set(*id - sp.start)) {
      ++f.duplicate;
      f.sample("duplicate key in " + bucket + ": " + key);
      return;
    }
    ++found;
  });

  r.found = found.load();
  for (uint64_t i = 0; i < sp.count; ++i) {
    const uint64_t id = sp.start + i;
    if (!present(id)) continue;
    ++r.expected;
    if (!bits.test(i)) {
      ++r.missing;
      if (r.missing_keys.size() < kMaxMissingKeys) {
        r.missing_keys.push_back(load_key(id, sp.padding));
      }
    }
  }
  return r;
}

BucketResult verify_bucket_put(Lister &lister, const std::string &bucket, const PutSpace &sp,
                               const std::vector<std::string> &prefixes, int threads,
                               Failures &f)
{
  BucketResult r;
  r.bucket = bucket;
  const auto &tc = *sp.thread_counts;
  // One bitset per gtid owned by this bucket.
  std::vector<AtomicBitset> bits(tc.size());
  for (uint64_t g = 0; g < tc.size(); ++g) {
    if (g % sp.num_buckets == sp.bucket_index) {
      bits[g].resize(tc[g]);
      r.expected += tc[g];
    }
  }
  std::atomic<uint64_t> found{0};

  scan_prefixes(lister, bucket, prefixes, threads, f, [&](const std::string &key) {
    ++f.keys_checked;
    if (key.size() != put_key_len(sp.padding)) return;  // load key or foreign
    auto pk = parse_put_key(key, sp.padding);
    if (!pk || pk->ts != sp.ts) return;  // another run's key (or foreign)
    if (key != put_key(pk->ts, pk->gtid, pk->counter, sp.padding)) {
      ++f.bad_key;
      f.sample("bad put key in " + bucket + ": " + key);
      return;
    }
    if (pk->gtid >= tc.size() || pk->gtid % sp.num_buckets != sp.bucket_index) {
      ++f.out_of_range;
      f.sample("put key from wrong bucket/gtid in " + bucket + ": " + key);
      return;
    }
    if (pk->counter >= tc[pk->gtid]) {
      ++f.unexpected;
      f.sample("unexpected put key (counter >= put_count) in " + bucket + ": " + key);
      return;
    }
    if (bits[pk->gtid].test_and_set(pk->counter)) {
      ++f.duplicate;
      f.sample("duplicate put key in " + bucket + ": " + key);
      return;
    }
    ++found;
  });

  r.found = found.load();
  for (uint64_t g = 0; g < tc.size(); ++g) {
    if (g % sp.num_buckets != sp.bucket_index) continue;
    for (uint64_t c = 0; c < tc[g]; ++c) {
      if (bits[g].test(c)) continue;
      ++r.missing;
      if (r.missing_keys.size() < kMaxMissingKeys) {
        r.missing_keys.push_back("gtid=" + std::to_string(g) + " counter=" + std::to_string(c) +
                                 " key=" + put_key(sp.ts, static_cast<uint32_t>(g), c, sp.padding));
      }
    }
  }
  return r;
}

}  // namespace perfw
