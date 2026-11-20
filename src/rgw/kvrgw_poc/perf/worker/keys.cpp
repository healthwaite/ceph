#include "keys.hpp"

#include <algorithm>
#include <cstdio>

namespace perfw {

uint64_t splitmix64_next(uint64_t &state)
{
  state += kSplitMixInc;
  uint64_t z = state;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

uint64_t splitmix64_mix(uint64_t x)
{
  return splitmix64_next(x);
}

std::string rand_prefix(uint64_t seed, int padding_bytes)
{
  std::string out;
  out.reserve(static_cast<size_t>(padding_bytes));
  uint64_t st = seed;
  for (int i = 0; i < padding_bytes; ++i) {
    out.push_back(kCharset[splitmix64_next(st) % kCharset.size()]);
  }
  return out;
}

static void append_dec20(std::string &s, uint64_t v)
{
  char buf[32];
  int n = std::snprintf(buf, sizeof(buf), "%020llu", static_cast<unsigned long long>(v));
  s.append(buf, static_cast<size_t>(n));
}

static void append_hex(std::string &s, uint64_t v, int width)
{
  static const char *digits = "0123456789abcdef";
  for (int i = width - 1; i >= 0; --i) {
    s.push_back(digits[(v >> (4 * i)) & 0xf]);
  }
}

std::string load_key(uint64_t index, int padding_bytes)
{
  std::string k = rand_prefix(index, padding_bytes);
  append_dec20(k, index);
  return k;
}

uint64_t put_key_seed(uint64_t ts, uint64_t gtid, uint64_t counter)
{
  return splitmix64_mix(splitmix64_mix(ts) ^ (gtid << 32) ^ counter);
}

std::string put_key(uint64_t ts, uint32_t gtid, uint64_t counter, int padding_bytes)
{
  std::string k = rand_prefix(put_key_seed(ts, gtid, counter), padding_bytes);
  append_hex(k, ts, 8);
  append_hex(k, gtid, 4);
  append_dec20(k, counter);
  return k;
}

static std::optional<uint64_t> parse_digits(std::string_view s, int base)
{
  if (s.empty()) {
    return std::nullopt;
  }
  uint64_t v = 0;
  for (char c : s) {
    int d;
    if (c >= '0' && c <= '9') {
      d = c - '0';
    } else if (base == 16 && c >= 'a' && c <= 'f') {
      d = c - 'a' + 10;
    } else {
      return std::nullopt;
    }
    if (d >= base) {
      return std::nullopt;
    }
    uint64_t nv = v * static_cast<uint64_t>(base) + static_cast<uint64_t>(d);
    if (nv < v) {
      return std::nullopt;
    }
    v = nv;
  }
  return v;
}

std::optional<uint64_t> parse_key_id(std::string_view key)
{
  if (key.size() < 20) {
    return std::nullopt;
  }
  return parse_digits(key.substr(key.size() - 20), 10);
}

std::optional<ParsedPutKey> parse_put_key(std::string_view key, int padding_bytes)
{
  if (key.size() != put_key_len(padding_bytes)) {
    return std::nullopt;
  }
  const size_t p = static_cast<size_t>(padding_bytes);
  auto ts = parse_digits(key.substr(p, 8), 16);
  auto gtid = parse_digits(key.substr(p + 8, 4), 16);
  auto ctr = parse_digits(key.substr(p + 12, 20), 10);
  if (!ts || !gtid || !ctr) {
    return std::nullopt;
  }
  return ParsedPutKey{*ts, static_cast<uint32_t>(*gtid), *ctr};
}

std::string bucket_name(std::string_view prefix, uint64_t index)
{
  std::string s(prefix);
  s.push_back('-');
  s += std::to_string(index);
  return s;
}

uint64_t block_for_index(uint64_t i, uint64_t total, uint64_t parts)
{
  const uint64_t base = total / parts;
  const uint64_t extra = total % parts;
  const uint64_t boundary = extra * (base + 1);
  return i < boundary ? i / (base + 1) : extra + (i - boundary) / base;
}

Range block_range(uint64_t part, uint64_t parts, uint64_t total)
{
  const uint64_t base = total / parts;
  const uint64_t extra = total % parts;
  Range r;
  r.count = base + (part < extra ? 1 : 0);
  r.start = part * base + std::min(part, extra);
  return r;
}

std::vector<uint64_t> owned_buckets(int worker_index, int worker_count, uint64_t num_buckets)
{
  std::vector<uint64_t> v;
  for (uint64_t b = 0; b < num_buckets; ++b) {
    if (bucket_owner(b, worker_count) == worker_index) {
      v.push_back(b);
    }
  }
  return v;
}

std::vector<std::string> prefix_items(int padding_bytes)
{
  std::vector<std::string> v;
  if (padding_bytes == 0) {
    v.emplace_back();
    return v;
  }
  for (char c : kCharset) {
    v.emplace_back(1, c);
  }
  return v;
}

}  // namespace perfw
