#include "stats.hpp"

namespace perfw {

const char *metric_name(Metric m)
{
  switch (m) {
    case Metric::PutObject: return "put_object";
    case Metric::ListObjects: return "list_objects";
    case Metric::DeleteMulti: return "delete_multi";
    case Metric::ListDeleteMulti: return "list_delete_multi";
    case Metric::KeysListed: return "keys_listed";
    case Metric::KeysDeleted: return "keys_deleted";
    case Metric::SendLag: return "send_lag";
    default: return "unknown";
  }
}

void MetricStats::record(uint64_t micros)
{
  ++count;
  sum_micros += micros;
  if (hist.empty()) {
    hist.assign(kHistBuckets, 0);
  }
  ++hist[hist_index(micros)];
}

void MetricStats::merge(const MetricStats &o)
{
  count += o.count;
  errors += o.errors;
  sum_micros += o.sum_micros;
  queue_full += o.queue_full;
  missed += o.missed;
  for (const auto &[k, v] : o.error_codes) error_codes[k] += v;
  if (!o.hist.empty()) {
    if (hist.empty()) {
      hist.assign(kHistBuckets, 0);
    }
    for (size_t i = 0; i < o.hist.size(); ++i) {
      hist[i] += o.hist[i];
    }
  }
}

void ThreadStats::record(Metric m, uint64_t micros)
{
  std::lock_guard<std::mutex> g(mu_);
  w_[static_cast<size_t>(m)].record(micros);
}

void ThreadStats::record_error(Metric m, const std::string &code)
{
  std::lock_guard<std::mutex> g(mu_);
  auto &s = w_[static_cast<size_t>(m)];
  ++s.errors;
  ++s.error_codes[code.empty() ? "unknown" : code];
}

namespace {
std::mutex g_text_mu;
std::map<std::string, std::string> g_texts;
}  // namespace

void register_error_text(const std::string &code, const std::string &text)
{
  std::lock_guard<std::mutex> g(g_text_mu);
  g_texts.emplace(code, text);
}

std::map<std::string, std::string> error_texts()
{
  std::lock_guard<std::mutex> g(g_text_mu);
  return g_texts;
}

void ThreadStats::add_units(Metric m, uint64_t n)
{
  std::lock_guard<std::mutex> g(mu_);
  w_[static_cast<size_t>(m)].count += n;
}

void ThreadStats::add_queue_full(Metric m, uint64_t n)
{
  std::lock_guard<std::mutex> g(mu_);
  w_[static_cast<size_t>(m)].queue_full += n;
}

void ThreadStats::add_missed(Metric m, uint64_t n)
{
  std::lock_guard<std::mutex> g(mu_);
  w_[static_cast<size_t>(m)].missed += n;
}

StatsArray ThreadStats::take_window()
{
  StatsArray out;
  std::lock_guard<std::mutex> g(mu_);
  std::swap(out, w_);
  return out;
}

StatsHub::StatsHub(int threads)
{
  for (int i = 0; i < threads; ++i) {
    threads_.push_back(std::make_unique<ThreadStats>());
  }
}

StatsArray StatsHub::collect_window()
{
  StatsArray win;
  for (auto &t : threads_) {
    auto w = t->take_window();
    for (int i = 0; i < kMetricCount; ++i) {
      win[static_cast<size_t>(i)].merge(w[static_cast<size_t>(i)]);
    }
  }
  for (int i = 0; i < kMetricCount; ++i) {
    cum_[static_cast<size_t>(i)].merge(win[static_cast<size_t>(i)]);
  }
  return win;
}

}  // namespace perfw
