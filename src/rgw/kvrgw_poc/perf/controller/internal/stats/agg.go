package stats

import (
	"fmt"
	"sort"
	"strings"

	pb "kvrgw-perf/gen/perf/v1"
)

// Metric aggregate for one op type in one window (or cumulative).
type Metric struct {
	Count, Errors, SumMicros uint64
	// QueueFull counts submits refused with KVRGW_ERR_QUEUE_FULL (backed off and retried,
	// not errors); Missed counts open-loop ops that were due but not issued.
	QueueFull, Missed uint64
	ErrorCodes        map[string]uint64 // errors by code name
	Hist              Hist
}

func (m *Metric) Merge(o *Metric) {
	m.Count += o.Count
	m.Errors += o.Errors
	m.SumMicros += o.SumMicros
	m.QueueFull += o.QueueFull
	m.Missed += o.Missed
	for k, v := range o.ErrorCodes {
		if m.ErrorCodes == nil {
			m.ErrorCodes = map[string]uint64{}
		}
		m.ErrorCodes[k] += v
	}
	m.Hist.Merge(o.Hist)
}

// ShortCode strips the library prefix for display: KVRGW_ERR_TXN_CONFLICT -> TXN_CONFLICT.
func ShortCode(c string) string { return strings.TrimPrefix(c, "KVRGW_ERR_") }

// FormatErrorCodes renders "TXN_CONFLICT x5, NO_SUCH_BUCKET x1" (largest first).
func FormatErrorCodes(codes map[string]uint64) string {
	type kv struct {
		k string
		v uint64
	}
	var l []kv
	for k, v := range codes {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	parts := make([]string, len(l))
	for i, e := range l {
		parts[i] = fmt.Sprintf("%s x%d", ShortCode(e.k), e.v)
	}
	return strings.Join(parts, ", ")
}

func (m *Metric) Empty() bool {
	return m.Count == 0 && m.Errors == 0 && m.QueueFull == 0 && m.Missed == 0
}

// IsCounter reports counter-style op types (no latency).
func IsCounter(op string) bool { return op == "keys_listed" || op == "keys_deleted" }

// FromProto converts an OpStats message.
func FromProto(o *pb.OpStats) Metric {
	m := Metric{Count: o.Count, Errors: o.Errors, SumMicros: o.SumMicros, QueueFull: o.QueueFull, Missed: o.Missed}
	if len(o.ErrorCodes) > 0 {
		m.ErrorCodes = map[string]uint64{}
		for k, v := range o.ErrorCodes {
			m.ErrorCodes[k] = v
		}
	}
	if o.Latency != nil {
		m.Hist.AddSparse(o.Latency.BucketIndex, o.Latency.BucketCount)
	}
	return m
}

// Window is one aggregated window across workers.
type Window struct {
	Index      int64
	DurationNs int64
	Ops        map[string]*Metric
	Server     map[string]uint64 // summed server stats (cumulative) as of this window
}

// ServerFlat flattens a ServerStats message to the names used in server_stats.csv.
func ServerFlat(s *pb.ServerStats) map[string]uint64 {
	out := map[string]uint64{}
	if s == nil {
		return out
	}
	for _, o := range s.Ops {
		out[o.Op+".count"] = o.Count
		out[o.Op+".total_us"] = o.TotalUs
		out[o.Op+".fdb_us"] = o.FdbUs
		out[o.Op+".fdb_get_us"] = o.FdbGetUs
		out[o.Op+".fdb_commit_us"] = o.FdbCommitUs
		out[o.Op+".fdb_scan_us"] = o.FdbScanUs
		out[o.Op+".disk_us"] = o.DiskUs
	}
	out["batch.commits"] = s.BatchCommits
	out["batch.entries"] = s.BatchEntries
	out["batch.wait_us_total"] = s.BatchWaitUsTotal
	out["batch.queue_size_total"] = s.BatchQueueSizeTotal
	out["batch.conflict_pushbacks"] = s.BatchConflictPushbacks
	out["txn.retries"] = s.TxnRetries
	out["txn.hard_failures"] = s.TxnHardFailures
	out["async.queue_full_rejects"] = s.QueueFullRejects
	out["async.inflight_ops_peak"] = s.InflightOpsPeak
	out["async.frames_heap_fallback"] = s.FramesHeapFallback
	out["async.max_frame_size"] = s.MaxFrameSize
	for k, v := range s.Errors {
		out["error."+k] = v
	}
	return out
}

// Aggregator sums same-numbered windows across workers. A window is released once every
// still-running worker has reported a window >= it (workers emit every window), or has
// finished.
type Aggregator struct {
	workers int
	pending map[int64]*Window
	latest  []int64 // highest window reported per worker (-1 none)
	done    []bool
	lastSrv []map[string]uint64
	next    int64 // next window index to release
}

func NewAggregator(workers int) *Aggregator {
	a := &Aggregator{workers: workers, pending: map[int64]*Window{},
		latest: make([]int64, workers), done: make([]bool, workers),
		lastSrv: make([]map[string]uint64, workers)}
	for i := range a.latest {
		a.latest[i] = -1
	}
	return a
}

// Add records a progress report from worker w and returns any windows now complete.
func (a *Aggregator) Add(w int, p *pb.ProgressReport) []*Window {
	win := a.pending[p.Window]
	if win == nil {
		win = &Window{Index: p.Window, Ops: map[string]*Metric{}}
		a.pending[p.Window] = win
	}
	if p.WindowDurationNs > win.DurationNs {
		win.DurationNs = p.WindowDurationNs
	}
	for _, o := range p.WindowStats {
		m := FromProto(o)
		cur := win.Ops[o.OperationType]
		if cur == nil {
			cur = &Metric{}
			win.Ops[o.OperationType] = cur
		}
		cur.Merge(&m)
	}
	if p.ServerStats != nil {
		a.lastSrv[w] = ServerFlat(p.ServerStats)
	}
	if p.Window > a.latest[w] {
		a.latest[w] = p.Window
	}
	return a.release()
}

// Finish marks worker w as finished (no more windows) and returns completed windows.
func (a *Aggregator) Finish(w int) []*Window {
	a.done[w] = true
	return a.release()
}

// Flush releases everything that is pending (after all workers finished).
func (a *Aggregator) Flush() []*Window {
	for i := range a.done {
		a.done[i] = true
	}
	return a.release()
}

func (a *Aggregator) release() []*Window {
	var out []*Window
	for {
		allDone := true
		for i := 0; i < a.workers; i++ {
			if a.done[i] {
				continue
			}
			allDone = false
			if a.latest[i] < a.next {
				return out // an unfinished worker has not reported window `next` yet
			}
		}
		if allDone && len(a.pending) == 0 {
			return out
		}
		if w := a.pending[a.next]; w != nil {
			delete(a.pending, a.next)
			// server stats: sum of the latest snapshots of all workers
			w.Server = map[string]uint64{}
			for _, s := range a.lastSrv {
				for k, v := range s {
					w.Server[k] += v
				}
			}
			out = append(out, w)
		}
		a.next++
	}
}
