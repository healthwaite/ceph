package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"kvrgw-perf/internal/results"
)

// ClusterSample is the cluster-level extraction of one `status json`.
type ClusterSample struct {
	TxnHz, ReadsHz, WritesHz, ConflictHz                     float64
	WorstQueueSS, WorstQueueLog, LimitingQueueSS, DurLagSecs float64
}

// ProcessRow is one (process, role) row; Vals only holds fields applicable to the role.
type ProcessRow struct {
	Addr string
	Role string
	Vals map[string]float64
}

// ProcessColumns are the numeric columns of fdb_process.csv, in order.
var ProcessColumns = []string{"cpu_cores", "mem_bytes", "rss_bytes", "input_hz", "durable_hz",
	"stored_bytes", "kvstore_bytes", "data_lag_s", "durability_lag_s", "queue_disk_bytes",
	"queue_mem_bytes", "disk_busy", "disk_reads_hz", "disk_writes_hz"}

type obj = map[string]any

func dig(m any, path ...string) (any, bool) {
	cur := m
	for _, p := range path {
		o, ok := cur.(obj)
		if !ok {
			return nil, false
		}
		cur, ok = o[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func num(m any, path ...string) (float64, bool) {
	v, ok := dig(m, path...)
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	return f, ok
}

func numOr0(m any, path ...string) float64 {
	f, _ := num(m, path...)
	return f
}

// ParseStatus extracts cluster and per-process rows from `status json` output.
func ParseStatus(data []byte) (ClusterSample, []ProcessRow, error) {
	var cs ClusterSample
	// fdbcli may print warnings before the JSON document.
	if i := bytes.IndexByte(data, '{'); i > 0 {
		data = data[i:]
	}
	var top obj
	if err := json.Unmarshal(data, &top); err != nil {
		return cs, nil, fmt.Errorf("status json: %w", err)
	}
	cl, ok := top["cluster"].(obj)
	if !ok {
		return cs, nil, fmt.Errorf("status json: no cluster section")
	}
	cs.TxnHz = numOr0(cl, "workload", "transactions", "committed", "hz")
	cs.ReadsHz = numOr0(cl, "workload", "operations", "reads", "hz")
	cs.WritesHz = numOr0(cl, "workload", "operations", "writes", "hz")
	cs.ConflictHz = numOr0(cl, "workload", "transactions", "conflicted", "hz")
	cs.WorstQueueSS = numOr0(cl, "qos", "worst_queue_bytes_storage_server")
	cs.WorstQueueLog = numOr0(cl, "qos", "worst_queue_bytes_log_server")
	cs.LimitingQueueSS = numOr0(cl, "qos", "limiting_queue_bytes_storage_server")
	cs.DurLagSecs = numOr0(cl, "qos", "limiting_durability_lag_storage_server", "seconds")

	procs, _ := cl["processes"].(obj)
	ids := make([]string, 0, len(procs))
	for id := range procs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var rows []ProcessRow
	for _, id := range ids {
		p, _ := procs[id].(obj)
		addr, _ := p["address"].(string)
		common := func() map[string]float64 {
			v := map[string]float64{
				"cpu_cores":      numOr0(p, "cpu", "usage_cores"),
				"mem_bytes":      numOr0(p, "memory", "used_bytes"),
				"disk_busy":      numOr0(p, "disk", "busy"),
				"disk_reads_hz":  numOr0(p, "disk", "reads", "hz"),
				"disk_writes_hz": numOr0(p, "disk", "writes", "hz"),
			}
			if r, ok := num(p, "memory", "rss_bytes"); ok {
				v["rss_bytes"] = r
			} else {
				v["rss_bytes"] = v["mem_bytes"]
			}
			return v
		}
		roles, _ := p["roles"].([]any)
		var other []string
		for _, ri := range roles {
			r, _ := ri.(obj)
			name, _ := r["role"].(string)
			switch name {
			case "storage":
				v := common()
				v["input_hz"] = numOr0(r, "input_bytes", "hz")
				v["durable_hz"] = numOr0(r, "durable_bytes", "hz")
				v["stored_bytes"] = numOr0(r, "stored_bytes")
				v["kvstore_bytes"] = numOr0(r, "kvstore_used_bytes")
				v["data_lag_s"] = numOr0(r, "data_lag", "seconds")
				v["durability_lag_s"] = numOr0(r, "durability_lag", "seconds")
				v["queue_disk_bytes"] = numOr0(r, "queue_disk_used_bytes")
				rows = append(rows, ProcessRow{addr, "storage", v})
			case "log":
				v := common()
				v["input_hz"] = numOr0(r, "input_bytes", "hz")
				v["durable_hz"] = numOr0(r, "durable_bytes", "hz")
				v["queue_disk_bytes"] = numOr0(r, "queue_disk_used_bytes")
				v["queue_mem_bytes"] = numOr0(r, "queue_memory_bytes")
				rows = append(rows, ProcessRow{addr, "log", v})
			default:
				other = append(other, name)
			}
		}
		class, _ := p["class_type"].(string)
		wantOther := class == "stateless"
		for _, n := range other {
			if n == "commit_proxy" || n == "grv_proxy" || n == "resolver" {
				wantOther = true
			}
		}
		if wantOther {
			role := "none"
			if len(other) > 0 {
				role = strings.Join(other, ",")
			}
			rows = append(rows, ProcessRow{addr, role, common()})
		}
	}
	return cs, rows, nil
}

// FDBSampler polls fdbcli status json.
type FDBSampler struct {
	Path        string // fdbcli binary
	ClusterFile string
	Interval    time.Duration
	Cluster     *results.CSV
	Process     *results.CSV
	Logf        func(format string, args ...any)

	Samples, Failures atomic.Int64
}

// Status runs `fdbcli status json` with a 5s outer timeout.
func (s *FDBSampler) Status(ctx context.Context) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := []string{}
	if s.ClusterFile != "" {
		args = append(args, "-C", s.ClusterFile)
	}
	args = append(args, "--exec", "status json", "--timeout", "3")
	out, err := exec.CommandContext(cctx, s.Path, args...).Output()
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	return out, nil
}

// Run polls until ctx is cancelled.
func (s *FDBSampler) Run(ctx context.Context) {
	tk := time.NewTicker(s.Interval)
	defer tk.Stop()
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tk.C:
			out, err := s.Status(ctx)
			var cs ClusterSample
			var rows []ProcessRow
			if err == nil {
				cs, rows, err = ParseStatus(out)
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.Failures.Add(1)
				if !warned {
					warned = true
					s.Logf("WARN fdb status sample failed (further failures counted silently): %v", err)
				}
				continue
			}
			s.Samples.Add(1)
			ms := results.I(now.UnixMilli())
			s.Cluster.Row(ms, results.F(cs.TxnHz), results.F(cs.ReadsHz), results.F(cs.WritesHz),
				results.F(cs.ConflictHz), results.F(cs.WorstQueueSS), results.F(cs.WorstQueueLog),
				results.F(cs.LimitingQueueSS), results.F(cs.DurLagSecs))
			for _, r := range rows {
				rec := []string{ms, r.Addr, r.Role}
				for _, c := range ProcessColumns {
					if v, ok := r.Vals[c]; ok {
						rec = append(rec, results.F(v))
					} else {
						rec = append(rec, "")
					}
				}
				s.Process.Row(rec...)
			}
		}
	}
}
