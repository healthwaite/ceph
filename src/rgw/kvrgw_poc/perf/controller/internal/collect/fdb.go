package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kvrgw-perf/internal/results"
)

// ClusterSample is the cluster-level extraction of one `status json`.
type ClusterSample struct {
	TxnHz, ReadsHz, WritesHz, ConflictHz                     float64
	WorstQueueSS, WorstQueueLog, LimitingQueueSS, DurLagSecs float64
	DiskUsedBytes, KVBytes                                   float64 // cluster.data total_disk_used_bytes / total_kv_size_bytes
}

// RoleRow is one line of the cluster configuration table: the processes holding a role and
// their combined CPU. A process holding several roles counts under each.
type RoleRow struct {
	Role  string
	Cores float64
	Procs int
}

// RoleTable sums per-process CPU by role, by cores descending.
func RoleTable(rows []CPURow) []RoleRow {
	by := map[string]*RoleRow{}
	for _, r := range rows {
		for _, role := range r.Roles {
			rr := by[role]
			if rr == nil {
				rr = &RoleRow{Role: role}
				by[role] = rr
			}
			rr.Cores += r.Cores
			rr.Procs++
		}
	}
	out := make([]RoleRow, 0, len(by))
	for _, rr := range by {
		out = append(out, *rr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cores != out[j].Cores {
			return out[i].Cores > out[j].Cores
		}
		return out[i].Role < out[j].Role
	})
	return out
}

// FormatRoleTable renders the table as aligned text lines, each prefixed with indent.
func FormatRoleTable(rows []RoleRow, indent string) string {
	width := 4
	for _, r := range rows {
		if len(r.Role) > width {
			width = len(r.Role)
		}
	}
	width += 2
	var b strings.Builder
	fmt.Fprintf(&b, "%s%-*s%8s%7s\n", indent, width, "role", "cores", "procs")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s%-*s%8.2f%7d\n", indent, width, r.Role, r.Cores, r.Procs)
	}
	return b.String()
}

// ParseConfig returns the role table of a `status json` document.
func ParseConfig(data []byte) ([]RoleRow, error) {
	_, _, cpu, err := ParseStatusFull(data)
	if err != nil {
		return nil, err
	}
	return RoleTable(cpu), nil
}

// CPURow is the CPU of one process in one sample, with every role it holds. Unlike ProcessRow
// it covers all processes (coordinators, masters, ... too) and has one row per process.
type CPURow struct {
	Addr, Class string
	Roles       []string // sorted, de-duplicated; ["none"] if the process holds no role
	Cores       float64
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
	cs, rows, _, err := ParseStatusFull(data)
	return cs, rows, err
}

// ParseStatusFull is ParseStatus plus one CPURow for every process in the cluster.
func ParseStatusFull(data []byte) (ClusterSample, []ProcessRow, []CPURow, error) {
	var cs ClusterSample
	// fdbcli may print warnings before the JSON document.
	if i := bytes.IndexByte(data, '{'); i > 0 {
		data = data[i:]
	}
	var top obj
	if err := json.Unmarshal(data, &top); err != nil {
		return cs, nil, nil, fmt.Errorf("status json: %w", err)
	}
	cl, ok := top["cluster"].(obj)
	if !ok {
		return cs, nil, nil, fmt.Errorf("status json: no cluster section")
	}
	cs.TxnHz = numOr0(cl, "workload", "transactions", "committed", "hz")
	cs.ReadsHz = numOr0(cl, "workload", "operations", "reads", "hz")
	cs.WritesHz = numOr0(cl, "workload", "operations", "writes", "hz")
	cs.ConflictHz = numOr0(cl, "workload", "transactions", "conflicted", "hz")
	cs.WorstQueueSS = numOr0(cl, "qos", "worst_queue_bytes_storage_server")
	cs.WorstQueueLog = numOr0(cl, "qos", "worst_queue_bytes_log_server")
	cs.LimitingQueueSS = numOr0(cl, "qos", "limiting_queue_bytes_storage_server")
	cs.DurLagSecs = numOr0(cl, "qos", "limiting_durability_lag_storage_server", "seconds")

	cs.DiskUsedBytes = numOr0(cl, "data", "total_disk_used_bytes")
	cs.KVBytes = numOr0(cl, "data", "total_kv_size_bytes")

	procs, _ := cl["processes"].(obj)
	ids := make([]string, 0, len(procs))
	for id := range procs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var rows []ProcessRow
	var cpuRows []CPURow
	for _, id := range ids {
		p, _ := procs[id].(obj)
		addr, _ := p["address"].(string)
		class, _ := p["class_type"].(string)
		seen := map[string]bool{}
		for _, ri := range func() []any { r, _ := p["roles"].([]any); return r }() {
			if r, ok := ri.(obj); ok {
				if name, _ := r["role"].(string); name != "" {
					seen[name] = true
				}
			}
		}
		labels := make([]string, 0, len(seen))
		for n := range seen {
			labels = append(labels, n)
		}
		sort.Strings(labels)
		if len(labels) == 0 {
			labels = []string{"none"}
		}
		cpuRows = append(cpuRows, CPURow{Addr: addr, Class: class, Roles: labels, Cores: numOr0(p, "cpu", "usage_cores")})
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
	return cs, rows, cpuRows, nil
}

// FDBSampler polls fdbcli status json.
type FDBSampler struct {
	Path        string // fdbcli binary
	ClusterFile string
	Interval    time.Duration
	Timeout     time.Duration // fdbcli --timeout (whole seconds)
	OuterLimit  time.Duration // kill the fdbcli process after this long (> Timeout)
	Cluster     *results.CSV
	Process     *results.CSV
	CPU         *results.CSV   // optional: per-process CPU for every process
	Raw         *results.Lines // optional: every status sample (or failure), one JSON object per line
	Logf        func(format string, args ...any)

	Samples, Failures atomic.Int64

	phase atomic.Pointer[string]

	mu    sync.Mutex
	last  ClusterSample
	hasLs bool
}

// SetPhase names the run phase recorded with each raw sample ("init", "benchmark", ...).
func (s *FDBSampler) SetPhase(p string) { s.phase.Store(&p) }

func (s *FDBSampler) currentPhase() string {
	if p := s.phase.Load(); p != nil {
		return *p
	}
	return ""
}

// writeRaw appends one record to Raw: the compacted status document, or the error. ts and phase
// are those of the moment the call started; a call that straddles a phase change keeps the
// phase it started in (took_ms shows how long it ran).
func (s *FDBSampler) writeRaw(ts time.Time, phase string, took time.Duration, out []byte, err error) {
	if s.Raw == nil {
		return
	}
	var b bytes.Buffer
	ph, _ := json.Marshal(phase)
	fmt.Fprintf(&b, `{"ts_ms":%d,"phase":%s,"took_ms":%d,`, ts.UnixMilli(), ph, took.Milliseconds())
	if err == nil {
		var doc bytes.Buffer
		// fdbcli may print warnings before the JSON document (ParseStatusFull skips them too).
		if i := bytes.IndexByte(out, '{'); i > 0 {
			out = out[i:]
		}
		if err = json.Compact(&doc, out); err == nil {
			b.WriteString(`"status":`)
			b.Write(doc.Bytes())
			b.WriteByte('}')
			err = nil
		} else {
			err = fmt.Errorf("status output is not valid JSON: %w", err)
		}
	}
	if err != nil {
		b.Reset()
		msg, _ := json.Marshal(err.Error())
		fmt.Fprintf(&b, `{"ts_ms":%d,"phase":%s,"took_ms":%d,"error":%s}`, ts.UnixMilli(), ph, took.Milliseconds(), msg)
	}
	if werr := s.Raw.Write(b.Bytes()); werr != nil {
		s.Logf("WARN writing fdb_status.jsonl: %v", werr)
	}
}

// Last returns the most recent successful cluster sample.
func (s *FDBSampler) Last() (ClusterSample, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, s.hasLs
}

// Status runs `fdbcli status json`: fdbcli gets --timeout (default 3s) and the process is killed
// after OuterLimit (default 5s). A failure carries fdbcli's stderr and how long the call took.
func (s *FDBSampler) Status(ctx context.Context) ([]byte, error) {
	timeout, outer := s.Timeout, s.OuterLimit
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if outer <= timeout {
		outer = timeout + 2*time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, outer)
	defer cancel()
	args := []string{}
	if s.ClusterFile != "" {
		args = append(args, "-C", s.ClusterFile)
	}
	args = append(args, "--exec", "status json", "--timeout", fmt.Sprint(int((timeout+time.Second-1)/time.Second)))
	t0 := time.Now()
	cmd := exec.CommandContext(cctx, s.Path, args...)
	cmd.WaitDelay = time.Second // return soon after the kill even if a child still holds the pipe
	out, err := cmd.Output()
	if err != nil {
		took := time.Since(t0).Round(100 * time.Millisecond)
		switch {
		case cctx.Err() == context.DeadlineExceeded:
			return nil, fmt.Errorf("fdbcli killed after the %s outer limit (its own --timeout was %s)", outer, timeout)
		default:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				msg := strings.TrimSpace(string(ee.Stderr))
				if msg == "" {
					msg = "no stderr"
				}
				if len(msg) > 300 {
					msg = msg[:300] + "..."
				}
				return nil, fmt.Errorf("fdbcli failed after %s (--timeout %s): %v: %s", took, timeout, err, msg)
			}
			return nil, err
		}
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	return out, nil
}

// failureLogEvery limits how often sample failures are logged during a run.
const failureLogEvery = 5 * time.Minute

// Run polls until ctx is cancelled.
func (s *FDBSampler) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Logf("WARN fdb sampling not started: interval must be > 0")
		return
	}
	tk := time.NewTicker(s.Interval)
	defer tk.Stop()
	var lastLog time.Time
	var suppressed int64
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tk.C:
			phase, callStart := s.currentPhase(), time.Now()
			out, err := s.Status(ctx)
			if ctx.Err() == nil {
				s.writeRaw(now, phase, time.Since(callStart), out, err)
			}
			var cs ClusterSample
			var rows []ProcessRow
			var cpuRows []CPURow
			if err == nil {
				cs, rows, cpuRows, err = ParseStatusFull(out)
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.Failures.Add(1)
				// Log the reason, but at most once per failureLogEvery (the first one always).
				if lastLog.IsZero() || time.Since(lastLog) >= failureLogEvery {
					extra := ""
					if suppressed > 0 {
						extra = fmt.Sprintf(" (%d more failures since the last message)", suppressed)
					}
					s.Logf("WARN fdb status sample failed (%d failed, %d ok so far)%s: %v",
						s.Failures.Load(), s.Samples.Load(), extra, err)
					lastLog, suppressed = time.Now(), 0
				} else {
					suppressed++
				}
				continue
			}
			s.Samples.Add(1)
			s.mu.Lock()
			s.last, s.hasLs = cs, true
			s.mu.Unlock()
			ms := results.I(now.UnixMilli())
			s.Cluster.Row(ms, results.F(cs.TxnHz), results.F(cs.ReadsHz), results.F(cs.WritesHz),
				results.F(cs.ConflictHz), results.F(cs.WorstQueueSS), results.F(cs.WorstQueueLog),
				results.F(cs.LimitingQueueSS), results.F(cs.DurLagSecs), results.F(cs.DiskUsedBytes), results.F(cs.KVBytes))
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
			if s.CPU != nil {
				for _, r := range cpuRows {
					s.CPU.Row(ms, r.Addr, r.Class, strings.Join(r.Roles, ";"), results.F(r.Cores))
				}
			}
		}
	}
}
