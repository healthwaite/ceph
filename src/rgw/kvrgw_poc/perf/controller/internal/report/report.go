// Package report implements `kvrgw-perf report <results-dir>`: it reads only the files
// written by an invocation (never touches workers or FDB).
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"kvrgw-perf/internal/collect"
	"kvrgw-perf/internal/results"
	"kvrgw-perf/internal/stats"
)

// Options are the report flags.
type Options struct {
	Warmup    time.Duration
	Deviation float64
	PerServer bool
	// Detailed adds the per-window statistics tables; by default only run totals are printed.
	Detailed bool
	// Window widens the recorded windows of the client-ops table to this size (0 = as
	// recorded). It must be a whole multiple of the recorded window.
	Window time.Duration
}

// Exit codes: 0 ok, 1 summary records a failed run, 2 unreadable results dir.
func Run(w io.Writer, dir string, o Options) int {
	if o.Deviation == 0 {
		o.Deviation = 10
	}
	r, err := load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		return 2
	}
	if err := r.checkWindow(o); err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		return 2
	}
	r.print(w, o)
	if r.sum != nil && r.sum.Failed {
		return 1
	}
	return 0
}

type metricRow struct {
	ts        int64
	window    int64
	op        string
	count     uint64
	errors    uint64
	queueFull uint64 // QUEUE_FULL backoffs (absent in older results)
	missed    uint64 // open-loop ops not issued (absent in older results)
	opsPerSec float64
	meanUs    float64
	hasLat    bool
	p50, p99  float64
}

type data struct {
	dir            string
	startMs, endMs int64
	metrics        []metricRow
	hist           map[string]map[int64]stats.Hist // op -> window -> hist
	errCodes       []errRow
	wend           map[int64]int64     // window index -> window end (unix ms)
	server         map[string][]sample // name -> series
	cpu            map[string][]sample
	fdbCluster     map[string][]sample // column -> series
	fdbProc        map[procKey]map[string][]sample
	fdbCPU         map[string]*cpuProc // process address -> CPU samples (fdb_cpu.csv)
	sum            *results.Summary
	intervalMs     int64
	hasFDB         bool
	fdbConfig      []collect.RoleRow // cluster configuration at the start (fdb_status_start.json)
	fdbStartDisk   float64
	hasStartDisk   bool
}

type errRow struct {
	ts    int64
	op    string
	code  string
	count uint64
}

type sample struct {
	ts int64
	v  float64
}

type procKey struct{ addr, role string }

func readCSV(path string) ([]string, [][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	recs, err := rd.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(recs) == 0 {
		return nil, nil, nil
	}
	return recs[0], recs[1:], nil
}

func pf(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }
func pi(s string) int64   { v, _ := strconv.ParseInt(s, 10, 64); return v }
func pu(s string) uint64  { v, _ := strconv.ParseUint(s, 10, 64); return v }

func load(dir string) (*data, error) {
	d := &data{dir: dir, wend: map[int64]int64{}, hist: map[string]map[int64]stats.Hist{}, server: map[string][]sample{},
		cpu: map[string][]sample{}, fdbCluster: map[string][]sample{}, fdbProc: map[procKey]map[string][]sample{},
		fdbCPU: map[string]*cpuProc{}}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("cannot read results directory %q", dir)
	}
	// events.csv (required)
	_, ev, err := readCSV(filepath.Join(dir, "events.csv"))
	if err != nil {
		return nil, fmt.Errorf("events.csv: %w", err)
	}
	for _, r := range ev {
		if len(r) < 2 {
			continue
		}
		switch r[1] {
		case "benchmark_start":
			d.startMs = pi(r[0])
		case "benchmark_end":
			d.endMs = pi(r[0])
		}
	}
	if d.startMs == 0 || d.endMs == 0 || d.endMs < d.startMs {
		return nil, fmt.Errorf("events.csv lacks a valid benchmark_start/benchmark_end")
	}
	if s, err := results.ReadSummary(filepath.Join(dir, "summary.json")); err == nil {
		d.sum = s
		d.intervalMs = s.Parameters.ReportIntervalMs
	}
	// metrics.csv
	if _, rows, err := readCSV(filepath.Join(dir, "metrics.csv")); err == nil {
		for _, r := range rows {
			if len(r) < 14 {
				continue
			}
			m := metricRow{ts: pi(r[0]), window: pi(r[1]), op: r[2], count: pu(r[3]), errors: pu(r[4]),
				opsPerSec: pf(r[5])}
			if len(r) >= 16 {
				m.queueFull, m.missed = pu(r[14]), pu(r[15])
			}
			if r[6] != "" {
				m.hasLat = true
				m.meanUs, m.p50, m.p99 = pf(r[6]), pf(r[7]), pf(r[9])
			}
			d.metrics = append(d.metrics, m)
			d.wend[m.window] = m.ts
		}
	}
	// errors.csv (optional: only written when errors occurred)
	if _, rows, err := readCSV(filepath.Join(dir, "errors.csv")); err == nil {
		for _, r := range rows {
			if len(r) >= 5 {
				d.errCodes = append(d.errCodes, errRow{pi(r[0]), r[2], r[3], pu(r[4])})
			}
		}
	}
	// hist.csv
	if _, rows, err := readCSV(filepath.Join(dir, "hist.csv")); err == nil {
		for _, r := range rows {
			if len(r) < 4 {
				continue
			}
			op, win := r[1], pi(r[0])
			if d.hist[op] == nil {
				d.hist[op] = map[int64]stats.Hist{}
			}
			h := d.hist[op][win]
			h.AddBucket(int(pi(r[2])), pu(r[3]))
			d.hist[op][win] = h
		}
	}
	if _, rows, err := readCSV(filepath.Join(dir, "server_stats.csv")); err == nil {
		for _, r := range rows {
			if len(r) >= 4 {
				d.server[r[2]] = append(d.server[r[2]], sample{pi(r[0]), pf(r[3])})
			}
		}
	}
	if _, rows, err := readCSV(filepath.Join(dir, "cpu.csv")); err == nil {
		for _, r := range rows {
			if len(r) >= 3 {
				d.cpu[r[1]] = append(d.cpu[r[1]], sample{pi(r[0]), pf(r[2])})
			}
		}
	}
	if hdr, rows, err := readCSV(filepath.Join(dir, "fdb_cluster.csv")); err == nil && hdr != nil {
		d.hasFDB = true
		for _, r := range rows {
			for i := 1; i < len(r) && i < len(hdr); i++ {
				d.fdbCluster[hdr[i]] = append(d.fdbCluster[hdr[i]], sample{pi(r[0]), pf(r[i])})
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "fdb_status_start.json")); err == nil {
		if cs, _, cpu, err := collect.ParseStatusFull(raw); err == nil {
			d.fdbConfig = collect.RoleTable(cpu)
			d.fdbStartDisk, d.hasStartDisk = cs.DiskUsedBytes, true
		}
	}
	if hdr, rows, err := readCSV(filepath.Join(dir, "fdb_process.csv")); err == nil && hdr != nil {
		for _, r := range rows {
			if len(r) < 3 {
				continue
			}
			k := procKey{r[1], r[2]}
			if d.fdbProc[k] == nil {
				d.fdbProc[k] = map[string][]sample{}
			}
			for i := 3; i < len(r) && i < len(hdr); i++ {
				if r[i] != "" {
					d.fdbProc[k][hdr[i]] = append(d.fdbProc[k][hdr[i]], sample{pi(r[0]), pf(r[i])})
				}
			}
		}
	}
	if _, rows, err := readCSV(filepath.Join(dir, "fdb_cpu.csv")); err == nil {
		for _, r := range rows {
			if len(r) < 5 {
				continue
			}
			p := d.fdbCPU[r[1]]
			if p == nil {
				p = &cpuProc{roles: strings.Split(r[3], ";")}
				d.fdbCPU[r[1]] = p
			}
			p.samples = append(p.samples, sample{pi(r[0]), pf(r[4])})
		}
	}
	return d, nil
}

// window selection -------------------------------------------------------------------

// bounds returns the analysis window in ms.
func (d *data) bounds(o Options) (from, to int64) {
	return d.startMs + o.Warmup.Milliseconds(), d.endMs
}

func inSamples(s []sample, from, to int64) []float64 {
	var out []float64
	for _, x := range s {
		if x.ts >= from && x.ts <= to {
			out = append(out, x.v)
		}
	}
	return out
}

// formatting ---------------------------------------------------------------------------

func grouped(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := strconv.FormatInt(n, 10)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func num(v float64) string {
	a := math.Abs(v)
	switch {
	case v == 0:
		return "0"
	case a >= 1e9:
		return fmt.Sprintf("%.2fG", v/1e9)
	case a >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case a >= 100:
		return grouped(int64(math.Round(v)))
	case a >= 10:
		return fmt.Sprintf("%.1f", v)
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

func clock(ms int64) string { return time.UnixMilli(ms).UTC().Format("15:04:05Z") }

func row(w io.Writer, label string, s stats.Summary, showDev bool) {
	rowF(w, label, s, showDev, num)
}

// rowMs prints a row whose samples are latencies in microseconds, in ms to 3 significant figures.
func rowMs(w io.Writer, label string, s stats.Summary, showDev bool) {
	rowF(w, label, s, showDev, stats.MsNum)
}

func rowF(w io.Writer, label string, s stats.Summary, showDev bool, f func(float64) string) {
	fmt.Fprintf(w, " %-18s%9s%9s%9s%9s%9s%9s%9s", label, f(s.Min), f(s.Max), f(s.Avg), f(s.Median),
		f(s.P90), f(s.P95), f(s.P99))
	if showDev {
		fmt.Fprintf(w, "%7.1f%%", s.DevPct)
	}
	fmt.Fprintln(w)
}

func (d *data) print(w io.Writer, o Options) {
	from, to := d.bounds(o)
	name := filepath.Base(strings.TrimRight(d.dir, "/"))
	line := strings.Repeat("=", 74)
	fmt.Fprintf(w, "%s\n kvrgw-perf report: %s\n%s\n", line, name, line)

	// ---- header ----
	k := d.widen(o)
	nwin := len(d.windowsInRange(from, to))
	winLen := time.Duration(d.intervalMs) * time.Millisecond
	if k > 1 {
		nwin /= k // complete widened windows only; a trailing partial one is left out of the table
		winLen *= time.Duration(k)
	}
	if d.sum != nil {
		p := d.sum.Parameters
		fmt.Fprintf(w, " Operation : %s      Buckets: %d\n", d.sum.Command, p.NumBuckets)
		mode := p.DriverMode
		if mode == "" {
			mode = "sync" // results from before driver_mode existed
		}
		fmt.Fprintf(w, " Clients   : %d workers x %d streams   driver_mode: %s", p.WorkerCount, p.Streams(), mode)
		if mode == "async" {
			fmt.Fprintf(w, "   driver_threads: %d", p.DriverThreads)
		}
		if p.RateOpsPerSec > 0 {
			fmt.Fprintf(w, "   rate_ops_per_sec: %g per worker (open loop)", p.RateOpsPerSec)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, " Benchmark : %s -> %s (%.0fs)   Warmup skipped: first %s\n", clock(d.startMs), clock(d.endMs),
		float64(d.endMs-d.startMs)/1000, o.Warmup)
	fmt.Fprintf(w, " Analysed  : %s -> %s (%d windows of %s)\n", clock(from), clock(to), nwin, winLen.String())
	if d.sum != nil {
		if v := d.sum.Verify; v != nil && v.Ran {
			st := "PASS"
			if !v.Pass {
				st = "FAIL"
			}
			fmt.Fprintf(w, " Verify    : %s  (%d buckets, %d missing, %d duplicates, took %s)\n", st, len(v.Buckets), v.Missing, v.Duplicate,
				(time.Duration(v.DurationMs) * time.Millisecond).Round(10*time.Millisecond))
		} else {
			fmt.Fprintln(w, " Verify    : not run")
		}
		if d.sum.Command == "run-put-object-overwrite-versioned" {
			fmt.Fprintf(w, " Versions  : %d written, avg %.2f per object over %d objects (one per successful put; load's null versions not counted)\n",
				d.sum.VersionsWritten, d.sum.VersionsPerObject, d.sum.Parameters.NumObjectsToOverwrite)
		}
		if d.sum.OpErrors > 0 {
			note := "(all retried OK)"
			if d.sum.Failed {
				note = "(run FAILED)"
			}
			fmt.Fprintf(w, " Errors    : %d %s\n", d.sum.OpErrors, note)
		} else {
			fmt.Fprintln(w, " Errors    : 0")
		}
		if d.sum.Failed {
			fmt.Fprintf(w, " Status    : FAILED  %s\n", strings.Join(d.sum.Failures, "; "))
		}
	}

	d.printClient(w, o, from, to)
	d.printCPU(w, o, from, to)
	d.printServer(w, o, from, to)
	if d.hasFDB {
		d.printFDB(w, o, from, to)
	}
}

func (d *data) printClient(w io.Writer, o Options, from, to int64) {
	// Average rates are over the analysed part of the run (benchmark start+warmup to end).
	runSecs := float64(to-from) / 1000
	if runSecs <= 0 {
		runSecs = 1
	}
	ops := []string{}
	for _, op := range []string{"put_object", "list_objects", "delete_multi", "list_delete_multi", "keys_listed", "keys_deleted"} {
		for _, m := range d.metrics {
			if m.op == op {
				ops = append(ops, op)
				break
			}
		}
	}
	if len(ops) == 0 {
		return
	}
	k := d.widen(o)
	winLen := time.Duration(d.intervalMs) * time.Millisecond * time.Duration(k)
	nwin := len(d.series(ops[0], from, to, k))
	banner(w, "Client ops")
	// The per-window tables are only printed with --detailed; the loop below also builds the
	// totals, so it always runs and writes to pw.
	pw := detailedWriter(w, o)
	subHeading(pw, "Per-window statistics", fmt.Sprintf("%d windows of %s, merged across workers", nwin, winLen), windowNote)
	type total struct {
		count, errs       uint64
		queueFull, missed uint64
		meanUs            float64
		hist              stats.Hist
	}
	totals := map[string]*total{}
	for _, op := range ops {
		var rate, mean, p50, p99, errs []float64
		for _, sm := range d.series(op, from, to, k) {
			rate = append(rate, sm.rate)
			errs = append(errs, sm.errs)
			if sm.hasLat {
				mean = append(mean, sm.mean)
				p50 = append(p50, sm.p50)
				p99 = append(p99, sm.p99)
			}
		}
		// Totals always cover every recorded window in range (including a trailing partial
		// widened window).
		t := &total{}
		wins := map[int64]bool{}
		var sumUs float64
		var latCount uint64
		for _, m := range d.metrics {
			if m.op != op || m.ts <= from || m.ts > to {
				continue
			}
			wins[m.window] = true
			t.count += m.count
			t.errs += m.errors
			t.queueFull += m.queueFull
			t.missed += m.missed
			if m.hasLat {
				sumUs += m.meanUs * float64(m.count)
				latCount += m.count
			}
		}
		if latCount > 0 {
			t.meanUs = sumUs / float64(latCount)
		}
		for win := range wins {
			t.hist.Merge(d.hist[op][win])
		}
		totals[op] = t
		if op != ops[0] {
			fmt.Fprintln(pw)
		}
		fmt.Fprintf(pw, " %-18s%9s%9s%9s%9s%9s%9s%9s%8s\n", op, "min", "max", "avg", "median", "p90", "p95", "p99", "dev%")
		if stats.IsCounter(op) {
			row(pw, "keys/sec", stats.Summarize(rate, o.Deviation), true)
			continue
		}
		row(pw, "ops/sec", stats.Summarize(rate, o.Deviation), true)
		rowMs(pw, "mean_ms", stats.Summarize(mean, o.Deviation), true)
		rowMs(pw, "p50_ms", stats.Summarize(p50, o.Deviation), true)
		rowMs(pw, "p99_ms", stats.Summarize(p99, o.Deviation), true)
		row(pw, "errors/win", stats.Summarize(errs, o.Deviation), true)
	}

	subHeading(w, "Run totals", fmt.Sprintf("%s analysed, all windows merged", time.Duration(to-from)*time.Millisecond),
		"percentiles come from the merged latency histogram; mean is count-weighted")
	// Column widths grow with the data so large counts (e.g. 1,000,000,000) stay aligned
	// with their headers instead of pushing the row right.
	wide := func(min int, cells ...string) int {
		for _, c := range cells {
			if len(c)+2 > min {
				min = len(c) + 2
			}
		}
		return min
	}
	var latOps, ctrOps []string
	for _, op := range ops {
		if stats.IsCounter(op) {
			ctrOps = append(ctrOps, op)
		} else {
			latOps = append(latOps, op)
		}
	}
	if len(latOps) > 0 {
		// The queue_full column (submits refused at the backend's in-flight limit) is shown for
		// async-mode runs, and for any run where it is non-zero.
		showQF := d.sum != nil && d.sum.Parameters.DriverMode == "async"
		opsW, errW, qfW := wide(12, "ops"), wide(9, "errors"), 0
		for _, op := range latOps {
			t := totals[op]
			opsW = wide(opsW, grouped(int64(t.count)))
			errW = wide(errW, grouped(int64(t.errs)))
			showQF = showQF || t.queueFull > 0
		}
		qfHdr := ""
		if showQF {
			qfW, qfHdr = wide(12, "queue_full"), "queue_full"
			for _, op := range latOps {
				qfW = wide(qfW, grouped(int64(totals[op].queueFull)))
			}
		}
		fmt.Fprintf(w, " %-18s%*s%*s%*s%11s%9s%9s%9s%9s%9s\n", "op", opsW, "ops", errW, "errors", qfW, qfHdr,
			"avg ops/s", "mean_ms", "p50_ms", "p90_ms", "p99_ms", "p999_ms")
		for _, op := range latOps {
			t := totals[op]
			qf := ""
			if showQF {
				qf = grouped(int64(t.queueFull))
			}
			fmt.Fprintf(w, " %-18s%*s%*s%*s%11s%9s%9s%9s%9s%9s\n", op, opsW, grouped(int64(t.count)), errW, grouped(int64(t.errs)),
				qfW, qf,
				num(float64(t.count)/runSecs), stats.MsNum(t.meanUs), stats.MsNum(float64(t.hist.Quantile(0.5))),
				stats.MsNum(float64(t.hist.Quantile(0.9))), stats.MsNum(float64(t.hist.Quantile(0.99))), stats.MsNum(float64(t.hist.Quantile(0.999))))
		}
	}
	if d.sum != nil && d.sum.Parameters.RateOpsPerSec > 0 {
		p := d.sum.Parameters
		target := p.RateOpsPerSec * float64(p.WorkerCount)
		var achieved float64
		var missed uint64
		for _, op := range latOps {
			achieved += float64(totals[op].count) / runSecs
			missed += totals[op].missed
		}
		fmt.Fprintf(w, "\n open loop    : target %s ops/s, achieved %s ops/s (%.1f%%), missed %s; latency from scheduled send time\n",
			num(target), num(achieved), 100*achieved/target, grouped(int64(missed)))
	}
	// Client-side health.
	for _, op := range latOps {
		if t := totals[op]; t.queueFull > 0 {
			fmt.Fprintf(w, " [WARN] %s: %s submits hit the backend in-flight limit (queue_full): streams_per_worker exceeds max_inflight_ops\n",
				op, grouped(int64(t.queueFull)))
		}
		if t := totals[op]; t.missed > 0 {
			fmt.Fprintf(w, " [WARN] %s: %s scheduled ops were not issued (missed): the target rate was not held\n",
				op, grouped(int64(t.missed)))
		}
	}
	if len(ctrOps) > 0 {
		keyW := wide(12, "keys")
		for _, op := range ctrOps {
			keyW = wide(keyW, grouped(int64(totals[op].count)))
		}
		fmt.Fprintf(w, "\n %-18s%*s%14s\n", "op", keyW, "keys", "avg keys/s")
		for _, op := range ctrOps {
			t := totals[op]
			fmt.Fprintf(w, " %-18s%*s%14s\n", op, keyW, grouped(int64(t.count)), num(float64(t.count)/runSecs))
		}
	}
	for _, op := range ops {
		if !stats.IsCounter(op) {
			d.printErrorCodes(w, op, from, to)
		}
	}
}

// printErrorCodes lists the op's errors in the analysis window by library error code, with
// the readable text recorded in summary.json.
func (d *data) printErrorCodes(w io.Writer, op string, from, to int64) {
	codes := map[string]uint64{}
	for _, e := range d.errCodes {
		if e.op == op && e.ts > from && e.ts <= to {
			codes[e.code] += e.count
		}
	}
	if len(codes) > 0 {
		fmt.Fprintln(w)
	}
	for _, c := range sortedByCount(codes) {
		line := fmt.Sprintf("   errors: %-28s x%d", stats.ShortCode(c), codes[c])
		if d.sum != nil && d.sum.ErrorDescriptions[c] != "" {
			line += "  " + d.sum.ErrorDescriptions[c]
		}
		fmt.Fprintln(w, line)
	}
}

func sortedByCount(m map[string]uint64) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Slice(k, func(i, j int) bool {
		if m[k[i]] != m[k[j]] {
			return m[k[i]] > m[k[j]]
		}
		return k[i] < k[j]
	})
	return k
}

// cpuSources returns the cpu.csv sources in display order (workers naturally sorted, host last).
func (d *data) cpuSources() []string {
	var srcs []string
	for k := range d.cpu {
		srcs = append(srcs, k)
	}
	sort.Slice(srcs, func(i, j int) bool {
		if (srcs[i] == "system") != (srcs[j] == "system") {
			return srcs[j] == "system"
		}
		return natLess(srcs[i], srcs[j])
	})
	return srcs
}

func cpuLabel(s string) string {
	if s == "system" {
		return "system (host)"
	}
	return strings.Replace(s, "-", " ", 1)
}

// cpuInterval is the median spacing of a source's samples in (from,to], in ms (0 if unknown).
func cpuInterval(s []sample, from, to int64) int64 {
	var gaps []int64
	var prev int64
	for _, x := range s {
		if x.ts < from || x.ts > to {
			continue
		}
		if prev != 0 {
			gaps = append(gaps, x.ts-prev)
		}
		prev = x.ts
	}
	if len(gaps) == 0 {
		return 0
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return gaps[len(gaps)/2]
}

// windowedStatsWarning returns "" when samples of a source can be assigned to display windows
// of length winLen, or an explanation of why per-window statistics can't be produced. The
// sampling interval must not be longer than the window, or windows would have no samples.
func windowedStatsWarning(what, setting string, samples []sample, from, to int64, winLen time.Duration) string {
	iv := cpuInterval(samples, from, to)
	if iv == 0 {
		return fmt.Sprintf("%s: too few samples in the analysed range to compute per-window statistics.", what)
	}
	if ivd := time.Duration(iv) * time.Millisecond; ivd > winLen {
		return fmt.Sprintf("%s is sampled every ~%s, which is longer than the %s window, so some windows would have no samples. "+
			"Use --window %s or longer (a whole multiple of the recorded window), or lower %s and re-run.",
			what, ivd.Round(100*time.Millisecond), winLen, ivd.Round(time.Second), setting)
	}
	return ""
}

// detailedWriter returns w with --detailed, else a writer that discards, so per-window code
// paths can stay in place without printing.
func detailedWriter(w io.Writer, o Options) io.Writer {
	if o.Detailed {
		return w
	}
	return io.Discard
}

// banner prints a section heading: a full-width rule, the upper-case title and another rule.
func banner(w io.Writer, title string) {
	rule := strings.Repeat("=", 74)
	fmt.Fprintf(w, "\n%s\n %s\n%s\n", rule, strings.ToUpper(title), rule)
}

// subHeading prints a table heading within a section: the table type and its details on one
// line, a light rule, then each note in parentheses and a blank line before the table.
func subHeading(w io.Writer, title, detail string, notes ...string) {
	line := " " + title
	if detail != "" {
		line += "   " + detail
	}
	fmt.Fprintf(w, "\n%s\n %s\n", line, strings.Repeat("-", 72))
	for _, n := range notes {
		fmt.Fprintf(w, " (%s)\n", n)
	}
	fmt.Fprintln(w)
}

const windowNote = "each row is measured once per window; min/max/avg/median/pXX/dev% are taken across those windows"

// windowsNote is the "N windows of W" part of a heading. When some windows had no samples it
// says how many contributed, so the statistics aren't read as covering more than they do.
func windowsNote(withData, total int, winLen time.Duration) string {
	if withData == total {
		return fmt.Sprintf("%d windows of %s", total, winLen)
	}
	return fmt.Sprintf("%d of %d windows of %s had samples", withData, total, winLen)
}

// windowHasSample reports whether any of the series has a sample in (start,end].
func windowHasSample(win [2]int64, series ...[]sample) bool {
	for _, s := range series {
		for _, x := range s {
			if x.ts > win[0] && x.ts <= win[1] {
				return true
			}
		}
	}
	return false
}

// sampleNote describes a sampled series for a heading, e.g. "4 samples at ~5s".
func sampleNote(samples []sample, from, to int64) string {
	n := len(inSamples(samples, from, to))
	iv := time.Duration(cpuInterval(samples, from, to)) * time.Millisecond
	if iv == 0 {
		return fmt.Sprintf("%d samples", n)
	}
	return fmt.Sprintf("%d samples at ~%s", n, iv.Round(100*time.Millisecond))
}

// cpuWindows returns the display windows as (start,end] ms ranges: one per recorded window
// (k == 1) or one per complete group of k recorded windows, matching the Client ops series.
func (d *data) cpuWindows(from, to int64, k int) [][2]int64 {
	all := d.windowsInRange(from, to)
	if k < 1 {
		k = 1
	}
	var out [][2]int64
	for b := 0; (b+1)*k <= len(all); b++ {
		first, last := all[b*k], all[(b+1)*k-1]
		start, ok := d.wend[first-1]
		if !ok {
			start = d.wend[first] - d.intervalMs
		}
		out = append(out, [2]int64{start, d.wend[last]})
	}
	return out
}

func (d *data) printCPU(w io.Writer, o Options, from, to int64) {
	if len(d.cpu) == 0 {
		return
	}
	banner(w, "Worker CPU")
	srcs := d.cpuSources()
	wins := d.cpuWindows(from, to, d.widen(o))
	winLen := time.Duration(d.intervalMs) * time.Millisecond * time.Duration(d.widen(o))
	runSecs := float64(to-from) / 1000
	if runSecs <= 0 {
		runSecs = 1
	}

	// Per-window series: mean of the samples that fall in each window. If the sampler is slower
	// than the window the table is not produced; a warning explains why.
	perWindow := len(wins) > 0 && d.intervalMs > 0
	var cpuWarn string
	if perWindow {
		for _, s := range srcs {
			if cpuWarn = windowedStatsWarning("Worker CPU", "cpu_sample_interval_ms", d.cpu[s], from, to, winLen); cpuWarn != "" {
				perWindow = false
				break
			}
		}
	}
	workers := 0
	for _, s := range srcs {
		if s != "system" {
			workers++
		}
	}
	if o.Detailed && perWindow {
		var all [][]sample
		for _, s := range srcs {
			all = append(all, d.cpu[s])
		}
		withData := 0
		for _, win := range wins {
			if windowHasSample(win, all...) {
				withData++
			}
		}
		subHeading(w, "Per-window statistics", windowsNote(withData, len(wins), winLen)+", cores",
			"each row is the mean of the CPU samples in each window; min/max/avg/median/pXX/dev% are taken across those windows")
		fmt.Fprintf(w, " %-18s%9s%9s%9s%9s%9s%9s%9s%8s\n", "", "min", "max", "avg", "median", "p90", "p95", "p99", "dev%")
		perSrc := map[string][]float64{}
		sum := make([]float64, 0, len(wins))
		for _, win := range wins {
			var tot float64
			complete := true
			for _, s := range srcs {
				var n int
				var acc float64
				for _, x := range d.cpu[s] {
					if x.ts > win[0] && x.ts <= win[1] {
						acc += x.v
						n++
					}
				}
				if n == 0 {
					if s != "system" {
						complete = false
					}
					continue
				}
				perSrc[s] = append(perSrc[s], acc/float64(n))
				if s != "system" {
					tot += acc / float64(n)
				}
			}
			if complete && workers > 1 {
				sum = append(sum, tot)
			}
		}
		for _, s := range srcs {
			row(w, cpuLabel(s), stats.Summarize(perSrc[s], o.Deviation), true)
		}
		if workers > 1 && len(sum) > 0 {
			row(w, "all workers", stats.Summarize(sum, o.Deviation), true)
		}
	} else if o.Detailed && cpuWarn != "" {
		subHeading(w, "Per-window statistics", "not shown")
		fmt.Fprintf(w, " [WARN] %s\n", cpuWarn)
	}

	// Run totals.
	subHeading(w, "Run totals", fmt.Sprintf("%s analysed, %s", time.Duration(to-from)*time.Millisecond, sampleNote(d.cpu[srcs[0]], from, to)),
		"averages over every CPU sample in the run; \"all workers\" sums the per-worker averages")
	fmt.Fprintf(w, " %-18s%12s\n", "source", "avg cores")
	var workerAvg float64
	for _, s := range srcs {
		if s == "system" {
			continue
		}
		workerAvg += stats.Summarize(inSamples(d.cpu[s], from, to), o.Deviation).Avg
	}
	if workers > 1 {
		fmt.Fprintf(w, " %-18s%12s\n", "all workers", num(workerAvg))
	}
	for _, s := range srcs {
		if workers == 1 || s == "system" {
			avg := stats.Summarize(inSamples(d.cpu[s], from, to), o.Deviation).Avg
			fmt.Fprintf(w, " %-18s%12s\n", cpuLabel(s), num(avg))
		}
	}
	// Client CPU cost per op, only when there is exactly one latency-bearing op.
	var opNames []string
	var count uint64
	seen := map[string]bool{}
	for _, m := range d.metrics {
		if stats.IsCounter(m.op) || m.ts <= from || m.ts > to {
			continue
		}
		if !seen[m.op] {
			seen[m.op] = true
			opNames = append(opNames, m.op)
		}
		count += m.count
	}
	if len(opNames) == 1 && count > 0 && workerAvg > 0 {
		rate := float64(count) / runSecs
		fmt.Fprintf(w, "\n client CPU efficiency: %s ops/s per core   (%s ops/s / %s cores, %s)\n",
			num(rate/workerAvg), num(rate), num(workerAvg), opNames[0])
	}
}

func natLess(a, b string) bool {
	ia, ib := strings.LastIndex(a, "-"), strings.LastIndex(b, "-")
	if ia >= 0 && ib >= 0 && a[:ia] == b[:ib] {
		x, e1 := strconv.Atoi(a[ia+1:])
		y, e2 := strconv.Atoi(b[ib+1:])
		if e1 == nil && e2 == nil {
			return x < y
		}
	}
	return a < b
}

// serverDelta returns the cumulative delta of a counter over the analysis window.
func (d *data) serverDelta(name string, from, to int64) (float64, bool) {
	s := d.server[name]
	if len(s) == 0 {
		return 0, false
	}
	base, last := 0.0, math.NaN()
	for _, x := range s {
		if x.ts <= from {
			base = x.v
		}
		if x.ts <= to {
			last = x.v
		}
	}
	if math.IsNaN(last) {
		return 0, false
	}
	return last - base, true
}

// printServerWindows prints per-window statistics of the server-side counters. Counters are
// cumulative snapshots at window boundaries, so each display window's value is a delta.
func (d *data) printServerWindows(w io.Writer, o Options, from, to int64, opNames []string) {
	wins := d.cpuWindows(from, to, d.widen(o))
	if len(wins) == 0 {
		return
	}
	winLen := time.Duration(d.intervalMs) * time.Millisecond * time.Duration(d.widen(o))
	subHeading(w, "Per-window statistics", fmt.Sprintf("%d windows of %s, summed over workers", len(wins), winLen), windowNote,
		"latency and size rows are per-window means; the library exposes sums and counts, not histograms")
	firstHdr := true
	hdr := func(name string) {
		if firstHdr {
			firstHdr = false
		} else {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, " %-18s%9s%9s%9s%9s%9s%9s%9s%8s\n", name, "min", "max", "avg", "median", "p90", "p95", "p99", "dev%")
	}
	// delta returns the counter's change over window i; ok is false when it is missing or went
	// backwards (a worker restart), so the window is left out of that row.
	delta := func(name string, i int) (float64, bool) {
		v, ok := d.serverDelta(name, wins[i][0], wins[i][1])
		return v, ok && v >= 0
	}
	secs := func(i int) float64 { return float64(wins[i][1]-wins[i][0]) / 1000 }
	// ratio collects num/den per window for windows where den > 0.
	ratio := func(numName, denName string, scale float64) []float64 {
		var out []float64
		for i := range wins {
			n, ok1 := delta(numName, i)
			dn, ok2 := delta(denName, i)
			if ok1 && ok2 && dn > 0 {
				out = append(out, n/dn*scale)
			}
		}
		return out
	}
	perSec := func(name string) []float64 {
		var out []float64
		for i := range wins {
			if v, ok := delta(name, i); ok {
				out = append(out, v/secs(i))
			}
		}
		return out
	}
	perWin := func(name string) []float64 {
		var out []float64
		for i := range wins {
			if v, ok := delta(name, i); ok {
				out = append(out, v)
			}
		}
		return out
	}
	sm := func(v []float64) stats.Summary { return stats.Summarize(v, o.Deviation) }
	for _, op := range opNames {
		if c, _ := d.serverDelta(op+".count", from, to); c <= 0 {
			continue
		}
		// Counts and latencies come from the client tables (the harness's own measurements);
		// the only per-op figure only the library has is the data-store (disk) time.
		if disk, _ := d.serverDelta(op+".disk_us", from, to); disk > 0 {
			hdr(op)
			rowMs(w, "avg_disk_ms", sm(ratio(op+".disk_us", op+".count", 1)), true)
		}
	}
	if c, ok := d.serverDelta("batch.commits", from, to); ok && c > 0 {
		hdr("batches")
		row(w, "commits/s", sm(perSec("batch.commits")), true)
		row(w, "avg_size", sm(ratio("batch.entries", "batch.commits", 1)), true)
		row(w, "avg_wait_us", sm(ratio("batch.wait_us_total", "batch.commits", 1)), true)
		row(w, "avg_queue", sm(ratio("batch.queue_size_total", "batch.commits", 1)), true)
		row(w, "pushbacks/win", sm(perWin("batch.conflict_pushbacks")), true)
	}
	hdr("txn")
	row(w, "retries/win", sm(perWin("txn.retries")), true)
	row(w, "hard_fails/win", sm(perWin("txn.hard_failures")), true)
}

func (d *data) printServer(w io.Writer, o Options, from, to int64) {
	if len(d.server) == 0 {
		return
	}
	banner(w, "Server-side KVRGW")
	secs := float64(to-from) / 1000
	var opNames []string
	for n := range d.server {
		if op, ok := strings.CutSuffix(n, ".count"); ok && !strings.HasPrefix(n, "batch.") && !strings.HasPrefix(n, "txn.") &&
			!strings.HasPrefix(n, "async.") {
			opNames = append(opNames, op)
		}
	}
	sort.Strings(opNames)
	if o.Detailed {
		d.printServerWindows(w, o, from, to, opNames)
	}
	subHeading(w, "Run totals", fmt.Sprintf("%s analysed, summed over workers", time.Duration(to-from)*time.Millisecond),
		"op counts and latencies are in CLIENT OPS (the harness's own measurements); this section only has what the library alone knows")
	// The library does not instrument FDB get/commit/scan time (the hooks are never called), so
	// the only per-op figure is the data-store (disk) time, shown only if any op has some.
	type opRow struct {
		op   string
		disk float64
	}
	var rows []opRow
	for _, op := range opNames {
		c, _ := d.serverDelta(op+".count", from, to)
		if c <= 0 {
			continue
		}
		if disk := d.opDelta(op, "disk_us", from, to) / c; disk > 0 {
			rows = append(rows, opRow{op, disk})
		}
	}
	if len(rows) > 0 {
		fmt.Fprintf(w, " %-18s%13s\n", "op", "avg_disk_ms")
		for _, r := range rows {
			fmt.Fprintf(w, " %-18s%13s\n", r.op, stats.MsNum(r.disk))
		}
	}
	if commits, ok := d.serverDelta("batch.commits", from, to); ok && commits > 0 {
		ent, _ := d.serverDelta("batch.entries", from, to)
		wait, _ := d.serverDelta("batch.wait_us_total", from, to)
		q, _ := d.serverDelta("batch.queue_size_total", from, to)
		cp, _ := d.serverDelta("batch.conflict_pushbacks", from, to)
		fmt.Fprintf(w, "\n %-18s%12s%12s%14s%12s%12s\n", "batches", "commits/s", "avg_size", "avg_wait_us", "avg_queue", "pushbacks")
		fmt.Fprintf(w, " %-18s%12s%12.1f%14s%12.1f%12s\n", "", num(commits/secs), ent/commits, num(wait/commits), q/commits, grouped(int64(cp)))
	}
	rt, _ := d.serverDelta("txn.retries", from, to)
	hf, _ := d.serverDelta("txn.hard_failures", from, to)
	var errs []string
	var names []string
	for n := range d.server {
		if strings.HasPrefix(n, "error.") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if v, _ := d.serverDelta(n, from, to); v > 0 {
			errs = append(errs, fmt.Sprintf("%s=%d", strings.TrimPrefix(n, "error."), int64(v)))
		}
	}
	fmt.Fprintf(w, "\n %-18s%12s%14s\n", "txn", "retries", "hard_failures")
	fmt.Fprintf(w, " %-18s%12s%14s\n", "", grouped(int64(rt)), grouped(int64(hf)))
	if _, ok := d.server["async.queue_full_rejects"]; ok {
		qf, _ := d.serverDelta("async.queue_full_rejects", from, to)
		// The peak is a gauge (summed over workers per sample): report its highest value.
		var peak float64
		for _, s := range inSamples(d.server["async.inflight_ops_peak"], d.startMs, to) {
			peak = math.Max(peak, s)
		}
		fmt.Fprintf(w, "\n %-18s%20s%20s\n", "async", "queue_full_rejects", "inflight_ops_peak")
		fmt.Fprintf(w, " %-18s%20s%20s\n", "", grouped(int64(qf)), grouped(int64(peak)))
		if qf > 0 {
			fmt.Fprintln(w, " [WARN] the backend refused ops at its in-flight limit (max_inflight_ops)")
		}
	}
	fmt.Fprintf(w, " server errors: %s\n", orNone(errs))
}

func (d *data) opDelta(op, field string, from, to int64) float64 {
	v, _ := d.serverDelta(op+"."+field, from, to)
	return v
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}

// FDB -------------------------------------------------------------------------------------

type procStat struct {
	key  procKey
	med  map[string]float64
	flag string
}

func (d *data) procStats(from, to int64) []procStat {
	var out []procStat
	for k, cols := range d.fdbProc {
		ps := procStat{key: k, med: map[string]float64{}}
		any := false
		for c, s := range cols {
			v := inSamples(s, from, to)
			if len(v) > 0 {
				any = true
				ps.med[c] = stats.Summarize(v, 10).Median
			}
		}
		if any {
			ps.flag = ssFlags(k.role, ps.med)
			out = append(out, ps)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].key.role != out[j].key.role {
			return out[i].key.role < out[j].key.role
		}
		return out[i].key.addr < out[j].key.addr
	})
	return out
}

// ssFlags are the per-server flags (thresholds from the legacy health check).
func ssFlags(role string, m map[string]float64) string {
	if role != "storage" {
		return ""
	}
	cpu, in, dur, lag := m["cpu_cores"], m["input_hz"], m["durable_hz"], m["data_lag_s"]
	var f []string
	if cpu >= 0.95 {
		f = append(f, "[SATURATED]")
	}
	if cpu > 0.25 && dur > 0 && in/dur > 2.0 {
		f = append(f, "[HOTSPOT]")
	}
	if lag > 5.0 {
		f = append(f, "[FALLING_BEHIND]")
	}
	return strings.Join(f, " ")
}

func roleLabel(role string) string {
	switch role {
	case "storage":
		return "SS "
	case "log":
		return "LOG"
	}
	return "SL "
}

type fdbCol struct {
	label, col string
	scale      float64
}

var fdbClusterCols = []fdbCol{{"txn/s", "txn_hz", 1}, {"reads/s", "reads_hz", 1}, {"writes/s", "writes_hz", 1},
	{"conflicts/s", "conflict_hz", 1}, {"worst SS queue (MB)", "worst_queue_ss", 1e6}, {"durability lag (s)", "durability_lag_s", 1}}

func (d *data) printFDB(w io.Writer, o Options, from, to int64) {
	banner(w, "FDB cluster")
	winLen := time.Duration(d.intervalMs) * time.Millisecond * time.Duration(d.widen(o))
	wins := d.cpuWindows(from, to, d.widen(o))
	if o.Detailed && len(wins) > 0 && d.intervalMs > 0 {
		warn := windowedStatsWarning("FDB cluster", "fdb_sample_interval_ms", d.fdbCluster["txn_hz"], from, to, winLen)
		if warn != "" {
			subHeading(w, "Per-window statistics", "not shown")
			fmt.Fprintf(w, " [WARN] %s\n", warn)
		} else {
			withData := 0
			for _, win := range wins {
				if windowHasSample(win, d.fdbCluster["txn_hz"]) {
					withData++
				}
			}
			subHeading(w, "Per-window statistics", windowsNote(withData, len(wins), winLen),
				"each row is the mean of the FDB status samples in each window; min/max/avg/median/pXX/dev% are taken across those windows")
			fmt.Fprintf(w, " %-22s%9s%9s%9s%9s%9s%9s%9s%8s\n", "", "min", "max", "avg", "median", "p90", "p95", "p99", "dev%")
			for _, c := range fdbClusterCols {
				var vals []float64
				for _, win := range wins {
					var acc float64
					var n int
					for _, x := range d.fdbCluster[c.col] {
						if x.ts > win[0] && x.ts <= win[1] {
							acc += x.v / c.scale
							n++
						}
					}
					if n > 0 {
						vals = append(vals, acc/float64(n))
					}
				}
				s := stats.Summarize(vals, o.Deviation)
				fmt.Fprintf(w, " %-22s%9s%9s%9s%9s%9s%9s%9s%7.1f%%\n", c.label, num(s.Min), num(s.Max), num(s.Avg), num(s.Median),
					num(s.P90), num(s.P95), num(s.P99), s.DevPct)
			}
		}
	}

	subHeading(w, "Run totals", fmt.Sprintf("%s analysed, %s", time.Duration(to-from)*time.Millisecond, sampleNote(d.fdbCluster["txn_hz"], from, to)),
		"each row summarises every FDB status sample in the run")
	fmt.Fprintf(w, " %-22s%9s%9s%9s%9s\n", "", "min", "max", "avg", "median")
	for _, c := range fdbClusterCols {
		v := inSamples(d.fdbCluster[c.col], from, to)
		for i := range v {
			v[i] /= c.scale
		}
		s := stats.Summarize(v, o.Deviation)
		fmt.Fprintf(w, " %-22s%9s%9s%9s%9s\n", c.label, num(s.Min), num(s.Max), num(s.Avg), num(s.Median))
	}

	d.printFDBDisk(w)
	if len(d.fdbConfig) > 0 {
		subHeading(w, "Cluster configuration", "at start of run",
			"cores is the CPU in use at the start; a process holding several roles counts under each")
		fmt.Fprint(w, collect.FormatRoleTable(d.fdbConfig, " "))
	}

	procs := d.procStats(from, to)
	banner(w, "FDB by role")
	fmt.Fprintln(w)
	if o.PerServer {
		for _, p := range procs {
			m := p.med
			switch p.key.role {
			case "storage":
				r := 0.0
				if m["durable_hz"] > 0 {
					r = m["input_hz"] / m["durable_hz"]
				}
				fmt.Fprintf(w, " SS  %-21s in/dur=%.1f lag=%.1fs cpu=%.2f %s\n", p.key.addr, r, m["data_lag_s"], m["cpu_cores"], p.flag)
			case "log":
				fmt.Fprintf(w, " LOG %-21s input=%s/s q_disk=%s cpu=%.2f\n", p.key.addr, bytesStr(m["input_hz"]), bytesStr(m["queue_disk_bytes"]), m["cpu_cores"])
			default:
				fmt.Fprintf(w, " SL  %-21s cpu=%.2f (%s)\n", p.key.addr, m["cpu_cores"], p.key.role)
			}
		}
	} else {
		groups := map[string][]procStat{}
		for _, p := range procs {
			g := p.key.role
			if g != "storage" && g != "log" {
				g = "other"
			}
			groups[g] = append(groups[g], p)
		}
		rng := func(ps []procStat, col string, f func(float64) string) string {
			lo, hi := math.Inf(1), math.Inf(-1)
			for _, p := range ps {
				v := p.med[col]
				lo, hi = math.Min(lo, v), math.Max(hi, v)
			}
			if lo == hi {
				return f(lo)
			}
			return f(lo) + "-" + f(hi)
		}
		f2 := func(v float64) string { return fmt.Sprintf("%.2f", v) }
		if ps := groups["storage"]; len(ps) > 0 {
			lo, hi := math.Inf(1), math.Inf(-1)
			for _, p := range ps {
				if p.med["durable_hz"] > 0 {
					r := p.med["input_hz"] / p.med["durable_hz"]
					lo, hi = math.Min(lo, r), math.Max(hi, r)
				}
			}
			ratio := "n/a"
			if !math.IsInf(lo, 1) {
				ratio = fmt.Sprintf("%.1f-%.1fx", lo, hi)
			}
			fmt.Fprintf(w, " SS  (%d)   in/dur=%s   lag=%ss   cpu=%s   mem=%s\n", len(ps), ratio,
				rng(ps, "data_lag_s", func(v float64) string { return fmt.Sprintf("%.1f", v) }), rng(ps, "cpu_cores", f2),
				rng(ps, "mem_bytes", bytesStr))
		}
		if ps := groups["log"]; len(ps) > 0 {
			fmt.Fprintf(w, " LOG (%d)   input=%s/s   q_disk=%s   cpu=%s\n", len(ps), rng(ps, "input_hz", bytesStr),
				rng(ps, "queue_disk_bytes", bytesStr), rng(ps, "cpu_cores", f2))
		}
		if ps := groups["other"]; len(ps) > 0 && len(d.fdbCPU) == 0 {
			rs := map[string]bool{}
			for _, p := range ps {
				for _, r := range strings.Split(p.key.role, ",") {
					rs[r] = true
				}
			}
			var names []string
			for r := range rs {
				names = append(names, r)
			}
			sort.Strings(names)
			fmt.Fprintf(w, " SL  (%d)   cpu=%s (%s)\n", len(ps), rng(ps, "cpu_cores", f2), strings.Join(names, ", "))
		}
	}

	d.printFDBCPU(w, from, to)
	if o.Detailed {
		d.printFDBCPUWindows(w, o, from, to)
		d.printFDBRoleWindows(w, o, from, to)
	}

	banner(w, "Health")
	fmt.Fprintln(w)
	bad := 0
	for _, p := range procs {
		if p.flag != "" {
			bad++
			fmt.Fprintf(w, " [WARN] storage %s: %s\n", p.key.addr, p.flag)
		}
	}
	stalled := 0
	for _, p := range procs {
		if p.key.role == "storage" && p.med["durable_hz"] == 0 && (p.med["input_hz"] > 0 || p.med["queue_disk_bytes"] > 0) {
			stalled++
			fmt.Fprintf(w, " [WARN] durability stalled on storage %s (durable_hz=0 while data is queued)\n", p.key.addr)
		}
	}
	if bad == 0 && stalled == 0 {
		fmt.Fprintln(w, " [OK] durability kept up with input on all storage servers")
	}
	// TLog queue growth: first vs second half of the analysis window.
	var first, second []float64
	mid := from + (to-from)/2
	for k, cols := range d.fdbProc {
		if k.role != "log" {
			continue
		}
		for _, s := range cols["queue_disk_bytes"] {
			if s.ts < from || s.ts > to {
				continue
			}
			if s.ts <= mid {
				first = append(first, s.v)
			} else {
				second = append(second, s.v)
			}
		}
	}
	if len(first) > 0 && len(second) > 0 {
		a, b := stats.Summarize(first, 10).Avg, stats.Summarize(second, 10).Avg
		if b > a*1.5 && b > 1e6 {
			fmt.Fprintf(w, " [WARN] TLog queue_disk shows sustained growth: first half %s, second half %s\n", bytesStr(a), bytesStr(b))
		} else {
			fmt.Fprintf(w, " [OK] TLog queue stable (first half %s, second half %s)\n", bytesStr(a), bytesStr(b))
		}
	}
	// Hot storage process: per-process CPU much above the median.
	if msg := d.storageImbalanceWarning(from, to); msg != "" {
		fmt.Fprintf(w, " [WARN] %s\n", msg)
	}
	// Ratekeeper limiting queue (~50% of the 1.5GB storage hard limit).
	if v := inSamples(d.fdbCluster["limiting_queue_ss"], from, to); len(v) > 0 {
		if mx := stats.Summarize(v, 10).Max; mx > 750e6 {
			fmt.Fprintf(w, " [WARN] ratekeeper limiting storage queue reached %s\n", bytesStr(mx))
		}
	}
}

func bytesStr(b float64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.1fGB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.0fMB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.0fKB", b/1e3)
	}
	return fmt.Sprintf("%.0fB", b)
}

// ---- widening ----

// opSample is one (possibly widened) window of one op.
type opSample struct {
	rate, mean, p50, p99, errs float64
	hasLat                     bool
}

// windowsInRange returns the distinct recorded window indexes whose end is in (from,to].
func (d *data) windowsInRange(from, to int64) []int64 {
	var ws []int64
	for w, ts := range d.wend {
		if ts > from && ts <= to {
			ws = append(ws, w)
		}
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i] < ws[j] })
	// The run's final window is usually a stub (the run ends a few ms after a boundary). Its
	// rates and latencies come from very few requests, so leave it out of windowed statistics.
	// Run totals are built from the raw rows and still include it.
	if n := len(ws); n > 0 && d.intervalMs > 0 {
		last := int64(-1)
		for w := range d.wend {
			if w > last {
				last = w
			}
		}
		if ws[n-1] == last && d.windowDur(last) < float64(d.intervalMs)/2000 {
			ws = ws[:n-1]
		}
	}
	return ws
}

// widen returns how many recorded windows make up one displayed window (1 = as recorded).
func (d *data) widen(o Options) int {
	if o.Window <= 0 || d.intervalMs <= 0 {
		return 1
	}
	return int(o.Window.Milliseconds() / d.intervalMs)
}

// checkWindow validates --window against the recorded window size.
func (d *data) checkWindow(o Options) error {
	if o.Window == 0 {
		return nil
	}
	if d.intervalMs <= 0 { // no summary.json: infer from the first two window ends
		ws := d.windowsInRange(0, 1<<62)
		if len(ws) >= 2 {
			d.intervalMs = d.wend[ws[1]] - d.wend[ws[0]]
		}
	}
	if d.intervalMs <= 0 {
		return fmt.Errorf("--window: cannot determine the recorded window size")
	}
	rec := time.Duration(d.intervalMs) * time.Millisecond
	if o.Window < rec || o.Window%rec != 0 {
		return fmt.Errorf("--window %s must be a whole multiple of the recorded window (%s)", o.Window, rec)
	}
	from, to := d.bounds(o)
	if k := d.widen(o); k > 1 && len(d.windowsInRange(from, to)) < k {
		return fmt.Errorf("--window %s is longer than the analysed range (%d recorded windows of %s)",
			o.Window, len(d.windowsInRange(from, to)), rec)
	}
	return nil
}

// windowDur is the length of recorded window w in seconds.
func (d *data) windowDur(w int64) float64 {
	prev, ok := d.wend[w-1]
	if !ok {
		prev = d.startMs + w*d.intervalMs
	}
	if s := float64(d.wend[w]-prev) / 1000; s > 0 {
		return s
	}
	return float64(d.intervalMs) / 1000
}

// series returns the op's samples in (from,to]: one per recorded window (k == 1), or one per
// complete group of k consecutive recorded windows. Widened percentiles come from the merged
// per-window histograms (never from averaging percentiles).
func (d *data) series(op string, from, to int64, k int) []opSample {
	rows := map[int64]metricRow{}
	for _, m := range d.metrics {
		if m.op == op && m.ts > from && m.ts <= to {
			rows[m.window] = m
		}
	}
	if k <= 1 {
		var out []opSample
		for _, w := range d.windowsInRange(from, to) {
			m, ok := rows[w]
			if !ok {
				continue
			}
			out = append(out, opSample{rate: m.opsPerSec, errs: float64(m.errors), hasLat: m.hasLat && m.count > 0,
				mean: m.meanUs, p50: m.p50, p99: m.p99})
		}
		return out
	}
	all := d.windowsInRange(from, to)
	var out []opSample
	for b := 0; (b+1)*k <= len(all); b++ {
		var count, errors, latCount uint64
		var latSum, secs float64
		var h stats.Hist
		for _, w := range all[b*k : (b+1)*k] {
			secs += d.windowDur(w)
			m, ok := rows[w]
			if !ok {
				continue
			}
			count += m.count
			errors += m.errors
			if m.hasLat && m.count > 0 {
				latCount += m.count
				latSum += m.meanUs * float64(m.count)
			}
			h.Merge(d.hist[op][w])
		}
		s := opSample{rate: float64(count) / secs, errs: float64(errors)}
		if latCount > 0 {
			s.hasLat = true
			s.mean = latSum / float64(latCount)
			s.p50, s.p99 = float64(h.Quantile(0.5)), float64(h.Quantile(0.99))
		}
		out = append(out, s)
	}
	return out
}

// printFDBDisk prints the disk space used by FDB at the start and end of the run.
func (d *data) printFDBDisk(w io.Writer) {
	ser := d.fdbCluster["disk_used_bytes"]
	if len(ser) == 0 && !d.hasStartDisk {
		return
	}
	var start, end float64
	switch {
	case d.hasStartDisk:
		start = d.fdbStartDisk
	case len(ser) > 0:
		start = ser[0].v
	}
	if len(ser) > 0 {
		end = ser[len(ser)-1].v
	}
	subHeading(w, "Disk space used", "", "total_disk_used_bytes from FDB status, summed over the cluster, including replicas")
	fmt.Fprintf(w, " start %s", bytesStr(start))
	if len(ser) > 0 {
		sign := "+"
		if end < start {
			sign = "-"
		}
		fmt.Fprintf(w, "   end %s   change %s%s", bytesStr(end), sign, bytesStr(math.Abs(end-start)))
	}
	fmt.Fprintln(w)
}
