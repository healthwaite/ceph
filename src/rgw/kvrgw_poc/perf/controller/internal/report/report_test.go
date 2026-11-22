package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kvrgw-perf/internal/config"
	"kvrgw-perf/internal/results"
)

// fixture writes a results dir: benchmark 1000s..1020s, 1s windows ending at 1001..1020
// (plus one stray row after the end). ops/sec == window number * 100 so exclusion is visible.
func fixture(t *testing.T, failed bool) string {
	dir := t.TempDir()
	w := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const start = int64(1_000_000)
	w("events.csv", fmt.Sprintf("unix_ts_ms,event\n%d,invocation_start\n%d,benchmark_start\n%d,benchmark_end\n%d,verify_start\n",
		start-500, start, start+20000, start+21000))
	var m, h, s, c strings.Builder
	m.WriteString(strings.Join(results.MetricsHeader, ",") + "\n")
	h.WriteString("window,op_type,bucket_index,count\n")
	s.WriteString("unix_ts_ms,window,name,value\n")
	c.WriteString("unix_ts_ms,source,cores\n")
	for win := int64(0); win < 22; win++ { // windows 20,21 end after benchmark_end
		ts := start + (win+1)*1000
		rate := (win + 1) * 100
		fmt.Fprintf(&m, "%d,%d,put_object,%d,0,%d.000,1000.000,1000,2000,3000,4000,5000,%d,0\n", ts, win, rate, rate, rate)
		// 100 samples of ~1000us per window (bucket 100 holds 1000us), win 21 would be excluded
		fmt.Fprintf(&h, "%d,put_object,%d,%d\n", win, 100, rate)
		fmt.Fprintf(&s, "%d,%d,PutObject.count,%d\n", ts, win, (win+1)*100)
		fmt.Fprintf(&s, "%d,%d,PutObject.total_us,%d\n", ts, win, (win+1)*100*500)
		fmt.Fprintf(&s, "%d,%d,PutObject.fdb_us,%d\n", ts, win, (win+1)*100*400)
		fmt.Fprintf(&c, "%d,worker-0,%d.0\n", ts, 2)
		fmt.Fprintf(&c, "%d,system,%d.0\n", ts, 10)
	}
	w("metrics.csv", m.String())
	w("hist.csv", h.String())
	w("server_stats.csv", s.String())
	w("cpu.csv", c.String())
	// FDB: 3 storage servers (one hotspot), 1 log
	var fc, fp strings.Builder
	fc.WriteString(strings.Join(results.FDBClusterHeader, ",") + "\n")
	fp.WriteString(strings.Join(results.FDBProcessHeader, ",") + "\n")
	for i := int64(0); i < 20; i++ {
		ts := start + i*1000
		fmt.Fprintf(&fc, "%d,4000,900,38000,0.5,12000000,5000000,3000000,0.4\n", ts)
		for _, ss := range []struct {
			addr string
			cpu  string
			in   string
		}{{"10.0.0.1:4501", "0.5", "1000"}, {"10.0.0.2:4502", "0.6", "1100"}, {"10.0.0.3:4503", "0.97", "3000"}} {
			fmt.Fprintf(&fp, "%d,%s,storage,%s,100,100,%s,1000,1,1,0.3,0.5,5,,0.1,1,2\n", ts, ss.addr, ss.cpu, ss.in)
		}
		fmt.Fprintf(&fp, "%d,10.0.0.9:4600,log,0.5,100,100,70,69,,,,,1000,50,0.1,1,2\n", ts)
		fmt.Fprintf(&fp, "%d,10.0.0.8:4700,\"commit_proxy,resolver\",0.2,100,100,,,,,,,,,0,0,0\n", ts)
	}
	w("fdb_cluster.csv", fc.String())
	w("fdb_process.csv", fp.String())
	sum := results.Summary{Command: "run-put-object", Parameters: config.Defaults(), Failed: failed, OpErrors: 6,
		Verify: &results.VerifySummary{Ran: true, Pass: true, DurationMs: 41000, Buckets: make([]results.BucketVerify, 4)}}
	sum.Parameters.ReportIntervalMs = 1000
	sum.Parameters.WorkerCount, sum.Parameters.ThreadsPerWorker, sum.Parameters.NumBuckets = 4, 8, 4
	sum.Totals = map[string]results.OpTotals{"put_object": {Errors: 6}}
	sum.ErrorDescriptions = map[string]string{"KVRGW_ERR_TXN_CONFLICT": "Transaction conflict"}
	var e strings.Builder
	e.WriteString("unix_ts_ms,window,op_type,error_code,count\n")
	fmt.Fprintf(&e, "%d,3,put_object,KVRGW_ERR_TXN_CONFLICT,4\n", start+4000)  // inside the window with a 2s warmup
	fmt.Fprintf(&e, "%d,0,put_object,KVRGW_ERR_TXN_CONFLICT,50\n", start+1000) // before a 2s warmup
	w("errors.csv", e.String())
	b, _ := json.Marshal(sum)
	w("summary.json", string(b))
	return dir
}

func render(t *testing.T, dir string, o Options) (string, int) {
	var buf bytes.Buffer
	code := Run(&buf, dir, o)
	return buf.String(), code
}

func TestWarmupWindowing(t *testing.T) {
	dir := fixture(t, false)
	out, code := render(t, dir, Options{Detailed: true, Warmup: 10 * time.Second})
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// Windows ending in (start+10s, start+20s] => window numbers 10..19 => rates 1100..2000.
	// Excluded: rows before warmup (rate<=1000) and after benchmark_end (windows 20, 21).
	if !strings.Contains(out, "1,100") || strings.Contains(out, "2,100") {
		t.Fatalf("min/max rates wrong:\n%s", out)
	}
	if !strings.Contains(out, "10 windows of 1s") {
		t.Fatalf("window count:\n%s", out)
	}
	if !strings.Contains(out, "Warmup skipped: first 10s") {
		t.Fatal("warmup in header")
	}
	// Totals: sum 1100..2000 = 15500 ops from merged hist windows only.
	// 15,500 ops over the 10s analysed window => 1,550 ops/s average; latencies in ms (3 s.f.)
	if !strings.Contains(out, "put_object              15,500        0      1,550     1.00    0.146") {
		t.Fatalf("totals:\n%s", out)
	}
	if !strings.Contains(out, "Verify    : PASS  (4 buckets") {
		t.Fatalf("verify line:\n%s", out)
	}
	// The server section no longer repeats op counts/latencies (the client tables are the source
	// of truth); it still has the txn counters.
	if !strings.Contains(out, "SERVER-SIDE KVRGW") || strings.Contains(out, "avg_total_ms") ||
		hasRow(out, "PutObject", "1,000", "100", "0.500") ||
		strings.Contains(out, "avg_fdb") || strings.Contains(out, "commit=") || !strings.Contains(out, "hard_failures") {
		t.Fatalf("server section:\n%s", out)
	}
	// worker CPU and system CPU present
	if !strings.Contains(out, "worker 0") || !strings.Contains(out, "system (host)") {
		t.Fatalf("cpu section:\n%s", out)
	}
}

func TestErrorBreakdown(t *testing.T) {
	out, _ := render(t, fixture(t, false), Options{Warmup: 2 * time.Second})
	if !strings.Contains(out, "errors: TXN_CONFLICT") || !strings.Contains(out, "x4  Transaction conflict") {
		t.Fatalf("breakdown missing or wrong:\n%s", out)
	}
	if strings.Contains(out, "x54") || strings.Contains(out, "x50") {
		t.Fatal("rows before the warmup boundary must be excluded")
	}
}

func TestNoWarmupIncludesAllWindows(t *testing.T) {
	out, _ := render(t, fixture(t, false), Options{})
	if !strings.Contains(out, "20 windows of 1s") || !strings.Contains(out, "21,000") {
		t.Fatalf("\n%s", out)
	}
}

func TestDevPercent(t *testing.T) {
	// ops/sec series 1100..2000 (10 windows): median 1550; |v-med|/med>10% for most values.
	out, _ := render(t, fixture(t, false), Options{Detailed: true, Warmup: 10 * time.Second, Deviation: 10})
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "ops/sec") && line == "" {
			line = l
		}
	}
	// values within 10% of 1550 are 1395..1705: 1400,1500,1600,1700 => 4 of 10 => 60% deviate
	if !strings.Contains(line, "60.0%") {
		t.Fatalf("ops/sec line %q", line)
	}
	out, _ = render(t, fixture(t, false), Options{Detailed: true, Warmup: 10 * time.Second, Deviation: 100})
	if strings.Contains(out, "60.0%") {
		t.Fatal("deviation flag ignored")
	}
}

func TestRoleAggregationVsPerServer(t *testing.T) {
	dir := fixture(t, false)
	agg, _ := render(t, dir, Options{Warmup: 5 * time.Second})
	if !strings.Contains(agg, "SS  (3)") || !strings.Contains(agg, "LOG (1)") || !strings.Contains(agg, "SL  (1)") {
		t.Fatalf("aggregated roles:\n%s", agg)
	}
	if !strings.Contains(agg, "cpu=0.50-0.97") {
		t.Fatalf("range:\n%s", agg)
	}
	byRole := strings.Split(strings.Split(agg, "FDB BY ROLE")[1], "HEALTH")[0]
	if strings.Contains(byRole, "10.0.0.3:4503") {
		t.Fatal("aggregated view must not list processes")
	}
	per, _ := render(t, dir, Options{Warmup: 5 * time.Second, PerServer: true})
	if !strings.Contains(per, "10.0.0.3:4503") || !strings.Contains(per, "[HOTSPOT]") || !strings.Contains(per, "10.0.0.1:4501") {
		t.Fatalf("per server:\n%s", per)
	}
	for _, l := range strings.Split(per, "\n") {
		if strings.Contains(l, "SS  10.0.0.1:4501") && strings.Contains(l, "[HOTSPOT]") {
			t.Fatal("only the hot server should be flagged")
		}
	}
	if !strings.Contains(agg, "[OK] TLog queue stable") {
		t.Fatalf("health:\n%s", agg)
	}
}

func TestExitCodes(t *testing.T) {
	if _, code := render(t, fixture(t, true), Options{}); code != 1 {
		t.Fatalf("failed run => 1, got %d", code)
	}
	if _, code := render(t, filepath.Join(t.TempDir(), "missing"), Options{}); code != 2 {
		t.Fatalf("unreadable => 2, got %d", code)
	}
	empty := t.TempDir()
	if _, code := render(t, empty, Options{}); code != 2 {
		t.Fatalf("no events.csv => 2, got %d", code)
	}
}

// hasRow reports whether some output line has exactly these whitespace-separated fields.
func hasRow(out string, fields ...string) bool {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == len(fields) && strings.Join(f, " ") == strings.Join(fields, " ") {
			return true
		}
	}
	return false
}

func TestWiden(t *testing.T) {
	dir := fixture(t, false)
	// Warmup 10s => recorded windows 10..19 (rates 1100..2000). 5s windows => two buckets:
	// (1100+..+1500)/5 = 1300 ops/s and (1600+..+2000)/5 = 1800 ops/s.
	out, code := render(t, dir, Options{Detailed: true, Warmup: 10 * time.Second, Window: 5 * time.Second})
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "(2 windows of 5s)") {
		t.Fatalf("header:\n%s", out)
	}
	var ops, p50 string
	for _, l := range strings.Split(out, "\n") {
		switch f := strings.Fields(l); {
		case len(f) > 0 && f[0] == "ops/sec" && ops == "":
			ops = l
		case len(f) > 0 && f[0] == "p50_ms":
			p50 = l
		}
	}
	if f := strings.Fields(ops); len(f) < 3 || f[1] != "1,300" || f[2] != "1,800" {
		t.Fatalf("ops/sec min/max wrong: %q", ops)
	}
	// Percentiles come from the merged histograms (fixture: bucket 100 => 146us), not the
	// per-window p50 column (1000us).
	if !strings.Contains(p50, "0.146") {
		t.Fatalf("p50 should come from merged histograms: %q", p50)
	}
	// Totals still cover every recorded window in range.
	if !strings.Contains(out, "15,500") {
		t.Fatalf("totals:\n%s", out)
	}
}

func TestWidenDropsTrailingPartialWindow(t *testing.T) {
	// 20 recorded windows in range; 8s windows => 2 complete (16 windows), 4 left over.
	out, _ := render(t, fixture(t, false), Options{Window: 8 * time.Second})
	if !strings.Contains(out, "(2 windows of 8s)") || !strings.Contains(out, "21,000") {
		t.Fatalf("\n%s", out)
	}
}

func TestWidenValidation(t *testing.T) {
	dir := fixture(t, false)
	for _, w := range []time.Duration{1500 * time.Millisecond, 500 * time.Millisecond, 60 * time.Second} {
		if out, code := render(t, dir, Options{Warmup: 10 * time.Second, Window: w}); code != 2 {
			t.Errorf("--window %s: want exit 2, got %d\n%s", w, code, out)
		}
	}
	// same as recorded size is allowed and equals the default output
	a, _ := render(t, dir, Options{Detailed: true, Window: time.Second})
	b, _ := render(t, dir, Options{Detailed: true})
	if a != b {
		t.Fatal("--window equal to the recorded window must not change the report")
	}
}

func TestWorkerCPUWindowsAndTotals(t *testing.T) {
	out, _ := render(t, fixture(t, false), Options{Detailed: true, Warmup: 10 * time.Second})
	for _, want := range []string{"WORKER CPU", "Per-window statistics   10 windows of 1s, cores", "Run totals   10s analysed", "source", "system (host)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestServerWindowsAndTotals(t *testing.T) {
	out, _ := render(t, fixture(t, false), Options{Detailed: true, Warmup: 10 * time.Second})
	for _, want := range []string{"SERVER-SIDE KVRGW", "Per-window statistics   10 windows of 1s, summed over workers", "Run totals   10s analysed", "hard_failures"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestWindowedStatsWarning(t *testing.T) {
	var s []sample
	for i := int64(1); i <= 10; i++ {
		s = append(s, sample{ts: i * 5000, v: 1})
	}
	if w := windowedStatsWarning("FDB cluster", "fdb_sample_interval_ms", s, 0, 50000, time.Second); !strings.Contains(w, "every ~5s") ||
		!strings.Contains(w, "--window 5s or longer") || !strings.Contains(w, "fdb_sample_interval_ms") {
		t.Fatalf("warning: %q", w)
	}
	if w := windowedStatsWarning("FDB cluster", "x", s, 0, 50000, 5*time.Second); w != "" {
		t.Fatalf("interval == window should be fine: %q", w)
	}
	if w := windowedStatsWarning("FDB cluster", "x", s[:1], 0, 50000, time.Second); !strings.Contains(w, "too few samples") {
		t.Fatalf("few samples: %q", w)
	}
}

func TestFDBPerWindow(t *testing.T) {
	out, _ := render(t, fixture(t, false), Options{Detailed: true, Warmup: 10 * time.Second})
	if !strings.Contains(out, "FDB CLUSTER") || !strings.Contains(out, "Per-window statistics   9 of 10 windows of 1s had samples") || !strings.Contains(out, "Run totals   10s analysed, 10 samples at ~1s") {
		t.Fatalf("\n%s", out)
	}
}

func TestTrailingStubWindowDropped(t *testing.T) {
	d := &data{intervalMs: 1000, startMs: 0, wend: map[int64]int64{0: 1000, 1: 2000, 2: 3000, 3: 3024}}
	if got := d.windowsInRange(0, 1<<40); len(got) != 3 || got[2] != 2 {
		t.Fatalf("stub window should be dropped: %v", got)
	}
	d.wend[3] = 3800 // a long final window is kept
	if got := d.windowsInRange(0, 1<<40); len(got) != 4 {
		t.Fatalf("long final window should be kept: %v", got)
	}
}

func TestSampleNote(t *testing.T) {
	s := []sample{{1000, 1}, {6000, 1}, {11000, 1}}
	if got := sampleNote(s, 0, 20000); got != "3 samples at ~5s" {
		t.Fatalf("%q", got)
	}
}

func TestWindowsNote(t *testing.T) {
	if got := windowsNote(3, 3, 10*time.Second); got != "3 windows of 10s" {
		t.Fatal(got)
	}
	if got := windowsNote(2, 3, 10*time.Second); got != "2 of 3 windows of 10s had samples" {
		t.Fatal(got)
	}
	s := []sample{{1500, 1}}
	if !windowHasSample([2]int64{1000, 2000}, s) || windowHasSample([2]int64{2000, 3000}, s) {
		t.Fatal("windowHasSample")
	}
}

func TestNumAbbreviatesMillions(t *testing.T) {
	for in, want := range map[float64]string{999999: "999,999", 1416580: "1.42M", 2.5e9: "2.50G", -1.5e6: "-1.50M"} {
		if got := num(in); got != want {
			t.Fatalf("num(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultOmitsPerWindowTables(t *testing.T) {
	dir := fixture(t, false)
	def, _ := render(t, dir, Options{Warmup: 10 * time.Second})
	for _, gone := range []string{"Per-window statistics", "errors/win", "retries/win"} {
		if strings.Contains(def, gone) {
			t.Fatalf("%q must only appear with --detailed:\n%s", gone, def)
		}
	}
	for _, want := range []string{"CLIENT OPS", "Run totals", "15,500", "WORKER CPU", "SERVER-SIDE KVRGW", "FDB CLUSTER", "FDB BY ROLE"} {
		if !strings.Contains(def, want) {
			t.Fatalf("missing %q:\n%s", want, def)
		}
	}
	det, _ := render(t, dir, Options{Warmup: 10 * time.Second, Detailed: true})
	if strings.Count(det, "Per-window statistics") != 4 {
		t.Fatalf("expected a per-window table in each of the four sections:\n%s", det)
	}
}

// withCPU adds an fdb_cpu.csv (one row per process per FDB sample) to a fixture directory.
func withCPU(t *testing.T, dir string, hotStorage string, step ...int) {
	t.Helper()
	every := 1
	if len(step) > 0 {
		every = step[0] // keep every Nth FDB sample (to make the CPU sampling slower)
	}
	b, err := os.ReadFile(filepath.Join(dir, "fdb_cluster.csv"))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	out.WriteString(strings.Join(results.FDBCPUHeader, ",") + "\n")
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if i == 0 {
			continue
		}
		if (i-1)%every != 0 {
			continue
		}
		ts := strings.SplitN(line, ",", 2)[0]
		for _, p := range [][]string{
			{"10.0.0.1:4501", "storage", "coordinator;storage", "0.5"},
			{"10.0.0.2:4502", "storage", "storage", "0.6"},
			{"10.0.0.3:4503", "storage", "storage", hotStorage},
			{"10.0.0.9:4600", "transaction", "log", "0.5"},
			{"10.0.0.8:4700", "stateless", "commit_proxy;resolver", "0.2"},
			{"10.0.0.7:4500", "coordinator", "coordinator", "0.08"},
		} {
			fmt.Fprintf(&out, "%s,%s,%s,%s,%s\n", ts, p[0], p[1], p[2], p[3])
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "fdb_cpu.csv"), []byte(out.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFDBCPUByRole(t *testing.T) {
	dir := fixture(t, false)
	base, _ := render(t, dir, Options{Warmup: 5 * time.Second})
	if !strings.Contains(base, "SL  (1)") || strings.Contains(base, "CPU by role") {
		t.Fatalf("without fdb_cpu.csv the old SL line stays and no CPU table appears:\n%s", base)
	}
	withCPU(t, dir, "0.97")
	out, _ := render(t, dir, Options{Warmup: 5 * time.Second})
	for _, want := range []string{"CPU by role   ", "mean cores per process over the run"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	// A process with several roles counts under each, once in the total.
	for _, row := range [][]string{
		{"storage", "2.07", "3", "0.690"},
		{"coordinator", "0.58", "2", "0.290"},
		{"log", "0.50", "1", "0.500"},
		{"commit_proxy", "0.20", "1", "0.200"},
		{"resolver", "0.20", "1", "0.200"},
	} {
		if !hasRow(out, row...) {
			t.Fatalf("missing role row %v:\n%s", row, out)
		}
	}
	if !strings.Contains(out, "2.85      6     0.475   0.71 cores per 1,000 committed txn/s") {
		t.Fatalf("total row (6 processes, 2.85 cores, 4000 txn/s):\n%s", out)
	}
	if !strings.Contains(out, "min=0.500 median=0.600 mean=0.690 max=0.970 stddev=0.202") ||
		!strings.Contains(out, "max/median 1.6x   hottest: 10.0.0.3:4503 0.97, 10.0.0.2:4502 0.60, 10.0.0.1:4501 0.50") {
		t.Fatalf("storage spread:\n%s", out)
	}
	if strings.Contains(out, "SL  (") || strings.Contains(out, "storage CPU imbalance") {
		t.Fatalf("SL line is replaced by the table; 1.6x is below the 1.8 threshold:\n%s", out)
	}
}

func TestStorageCPUImbalanceWarning(t *testing.T) {
	dir := fixture(t, false)
	withCPU(t, dir, "1.5") // median 0.6, hottest 1.5 => 2.5x
	out, _ := render(t, dir, Options{Warmup: 5 * time.Second})
	want := "[WARN] storage CPU imbalance: hottest 10.0.0.3:4503 at 1.50 cores is 2.5x the median (0.60)"
	if !strings.Contains(out, want) {
		t.Fatalf("missing %q:\n%s", want, out)
	}
	// Just under the threshold does not warn: 1.02 / 0.6 = 1.7 (the test is "above 1.8").
	dir = fixture(t, false)
	withCPU(t, dir, "1.02")
	out, _ = render(t, dir, Options{Warmup: 5 * time.Second})
	if strings.Contains(out, "storage CPU imbalance") {
		t.Fatalf("a ratio of 1.7 must not warn:\n%s", out)
	}
}

func cpuRow(out, label string) []string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), label) {
			return strings.Fields(strings.TrimSpace(l)[len(label):])
		}
	}
	return nil
}

func TestFDBCPUPerWindow(t *testing.T) {
	dir := fixture(t, false)
	withCPU(t, dir, "0.97")
	// 5s windows: each holds five 1s samples, and the per-process CPU is constant.
	out, _ := render(t, dir, Options{Warmup: 5 * time.Second, Window: 5 * time.Second, Detailed: true})
	if !strings.Contains(out, "CPU per-window statistics   3 windows of 5s") {
		t.Fatalf("heading:\n%s", out)
	}
	for label, want := range map[string]string{
		"total (cores)":           "2.85", // 0.5+0.6+0.97+0.5+0.2+0.08, each process once
		"storage (cores)":         "2.07",
		"log (cores)":             "0.50",
		"storage max/median":      "1.62", // 0.97 / 0.60
		"hottest storage (cores)": "0.97",
	} {
		f := cpuRow(out, label)
		if len(f) < 8 || f[0] != want || f[1] != want || f[2] != want || f[3] != want {
			t.Fatalf("%s: want %s in min/max/avg/median, got %v\n%s", label, want, f, out)
		}
	}
	// The default report has the by-role table but not the per-window one.
	def, _ := render(t, dir, Options{Warmup: 5 * time.Second})
	if strings.Contains(def, "CPU per-window statistics") || !strings.Contains(def, "CPU by role") {
		t.Fatalf("per-window CPU must be --detailed only:\n%s", def)
	}
}

func TestFDBCPUPerWindowNeedsFastEnoughSampling(t *testing.T) {
	dir := fixture(t, false)
	withCPU(t, dir, "0.97", 3) // one sample every 3s, but 1s windows
	out, _ := render(t, dir, Options{Warmup: 5 * time.Second, Detailed: true})
	if !strings.Contains(out, "CPU per-window statistics   not shown") ||
		!strings.Contains(out, "[WARN] FDB CPU is sampled every ~3s, which is longer than the 1s window") {
		t.Fatalf("expected the not-shown warning:\n%s", out)
	}
	if !strings.Contains(out, "CPU by role") {
		t.Fatalf("the run-totals table does not depend on the window:\n%s", out)
	}
}

func TestFDBPerRoleWindows(t *testing.T) {
	dir := fixture(t, false)
	out, code := render(t, dir, Options{Detailed: true, Warmup: 2 * time.Second})
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	i := strings.Index(out, "FDB per-role statistics")
	if i < 0 {
		t.Fatalf("no per-role table\n%s", out)
	}
	tbl := out[i:]
	// row finds a table row by its label (whitespace-insensitive) and returns its fields after it.
	row := func(label string) []string {
		want := strings.Fields(label)
		for _, l := range strings.Split(tbl, "\n") {
			f := strings.Fields(l)
			if len(f) >= len(want)+8 && strings.Join(f[:len(want)], " ") == strings.Join(want, " ") {
				return f[len(want):] // n min max avg median p90 p95 p99
			}
		}
		t.Fatalf("no row %q in\n%s", label, tbl)
		return nil
	}
	eq := func(got []string, want ...string) {
		t.Helper()
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Fatalf("got %v want %v\n%s", got, want, tbl)
		}
	}
	// 3 storage servers with cpu 0.5/0.6/0.97 in each of 17 windows: n=51, min, max, avg, median, p90, p95, p99.
	eq(row("storage (3) cpu (cores)"), "51", "0.50", "0.97", "0.69", "0.60", "0.97", "0.97", "0.97")
	// hottest/median is 0.97/0.6 in every window: n = windows.
	eq(row("storage (3) cpu hottest/median"), "17", "1.62", "1.62", "1.62", "1.62", "1.62", "1.62", "1.62")
	// disk busy is 0.1 => 10.0%, ratio 1.00.
	eq(row("storage (3) disk busy (%)"), "51", "10.0", "10.0", "10.0", "10.0", "10.0", "10.0", "10.0")
	eq(row("storage (3) disk busy hottest/median"), "17", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00")
	eq(row("log (1) disk busy (%)"), "17", "10.0", "10.0", "10.0", "10.0", "10.0", "10.0", "10.0")
	// The combined "commit_proxy,resolver" process counts under each role; no disk rows for them.
	eq(row("commit_proxy (1) cpu (cores)"), "17", "0.20", "0.20", "0.20", "0.20", "0.20", "0.20", "0.20")
	eq(row("resolver (1) cpu (cores)"), "17", "0.20", "0.20", "0.20", "0.20", "0.20", "0.20", "0.20")
	if strings.Contains(tbl, "resolver     (1)  disk") || strings.Contains(tbl, "commit_proxy (1)  disk") {
		t.Fatalf("stateless roles must not have disk rows:\n%s", tbl)
	}
	// Not shown without --detailed.
	out, _ = render(t, dir, Options{Warmup: 2 * time.Second})
	if strings.Contains(out, "FDB per-role statistics") {
		t.Fatal("per-role table must be --detailed only")
	}
}

func TestSendLagHint(t *testing.T) {
	cases := []struct {
		lag, op uint64
		drv     float64
		want    string
	}{
		{900, 2000, 0.9, ""},                             // under 1 ms: nothing
		{1070, 1917000, 0.12, "[INFO]"},                  // negligible next to op p99
		{5000, 20000, 0.87, "raise driver_threads"},      // significant, drivers busy
		{5000, 20000, 0.10, "the lag comes from bursts"}, // significant, drivers idle
		{5000, 0, 0.10, "the lag comes from bursts"},     // no op p99 known
	}
	for _, c := range cases {
		got := sendLagHint(c.lag, c.op, c.drv)
		if (c.want == "" && got != "") || (c.want != "" && !strings.Contains(got, c.want)) {
			t.Errorf("sendLagHint(%d, %d, %.2f) = %q, want %q", c.lag, c.op, c.drv, got, c.want)
		}
	}
}
