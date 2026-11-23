package collect

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseStatusFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	cs, rows, err := ParseStatus(append([]byte("warning: something\n"), data...))
	if err != nil {
		t.Fatal(err)
	}
	if cs.TxnHz != 4130.5 || cs.WritesHz != 38600 || cs.ConflictHz != 0.4 || cs.WorstQueueSS != 12400000 ||
		cs.LimitingQueueSS != 3000000 || cs.DurLagSecs != 0.4 || cs.ReadsHz != 900 || cs.WorstQueueLog != 5000000 {
		t.Fatalf("cluster: %+v", cs)
	}
	if len(rows) != 4 { // ss, log, commit_proxy+resolver, idle stateless; storage without roles skipped
		t.Fatalf("rows=%d %+v", len(rows), rows)
	}
	ss, lg, sl, idle := rows[0], rows[1], rows[2], rows[3]
	if ss.Role != "storage" || ss.Addr != "10.0.0.1:4501" || ss.Vals["input_hz"] != 1000 ||
		ss.Vals["durable_hz"] != 900 || ss.Vals["kvstore_bytes"] != 6000 || ss.Vals["durability_lag_s"] != 0.5 ||
		ss.Vals["data_lag_s"] != 0.3 || ss.Vals["queue_disk_bytes"] != 777 || ss.Vals["rss_bytes"] != 2e9 ||
		ss.Vals["disk_writes_hz"] != 20 {
		t.Fatalf("ss: %+v", ss)
	}
	if _, has := ss.Vals["queue_mem_bytes"]; has {
		t.Fatal("storage row must not have queue_mem_bytes")
	}
	if lg.Role != "log" || lg.Vals["queue_mem_bytes"] != 50 || lg.Vals["rss_bytes"] != 1000 {
		t.Fatalf("log: %+v", lg)
	}
	if sl.Role != "commit_proxy,resolver" || sl.Vals["cpu_cores"] != 0.2 {
		t.Fatalf("sl: %+v", sl)
	}
	if _, has := sl.Vals["input_hz"]; has {
		t.Fatal("stateless row must only have common fields")
	}
	if idle.Role != "none" {
		t.Fatalf("idle: %+v", idle)
	}
}

func TestParseStatusErrors(t *testing.T) {
	if _, _, err := ParseStatus([]byte("not json")); err == nil {
		t.Fatal("want error")
	}
	if _, _, err := ParseStatus([]byte(`{"client":{}}`)); err == nil {
		t.Fatal("want error for missing cluster")
	}
}

func TestProcTicks(t *testing.T) {
	// comm contains spaces and a ')' to exercise the parser.
	stat := "1234 (kv rgw) worker) S 1 2 3 4 5 6 7 8 9 10 150 50 0 0 20 0 8 0 100 0 0"
	got, err := ProcTicks(stat)
	if err != nil || got != 200 {
		t.Fatalf("got %d err %v", got, err)
	}
	if _, err := ProcTicks("garbage"); err == nil {
		t.Fatal("want error")
	}
	if c := WorkerCores(100, 300, 2); c != 1.0 {
		t.Fatalf("cores %v", c)
	}
	if c := WorkerCores(300, 100, 2); c != 0 {
		t.Fatalf("cores %v", c)
	}
}

func TestProcStat(t *testing.T) {
	a, err := ParseProcStat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0 0 0\nintr 1\n")
	if err != nil || a.NCPU != 2 || a.Total != 1000 || a.Busy != 200 {
		t.Fatalf("%+v %v", a, err)
	}
	b, _ := ParseProcStat("cpu  200 0 200 1000 0 0 0 0 0 0\ncpu0 1 0 0 0 0 0 0 0 0 0\ncpu1 1 0 0 0 0 0 0 0 0 0\n")
	// busy delta 200 / total delta 400 = 0.5 of 2 cpus = 1.0 core
	if c := SystemCores(a, b); c != 1.0 {
		t.Fatalf("system cores %v", c)
	}
}

func TestParseStatusFullCPURows(t *testing.T) {
	data, err := os.ReadFile("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _, cpu, err := ParseStatusFull(data)
	if err != nil {
		t.Fatal(err)
	}
	// One row per process, including the storage-class process with no roles.
	if len(cpu) != 5 {
		t.Fatalf("cpu rows=%d %+v", len(cpu), cpu)
	}
	byAddr := map[string]CPURow{}
	for _, r := range cpu {
		byAddr[r.Addr] = r
	}
	if r := byAddr["10.0.0.1:4501"]; r.Cores != 0.6 || len(r.Roles) != 1 || r.Roles[0] != "storage" || r.Class != "storage" {
		t.Fatalf("storage: %+v", r)
	}
	if r := byAddr["10.0.0.3:4503"]; len(r.Roles) != 2 || r.Roles[0] != "commit_proxy" || r.Roles[1] != "resolver" {
		t.Fatalf("multi-role must list every role, sorted: %+v", r)
	}
	if r := byAddr["10.0.0.4:4504"]; len(r.Roles) != 1 || r.Roles[0] != "none" || r.Cores != 0.01 {
		t.Fatalf("no roles => none: %+v", r)
	}
}

func fakeFdbcli(t *testing.T, body string) string {
	t.Helper()
	p := t.TempDir() + "/fdbcli"
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStatusFailureCarriesStderrAndTimeouts(t *testing.T) {
	s := &FDBSampler{Path: fakeFdbcli(t, `echo "ERROR: Timed out" >&2; exit 1`), Timeout: 3 * time.Second, OuterLimit: 5 * time.Second}
	_, err := s.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ERROR: Timed out") || !strings.Contains(err.Error(), "--timeout 3s") {
		t.Fatalf("want stderr and timeout in error, got %v", err)
	}
	// The process is killed at the outer limit; the error says so.
	s = &FDBSampler{Path: fakeFdbcli(t, `sleep 10`), Timeout: time.Second, OuterLimit: 1500 * time.Millisecond}
	start := time.Now()
	_, err = s.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "outer limit") || time.Since(start) > 5*time.Second {
		t.Fatalf("want outer-limit kill, got %v after %s", err, time.Since(start))
	}
}

func TestStatusPassesWholeSecondTimeout(t *testing.T) {
	out := t.TempDir() + "/args"
	s := &FDBSampler{Path: fakeFdbcli(t, `echo "$@" > `+out+`; echo '{"cluster":{}}'`), Timeout: 20 * time.Second, OuterLimit: 22 * time.Second}
	if _, err := s.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "--timeout 20") {
		t.Fatalf("args: %s", b)
	}
}
