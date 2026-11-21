package config

import (
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const sample = `
base:
  num_objects: 5000
  num_buckets: 4
  worker_count: 2
  threads_per_worker: 8
load:
  threads_per_worker: 16
run-list-objects:
  page_size: 500
run-put-object: {}
`

func mustFile(t *testing.T, s string) *File {
	f, err := ParseFile([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMergePrecedence(t *testing.T) {
	f := mustFile(t, sample)
	c, err := Resolve(f, "load")
	if err != nil {
		t.Fatal(err)
	}
	if c.NumObjects != 5000 || c.ThreadsPerWorker != 16 || c.WorkerCount != 2 || c.PaddingBytes != 16 {
		t.Fatalf("%+v", c)
	}
	c, _ = Resolve(f, "run-put-object")
	if c.ThreadsPerWorker != 8 {
		t.Fatalf("base should win when no override: %+v", c)
	}
	// CLI beats file.
	ov := NewOverrides()
	ov.vals["threads_per_worker"] = "3"
	if err := ov.Apply(&c); err != nil || c.ThreadsPerWorker != 3 {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestStrictness(t *testing.T) {
	if _, err := ParseFile([]byte("bogus: {}")); err == nil {
		t.Fatal("unknown section must fail")
	}
	f := mustFile(t, "base:\n  nope: 1\n")
	if _, err := Resolve(f, "load"); err == nil {
		t.Fatal("unknown key must fail")
	}
	f = mustFile(t, "base:\n  num_objects: abc\n")
	if _, err := Resolve(f, "load"); err == nil {
		t.Fatal("wrong type must fail")
	}
	ov := NewOverrides()
	ov.vals["num_objects"] = "x"
	c := Defaults()
	if err := ov.Apply(&c); err == nil {
		t.Fatal("bad CLI value must fail")
	}
}

func TestOpsDurationRules(t *testing.T) {
	c := Defaults()
	if err := c.Validate("run-put-object"); err == nil {
		t.Fatal("neither ops nor duration must fail")
	}
	c.Ops, c.Duration = 10, "5s"
	if err := c.Validate("run-put-object"); err == nil {
		t.Fatal("both must fail")
	}
	c.Duration = ""
	if err := c.Validate("run-put-object"); err != nil {
		t.Fatal(err)
	}
	c.Duration = "bogus"
	c.Ops = 0
	if err := c.Validate("run-put-object"); err == nil {
		t.Fatal("bad duration")
	}
	c.Duration = "30s"
	if err := c.Validate("load"); err == nil {
		t.Fatal("duration invalid for load")
	}
	// CLI --ops replaces a duration from the file.
	c = Defaults()
	c.Duration = "30s"
	ov := NewOverrides()
	ov.vals["ops"] = "100"
	ov.Apply(&c)
	if c.Duration != "" || c.Ops != 100 {
		t.Fatalf("%+v", c)
	}
	// num_objects_to_overwrite: required (and a total <= num_objects) for the versioned
	// command, rejected for every other command.
	c = Defaults()
	c.Ops = 1
	if err := c.Validate("run-put-object-overwrite-versioned"); err == nil {
		t.Fatal("versioned overwrite needs num_objects_to_overwrite")
	}
	c.NumObjects, c.NumObjectsToOverwrite = 1000, 1001
	if err := c.Validate("run-put-object-overwrite-versioned"); err == nil {
		t.Fatal("num_objects_to_overwrite > num_objects must fail")
	}
	c.NumObjectsToOverwrite = 1000
	if err := c.Validate("run-put-object-overwrite-versioned"); err != nil {
		t.Fatalf("valid versioned overwrite: %v", err)
	}
	if err := c.Validate("run-put-object-overwrite"); err == nil {
		t.Fatal("num_objects_to_overwrite must be rejected for run-put-object-overwrite")
	}
	c.NumObjectsToOverwrite = 0
	if err := c.Validate("run-put-object-overwrite"); err != nil {
		t.Fatalf("run-put-object-overwrite needs no limit: %v", err)
	}
}

func TestCommandRulesAndWorkerJSON(t *testing.T) {
	c := Defaults()
	c.WorkerCount, c.NumBuckets = 8, 3
	w := c.ApplyCommandRules("run-list-objects")
	if c.WorkerCount != 3 || len(w) != 1 {
		t.Fatalf("capping failed: %+v %v", c.WorkerCount, w)
	}
	c = Defaults()
	c.WorkerCount, c.ThreadsPerWorker, c.SingleThreadMode = 4, 8, true
	c.ApplyCommandRules("run-delete-multi")
	if c.WorkerCount != 1 || c.ThreadsPerWorker != 1 {
		t.Fatal("single thread mode")
	}
	c.Duration = "2s"
	b, err := c.WorkerJSON()
	if err != nil || !contains(string(b), `"duration_ms":2000`) || contains(string(b), "fdb") {
		t.Fatalf("%s %v", b, err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// The shipped file may carry tuned values, but it must parse strictly, validate for every
// command, and list every config key explicitly in `base` (so all settings are discoverable).
func TestShippedConfigIsComplete(t *testing.T) {
	f, err := LoadFile("../../../kvrgw-perf.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := yaml.Unmarshal(f.sections["base"], &base); err != nil {
		t.Fatal(err)
	}
	rt := reflect.TypeOf(Config{})
	for i := 0; i < rt.NumField(); i++ {
		key := strings.Split(rt.Field(i).Tag.Get("yaml"), ",")[0]
		if key == "-" || key == "" || key == "ops" || key == "duration" ||
			key == "page_size" || key == "single_thread_mode" || key == "num_objects_to_overwrite" || key == "force" {
			continue // command-specific keys live in the command sections
		}
		if _, ok := base[key]; !ok {
			t.Errorf("base section does not list %q", key)
		}
	}
	for _, cmd := range Commands {
		c, err := Resolve(f, cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if cmd != "load" {
			if c.Ops != 0 || c.Duration == "" {
				t.Fatalf("%s: want a default duration and no ops, got ops=%d duration=%q", cmd, c.Ops, c.Duration)
			}
			c.Ops, c.Duration = 1, ""
		}
		if err := c.Validate(cmd); err != nil {
			t.Errorf("%s: %v", cmd, err)
		}
	}
}

func TestKvrgwYAML(t *testing.T) {
	c := Defaults()
	c.Kvrgw.BatchSize = 9
	p := t.TempDir() + "/kvrgw.yaml"
	if err := c.WriteKvrgwYAML(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	for _, want := range []string{"tier:", "max_inline: 256", "max_kv_store: 4096", "batch_size: 9", "backend_workers: 4"} {
		if !contains(string(b), want) {
			t.Errorf("missing %q in\n%s", want, b)
		}
	}
	if env := c.KvrgwEnv(); env[0] != "KVRGW_BATCH_SIZE=9" || !contains(strings.Join(env, " "), "KVRGW_BACKEND_WORKERS=4") ||
		!contains(strings.Join(env, " "), "KVRGW_MAX_INFLIGHT_OPS=4096") || contains(strings.Join(env, " "), "KVRGW_BATCH_THREADS") {
		t.Fatalf("%v", env)
	}
	// Deprecated batch_threads is passed through only when backend_workers is unset.
	old := Defaults()
	old.Kvrgw.BackendWorkers, old.Kvrgw.BatchThreads = 0, 8
	if env := strings.Join(old.KvrgwEnv(), " "); !contains(env, "KVRGW_BATCH_THREADS=8") || contains(env, "KVRGW_BACKEND_WORKERS") {
		t.Fatalf("%v", env)
	}
	ov := NewOverrides()
	ov.vals["batch_size"] = "2"
	ov.vals["max_inline"] = "512"
	ov.Apply(&c)
	if c.Kvrgw.BatchSize != 2 || c.Kvrgw.MaxInline != 512 {
		t.Fatalf("%+v", c.Kvrgw)
	}
	if _, err := ParseFile([]byte("kvrgw: {}")); err != nil {
		t.Fatal(err)
	}
	f, _ := ParseFile([]byte("kvrgw:\n  bogus: 1\n"))
	if _, err := Resolve(f, "load"); err == nil {
		t.Fatal("unknown kvrgw key must fail")
	}
}

func TestDriverModeAndStreams(t *testing.T) {
	c := Defaults()
	c.Duration = "1s"
	c.ThreadsPerWorker = 16
	if c.Streams() != 16 || c.Generators() != 16 {
		t.Fatalf("streams default to threads: %d %d", c.Streams(), c.Generators())
	}
	c.StreamsPerWorker = 512
	if c.Streams() != 512 {
		t.Fatal("streams_per_worker")
	}
	c.DriverMode = "bogus"
	if c.Validate("run-put-object") == nil {
		t.Fatal("bad driver_mode must fail")
	}
	c.DriverMode = "sync"
	c.RateOpsPerSec = 1000
	if c.Validate("run-put-object") == nil {
		t.Fatal("open loop needs async")
	}
	c.DriverMode = "async"
	if err := c.Validate("run-put-object"); err != nil {
		t.Fatal(err)
	}
	if c.Validate("run-list-objects") == nil {
		t.Fatal("open loop list-objects must fail")
	}
	if c.Generators() != c.DriverThreads {
		t.Fatal("open loop: one generator per driver thread")
	}
	b, _ := c.WorkerJSON()
	for _, want := range []string{`"driver_mode":"async"`, `"streams_per_worker":512`, `"driver_threads":2`, `"rate_ops_per_sec":1000`} {
		if !contains(string(b), want) {
			t.Fatalf("%s missing %s", b, want)
		}
	}
	ov := NewOverrides()
	ov.vals["streams_per_worker"] = "64"
	ov.vals["driver_mode"] = "sync"
	ov.vals["rate_ops_per_sec"] = "0"
	ov.vals["max_inflight_ops"] = "100"
	if err := ov.Apply(&c); err != nil || c.Streams() != 64 || c.DriverMode != "sync" || c.Kvrgw.MaxInflightOps != 100 {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestForceFlag(t *testing.T) {
	// --force (bare) and --force=false register on a FlagSet and reach the worker config.
	ov := NewOverrides()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	ov.Register(fs)
	if err := fs.Parse([]string{"--force"}); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	if err := ov.Apply(&c); err != nil || !c.Force {
		t.Fatalf("--force not applied: %v %+v", err, c.Force)
	}
	if err := c.Validate("load"); err != nil {
		t.Fatalf("force is valid for load: %v", err)
	}
	if err := c.Validate("run-put-object"); err == nil {
		t.Fatal("force must be rejected for run-* commands")
	}
	j, err := c.WorkerJSON()
	if err != nil || !strings.Contains(string(j), `"force":true`) {
		t.Fatalf("worker json: %s %v", j, err)
	}
	if Defaults().Force {
		t.Fatal("force must default to false")
	}
}

func TestBucketRangeAndVersionedPrompt(t *testing.T) {
	c := Defaults()
	c.BucketNamePrefix, c.NumBuckets = "rgwkv", 10
	if got := c.BucketRange(); got != "rgwkv-0..9" {
		t.Fatal(got)
	}
	c.NumBuckets = 1
	if got := c.BucketRange(); got != "rgwkv-0" {
		t.Fatal(got)
	}
	c.NumBuckets = 10
	want := "run-put-object-overwrite-versioned will ENABLE versioning on buckets rgwkv-0..9. " +
		"Versioning cannot be switched back off, and old versions are not reclaimed. " +
		"You will not be able to run run-put-object-overwrite (non-versioned) again for this key-set. " +
		"Continue? [y/N] "
	if got := c.VersionedOverwritePrompt(); got != want {
		t.Fatalf("prompt:\n%q\nwant:\n%q", got, want)
	}
}

func TestFdbSampleIntervalMustCoverStatusCall(t *testing.T) {
	c := Defaults()
	c.NumObjects, c.NumBuckets = 1, 1
	if err := c.Validate("load"); err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
	// 20s timeout => 22s outer limit: a 5s interval is rejected, 30s is fine.
	c.FdbStatusTimeoutMs = 20000
	if got := c.FdbStatusOuterLimit(); got != 22*time.Second {
		t.Fatalf("outer limit %s", got)
	}
	if err := c.Validate("load"); err == nil || !strings.Contains(err.Error(), "fdb_sample_interval_ms") {
		t.Fatalf("want interval error, got %v", err)
	}
	c.FdbSampleIntervalMs = 30000
	if err := c.Validate("load"); err != nil {
		t.Fatal(err)
	}
	// Not enforced when FDB stats are off; non-positive values are always rejected when on.
	c.FdbSampleIntervalMs = 0
	if err := c.Validate("load"); err == nil {
		t.Fatal("zero interval must be rejected")
	}
	c.FdbStats = false
	if err := c.Validate("load"); err != nil {
		t.Fatalf("fdb_stats off: %v", err)
	}
	// Sub-second timeouts round up to a whole second (fdbcli takes whole seconds).
	c.FdbStatusTimeoutMs = 1500
	if got := c.FdbStatusTimeout(); got != 2*time.Second {
		t.Fatalf("timeout %s", got)
	}
}

func TestListDeleteMulti(t *testing.T) {
	c := Defaults()
	c.NumObjects, c.NumBuckets, c.Duration = 100, 4, "1m"
	if !IsCommand("run-list-delete-multi") {
		t.Fatal("run-list-delete-multi must be a command")
	}
	if err := c.Validate("run-list-delete-multi"); err != nil {
		t.Fatal(err)
	}
	c.PaddingBytes = 1
	if err := c.Validate("run-list-delete-multi"); err == nil || !strings.Contains(err.Error(), "padding_bytes") {
		t.Fatalf("want padding error, got %v", err)
	}
	c.PaddingBytes, c.WorkerCount = 16, 8
	if w := c.ApplyCommandRules("run-list-delete-multi"); len(w) != 1 || c.WorkerCount != 4 {
		t.Fatalf("worker cap: %v %d", w, c.WorkerCount)
	}
	c.SingleThreadMode = true
	c.ApplyCommandRules("run-list-delete-multi")
	if c.WorkerCount != 1 || c.ThreadsPerWorker != 1 {
		t.Fatal("single thread mode")
	}
}

func TestFdbStatusRawDefaultsOnAndCanBeDisabled(t *testing.T) {
	c := Defaults()
	if !c.FdbStatusRaw {
		t.Fatal("fdb_status_raw must default to true")
	}
	if err := Set(&c, "fdb_status_raw", "false"); err != nil || c.FdbStatusRaw {
		t.Fatalf("set false: %v %v", err, c.FdbStatusRaw)
	}
	o := NewOverrides()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	o.Register(fs)
	if err := fs.Parse([]string{"--fdb-status-raw=true"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Apply(&c); err != nil || !c.FdbStatusRaw {
		t.Fatalf("flag: %v %v", err, c.FdbStatusRaw)
	}
}
