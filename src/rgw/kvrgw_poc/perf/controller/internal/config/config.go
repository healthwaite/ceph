// Package config loads the perf harness config (base <- command section <- CLI flags).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// FdbStatusMargin is added to the fdbcli timeout to get the outer limit after which the fdbcli
// process is killed. It lets fdbcli time out and report by itself first.
const FdbStatusMargin = 2 * time.Second

// FdbStatusTimeout is the `--timeout` given to fdbcli: fdb_status_timeout_ms rounded up to whole
// seconds (fdbcli takes whole seconds).
func (c *Config) FdbStatusTimeout() time.Duration {
	secs := (c.FdbStatusTimeoutMs + 999) / 1000
	if secs < 1 {
		secs = 1
	}
	return time.Duration(secs) * time.Second
}

// FdbStatusOuterLimit is the longest a status call can take before the process is killed.
func (c *Config) FdbStatusOuterLimit() time.Duration { return c.FdbStatusTimeout() + FdbStatusMargin }

// Commands lists the valid operation commands (report is handled separately).
var Commands = []string{
	"load", "run-put-object", "run-list-objects", "run-put-object-overwrite",
	"run-put-object-overwrite-versioned", "run-list-delete-multi", "run-delete-multi", "run-get-object",
}

func IsCommand(c string) bool {
	for _, x := range Commands {
		if x == c {
			return true
		}
	}
	return false
}

// Config is the fully resolved configuration. yaml keys == CLI flag names (snake_case).
type Config struct {
	NumObjects       uint64 `yaml:"num_objects" json:"num_objects"`
	NumBuckets       uint64 `yaml:"num_buckets" json:"num_buckets"`
	BucketNamePrefix string `yaml:"bucket_name_prefix" json:"bucket_name_prefix"`
	PaddingBytes     int    `yaml:"padding_bytes" json:"padding_bytes"`
	ObjectSizeBytes  uint64 `yaml:"object_size_bytes" json:"object_size_bytes"`
	// MetadataCount user-metadata items (x-amz-meta-*) of MetadataSize bytes each are attached to
	// every object written by load and the put runs. 0 disables.
	MetadataCount    int `yaml:"metadata_count" json:"metadata_count"`
	MetadataSize     int `yaml:"metadata_size" json:"metadata_size"`
	WorkerCount      int `yaml:"worker_count" json:"worker_count"`
	ThreadsPerWorker int `yaml:"threads_per_worker" json:"threads_per_worker"`
	// DriverMode is the worker's client model: "sync" (one blocking thread per stream,
	// calling the sync API) or "async" (streams are coroutines on DriverThreads executors
	// calling the _a ops).
	DriverMode string `yaml:"driver_mode" json:"driver_mode"`
	// StreamsPerWorker is the closed-loop concurrency per worker; 0 means ThreadsPerWorker.
	StreamsPerWorker int `yaml:"streams_per_worker" json:"streams_per_worker"`
	DriverThreads    int `yaml:"driver_threads" json:"driver_threads"`
	// RateOpsPerSec > 0 switches the run-* command to open loop at this per-worker rate
	// (async mode only); latency is measured from each op's scheduled send time.
	RateOpsPerSec float64 `yaml:"rate_ops_per_sec" json:"rate_ops_per_sec"`
	// Arrival is the open-loop inter-arrival distribution: "constant" or "poisson".
	Arrival string `yaml:"arrival" json:"arrival"`

	// Ramp (--ramp, run-put-* only): an open-loop run whose target steps up linearly
	// (cluster totals) until a step fails its criteria; see perf/RAMP.md.
	Ramp bool `yaml:"ramp" json:"ramp"`
	// RampMode: "sla" judges steps on latency, misses, errors, backlog and throughput;
	// "throughput" only on throughput (and errors): it ramps until a step completes
	// less than ramp_min_achieved_pct of its target.
	RampMode                string  `yaml:"ramp_mode" json:"ramp_mode"`
	RampStartRate           float64 `yaml:"ramp_start_rate" json:"ramp_start_rate"`
	RampStepRate            float64 `yaml:"ramp_step_rate" json:"ramp_step_rate"` // 0 = ramp_start_rate
	RampMaxRate             float64 `yaml:"ramp_max_rate" json:"ramp_max_rate"`   // 0 = none
	RampWarmup              string  `yaml:"ramp_warmup" json:"ramp_warmup"`
	RampMeasure             string  `yaml:"ramp_measure" json:"ramp_measure"`
	RampMaxP99Ms            float64 `yaml:"ramp_max_p99_ms" json:"ramp_max_p99_ms"`
	RampMaxMissedPct        float64 `yaml:"ramp_max_missed_pct" json:"ramp_max_missed_pct"`
	RampMaxErrorPct         float64 `yaml:"ramp_max_error_pct" json:"ramp_max_error_pct"`
	RampMinAchievedPct      float64 `yaml:"ramp_min_achieved_pct" json:"ramp_min_achieved_pct"`
	RampMaxBacklogGrowthPct float64 `yaml:"ramp_max_backlog_growth_pct" json:"ramp_max_backlog_growth_pct"`
	VerifyThreads           int     `yaml:"verify_threads" json:"verify_threads"`
	TenantName              string  `yaml:"tenant_name" json:"tenant_name"`
	ReportIntervalMs        int64   `yaml:"report_interval_ms" json:"report_interval_ms"`

	FdbStats bool `yaml:"fdb_stats" json:"fdb_stats"`
	// FdbStatusRaw also saves every `status json` sample, compacted, to fdb_status.jsonl
	// (tagged with the run phase). Only applies when fdb_stats is on.
	FdbStatusRaw        bool   `yaml:"fdb_status_raw" json:"fdb_status_raw"`
	FdbClusterFile      string `yaml:"fdb_cluster_file" json:"fdb_cluster_file"`
	FdbcliPath          string `yaml:"fdbcli_path" json:"fdbcli_path"`
	FdbSampleIntervalMs int64  `yaml:"fdb_sample_interval_ms" json:"fdb_sample_interval_ms"`
	// FdbStatusTimeoutMs is the timeout given to `fdbcli --exec "status json"` (rounded up to
	// whole seconds); on a heavily loaded cluster the call can take many seconds.
	FdbStatusTimeoutMs  int64 `yaml:"fdb_status_timeout_ms" json:"fdb_status_timeout_ms"`
	CpuSampleIntervalMs int64 `yaml:"cpu_sample_interval_ms" json:"cpu_sample_interval_ms"`

	// run-* only
	Ops      uint64 `yaml:"ops" json:"ops,omitempty"`
	Duration string `yaml:"duration" json:"duration,omitempty"`

	PageSize         int  `yaml:"page_size" json:"page_size"`
	SingleThreadMode bool `yaml:"single_thread_mode" json:"single_thread_mode"`
	// NumObjectsToOverwrite (run-put-object-overwrite-versioned only) is the total number of
	// keys overwritten, shared evenly across all workers * threads.
	NumObjectsToOverwrite uint64 `yaml:"num_objects_to_overwrite" json:"num_objects_to_overwrite"`

	// Force (load only): proceed even if some target buckets already exist. Existing buckets
	// and objects are kept; load puts its keys into them (new versions of existing keys).
	Force bool `yaml:"force" json:"force"`

	// Kvrgw is the runtime (kvrgw.yaml) configuration; it comes from the top-level `kvrgw:`
	// section of the file, not from base/command sections.
	Kvrgw KvrgwConfig `yaml:"-" json:"kvrgw"`
}

// KvrgwConfig mirrors the `tier:` block of backend/kvrgw.yaml, plus the async runtime
// knobs (exported as KVRGW_* environment variables by KvrgwEnv).
type KvrgwConfig struct {
	MaxInline         uint32 `yaml:"max_inline" json:"max_inline"`
	MaxKvStore        uint32 `yaml:"max_kv_store" json:"max_kv_store"`
	KvStoreCoalescing bool   `yaml:"kv_store_coalescing" json:"kv_store_coalescing"`
	BatchSize         int    `yaml:"batch_size" json:"batch_size"`
	BatchTimeoutUs    int    `yaml:"batch_timeout_us" json:"batch_timeout_us"`
	// BatchThreads is deprecated (backend_workers replaces it). When set and
	// backend_workers is not, it is exported as KVRGW_BATCH_THREADS, which the runtime reads
	// as backend_workers with a warning.
	BatchThreads        int   `yaml:"batch_threads,omitempty" json:"batch_threads,omitempty"`
	BackendWorkers      int   `yaml:"backend_workers" json:"backend_workers"`
	MaxInflightOps      int64 `yaml:"max_inflight_ops" json:"max_inflight_ops"`
	TxnMaxAttempts      int   `yaml:"txn_max_attempts" json:"txn_max_attempts"`
	BatchTxnMaxAttempts int   `yaml:"batch_txn_max_attempts" json:"batch_txn_max_attempts"`
	TxnTimeoutMs        int64 `yaml:"txn_timeout_ms" json:"txn_timeout_ms"`
	// Simulated data-tier latency (microseconds per data-store write / read). The perf
	// worker's data store keeps no bytes; these sleeps are its only cost. 0 = none.
	SimDiskWriteUs int64 `yaml:"sim_disk_write_us" json:"sim_disk_write_us"`
	SimDiskReadUs  int64 `yaml:"sim_disk_read_us" json:"sim_disk_read_us"`
}

// WriteKvrgwYAML synthesizes the runtime config file the workers read via
// KVRGW_CONFIG_FILE. (The runtime's loader only honours the first three keys; the
// batch_* values take effect through the KVRGW_BATCH_* variables from KvrgwEnv.)
func (c *Config) WriteKvrgwYAML(path string) error {
	b, err := yaml.Marshal(struct {
		Tier KvrgwConfig `yaml:"tier"`
	}{c.Kvrgw})
	if err != nil {
		return err
	}
	hdr := "# Generated by kvrgw-perf from the `kvrgw:` section of the harness config.\n"
	return os.WriteFile(path, append([]byte(hdr), b...), 0o644)
}

// KvrgwEnv returns the environment overrides that make the batch and async runtime
// settings effective (the yaml loader reads only the tier keys).
func (c *Config) KvrgwEnv() []string {
	k := c.Kvrgw
	env := []string{
		fmt.Sprintf("KVRGW_BATCH_SIZE=%d", k.BatchSize),
		fmt.Sprintf("KVRGW_BATCH_TIMEOUT_US=%d", k.BatchTimeoutUs),
	}
	switch {
	case k.BackendWorkers > 0:
		env = append(env, fmt.Sprintf("KVRGW_BACKEND_WORKERS=%d", k.BackendWorkers))
	case k.BatchThreads > 0:
		env = append(env, fmt.Sprintf("KVRGW_BATCH_THREADS=%d", k.BatchThreads))
	}
	if k.MaxInflightOps > 0 {
		env = append(env, fmt.Sprintf("KVRGW_MAX_INFLIGHT_OPS=%d", k.MaxInflightOps))
	}
	if k.TxnMaxAttempts > 0 {
		env = append(env, fmt.Sprintf("KVRGW_TXN_MAX_ATTEMPTS=%d", k.TxnMaxAttempts))
	}
	if k.BatchTxnMaxAttempts > 0 {
		env = append(env, fmt.Sprintf("KVRGW_BATCH_TXN_MAX_ATTEMPTS=%d", k.BatchTxnMaxAttempts))
	}
	env = append(env, fmt.Sprintf("KVRGW_TXN_TIMEOUT_MS=%d", k.TxnTimeoutMs))
	if k.SimDiskWriteUs > 0 {
		env = append(env, fmt.Sprintf("KVRGW_SIM_DISK_WRITE_US=%d", k.SimDiskWriteUs))
	}
	if k.SimDiskReadUs > 0 {
		env = append(env, fmt.Sprintf("KVRGW_SIM_DISK_READ_US=%d", k.SimDiskReadUs))
	}
	return env
}

// Streams is the effective closed-loop concurrency per worker (streams_per_worker, or
// threads_per_worker when that is 0).
func (c *Config) Streams() int {
	if c.StreamsPerWorker > 0 {
		return c.StreamsPerWorker
	}
	return c.ThreadsPerWorker
}

// OpenLoop reports a fixed-rate run (rate_ops_per_sec > 0).
func (c *Config) OpenLoop() bool { return c.RateOpsPerSec > 0 }

// Generators is the number of key-space generators per worker: the streams in closed
// loop, one per driver thread in open loop. RunSummary.thread_counts has one entry per
// generator, and global stream ids run over WorkerCount * Generators().
func (c *Config) Generators() int {
	if c.OpenLoop() {
		return c.DriverThreads
	}
	return c.Streams()
}

// ConcurrencyLabel describes the client model, e.g. "4 x 128 streams (sync)".
func (c *Config) ConcurrencyLabel() string {
	if c.DriverMode == "async" {
		s := fmt.Sprintf("%d workers x %d streams on %d driver threads (async)", c.WorkerCount, c.Streams(), c.DriverThreads)
		if c.OpenLoop() {
			s = fmt.Sprintf("%d workers x %d driver threads, open loop at %g ops/s per worker (async)",
				c.WorkerCount, c.DriverThreads, c.RateOpsPerSec)
		}
		return s
	}
	return fmt.Sprintf("%d workers x %d streams (sync: one thread each)", c.WorkerCount, c.Streams())
}

// RampCommands are the commands that support --ramp.
var RampCommands = []string{"run-put-object", "run-put-object-overwrite", "run-put-object-overwrite-versioned"}

// RampThroughputOnly reports ramp_mode throughput (latency, misses and backlog are
// not failure criteria).
func (c *Config) RampThroughputOnly() bool { return c.RampMode == "throughput" }

// RampMinAchieved is ramp_min_achieved_pct, or its mode default when 0: 99% for
// sla, 98% for throughput.
func (c *Config) RampMinAchieved() float64 {
	if c.RampMinAchievedPct > 0 {
		return c.RampMinAchievedPct
	}
	if c.RampThroughputOnly() {
		return 98
	}
	return 99
}

// InflightCap is the most async ops the cluster can have in flight: in open loop
// each driver may have max_inflight_ops / driver_threads outstanding, in closed loop
// each worker has at most min(streams, max_inflight_ops) (beyond it, QUEUE_FULL).
// 0 for sync mode or when max_inflight_ops is unknown.
func (c *Config) InflightCap() int64 {
	if c.DriverMode != "async" || c.Kvrgw.MaxInflightOps <= 0 {
		return 0
	}
	per := c.Kvrgw.MaxInflightOps
	if c.OpenLoop() {
		g := c.Kvrgw.MaxInflightOps / int64(c.DriverThreads)
		if g < 1 {
			g = 1
		}
		per = g * int64(c.DriverThreads)
	} else if s := int64(c.Streams()); s < per {
		per = s
	}
	return per * int64(c.WorkerCount)
}

// RampStep returns the per-step increment (cluster total, ops/s).
func (c *Config) RampStep() float64 {
	if c.RampStepRate > 0 {
		return c.RampStepRate
	}
	return c.RampStartRate
}

// RampRate returns step i's target (cluster total, ops/s).
func (c *Config) RampRate(i int) float64 { return c.RampStartRate + float64(i)*c.RampStep() }

// RampDurations parses ramp_warmup and ramp_measure.
func (c *Config) RampDurations() (warmup, measure time.Duration, err error) {
	if warmup, err = time.ParseDuration(c.RampWarmup); err != nil {
		return 0, 0, fmt.Errorf("ramp_warmup: %w", err)
	}
	if measure, err = time.ParseDuration(c.RampMeasure); err != nil {
		return 0, 0, fmt.Errorf("ramp_measure: %w", err)
	}
	return warmup, measure, nil
}

// validateRamp checks the --ramp settings.
func (c *Config) validateRamp(command string) error {
	ok := false
	for _, x := range RampCommands {
		ok = ok || x == command
	}
	if !ok {
		return fmt.Errorf("--ramp is supported for %v, not %s", RampCommands, command)
	}
	if c.RateOpsPerSec > 0 {
		return fmt.Errorf("--ramp sets the rate itself; drop rate_ops_per_sec")
	}
	if c.Ops != 0 {
		return fmt.Errorf("--ramp runs until a step fails; ops is not allowed")
	}
	if c.RampMode != "sla" && c.RampMode != "throughput" {
		return fmt.Errorf("ramp_mode must be sla or throughput, not %q", c.RampMode)
	}
	if c.RampStartRate <= 0 {
		return fmt.Errorf("--ramp needs ramp_start_rate > 0 (ops/s, cluster total)")
	}
	if c.RampStepRate < 0 || c.RampMaxRate < 0 {
		return fmt.Errorf("ramp_step_rate and ramp_max_rate must be >= 0")
	}
	if c.RampMaxRate > 0 && c.RampMaxRate < c.RampStartRate {
		return fmt.Errorf("ramp_max_rate (%g) is below ramp_start_rate (%g)", c.RampMaxRate, c.RampStartRate)
	}
	w, m, err := c.RampDurations()
	if err != nil {
		return err
	}
	if w < 0 || m <= 0 {
		return fmt.Errorf("ramp_warmup must be >= 0 and ramp_measure > 0")
	}
	if c.ReportIntervalMs <= 0 {
		return fmt.Errorf("--ramp needs report_interval_ms > 0 (steps are whole report windows)")
	}
	if c.RampMaxP99Ms <= 0 || c.RampMaxMissedPct < 0 || c.RampMaxErrorPct < 0 ||
		c.RampMinAchievedPct < 0 || c.RampMinAchievedPct > 100 || c.RampMaxBacklogGrowthPct < 0 {
		return fmt.Errorf("ramp criteria out of range (max_p99_ms > 0, pcts >= 0, min_achieved_pct in [0,100])")
	}
	return nil
}

// OpenLoopCommands are the commands that support rate_ops_per_sec.
var OpenLoopCommands = []string{"run-put-object", "run-put-object-overwrite",
	"run-put-object-overwrite-versioned", "run-delete-multi"}

// Defaults returns the built-in defaults. perf/kvrgw-perf.yaml lists the same values
// explicitly (a test keeps the two in sync).
func Defaults() Config {
	return Config{
		NumObjects: 1000000, NumBuckets: 10, BucketNamePrefix: "rgwkv",
		PaddingBytes: 16, ObjectSizeBytes: 8192, MetadataCount: 6, MetadataSize: 64, WorkerCount: 1, ThreadsPerWorker: 1,
		DriverMode: "sync", StreamsPerWorker: 0, DriverThreads: 2, RateOpsPerSec: 0, Arrival: "constant",
		RampWarmup: "30s", RampMeasure: "60s", RampMaxP99Ms: 50, RampMaxMissedPct: 0.1,
		RampMaxErrorPct: 0.1, RampMinAchievedPct: 0, RampMaxBacklogGrowthPct: 50, RampMode: "sla",
		VerifyThreads: 4, TenantName: envOr("KVRGW_TENANT_NAME", "kv-poc"),
		ReportIntervalMs: 1000,
		FdbStats:         true, FdbStatusRaw: true, FdbClusterFile: os.Getenv("FDB_CLUSTER_FILE"), FdbcliPath: "/opt/foundationdb/usr/bin/fdbcli",
		FdbSampleIntervalMs: 5000, FdbStatusTimeoutMs: 3000, CpuSampleIntervalMs: 1000,
		PageSize: 1000,
		Kvrgw: KvrgwConfig{MaxInline: 256, MaxKvStore: 4096, BatchSize: 5, BatchTimeoutUs: 1000,
			BackendWorkers: 4, MaxInflightOps: 4096, TxnMaxAttempts: 3, BatchTxnMaxAttempts: 10},
	}
}

// resolveFdbcli finds the fdbcli binary: the configured path if it exists, else PATH, else
// the usual container locations (next to this executable, /opt/kvrgw, /opt/foundationdb).
func resolveFdbcli(p string) string {
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if lp, err := exec.LookPath(p); err == nil {
		return lp
	}
	cands := []string{"/opt/kvrgw/fdbcli", "/opt/foundationdb/usr/bin/fdbcli"}
	if exe, err := os.Executable(); err == nil {
		cands = append([]string{filepath.Join(filepath.Dir(exe), "fdbcli")}, cands...)
	}
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return p
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// sectionNames are the allowed top-level keys of the file.
var sectionNames = append([]string{"kvrgw", "base"}, Commands...)

// File is the parsed config file: raw per-section YAML.
type File struct {
	sections map[string][]byte
}

// LoadFile parses YAML/JSON; unknown section names and unknown keys are errors.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseFile(data)
}

func ParseFile(data []byte) (*File, error) {
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	f := &File{sections: map[string][]byte{}}
	for k, n := range raw {
		ok := false
		for _, s := range sectionNames {
			if s == k {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("config: unknown section %q (valid: base, %v)", k, Commands)
		}
		if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
			continue
		}
		b, err := yaml.Marshal(&n)
		if err != nil {
			return nil, err
		}
		f.sections[k] = b
	}
	return f, nil
}

func decodeStrict(b []byte, into *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil && err.Error() != "EOF" {
		return err
	}
	return nil
}

// Resolve = defaults <- base <- command section. (CLI overrides are applied by the caller
// with Set.) f may be nil.
func Resolve(f *File, command string) (Config, error) {
	cfg := Defaults()
	if f != nil {
		if b, ok := f.sections["kvrgw"]; ok {
			dec := yaml.NewDecoder(bytes.NewReader(b))
			dec.KnownFields(true)
			if err := dec.Decode(&cfg.Kvrgw); err != nil && err.Error() != "EOF" {
				return cfg, fmt.Errorf("config section \"kvrgw\": %w", err)
			}
		}
		for _, sec := range []string{"base", command} {
			if b, ok := f.sections[sec]; ok {
				if err := decodeStrict(b, &cfg); err != nil {
					return cfg, fmt.Errorf("config section %q: %w", sec, err)
				}
			}
		}
	}
	if cfg.FdbClusterFile == "" {
		cfg.FdbClusterFile = os.Getenv("FDB_CLUSTER_FILE")
	}
	cfg.FdbcliPath = resolveFdbcli(cfg.FdbcliPath)
	return cfg, nil
}

// DurationValue parses cfg.Duration (Go duration syntax); 0 if unset.
func (c *Config) DurationValue() (time.Duration, error) {
	if c.Duration == "" {
		return 0, nil
	}
	return time.ParseDuration(c.Duration)
}

// Validate checks everything that can be checked before workers are started.
func (c *Config) Validate(command string) error {
	if c.NumObjects == 0 {
		return fmt.Errorf("num_objects must be > 0")
	}
	if c.NumBuckets == 0 {
		return fmt.Errorf("num_buckets must be > 0")
	}
	if c.WorkerCount < 1 || c.ThreadsPerWorker < 1 {
		return fmt.Errorf("worker_count and threads_per_worker must be >= 1")
	}
	if c.StreamsPerWorker < 0 {
		return fmt.Errorf("streams_per_worker must be >= 0 (0 = threads_per_worker)")
	}
	if c.Arrival != "constant" && c.Arrival != "poisson" {
		return fmt.Errorf("arrival must be constant or poisson, not %q", c.Arrival)
	}
	if c.Ramp {
		if err := c.validateRamp(command); err != nil {
			return err
		}
	}
	if c.DriverMode != "sync" && c.DriverMode != "async" {
		return fmt.Errorf("driver_mode must be sync or async, not %q", c.DriverMode)
	}
	if c.DriverThreads < 1 {
		return fmt.Errorf("driver_threads must be >= 1")
	}
	if c.RateOpsPerSec < 0 {
		return fmt.Errorf("rate_ops_per_sec must be >= 0")
	}
	if c.OpenLoop() && !c.Ramp {
		if c.DriverMode != "async" {
			return fmt.Errorf("rate_ops_per_sec (open loop) requires driver_mode: async")
		}
		ok := false
		for _, x := range OpenLoopCommands {
			ok = ok || x == command
		}
		if !ok {
			return fmt.Errorf("open loop (rate_ops_per_sec) is not supported for %s (supported: %v)", command, OpenLoopCommands)
		}
	}
	if c.WorkerCount*c.Generators() > 65536 {
		return fmt.Errorf("worker_count * streams_per_worker must be <= 65536")
	}
	if c.VerifyThreads < 1 {
		return fmt.Errorf("verify_threads must be >= 1")
	}
	if c.MetadataCount < 0 || c.MetadataCount > 160 {
		return fmt.Errorf("metadata_count must be in 0..160")
	}
	if c.MetadataCount > 0 && (c.MetadataSize < 1 || c.MetadataSize > 2048) {
		return fmt.Errorf("metadata_size must be in 1..2048 when metadata_count > 0")
	}
	if c.PaddingBytes < 0 || c.PaddingBytes > 700 {
		return fmt.Errorf("padding_bytes out of range")
	}
	if c.PageSize < 1 {
		return fmt.Errorf("page_size must be >= 1")
	}
	if c.ReportIntervalMs < 0 {
		return fmt.Errorf("report_interval_ms must be >= 0")
	}
	if c.CpuSampleIntervalMs < 1 {
		return fmt.Errorf("cpu_sample_interval_ms must be >= 1")
	}
	if c.FdbStats {
		if c.FdbStatusTimeoutMs < 1 {
			return fmt.Errorf("fdb_status_timeout_ms must be >= 1")
		}
		if c.FdbSampleIntervalMs < 1 {
			return fmt.Errorf("fdb_sample_interval_ms must be >= 1")
		}
		// Sampling is sequential: an interval shorter than the longest a status call may take
		// would make the sampler call back to back.
		if iv, lim := time.Duration(c.FdbSampleIntervalMs)*time.Millisecond, c.FdbStatusOuterLimit(); iv < lim {
			return fmt.Errorf("fdb_sample_interval_ms (%s) must be >= the longest a status call may take, %s "+
				"(fdb_status_timeout_ms %d rounded up to whole seconds, plus %s); raise the interval or lower the timeout",
				iv, lim, c.FdbStatusTimeoutMs, FdbStatusMargin)
		}
	}
	d, err := c.DurationValue()
	if err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	if d < 0 {
		return fmt.Errorf("duration must be positive")
	}
	if command == "load" {
		if c.Ops != 0 || d != 0 {
			return fmt.Errorf("ops/duration are not valid for load")
		}
	} else if !c.Ramp {
		if (c.Ops != 0) == (d != 0) {
			return fmt.Errorf("%s requires exactly one of --ops or --duration", command)
		}
	}
	if command == "run-list-delete-multi" && c.PaddingBytes < 2 {
		return fmt.Errorf("run-list-delete-multi splits on the first 2 key characters and needs padding_bytes >= 2")
	}
	if c.Force && command != "load" {
		return fmt.Errorf("--force only applies to load")
	}
	if command == "run-put-object-overwrite-versioned" {
		if c.NumObjectsToOverwrite == 0 {
			return fmt.Errorf("%s requires num_objects_to_overwrite > 0", command)
		}
		if c.NumObjectsToOverwrite > c.NumObjects {
			return fmt.Errorf("num_objects_to_overwrite (%d) must be <= num_objects (%d)", c.NumObjectsToOverwrite, c.NumObjects)
		}
	} else if c.NumObjectsToOverwrite != 0 {
		return fmt.Errorf("num_objects_to_overwrite only applies to run-put-object-overwrite-versioned (run-put-object-overwrite overwrites every key)")
	}
	return nil
}

// BucketRange names the target buckets compactly, e.g. "rgwkv-0..9" (or "rgwkv-0" for one).
func (c *Config) BucketRange() string {
	if c.NumBuckets <= 1 {
		return fmt.Sprintf("%s-0", c.BucketNamePrefix)
	}
	return fmt.Sprintf("%s-0..%d", c.BucketNamePrefix, c.NumBuckets-1)
}

// VersionedOverwritePrompt is the confirmation shown before run-put-object-overwrite-versioned,
// which enables versioning on the buckets.
func (c *Config) VersionedOverwritePrompt() string {
	return fmt.Sprintf("run-put-object-overwrite-versioned will ENABLE versioning on buckets %s. "+
		"Versioning cannot be switched back off, and old versions are not reclaimed. "+
		"You will not be able to run run-put-object-overwrite (non-versioned) again for this key-set. "+
		"Continue? [y/N] ", c.BucketRange())
}

// ApplyCommandRules adjusts the config for command-specific semantics. It returns
// human-readable warnings.
func (c *Config) ApplyCommandRules(command string) (warnings []string) {
	if c.Ramp {
		// A ramp is an open-loop async run; the first step's rate is split evenly
		// across the workers, later steps arrive as RunControl.set_rate.
		if c.DriverMode != "async" {
			warnings = append(warnings, "--ramp runs in driver_mode async")
		}
		c.DriverMode = "async"
		c.RateOpsPerSec = c.RampStartRate / float64(c.WorkerCount)
		// The ramp runs until a step fails (or ramp_max_rate); duration, often
		// set per command in the config file, does not apply.
		if c.Duration != "" {
			warnings = append(warnings, fmt.Sprintf("--ramp ignores duration (%s)", c.Duration))
			c.Duration = ""
		}
	}
	switch command {
	case "run-list-objects", "run-list-delete-multi":
		if c.SingleThreadMode {
			c.WorkerCount, c.ThreadsPerWorker, c.StreamsPerWorker = 1, 1, 1
		} else if uint64(c.WorkerCount) > c.NumBuckets {
			warnings = append(warnings, fmt.Sprintf(
				"num_buckets (%d) < worker_count (%d): capping worker_count at %d so every worker owns a bucket",
				c.NumBuckets, c.WorkerCount, c.NumBuckets))
			c.WorkerCount = int(c.NumBuckets)
		}
	case "run-delete-multi":
		if c.SingleThreadMode {
			c.WorkerCount, c.ThreadsPerWorker, c.StreamsPerWorker = 1, 1, 1
		}
	}
	return
}

// workerJSON is what workers receive (no collector keys).
type workerJSON struct {
	NumObjects            uint64  `json:"num_objects"`
	NumBuckets            uint64  `json:"num_buckets"`
	BucketNamePrefix      string  `json:"bucket_name_prefix"`
	PaddingBytes          int     `json:"padding_bytes"`
	ObjectSizeBytes       uint64  `json:"object_size_bytes"`
	MetadataCount         int     `json:"metadata_count"`
	MetadataSize          int     `json:"metadata_size"`
	ThreadsPerWorker      int     `json:"threads_per_worker"`
	DriverMode            string  `json:"driver_mode"`
	StreamsPerWorker      int     `json:"streams_per_worker"`
	DriverThreads         int     `json:"driver_threads"`
	RateOpsPerSec         float64 `json:"rate_ops_per_sec"`
	Arrival               string  `json:"arrival"`
	Ramp                  bool    `json:"ramp,omitempty"`
	VerifyThreads         int     `json:"verify_threads"`
	TenantName            string  `json:"tenant_name"`
	ReportIntervalMs      int64   `json:"report_interval_ms"`
	Ops                   uint64  `json:"ops,omitempty"`
	DurationMs            int64   `json:"duration_ms,omitempty"`
	PageSize              int     `json:"page_size"`
	SingleThreadMode      bool    `json:"single_thread_mode"`
	NumObjectsToOverwrite uint64  `json:"num_objects_to_overwrite"`
	Force                 bool    `json:"force"`
}

// WorkerJSON renders the config sent in InitRequest.config_json.
func (c *Config) WorkerJSON() ([]byte, error) {
	d, err := c.DurationValue()
	if err != nil {
		return nil, err
	}
	return json.Marshal(workerJSON{
		c.NumObjects, c.NumBuckets, c.BucketNamePrefix, c.PaddingBytes, c.ObjectSizeBytes, c.MetadataCount, c.MetadataSize,
		c.ThreadsPerWorker, c.DriverMode, c.Streams(), c.DriverThreads, c.RateOpsPerSec, c.Arrival, c.Ramp,
		c.VerifyThreads, c.TenantName,
		c.ReportIntervalMs, c.Ops, d.Milliseconds(), c.PageSize,
		c.SingleThreadMode, c.NumObjectsToOverwrite, c.Force,
	})
}

// ResolvedJSON is the pretty full config written to config.resolved.json.
func (c *Config) ResolvedJSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
