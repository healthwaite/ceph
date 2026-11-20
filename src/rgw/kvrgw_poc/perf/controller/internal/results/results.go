// Package results writes the per-invocation results directory (spec 8.1).
package results

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Dir is a results directory.
type Dir struct{ Path string }

func NewRunDir(path, command string, now time.Time) (*Dir, error) {
	if path == "" {
		path = filepath.Join("perf-results", now.UTC().Format("20060102T150405Z")+"-"+command)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &Dir{Path: abs}, nil
}

func (d *Dir) File(name string) string { return filepath.Join(d.Path, name) }

// CSV is a flushed, concurrency-safe CSV writer.
type CSV struct {
	mu sync.Mutex
	f  *os.File
	w  *csv.Writer
}

// OpenCSV creates the file and writes the header.
func (d *Dir) OpenCSV(name string, header ...string) (*CSV, error) {
	f, err := os.Create(d.File(name))
	if err != nil {
		return nil, err
	}
	c := &CSV{f: f, w: csv.NewWriter(bufio.NewWriter(f))}
	c.w.Write(header)
	c.w.Flush()
	return c, nil
}

// Row writes one row and flushes.
func (c *CSV) Row(fields ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.w.Write(fields)
	c.w.Flush()
}

func (c *CSV) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.w.Flush()
	return c.f.Close()
}

// Helpers for number formatting.
func U(v uint64) string  { return strconv.FormatUint(v, 10) }
func I(v int64) string   { return strconv.FormatInt(v, 10) }
func F(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }

// Events appends to events.csv.
type Events struct{ c *CSV }

func (d *Dir) OpenEvents() (*Events, error) {
	c, err := d.OpenCSV("events.csv", "unix_ts_ms", "event")
	if err != nil {
		return nil, err
	}
	return &Events{c}, nil
}

func (e *Events) At(ms int64, name string) { e.c.Row(I(ms), name) }
func (e *Events) Now(name string)          { e.At(time.Now().UnixMilli(), name) }
func (e *Events) Close() error             { return e.c.Close() }

// Columns of each CSV (shared with the report reader).
var (
	MetricsHeader     = []string{"unix_ts_ms", "window", "op_type", "count", "errors", "ops_per_sec", "mean_us", "p50_us", "p90_us", "p99_us", "p999_us", "max_us", "cum_count", "cum_errors"}
	ErrorsHeader      = []string{"unix_ts_ms", "window", "op_type", "error_code", "count"}
	HistHeader        = []string{"window", "op_type", "bucket_index", "count"}
	ServerStatsHeader = []string{"unix_ts_ms", "window", "name", "value"}
	CPUHeader         = []string{"unix_ts_ms", "source", "cores"}
	FDBClusterHeader  = []string{"unix_ts_ms", "txn_hz", "reads_hz", "writes_hz", "conflict_hz", "worst_queue_ss", "worst_queue_log", "limiting_queue_ss", "durability_lag_s"}
	// FDBCPUHeader: one row per process per sample (roles joined with ";"), so CPU can be summed
	// per role without double counting processes that hold several roles.
	FDBCPUHeader     = []string{"unix_ts_ms", "addr", "class", "roles", "cpu_cores"}
	FDBProcessHeader = []string{"unix_ts_ms", "addr", "role", "cpu_cores", "mem_bytes", "rss_bytes", "input_hz", "durable_hz", "stored_bytes", "kvstore_bytes", "data_lag_s", "durability_lag_s", "queue_disk_bytes", "queue_mem_bytes", "disk_busy", "disk_reads_hz", "disk_writes_hz"}
)

var _ = fmt.Sprint
