package results

import (
	"encoding/json"
	"os"

	"kvrgw-perf/internal/config"
)

// OpTotals are whole-benchmark totals for one op type.
type OpTotals struct {
	Count     uint64  `json:"count"`
	Errors    uint64  `json:"errors"`
	OpsPerSec float64 `json:"ops_per_sec"`
	MeanUs    float64 `json:"mean_us,omitempty"`
	P50Us     uint64  `json:"p50_us,omitempty"`
	P90Us     uint64  `json:"p90_us,omitempty"`
	P99Us     uint64  `json:"p99_us,omitempty"`
	P999Us    uint64  `json:"p999_us,omitempty"`
	MaxUs     uint64  `json:"max_us,omitempty"`
	// ErrorCodes breaks Errors down by library error code name.
	ErrorCodes map[string]uint64 `json:"error_codes,omitempty"`
}

type WorkerSummary struct {
	WorkerIndex  int      `json:"worker_index"`
	ThreadCounts []uint64 `json:"thread_counts,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type BucketVerify struct {
	Bucket      string   `json:"bucket"`
	Expected    uint64   `json:"expected"`
	Found       uint64   `json:"found"`
	Missing     uint64   `json:"missing"`
	MissingKeys []string `json:"missing_keys,omitempty"`
}

type VerifySummary struct {
	Ran           bool           `json:"ran"`
	Pass          bool           `json:"pass"`
	DurationMs    int64          `json:"duration_ms"`
	Buckets       []BucketVerify `json:"buckets,omitempty"`
	KeysChecked   uint64         `json:"keys_checked"`
	Missing       uint64         `json:"missing"`
	BadKey        uint64         `json:"bad_key"`
	OutOfRange    uint64         `json:"out_of_range"`
	Unexpected    uint64         `json:"unexpected"`
	Duplicate     uint64         `json:"duplicate"`
	OtherFailures uint64         `json:"other_failures"`
	Samples       []string       `json:"samples,omitempty"`
	Errors        []string       `json:"errors,omitempty"`
}

// Summary is summary.json.
type Summary struct {
	Command       string              `json:"command"`
	BenchmarkID   string              `json:"benchmark_id"`
	Parameters    config.Config       `json:"parameters"`
	RunStartUnixS int64               `json:"run_start_unix_s"`
	Workers       []WorkerSummary     `json:"workers"`
	Totals        map[string]OpTotals `json:"totals"`
	ServerTotals  map[string]uint64   `json:"server_stats_final,omitempty"`
	Verify        *VerifySummary      `json:"verify,omitempty"`
	OpErrors      uint64              `json:"op_errors"`
	// VersionsWritten (run-put-object-overwrite-versioned only) is the number of new object
	// versions the run wrote: one per successful put. The null versions made by load come on top.
	VersionsWritten uint64 `json:"versions_written,omitempty"`
	// VersionsPerObject is VersionsWritten averaged over the num_objects_to_overwrite keys.
	VersionsPerObject float64 `json:"versions_per_object,omitempty"`
	// ErrorDescriptions maps error code names to human-readable text.
	ErrorDescriptions map[string]string `json:"error_descriptions,omitempty"`
	Failed            bool              `json:"failed"`
	Failures          []string          `json:"failures,omitempty"`
	ExitStatus        int               `json:"exit_status"`
}

func ReadSummary(path string) (*Summary, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Summary
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
