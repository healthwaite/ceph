package config

import (
	"flag"
	"fmt"
	"strconv"
)

// Overrides collects CLI flag values for config keys. Only flags actually set on the
// command line (tracked via flag.Visit) are applied.
type Overrides struct {
	vals map[string]string
}

func NewOverrides() *Overrides { return &Overrides{vals: map[string]string{}} }

// flagKeys maps flag name -> config key (snake_case keys also accepted as-is via dashes).
var flagKeys = map[string]string{
	"num-objects": "num_objects", "num-buckets": "num_buckets",
	"bucket-name-prefix": "bucket_name_prefix", "padding-bytes": "padding_bytes",
	"object-size-bytes": "object_size_bytes",
	"workers":           "worker_count", "worker-count": "worker_count",
	"threads": "threads_per_worker", "threads-per-worker": "threads_per_worker",
	"verify-threads": "verify_threads", "tenant-name": "tenant_name",
	"batch-size": "batch_size", "batch-timeout-us": "batch_timeout_us",
	"batch-threads": "batch_threads", "max-inline": "max_inline", "max-kv-store": "max_kv_store",
	"kv-store-coalescing": "kv_store_coalescing", "report-interval-ms": "report_interval_ms",
	"fdb-cluster-file": "fdb_cluster_file", "fdbcli-path": "fdbcli_path",
	"fdb-sample-interval-ms": "fdb_sample_interval_ms",
	"cpu-sample-interval-ms": "cpu_sample_interval_ms",
	"ops":                    "ops", "duration": "duration", "page-size": "page_size",
	"single-thread-mode":       "single_thread_mode",
	"num-objects-to-overwrite": "num_objects_to_overwrite",
	"force":                    "force",
}

// Register adds a string flag for every config key to fs (bool-like flags accept
// --flag=true/false). Values are recorded only when set.
func (o *Overrides) Register(fs *flag.FlagSet) {
	for name := range flagKeys {
		n := name
		if n == "single-thread-mode" || n == "force" {
			continue
		}
		fs.Func(n, "config override for "+flagKeys[n], func(v string) error {
			o.vals[flagKeys[n]] = v
			return nil
		})
	}
	// Boolean convenience flags usable without a value.
	fs.BoolFunc("single-thread-mode", "use one worker and one thread on bucket 0", func(v string) error {
		if v == "" {
			v = "true"
		}
		o.vals["single_thread_mode"] = v
		return nil
	})
	fs.BoolFunc("force", "load: proceed even if the target buckets already exist (nothing is deleted)", func(v string) error {
		if v == "" {
			v = "true"
		}
		o.vals["force"] = v
		return nil
	})
	fs.BoolFunc("no-fdb-stats", "disable FDB status sampling", func(v string) error {
		if v == "" {
			v = "true"
		}
		if v == "true" {
			o.vals["fdb_stats"] = "false"
		}
		return nil
	})
}

// Apply writes the recorded overrides into c.
func (o *Overrides) Apply(c *Config) error {
	// --ops and --duration are mutually exclusive: a CLI value replaces the other source.
	if _, ok := o.vals["ops"]; ok {
		c.Duration = ""
	}
	if _, ok := o.vals["duration"]; ok {
		c.Ops = 0
	}
	for k, v := range o.vals {
		if err := Set(c, k, v); err != nil {
			return fmt.Errorf("--%s: %w", k, err)
		}
	}
	return nil
}

// Set assigns a config key from its string form.
func Set(c *Config, key, v string) error {
	u := func(dst *uint64) error {
		x, err := strconv.ParseUint(v, 10, 64)
		*dst = x
		return err
	}
	i := func(dst *int) error {
		x, err := strconv.Atoi(v)
		*dst = x
		return err
	}
	u32 := func(dst *uint32) error {
		x, err := strconv.ParseUint(v, 10, 32)
		*dst = uint32(x)
		return err
	}
	i64 := func(dst *int64) error {
		x, err := strconv.ParseInt(v, 10, 64)
		*dst = x
		return err
	}
	b := func(dst *bool) error {
		x, err := strconv.ParseBool(v)
		*dst = x
		return err
	}
	switch key {
	case "num_objects":
		return u(&c.NumObjects)
	case "num_buckets":
		return u(&c.NumBuckets)
	case "bucket_name_prefix":
		c.BucketNamePrefix = v
	case "padding_bytes":
		return i(&c.PaddingBytes)
	case "object_size_bytes":
		return u(&c.ObjectSizeBytes)
	case "worker_count":
		return i(&c.WorkerCount)
	case "threads_per_worker":
		return i(&c.ThreadsPerWorker)
	case "verify_threads":
		return i(&c.VerifyThreads)
	case "tenant_name":
		c.TenantName = v
	case "batch_size":
		return i(&c.Kvrgw.BatchSize)
	case "batch_timeout_us":
		return i(&c.Kvrgw.BatchTimeoutUs)
	case "batch_threads":
		return i(&c.Kvrgw.BatchThreads)
	case "max_inline":
		return u32(&c.Kvrgw.MaxInline)
	case "max_kv_store":
		return u32(&c.Kvrgw.MaxKvStore)
	case "kv_store_coalescing":
		return b(&c.Kvrgw.KvStoreCoalescing)
	case "report_interval_ms":
		return i64(&c.ReportIntervalMs)
	case "fdb_stats":
		return b(&c.FdbStats)
	case "fdb_cluster_file":
		c.FdbClusterFile = v
	case "fdbcli_path":
		c.FdbcliPath = v
	case "fdb_sample_interval_ms":
		return i64(&c.FdbSampleIntervalMs)
	case "cpu_sample_interval_ms":
		return i64(&c.CpuSampleIntervalMs)
	case "ops":
		return u(&c.Ops)
	case "duration":
		c.Duration = v
	case "page_size":
		return i(&c.PageSize)
	case "single_thread_mode":
		return b(&c.SingleThreadMode)
	case "num_objects_to_overwrite":
		return u(&c.NumObjectsToOverwrite)
	case "force":
		return b(&c.Force)
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}
