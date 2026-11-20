# kvrgw perf harness — specification

Status: implemented (see README.md for build/run notes and deliberate deviations). This document is self-contained: an
implementer should not need any other context. Paths are relative to
`src/rgw/kvrgw_poc/` unless stated otherwise.

## 1. Goals and constraints

Build a new benchmark harness for kvrgw consisting of:

- **`kvrgw-perf` (controller)** — a Go program. Parses config, starts/finds
  workers, drives them through phases over gRPC, aggregates metrics, samples FDB
  cluster status and worker/system CPU, and writes timestamped CSV/JSON results
  (§8). Its `report` subcommand analyses a results directory (§8.3).
- **`kvrgw-perf-worker` (worker)** — a C++ gRPC server. Each worker process
  starts an in-process kvrgw runtime and calls the service layer directly
  (`KvRgwServiceImpl::put_object`, `list_objects`, ...), **not** via the Go
  frontend/S3 path. Similar in spirit to `backend/src/perf_driver.cpp`, but
  non-interactive and driven by the controller.

Hard constraints:

1. **Do not modify any existing implementation code.** All new code lives under
   `perf/`. The only permitted edit to an existing file is a small, optional
   block in `backend/CMakeLists.txt` (see §9). `libkvrgw` must not depend on gRPC.
2. **Opt-in build.** gRPC/protobuf are only required when the harness is enabled
   (`-DKVRGW_BUILD_PERF_HARNESS=ON`, default OFF).
3. **No references to any external/sibling benchmark project** in code, comments,
   docs, flags, binary names or commit messages. Code ported from the author's own
   earlier tooling (key generation, histograms, aggregation, local launch) is fine;
   just don't name it.
4. Everything runs in containers (Rocky 9, see `perf/Dockerfile.build`), so we control
   gRPC packaging.
5. **Standalone: the harness replaces the legacy perf tooling and does not use
   it.** `scripts/run_perf_from_def.sh`, `gen_perf_test.sh`,
   `display_perf_results.sh`, `collect_fdb_metrics.sh`, the `Perf-Test-*.txt/md`
   files and the admin-socket/`socat` collection are neither invoked nor modified.
   All metric collection and analysis is implemented in Go (no bash, Python or
   `socat` at run time). Bringing FDB up and down is the caller's responsibility;
   the harness only reads from an already-running cluster. (Deleting the legacy
   tooling is a separate decision, out of scope here.)
6. **Everything is timestamped** (Unix ms, UTC) so that analysis can select any
   time range; there is no idle/ramp-up/active/drain state machine. Warmup is
   handled at report time with `--warmup <duration>` (§8.3).
7. **Networking is out of scope for v1.** Only *local mode* is implemented: the
   controller spawns N worker processes on the same host and talks to them over
   loopback gRPC. Design the controller so that "workers at given addresses" is the
   abstraction, so remote workers can be added later without protocol changes.

## 2. Terminology

- **worker**: one `kvrgw-perf-worker` process (models one RGW instance).
  `worker_index` in `[0, worker_count)`.
- **thread**: a benchmark thread within a worker. `threads_per_worker` per worker.
  `global_thread_id = worker_index * threads_per_worker + thread_id`,
  `total_threads = worker_count * threads_per_worker`.
- **invocation**: one run of the controller binary executing one command
  (`load` or one `run-*`). Each invocation is independent; the *caller* is
  responsible for sequencing (e.g. `load` once, then several `run-*`). The harness
  stores no state between invocations and does not validate that layout config
  matches the earlier load.
- **run start time** `run_start_unix_s`: wall-clock Unix seconds sampled by the
  controller when the invocation begins. Sent to all workers in `Init`.

## 3. Repository layout

```
perf/
  SPEC.md                        # this file
  CMakeLists.txt                 # builds worker (+ proto C++ stubs); optionally invokes Go build
  proto/perf/v1/worker.proto     # shared protocol
  worker/                        # C++: kvrgw-perf-worker
    main.cpp                     # flag parsing, runtime start, gRPC server
    service.{cpp,hpp}            # Worker::Service handlers: Init/Run/Verify/Cleanup
    config.{cpp,hpp}             # parse+validate resolved config JSON (nlohmann-json)
    keys.{cpp,hpp}               # bucket names, object keys, shard math
    stats.{cpp,hpp}              # per-window + cumulative histograms
    ops/                         # one file per operation (load, put_object, ...)
    tests/                       # unit tests (keys, shard math, histogram)
  controller/                    # Go module (own go.mod), binary kvrgw-perf
    cmd/kvrgw-perf/main.go
    internal/config/             # base config + per-command overrides
    internal/local/              # spawn/stop local workers
    internal/controller/         # phase orchestration
    internal/stats/              # histogram merge, windowed aggregation, quantiles
    internal/collect/            # FDB status sampler (fdbcli), /proc CPU sampler
    internal/results/            # results-dir writers/readers (CSV, events, summary)
    internal/report/             # `report` subcommand + terminal progress
    gen/perf/v1/                 # generated Go stubs (check in)
```

Generated Go stubs are checked in (`protoc-gen-go`/`protoc-gen-go-grpc` may not be
present in the build image); document the regen command in `perf/README.md`.
C++ stubs are generated at build time by CMake.

## 4. Operations

All operations share one lifecycle (§6). Two kinds:

### 4.1 `load`

Creates `num_buckets` buckets and loads `num_objects` objects across them.

- Bucket names: `<bucket_name_prefix>-<i>` for `i` in `[0, num_buckets)`
  (default prefix `rgwkv`, e.g. `rgwkv-3`).
- Buckets are left **unversioned** (`create_bucket` only; no `put_bucket_versioning`).
  `run-put-object-overwrite` needs that; `run-put-object-overwrite-versioned` enables
  versioning itself after a confirmation.
- Bucket creation is done by **worker 0 during `Init`** (the controller does not
  talk to kvrgw). Other workers' `Init` does not touch buckets. Because the
  controller waits for READY from *all* workers before starting `RunBenchmark`,
  buckets exist before any put. `KVRGW_ERR_BUCKET_ALREADY_EXISTS` is a hard error
  in `load` (the caller must clean up), unless `force: true` / `--force` is set: then existing
  buckets and their objects are kept, only missing buckets are created, and load puts its keys
  (new versions of existing keys). Verify then needs the same `num_objects`, `num_buckets` and
  `padding_bytes` as the earlier load, or leftover keys fail it as out of range.
- Object index space is `[0, num_objects)`. Global object index `i` maps to bucket
  `bucket_for_index(i)` (contiguous blocks; first `num_objects % num_buckets`
  buckets get one extra object — see §5.3).
- Each thread gets a **disjoint contiguous index range** `index_range(...)`
  (§5.3). A thread's range may straddle bucket boundaries; the thread
  walks its range and switches bucket when `bucket_for_index` changes.
- Operation per object: `put_object` with `object_size_bytes` of payload. A failed
  `put_object` is retried (same key) up to 10 times; if it still fails the worker
  fails, which fails the invocation (controller cancels the other workers and exits
  non-zero). Each failed attempt is counted in the error metrics.
- Always a fixed op count (= its range size). `duration` is not valid for `load`.
- **Verify**: list each bucket and account for every object using the bitset
  technique in §5.4 (expected key set = all indices of the bucket).

### 4.2 `run-*`

All `run-*` commands require a previous `load` (caller's responsibility).
Each takes either `--ops N` (total across the cluster, split evenly over
`total_threads`; remainder to lowest global_thread_ids) **or** `--duration D`
(each thread runs until `D` elapsed since the synchronised start). Exactly one
must be set. One "op" is one API call: a `put_object`, one `list_objects` page, or
one `delete_multi` call (which deletes up to `page_size` keys).

Each has an optional **Verify** step that runs after *all* threads of *all*
workers have finished the benchmark phase (controller barrier, §6).

#### `run-put-object`
Inserts brand-new keys never present in `load` or any earlier run.

- Key: `rand_prefix(seed) + hex8(run_start_unix_s) + hex4(global_thread_id) + "%020d"(counter)`
  (§5.2). hex is fixed-width lowercase. `counter` starts at 0 per thread per
  invocation and is the **key id** (last 20 chars). `seed` is a deterministic
  function of `(run_start_unix_s, global_thread_id, counter)`, e.g.
  `splitmix64_mix(splitmix64_mix(ts) ^ (gtid << 32) ^ counter)`, so the prefix can be
  regenerated by the verifier. Keys are always distinct from load keys (different
  length: `padding_bytes + 32` vs `padding_bytes + 20`) and from other
  invocations' keys, given invocations start at least 1 second apart (accepted:
  runs are seconds apart; clock drift ignored).
- Bucket: `global_thread_id % num_buckets`.
- Each thread's final progress report records `put_count[gtid]` (objects
  successfully written); the controller forwards all of these to Verify (§6).
  The counter advances only after a successful put. A failed put is retried with
  the same key up to 10 times, after which the worker (and therefore the test)
  fails, as in `load`.
- Verify (§5.4): list each bucket; entries whose length is `padding_bytes + 32` and
  whose ts field equals this run's are "this run's keys"; everything else (load
  keys, other runs' keys) is ignored. For each of this run's keys: parse
  `gtid` and `counter`, check `gtid % num_buckets == bucket`,
  `counter < put_count[gtid]`, the key equals the regenerated expected key, and
  the bit for `counter` in a per-`gtid` bitset is not already set (duplicate =
  failure). Completeness: after the scan, every `counter < put_count[gtid]` must
  have its bit set; missing ones are reported by key. Note this lists whole buckets
  (including load keys), so it is slow on large loads; `--no-verify` skips it.
- Extra metrics/config: none.

#### `run-list-objects`
- Buckets are split over workers: bucket `b` is owned by worker `b % worker_count`.
  Within a worker, the owned buckets are processed by `threads_per_worker` threads
  using the prefix-partition scheme in §5.4 (the 68 first-char prefixes of a bucket
  are the work items). Each thread repeatedly pages
  `list_objects(prefix=c, max_keys=page_size)` through its prefixes to the end of
  each, then restarts from its first one.
- Edge case `num_buckets < worker_count`: the controller logs a warning and caps the
  effective `worker_count` for this invocation at `num_buckets`, so no worker is
  left without a bucket (no bucket is ever shared between workers).
- **No verification during the run** (listing is measured as-is; keys come back in
  lexicographic order of a random prefix, so there is nothing cheap to check).
  Pages are only counted/timed; `list_objects` errors count as errors.
- Extra metric: `keys_listed` (counter; reported as keys/s).
- Config: `page_size` (default 1000), `single_thread_mode` (default false): if
  true, ignore `worker_count`, `threads_per_worker` and bucket splitting; use exactly
  one worker with one thread listing the first bucket (all its prefixes).
  `num_objects`/`num_buckets` are still needed to know bucket 0's id space.
- Verify (after the run, same as `load` verify; §5.4): nothing was written, so the
  full load set must still be present exactly once. In `single_thread_mode` only
  bucket 0 is verified.

#### `run-put-object-overwrite`
- Key range split across workers/threads as in `load`. Each thread continually loops
  over its **whole range** overwriting the keys in order via `put_object`, so every
  loaded key is overwritten. There is no limit option; `num_objects_to_overwrite` is
  rejected for this command (it applies to `-versioned` only).
- **Requires never-versioned buckets**, so that every put replaces the object in place:
  - Init fails unless `get_bucket_versioning` is DISABLED (ENABLED, or SUSPENDED which means it
    was enabled before, are refused with a hint to use a new `bucket_name_prefix` and load).
  - Every put is checked: the runtime reports a version id in `PutObjectResult` only when the put
    created a version (versioning ENABLED), so a put returning one aborts the run.
  - The runtime stores no "ever enabled" flag and `put_bucket_versioning` accepts any state, so
    the state alone cannot prove a bucket was never versioned; verify therefore also scans.
- Verify (§5.4): same as `load` verify (the overwritten keys are the load set and must each
  appear exactly once), but listing goes through `list_object_versions`, and any entry that is
  not a lone null version (a real version id, or a delete marker) is an additional failure, so
  leftover version history from an earlier versioned use of the buckets is caught. A key with
  two versions is listed twice and so also counts as a duplicate.
- Note: load buckets are unversioned, so an overwrite replaces the object in place (the
  replaced object goes to the runtime's garbage collection); it does not create a version.

#### `run-put-object-overwrite-versioned`
- Key selection: as `run-put-object-overwrite`, but limited. `num_objects_to_overwrite`
  is the **total** number of keys overwritten, shared evenly across all
  `workers * threads` (remainder to the first threads; must be `<= num_objects`, so no
  thread is ever clamped). Each thread overwrites the first `share` keys of its own range,
  e.g. 1,000,000 over 8 workers x 32 threads is 3,906 or 3,907 keys per thread.
- **Why the limit matters.** (1) The verify compares each key's version count with how
  often the run wrote it, which only means something if keys are written repeatedly; a set
  much larger than the number of puts the run can do leaves most keys with 0 or 1 versions
  and checks almost nothing, so choose a set small enough to be looped over several times.
  (2) Verification makes one `list_object_versions` call per overwritten key, so the size of
  the set bounds how long verification takes. (It does *not* bound memory: verification keeps
  only a put count per thread.)
- **Enables versioning.** The controller prompts before any worker starts (`--yes` skips it):
  "run-put-object-overwrite-versioned will ENABLE versioning on buckets rgwkv-0..9. Versioning
  cannot be switched back off, and old versions are not reclaimed. You will not be able to run
  run-put-object-overwrite (non-versioned) again for this key-set. Continue? [y/N]". Init then
  requires the buckets to exist, and worker 0 calls `put_bucket_versioning(Enabled)` on each
  (the other workers need not wait: the benchmark starts only after every worker's init).
- Each thread loops over its overwrite keys writing new versions. It tracks only
  `full_loops` completed and `last_index` (index within the overwrite window of
  the last key written), no per-key counters. Expected versions for the key at
  window position `p`: `full_loops + (p <= last_index_in_partial_loop ? 1 : 0)`
  (account for the "no partial loop" case explicitly).
- Verify: per key (point lookups; keys are known so no bucket scan or bitset is
  needed; each thread checks its own window), call
  `list_object_versions(prefix=key)` (page through if needed) and count versions with `key == exact` and
  `last_modified_unix >= run_start_unix_s` (the worker uses the second of the synchronised benchmark start from `RunControl.run_start_unix_ns`, which is never earlier and avoids counting a previous back-to-back invocation's writes). This isolates versions written by
  this run without snapshotting prior counts (timestamp resolution is seconds; two
  runs overlapping in the same second is accepted as out of scope). Count must
  equal expected. Mismatches are reported as verify errors with key and
  expected/actual.
- Config: `num_objects_to_overwrite`.

#### `run-delete-multi`
- **Destructive.** The controller prompts: "run-delete-multi deletes objects
  created by load and cannot be undone. Continue? [y/N]". `--yes` skips the
  prompt. Prompt happens before any worker is started.
- Split buckets/objects over workers/threads as in `load`. Each thread calls
  `delete_multi` over batches of up to `page_size` consecutive keys from its
  range and stops when it has deleted the whole range (the run ends once every
  thread is done, even with `--duration` still remaining). `--ops` counts
  `delete_multi` calls and must not exceed what a thread needs to cover its range;
  otherwise init fails with an error (lower `--ops`).
- Extra metric: `keys_deleted` (counter; keys/s).
- Any per-key error in a `delete_multi` outcome (or a failed call) is a hard
  failure: the worker fails and so does the invocation. This guarantees that
  `keys_deleted_total` maps exactly to "the first N keys of the range", which the
  Verify prediction below relies on.
- Each thread deletes its range in index order in batches, so after the first pass
  the keys at positions `[0, deleted)` of its range are gone, where
  `deleted = min(keys_deleted_total, range_count)`. The final progress report
  records `delete_progress[gtid] = deleted`; the controller forwards all of them
  to Verify (§6).
- Verify (§5.4): list each bucket (`list_objects` omits current delete markers).
  Expected surviving indices are exactly those at positions `>= delete_progress[gtid]`
  within each thread's range. Any listed key whose index is not expected to survive
  is a failure; per-bucket found count must equal the expected survivor count.
- Config: `page_size` (default 1000, max keys per call), `single_thread_mode`
  (as in `run-list-objects`, applied to the first bucket: one thread deletes all of
  bucket 0's ids in order, and only bucket 0 is verified).

## 5. Shared definitions

### 5.1 Configuration

Resolved config = **base** ← overridden by **command-specific** (`load` or `run-*`)
section ← overridden by CLI flags. The controller does the merge and sends the
fully resolved config as JSON bytes in `InitRequest.config_json`; workers just
parse it. Format of the input config file: YAML or JSON (pick YAML via the Go
`yaml.v3` lib; support JSON too since YAML is a superset).

**Config files — location and syntax.** There are two distinct configs; don't mix them:

1. *Perf harness config* (new, owned by the controller). Passed with
   `--config <path>`; if omitted, the controller looks for `./kvrgw-perf.yaml` and
   otherwise runs on built-in defaults. In the container, mount it (e.g.
   `/etc/kvrgw-perf/perf.yaml`) or pass the path explicitly. Layout:
   ```yaml
   base:                 # every key from the §5.1 table
     num_objects: 1000000
     num_buckets: 10
     bucket_name_prefix: rgwkv
     padding_bytes: 16
     object_size_bytes: 8192
     worker_count: 4
     threads_per_worker: 8
     verify_threads: 4
     tenant_name: kv-poc
     report_interval_ms: 1000
   load:                 # per-command overrides; same keys plus command-specific ones
     threads_per_worker: 16
   run-put-object: {}
   run-list-objects:
     page_size: 1000
     single_thread_mode: false
   run-put-object-overwrite-versioned:
     num_objects_to_overwrite: 100000
   run-delete-multi:
     page_size: 1000
   ```
   Keys are `snake_case` and identical to the CLI flag names (`--page-size` ⇒
   `page_size`). Unknown keys, wrong types and `ops` + `duration` both set are
   errors reported before any worker starts. Command section names match the CLI
   subcommand names exactly. Durations in the file are plain integers with the unit
   in the key name (`_ms`, `_us`, `_bytes`); `duration` on the CLI/in the file
   accepts Go duration syntax (`30s`, `5m`).
   The harness config file is parsed by the controller only; the collector keys
   (`fdb_*`, `cpu_*`) are not sent to workers.
2. *kvrgw runtime config* (existing `backend/kvrgw.yaml`). Read by the worker's
   `KvRgwRuntime`; located via `KVRGW_CONFIG_FILE` (default `kvrgw.yaml` in the
   working dir, see `kvrgw_runtime.cpp`). The controller does not parse it; local
   mode passes through `KVRGW_CONFIG_FILE`/`KVRGW_DATA` from its own environment to
   each worker. The harness config's `batch_*` keys, if set, override the
   runtime's values at worker start.

The resolved config (JSON) is also written to `<run-dir>/config.resolved.json` for
reproducibility.

Base options (defaults must be taken from the existing code-base where one exists —
check `backend/kvrgw.yaml` (`tier.batch_size`, `batch_timeout_us`, `batch_threads`)
and `perf_driver.cpp` (`KVRGW_*` env handling, key prefix/suffix lengths,
`kKeyPrefixMaxLen`) rather than inventing new numbers; where none, use defaults below):

| key | default | meaning |
|---|---|---|
| `num_objects` | 1,000,000 | total objects in the load |
| `num_buckets` | 10 | buckets objects are spread over |
| `bucket_name_prefix` | `rgwkv` | bucket name = `<prefix>-<i>` |
| `padding_bytes` | 16 (match existing key-length default if one exists) | length of random key prefix |
| `object_size_bytes` | 8192 | payload size |
| `worker_count` | 1 | number of worker processes |
| `threads_per_worker` | 1 | benchmark threads per worker |
| `verify_threads` | 4 | threads per worker for list-based Verify scans (§5.4); independent of `threads_per_worker` |
| `tenant_name` | `kv-poc` (`KVRGW_TENANT_NAME`) | tenant to use |
| `batch_size`, `batch_timeout_us`, `batch_threads` | from `kvrgw.yaml` | PutObject batch queue; applied by the worker via `service.batch_queue()` (stop/start as `perf_driver.cpp`'s `set-batch` does) only if explicitly set |
| `report_interval_ms` | 1000 | progress-window length |
| `fdb_stats` | true | controller samples `fdbcli status json` (§8.2); disable with `--no-fdb-stats` |
| `fdb_cluster_file` | `$FDB_CLUSTER_FILE` | cluster file passed to `fdbcli -C` |
| `fdbcli_path` | `fdbcli` (on `PATH`) | fdbcli binary |
| `fdb_sample_interval_ms` | 5000 | FDB status poll period |
| `cpu_sample_interval_ms` | 1000 | worker/system CPU sample period |
| `ops` / `duration` | — | run-* only; exactly one |

Command-specific options are listed per-operation in §4. Validate everything in
the controller before starting workers; workers re-validate in `Init`.

### 5.2 Key format

Bucket: `<bucket_name_prefix>-<bucket_index>`.

Object key for global index `i` (load keys): `rand_prefix(i) + "%020d"(i)`.
The trailing 20 decimal digits are the **key id** (`i` for load keys). `rand_prefix(seed)`
is `padding_bytes` bytes generated by SplitMix64 from `seed` over the charset
below; for load keys `seed = i`. Keys are therefore deterministic and
regenerable from the id alone, but are **not ordered by index** (random prefix).
There is no "sequential" mode.

Charset (no `/`): `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!-_.*'()`.
SplitMix64: `seed += 0x9e3779b97f4a7c15; z = seed; z = (z ^ (z>>30)) * 0xbf58476d1ce4e5b9; z = (z ^ (z>>27)) * 0x94d049bb133111eb; return z ^ (z>>31)`; each byte is `charset[next() % len(charset)]`.
Only workers generate keys (C++), so no cross-language key compatibility is
required.

### 5.3 Shard math (implement in C++, unit-test)

```
bucket_for_index(i, num_objects, num_buckets):
  base = num_objects / num_buckets; extra = num_objects % num_buckets
  boundary = extra * (base + 1)
  i < boundary ? i / (base + 1) : extra + (i - boundary) / base

index_range(global_thread_id, total_threads, num_objects) -> (start, count):
  base = num_objects / total_threads; extra = num_objects % total_threads
  count = base + (gtid < extra ? 1 : 0)
  start = gtid * base + min(gtid, extra)
```
A thread with `count == 0` simply does nothing. Op-count splitting for `--ops N`
uses the same remainder rule over `total_threads`.

### 5.4 Verification by listing + bitset

Because prefixes are random, a thread's index range is not a contiguous key range
and cannot be listed directly. Instead verification lists **whole buckets** and
accounts for every object via a bitset. One shared helper implements this for
`load`, `run-list-objects`, `run-put-object-overwrite`, `run-delete-multi` (and, with
the key-id parsing described in `run-put-object`, for `run-put-object`).

Each op supplies: the bucket's key-id space (for load-family ops, the bucket's
index range `[bucket_start, bucket_end)` from `bucket_for_index`), a function
`expected_key(id)`, and `expected_present(id)` (true for all ids for load /
list / overwrite; `id >= start+delete_progress` of the owning thread for
delete-multi).

Ownership: **each bucket is verified entirely by one worker**, bucket `b` by worker
`b % worker_count`, so the verifying worker holds the complete picture and can say
categorically which objects are missing from which bucket. Workers owning no bucket
(`num_buckets < worker_count`) do nothing in Verify and return success with empty
results; when `num_buckets` isn't a multiple of `worker_count` some workers own one
more bucket than others (accepted).

Within a worker, a bucket's scan is partitioned by prefix over `verify_threads`
threads (config, default **4**; independent of `threads_per_worker`):
- Work items are the first prefix chars `c` of the 68-char charset (list with
  `prefix = c`). If `padding_bytes == 0` there is a single item with empty prefix
  (no parallelism).
- Threads pull items from a shared atomic counter (dynamic balancing; prefix
  populations are uneven).
- The bucket has **one shared bitset**, `std::vector<uint64_t>` sized to the
  bucket's id space, accessed through `std::atomic_ref<uint64_t>::fetch_or` (the
  returned old word tells whether the bit was already set). Distinct prefixes
  imply distinct ids, but ids share words, so the atomic is required. Buckets are
  processed one after another per worker.

Per work item: page `list_objects(prefix=c, max_keys=1000, continuation_token...)` to
the end. For each returned key:
1. parse the last 20 chars as decimal `id` (failure → `bad_key`);
2. check `key == expected_key(id)` (prefix bytes are deterministic; mismatch →
   `bad_key`);
3. check `id` is inside the bucket's id space (else `out_of_range`) and
   `expected_present(id)` (else `unexpected`, e.g. a key that should have been
   deleted);
4. test-and-set bit `id - bucket_start` in a `std::vector<uint64_t>` bitset sized
   to the bucket's id space; already set → `duplicate` (a key seen twice must never
   happen).
Count each valid key as `found`. Record the first few failure descriptions
(capped, e.g. 20) as samples.

When the bucket scan finishes, the worker sweeps the bitset against
`expected_present(id)`: every expected id whose bit is clear is **missing**. The
worker reports, per bucket: `expected`, `found`, `missing` count, and the first N
(e.g. 100) missing ids rendered as full object keys via `expected_key(id)`, plus the
failure counters. Nothing needs to be merged across workers (each bucket belongs to
one worker); the controller just aggregates and prints.

For `run-put-object` the bucket's "id space" is a set of bitsets, one per
`global_thread_id` with `gtid % num_buckets == b`, each sized
`thread_counts[gtid]` (from `VerifyRequest`); expected ids are
`[0, thread_counts[gtid])`; missing keys are reported by `(gtid, counter)`. Only keys
matching this run's format and ts are considered (others ignored).
Ops that don't verify by listing (`run-put-object-overwrite-versioned`) don't use
this helper.

## 6. Lifecycle and gRPC protocol

The controller is the gRPC **client**; workers never connect back. Sync C++ gRPC API
(thread per handler) is sufficient. Streaming RPCs use `PhaseEvent`.

```proto
syntax = "proto3";
package perf.v1;

service Worker {
  // Resolve config, start/attach runtime, create buckets (load, worker 0 only),
  // check preconditions. Streams exactly one terminal PhaseEvent{READY}.
  rpc Init(InitRequest) returns (stream PhaseEvent);
  // Run the benchmark. First client message carries run_control; later may send Cancel.
  // Streams periodic PhaseEvent{progress} and a terminal PhaseEvent{DONE}.
  rpc RunBenchmark(stream RunControl) returns (stream PhaseEvent);
  // Run the operation's Verify step (if any). Terminal PhaseEvent{DONE}; failures in .error
  // and details in .verify.
  rpc Verify(VerifyRequest) returns (stream PhaseEvent);
  // Release resources. Terminal PhaseEvent{DONE}.
  rpc Cleanup(CleanupRequest) returns (stream PhaseEvent);
}

message InitRequest {
  string operation = 1;        // "load", "run-put-object", ...
  bytes config_json = 2;       // fully resolved config
  int32 worker_index = 3;
  int32 worker_count = 4;
  string benchmark_id = 5;     // unique per invocation
  int64 run_start_unix_s = 6;  // controller wall clock; used in put-object keys & versioned verify
}
message RunControl {
  string benchmark_id = 1;     // first message only
  int64 run_start_unix_ns = 2; // first message only: aligns windows across workers
  int64 report_interval_ms = 3;// first message only; 0 disables progress
  oneof msg { Cancel cancel = 4; }
}
message Cancel {}
message VerifyRequest {
  string benchmark_id = 1;
  // Indexed by global_thread_id (length total_threads), assembled by the controller from
  // each worker's RunSummary: put_count (run-put-object) or delete_progress (run-delete-multi).
  // Empty for other operations.
  repeated uint64 thread_counts = 2;
}
message CleanupRequest { string benchmark_id = 1; }

message PhaseEvent {
  enum State { READY = 0; DONE = 1; }
  State state = 1;
  string error = 2;            // non-empty => phase failed
  ProgressReport progress = 3; // periodic events carry no phase transition
  VerifyResult verify = 4;     // set on Verify's DONE
  RunSummary run_summary = 5;  // set on RunBenchmark's DONE
}
message RunSummary {
  int32 worker_index = 1;
  repeated uint64 thread_counts = 2; // indexed by thread_id within the worker
}
message ProgressReport {
  int32 worker_index = 1;
  int64 window = 2;            // 0-based, from run_start_unix_ns
  int64 window_duration_ns = 3;// shorter for final partial window
  repeated OpStats window_stats = 4;
  repeated OpStats cumulative_stats = 5; // full snapshot, not delta
  int64 cumulative_as_of_unix_ns = 6;
  ServerStats server_stats = 7; // cumulative snapshot of in-process kvrgw stats
}
// Snapshot of the worker's in-process kvrgw statistics (the same counters the
// legacy admin socket exposed via get-latency / get-batch-stats / get-error-stats).
// All values are cumulative since process start; the controller diffs them.
// Read them directly from the runtime objects in-process; no admin socket is used.
message ServerStats {
  repeated ServerOpStats ops = 1;   // only op types with count > 0
  uint64 batch_commits = 2;         // attempted_batch_commits
  uint64 batch_entries = 3;         // attempted_entries_batched
  uint64 batch_wait_us_total = 4;   // attempted_total_wait_us
  uint64 batch_queue_size_total = 5;// total_queue_size_at_extract
  uint64 batch_conflict_pushbacks = 6;
  uint64 txn_retries = 7;           // if exposed; else 0
  uint64 txn_hard_failures = 8;     // if exposed; else 0
  map<string, uint64> errors = 9;   // KvrgwErrorCode name -> count, non-zero only
}
message ServerOpStats {
  string op = 1;                    // e.g. "PutObject", "ListObjects"
  uint64 count = 2;
  uint64 total_us = 3;
  uint64 fdb_us = 4;
  uint64 fdb_get_us = 5;
  uint64 fdb_commit_us = 6;
  uint64 fdb_scan_us = 7;
  uint64 disk_us = 8;
}
message OpStats {
  string operation_type = 1;   // "put_object","list_objects","delete_multi",
                               // plus counter-style types: "keys_listed","keys_deleted"
  uint64 count = 2;            // successes; latency covers only these
  uint64 errors = 3;
  uint64 sum_micros = 4;
  Histogram latency = 5;       // empty for counter-style types (count = units)
}
message Histogram { repeated uint32 bucket_index = 1; repeated uint64 bucket_count = 2; }
message VerifyResult {
  repeated BucketVerify buckets = 1; // one per bucket owned by this worker
  uint64 keys_checked = 2;           // total keys seen
  uint64 bad_key = 3;
  uint64 out_of_range = 4;
  uint64 unexpected = 5;
  uint64 duplicate = 6;
  uint64 other_failures = 7;         // e.g. version-count mismatches, list errors
  repeated string samples = 8;       // capped failure descriptions
}
message BucketVerify {
  string bucket = 1;
  uint64 expected = 2;
  uint64 found = 3;
  uint64 missing = 4;
  repeated string missing_keys = 5;  // capped (first ~100), full object keys
}
```

Controller sequence per invocation (all workers in parallel, with a barrier between
steps — every worker must finish step *n* before any starts step *n+1*):

1. (local mode) spawn workers, wait until each accepts gRPC.
2. `Init` on all → wait all READY. Any error aborts (cancel/cleanup).
3. Pick `run_start_unix_ns` slightly in the future (e.g. now + 1s), `RunBenchmark`
   on all; consume progress events, aggregate by window across workers, write CSV.
   Workers start work at `run_start_unix_ns`. Duration-based runs end `duration`
   after it. On SIGINT the controller sends `Cancel`, workers drain in-flight ops
   and emit DONE.
4. `Verify` on all (skipped if the operation has none or `--no-verify`).
   Non-zero failures → controller exits non-zero after printing summaries.
5. `Cleanup` on all, then (local mode) stop workers (SIGTERM, 15s grace, then kill).

Window alignment: every worker buckets ops into windows of `report_interval_ms`
measured from `run_start_unix_ns`, so window N covers the same wall-clock span
on every worker; the controller sums same-numbered windows (no interpolation).

Histogram: sparse log-linear, microseconds. `linearLimit=64` (values <64 get own bucket),
`subBuckets=32`, `numBuckets = 64 + 35*32`, clamp above. For `micros>=64`:
`e = bitlen(micros) - 6; idx = 64 + (e-1)*32 + (micros>>e) - 32`.
Bucket midpoint for idx>=64: `k=idx-64; e=k/32+1; m=k%32+32; (m<<e) + (1<<(e-1))`.
Merge = add counts. Quantiles from merged histograms only (never average
percentiles). **Implement identically in C++ and Go and share a test vector file
(`perf/proto/testdata/histogram.json`: micros → bucket index) that both unit tests
read.**

## 7. Worker details

- Startup mirrors `backend/src/main.cpp` `--perf` mode: create
  `kvrgw::KvRgwRuntime`, `KvRgwStartOptions{perf_mode=true, data_root=$KVRGW_DATA}`,
  `runtime.start()`, then use `runtime.service()`. Exactly **one runtime per
  process** (FDB network thread is per process — this is why multiple worker
  processes are needed to scale). Worker flags: `--listen host:port`,
  `--data-root`. Resolve tenant via `service.resolve_tenant(tenant_name)` /
  `add_tenant` like `perf_driver.cpp` does.
- Set `KVRGW_INSTANCE_ID=<worker_index>` in the worker environment (local mode).
  Check in `service_impl`/`kvrgw_runtime` whether the runtime derives a distinct
  rgw_id/ref-tag namespace per instance; if so make sure each local worker gets a
  unique value; if it requires config, add it to local-mode spawning.
- API calls (see `backend/src/service_impl.hpp`): `create_bucket`,
  `put_bucket_versioning(.., VersioningState::Enabled)`, `get_bucket_versioning`,
  `put_object(tenant, bucket, key, data, len, content_type, estimated_size, cond=nullptr, tags={}, metadata={})`,
  `list_objects(tenant, bucket, prefix, delimiter="", max_keys, continuation_token, marker, &out)`,
  `list_object_versions(tenant, bucket, prefix, max_keys, key_marker, version_id_marker, &out)`,
  `delete_multi(tenant, bucket, keys, objects, &outcomes)`. Prefer the C++ service
  API (as `perf_driver.cpp` does) over the C API.
- Threads: `threads_per_worker` `std::jthread`s. Each thread owns a local
  `ThreadStats` (per-op window + cumulative histograms) to avoid contention; a
  reporter thread snapshots/merges at each window boundary and calls
  `ServerWriter::Write` (guard with a mutex). Use a monotonic clock for latency;
  windows are derived from `run_start_unix_ns`.
- Each op is recorded with its `operation_type`; errors counted per type with the
  `kvrgw_strerror` text logged (rate-limited) to the worker log.
- `ServerStats` (§6): at each window boundary the reporter also reads the runtime's
  existing `LatencyStats`, `BatchStats` and `ErrorStats` objects (see
  `backend/src/admin_server.cpp` `get-latency` / `get-batch-stats` /
  `get-error-stats` for the field names and how they are reached from the runtime)
  and fills `ProgressReport.server_stats`. This must be done **without modifying
  existing code**. If the runtime does not expose these objects publicly, report
  it as a blocker in the PR description rather than patching the runtime;
  acceptable fallback: the worker queries its own admin socket
  (`KVRGW_ADMIN_SOCKET=<run-dir>/admin-<i>.sock`) from the reporter thread using
  the existing text protocol (single poller per socket; never reset counters).
- Duration/op-count stop condition checked per iteration; `Cancel` sets an atomic
  stop flag.
- Verify runs after the controller's barrier; the worker verifies the buckets it
  owns (§5.4) one at a time with `verify_threads` scan threads over a shared
  atomic bitset, and returns a `BucketVerify` per bucket.
- Payload: reuse a pre-filled shared buffer sized `object_size_bytes`; no per-op
  allocation.

## 8. Controller details

- Go module `kvrgw-perf`, dependencies: grpc, protobuf, yaml.v3, zerolog (or std
  `log/slog`), cobra (or std flag).
- CLI: `kvrgw-perf [--config file.yaml] [--workers N] [--threads M] [--worker-binary path] [--base-port 19090] [--cpus LIST] [--run-dir DIR] [--yes] [--no-verify] [--no-fdb-stats] [--fdb-cluster-file PATH] <command> [flags]`
  with commands `load`, `run-put-object`, `run-list-objects`,
  `run-put-object-overwrite`, `run-put-object-overwrite-versioned`,
  `run-delete-multi`, plus `report <results-dir> [--warmup D] [--deviation N] [--per-server]` (§8.3). `--ops`/`--duration`, `--page-size`,
  `--single-thread-mode`, `--num-objects-to-overwrite` as flags mapping to the
  config keys.
- **Local mode** (the only mode in v1): spawn `worker_count` child processes
  `kvrgw-perf-worker --listen 127.0.0.1:<base_port+i>`, with env
  `KVRGW_INSTANCE_ID=i` (+ inherited `KVRGW_*`, `FDB_CLUSTER_FILE`,
  `LD_LIBRARY_PATH`), stdout/stderr to `<run-dir>/worker-<i>.log`, optional CPU
  pinning (`taskset`/`sched_setaffinity`: split `--cpus` pool evenly or by
  cores-per-worker), controller log to `<run-dir>/controller.log`. Stop children
  with SIGTERM + 15s grace then SIGKILL. If any worker exits before the
  controller finishes, fail the invocation.
  Keep this behind an interface (`WorkerLauncher`) so a future "connect to given
  addresses" implementation is a drop-in.
- **Results directory** (§8.1) replaces the single CSV: every invocation writes
  timestamped files into its own `--run-dir` (default
  `perf-results/<UTC yyyymmddThhmmssZ>-<command>/`). Also print a
  one-line-per-window terminal summary during the run, and at the end a final
  per-op summary (totals, overall quantiles, errors) plus the verify summary.
- Exit codes: 0 success; 1 benchmark/verify failures or worker errors; 2 usage.

### 8.1 Results directory (one per invocation)

All timestamps are Unix milliseconds UTC (`unix_ts_ms`) from the controller's clock.

| file | content |
|---|---|
| `config.resolved.json` | fully resolved config (§5.1) |
| `events.csv` | `unix_ts_ms,event` for `invocation_start`, `init_done`, `benchmark_start` (= `run_start_unix_ns`), `benchmark_end` (last worker DONE), `verify_start`, `verify_end`, `invocation_end` |
| `summary.json` | command, parameters, totals per op, per-worker `RunSummary`, verify result (incl. per-bucket missing counts/keys), error count, exit status |
| `metrics.csv` | client metrics, one row per (window, op_type): `unix_ts_ms, window, op_type, count, errors, ops_per_sec, mean_us, p50_us, p90_us, p99_us, p999_us, max_us, cum_count, cum_errors`. Counter-style types (`keys_listed`, `keys_deleted`) fill `count`/`ops_per_sec` (= units/s) and leave latency columns empty. `unix_ts_ms` is the window end. Flushed every window |
| `hist.csv` | sparse merged per-window histograms: `window, op_type, bucket_index, count` (lets `report` compute overall quantiles over any time range) |
| `server_stats.csv` | server-side kvrgw stats summed over workers, long format, cumulative (consumers diff): `unix_ts_ms,window,name,value`. `name` is `<Op>.count`, `<Op>.total_us`, `<Op>.fdb_us`, `<Op>.fdb_get_us`, `<Op>.fdb_commit_us`, `<Op>.fdb_scan_us`, `<Op>.disk_us` (e.g. `PutObject.count`), `batch.commits`, `batch.entries`, `batch.wait_us_total`, `batch.queue_size_total`, `batch.conflict_pushbacks`, `txn.retries`, `txn.hard_failures`, or `error.<KvrgwErrorCode name>` |
| `cpu.csv` | `unix_ts_ms,source,cores` — `source` = `worker-<i>` (CPU of the worker process, in cores, from `/proc/<pid>/stat` utime+stime delta) or `system` (whole-host CPU busy in cores-equivalent from `/proc/stat` delta) |
| `fdb_cluster.csv` | `unix_ts_ms, txn_hz, reads_hz, writes_hz, conflict_hz, worst_queue_ss, worst_queue_log, limiting_queue_ss, durability_lag_s` |
| `fdb_process.csv` | long format, one row per (sample, process, role): `unix_ts_ms, addr, role, cpu_cores, mem_bytes, rss_bytes, input_hz, durable_hz, stored_bytes, kvstore_bytes, data_lag_s, durability_lag_s, queue_disk_bytes, queue_mem_bytes, disk_busy, disk_reads_hz, disk_writes_hz` (fields not applicable to a role are empty) |
| `fdb_cpu.csv` | one row per (sample, process) for **every** process: `unix_ts_ms, addr, class, roles, cpu_cores`; `roles` is every role the process holds, sorted and joined with `;` (`none` if it holds none). The report sums mean CPU per role from it (a process counts under each of its roles and once in the total), prints the storage spread, and warns when the hottest storage process exceeds 1.8x the median. Results without this file fall back to the grouped `SS`/`LOG`/`SL` lines. |
| `fdb_status_start.json` | one raw `status json` snapshot taken at `invocation_start` (cluster configuration: redundancy, engine, process layout) |
| `controller.log`, `worker-<i>.log` | logs |

Raw per-sample `status json` dumps are **not** written (extracted CSVs only).

### 8.2 Collectors (in the controller, Go)

- **Client metrics:** from worker progress events (`metrics.csv`, `hist.csv`,
  `server_stats.csv`) as described in §6.
- **FDB status sampler:** a goroutine started at `invocation_start` (after the
  start snapshot) and stopped at `invocation_end`, polling every
  `fdb_sample_interval_ms`:
  `fdbcli -C <fdb_cluster_file> --exec "status json" --timeout 3` (exec with a 5s
  outer timeout). Parse the JSON natively. A failed/empty sample is skipped
  (log once per run at warn level, with a count at the end). Extracted fields (JSON
  paths under `cluster`):
  - cluster: `workload.transactions.committed.hz`, `workload.operations.reads.hz`,
    `workload.operations.writes.hz`, `workload.transactions.conflicted.hz`;
    `qos.worst_queue_bytes_storage_server`, `qos.worst_queue_bytes_log_server`,
    `qos.limiting_queue_bytes_storage_server`,
    `qos.limiting_durability_lag_storage_server.seconds`.
  - per process in `processes` (one row per role of interest): `address`,
    `cpu.usage_cores`, `memory.used_bytes`, `memory.rss_bytes`,
    `disk.busy`, `disk.reads.hz`, `disk.writes.hz`; for `storage` roles also
    `input_bytes.hz`, `durable_bytes.hz`, `stored_bytes`, `kvstore_used_bytes`,
    `data_lag.seconds`, `durability_lag.seconds`, `queue_disk_used_bytes`; for
    `log` roles `input_bytes.hz`, `durable_bytes.hz`, `queue_disk_used_bytes`,
    `queue_memory_bytes`; for other roles (stateless class and
    `commit_proxy`/`grv_proxy`/`resolver`) only the common fields, with the
    comma-joined role names in `role`.
  (The legacy `scripts/run_perf_from_def.sh` `collect_fdb_stats` shows exactly
  these extractions; port them, don't invoke it.) FDB may run on other machines;
  nothing here assumes FDB is local. Disk-free is intentionally not collected.
  If `fdb_stats` is false or `fdbcli`/the cluster file is unavailable: log a
  warning and run without FDB data (the report then omits the FDB sections).
- **CPU sampler:** every `cpu_sample_interval_ms`, for each local worker pid read
  `/proc/<pid>/stat` (fields 14+15; clock ticks are 100/s on Linux) and `/proc/stat` first line; write
  deltas as cores to `cpu.csv`. Local mode only (worker pids are known).
- No host `iostat`/`pidstat`, no admin-socket polling by the controller.

### 8.3 `kvrgw-perf report <results-dir> [flags]`

Reads only the files in §8.1 (never touches workers or FDB). Flags:
`--warmup <duration>` (Go `time.ParseDuration`, default `0s`), `--deviation N`
(default 10), `--per-server`.

**Analysis window** = `[benchmark_start + warmup, benchmark_end]` from
`events.csv`. Every sample/row outside it is ignored, including the verify
phase and anything after `benchmark_end`. The window is printed in the header. There
is no idle/rampup/active/drain classification.

**Statistics.** For each metric take the per-window (or per-sample) values inside
the analysis window and print `min max avg median p90 p95 p99 dev%`, where `dev%`
is the percentage of samples whose `|v - median| / median` exceeds `--deviation`%
(0 when the median is 0). Overall latency quantiles and totals come from merging
`hist.csv` windows inside the analysis window (never averaging percentiles).
Cumulative columns (`server_stats.csv`) are diffed over the analysis window.

**Output sections** (omit a section if its data is absent; counter-style types such
as `keys_listed` print only ops/sec):

```
==========================================================================
 kvrgw-perf report: run-put-object-1
==========================================================================
 Operation : run-put-object      Workers: 4 x 8 threads   Buckets: 4
 Benchmark : 12:00:05Z -> 12:03:05Z (180s)   Warmup skipped: first 10s
 Analysed  : 12:00:15Z -> 12:03:05Z (170 windows of 1s)
 Verify    : PASS  (4 buckets, 0 missing, 0 duplicates, took 41s)
 Errors    : 6 (all retried OK)

--- Client ops (cluster total, merged across workers) ---
 put_object     min      max      avg   median      p90      p95      p99   dev%
 ops/sec     35,100   38,900   37,200   37,350   38,300   38,600   38,850   0.0%
 mean_us      3,150    3,900    3,420    3,400    3,700    3,780    3,880   8.8%
 p50_us       2,900    3,500    3,150    3,130    3,380    3,440    3,490   5.3%
 p99_us       9,800   21,000   12,400   11,500   16,200   18,900   20,700  35.1%
 errors/win       0        2      0.1        0        0        1        2   0.0%
 Totals: 6,324,000 ops   overall p50=3.1ms p99=12.9ms p999=31ms

--- Worker CPU (client side, cores) ---
                 min    max    avg   median
 worker 0       5.1    6.3    5.8     5.8
 ...
 system-wide CPU (rgw host)   41.2%  47.9%  44.6%   44.7%

--- Server-side KVRGW (summed over workers) ---
 PutObject: avg_total=3,390us  avg_fdb=2,610us (77%)  commit=1,980us  get=410us  disk=0us
 Batches: 4,130 commits/s  avg size 9.0  avg wait 612us  avg queue 12.7  conflict pushbacks 12
 Txn: retries 214  hard failures 0   Server errors: KVRGW_ERR_TXN_CONFLICT=6

--- FDB cluster ---
                       min      max      avg   median
 txn/s               3,980    4,260    4,130    4,140
 writes/s           37,100   40,200   38,600   38,700
 conflicts/s           0.0      3.0      0.4      0.0
 worst SS queue (MB)   4.1     38.0     12.4     10.2
 durability lag (s)    0.2      0.9      0.4      0.4

--- FDB by role ---
 SS  (3)   in/dur=1.0-1.1x   lag=0.3-0.5s   cpu=0.58-0.64   mem=2.1-2.2GB
 LOG (3)   input=70MB/s each   q_disk=0.9-1.2GB   cpu=0.52-0.57
 SL  (4)   cpu=0.20-0.45 (commit_proxy, grv_proxy, resolver, master)

--- Health ---
 [OK] durability kept up with input on all storage servers
 [OK] TLog queue stable (first half 1.0GB, second half 1.1GB)
```

(The numbers are illustrative.) Definitions:
- **FDB by role** (default, aggregated): per process take the median of each metric
  over the analysis window; print the min–max across the processes of the role.
  `in/dur` = median `input_hz` / median `durable_hz`. With `--per-server`,
  print one line per process instead, e.g.
  `SS :4503 in/dur=2.3 lag=4.1s cpu=0.97 [HOTSPOT]`, with the per-process
  flags below.
- **Flags and warnings** are ported from the legacy
  `scripts/display_perf_results.sh` `HEALTH` section (read it for exact
  thresholds; do not run or modify it): per-server `[HOTSPOT]`, `[SATURATED]`,
  `[FALLING_BEHIND]`; warnings for durability stalled (`durable_hz` 0 while data
  is queued) and TLog queue growth (first half vs second half of the window).
  Do **not** port the drain/settle checks, RAM-limit and disk-free warnings
  (not collected).
- **Server-side KVRGW**: from `server_stats.csv` diffs over the analysis window
  divided by the count delta (`avg_*`), and batch counters per second.
- The report exits 0 unless the results directory is unreadable (exit 2) or
  `summary.json` records a failed run (exit 1).

## 9. Build integration

**Scope of support:** building and testing happen only inside the Docker
build container (`perf/Dockerfile.build`, driven by `perf/Makefile`). Native host
builds and host package installs are explicitly out of scope; do not add
host-specific fallbacks or documentation for them. All build/test validation
should be done in the build container.

- `perf/CMakeLists.txt` (included only when enabled): `find_package(Protobuf REQUIRED)`,
  `find_package(gRPC CONFIG REQUIRED)`, nlohmann_json (already in the image);
  generate C++ stubs from `proto/perf/v1/worker.proto` with `protobuf_generate`
  + `grpc_cpp_plugin`; build `kvrgw-perf-worker` linking `kvrgw` (target from
  `backend/CMakeLists.txt`) and `gRPC::grpc++`; include dirs for
  `backend/src` and `backend/include`; same RPATH conventions as `kv-rgw-backend`.
  Add worker unit tests (keys/shard/histogram) as plain executables like the
  existing tests. Add a custom target for `go build -o ${CMAKE_BINARY_DIR}/kvrgw-perf`
  in `perf/controller` (pattern: the `frontend` target in `backend/CMakeLists.txt`),
  `DEPENDS` nothing from kvrgw (the controller must not link it).
- The only edit to an existing file (optional but intended) — append to
  `backend/CMakeLists.txt`:
  ```cmake
  option(KVRGW_BUILD_PERF_HARNESS "Build gRPC perf controller/worker" OFF)
  if(KVRGW_BUILD_PERF_HARNESS)
    add_subdirectory(${CMAKE_SOURCE_DIR}/../perf ${CMAKE_BINARY_DIR}/perf)
  endif()
  ```
- `perf/Dockerfile.build` provides `grpc-devel grpc-plugins protobuf-devel
  protobuf-compiler` (EPEL 9) alongside the FDB client package, which provides
  `fdbcli` at `/opt/foundationdb/usr/bin/fdbcli` for the FDB sampler (§8.2).

## 10. Testing and acceptance

- Unit tests (C++): key generation determinism, key-id parsing and
  `expected_key` round-trip for load and put-object keys, bitset helper (dup /
  out-of-range / unexpected / missing detection incl. concurrent `atomic_ref` use from
  several threads), bucket-to-worker and prefix-to-thread assignment cover every
  bucket / prefix exactly once (incl. `num_buckets < worker_count`), `bucket_for_index`,
  `index_range` (sum of counts == `num_objects`, contiguity, no overlap, edge cases
  `num_objects < total_threads`), histogram index/midpoint vs shared test vector,
  versioned expected-count formula. The verification helper should be testable
  against an in-memory fake lister (no FDB), including missing/duplicate/extra keys.
- Unit tests (Go): config merge precedence, histogram merge/quantiles vs shared
  vector, window aggregation across workers, CSV writer, ops/duration splitting,
  `status json` extraction against a checked-in fixture (cluster + per-role
  process rows), `/proc` CPU parsing and delta math, and `report`: warmup
  windowing from `events.csv` (rows before `benchmark_start+warmup` and after
  `benchmark_end` are excluded), stats/`dev%` computation, role aggregation vs
  `--per-server`, `--warmup` duration parsing.
- Integration (needs an FDB cluster, e.g. a `foundationdb/foundationdb` container
  on the same docker network as the build container): local mode with 2 workers × 2 threads:
  1. `load` with 10k objects / 4 buckets → verify passes.
  2. Each `run-*` for a few seconds → verify passes, results dir contains all
     §8.1 files (FDB files only if `fdbcli` works), CSV has expected rows,
     errors == 0, and `kvrgw-perf report <dir> --warmup 2s` prints all sections.
  3. Negative: `run-put-object-overwrite` against a versioned bucket (e.g. after
     `run-put-object-overwrite-versioned`) fails in Init; `run-put-object-overwrite-versioned`
     and `run-delete-multi` abort without `--yes` on "n" (and `n` leaves the buckets unversioned).
  4. Default build (option OFF) still builds `libkvrgw` and `kv-rgw-backend`
     without gRPC installed.

## 11. Assumptions / open items for the implementer

- Verification lists whole buckets (random prefixes prevent range listing); on very
  large loads it is slow. Each bucket is owned by one worker, so missing objects
  are reported exactly (capped list of keys + total count).
- Edge cases assumed for bucket ownership: `num_buckets < worker_count` and
  `num_buckets % worker_count != 0` (see §4 `run-list-objects` and §5.4).
- `create_bucket` on existing bucket is an error for `load`.
- Check whether kvrgw requires per-process unique instance/rgw ids (see §7).
- Exact defaults for `padding_bytes` and batch settings should
  be taken from existing code (`perf_driver.cpp`, `kvrgw.yaml`).
- Versioned-verify relies on 1-second `last_modified_unix` resolution and runs
  being ≥1s apart; no state snapshot is taken.
- Server-side stats access (§7): confirm how `LatencyStats`/`BatchStats`/`ErrorStats`
  are reachable from `KvRgwRuntime`; the txn retry/failure counters may not exist
  (report 0 and note it).
- Health thresholds (§8.3) come from the legacy `display_perf_results.sh`; the
  legacy `fdb_stats` JSON field names are the reference for §8.2 extraction.
- The `report` output has no drain/settle analysis: FDB sampling stops with the
  invocation, so post-benchmark catch-up is not observed.
