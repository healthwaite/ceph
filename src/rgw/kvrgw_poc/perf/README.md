# kvrgw perf harness

`kvrgw-perf` (Go controller) drives one or more `kvrgw-perf-worker` processes (C++, each
embedding a kvrgw runtime and calling the service layer directly) over gRPC, and writes
timestamped results (CSV/JSON) into a per-invocation results directory. `kvrgw-perf report`
analyses such a directory. The full design is in [SPEC.md](SPEC.md).

Everything is built and tested in a Docker build container (Rocky 9, see
[Dockerfile.build](Dockerfile.build)). The [Makefile](Makefile) has two host targets and two
in-container targets; each refuses to run on the wrong side. `make` with no target lists them.

## Build and test

On the host, from `src/rgw/kvrgw_poc/perf`:

    make docker-image      # build the image (kvrgw-perf-build)
    make shell             # container shell; the ceph tree is mounted at /workspace

Inside the container shell:

    make build             # kvrgw-perf (Go) and kvrgw-perf-worker (C++)
    make test              # C++ unit tests (ctest -R perf_) and `go test ./...`

or, non-interactively from the host, `make shell CMD='make build'` (and `CMD='make test'`).
`EXTRA_ARGS` adds `docker run` arguments (see Run, below).

`make build` produces `build/kvrgw-perf`, `build/perf/kvrgw-perf-worker` and
`build/kvrgw-perf.yaml` under `src/rgw/kvrgw_poc`. The harness is opt-in in the backend CMake
(`-DKVRGW_BUILD_PERF_HARNESS=ON`, which the Makefile passes); with the option OFF (default)
gRPC/protobuf are not needed and nothing here is built. The first `go build`/`go test` downloads
Go modules, so the container needs network access.

## Client models (driver_mode)

Concurrency is counted in *streams*: sequential clients with one op in flight.

- `driver_mode: sync` (default): one blocking thread per stream calling the sync
  service API (a thread-per-request client, as the C API / gateway is).
- `driver_mode: async`: `streams_per_worker` coroutines on `driver_threads`
  executors calling the `_a` service ops, so concurrency is not bounded by thread
  count. Example: `--driver-mode async --streams 1024 --driver-threads 2`.
- Open loop: `--driver-mode async --rate 20000` issues 20,000 ops/s per worker on a
  fixed schedule and measures latency from each op's scheduled time; `missed` counts
  ops that could not be issued (the rate was not held). `send_lag` (send time minus
  scheduled time per op) shows how much of that latency is the driver sending late:
  the driver thread that sends also prepares ops and handles their completions, so a
  busy driver sends late. The report flags send lag only when its p99 is over 1 ms and
over 10% of the op's p99, and suggests more `driver_threads` when drivers are busy
(otherwise the lag is from send bursts); a smaller lag is noted as negligible.

Async runtime knobs live in the `kvrgw:` section (`backend_workers`,
`max_inflight_ops`, `txn_max_attempts`, `batch_txn_max_attempts`,
`txn_timeout_ms`). A non-zero `queue_full` means `streams_per_worker` exceeded
`max_inflight_ops`. To compare against the pre-async backend, run the old worker
binary with the same configuration.

Ramp: `--ramp` on run-put-object / -overwrite / -overwrite-versioned finds the maximum
sustainable rate. It offers `ramp_start_rate`, then `+ ramp_step_rate` per step (cluster
totals), each step a warm-up then a measured window, and stops at the first step that
misses a criterion (p99 below `ramp_max_p99_ms`, achieved, missed, errors, backlog); a
step where the load generator itself is the limit is reported as invalid. With
`--ramp-mode throughput` only throughput counts: it ramps until a step completes less
than 98% of its target, whatever the latency. `duration` does not apply to a ramp.
Every async run first logs Little's-law bound: max rate = in-flight cap
(`max_inflight_ops` x workers) / mean latency. Examples:

    kvrgw-perf --ramp --ramp-start-rate 5000 --ramp-step-rate 1000 run-put-object-overwrite
    kvrgw-perf --ramp --ramp-mode throughput --ramp-start-rate 5000 --ramp-step-rate 2000 run-put-object-overwrite

`--arrival poisson` uses exponential inter-arrival times (any open-loop run). Results:
the live per-step lines, `ramp_steps.csv`, `summary.json` and the report's Ramp section.
Prefer run-put-object-overwrite for a capacity number: run-put-object grows the data set
for the whole ramp. Details: `RAMP.md`.

Thread utilisation: every progress report carries CPU and wall time for each backend
worker (`kvrgw-be-N`), the FDB client network thread (`fdb-network`) and each async
driver (`perf-drv-N`), plus libfdb_c's own network-thread busyness. The report's
"Thread utilisation" section shows busy % per group (per thread with `--detailed`)
over the analysed window, with hints: a saturated `fdb-network` means add worker
processes; saturated backend workers or drivers mean raise `backend_workers` /
`driver_threads`; mostly idle ones can be lowered. The run summary prints the same
per-group figures for the whole run.

## Running on another machine

To run the harness somewhere that has Docker and an FDB cluster but no build environment, package it
as a runtime image and ship it. On the host:

    make image             # build, stage dist/image, docker build kvrgw-perf:<git sha>[-dirty]
    make save              # dist/kvrgw-perf-<tag>.tar.gz plus dist/kvrgw-perf.image
    make deploy            # rsync both and deploy/kvrgw-perf-run.sh to client:~/dev/kvrgw-perf
                           # (DEPLOY_HOST=... DEPLOY_DIR=... override the destination)

On the target machine:

    cd ~/dev/kvrgw-perf && ./kvrgw-perf-run.sh     # shell in the container
    kvrgw-perf load                                # then run kvrgw-perf as usual
    ./kvrgw-perf-run.sh kvrgw-perf run-put-object --duration 60s   # or one command

`kvrgw-perf-run.sh` runs `docker load` the first time (or when a new tarball arrives), then
`docker run` with host networking, the host's `/etc/foundationdb/fdb.cluster` mounted read-only at the
same path, `./perf-results` mounted as the results directory, and
`--security-opt seccomp=unconfined` (needed for glibc 2.34+ images on Docker older than 20.10.10).
Override with `CLUSTER_FILE`, `RESULTS_DIR` and `DOCKER_RUN_ARGS` (set it to empty to drop the seccomp
option). The image has `kvrgw-perf`, `kvrgw-perf-worker` and `fdbcli` on `PATH`, and sets
`FDB_CLUSTER_FILE` and `KVRGW_DATA`. Perf mode never writes object data, but the runtime creates its
data directory, so `KVRGW_DATA` is just a writable path inside the container (`/tmp/kvrgw-data`).
Old tarballs are not removed from the target; delete them as needed.

### Regenerating the Go gRPC stubs

The generated Go stubs in `controller/gen/perf/v1/` are checked in. After editing
`proto/perf/v1/worker.proto`:

    cd perf/controller
    protoc -I ../proto/perf/v1 \
      --go_out=gen/perf/v1 --go_opt=paths=source_relative \
      --go-grpc_out=gen/perf/v1 --go-grpc_opt=paths=source_relative \
      ../proto/perf/v1/worker.proto

(needs `protoc-gen-go` and `protoc-gen-go-grpc`). The C++ stubs are generated by CMake.

## Run

Bring FDB up yourself; the harness only reads from a running cluster. Set
`FDB_CLUSTER_FILE` and `KVRGW_DATA` as for the gateway.

For example, with FDB in a container on a shared docker network:

    docker network create kvrgw-perf-net
    docker run -d --name perf-fdb --network kvrgw-perf-net foundationdb/foundationdb:7.3.77
    docker exec perf-fdb fdbcli --exec 'configure new single ssd'
    docker exec perf-fdb cat /var/fdb/fdb.cluster > /tmp/fdb.cluster
    make shell EXTRA_ARGS='--network kvrgw-perf-net -v /tmp/fdb.cluster:/tmp/fdb.cluster \
        -e FDB_CLUSTER_FILE=/tmp/fdb.cluster -e KVRGW_DATA=/tmp/kvrgw-data'

The build image includes `fdbcli` (`/opt/foundationdb/usr/bin/fdbcli`, the default
`fdbcli_path`, and on `PATH`), so FDB statistics are collected without extra setup; pass
`--no-fdb-stats` to skip them.

Then, in that shell (from `src/rgw/kvrgw_poc`):

    build/kvrgw-perf load
    build/kvrgw-perf run-put-object --duration 60s
    build/kvrgw-perf run-list-objects --duration 30s
    build/kvrgw-perf run-get-object --duration 30s       # random reads, no verify
    build/kvrgw-perf report perf-results/<dir> --warmup 10s              # run totals only
    build/kvrgw-perf report perf-results/<dir> --warmup 10s --detailed   # plus per-window statistics
    build/kvrgw-perf report perf-results/<dir> --warmup 10s --window 30s   # widen the windows

All settings live in one file, [kvrgw-perf.yaml](kvrgw-perf.yaml), which lists every default
explicitly. It is found via `--config`, else `./kvrgw-perf.yaml`, else next to the
`kvrgw-perf` binary (the build copies it there), else `/opt/kvrgw/kvrgw-perf.yaml`.
Sections: `kvrgw` (the runtime tier/batch settings), `base`, and one per command.
Resolution is built-in default <- `base` <- command section <- CLI flag; keys are snake_case
and every key is also a `--kebab-case` flag (`--batch-size`, `--max-inline`, ...).
The controller synthesizes `<run-dir>/kvrgw.yaml` from the `kvrgw` section and points the
workers at it (`KVRGW_CONFIG_FILE`), so `backend/kvrgw.yaml` is not used. The runtime's yaml
loader ignores `batch_*` and the async keys, so the controller also exports them as
`KVRGW_*` environment variables.
See SPEC.md section 5.1 for the key table.
Each invocation is independent: `load` once, then any number of `run-*`, using the same
layout config. `run-*` commands take exactly one of `--ops N` / `--duration D`.

Local mode (the only mode in v1) spawns `worker_count` workers on `127.0.0.1:<base-port+i>` (base port 19090 by default, `--base-port` to change);
`--cpus 0-15` splits a CPU pool across them with `taskset`.

Results directory: `config.resolved.json kvrgw.yaml events.csv metrics.csv errors.csv hist.csv server_stats.csv ramp_steps.csv (--ramp)
cpu.csv fdb_cluster.csv fdb_process.csv fdb_cpu.csv fdb_status_start.json fdb_status.jsonl summary.json controller.log
worker-<i>.log` (spec section 8.1). FDB files are present only if `fdbcli` works.
`fdb_status.jsonl` holds every raw `status json` sample, compacted and uncompressed, one JSON object per
line tagged with the run phase (`init`, `benchmark`, `post`, `verify`); failed or timed-out calls get an
`error` line. It is about 330 KB per sample on a 115-process cluster (~0.45 GiB per 12 h at the 30 s
interval). Turn it off with `fdb_status_raw: false` (`--fdb-status-raw=false`). For example,
`jq -c 'select(.phase=="verify") | .status' fdb_status.jsonl`.

Exit codes: 0 success, 1 benchmark/verify failure or worker error, 2 usage.

## Notes and deliberate choices

- Keys use a 70-character prefix charset (the spec text says 68; the listed charset has 70
  characters, so prefix work items = 70 first characters).
- `fdb_cpu.csv` records the CPU of every FDB process (not just storage, log and stateless ones) with all
  of its roles. The report's "CPU by role" table sums each process's mean CPU per role (a process with
  several roles counts under each, once in the total), gives total cores per 1,000 committed txn/s, and
  shows how evenly storage CPU is spread (min/median/mean/max/stddev, max/median, the hottest processes).
  Health warns when the hottest storage process is more than 1.8x the median.
- Every put (`load`, `run-put-object`, the overwrite runs) attaches `metadata_count` user-metadata items
  (default 6) of `metadata_size` bytes each (default 64), as `meta000`, `meta001`, ...; set
  `metadata_count: 0` to write objects without metadata.
- `run-list-delete-multi` is **destructive** (asks for confirmation; `--yes` skips it). Each worker owns a
  bucket and its threads split the bucket's two-character key prefixes between them (needs
  `padding_bytes >= 2`). A thread lists `page_size` keys with a continuation token, deletes exactly
  those keys with `delete_multi`, and repeats until its prefixes are empty. It reports `list_objects`
  (list only), `delete_multi` (delete only) and `list_delete_multi` (both) latencies.
  `kvrgw-perf-suite.sh` runs it instead of `run-delete-multi`, which stays available on its own.
- `run-put-object-overwrite` overwrites every loaded key (each thread loops over its whole slice).
  `run-put-object-overwrite-versioned` overwrites only `num_objects_to_overwrite` keys in total,
  shared evenly across all workers x threads (it must be `<= num_objects`). The limit matters
  because the version-count check is only meaningful if each key is overwritten repeatedly, so keep
  the set small enough for the run to loop over it several times, and because verification makes one
  `list_object_versions` call per overwritten key, so the set size bounds verify time.
- `load` leaves the buckets **unversioned**. `run-put-object-overwrite` requires that: init fails if a
  bucket's versioning is enabled or suspended (suspended means it was enabled once), a run aborts as
  soon as a put reports a new version (the runtime returns a version id only for a put into a
  versioning-enabled bucket), and verify lists through `list_object_versions` and fails on any version
  history (a non-null version, a delete marker, or a key with more than one version). The runtime does
  not record whether versioning was ever enabled and does not forbid going back to disabled, so state
  alone cannot prove "never versioned"; the version scan is what catches leftovers.
  `run-put-object-overwrite-versioned` asks for confirmation (`--yes` skips it) and then enables versioning
  on the buckets. That cannot be undone, old versions are never reclaimed, and `run-put-object-overwrite`
  will refuse those buckets afterwards; `load` into a new `--bucket-name-prefix` to get unversioned ones.
- `create_bucket` is idempotent in the runtime, so `load` checks `bucket_exists` first and
  fails if any target bucket already exists. `load --force` (config key `force`, `load` only)
  proceeds anyway: existing buckets and objects are kept (nothing is deleted), only missing
  buckets are created (their versioning state is left alone). Keys are put again, replacing
  existing objects in place if the bucket is unversioned. Verify expects exactly the keys this load writes, so use the same `num_objects`,
  `num_buckets` and `padding_bytes` as the earlier load; with different values the leftover keys
  are reported as "out of range" and verify fails (use `--no-verify` to skip it).
- The versioned-overwrite verify counts versions with `last_modified_unix >=` the second of
  the synchronised benchmark start (`RunControl.run_start_unix_ns`) instead of the
  invocation start second. It is never earlier, and it keeps back-to-back invocations from
  counting the previous run's final writes when both fall in the same wall-clock second.
- Load-style verify ignores well-formed `run-put-object` keys left in the buckets by earlier
  runs (they are regenerated and checked, then skipped), so `load`, `run-put-object`, then
  other `run-*` can be chained against the same buckets.
- `report_interval_ms: 0` disables periodic windows; workers then send one report covering
  the whole run.
- Server-side stats are recorded by the caller in this code base (as `perf_driver.cpp`
  does), so the worker wraps each call in `ScopedRequestLatency`. In the runs I checked, only
  8 KiB objects (above `max_kv_store`) showed batch commits; 100 B and 1 KiB objects showed none.
- The library never calls its FDB get/commit/scan timing hooks, so the report's server-side section shows only `avg_total` (and `disk` when non-zero).
- `fdbcli_path` defaults to `/opt/foundationdb/usr/bin/fdbcli`; if absent it falls back to `PATH`, then next to the binary, `/opt/kvrgw`.
- `cpu.csv`/report show system CPU in cores-equivalent (no CPU count is recorded).
- Errors are counted per library error code (`KVRGW_ERR_*`). The live window line shows
  `err=N [NO_SUCH_BUCKET x5, ...]`, `errors.csv` has one row per (window, op, code),
  `summary.json` has `error_codes` and `error_descriptions` (the `kvrgw_strerror` text), and
  `report` lists them under each op. Fatal errors name the bucket, an abbreviated key, the code
  and its text; failed `list_objects` calls are logged (first 20 per worker) as well as counted.
  A run whose only problems are counted, non-fatal errors (e.g. `list_objects`) still exits 0.
- `report --detailed` also prints an "FDB per-role statistics" table (from `fdb_process.csv`): for storage,
  log, grv_proxy, commit_proxy and resolver, one row each for CPU cores and, for storage and log, disk busy %.
  Each process's mean in each window is one value, and the row summarises the pool of processes x windows
  (`n` column), so a single hot process shows in the tail. Storage also gets `hottest/median` rows: in each
  window the busiest storage process over the median one, summarised across windows (`n` = windows). A
  process holding several roles (e.g. coordinator + grv_proxy) counts under each of them.
- `report --window D` (implies `--detailed`) widens the per-window tables to windows of D (a
  whole multiple of the recorded `report_interval_ms`; it cannot narrow windows). Counts,
  errors and rates are summed over the group, and p50/p99 come from the merged per-window
  histograms (not averaged). A trailing group of fewer windows is left out of the per-window
  tables but still counted in the run totals. To see finer detail, record with a smaller
  `report_interval_ms`.
