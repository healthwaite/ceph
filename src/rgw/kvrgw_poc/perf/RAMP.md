# kvrgw-perf: open-loop ramp (`--ramp`) — plan

Find the **maximum sustainable throughput** of the PUT path by offering a fixed-rate,
open-loop load that steps up linearly, judging every step against explicit criteria,
and stopping at the first step that fails. Builds on the async open-loop mode
(`driver_mode: async`, `rate_ops_per_sec`).

Decisions (agreed 2026-11-22):

| Topic | Decision |
|---|---|
| Rate units | Cluster totals (ops/s over all workers), split evenly across workers |
| Latency criterion | End-to-end p99 (from scheduled send time) below `ramp_max_p99_ms` (default 50 ms) |
| Missed arrivals | At most `ramp_max_missed_pct` of scheduled arrivals (default 0.1%) |
| Search | Linear: `start`, `start + step`, `start + 2·step`, …; stop at the first failing step |
| Step timing | `ramp_warmup` 30 s then `ramp_measure` 60 s per step (rounded up to whole report windows) |
| CLI | `--ramp` flag on `run-put-object`, `run-put-object-overwrite`, `run-put-object-overwrite-versioned` |
| Verify | Runs at the end as usual (key counters stay contiguous across steps) |
| Arrivals | `arrival: constant` (default) or `poisson`, for every open-loop run |

## Configuration

| key | default | meaning |
|---|---|---|
| `ramp` | false | `--ramp`: run the command as an open-loop ramp (implies `driver_mode: async`) |
| `ramp_start_rate` | — (required) | first step's target, ops/s, cluster total |
| `ramp_step_rate` | = `ramp_start_rate` | increment per step, ops/s, cluster total |
| `ramp_max_rate` | 0 (none) | stop after the step at or below this rate |
| `ramp_warmup` | `30s` | not measured; lets the new rate settle |
| `ramp_measure` | `60s` | the measured part of each step |
| `ramp_max_p99_ms` | 50 | end-to-end p99 must be below this |
| `ramp_max_missed_pct` | 0.1 | missed / scheduled arrivals |
| `ramp_max_error_pct` | 0.1 | errors / (completed + errors) |
| `ramp_min_achieved_pct` | 99 | completed / target over the measure window |
| `ramp_max_backlog_growth_pct` | 50 | outstanding ops at the end of the measure window vs its start |
| `arrival` | `constant` | `constant` or `poisson` inter-arrival times |

`duration` is optional with `--ramp` (an overall cap); `ops` is not allowed. `rate_ops_per_sec`
is ignored (the ramp sets it).

## Mechanism

- **One run, rate changed in-band.** The controller already holds a `RunBenchmark` stream
  to every worker. A new `RunControl.set_rate {step, rate_ops_per_sec (per worker),
  effective_at_unix_ns}` tells each worker to switch at a common future window boundary.
  The controller sends the next step's change one step ahead, so steps are contiguous;
  when a step fails it cancels the run (the next step may have started briefly; it is
  not evaluated).
- **No burst at a change.** At `effective_at` each generator re-anchors its schedule there
  (offset 0, new period); its key counter continues, so keys stay `[0, issued)`.
- **Schedule.** Deadlines are `anchor + offset`, with `offset` a double in seconds:
  `k · D / rate` for constant arrivals, or a running sum of exponential samples
  (mean `D / rate`, per-generator seeded RNG) for Poisson. No integer-period drift.
- **Steps are whole windows** of `report_interval_ms`: `warm` windows then `meas` windows.
  Results come from merging the measure windows' histograms and counters.

## Per-step measurements

From the measure windows, summed / merged over workers:

- target, scheduled (`send_lag` count + missed), completed, achieved ops/s and % of target
- missed %, error %
- end-to-end latency (from scheduled time) p50 / p99 / p99.9
- service time (send → completion, new `service_time` histogram) p99
- send lag p99
- outstanding ops (new per-window gauge) at the start and end of the measure window
- busiest driver thread's busy %

## Verdict per step

A step **passes** when every criterion holds: achieved ≥ `ramp_min_achieved_pct`,
missed ≤ `ramp_max_missed_pct`, errors ≤ `ramp_max_error_pct`, p99 < `ramp_max_p99_ms`,
backlog growth ≤ `ramp_max_backlog_growth_pct`. The failing criteria are listed.

A step is **generator-limited** (result invalid, ramp stops) when the busiest driver is
≥ 85% busy, or send lag is significant (p99 ≥ 1 ms and ≥ 10% of op p99). The hint: raise
`driver_threads` or `worker_count`. A Little's-law check flags steps whose expected
in-flight ops (rate × p99) approach the outstanding cap (`max_inflight_ops` × workers),
where misses would come from the cap rather than the system.

Stop reasons: first failing step, generator-limited, `ramp_max_rate` reached, `duration`
cap, interrupt. Results: **max sustainable** = highest passing target; **max achieved** =
highest completed ops/s in any step.

## Outputs

- Live line per step: target, achieved, p99, missed %, verdict and failing criteria.
- `ramp_steps.csv`: one row per evaluated step with every measurement and the verdict.
- `summary.json`: `ramp` with steps, max sustainable, max achieved, stop reason.
- `kvrgw-perf report`: a Ramp section with the step table and both results.

## Phases

1. Plan (this file).
2. Worker: `SetRate`, re-anchored schedule, `arrival: poisson`, per-window `outstanding`
   gauge, `service_time` histogram. Proto field additions only.
3. Controller: config/flags/validation, the step driver, per-step evaluation, outputs,
   report section, unit tests for evaluation and step planning.
4. Validate locally (constant and Poisson ramps, verify PASS), docs, push.
