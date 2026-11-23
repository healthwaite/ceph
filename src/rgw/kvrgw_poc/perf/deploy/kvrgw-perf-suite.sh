#!/usr/bin/env bash
# Run the whole perf suite: `load`, then every run-* benchmark in the order its section appears in
# kvrgw-perf.yaml, then `report` for each, and collect everything into one directory.
#
#   ./kvrgw-perf-suite.sh [kvrgw-perf global flags...]     # e.g. --workers 4 --threads 16
#
# Uses kvrgw-perf-run.sh next to this script (so it runs in the container). Extra arguments are
# passed to load and to every run-* command; --yes is always added (run-list-delete-multi is
# destructive and would otherwise prompt), so don't pass --ops/--duration (not valid for load; set
# them in the yaml, via CONFIG). Output is shown live and also saved.
#
# run-delete-multi is skipped: run-list-delete-multi replaces it in the suite (it stays runnable by hand).
# run-list-objects is run twice: first with --single-thread-mode (directory NN-run-list-objects-single-thread,
# using the yaml's other run-list-objects settings), then with the yaml settings as they are.
#
# Layout of $SUITE_DIR (default <RESULTS_DIR>/suite-<UTC timestamp>):
#   NN-<command>/        raw artifacts of that invocation (CSV, JSON, logs: the controller's run dir)
#   stdout/NN-<command>.log   everything the invocation printed
#   reports/NN-<command>.txt  `kvrgw-perf report` output for that run
#   kvrgw-perf.yaml      the config the order was taken from
#   suite.log            the suite's own progress, with per-step exit codes
#   fdb_status_end.json  `status json` after the last benchmark (if fdbcli works)
#   ../<suite>.tar.gz    everything above
#
# Environment:
#   CONFIG        host yaml to use instead of the one in the image (mounted over ./kvrgw-perf.yaml)
#   RESULTS_DIR   host results dir, as for kvrgw-perf-run.sh   (default <this dir>/perf-results)
#   SUITE_DIR     host directory for this suite, must be inside RESULTS_DIR
#   REPORT_ARGS   extra arguments for every `report`, e.g. "--warmup 10s --detailed"
#   ONLY          space-separated subset of steps to run, by label (default: all); the labels are
#                 the run-* section names plus run-list-objects-single-thread
# A failing run-* is recorded and the suite carries on; a failing load stops it. The exit status
# is non-zero if any step failed.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export RESULTS_DIR=${RESULTS_DIR:-$here/perf-results}
runner=$here/kvrgw-perf-run.sh
[ -x "$runner" ] || { echo "error: $runner not found or not executable" >&2; exit 1; }

suite=suite-$(date -u +%Y%m%dT%H%M%SZ)
SUITE_DIR=${SUITE_DIR:-$RESULTS_DIR/$suite}
case $(realpath -m "$SUITE_DIR")/ in
    "$(realpath -m "$RESULTS_DIR")"/*) ;;
    *) echo "error: SUITE_DIR must be inside RESULTS_DIR ($RESULTS_DIR)" >&2; exit 1 ;;
esac
suite=$(basename "$SUITE_DIR")
cdir=/work/perf-results/${SUITE_DIR#"$(realpath -m "$RESULTS_DIR")"/}   # same dir, as the container sees it
mkdir -p "$SUITE_DIR/stdout" "$SUITE_DIR/reports"
exec 3>&1
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$SUITE_DIR/suite.log" >&3; }

if [ -n "${CONFIG:-}" ]; then
    [ -f "$CONFIG" ] || { echo "error: CONFIG $CONFIG not found" >&2; exit 1; }
    cp "$CONFIG" "$SUITE_DIR/kvrgw-perf.yaml"
    DOCKER_RUN_ARGS="${DOCKER_RUN_ARGS---security-opt seccomp=unconfined} -v $(realpath "$CONFIG"):/work/kvrgw-perf.yaml:ro"
    export DOCKER_RUN_ARGS
    yaml=$CONFIG
else
    "$runner" cat /opt/kvrgw/kvrgw-perf.yaml > "$SUITE_DIR/kvrgw-perf.yaml" \
        || { echo "error: cannot read kvrgw-perf.yaml from the image" >&2; exit 1; }
    yaml=$SUITE_DIR/kvrgw-perf.yaml
fi

# Steps are "label|command|extra flags". The run-* sections come in file order (commented-out
# sections do not match); run-list-objects is preceded by a single_thread_mode run of it, whose
# label (and so output directory) says so.
steps=()
while read -r c; do
    [ "$c" = run-delete-multi ] && continue   # superseded by run-list-delete-multi
    [ "$c" = run-list-objects ] && steps+=("run-list-objects-single-thread|run-list-objects|--single-thread-mode")
    steps+=("$c|$c|")
done < <(sed -n 's/^\(run-[A-Za-z0-9-]*\):.*/\1/p' "$yaml")
if [ -n "${ONLY:-}" ]; then
    keep=()
    for st in "${steps[@]}"; do
        for o in $ONLY; do [ "${st%%|*}" = "$o" ] && keep+=("$st"); done
    done
    steps=("${keep[@]}")
fi
[ ${#steps[@]} -gt 0 ] || { echo "error: no run-* sections found in $yaml" >&2; exit 1; }
labels=()
for st in "${steps[@]}"; do labels+=("${st%%|*}"); done

log "suite $suite: load, ${labels[*]}"
log "extra args: $* ; report args: ${REPORT_ARGS:-<none>}"

failed=()
n=0
step() {   # step <label> <command> [flags]   (runs the benchmark, then its report)
    local label=$1 cmd=$2 name flags=()
    [ -z "${3:-}" ] || flags=("$3")
    name=$(printf '%02d-%s' "$n" "$label")
    log "=== $name: kvrgw-perf ${extra[*]} ${flags[*]} --yes --run-dir $cdir/$name $cmd"
    "$runner" kvrgw-perf "${extra[@]}" "${flags[@]}" --yes --run-dir "$cdir/$name" "$cmd" 2>&1 | tee "$SUITE_DIR/stdout/$name.log"
    local rc=${PIPESTATUS[0]}
    log "$name exit status $rc"
    if [ -d "$SUITE_DIR/$name" ] && [ "$cmd" != load ]; then
        # shellcheck disable=SC2086
        "$runner" kvrgw-perf report "$cdir/$name" ${REPORT_ARGS:-} 2>&1 | tee "$SUITE_DIR/reports/$name.txt"
        [ "${PIPESTATUS[0]}" -eq 0 ] || { log "$name: report failed"; failed+=("$name(report)"); }
    fi
    [ "$rc" -eq 0 ] || failed+=("$name")
    return "$rc"
}

extra=("$@")
step load load || { log "load failed; stopping"; exit 1; }
for st in "${steps[@]}"; do
    IFS='|' read -r label cmd flags <<<"$st"
    n=$((n + 1))
    step "$label" "$cmd" "$flags"
done

# Raw cluster state after the last benchmark; best effort.
"$runner" fdbcli --exec 'status json' > "$SUITE_DIR/fdb_status_end.json" 2>/dev/null || rm -f "$SUITE_DIR/fdb_status_end.json"

tar -C "$(dirname "$SUITE_DIR")" -czf "$SUITE_DIR.tar.gz" "$suite" && log "artifacts: $SUITE_DIR (and $SUITE_DIR.tar.gz)"
if [ ${#failed[@]} -gt 0 ]; then
    log "FAILED: ${failed[*]}"
    exit 1
fi
log "all steps OK"
