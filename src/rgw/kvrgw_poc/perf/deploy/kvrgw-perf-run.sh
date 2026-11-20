#!/usr/bin/env bash
# Run kvrgw-perf in a container on this machine (copied here by `make deploy`).
#
#   ./kvrgw-perf-run.sh                          # shell in the container; then run kvrgw-perf ...
#   ./kvrgw-perf-run.sh kvrgw-perf load          # or run one command
#
# Loads the image from the tarball next to this script if it isn't loaded yet, mounts the
# host FDB cluster file at /etc/foundationdb/fdb.cluster, and keeps results in ./perf-results.
#
# Environment overrides:
#   CLUSTER_FILE     host cluster file             (default /etc/foundationdb/fdb.cluster)
#   RESULTS_DIR      host dir for perf-results     (default <this dir>/perf-results)
#   DOCKER_RUN_ARGS  extra `docker run` arguments  (default --security-opt seccomp=unconfined,
#                    needed for glibc 2.34+ images on Docker < 20.10.10; set to "" to disable)
#   DOCKER           docker binary                 (default docker)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DOCKER=${DOCKER:-docker}
CLUSTER_FILE=${CLUSTER_FILE:-/etc/foundationdb/fdb.cluster}
RESULTS_DIR=${RESULTS_DIR:-$here/perf-results}
DOCKER_RUN_ARGS=${DOCKER_RUN_ARGS---security-opt seccomp=unconfined}

die() { echo "error: $*" >&2; exit 1; }

[ -f "$here/kvrgw-perf.image" ] || die "no kvrgw-perf.image next to this script (run 'make deploy')"
image=$(cat "$here/kvrgw-perf.image")
tarball="$here/kvrgw-perf-${image#*:}.tar.gz"
[ -f "$CLUSTER_FILE" ] || die "FDB cluster file $CLUSTER_FILE not found (set CLUSTER_FILE)"

if ! "$DOCKER" image inspect "$image" >/dev/null 2>&1; then
    [ -f "$tarball" ] || die "image $image is not loaded and $tarball is missing"
    echo "loading $image from $(basename "$tarball") ..." >&2
    "$DOCKER" load -i "$tarball"
fi

mkdir -p "$RESULTS_DIR"
cmd=("$@")
[ $# -gt 0 ] || cmd=(/bin/bash)
tty=(-i)
[ -t 0 ] && tty=(-it)

# DOCKER_RUN_ARGS is deliberately unquoted so it splits into separate arguments.
# shellcheck disable=SC2086
exec "$DOCKER" run --rm "${tty[@]}" --network host $DOCKER_RUN_ARGS \
    --user "$(id -u):$(id -g)" \
    -v "$CLUSTER_FILE":/etc/foundationdb/fdb.cluster:ro \
    -v "$RESULTS_DIR":/work/perf-results \
    "$image" "${cmd[@]}"
