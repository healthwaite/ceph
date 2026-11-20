# Build, test and run the kvrgw-perf harness in a container.
#
# Host targets (run these on your machine):
#   docker-image   build the build-container image from Dockerfile.build
#   shell          start a container from the image with the ceph tree mounted at
#                  /workspace (CMD='make build' runs one command instead of a shell)
#
# In-container targets (run these inside `make shell`; they refuse to run on the host):
#   build          compile kvrgw-perf (Go controller) and kvrgw-perf-worker (C++)
#   test           build and run the C++ and Go unit tests

POC_DIR   := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
PERF_DIR  := $(POC_DIR)/perf
CEPH_ROOT := $(abspath $(POC_DIR)/../../..)

DOCKER     ?= docker
IMAGE      ?= kvrgw-perf-build
CMD        ?= /bin/bash
# Extra `docker run` arguments, e.g. EXTRA_ARGS='--network mynet -e FDB_CLUSTER_FILE=/tmp/fdb.cluster'
EXTRA_ARGS ?=
TTY_FLAGS  := $(shell [ -t 0 ] && echo -it)

FDB_ROOT   ?= /opt/foundationdb
BUILD_JOBS ?= $(shell nproc)
PERF_TESTS := perf_keys_test perf_histogram_test perf_verify_test perf_stats_test

IN_CONTAINER := $(or $(wildcard /.dockerenv),$(wildcard /run/.containerenv))

define require_host
@if [ -n "$(IN_CONTAINER)" ]; then \
	echo "'make $@' runs on the host; run it outside the build container" >&2; exit 1; fi
endef

define require_container
@if [ -z "$(IN_CONTAINER)" ]; then \
	echo "'make $@' runs inside the build container; start one with 'make shell'" >&2; exit 1; fi
endef

.DEFAULT_GOAL := help
.PHONY: help docker-image shell build test

help:
	@sed -n '1,/^POC_DIR/p' $(lastword $(MAKEFILE_LIST)) | sed '$$d' | sed 's/^# \{0,1\}//'

docker-image:
	$(require_host)
	$(DOCKER) build -t "$(IMAGE)" - < "$(PERF_DIR)/Dockerfile.build"

shell: docker-image
	$(DOCKER) run --rm $(TTY_FLAGS) \
		--user "$$(id -u):$$(id -g)" \
		--mount "type=bind,source=$(CEPH_ROOT),target=/workspace" \
		$(EXTRA_ARGS) \
		"$(IMAGE)" $(CMD)

# Outputs: build/kvrgw-perf, build/perf/kvrgw-perf-worker, build/kvrgw-perf.yaml
build:
	$(require_container)
	cd "$(POC_DIR)" && cmake -S backend -B build -DKVRGW_BUILD_PERF_HARNESS=ON -DFDB_ROOT="$(FDB_ROOT)"
	cd "$(POC_DIR)" && cmake --build build -j"$(BUILD_JOBS)" --target kvrgw-perf-worker kvrgw-perf

test: build
	$(require_container)
	cd "$(POC_DIR)" && cmake --build build -j"$(BUILD_JOBS)" --target $(PERF_TESTS)
	cd "$(POC_DIR)" && ctest --test-dir build -R '^perf_' --output-on-failure
	cd "$(PERF_DIR)/controller" && go test ./...
