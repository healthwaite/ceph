# Build, test and run the kvrgw-perf harness in a container.
#
# Host targets (run these on your machine):
#   docker-image   build the build-container image from Dockerfile.build
#   shell          start a container from the image with the ceph tree mounted at
#                  /workspace (CMD='make build' runs one command instead of a shell)
#   image          build a runtime image containing kvrgw-perf (builds, then `make stage`)
#   save           save that image to dist/kvrgw-perf-<tag>.tar.gz
#   deploy         rsync the tarball and deploy/kvrgw-perf-run.sh to DEPLOY_HOST:DEPLOY_DIR
#                  (default client:dev/kvrgw-perf)
#
# In-container targets (run these inside `make shell`; they refuse to run on the host):
#   build          compile kvrgw-perf (Go controller) and kvrgw-perf-worker (C++)
#   test           build and run the C++ and Go unit tests
#   stage          build, then copy the runtime files into dist/image (used by `make image`)

POC_DIR   := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
PERF_DIR  := $(POC_DIR)/perf
CEPH_ROOT := $(abspath $(POC_DIR)/../../..)

DOCKER     ?= docker
IMAGE      ?= kvrgw-perf-build
CMD        ?= /bin/bash
# Extra `docker run` arguments, e.g. EXTRA_ARGS='--network mynet -e FDB_CLUSTER_FILE=/tmp/fdb.cluster'
EXTRA_ARGS ?=
TTY_FLAGS  := $(shell [ -t 0 ] && echo -it)

# Runtime image / deployment (image, save, deploy)
RUNTIME_IMAGE ?= kvrgw-perf
DEPLOY_HOST   ?= client
DEPLOY_DIR    ?= dev/kvrgw-perf
DIST          := $(PERF_DIR)/dist
STAGE_DIR     := $(DIST)/image
# Image tag: short git sha, with -dirty if the kvrgw_poc tree has uncommitted changes.
TAG           ?= $(shell git -C "$(POC_DIR)" rev-parse --short HEAD 2>/dev/null || echo dev)$(shell git -C "$(POC_DIR)" diff --quiet HEAD -- . 2>/dev/null || echo -dirty)
TARBALL       := $(DIST)/kvrgw-perf-$(TAG).tar.gz

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
.PHONY: help docker-image shell image save deploy build test stage

help:
	@sed -n '1,/^POC_DIR/p' $(lastword $(MAKEFILE_LIST)) | sed '$$d' | sed 's/^# \{0,1\}//'

docker-image:
	$(require_host)
	$(DOCKER) build -t "$(IMAGE)" - < "$(PERF_DIR)/Dockerfile.build"

shell: docker-image
	$(require_host)
	$(DOCKER) run --rm $(TTY_FLAGS) \
		--user "$$(id -u):$$(id -g)" \
		--mount "type=bind,source=$(CEPH_ROOT),target=/workspace" \
		$(EXTRA_ARGS) \
		"$(IMAGE)" $(CMD)

# Runtime image with kvrgw-perf, the worker, libkvrgw.so, libfdb_c.so and fdbcli (Dockerfile.runtime).
image: docker-image
	$(require_host)
	$(MAKE) shell CMD='make stage'
	BUILDX_NO_DEFAULT_ATTESTATIONS=1 $(DOCKER) build -f "$(PERF_DIR)/Dockerfile.runtime" \
		-t "$(RUNTIME_IMAGE):$(TAG)" -t "$(RUNTIME_IMAGE):latest" "$(STAGE_DIR)"

save: image
	$(require_host)
	rm -f "$(DIST)"/kvrgw-perf-*.tar.gz
	$(DOCKER) save "$(RUNTIME_IMAGE):$(TAG)" | gzip > "$(TARBALL)"
	echo "$(RUNTIME_IMAGE):$(TAG)" > "$(DIST)/kvrgw-perf.image"
	@ls -lh "$(TARBALL)"

deploy: save
	$(require_host)
	ssh "$(DEPLOY_HOST)" mkdir -p "$(DEPLOY_DIR)"
	rsync -av --partial --progress \
		"$(TARBALL)" "$(DIST)/kvrgw-perf.image" "$(PERF_DIR)/deploy/kvrgw-perf-run.sh" \
		"$(DEPLOY_HOST):$(DEPLOY_DIR)/"
	@echo "On $(DEPLOY_HOST): cd $(DEPLOY_DIR) && ./kvrgw-perf-run.sh"

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

# Copy everything the runtime image needs into dist/image (flat, as in /opt/kvrgw).
stage: build
	$(require_container)
	rm -rf "$(STAGE_DIR)" && mkdir -p "$(STAGE_DIR)"
	cp -L "$(POC_DIR)/build/kvrgw-perf" "$(POC_DIR)/build/perf/kvrgw-perf-worker" \
		"$(POC_DIR)/build/libkvrgw.so" "$(POC_DIR)/build/kvrgw-perf.yaml" \
		"$(FDB_ROOT)/usr/lib64/libfdb_c.so" "$(FDB_ROOT)/usr/bin/fdbcli" "$(STAGE_DIR)/"
