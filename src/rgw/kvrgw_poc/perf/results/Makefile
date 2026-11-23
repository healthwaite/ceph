# Re-run `kvrgw-perf report` on the results in this directory, in the runtime container
# (the image built by `make image` in ../, which has kvrgw-perf on its PATH). Needs Docker only:
# no FoundationDB, and the results are mounted read-only.
#
#   image    build the runtime image (runs `make image` in ..; slow, only needed once)
#   shell    shell in the container; the results are at /results (the working directory)
#   report   run one report; prints to stdout, so redirect it to keep it:
#              make report DIR=suite-20261120T162143Z/01-run-put-object \
#                          ARGS="--window 10m --warmup 1h --detailed" > 01.txt
#
# Report options (see `kvrgw-perf report`): --warmup D  --window D  --detailed
#   --deviation N  --per-server.  --window must be a whole multiple of the 10s recorded window,
#   and the FDB tables need FDB samples at least that often (so --window 30s or more).

HERE   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DOCKER ?= docker
IMAGE  ?= kvrgw-perf:latest
# Same default as ../deploy/kvrgw-perf-run.sh (glibc 2.34+ images on Docker < 20.10.10).
DOCKER_RUN_ARGS ?= --security-opt seccomp=unconfined
TTY := $(shell [ -t 0 ] && echo -t)
DIR  ?=
ARGS ?=

RUN = $(DOCKER) run --rm $(DOCKER_RUN_ARGS) --user "$$(id -u):$$(id -g)" \
	-v "$(HERE)":/results:ro -w /results

.DEFAULT_GOAL := help
.PHONY: help image shell report check-image

help:
	@sed -n '1,/^HERE/p' $(lastword $(MAKEFILE_LIST)) | sed '$$d' | sed 's/^# \{0,1\}//'

image:
	$(MAKE) -C "$(HERE)/.." image

check-image:
	@$(DOCKER) image inspect "$(IMAGE)" >/dev/null 2>&1 || { \
		echo "image $(IMAGE) not found: run 'make image' (or set IMAGE=...)" >&2; exit 1; }

shell: check-image
	@$(RUN) -i $(TTY) "$(IMAGE)" /bin/bash

report: check-image
	@[ -n "$(DIR)" ] || { echo "usage: make report DIR=<results dir, relative to here> [ARGS=\"--window 10m ...\"]" >&2; exit 2; }
	@[ -d "$(HERE)/$(DIR)" ] || { echo "no such directory: $(DIR)" >&2; exit 2; }
	@$(RUN) -i "$(IMAGE)" kvrgw-perf report "$(DIR)" $(ARGS)
