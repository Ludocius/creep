# Works with GNU make on Linux, macOS and Windows (Git Bash sh).

PKG     ?= ./...
MODULE  := github.com/Ludocius/creep
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDINFO := $(MODULE)/internal/buildinfo
# Characters allowed in version and commit; anything else is dropped so a tag
# name can never break out of the -ldflags quoting.
SAFE_CHARS := A-Za-z0-9._+-

ifeq ($(OS),Windows_NT)
EXE := .exe
endif
BIN := bin/creep$(EXE)

.PHONY: build test check fmt-check tidy vet budget clean

# VERSION and COMMIT reach the recipe through the environment, never as shell
# text, and are filtered to SAFE_CHARS before use.
build: export CREEP_VERSION = $(VERSION)
build: export CREEP_COMMIT = $(COMMIT)
build:
	@v="$$(printf '%s' "$$CREEP_VERSION" | tr -cd '$(SAFE_CHARS)')"; \
	c="$$(printf '%s' "$$CREEP_COMMIT" | tr -cd '$(SAFE_CHARS)')"; \
	set -x; go build -trimpath -ldflags "-s -w -X $(BUILDINFO).version=$${v:-dev} -X $(BUILDINFO).commit=$${c:-unknown}" -o $(BIN) ./cmd/creep

test:
	go test $(PKG)

check: fmt-check tidy vet budget
	@# -race needs cgo; Go disables cgo when no C compiler is found (common on Windows).
	@if [ "$$(go env CGO_ENABLED)" = "1" ]; then \
		echo "go test -race ./..."; go test -race ./...; \
	else \
		echo "cgo disabled: running go test ./... without -race"; go test ./...; \
	fi

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

# Fails when go.mod or go.sum differ from what go mod tidy would write, so a
# used dependency cannot hide behind a stale // indirect comment.
tidy:
	go mod tidy -diff

vet:
	go vet ./...

# Dependency allowlist, network/exec import rules, module and binary caps,
# file length, workflow pinning.
budget:
	go run ./internal/tools/budget

clean:
	rm -f bin/creep bin/creep.exe coverage.out
