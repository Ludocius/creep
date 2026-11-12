# Works with GNU make on Linux, macOS and Windows (Git Bash sh).

PKG     ?= ./...
MODULE  := github.com/Ludocius/creep
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X $(MODULE)/internal/buildinfo.version=$(VERSION) -X $(MODULE)/internal/buildinfo.commit=$(COMMIT)

ifeq ($(OS),Windows_NT)
EXE := .exe
endif
BIN := bin/creep$(EXE)

.PHONY: build test check fmt-check vet clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/creep

test:
	go test $(PKG)

check: fmt-check vet
	@# -race needs cgo; Go disables cgo when no C compiler is found (common on Windows).
	@if [ "$$(go env CGO_ENABLED)" = "1" ]; then \
		echo "go test -race ./..."; go test -race ./...; \
	else \
		echo "cgo disabled: running go test ./... without -race"; go test ./...; \
	fi

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

clean:
	rm -f bin/creep bin/creep.exe coverage.out
