# Works with GNU make on Linux, macOS and Windows (Git Bash sh).

PKG     ?= ./...
MODULE  := github.com/sneakercreepers/creep
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

.PHONY: build test check fmt-check tidy vet budget rulesets clean

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

# Dependency allowlist, network/exec import rules, architecture layer table,
# non-Go sources and workspace files, module and binary caps, file length,
# workflow pinning, agent-loop policy phrases.
budget:
	go run ./internal/tools/budget

# Creates or updates each ruleset in .github/rulesets (file name = ruleset name),
# then applies .github/settings, so re-running after a reviewed change is safe.
# Needs gh authenticated as an admin.
REPO ?= sneakercreepers/creep
rulesets: repo-settings
	@for f in .github/rulesets/*.json; do \
		name="$$(basename "$$f" .json)"; \
		id="$$(gh api "repos/$(REPO)/rulesets" --jq ".[] | select(.name == \"$$name\") | .id")" || exit 1; \
		if [ -n "$$id" ]; then \
			echo "update $$name ($$id)"; gh api -X PUT "repos/$(REPO)/rulesets/$$id" --input "$$f" >/dev/null || exit 1; \
		else \
			echo "create $$name"; gh api -X POST "repos/$(REPO)/rulesets" --input "$$f" >/dev/null || exit 1; \
		fi; \
	done

# The release environment only deploys v* tags. The tag policy is added only when
# missing because POSTing a duplicate fails.
repo-settings:
	@echo "update actions permissions"; gh api -X PUT "repos/$(REPO)/actions/permissions" --input .github/settings/actions-permissions.json >/dev/null
	@echo "update environment release"; gh api -X PUT "repos/$(REPO)/environments/release" --input .github/settings/release-environment.json >/dev/null
	@n="$$(gh api "repos/$(REPO)/environments/release/deployment-branch-policies" --jq '[.branch_policies[] | select(.name == "v*" and .type == "tag")] | length')" || exit 1; \
	if [ "$$n" = 0 ]; then \
		echo "add tag policy v*"; gh api -X POST "repos/$(REPO)/environments/release/deployment-branch-policies" -f name='v*' -f type=tag >/dev/null || exit 1; \
	fi

clean:
	rm -f bin/creep bin/creep.exe coverage.out
