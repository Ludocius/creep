# ADR 0008: wazero and tree-sitter grammars compiled to WebAssembly

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** @Ludocius

## Context

Issue #9 (split into #85–#88) extracts routes, sinks and auth checks from Python and JavaScript/TypeScript. That needs real parsers: regular expressions miss decorators, nested routers and aliased imports. tree-sitter has maintained grammars for all three, but its runtime and grammars are C. creep must stay one static binary built with `CGO_ENABLED=0`, and the files it parses are untrusted: a hostile repository chooses the input to a C parser.

Requirements: no cgo; a parser bug triggered by a file must not reach the host (memory, files, network); bounded memory and time per file; pinned, reviewable grammar artifacts; a small module graph (`make budget` caps it at 30 modules).

## Options

| Option | Pros | Cons |
|---|---|---|
| wazero running tree-sitter compiled to WebAssembly | Pure Go, no cgo; the C code runs in a sandbox with its own linear memory, a page cap and no host access unless granted; one transitive module (`golang.org/x/sys`) | Guest code runs several times slower than native; compiling a grammar takes about a second; grammars become binary artifacts we must build and pin |
| `github.com/tree-sitter/go-tree-sitter` (cgo) | Official binding, native speed | Needs cgo and a C toolchain per target; a parser memory bug corrupts the host process |
| A pure-Go tree-sitter port | No WebAssembly step | Young, single-maintainer projects; every grammar must be ported or generated; a bug runs with full host privileges |
| Go-only heuristics (regexp, hand-written lexers) | No dependency | Misses real routes and sinks; one parser per framework to maintain |

## Decision

Use `github.com/tetratelabs/wazero` v1.12.0 to run tree-sitter grammars built to `wasm32-wasip1`: it keeps the static binary and puts the C parser behind a sandbox boundary. wazero raises the module's `go` directive to 1.25 (the toolchain is already 1.27).

**Grammar artifacts.** `internal/static/grammars/build.sh` builds one module per language (`python`, `javascript`, `typescript`, `tsx`) from:

| Input | Version | License |
|---|---|---|
| tree-sitter runtime (`lib/`) | v0.27.1 | MIT |
| tree-sitter-python | v0.25.0 | MIT |
| tree-sitter-javascript | v0.25.0 | MIT |
| tree-sitter-typescript (`typescript`, `tsx`) | v0.23.2 | MIT |
| wasi-sdk (clang, wasi-libc, compiler-rt) | 34.0 | Apache-2.0 WITH LLVM-exception; wasi-libc also MIT and CC0 parts |
| `grammars/glue.c` (ours) | — | Apache-2.0 |

Every archive is downloaded from its GitHub release or tag and checked against a SHA-256 pinned in the script before it is unpacked. Each module links the runtime, one grammar and `glue.c`, which exports a small API: allocate, parse into flat fixed-size records, and read symbol and field names. The script writes `grammars/SHA256SUMS`; `TestEmbeddedGrammarsMatchSums` fails if a `.wasm` file and the sums disagree, so a swapped grammar shows in review. The build uses `-ffile-prefix-map` so its output does not depend on the build directory. Third-party notices are in `NOTICE`.

**Sandbox.** The modules import only `fd_write`, `fd_seek`, `fd_close` and `clock_time_get` from WASI, and `TestGrammarImportsOnlyAllowedWASI` fails on any new import. wazero's defaults give them no preopened directories, no environment or arguments, discarded stdout and stderr, and a fake clock. `glue.c` is the one allowlisted non-Go source (`foreignAllowed`); its directory has no Go files, so the go command never compiles it.

**Network rule.** wazero links package `net` for WASI sockets, which a guest gets only when the host passes listeners through `wazero/experimental/sock`. The net-reach check therefore exempts exactly `wazero` and `wazero/imports/wasi_snapshot_preview1`, and only when imported by `internal/static` (`netReachAllowed`). Importing `experimental/sock`, or wazero from any other package, still fails `make budget`.

**Limits.** Each parse uses a fresh module instance, so no state carries over between files. A file over 1 MiB is not parsed; guest memory is capped at 256 MiB; the tree at 2^20 nodes; one parse at 30 s (`WithCloseOnContextDone`). A guest trap or a hit limit returns `ErrResourceLimit`. The host validates every record (parent order, symbol and field ranges, byte offsets inside the file) and returns `ErrInvalidTree` instead of trusting guest memory.

## Consequences

- `docs/adr/dependencies.txt` lists wazero; `make budget` enforces it. `golang.org/x/sys` comes in as wazero's only dependency.
- Grammar upgrades are a reviewed change to `build.sh` hashes plus regenerated `.wasm` files and `SHA256SUMS`. Building needs linux/amd64 (or a Linux container) and network access to GitHub; running creep does not.
- The binary grows by about 4 MiB of grammars plus wazero; the 16 MiB binary cap still holds.
- Parsing is slow next to native tree-sitter (about 12 s for a 1 MiB Python file on a laptop, `BenchmarkParseMaxFile`) and each grammar compiles once per run. Faster paths (instance reuse, compilation cache, smaller file cap) are follow-ups measured with that benchmark.
- No third language before v1.0 (maintainability matrix, architecture §6); each new grammar needs this ADR's build and conformance tests.
