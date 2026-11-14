#!/bin/sh
# Rebuilds the tree-sitter grammar modules that internal/static embeds
# (ADR 0007). Run on linux/amd64 with curl, tar and sha256sum, for example:
#
#   docker run --rm -v "$PWD:/src" -w /src golang:1.27.4 internal/static/grammars/build.sh
#
# Every download is pinned by SHA-256 before it is unpacked. CREEP_GRAMMAR_CACHE
# may name a directory of already downloaded archives, named after the first
# argument of fetch (sdk.tar.gz, runtime.tar.gz, ...); they are checked too.
# The script rewrites the *.wasm files and SHA256SUMS next to it; commit both.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

WASI_SDK=wasi-sdk-34.0-x86_64-linux
WASI_SDK_URL=https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/$WASI_SDK.tar.gz
WASI_SDK_SUM=b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4
TS=https://github.com/tree-sitter

# fetch NAME URL SHA256 downloads (or reuses) an archive, checks it and
# unpacks it into $work/NAME.
fetch() {
	archive="$work/$1.tar.gz"
	if [ -n "${CREEP_GRAMMAR_CACHE:-}" ] && [ -f "$CREEP_GRAMMAR_CACHE/$1.tar.gz" ]; then
		cp "$CREEP_GRAMMAR_CACHE/$1.tar.gz" "$archive"
	else
		curl -fsSL --proto '=https' -o "$archive" "$2"
	fi
	echo "$3  $archive" | sha256sum -c - >/dev/null
	mkdir "$work/$1"
	tar -xzf "$archive" --strip-components=1 -C "$work/$1"
}

fetch sdk "$WASI_SDK_URL" "$WASI_SDK_SUM"
fetch runtime "$TS/tree-sitter/archive/refs/tags/v0.27.1.tar.gz" 982cd3d4d9eb7be18c243240a622423fd2e4ecb4bec2cd98832c2f3fa1f0f333
fetch python "$TS/tree-sitter-python/archive/refs/tags/v0.25.0.tar.gz" 4609a3665a620e117acf795ff01b9e965880f81745f287a16336f4ca86cf270c
fetch javascript "$TS/tree-sitter-javascript/archive/refs/tags/v0.25.0.tar.gz" 9712fc283d3dc01d996d20b6392143445d05867a7aad76fdd723824468428b86
fetch typescript "$TS/tree-sitter-typescript/archive/refs/tags/v0.23.2.tar.gz" 2c4ce711ae8d1218a3b2f899189298159d672870b5b34dff5d937bed2f3e8983

# build NAME SRC_DIR LANGUAGE_FUNCTION compiles one grammar with the runtime
# and glue.c into NAME.wasm. No WASI start function: the host calls exports.
build() {
	"$work/sdk/bin/clang" --target=wasm32-wasip1 --sysroot="$work/sdk/share/wasi-sysroot" \
		-O2 -mexec-model=reactor -ffile-prefix-map="$work"=. -ffile-prefix-map="$here"=. \
		-I"$work/runtime/lib/include" -I"$work/runtime/lib/src" -I"$2" \
		-DCREEP_LANGUAGE="$3" \
		"$work/runtime/lib/src/lib.c" "$2/parser.c" "$2/scanner.c" "$here/glue.c" \
		-Wl,--strip-all -o "$here/$1.wasm"
}

build python "$work/python/src" tree_sitter_python
build javascript "$work/javascript/src" tree_sitter_javascript
build typescript "$work/typescript/typescript/src" tree_sitter_typescript
build tsx "$work/typescript/tsx/src" tree_sitter_tsx

cd "$here"
sha256sum javascript.wasm python.wasm tsx.wasm typescript.wasm >SHA256SUMS
