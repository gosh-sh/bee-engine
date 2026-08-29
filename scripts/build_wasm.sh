#!/usr/bin/env bash
# Build WASM artifacts with machine paths stripped from the binaries.
#
# rustc embeds absolute paths (panic locations, debug info) into the artifact;
# without remapping the deployed .wasm leaks /Users/<name>/... of whoever built
# it. --remap-path-prefix rewrites them at compile time. rustc applies the LAST
# matching rule, so generic prefixes go first, specific ones last.
#
# Note: changing RUSTFLAGS invalidates the cargo cache — the first build after
# this script is introduced (or after editing the flags) is a full rebuild.
#
# Usage: scripts/build_wasm.sh [sdk|verifier|all]   (default: all)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

export RUSTFLAGS="${RUSTFLAGS:-} \
--remap-path-prefix=$HOME=/home \
--remap-path-prefix=$REPO_ROOT=/build \
--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

# Gate: fail the build if any machine path survived into the artifact.
leak_check() {
    local artifact="$1"
    if strings "$artifact" | grep -qE "/Users/|/home/[a-z]+/"; then
        echo "LEAK: machine paths in $artifact:" >&2
        strings "$artifact" | grep -oE "(/Users/|/home/[a-z]+/)[^\"']{0,80}" | sort -u | head >&2
        exit 1
    fi
    echo "OK: no machine paths in $artifact"
}

build_sdk() {
    echo "=== bee_sdk (browser WASM, wasm-pack) ==="
    (cd "$REPO_ROOT/bee_sdk" && rm -rf pkg && wasm-pack build --target web)
    leak_check "$REPO_ROOT/bee_sdk/pkg/bee_sdk_bg.wasm"
}

# Both verifiers build the same way; v1 stays buildable because its binary is
# whitelisted on the nodes and v1 miners still call it.
build_one_verifier() {
    local crate="$1" artifact="$2"
    echo "=== $crate (WASI component, wasm32-wasip2) ==="
    # If `wit` was updated, run `cargo component bindings` first (see bee_verifier/README.md).
    # -Zbuild-std rebuilds std locally — without the remap its .rustup paths
    # would leak into the artifact too.
    # immediate-abort used to be the build-std feature `panic_immediate_abort`;
    # on current nightly it is a real panic strategy passed via -Cpanic.
    (cd "$REPO_ROOT/$crate" && \
        RUSTFLAGS="$RUSTFLAGS -Zunstable-options -Cpanic=immediate-abort" cargo +nightly build \
        -Zbuild-std=std,panic_abort \
        --target wasm32-wasip2 \
        --release)
    local out="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/wasm32-wasip2/release/$artifact"
    leak_check "$out"
    # The node whitelists binaries by hash, so print it: it is what goes into
    # the contract and into the node's wasm hash list.
    echo "sha256: $(shasum -a256 "$out" | cut -d" " -f1)  ($artifact)"
}

build_verifier() {
    build_one_verifier bee_verifier bee_verifier.wasm
}

build_verifier_v2() {
    build_one_verifier bee_verifier_v2 bee_verifier_v2.wasm
}

case "${1:-all}" in
    sdk) build_sdk ;;
    verifier) build_verifier ;;
    verifier-v2) build_verifier_v2 ;;
    all)
        build_sdk
        build_verifier
        build_verifier_v2
        ;;
    *)
        echo "usage: $0 [sdk|verifier|verifier-v2|all]" >&2
        exit 1
        ;;
esac
