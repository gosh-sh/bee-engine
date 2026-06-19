# Bee-engine

Rust workspace for blockchain mining, proof verification, wallet management, and cryptographic operations. Targets native Rust, browser WASM (`wasm32-unknown-unknown`), and WASI 2.0 (`wasm32-wasip2`).

## Crates

```
bee_sdk        WASM aggregator — re-exports all crates into a single .wasm bundle
bee_wallet     Wallet operations (send tokens, accumulator, connect, deploy)
bee_crypto     Signing, encryption, mnemonics, hashing
bee_miner      Mining: proof generation, merkle trees, WASM workers
bee_connect    dApp ↔ wallet connect protocol, encrypted session management
bee_verifier   Proof verifier (WASI component, separate target)
bee_shared     Shared Borsh-serialized types
bee_infra      Async sleep/poll utilities
```

## Prerequisites

- **Rust** 1.86+
- **LLVM 21+** (for WASM compilation of `blst` dependency)
- **wasm-pack**: `cargo install wasm-pack`
- **cargo-component**: `cargo install cargo-component`

## Build

Both WASM artifacts are built via the script — it remaps machine paths out of
the binaries (`--remap-path-prefix`) and fails the build if a `/Users/...` or
`/home/<user>/...` path survives into the artifact:

```bash
scripts/build_wasm.sh sdk        # bee_sdk → bee_sdk/pkg (wasm-pack, browser)
scripts/build_wasm.sh verifier   # bee_verifier → wasm32-wasip2 (WASI component)
scripts/build_wasm.sh            # both
```

If `bee_verifier/wit` was updated, run `cargo component bindings` in
`bee_verifier/` first (see `bee_verifier/README.md`).

## Tests

```bash
cargo test --workspace                          # all native tests
cargo test -p bee-wallet                        # single crate
cargo test -p bee-wallet -- test_name           # single test
cargo test -p bee-wallet -- --test-threads=1    # bee_wallet integration tests (sequential)
wasm-pack test --headless --chrome -p bee_miner # WASM tests (browser)
```

`bee_wallet` integration tests hit shellnet and share on-chain state (accumulator queues). Run with `--test-threads=1` to avoid flaky failures.

## Lint & Format

```bash
cargo clippy --workspace
cargo fmt --all -- --check
```

Formatting uses nightly rustfmt features (`imports_granularity = "Item"`, `group_imports = "StdExternalCrate"`).

## Examples

### miner-react

React dApp demonstrating wallet connect, mining key setup, and wallet ownership verification.

```bash
cd bee_sdk && rm -rf pkg && wasm-pack build --target web
cd ../examples/javascript/miner-react
npm install
npm run dev
```

## Troubleshooting

### `blst` build errors

```
warning: blst@0.3.16: error: unable to create target:
'No available targets are compatible with triple "wasm32-unknown-unknown"'
```

System `clang` is too old. Install LLVM 21+:

```bash
brew install llvm
```

Add to `~/.zshrc`:

```bash
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export LDFLAGS="-L/opt/homebrew/opt/llvm/lib"
export CPPFLAGS="-I/opt/homebrew/opt/llvm/include"
export CMAKE_PREFIX_PATH="/opt/homebrew/opt/llvm"
```

Verify: `clang --version` reports LLVM 21+, `which clang` returns `/opt/homebrew/opt/llvm/bin/clang`.

## License

Bee-engine is licensed under the **GNU Affero General Public License v3.0** —
see [LICENSE.md](LICENSE.md). The AGPL terms apply only to Bee-engine itself;
the Acki Nacki node software it interoperates with at runtime is licensed
separately. See [NOTICE.md](NOTICE.md) for details.
