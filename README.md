# Bee-engine

**TODO:** Add a description of the project’s purpose and high-level architecture.



## Prerequisites

Before building the project, ensure the following tools are installed:

1. **LLVM** — version **21 or higher**
2. **wasm-pack**
   `cargo install wasm-pack`
3. **cargo-component** `cargo install cargo-component`
   

## Building engine-sdk (WASM)
This step builds the SDK targeting browser-compatible WebAssembly.
```bash
cd engine_sdk
rm -rf pkg && wasm-pack build --target web
```

Output artifacts are generated in the `pkg/` directory.

## Building the Verifier (WASI)

**TODO:** Verify the build commands below.

```bash
cd engine

# Generate WIT bindings
cargo component bindings

# Build the WASI-compatible WASM binary
cargo +nightly build \
  -Zbuild-std=std,panic_abort \
  -Zbuild-std-features=panic_immediate_abort \
  --target wasm32-wasip2 \
  --release
```

This produces a WASM component intended to run inside a WASI runtime.



## Language Bindings

**TODO:** Verify the build commands below.

### JavaScript

```bash
bun i
bunx jco transpile \
  engine/target/wasm32-wasip2/release/bee_engine_verifier.wasm \
  -o ./bindings/js
```

This command generates JavaScript bindings from the WASI component.

---

## Troubleshooting

### Build errors

If you encounter errors similar to the following when running the `wasm-pack build --target web` command:
```
warning: blst@0.3.16: error: unable to create target:
'No available targets are compatible with triple "wasm32-unknown-unknown"'
error: failed to run custom build command for `blst v0.3.16`
```

This usually indicates that your system `clang` is **too old** and does not support WebAssembly targets.

---

### Fix: Upgrade LLVM (macOS)

Install a newer LLVM version using Homebrew:

```bash
brew install llvm
```

Then add the following lines to the end of your `~/.zshrc`:

```bash
# LLVM / clang configuration
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export LDFLAGS="-L/opt/homebrew/opt/llvm/lib"
export CPPFLAGS="-I/opt/homebrew/opt/llvm/include"
export CMAKE_PREFIX_PATH="/opt/homebrew/opt/llvm"
```

Reload your shell configuration:

```bash
source ~/.zshrc
```

Verify the installation:
 - `clang --version`  reports LLVM **21+** or higher 
 - `which clang` returns `/opt/homebrew/opt/llvm/bin/clang`
