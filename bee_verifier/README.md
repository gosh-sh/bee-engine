## Build
```bash
# If `wit` was updated
cargo component bindings

# Build
rustup toolchain install 1.88
rustup target add --toolchain 1.88 wasm32-wasip2
cargo +1.88 build --release --target wasm32-wasip2
```

## Test
Remove `cdylib` from `Cargo.toml` and run `cargo test`
