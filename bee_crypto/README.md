# bee_crypto

Reusable crypto library for Bee ecosystem crates.

## Public API

`bee_crypto` intentionally exposes a small surface:

- native client: `bee_crypto::Crypto`
- wasm adapter module: `bee_crypto::wasm`
- error types: `bee_crypto::errors`

Domain-specific wallet logic (for example multifactor key-derivation workflows)
is intentionally out of scope and should live in wallet domain modules.

## Features

- `default`: empty
- `wasm`: enables wasm bindings (`wasm-bindgen`, `serde-wasm-bindgen`)
- `single-wasm`: convenience alias for `wasm`

## Native Usage (Rust)

```rust,no_run
use bee_crypto::Crypto;

let crypto = Crypto::new(vec!["mainnet.ackinacki.org".to_string()])?;
let password_hash = crypto.hash_password("my-password".to_string())?;
let ok = crypto.verify_password_hash("my-password".to_string(), password_hash)?;
assert!(ok);
# Ok::<(), bee_crypto::errors::AppError>(())
```

If you already have `Arc<ClientContext>`, prefer:

```rust,no_run
use std::sync::Arc;
use ackinacki_kit::tvm_client::ClientContext;
use bee_crypto::Crypto;

let tvm = Arc::new(ClientContext::new(Default::default())?);
let crypto = Crypto::from_client_context(tvm);
# Ok::<(), bee_crypto::errors::AppError>(())
```

## Wasm Usage (JS/TS)

```ts
import { Crypto } from "bee_crypto";

const crypto = new Crypto(["mainnet.ackinacki.org"]);
const hash = await crypto.hash_password("my-password");
const ok = await crypto.verify_password_hash("my-password", hash);
```

## Build & Test

```bash
cargo check -p bee-crypto
cargo test -p bee-crypto
cargo check -p bee-crypto --features wasm
```
