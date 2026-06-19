# Bee Wallet Architecture

## Layer Contract

1. `modules/*` is the orchestration layer.
2. `services/*` is the helper/use-case layer.
3. `adapters/*` is the external API/DTO layer.

## Responsibilities

### `modules`

- Assemble full domain scenarios (multi-step workflows).
- Coordinate retries/polling and transaction sequencing.
- Compose helpers from `services`, `infra`, contracts, and `bee_crypto::Crypto`.

### `services`

- Provide focused reusable helpers for domain operations.
- Contain contract call helpers and pure transformations.
- Stay composable and callable from modules without owning whole flows.

### `adapters`

- Convert external/native/wasm payloads to module calls.
- Return transport-friendly DTOs.
- Avoid embedding domain orchestration.

## Dependency Direction

`adapters -> modules -> services -> infra/contracts/bee_crypto`

Allowed:
- `modules` can call multiple `services`.
- `services` can call lower-level libraries/utilities.

Not allowed:
- `services` orchestrating whole cross-domain user flows.
- Cross-domain `pub use` re-exports from service modules for convenience.

## Crypto Boundary

- Generic crypto operations come from `bee_crypto::Crypto`.
- Wallet domain crypto (for example multifactor key derivation) stays inside wallet domain services.
