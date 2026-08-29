# bee_verifier_v2

Verifier for the sequential-chain proof, run by `gosh.runwasm` inside a block.
Referenced by `Miner_V2` in the acki-nacki contracts.

`bee_verifier` (v1) is left in place: its binary is already whitelisted on the
nodes and v1 miners keep calling it. This is a separate component with its own
hash, so both can be live at once while miners migrate.

## What it checks

The miner commits a merkle root over checkpoints — one chain state every
`stride` steps. The contract then names the intervals to open, and for each one
the verifier:

1. proves both endpoints are the committed checkpoints `index` and `index + 1`;
2. replays the `stride` steps and requires them to land exactly on the second.

Either half alone is forgeable: the merkle proof would let a miner open any pair
of checkpoints, the replay would let it invent endpoints. Together they say that
this stretch of the committed chain was really walked.

Cost is `intervals * stride` hashes plus two merkle paths each — **independent
of chain length**, which is what lets the miner's work be raised without making
in-block verification more expensive.

## Result layout

Same shape the miner contract already reads:

```
byte 0     1 = call succeeded, 0 = error (code in bytes 2-5)
byte 1     1 = every requested interval verified
bytes 2-5  u32 LE, work proven: committed intervals
```

Bytes 2-5 are *claimed* work; `Miner_V2` caps them by the blocks actually
elapsed since that miner's previous accepted session.

## Build

```bash
scripts/build_wasm.sh verifier-v2
```

Prints the sha256 of the artifact — that is what goes into `Miner_V2`'s
`_wasm_hash` and into the node's wasm hash whitelist. The build is
deterministic: a clean rebuild reproduces the same hash.

## Test

Remove `cdylib` from `Cargo.toml` and run `cargo test -p bee-verifier-v2`.
