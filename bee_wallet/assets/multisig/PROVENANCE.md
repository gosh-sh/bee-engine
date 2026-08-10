# Multisig assets — provenance

Three builds are vendored here:

| build | files | selected by | code hash |
|---|---|---|---|
| DexDo flat Multisig (**default**) | `Multisig.{tvc,abi.json}` | `code` omitted | `.tvc` sha256 `d3b38bca…` |
| `UpdateCustodianMultisigWallet_v2` v2.2.0 (**legacy deploy**) | `v2_2/UpdateCustodianMultisigWallet.{tvc,abi.json}` | `code: "update_custodian_v2_2"` or legacy `"update_custodian_v2"` | `09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded` |
| `UpdateCustodianMultisigWallet_v2` v2.4.0 (**new deploy**) | `v2_4/UpdateCustodianMultisigWallet.{tvc,abi.json}` | `code: "update_custodian_v2_4"` | `cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1` |

A caller can also pass its own build as `code: { tvc_b64, abi }` — see
"Any other build" below.

## Default build — DexDo flat Multisig

This is the **DexDo** multisig: `Multisig.abi.json` + `Multisig.tvc` are the flat
Multisig that DexDo uses, sourced from the DexDo repo:

    https://github.com/gosh-sh/dexdo  →  contracts/wallet/multisig/Multisig.sol

The repo ships only the `.sol` + `.abi.json` (no `.tvc`); the TVC is compiled on
demand. Rebuild it with the same compiler the project uses:

    sold --tvm-version gosh Multisig.sol     # sold 0.79.3, output is deterministic

Then copy `Multisig.tvc` + `Multisig.abi.json` here.

Note: this TVC differs from `ackinacki-kit`'s `contracts/abi/multisig/Multisig.tvc`
(identical ABI, different compiled code → different code_hash). We deploy
DexDo's build so addresses/code match what DexDo expects.

Current `Multisig.tvc` sha256: d3b38bcac8f60c1274f6099fc1e75746c02a2ff22af4efc689a754fd087a86fb

## `v2_2/` — UpdateCustodianMultisigWallet_v2 v2.2.0

Vendored **verbatim** (not recompiled) from `gosh-sh/acki-nacki` branch `dev`,
path `contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2/` — the merged
form of PR #2413 (commit `6ad89549a0b845ed70094b24b23fad3223cdd5e8`).
Upstream names carry a `_v2` suffix that is redundant inside `v2_2/`, so they are
stored here without it; the git blob SHAs match upstream exactly:

    upstream UpdateCustodianMultisigWallet_v2.tvc       7150 B   blob 9610c471dce949f6ec84b096711cb7f43c78343b
    upstream UpdateCustodianMultisigWallet_v2.abi.json 10856 B   blob 90b8f8518666a49e1caf30aeec332fcb22ab7311

    .tvc  sha256    535e180e85ee019c23631c6046449fa2a5536d88f55b26d64e026d671e82d520
    code hash       09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded
    compiler        sol 0.81.0

Refreshed from `dev` on 2026-07-27, superseding the pre-merge artifact taken from
branch `contracts/multisig` (`.tvc` 7147 B, sha256 `3e680a80…`, code hash
`31e402bb…`). The ABI is byte-identical across the two; only the compiled code
moved, so the **derived address of a v2 deploy changed** — anything that recorded
a v2 address computed before this refresh must recompute it.

To re-verify or refresh:

    gh api "repos/gosh-sh/acki-nacki/contents/contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2?ref=dev" \
      --jq '.[] | "\(.name) \(.sha)"'
    git hash-object v2_2/UpdateCustodianMultisigWallet.tvc    # must match the blob above

The code hash is read straight out of the `.tvc` with
`tvm_client::boc::decode_state_init` (`code_hash` = repr hash of the state-init
code cell) — the same value a node reports for a deployed account.

The `.tvc` and ABI sha256 values are pinned in unit tests and the code hash is
decoded from the TVC there, so a swapped file fails in CI rather than on a
network.

Relative to the default build its ABI is a strict superset by function set: all
17 functions identical (constructor included), plus `submitUpdateCode(cell,cell)
-> uint64` and `confirmUpdateCode(uint64)`. Its `fields` add `m_requestsMaskCode`
and `m_code` — which is why it must be deployed with its own ABI (see below).

Verified on shellnet after the 2026-07-27 refresh, through
`deploy_multisig_via_giver` with `code: "update_custodian_v2"`: account Active at
`0480508b8bf07b3df8830ab758a61be0ee9b36427d9780466a66712277bb468c::…`, on-chain
code hash `09f596d5…` as above.

The v2.2 artifact remains available for deterministic address recovery and
management of already-deployed wallets. It is not the build for new deployments.
The legacy wire name is deliberately kept bound to these exact bytes: silently
retargeting it to v2.4 would make the same keys resolve to a different address.

## `v2_4/` — UpdateCustodianMultisigWallet_v2 v2.4.0

Vendored **verbatim** (not recompiled) from immutable `gosh-sh/acki-nacki`
commit `44fe02ea01e4bb31d431ed57d1f9b3dc3dd88a18`, path
`contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2/`. This is the
canonical deployment artifact pinned by `dexdo-cli-private` on 2026-08-08.

    upstream UpdateCustodianMultisigWallet_v2.tvc       10943 B  blob a9156bd2da0672a07a7dc02140c2ce5364015edc
    upstream UpdateCustodianMultisigWallet_v2.abi.json  16885 B  blob 486e772a1d2238c587bdc9a33f78c5a66c3b8ba6

    .abi sha256     e7573b233667cf50d8edc9ab0ce235f8ac88674ae9610c77d426bec22070f581
    .tvc sha256     b0d72acbbdc6af309823e74b96b0b3ffb0f871a5b98316b6e89affdfb56c5c9d
    code hash       cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1
    contract        UpdateCustodianMultisigWallet_v2
    getVersion      2.4.0
    compiler        sol 0.81.0

To re-verify the immutable source:

    gh api "repos/gosh-sh/acki-nacki/contents/contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2?ref=44fe02ea01e4bb31d431ed57d1f9b3dc3dd88a18" \
      --jq '.[] | "\(.name) \(.sha)"'
    git hash-object v2_4/UpdateCustodianMultisigWallet.tvc

Relative to v2.2, v2.4 adds lifecycle/getter coverage and gas self-management.
Its constructor appends `minBalance` and `targetBalance`; `minBalance = 0`
disables automatic SHELL-to-vmshell conversion. The two balance fields are part
of the constructor call but not StateInit, so changing them does not change the
derived address for fixed code, ABI and deploy key.

## Any other build

`MultisigDeploySpec.code` (`code: { tvc_b64, abi }` over the wasm boundary)
deploys a build that isn't vendored here — see `MultisigCode` in
`src/services/multisig.rs`. Both halves are required, and that is not a
formality: on ABI ≥ 2.3 the state-init **data** cell is rebuilt from the ABI's
`fields` list before the address is hashed (`tvm_sdk::ContractImage::update_data`
→ `encode_storage_fields`), so an ABI is part of the address. Pairing one build's
code with another's ABI silently derives a *different* address whose storage
layout the code does not agree with — measured: v2's code with the default ABI
lands on a third address, even though the ABIs share every function signature.
