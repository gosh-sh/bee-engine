# Multisig assets — provenance

Two builds are vendored here:

| build | files | selected by | code hash |
|---|---|---|---|
| DexDo flat Multisig (**default**) | `Multisig.{tvc,abi.json}` | `code` omitted | `.tvc` sha256 `d3b38bca…` |
| `UpdateCustodianMultisigWallet` v2.1.0 | `v2/UpdateCustodianMultisigWallet.{tvc,abi.json}` | `code: "update_custodian_v2"` | `31e402bb4fc2bb740634ab00b074f2e4ae772f0744d8aabb7c51d44f430d86e3` |

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

## `v2/` — UpdateCustodianMultisigWallet v2.1.0

Vendored **verbatim** (not recompiled) from `gosh-sh/acki-nacki` PR #2413, branch
`contracts/multisig`, path
`contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2/`. Git blob SHAs of
the files here match that branch exactly:

    UpdateCustodianMultisigWallet.tvc       7147 B   blob c289fe7f746ca63ad8c067019eda43072dbda066
    UpdateCustodianMultisigWallet.abi.json 10856 B   blob 90b8f8518666a49e1caf30aeec332fcb22ab7311

    .tvc  sha256    3e680a80506fce6dd8c3b7209a6fed880b63a94e2317efe81f15173d0015d2d0
    code hash       31e402bb4fc2bb740634ab00b074f2e4ae772f0744d8aabb7c51d44f430d86e3
    compiler        sol 0.81.0

To re-verify or refresh:

    gh api "repos/gosh-sh/acki-nacki/contents/contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2?ref=contracts/multisig" \
      --jq '.[] | "\(.name) \(.sha)"'
    git hash-object v2/UpdateCustodianMultisigWallet.tvc      # must match the blob above

The `.tvc` sha256 is pinned in a unit test (`vendored_v2_asset_is_pinned`) and the
code hash is asserted on-chain by the integration tests, so a swapped file fails
in CI rather than on a network. **PR #2413 was unmerged when this was vendored** —
re-check the blob SHAs after it lands.

Relative to the default build its ABI is a strict superset by function set: all
17 functions identical (constructor included), plus `submitUpdateCode(cell,cell)
-> uint64` and `confirmUpdateCode(uint64)`. Its `fields` add `m_requestsMaskCode`
and `m_code` — which is why it must be deployed with its own ABI (see below).

Verified on shellnet through `deploy_multisig_via_giver` with
`code: "update_custodian_v2"`: account Active, `exit_code: 0`, on-chain code hash
as above.

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
