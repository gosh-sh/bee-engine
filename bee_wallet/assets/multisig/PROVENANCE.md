# Multisig assets — provenance

Two builds are vendored here:

| build | files | selected by | code hash |
|---|---|---|---|
| DexDo flat Multisig (**default**) | `Multisig.{tvc,abi.json}` | `code` omitted | `.tvc` sha256 `d3b38bca…` |
| `UpdateCustodianMultisigWallet_v2` v2.4.0 | `v2_4/UpdateCustodianMultisigWallet.{tvc,abi.json}` | `code: "update_custodian_v2_4"` | `cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1` |

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

## `v2_4/` — UpdateCustodianMultisigWallet_v2 v2.4.0

Vendored **verbatim** (not recompiled) from immutable `gosh-sh/acki-nacki`
commit `44fe02ea01e4bb31d431ed57d1f9b3dc3dd88a18`, path
`contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2/`. This is the
canonical deployment artifact pinned by `dexdo-cli-private` on 2026-08-08 and
used by the `ackinacki-kit` v5.1.0 multisig binding. A unit test asserts that
the bee deploy artifact and kit binding expose the same code hash.

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

The v2.4 build provides lifecycle/getter coverage and gas self-management. Its
constructor appends `minBalance` and `targetBalance`; `minBalance = 0`
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
