# Multisig assets — provenance

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
