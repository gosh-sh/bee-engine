# Canonical Multisig assets — provenance

Bee ships exactly one Multisig build. Every `compute_multisig_address`,
`deploy_multisig`, and `deploy_multisig_via_giver` call uses this ABI/TVC pair;
there is no runtime build selector or custom-code escape hatch.

| files | contract | version | code hash |
|---|---|---|---|
| `Multisig.{tvc,abi.json}` | `UpdateCustodianMultisigWallet_v2` | 2.4.0 | `cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1` |

The files are vendored **verbatim** (not recompiled) from immutable
`gosh-sh/acki-nacki` commit
`44fe02ea01e4bb31d431ed57d1f9b3dc3dd88a18`, path
`contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2/`. This is the
canonical deployment artifact pinned by `dexdo-cli-private` on 2026-08-08 and
used by the `ackinacki-kit` v5.1.0 multisig binding.

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
    git hash-object bee_wallet/assets/multisig/Multisig.tvc

The constructor accepts `minBalance` and `targetBalance`; `minBalance = 0`
disables automatic SHELL-to-vmshell conversion. These values are constructor
call arguments rather than StateInit data, so changing them for fixed owner
keys does not change the derived address.

Changing either artifact changes deterministic addresses and is therefore a
breaking bee release. Update this file, the pinned hash tests, and downstream
migration documentation together.
