# @teamgosh/bee-sdk

[![npm](https://img.shields.io/npm/v/@teamgosh/bee-sdk?color=cb3837&logo=npm)](https://www.npmjs.com/package/@teamgosh/bee-sdk)

WebAssembly SDK for [Acki Nacki](https://ackinacki.com) — drive multifactor
wallets, mining, wallet-connect sessions, and flat-multisig deploy straight from
the browser. Compiled from the `bee-engine` Rust workspace with `wasm-pack`
(`web` target), fully typed.

## Features

- **Multifactor wallets** — deploy, query, manage factors, zk-login.
- **Mining** — resolve miner addresses, set mining keys, drive a miner.
- **Wallet-connect** — shared-key sessions, challenge/response, profile resolve.
- **Flat multisig** — fully client-side giver-funded deploy + ECC balance reads.
- **Typed end-to-end** — complete `.d.ts` ships with the package.

> **Runtime:** browser / WebAssembly (built `wasm-pack --target web`). Not a
> Node package — it relies on the browser `WebAssembly` + `fetch` APIs.

## Install

```bash
npm i @teamgosh/bee-sdk
```

## Initialize

WebAssembly must be initialized **once** before any other call. The package
ships the `bee_sdk_bg.wasm` binary; point `init` at it so your bundler emits and
serves it. Pick the snippet for your setup:

**Vite**

```ts
import init from "@teamgosh/bee-sdk";
import wasmUrl from "@teamgosh/bee-sdk/bee_sdk_bg.wasm?url";

await init({ module_or_path: wasmUrl });
```

**webpack 5 / Next.js**

```ts
import init from "@teamgosh/bee-sdk";

const wasmUrl = new URL("@teamgosh/bee-sdk/bee_sdk_bg.wasm", import.meta.url);
await init({ module_or_path: wasmUrl });
```

**Any setup (host the file yourself)**

Copy `node_modules/@teamgosh/bee-sdk/bee_sdk_bg.wasm` into your static/public
assets, then pass its served URL:

```ts
import init from "@teamgosh/bee-sdk";

await init({ module_or_path: "/assets/bee_sdk_bg.wasm" });
```

Call `init` once at startup; everything below assumes it has resolved.

## Usage

### Flat multisig deploy (shellnet, fully client-side)

Funds a fresh multisig address from the default shellnet giver, then deploys it.
Always returns the owner keypair — **persist `secret`**. All amounts are strings
(u64 / ECC values exceed `2^53` and would lose precision as JS numbers).

```ts
import init, { deploy_multisig_via_giver, multisig_balances } from "@teamgosh/bee-sdk";

await init();

const res = await deploy_multisig_via_giver({
  endpoints: ["https://shellnet.ackinacki.org"],
  // keys?            — owner keypair; generated when omitted, always returned
  // owners_pubkey?   — custodians ["0x…"] (uint256[]), default [owner]
  // req_confirms?, req_confirms_data?  — default 1
  // giver_value?     — SHELL (ECC[2]) gas top-up, default "1000000000000000"
  // giver_ecc?       — extra ECC, Map<currency_id, "amount">
  // wait_for_active? — wait until Active, default true
  // code?            — deploy a different multisig build (see below)
});

console.log(res.address);     // 0x… canonical <dapp>::<account>
saveSecretSomewhere(res.secret);

// ECC balances of any account by address → { currency_id: raw_amount_string }
const balances = await multisig_balances({
  endpoints: ["https://shellnet.ackinacki.org"],
  address: res.address,
});
// e.g. { "2": "10000000000" }  (1 = NACKL, 2 = SHELL, 3 = USDC)
```

#### Choosing the multisig build

`code` picks which contract gets deployed. Three forms:

```ts
// 1. Omit it — the SDK's default build (DexDo flat Multisig).
await deploy_multisig_via_giver({ endpoints });

// 2. A build vendored in the SDK, by name. No `.tvc` to ship from the frontend.
await deploy_multisig_via_giver({
  endpoints,
  code: "update_custodian_v2_4", // UpdateCustodianMultisigWallet v2.4.0
  // Optional uint128 decimal strings. Omit (or pass 0/0) to disable automatic
  // SHELL-to-vmshell conversion.
  balance_config: {
    min_balance: "1000000000",
    target_balance: "2000000000",
  },
});

// 3. Your own build.
import abi from "./MyMultisig.abi.json";
await deploy_multisig_via_giver({
  endpoints,
  code: { tvc_b64: myTvcBase64, abi },   // `abi`: object or string
});
```

Vendored builds:

| `code` | contract | code hash |
|---|---|---|
| *(omitted)* | DexDo flat Multisig | — |
| `"update_custodian_v2"` | legacy alias for v2.2.0 | `09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded` |
| `"update_custodian_v2_2"` | `UpdateCustodianMultisigWallet` v2.2.0, retained for recovery | `09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded` |
| `"update_custodian_v2_4"` | `UpdateCustodianMultisigWallet` v2.4.0, current deploy | `cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1` |

Do not retarget the legacy `"update_custodian_v2"` name: contract code and ABI
participate in deterministic address derivation, so changing that alias to v2.4
would make existing v2.2 wallets resolve to a different address. New callers
should always use the explicit versioned selector.

In form 3, `tvc_b64` and `abi` are both required and must come from the *same*
build: on ABI ≥ 2.3 the state-init data cell is rebuilt from the ABI's `fields`
before the address is hashed, so mixing one build's code with another's ABI
derives a different address whose storage layout the code doesn't agree with.
Sending only one half is an error, not a default.

The build is part of the address, so each one lands somewhere different — the
returned `address` is always the one that was funded and deployed.
`balance_config` is constructor input rather than StateInit, so changing it for
the same v2.4 build and owner keys does not change the derived address.

### Multifactor wallet

```ts
import init, { Wallet } from "@teamgosh/bee-sdk";

await init();

const wallet = new Wallet(
  ["https://shellnet.ackinacki.org"],          // endpoints
  null,                                         // archive endpoints (optional)
  "https://app-backend.ackinacki.org/api",      // bee-infra backend
  "0x0000000000000000000000000000000000000000000000000000000000000000", // app id
);
```

### Wallet-connect & mining

```ts
import init, { BeeConnect, get_miner_address_by_wallet_name } from "@teamgosh/bee-sdk";

await init();

const connect = new BeeConnect();
const session = connect.create_shared_key_session(appId, 300, null);
// → present session.deep_link to the wallet app, then connect.wait_wallet_hello(...)

const minerAddress = await get_miner_address_by_wallet_name({
  client_config: { network: { endpoints: ["https://shellnet.ackinacki.org"] } },
  wallet_name: "my-wallet",
});
```

## Notes

- Account addresses come back in canonical dApp-scoped form `<dapp>::<account>`.
- The giver-funded multisig deploy is **shellnet-only** (the default giver lives
  only on shellnet) — gate it by network on your side.
- See `bee_sdk.d.ts` for the full, authoritative type surface.

## License

`LicenseRef-Acki-Nacki-Node-License` (see `license` in `package.json`).
