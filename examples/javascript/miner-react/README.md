# miner-react

React example for `@teamgosh/bee-sdk`:

- initializes wasm on page load
- creates `bee_connect` session via `create_shared_key_session`
- shows QR/deeplink for wallet app
- waits for `wallet_hello`
- sends `set_mining_keys` request over connect protocol
- after connect, shows wallet metadata and miner controls
- supports client-side `disconnect_session(...)` request

## Prerequisites

- local `bee_sdk` wasm package is built
- `examples/javascript/miner-react/package.json` points to local sdk:
  - `"@teamgosh/bee-sdk": "file:../../../bee_sdk/pkg"`

## Build sdk wasm

From repo root:

```bash
cd bee_sdk
wasm-pack build --target web
```

## Run example

```bash
cd examples/javascript/miner-react
npm install
npm run dev
```

`vite.config.ts` already allows fs access to local sdk package:

- `examples/javascript/miner-react`
- `bee_sdk/pkg`

## Connect flow used in `App.tsx`

1. page loads and calls wasm `init(...)`
2. user clicks `Connect wallet`
3. dApp creates shared-key session:
   - `create_shared_key_session(APP_ID, 300)`
4. UI shows:
   - QR with `session.deep_link`
   - `Open wallet` link
5. dApp waits for wallet handshake:
   - `wait_wallet_hello(ENDPOINTS, ...)`
6. after success UI shows:
   - wallet name
   - wallet address
   - miner panel
7. user requests mining keys setup:
   - dApp generates mining keys (`gen_mining_keys(APP_ID)`)
   - dApp sends `request_set_mining_keys(...)` with generated `owner_public`
8. after wallet handles request, user can initialize miner with the same keypair
9. user can press `Disconnect`:
   - dApp sends `client_disconnect` with `disconnect_session(...)`
   - UI drops local connection state

## Connect protocol (current)

- `wallet_hello` (wallet -> client) confirms established session
- `set_mining_keys` (client -> wallet) requests mining owner key setup
- `client_disconnect` (client -> wallet) requests session teardown

`client_hello_ack` is not used.

Wallet app should poll session stream and route by `msg_type`
(`query_connect_session_messages(...)`).

## Shellnet constants in example

- `ENDPOINTS = ["shellnet.ackinacki.org"]`
