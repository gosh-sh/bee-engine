# bee_wallet

Wallet SDK for AckiNacki blockchain. Native Rust + WASM (browser).

## Build

```bash
# Native
cargo build -p bee-wallet

# WASM
wasm-pack build --target web --no-default-features --features wasm
```

## Architecture

Layer boundaries and ownership rules are documented in
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

## API Overview

### Token Operations

| Method | Description |
|--------|-------------|
| `send_tokens(token_root, dest, amount)` | Send ECC (numeric token_root: "1"=NACKL, "2"=SHELL, "3"=USDC) or TIP-3 (address token_root) |
| `migrate_tip3_usdc(token_root, amount_raw)` | Convert TIP-3 USDC → ECC[3] via Exchange (1:1, irreversible) |
| `buy_shells(usdc_amount)` | Send USDC to accumulator, receive Shell |
| `sell_shells(denom)` | Place Shell for sale (denom: 1/10/100/1000), returns order_id |
| `get_my_sell_orders(page_size?, cursor?)` | Paginated list of seller's orders |
| `claim_usdc(denom, order_id)` | Claim USDC for a sold order |
| `redeem_nackl(nackl_amount)` | Burn NACKL, receive USDC (floating rate) |
| `get_nackl_redeem_rate()` | Current NACKL-to-USDC redemption rate |

### Transaction History

| Method | Description |
|--------|-------------|
| `get_history(multifactor_address, token_id, page_size?, cursor?, mining_cursor?)` | Paginated ECC/TIP-3 history |

- Supports hot + archive data sources (archive via optional `archive_endpoints` at construction)
- Known system addresses resolve to names: Giver, Exchange, Accumulator
- Cursors are opaque strings; archive cursors use `a:` prefix internally

### Connect (bee_connect integration)

| Message Type | Direction | Description |
|-------------|-----------|-------------|
| `wallet_hello` | w->c | Wallet announces name and address |
| `set_mining_keys` | c->w | Client requests mining key setup |
| `sign_challenge` | c->w | Client sends nonce for backend auth |
| `challenge_response` | w->c | Wallet returns signed nonce + address |
| `client_disconnect` | c->w | Client terminates session |

### Construction

```typescript
// WASM
const wallet = new Wallet(
  ["mainnet.ackinacki.org"],           // hot endpoints
  ["archive.mainnet.ackinacki.org"],   // archive endpoints (optional)
  apiUrl,
  appId
);
```

## Tools

### Faucet CLI (shellnet only)

```bash
cargo run -p bee-wallet --bin faucet
```

Interactive CLI to send ECC tokens (NACKL/SHELL/USDC) or mint TIP-3 USDC to any wallet by name on shellnet.
