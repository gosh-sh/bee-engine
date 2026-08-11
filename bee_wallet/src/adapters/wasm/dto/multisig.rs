//! TS-typed wasm DTOs for the flat-Multisig giver deploy. `TKeyPair` is
//! declared once in `dto/mod.rs` and reused here.

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export type TParamsOfDeployMultisigViaGiver = {
    endpoints: string[];
    keys?: TKeyPair;
    owners_pubkey?: string[];
    req_confirms?: number;
    req_confirms_data?: number;
    constructor_value?: string;
    // v2.4 only. Omit to pass 0/0 and disable automatic SHELL-to-vmshell
    // conversion. Decimal strings preserve the full uint128 range.
    balance_config?: TMultisigBalanceConfig;
    giver_value?: string;
    // Map, NOT Record: serde on the Rust side deserializes a JS Map's numeric
    // keys into the u32 currency ids. A plain object/Record stringifies its keys
    // and the WASM rejects them ("invalid type: string, expected u32").
    giver_ecc?: Map<number, string>;
    wait_for_active?: boolean;
    // Which multisig build to deploy. Omit for the SDK's default build, name a
    // build vendored in the SDK, or pass your own code+ABI pair.
    code?: TMultisigBuild | TMultisigCode;
};

// Build vendored in this SDK, selectable by name — no need to ship a `.tvc`
// from the frontend.
export type TMultisigBuild = "update_custodian_v2_4";

export type TMultisigBalanceConfig = {
    min_balance: string;
    target_balance: string;
};

// Your own build. `tvc_b64` and `abi` are BOTH required: on ABI >= 2.3 the
// state-init data cell is rebuilt from the ABI's `fields` list before the
// address is hashed, so the ABI is part of the address. Mixing one build's code
// with another's ABI derives an address whose storage layout the code does not
// agree with — hence no way to pass just one.
export type TMultisigCode = {
    // The build's `.tvc`, base64-encoded.
    tvc_b64: string;
    // That build's `.abi.json` — stringified or the imported object.
    abi: string | object;
};

export type TResultOfDeployMultisigViaGiver = {
    address: string;
    public: string;
    secret: string;
    already_deployed: boolean;
    deploy_tx?: string;
};

export type TParamsOfMultisigBalances = {
    endpoints: string[];
    address: string;
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "TParamsOfDeployMultisigViaGiver")]
    pub type TParamsOfDeployMultisigViaGiver;

    #[wasm_bindgen(typescript_type = "TResultOfDeployMultisigViaGiver")]
    pub type TResultOfDeployMultisigViaGiver;

    #[wasm_bindgen(typescript_type = "TParamsOfMultisigBalances")]
    pub type TParamsOfMultisigBalances;

    /// `{ currency_id: raw_amount_string }`, e.g. `{ "2": "10000000000" }`.
    #[wasm_bindgen(typescript_type = "Record<number, string>")]
    pub type TMultisigBalances;
}
