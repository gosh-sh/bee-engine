use wasm_bindgen::prelude::wasm_bindgen;

pub(crate) mod balances;
pub(crate) mod connect;
pub(crate) mod deploy;
pub(crate) mod keys;
pub(crate) mod miner;
pub(crate) mod multifactor;
pub(crate) mod multisig;
pub(crate) mod names;
pub(crate) mod tx;
pub(crate) mod write;
pub(crate) mod zkp;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export type TKeyPair = {
    public: string;
    secret: string;
};

export type TParamsOfDeployMultifactor = {
    wallet_name: string;
    zkid: string;
    password: string;
    proof: string;
    epk: string;
    esk: string;
    jwk_modulus: string;
    jwk_modulus_expire_at: number;
    index_mod_4: number;
    iss_base_64: string;
    header_base_64: string;
    epk_expire_at: number;
    kid: string;
    sub: string;
};

export type TParamsOfDeployMiner = {
    multifactor_address: string
    signer_keys: TKeyPair,
};

export type TParamsOfSetMiningKeys = {
    multifactor_address: string
    signer_keys: TKeyPair,
    mining_pubkey: string,
    app_id?: string,
    epk_expire_at?: number,
};

export type TParamsOfDelMiningKey = {
    multifactor_address: string;
    signer_keys: TKeyPair;
    app_id?: string;
    epk_expire_at?: number;
    and_wait?: boolean;
};

export type TParamsOfAddZKPFactor = {
    wallet_name: string;
    proof: string;
    epk: string;
    esk: string;
    header_base_64: string;
    epk_expire_at: number;
    jwk_expires_at: number;
    kid: string;
    sub: string;
    password: string
    zkid: string
}

export type TParamsOfChangeSeedPhrase = {
    password: string;
    signer_keys: TKeyPair;
    new_owner_keys: TKeyPair;
    multifactor_address: string;
}

export type TParamsOfGetMultifactorBalances = {
    multifactor_address: string;
};

export type TParamsOfGetTokensBalances = {
    multifactor_address: string;
    token_roots: { token_root: string; token_dapp: string }[];
};

export type TParamsOfGetHistory = {
    multifactor_address: string;
    token_id: string;
    page_size?: number;
    cursor?: string;
    mining_cursor?: string;
};

export type TParamsOfGetMinerAddress = {
    multifactor_address: string
};

export type TBuyShellsReq = {
    multifactor_address: string;
    usdc_amount: number;
    signer_keys: TKeyPair;
    bounce?: boolean;
};

export type TRedeemNacklReq = {
    multifactor_address: string;
    nackl_amount: number;
    signer_keys: TKeyPair;
    bounce?: boolean;
};

export type TMigrateTip3UsdcReq = {
    multifactor_address: string;
    token_root: string;
    token_dapp: string;
    amount_raw: string | number;
    signer_keys: TKeyPair;
    bounce?: boolean;
};

export type TClaimUsdcReq = {
    denom: number;
    order_id: number;
    signer_keys: TKeyPair;
};

export type TSendTokensDirectReq = {
    multifactor_address: string;
    destination_address: string;
    token_root: string;
    amount_raw: string | number;
    flags: number;
    signer_keys: TKeyPair;
    bounce?: boolean;
    /** Gas value in nanotons. Default: 1_000_000_000 (1 VMShell). */
    value?: number;
    /** ABI-encoded message body (base64). Carries a function call to the destination. */
    payload?: string;
};

export type TGetMySellOrdersReq = {
    multifactor_address: string;
    page_size?: number;
    cursor?: string;
};

export type TSellShellsReq = {
    multifactor_address: string;
    denom: number;
    signer_keys: TKeyPair;
    bounce?: boolean;
};

export type TSellShellsResult = {
    message_hash: string | null;
    order_id: number;
    denom: number;
    sell_order_address: string;
    sold: boolean;
    position_in_queue: number;
};

/**
 * Connect session state — opaque blob passed between WASM calls.
 *
 * Secret fields (encryption_root, my_dh_secret, signing_secret) are sensitive.
 * Store in secure storage (OS keychain), never log in plaintext.
 * Pass back to WASM as-is; do not modify fields.
 */
export type TConnectSessionState = {
    encryption_root: string;   // hex, 32 bytes — DO NOT log
    my_dh_secret: string;      // hex, 32 bytes — DO NOT log
    peer_dh_public: string;    // hex, 32 bytes
    signing_public: string;    // hex, 32 bytes
    signing_secret: string;    // hex, 32 bytes — DO NOT log
    created_at: number;        // UNIX epoch seconds, set at handshake
    expires_at: number;        // UNIX epoch seconds (0 = no expiration, default = created_at + 24h)
};

export type TParamsOfQueryConnectSessionMessages = {
    session_id: string;
    description: string;
    session_state?: TConnectSessionState;
    created_at_from?: number;
    before?: string;
    limit?: number;
};

/**
 * Saved data from `prepare_zk_login_v1` (carry through the OAuth round-trip).
 * Field names are camelCase because the underlying Rust struct uses camelCase.
 */
export type TZkLoginTempData = {
    maxEpoch: number;
    randomness: string;
    ephemeralPrivateKey: string;
};

export type TZkLoginCompleteWithProverParams = {
    savedData: TZkLoginTempData;
    jwt: string;
    jwtSub: string;
    jwtAud: string;
    userPassword: string;
    proverUrl: string;
};

export type TUpdateMultifactorZkIdReq = {
    address: string;
    zkid: string;
    password: string;
    proof: string;
    epk: string;
    esk: string;
    jwk_modulus: string;
    jwk_modulus_expire_at: number;
    index_mod_4: number;
    iss_base_64: string;
    header_base_64: string;
    epk_expire_at: number;
    pubkey: string;
    secretkey: string;
    kid: string;
    sub: string;
};

export type TDeleteZkpFactorByItselfReq = {
    multifactor_address: string;
    signer_keys: TKeyPair;
};

export type TParamsOfGetMultifactorInfo = {
    address: string;
};

export type TParamsOfGetMultifactorAddress = {
    pubkey: string;
};

export type TParamsGetMirrorAddress = {
    pubkey: string;
};

export type TGetEPKExpireReq = {
    epk: string;
    multifactor_address: string;
};

/**
 * Stage 5b — `prepare_multifactor_deploy_params` input.
 * Combines zk-login outputs with BIP39 owner keys + future multifactor address.
 */
export type TParamsOfPrepareDeploy = {
    zkid: string;
    password: string;
    proof: string;
    epk: string;
    esk: string;
    jwk_modulus: string;
    jwk_modulus_expire_at: number;
    index_mod_4: number;
    iss_base_64: string;
    header_base_64: string;
    epk_expire_at: number;
    keys: TKeyPair;
    kid: string;
    wallet_name: string;
    multifactor_address: string;
    sub: string;
};

export type TRootProviderCertificatesMap = Record<string, string>;

export type TTokenBalancesMap = Record<string, string>;
export type TNativeBalancesMap = Record<string, string>;
export type TMinerOwnerPublicMap = Record<string, string>;
export type TCandidateOwnerPubkeyExpirationMap = Record<string, string> | null;
export type TFactorsOrderedByTimestampMap = Record<string, string>;
export type TJwkData = {
    modulus: string;
    modulus_expire_at: string;
};
export type TJwkModulusDataMap = Record<string, TJwkData>;
export type TWhiteListOfAddressMap = Record<string, boolean>;

"#;
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "TParamsOfDeployMultifactor")]
    pub type TParamsOfDeployMultifactor;

    #[wasm_bindgen(typescript_type = "TParamsOfDeployMiner")]
    pub type TParamsOfDeployMiner;

    #[wasm_bindgen(typescript_type = "TParamsOfSetMiningKeys")]
    pub type TParamsOfSetMiningKeys;

    #[wasm_bindgen(typescript_type = "TParamsOfDelMiningKey")]
    pub type TParamsOfDelMiningKey;

    #[wasm_bindgen(typescript_type = "TKeyPair")]
    pub type TKeyPair;

    #[wasm_bindgen(typescript_type = "TParamsOfAddZKPFactor")]
    pub type TParamsOfAddZKPFactor;

    #[wasm_bindgen(typescript_type = "TParamsOfChangeSeedPhrase")]
    pub type TParamsOfChangeSeedPhrase;

    #[wasm_bindgen(typescript_type = "TParamsOfGetMultifactorBalances")]
    pub type TParamsOfGetMultifactorBalances;

    #[wasm_bindgen(typescript_type = "TParamsOfGetTokensBalances")]
    pub type TParamsOfGetTokensBalances;

    #[wasm_bindgen(typescript_type = "TParamsOfGetHistory")]
    pub type TParamsOfGetHistory;

    #[wasm_bindgen(typescript_type = "TParamsOfGetMinerAddress")]
    pub type TParamsOfGetMinerAddress;

    #[wasm_bindgen(typescript_type = "TBuyShellsReq")]
    pub type TBuyShellsReq;

    #[wasm_bindgen(typescript_type = "TRedeemNacklReq")]
    pub type TRedeemNacklReq;

    #[wasm_bindgen(typescript_type = "TMigrateTip3UsdcReq")]
    pub type TMigrateTip3UsdcReq;

    #[wasm_bindgen(typescript_type = "TClaimUsdcReq")]
    pub type TClaimUsdcReq;

    #[wasm_bindgen(typescript_type = "TSendTokensDirectReq")]
    pub type TSendTokensDirectReq;

    #[wasm_bindgen(typescript_type = "TGetMySellOrdersReq")]
    pub type TGetMySellOrdersReq;

    #[wasm_bindgen(typescript_type = "TSellShellsReq")]
    pub type TSellShellsReq;

    #[wasm_bindgen(typescript_type = "TParamsOfQueryConnectSessionMessages")]
    pub type TParamsOfQueryConnectSessionMessages;

    #[wasm_bindgen(typescript_type = "TTokenBalancesMap")]
    pub type TTokenBalancesMap;

    #[wasm_bindgen(typescript_type = "TNativeBalancesMap")]
    pub type TNativeBalancesMap;

    #[wasm_bindgen(typescript_type = "TMinerOwnerPublicMap")]
    pub type TMinerOwnerPublicMap;

    #[wasm_bindgen(typescript_type = "TCandidateOwnerPubkeyExpirationMap")]
    pub type TCandidateOwnerPubkeyExpirationMap;

    #[wasm_bindgen(typescript_type = "TFactorsOrderedByTimestampMap")]
    pub type TFactorsOrderedByTimestampMap;

    #[wasm_bindgen(typescript_type = "TJwkModulusDataMap")]
    pub type TJwkModulusDataMap;

    #[wasm_bindgen(typescript_type = "TWhiteListOfAddressMap")]
    pub type TWhiteListOfAddressMap;

    #[wasm_bindgen(typescript_type = "TZkLoginCompleteWithProverParams")]
    pub type TZkLoginCompleteWithProverParams;

    #[wasm_bindgen(typescript_type = "TUpdateMultifactorZkIdReq")]
    pub type TUpdateMultifactorZkIdReq;

    #[wasm_bindgen(typescript_type = "TDeleteZkpFactorByItselfReq")]
    pub type TDeleteZkpFactorByItselfReq;

    #[wasm_bindgen(typescript_type = "TParamsOfGetMultifactorInfo")]
    pub type TParamsOfGetMultifactorInfo;

    #[wasm_bindgen(typescript_type = "TParamsOfGetMultifactorAddress")]
    pub type TParamsOfGetMultifactorAddress;

    #[wasm_bindgen(typescript_type = "TParamsGetMirrorAddress")]
    pub type TParamsGetMirrorAddress;

    #[wasm_bindgen(typescript_type = "TGetEPKExpireReq")]
    pub type TGetEPKExpireReq;

    #[wasm_bindgen(typescript_type = "TParamsOfPrepareDeploy")]
    pub type TParamsOfPrepareDeploy;

    #[wasm_bindgen(typescript_type = "TRootProviderCertificatesMap")]
    pub type TRootProviderCertificatesMap;
}
