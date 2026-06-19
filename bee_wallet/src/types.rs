use ackinacki_kit::contracts::mvsystem::multifactor::AccountData as MultifactorData;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use num_bigint::BigInt;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::DisplayFromStr;

pub fn deserialize_u64_from_string_or_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrString {
        Number(u64),
        String(String),
    }

    match NumberOrString::deserialize(deserializer)? {
        NumberOrString::Number(v) => Ok(v),
        NumberOrString::String(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsOfGetMultifactorAddress {
    pub pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateMultifactorZkIdReq {
    pub address: String,
    pub zkid: String,
    pub password: String,
    pub proof: String,
    pub epk: String,
    pub esk: String,
    pub jwk_modulus: String,
    pub jwk_modulus_expire_at: i64,
    pub index_mod_4: i64,
    pub iss_base_64: String,
    pub header_base_64: String,
    pub epk_expire_at: i64,
    pub pubkey: String,
    pub secretkey: String,
    pub kid: String,
    pub sub: String,
}

impl std::fmt::Debug for UpdateMultifactorZkIdReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateMultifactorZkIdReq")
            .field("address", &self.address)
            .field("zkid", &self.zkid)
            .field("password", &"[REDACTED]")
            .field("proof", &"[REDACTED]")
            .field("epk", &self.epk)
            .field("esk", &"[REDACTED]")
            .field("jwk_modulus", &self.jwk_modulus)
            .field("jwk_modulus_expire_at", &self.jwk_modulus_expire_at)
            .field("index_mod_4", &self.index_mod_4)
            .field("iss_base_64", &self.iss_base_64)
            .field("header_base_64", &self.header_base_64)
            .field("epk_expire_at", &self.epk_expire_at)
            .field("pubkey", &self.pubkey)
            .field("secretkey", &"[REDACTED]")
            .field("kid", &self.kid)
            .field("sub", &self.sub)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsGetMirrorAddress {
    pub pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResultGetMirrorAddress {
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsOfGetMultifactorInfo {
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResultOfGetMultifactorInfo {
    pub data: Option<MultifactorData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBalanceByTokenRootReq {
    pub token_root: String,
    /// Bare 64-hex dApp ID of `token_root` (TIP-3 only; ignored for ECC "1"/"2"
    /// and on gql-server < 1.0.0).
    pub token_dapp: String,
    pub multifactor_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResultOfGetBalanceByTokenRoot {
    pub own_balance: ResultOfGetBalance,
    pub locked_balance: Option<ResultOfGetBalance>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ResultOfGetBalance {
    #[serde_as(as = "DisplayFromStr")]
    pub value: BigInt,
    #[serde_as(as = "DisplayFromStr")]
    pub decimals: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawPopitgameRewardsReq {
    pub multifactor_address: String,
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub bounce: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTokensReq {
    pub multifactor_address: String,
    pub destination_address: String,
    pub token_root: String,
    /// Bare 64-hex dApp ID of `token_root` (TIP-3 only; ignored for ECC and on
    /// gql-server < 1.0.0).
    pub token_dapp: String,
    #[serde(deserialize_with = "deserialize_u64_from_string_or_number")]
    pub amount_raw: u64,
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub bounce: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTokensDirectReq {
    pub multifactor_address: String,
    pub destination_address: String,
    pub token_root: String,
    #[serde(deserialize_with = "deserialize_u64_from_string_or_number")]
    pub amount_raw: u64,
    pub flags: u8,
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub bounce: Option<bool>,
    /// Native value (gas) attached to the message, in nanotons.
    /// Default: 1_000_000_000 (1 VMShell).
    #[serde(default)]
    pub value: Option<u128>,
    /// ABI-encoded message body (base64). When set, the message carries
    /// a function call to the destination contract.
    #[serde(default)]
    pub payload: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetEPKExpireReq {
    pub epk: String,
    pub multifactor_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetEPKExpireRes {
    pub epk_expire_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResultOfBlockchainWrite {
    pub message_ids: Vec<String>,
    pub pending_stage: Option<String>,
    pub pending_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuyShellsReq {
    /// Multifactor wallet address of the sender.
    pub multifactor_address: String,
    /// Amount in whole USDC (no decimals). SDK multiplies by
    /// USDC_DECIMALS_FACTOR internally.
    pub usdc_amount: u64,
    /// Signer keys (EPK factor).
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub bounce: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SellShellsReq {
    /// Multifactor wallet address of the sender.
    pub multifactor_address: String,
    /// Denomination: 1, 10, 100, or 1000 (whole USDC).
    /// SDK computes Shell amount = D * SHELL_PER_USDC.
    pub denom: u16,
    /// Signer keys (EPK factor).
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub bounce: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SellShellsResult {
    /// Hash of the sent message.
    pub message_hash: Option<String>,
    /// Assigned order_id.
    pub order_id: u64,
    /// Order denomination.
    pub denom: u16,
    /// SellOrderLot contract address.
    pub sell_order_address: String,
    /// Order already sold (bought by a buyer).
    pub sold: bool,
    /// Position in queue (0 if sold).
    /// If not sold: how many orders ahead (including this one).
    pub position_in_queue: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimUsdcReq {
    /// Order denomination (1, 10, 100, 1000).
    pub denom: u16,
    /// Order ID (from SellShellsResult.order_id).
    pub order_id: u64,
    /// Signer keys.
    pub signer_keys: KeyPair,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimUsdcResult {
    /// Hash of the sent message.
    pub message_hash: Option<String>,
    /// Payout in micro-USDC (D * USDC_DECIMALS_FACTOR).
    pub usdc_payout: u64,
}

fn default_sell_orders_page_size() -> u32 {
    20
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetMySellOrdersReq {
    /// Multifactor wallet address (seller).
    pub multifactor_address: String,
    /// Number of records per page (default 20).
    #[serde(default = "default_sell_orders_page_size")]
    pub page_size: u32,
    /// Cursor for the next page (`None` = first page).
    pub cursor: Option<String>,
}

/// Paginated result of `get_my_sell_orders`.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetMySellOrdersResult {
    pub orders: Vec<SellOrderInfo>,
    /// Opaque cursor for the next page (`None` = last page).
    pub next_cursor: Option<String>,
    pub has_next_page: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SellOrderInfo {
    pub denom: u16,
    pub order_id: u64,
    pub sell_order_address: String,
    pub claimed: bool,
    pub sold: bool,
    /// Position in queue (1..N for unsold, 0 for sold).
    pub position_in_queue: u64,
}

impl From<ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::SellerOrderInfo>
    for SellOrderInfo
{
    fn from(
        info: ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::SellerOrderInfo,
    ) -> Self {
        Self {
            denom: info.denom,
            order_id: info.order_id,
            sell_order_address: info.sell_order_address,
            claimed: info.claimed,
            sold: info.sold,
            position_in_queue: info.position_in_queue,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NacklRedeemRateResult {
    /// USDC available for redemption (micro-USDC).
    pub redeemable_usdc: u128,
    /// Current NACKL supply in circulation (nanoNACKL): supply - burned.
    pub current_nackl_supply: u128,
    /// Estimated USDC payout for 1 whole NACKL, scaled by 1e18.
    /// To get micro-USDC per 1 whole NACKL: `usdc_per_nackl / 1e9`.
    /// To get micro-USDC for N nanoNACKL: `N * usdc_per_nackl / 1e18`.
    /// 0 if currentSupply == 0 or redeemable == 0.
    pub usdc_per_nackl: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemNacklReq {
    pub multifactor_address: String,
    pub nackl_amount: u64,
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub bounce: Option<bool>,
}

/// Migrate TIP-3 USDC to ECC[3] USDC via Exchange contract.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrateTip3UsdcReq {
    pub multifactor_address: String,
    /// TIP-3 USDC token root address.
    pub token_root: String,
    /// Bare 64-hex dApp ID of `token_root` (ignored on gql-server < 1.0.0).
    pub token_dapp: String,
    /// Amount in raw micro-USDC (decimals=6).
    #[serde(deserialize_with = "deserialize_u64_from_string_or_number")]
    pub amount_raw: u64,
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub bounce: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfUpdateContract {
    pub multifactor_address: String,
    pub keys: KeyPair,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteZkpFactorByItselfReq {
    pub multifactor_address: String,
    pub signer_keys: KeyPair,
}
