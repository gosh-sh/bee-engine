use std::collections::HashMap;
use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSubmitTransaction;
use ackinacki_kit::contracts::mvsystem::ContractIndex;
use ackinacki_kit::contracts::traits::AbiAccessor;
use ackinacki_kit::tvm_client::abi::CallSet;
use ackinacki_kit::tvm_client::abi::ParamsOfEncodeMessageBody;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::processing::ResultOfSendMessage;
use ackinacki_kit::tvm_client::ClientContext;
use dodex_contracts::dex::root_pn::ParamsOfGenerateVoucher as KitParamsOfGenerateVoucher;
use dodex_contracts::dex::root_pn::RootPn;
use serde_json::json;

use crate::errors::AppError;
use crate::errors::AppResult;

#[allow(dead_code)]
pub struct ParamsOfGenerateVoucher {
    pub multifactor_address: String,
    pub token_type: u32,
    pub amount: u64,
    pub is_fee: bool,
    /// `skUCommit` to embed in the `RootPN.generateVoucher` payload — for the
    /// production halo2 flow this must match `poseidon([sk_u, 0])` of the
    /// `sk_u` the prover will use. Pass `"0"` when no halo2 binding is needed.
    pub sk_u_commit: String,
    pub signer_keys: ackinacki_kit::tvm_client::crypto::KeyPair,
    pub epk_expire_at: u64,
    pub mirror_index: u128,
}

/// Add RootPN to whitelist, encode `generatevoucher` payload, and send ECC
/// tokens from the multifactor to RootPN via `submitTransaction`.
pub async fn generate_voucher(
    tvm_client: Arc<ClientContext>,
    multifactor: &Arc<Multifactor>,
    params: ParamsOfGenerateVoucher,
) -> AppResult<ResultOfSendMessage> {
    let signer = Signer::Keys { keys: params.signer_keys };

    // 1. Add RootPN to whitelist
    super::multifactor::whitelist::update_multifactor_whitelist_and_wait(
        multifactor,
        super::multifactor::whitelist::ParamsOfUpdateMultifactorWhiteList {
            epk_expire_at: params.epk_expire_at,
            payload_destination: ContractIndex::RootPn,
            target_address: RootPn::DEFAULT_ADDRESS.to_string(),
            mirror_index: params.mirror_index,
            whitelisted_name: None,
        },
        &signer,
    )
    .await
    .map_err(|e| e.with_context("generate_voucher: add RootPN to whitelist"))?;

    // 2. Encode generatevoucher payload using RootPn ABI
    let root_pn =
        RootPn::new(tvm_client.clone(), crate::dapp::dex_contract_params(RootPn::DEFAULT_ADDRESS));
    let payload = ackinacki_kit::tvm_client::abi::encode_message_body(
        tvm_client,
        ParamsOfEncodeMessageBody {
            abi: root_pn.abi().clone(),
            call_set: CallSet {
                function_name: "generateVoucher".to_string(),
                header: None,
                input: Some(json!(KitParamsOfGenerateVoucher {
                    sk_u_commit: params.sk_u_commit.clone(),
                    is_fee: params.is_fee,
                })),
            },
            is_internal: true,
            signer: Signer::None,
            processing_try_index: None,
            address: None,
            signature_id: None,
        },
    )
    .await
    .map_err(|e| AppError::from(e).with_context("encode generatevoucher payload"))?
    .body;

    // 3. Submit transaction: send ECC + 2 vmshell native (compute fuel for
    //    `RootPN.generateVoucher`) to RootPN with the encoded payload.
    let ecc = HashMap::from([(params.token_type, params.amount)]);
    let result = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: RootPn::DEFAULT_ADDRESS.to_string(),
                epk_expire_at: params.epk_expire_at,
                value: 2_000_000_000,
                cc: ecc,
                bounce: true,
                all_balance: false,
                payload,
            },
            signer,
        )
        .await
        .map_err(|e| AppError::from(e).with_context("generate_voucher: submit_transaction"))?;

    crate::infra::ensure_tx_success(result, "generate_voucher")
}
