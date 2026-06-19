use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::AccountData as MultifactorData;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfAddJwkModulus;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::ClientContext;
use serde::Deserialize;
use serde::Serialize;

use crate::infra::poll_until;
use crate::services::multifactor::key_derivation::resolve_jwk_update_signer;
use crate::services::multifactor::key_derivation::ParamsOfBuildUpdateJwkKeys;

#[derive(Debug)]
pub struct AddJwkModulusReq {
    pub kid: String,
    pub password: String,
    pub sub: String,
    pub kid_boc_hash: String,
}

pub async fn add_jwk_modulus(
    tvm_ctx: Arc<ClientContext>,
    multifactor: &Arc<Multifactor>,
    multifactor_data: &MultifactorData,
    params: AddJwkModulusReq,
) -> crate::errors::AppResult<Option<String>> {
    let tls_res =
        fetch_tls(multifactor_data.iss_base_64.clone(), multifactor_data.index_mod_4.clone())
            .await
            .map_err(|e| e.with_context("failed to fetch tls"))?;

    let lv_kid = to_lv_kid(&params.kid)?;

    // `addJwkModulus` is gated by `onlyOwnerPubkey(_jwk_update_key)`, so we must
    // sign with the key that matches the wallet's on-chain `jwk_update_key`.
    // Pre-v3 wallets hold it on the legacy (396) HD path; resolving against the
    // on-chain value lets them sign instead of failing with 402/ERR_NOT_OWNER.
    let (jwk_signer, _resolved_path) = resolve_jwk_update_signer(
        tvm_ctx.clone(),
        ParamsOfBuildUpdateJwkKeys { password: params.password.clone(), sub: params.sub.clone() },
        &multifactor_data.jwk_update_key,
    )?;
    let res = multifactor
        .add_jwk_modulus(
            ParamsOfAddJwkModulus {
                lv_kid,
                root_cert_sn: tls_res.root_cert_sn_hex,
                tls_data: tls_res.tls_data,
            },
            Signer::Keys { keys: jwk_signer },
        )
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to add jwk modulus"))?;

    let res = crate::infra::ensure_tx_success(res, "add_jwk_modulus")?;
    let message_id = res.message_hash.clone();

    let boc_hash = params.kid_boc_hash.clone();
    let mf = Arc::clone(multifactor);
    let _details = poll_until(
        || {
            let mf = mf.clone();
            async move {
                super::query::get_multifactor_decoded_data(&mf)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            }
        },
        move |data: &MultifactorData| {
            let existing_contract_jwk = data.jwk_modulus_data.get(&format!("0x{}", boc_hash));
            existing_contract_jwk.is_some()
        },
        None,
        None,
    )
    .await?;

    Ok(message_id)
}

#[derive(Deserialize)]
pub struct TLSRes {
    pub root_cert_sn_hex: String,
    pub tls_data: String,
}

#[derive(Serialize)]
struct GetTlsReq {
    pub iss_base_64: String,
    pub index_mod_4: String,
}

async fn fetch_tls(iss_base_64: String, index_mod_4: String) -> crate::errors::AppResult<TLSRes> {
    let client = reqwest::Client::new();

    let response = client
        .post("https://oauth.gosh.sh/v1/tls")
        .json(&GetTlsReq { iss_base_64, index_mod_4 })
        .send()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Send fetch tls request"))?;

    if !response.status().is_success() {
        return Err(crate::errors::AppError::new(format!(
            "Fetch tls response (status: {})",
            response.status()
        )));
    }

    let res = response
        .json::<TLSRes>()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to deserialize"))?;

    Ok(res)
}

fn to_lv_kid(kid_hex: &str) -> crate::errors::AppResult<String> {
    let kid = hex::decode(kid_hex)
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to decode kid_hex"))?;
    let len = kid.len() as u8;
    let mut out = Vec::with_capacity(1 + kid.len());
    out.push(len);
    out.extend_from_slice(&kid);

    Ok(hex::encode(out))
}
