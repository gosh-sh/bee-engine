use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::mirror::ParamsOfDeployMultifactor;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::ClientContext;
use bee_crypto::Crypto as BeeCrypto;
use gosh_tls_lib::tls_connect::get_root_certs_map;
use serde::Deserialize;
use serde::Serialize;

use crate::services::multifactor::key_derivation::build_recovery_keys;
use crate::services::multifactor::key_derivation::build_update_jwk_keys;
use crate::services::multifactor::key_derivation::ParamsOfBuildRecoveryKeys;
use crate::services::multifactor::key_derivation::ParamsOfBuildUpdateJwkKeys;
use crate::services::multifactor::WASM_HASH;
use crate::services::zkp::auth::get_auth_provider;
use crate::services::zkp::auth::get_domain_by_auth_provider;
use crate::services::zkp::auth::Claim;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParamsOfPrepareDeploy {
    pub zkid: String,
    pub password: String,
    pub proof: String,
    pub epk: String,
    pub esk: String,
    pub jwk_modulus: String,
    pub jwk_modulus_expire_at: u64,
    pub index_mod_4: u8,
    pub iss_base_64: String,
    pub header_base_64: String,
    pub epk_expire_at: u64,
    pub keys: KeyPair,
    pub kid: String,
    pub wallet_name: String,
    pub multifactor_address: String,
    pub sub: String,
}

pub async fn prepare_multifactor_deploy(
    tvm_context: Arc<ClientContext>,
    params: ParamsOfPrepareDeploy,
) -> crate::errors::AppResult<(ParamsOfDeployMultifactor, String)> {
    let crypto = BeeCrypto::from_client_context(tvm_context.clone());
    let provider = get_auth_provider(Claim {
        value: params.iss_base_64.clone(),
        index_mod_4: params.index_mod_4,
    })?;

    let domain = get_domain_by_auth_provider(&provider)?;

    let root_provider_certificates = get_root_certs_map(&domain).map_err(|e| {
        crate::errors::AppError::from(e).with_context("failed to get root certificates")
    })?;

    let (recovery_keys_fn, update_jwk_keys_fn) = tokio::join!(
        build_recovery_keys(
            tvm_context.clone(),
            ParamsOfBuildRecoveryKeys {
                password: params.password.clone(),
                multifactor_address: params.multifactor_address.clone(),
            }
        ),
        build_update_jwk_keys(
            tvm_context.clone(),
            ParamsOfBuildUpdateJwkKeys {
                password: params.password.clone(),
                sub: params.sub.clone(),
            }
        )
    );

    let recovery_keys = recovery_keys_fn?;
    let update_jwk_keys = update_jwk_keys_fn?;
    let epk_sig = crypto.sign_detached_hex(params.epk.clone(), params.esk)?;

    let deploy_params = ParamsOfDeployMultifactor {
        name: params.wallet_name,
        zkid: params.zkid,
        proof: params.proof,
        epk: format!("0x{}", params.epk),
        epk_sig,
        epk_expire_at: params.epk_expire_at,
        jwk_modulus: params.jwk_modulus,
        kid: params.kid,
        jwk_modulus_expire_at: params.jwk_modulus_expire_at,
        index_mod_4: params.index_mod_4,
        iss_base_64: params.iss_base_64,
        header_base_64: params.header_base_64,
        pub_recovery_key: recovery_keys.pub_recovery_key,
        pub_recovery_key_sig: recovery_keys.pub_recovery_key_sig,
        // owner_pubkey: format!("0x{}", params.keys.public.clone()),
        root_provider_certificates,
        provider: provider.to_string(),
        jwk_update_key: update_jwk_keys.pub_jwk_update_key,
        jwk_update_key_sig: update_jwk_keys.pub_jwk_update_sig,
    };

    Ok((deploy_params, WASM_HASH.to_string()))
}
