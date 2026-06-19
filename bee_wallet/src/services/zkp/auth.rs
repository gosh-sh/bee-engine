use crate::services::zkp::utils::provider::OIDCProvider;
use crate::services::zkp::utils::zk_login::decode_base64_url;
use crate::services::zkp::utils::zk_login::verify_extended_claim;

const ISS: &str = "iss";

pub struct Claim {
    pub value: String,
    pub index_mod_4: u8,
}

pub fn get_auth_provider(claim: Claim) -> crate::errors::AppResult<OIDCProvider> {
    let ext_claim = decode_base64_url(&claim.value, &claim.index_mod_4).map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context("[get_auth_provider]: failed to decode claims")
    })?;
    let iss = verify_extended_claim(&ext_claim, ISS).map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context("[get_auth_provider]: failed to verify_extended_claim")
    })?;
    let provider = OIDCProvider::from_iss(&iss).map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context("[get_auth_provider]: failed to create oidc provider")
    })?;

    Ok(provider)
}

pub fn get_domain_by_auth_provider(provider: &OIDCProvider) -> crate::errors::AppResult<String> {
    match provider {
        OIDCProvider::Google => Ok("www.googleapis.com".to_string()),
        OIDCProvider::Gosh => Ok("oauth.gosh.sh".to_string()),
        OIDCProvider::Facebook => Ok("www.facebook.com".to_string()),
        other => Err(crate::errors::AppError::new(format!("bad auth provider: {other:?}"))),
    }
}
