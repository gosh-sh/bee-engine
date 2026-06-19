use serde_json::json;
use url::Url;

pub struct ParamsOfUpdateBoost {
    pub api_url: String,
    pub multifactor_address: String,
}

pub async fn update_boost_code(params: ParamsOfUpdateBoost) -> crate::errors::AppResult<()> {
    let base = Url::parse(&params.api_url)
        .map_err(|e| crate::errors::AppError::from(e).with_context("Invalid api_url"))?;

    let url = base
        .join("blockchain/update-boost")
        .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to build url"))?;
    let client = reqwest::Client::new();

    let response = client
        .post(url)
        .json(&json!({
            "multifactor_address": params.multifactor_address
        }))
        .send()
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("Failed to send update boost request")
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        return Err(crate::errors::AppError::new(format!(
            "Failed to update boost (status: {}, body: {})",
            status, body
        )));
    }

    Ok(())
}
