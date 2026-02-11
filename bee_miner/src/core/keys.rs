use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicDeriveSignKeys;
use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicFromRandom;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;

const MINING_WORD_COUNT: u8 = 24;
const DEEPLINK_RESOLVER_URL: &str = "https://links.gosh.sh";

#[derive(Debug, Clone)]
pub struct ResultOfGenMiningKeys {
    pub keys: KeyPair,
    pub deep_link: String,
}

#[derive(Serialize)]
struct MiningKeysDeeplinkPayloadData<'a> {
    pubkey: &'a str,
    app_id: &'a str,
}

impl ResultOfGenMiningKeys {
    pub fn deep_link(public: impl AsRef<str>, app_id: impl AsRef<str>) -> Result<String, String> {
        let payload =
            MiningKeysDeeplinkPayloadData { pubkey: public.as_ref(), app_id: app_id.as_ref() };

        let payload = serde_json::to_vec(&payload)
            .map_err(|e| format!("Serialize deep link payload ({e})"))?;
        let payload = URL_SAFE_NO_PAD.encode(payload);

        Ok(format!("{DEEPLINK_RESOLVER_URL}/deeplinks/wallet/connect?payload={payload}"))
    }
}

pub async fn gen_mining_keys(app_id: impl AsRef<str>) -> Result<ResultOfGenMiningKeys, String> {
    let context = Arc::new({
        let mut cfg = ClientConfig::default();
        cfg.network.endpoints = Some(vec!["localhost".to_string()]);
        ClientContext::new(cfg).map_err(|e| format!("Create tvm client context ({e})"))?
    });

    let mnemonic = ackinacki_kit::tvm_client::crypto::mnemonic_from_random(
        context.clone(),
        ParamsOfMnemonicFromRandom { dictionary: None, word_count: Some(MINING_WORD_COUNT) },
    )
    .map_err(|e| format!("Failed to generate mnemonic phrase ({e})"))?;

    let key_pair = ackinacki_kit::tvm_client::crypto::mnemonic_derive_sign_keys(
        context,
        ParamsOfMnemonicDeriveSignKeys {
            phrase: mnemonic.phrase,
            path: None,
            dictionary: None,
            word_count: Some(MINING_WORD_COUNT),
        },
    )
    .map_err(|e| format!("Failed to derive key pair ({e})"))?;

    Ok(ResultOfGenMiningKeys {
        deep_link: ResultOfGenMiningKeys::deep_link(&key_pair.public, app_id.as_ref())?,
        keys: key_pair,
    })
}
