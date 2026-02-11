use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::miner::contract::Miner;
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
pub struct ParamsOfEnsureMiningKeysPropagated {
    pub client_config: ClientConfig,
    pub miner_address: String,
    pub app_id: String,
    pub expected_owner_public: String,
    pub max_attempts: Option<u32>,
    pub interval_ms: Option<u64>,
}

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

pub async fn ensure_mining_keys_propagated(
    params: ParamsOfEnsureMiningKeysPropagated,
) -> Result<(), String> {
    let context = Arc::new(
        ClientContext::new(params.client_config)
            .map_err(|e| format!("Create tvm client context ({e})"))?,
    );
    let miner = Arc::new(Miner::new(context, &params.miner_address));
    let app_id = params.app_id;
    let expected_owner_public = params.expected_owner_public;

    bee_infra::poll_until(
        || {
            let miner = miner.clone();
            async move {
                miner
                    .get_details()
                    .await
                    .map_err(|e| format!("ensure_mining_keys_propagated: miner.get_details ({e})"))
            }
        },
        move |details| details.owner_public.get(&app_id) == Some(&expected_owner_public),
        params.max_attempts,
        params.interval_ms,
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use futures::executor::block_on;
    use serde::Deserialize;

    use super::DEEPLINK_RESOLVER_URL;
    use super::URL_SAFE_NO_PAD;

    const APP_ID: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

    #[derive(Debug, Deserialize)]
    struct DecodedPayload {
        pubkey: String,
        app_id: String,
    }

    #[test]
    fn gen_mining_keys_generates_keys_and_valid_deep_link() {
        let result = block_on(super::gen_mining_keys(APP_ID)).expect("keys should be generated");

        assert!(!result.keys.public.is_empty(), "public key should not be empty");
        assert!(!result.keys.secret.is_empty(), "secret key should not be empty");

        let prefix = format!("{DEEPLINK_RESOLVER_URL}/deeplinks/wallet/connect?payload=");
        let payload =
            result.deep_link.strip_prefix(&prefix).expect("deep link should have payload query");

        let decoded_payload_bytes =
            URL_SAFE_NO_PAD.decode(payload).expect("payload should be valid base64url");
        let decoded_payload: DecodedPayload =
            serde_json::from_slice(&decoded_payload_bytes).expect("payload should be valid json");

        assert_eq!(decoded_payload.pubkey, result.keys.public);
        assert_eq!(decoded_payload.app_id, APP_ID);
    }
}
