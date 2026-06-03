use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::miner::contract::Miner;
use ackinacki_kit::contracts::mvsystem::mirror::Mirror;
use ackinacki_kit::contracts::mvsystem::mirror::ParamsOfGetMinerAddress;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetIndexer;
use ackinacki_kit::contracts::traits::AddressAccessor;
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
pub struct ParamsOfGetMinerAddressByWalletName {
    pub client_config: ClientConfig,
    pub wallet_name: String,
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
    let miner = Arc::new(Miner::new_default(context, &params.miner_address));
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

pub async fn get_miner_address_by_wallet_name(
    params: ParamsOfGetMinerAddressByWalletName,
) -> Result<String, String> {
    let context = Arc::new(
        ClientContext::new(params.client_config)
            .map_err(|e| format!("Create tvm client context ({e})"))?,
    );

    let multifactor_address =
        get_multifactor_address_by_wallet_name(context.clone(), &params.wallet_name).await?;
    let miner = resolve_miner_for_multifactor(context, &multifactor_address).await?;
    Ok(miner.address().to_string())
}

async fn get_multifactor_address_by_wallet_name(
    tvm_client: Arc<ClientContext>,
    wallet_name: &str,
) -> Result<String, String> {
    let root = MobileVerifiersRoot::new_default(tvm_client);
    let indexer = root
        .get_indexer(ParamsOfGetIndexer { name: wallet_name.to_string() })
        .await
        .map_err(|e| format!("Get indexer by wallet name ({e})"))?;

    let details = indexer.get_details().await.map_err(|e| format!("Get indexer details ({e})"))?;

    Ok(details.multifactor_address)
}

async fn resolve_miner_for_multifactor(
    tvm_client: Arc<ClientContext>,
    multifactor_address: &str,
) -> Result<Miner, String> {
    let mirror = resolve_mirror_for_multifactor(tvm_client, multifactor_address)?;
    mirror
        .get_miner(ParamsOfGetMinerAddress { multifactor_address: multifactor_address.to_string() })
        .await
        .map_err(|e| format!("Resolve miner for multifactor ({e})"))
}

fn resolve_mirror_for_multifactor(
    tvm_client: Arc<ClientContext>,
    multifactor_address: &str,
) -> Result<Mirror, String> {
    let tail = multifactor_address
        .rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Invalid multifactor address format: {multifactor_address}"))?;

    Mirror::new_default(tvm_client, tail).map_err(|e| format!("Mirror::new ({e})"))
}

#[cfg(all(test, not(feature = "wasm")))]
mod tests {
    use ackinacki_kit::tvm_client::ClientConfig;
    use base64::Engine;
    use serde::Deserialize;

    use super::DEEPLINK_RESOLVER_URL;
    use super::URL_SAFE_NO_PAD;

    const APP_ID: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

    #[derive(Debug, Deserialize)]
    struct DecodedPayload {
        pubkey: String,
        app_id: String,
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gen_mining_keys_generates_keys_and_valid_deep_link() {
        let result = super::gen_mining_keys(APP_ID).await.expect("keys should be generated");

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

    #[tokio::test(flavor = "current_thread")]
    async fn get_miner_address_by_wallet_name_for_known_wallets() {
        let candidates = ["demo_wallet"];
        let mut last_error = String::new();

        for wallet_name in candidates {
            let mut cfg = ClientConfig::default();
            cfg.network.endpoints = Some(vec!["mainnet.ackinacki.org".to_string()]);

            match super::get_miner_address_by_wallet_name(
                super::ParamsOfGetMinerAddressByWalletName {
                    client_config: cfg,
                    wallet_name: wallet_name.to_string(),
                },
            )
            .await
            {
                Ok(address) => {
                    assert!(!address.is_empty(), "resolved miner address should not be empty");
                    assert!(
                        address.contains(':'),
                        "resolved miner address should look like TVM address, got: {address}"
                    );
                    return;
                }
                Err(e) => {
                    last_error = format!("wallet `{wallet_name}`: {e}");
                }
            }
        }

        panic!("Failed to resolve miner address for demo_wallet or wapp_t_1: {last_error}");
    }
}
