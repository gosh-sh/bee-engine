// Live network tests run by default — shellnet is always available.
// Tests share on-chain state, so they must run sequentially.
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use ackinacki_kit::contracts::account::AccountStatus;
use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::authservice::profile::AuthProfile;
use ackinacki_kit::contracts::authservice::root::AuthServiceRoot;
use ackinacki_kit::contracts::authservice::root::ParamsOfDeployProfileByIdentity;
use ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress;
use ackinacki_kit::contracts::authservice::root::ParamsOfHashMultifactor;
use ackinacki_kit::contracts::authservice::root::ParamsOfHashPubkey;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSubmitTransaction;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bee_connect::ConnectClient;
use bee_connect::ParamsOfCreateSharedKeySession;
use bee_connect::ParamsOfDisconnectSession;
use bee_connect::ParamsOfQueryActiveSessionsByMultifactor;
use bee_connect::ParamsOfRequestSetMiningKeys;
use bee_connect::ParamsOfResolveProfileAddress;
use bee_connect::ParamsOfWaitSetMiningKeysRequest;
use bee_connect::ParamsOfWaitWalletHello;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use hkdf::Hkdf;
use serial_test::serial;
use sha2::Sha256;

const ENDPOINT: &str = "https://shellnet.ackinacki.org";
const AUTH_SERVICE_MULTIFACTOR_ADDRESS: &str =
    "0:3d51528b8ad806dea2018d24fa9a428386f1c6883fb0944684fc08c4bbbe223a";
const AUTH_SERVICE_MULTIFACTOR_EPK: &str =
    "2b9d728a42e05dfe43a10fa0d8e16b0b06ad482822309fe1aabac01aff8b34ee";
const AUTH_SERVICE_MULTIFACTOR_ESK: &str =
    "8328afbf10019fa8d0002a3764f8bb433f8f5cf84ec51af0cdc172c6ef72dd29";
const AUTH_SERVICE_MULTIFACTOR_EPK_EXPIRE_AT: u64 = 1_788_095_099;

#[tokio::test]
#[serial]
async fn test_shared_key_handshake() {
    let context = create_context();
    let root = AuthServiceRoot::new_default(context.clone());

    let client = ConnectClient::new();
    let session = client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x1".to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session");

    // Simulate wallet-side DH key exchange
    let wallet_dh = bee_connect::dh::generate_dh_keypair().unwrap();
    let shared =
        bee_connect::dh::compute_shared_secret(&wallet_dh.secret_hex, &session.client_dh_public)
            .unwrap();
    let keys = bee_connect::dh::derive_session_keys(&shared, &session.session_id).unwrap();
    let signing_keys = KeyPair {
        public: keys.signing_public_hex.clone(),
        secret: keys.signing_secret_hex.to_string(),
    };

    let started_at = now_secs().saturating_sub(5);
    let endpoints = vec![ENDPOINT.to_string()];

    let profile_address = client
        .get_profile_address(ParamsOfResolveProfileAddress {
            endpoints: endpoints.clone(),
            description: session.description.clone(),
        })
        .await
        .expect("resolve profile address");

    let pubkey_hash = root
        .hash_pubkey(ParamsOfHashPubkey { pubkey: format!("0x{}", signing_keys.public) })
        .await
        .expect("hash_pubkey")
        .hash;
    let multifactor_hash = root
        .hash_multifactor(ParamsOfHashMultifactor {
            multifactor: AUTH_SERVICE_MULTIFACTOR_ADDRESS.to_string(),
        })
        .await
        .expect("hash_multifactor")
        .hash;

    let expected_profile = root
        .get_profile_address(ParamsOfGetProfileAddress { description: session.description.clone() })
        .await
        .expect("root get_profile_address")
        .profile;
    assert_eq!(profile_address.to_lowercase(), expected_profile.to_lowercase());

    let deploy_result = root
        .deploy_profile_by_identity(
            ParamsOfDeployProfileByIdentity {
                pubkey: format!("0x{}", signing_keys.public),
                multifactor_address: AUTH_SERVICE_MULTIFACTOR_ADDRESS.to_string(),
                description: session.description.clone(),
            },
            Signer::None,
        )
        .await
        .expect("deploy_profile_by_identity");
    ensure_tx_success(deploy_result, "deploy_profile_by_identity");

    let profile = AuthProfile::new_default(context.clone(), &profile_address);
    profile
        .wait_account(ParamsOfWaitAccount {
            status: AccountStatus::Active,
            attempts: Some(60),
            attempts_timeout: Some(2_000),
        })
        .await
        .expect("wait profile active");

    let details = profile.get_details().await.expect("get profile details");
    assert_eq!(details.description, session.description);
    assert_eq!(details.pubkey_hash.to_lowercase(), pubkey_hash.to_lowercase());
    assert_eq!(details.multifactor_hash.to_lowercase(), multifactor_hash.to_lowercase());

    // Wallet-side: send encrypted wallet_hello with DH public key
    let wallet_hello_json = encode_wallet_hello(
        &session.session_id,
        "shellnet_test_wallet",
        "0:feedbeef",
        &keys.encryption_root_hex,
        &wallet_dh.public_hex,
    );
    let hello_result = profile
        .add_context_text(&wallet_hello_json, Signer::Keys { keys: signing_keys.clone() })
        .await
        .expect("add_context_text wallet_hello");
    ensure_tx_success(hello_result, "wallet_hello add_context");

    // Client-side: wait for wallet_hello, finalize DH handshake
    let hello = retry_on_transient("wait_wallet_hello", || {
        let client = client.clone();
        let endpoints = endpoints.clone();
        let session_id = session.session_id.clone();
        let description = session.description.clone();
        let client_dh_secret = session.client_dh_secret.clone();
        async move {
            client
                .wait_wallet_hello(ParamsOfWaitWalletHello {
                    endpoints,
                    session_id,
                    description,
                    client_dh_secret,
                    created_at_from: Some(started_at),
                    max_attempts: Some(60),
                    interval_ms: Some(2_000),
                })
                .await
        }
    })
    .await
    .expect("wait_wallet_hello");
    assert_eq!(hello.wallet_name, "shellnet_test_wallet");
    assert_eq!(hello.wallet_address, "0:feedbeef");
    assert_eq!(hello.profile_address.to_lowercase(), profile_address.to_lowercase());

    let mut session_state = hello.session_state;

    // Client → Wallet: set_mining_keys
    let request_set_keys = client
        .request_set_mining_keys(ParamsOfRequestSetMiningKeys {
            endpoints: endpoints.clone(),
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: session_state.clone(),
            app_id: "0x1".to_string(),
            owner_public: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_set_mining_keys");
    session_state = request_set_keys.updated_session_state.clone();
    assert_eq!(request_set_keys.profile_address.to_lowercase(), profile_address.to_lowercase());
    assert!(request_set_keys.message_id.is_some());

    // Wallet reads set_mining_keys (using wallet-side session state)
    let wallet_session_state = bee_connect::dh::create_initial_state(
        &keys,
        &wallet_dh.secret_hex,
        &session.client_dh_public,
    );
    let set_keys = client
        .wait_set_mining_keys_request(ParamsOfWaitSetMiningKeysRequest {
            endpoints: endpoints.clone(),
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: Some(wallet_session_state),
            created_at_from: Some(started_at),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("wait_set_mining_keys_request");
    assert_eq!(set_keys.profile_address.to_lowercase(), profile_address.to_lowercase());
    assert_eq!(
        set_keys.app_id,
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(
        set_keys.owner_public,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    // Client → Wallet: disconnect
    let disconnect = client
        .disconnect_session(ParamsOfDisconnectSession {
            endpoints: endpoints.clone(),
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: session_state.clone(),
            reason: Some("user_requested".to_string()),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("disconnect_session");
    assert_eq!(disconnect.profile_address.to_lowercase(), profile_address.to_lowercase());
    assert!(disconnect.message_id.is_some());

    // Cleanup (best-effort — multifactor may not be active on testnet)
    destroy_profile_via_multifactor(context.clone(), &profile).await;
    let _ = profile
        .wait_account(ParamsOfWaitAccount {
            status: AccountStatus::NonExist,
            attempts: Some(10),
            attempts_timeout: Some(2_000),
        })
        .await;
}

#[tokio::test]
#[serial]
async fn test_query_active_sessions_by_multifactor_with_optional_app_id_filter() {
    let context = create_context();
    let root = AuthServiceRoot::new_default(context.clone());
    let client = ConnectClient::new();
    let endpoints = vec![ENDPOINT.to_string()];
    let started_at = now_secs().saturating_sub(2);

    let app_id_a = format!("0x{:064x}", now_secs());
    let app_id_b = format!("0x{:064x}", now_secs().saturating_add(1));

    let session_a = client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: app_id_a.clone(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session a");
    let session_b = client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: app_id_b.clone(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session b");

    // Simulate wallet-side DH to derive signing keys for profile deployment
    let wallet_dh_a = bee_connect::dh::generate_dh_keypair().unwrap();
    let shared_a = bee_connect::dh::compute_shared_secret(
        &wallet_dh_a.secret_hex,
        &session_a.client_dh_public,
    )
    .unwrap();
    let keys_a = bee_connect::dh::derive_session_keys(&shared_a, &session_a.session_id).unwrap();

    let wallet_dh_b = bee_connect::dh::generate_dh_keypair().unwrap();
    let shared_b = bee_connect::dh::compute_shared_secret(
        &wallet_dh_b.secret_hex,
        &session_b.client_dh_public,
    )
    .unwrap();
    let keys_b = bee_connect::dh::derive_session_keys(&shared_b, &session_b.session_id).unwrap();

    let malformed_description = format!("bee_connect:malformed:{}", now_secs());

    let profile_a = deploy_profile_for_description(
        &root,
        &context,
        &format!("0x{}", keys_a.signing_public_hex),
        &session_a.description,
    )
    .await;
    let profile_b = deploy_profile_for_description(
        &root,
        &context,
        &format!("0x{}", keys_b.signing_public_hex),
        &session_b.description,
    )
    .await;
    let malformed_profile = deploy_profile_for_description(
        &root,
        &context,
        &format!("0x{}", keys_a.signing_public_hex),
        &malformed_description,
    )
    .await;

    let test_result: Result<(), bee_connect::errors::AppError> = async {
        let mut unfiltered = None;
        for _ in 0..20 {
            let page = retry_on_transient("query_active_sessions_unfiltered", || {
                let client = client.clone();
                let endpoints = endpoints.clone();
                async move {
                    client
                        .query_active_sessions_by_multifactor(
                            ParamsOfQueryActiveSessionsByMultifactor {
                                endpoints,
                                multifactor_address: AUTH_SERVICE_MULTIFACTOR_ADDRESS.to_string(),
                                app_id: None,
                                created_at_from: Some(started_at),
                                before: None,
                            },
                        )
                        .await
                }
            })
            .await?;

            let has_a = page.sessions.iter().any(|s| {
                s.description == session_a.description
                    && s.app_id.as_deref() == Some(session_a.app_id.as_str())
            });
            let has_b = page.sessions.iter().any(|s| {
                s.description == session_b.description
                    && s.app_id.as_deref() == Some(session_b.app_id.as_str())
            });
            let has_malformed = page.sessions.iter().any(|s| {
                s.description == malformed_description
                    && s.app_id.is_none()
                    && s.session_id.is_none()
            });

            if has_a && has_b && has_malformed {
                unfiltered = Some(page);
                break;
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        let unfiltered = unfiltered.ok_or_else(|| {
            "query_active_sessions_by_multifactor: expected sessions not found".to_string()
        })?;
        assert!(!unfiltered.sessions.is_empty());

        let mut filtered = None;
        for _ in 0..20 {
            let page = retry_on_transient("query_active_sessions_filtered", || {
                let client = client.clone();
                let endpoints = endpoints.clone();
                let app_id = session_a.app_id.clone();
                async move {
                    client
                        .query_active_sessions_by_multifactor(
                            ParamsOfQueryActiveSessionsByMultifactor {
                                endpoints,
                                multifactor_address: AUTH_SERVICE_MULTIFACTOR_ADDRESS.to_string(),
                                app_id: Some(app_id),
                                created_at_from: Some(started_at),
                                before: None,
                            },
                        )
                        .await
                }
            })
            .await?;

            let has_a = page.sessions.iter().any(|s| s.description == session_a.description);
            if has_a {
                filtered = Some(page);
                break;
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        let filtered = filtered.ok_or_else(|| {
            "query_active_sessions_by_multifactor: filtered result empty".to_string()
        })?;
        assert!(filtered
            .sessions
            .iter()
            .all(|s| s.app_id.as_deref() == Some(session_a.app_id.as_str())));
        assert!(filtered.sessions.iter().any(|s| s.description == session_a.description));
        assert!(!filtered.sessions.iter().any(|s| s.description == session_b.description));
        assert!(!filtered.sessions.iter().any(|s| s.description == malformed_description));

        Ok(())
    }
    .await;

    // Cleanup (best-effort — multifactor may not be active on testnet)
    destroy_profile_via_multifactor(context.clone(), &profile_a).await;
    destroy_profile_via_multifactor(context.clone(), &profile_b).await;
    destroy_profile_via_multifactor(context.clone(), &malformed_profile).await;

    for (label, p) in [("a", &profile_a), ("b", &profile_b), ("malformed", &malformed_profile)] {
        let _ = p
            .wait_account(ParamsOfWaitAccount {
                status: AccountStatus::NonExist,
                attempts: Some(10),
                attempts_timeout: Some(2_000),
            })
            .await
            .inspect_err(|e| eprintln!("Warning: profile_{label} cleanup wait failed: {e}"));
    }

    if let Err(err) = test_result {
        panic!("{err}");
    }
}

#[tokio::test]
#[serial]
async fn test_query_active_sessions_regression_known_multifactor_no_duplicates() {
    let client = ConnectClient::new();
    let endpoints = vec![ENDPOINT.to_string()];

    let first_page = retry_on_transient("query_active_sessions_regression_page1", || {
        let client = client.clone();
        let endpoints = endpoints.clone();
        async move {
            client
                .query_active_sessions_by_multifactor(ParamsOfQueryActiveSessionsByMultifactor {
                    endpoints,
                    multifactor_address: AUTH_SERVICE_MULTIFACTOR_ADDRESS.to_string(),
                    app_id: None,
                    created_at_from: None,
                    before: None,
                })
                .await
        }
    })
    .await
    .expect("query first page");

    assert_no_duplicate_events(&first_page.sessions);

    if let Some(next_before) = first_page.next_before.clone() {
        let second_page = retry_on_transient("query_active_sessions_regression_page2", || {
            let client = client.clone();
            let endpoints = endpoints.clone();
            let next_before = next_before.clone();
            async move {
                client
                    .query_active_sessions_by_multifactor(
                        ParamsOfQueryActiveSessionsByMultifactor {
                            endpoints,
                            multifactor_address: AUTH_SERVICE_MULTIFACTOR_ADDRESS.to_string(),
                            app_id: None,
                            created_at_from: None,
                            before: Some(next_before),
                        },
                    )
                    .await
            }
        })
        .await
        .expect("query second page");

        assert_no_duplicate_events(&second_page.sessions);

        let first_events: HashSet<String> =
            first_page.sessions.iter().map(active_session_event_key).collect();
        let second_events: HashSet<String> =
            second_page.sessions.iter().map(active_session_event_key).collect();
        assert!(
            first_events.is_disjoint(&second_events),
            "pagination overlap by deploy event_id: first={first_events:?}, second={second_events:?}"
        );
    }
}

#[tokio::test]
#[serial]
async fn test_ping() {
    let client = ConnectClient::new();
    let result = client.ping();
    assert!(!result.is_empty(), "ping must return a non-empty string");
}

#[tokio::test]
#[serial]
async fn test_is_session_profile_deployed() {
    let context = create_context();
    let root = AuthServiceRoot::new_default(context.clone());
    let client = ConnectClient::new();
    let endpoints = vec![ENDPOINT.to_string()];

    // Create a session so we get a valid description
    let session = client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x1".to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session");

    // Simulate wallet-side DH to derive signing keys for profile deployment
    let wallet_dh = bee_connect::dh::generate_dh_keypair().unwrap();
    let shared =
        bee_connect::dh::compute_shared_secret(&wallet_dh.secret_hex, &session.client_dh_public)
            .unwrap();
    let keys = bee_connect::dh::derive_session_keys(&shared, &session.session_id).unwrap();

    // Deploy profile
    let profile = deploy_profile_for_description(
        &root,
        &context,
        &format!("0x{}", keys.signing_public_hex),
        &session.description,
    )
    .await;

    // Assert deployed profile is detected
    let deployed = retry_on_transient("is_session_profile_deployed_true", || {
        let client = client.clone();
        let endpoints = endpoints.clone();
        let description = session.description.clone();
        async move {
            client
                .is_session_profile_deployed(ParamsOfResolveProfileAddress {
                    endpoints,
                    description,
                })
                .await
        }
    })
    .await
    .expect("is_session_profile_deployed for deployed profile");
    assert!(deployed, "expected deployed profile to return true");

    // Assert bogus description returns false
    let bogus_description = format!("bee_connect:{}:bogus_session_id", now_secs());
    let not_deployed = retry_on_transient("is_session_profile_deployed_false", || {
        let client = client.clone();
        let endpoints = endpoints.clone();
        let description = bogus_description.clone();
        async move {
            client
                .is_session_profile_deployed(ParamsOfResolveProfileAddress {
                    endpoints,
                    description,
                })
                .await
        }
    })
    .await
    .expect("is_session_profile_deployed for bogus description");
    assert!(!not_deployed, "expected bogus description to return false");

    // Cleanup
    destroy_profile_via_multifactor(context.clone(), &profile).await;
    let _ = profile
        .wait_account(ParamsOfWaitAccount {
            status: AccountStatus::NonExist,
            attempts: Some(10),
            attempts_timeout: Some(2_000),
        })
        .await;
}

// ---------------------------------------------------------------------------
// Wallet-hello encoder (replicates bee_wallet logic for test isolation)
// ---------------------------------------------------------------------------

/// Builds an encrypted `wallet_hello` JSON envelope identical to what
/// `bee_wallet::services::connect::encode_wallet_hello_message` produces.
fn encode_wallet_hello(
    session_id: &str,
    wallet_name: &str,
    wallet_address: &str,
    encryption_root_hex: &str,
    wallet_dh_public_hex: &str,
) -> String {
    let seq = now_millis();
    let ts = now_secs();

    let body = serde_json::json!({
        "wallet_name": wallet_name,
        "wallet_address": wallet_address,
    });
    let plaintext = serde_json::to_vec(&body).expect("serialize wallet_hello body");

    let aad = serde_json::to_vec(&serde_json::json!({
        "v": "bee_connect.msg/1",
        "session_id": session_id,
        "dir": "w2c",
        "seq": seq,
        "type": "wallet_hello",
        "ts": ts,
    }))
    .expect("serialize AAD");

    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("generate nonce");
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("generate salt");

    let root_bytes = hex::decode(encryption_root_hex).expect("decode encryption_root_hex");
    let hk = Hkdf::<Sha256>::new(Some(&salt), &root_bytes);
    let mut key = [0u8; 32];
    hk.expand(b"bee_connect.msg.key.v1", &mut key).expect("HKDF expand");

    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
        .expect("encrypt wallet_hello");

    let envelope = serde_json::json!({
        "v": "bee_connect.msg/1",
        "session_id": session_id,
        "dir": "w2c",
        "seq": seq,
        "type": "wallet_hello",
        "ts": ts,
        "dh_public": wallet_dh_public_hex,
        "enc": {
            "alg": "xchacha20poly1305-hkdf-sha256",
            "nonce": URL_SAFE_NO_PAD.encode(nonce),
            "salt": URL_SAFE_NO_PAD.encode(salt),
        },
        "body": URL_SAFE_NO_PAD.encode(ciphertext),
    });

    serde_json::to_string(&envelope).expect("serialize wallet_hello envelope")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn create_context() -> Arc<ClientContext> {
    let mut config = ClientConfig::default();
    config.network.endpoints = Some(vec![ENDPOINT.to_string()]);
    Arc::new(ClientContext::new(config).expect("Create live network client context"))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("time").as_secs()
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("time").as_millis() as u64
}

fn multifactor_signer() -> Signer {
    Signer::Keys {
        keys: KeyPair {
            public: AUTH_SERVICE_MULTIFACTOR_EPK.to_string(),
            secret: AUTH_SERVICE_MULTIFACTOR_ESK.to_string(),
        },
    }
}

async fn deploy_profile_for_description(
    root: &AuthServiceRoot,
    context: &Arc<ClientContext>,
    owner_pubkey: &str,
    description: &str,
) -> AuthProfile {
    let deploy_result = root
        .deploy_profile_by_identity(
            ParamsOfDeployProfileByIdentity {
                pubkey: owner_pubkey.to_string(),
                multifactor_address: AUTH_SERVICE_MULTIFACTOR_ADDRESS.to_string(),
                description: description.to_string(),
            },
            Signer::None,
        )
        .await
        .expect("deploy_profile_by_identity");
    ensure_tx_success(deploy_result, "deploy_profile_by_identity");

    let profile_address = root
        .get_profile_address(ParamsOfGetProfileAddress { description: description.to_string() })
        .await
        .expect("get_profile_address")
        .profile;
    let profile = AuthProfile::new_default(context.clone(), &profile_address);
    profile
        .wait_account(ParamsOfWaitAccount {
            status: AccountStatus::Active,
            attempts: Some(60),
            attempts_timeout: Some(2_000),
        })
        .await
        .expect("wait profile active");
    profile
}

async fn destroy_profile_via_multifactor(context: Arc<ClientContext>, profile: &AuthProfile) {
    let multifactor = Multifactor::new_default(context, AUTH_SERVICE_MULTIFACTOR_ADDRESS);
    let send_result = retry_on_transient("destroy_profile_via_multifactor", || {
        let multifactor = multifactor.clone();
        let profile_address = profile.address().to_string();
        async move {
            let result = multifactor
                .submit_transaction(
                    ParamsOfSubmitTransaction {
                        dest: profile_address,
                        value: 1_000_000_000,
                        cc: Default::default(),
                        bounce: false,
                        all_balance: false,
                        epk_expire_at: AUTH_SERVICE_MULTIFACTOR_EPK_EXPIRE_AT,
                        payload: String::new(),
                    },
                    multifactor_signer(),
                )
                .await
                .map_err(|e| format!("submit_transaction destroy profile ({e})"))?;
            ensure_tx_success(result, "destroy_profile_via_multifactor");
            Ok(())
        }
    })
    .await;

    if let Err(e) = send_result {
        eprintln!(
            "Warning: failed to destroy profile {} (non-fatal cleanup): {e}",
            profile.address()
        );
    }
}

fn ensure_tx_success(
    result: ackinacki_kit::tvm_client::processing::ResultOfSendMessage,
    context: &str,
) {
    let aborted = result.aborted.unwrap_or(false);
    let exit_code = result.exit_code.unwrap_or(0);
    assert!(!(aborted || exit_code > 0), "{context}: tx aborted={aborted}, exit_code={exit_code}");
}

fn is_transient_client_error(err: &bee_connect::errors::AppError) -> bool {
    let lower = err.message.to_ascii_lowercase();
    lower.contains("connection reset by peer")
        || lower.contains("client error (sendrequest)")
        || lower.contains("all attempts failed")
}

async fn retry_on_transient<T, F, Fut>(
    label: &str,
    mut action: F,
) -> Result<T, bee_connect::errors::AppError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, bee_connect::errors::AppError>>,
{
    let max_attempts = 4;
    for attempt in 1..=max_attempts {
        match action().await {
            Ok(v) => return Ok(v),
            Err(err) if is_transient_client_error(&err) && attempt < max_attempts => {
                eprintln!("{label}: transient error on attempt {attempt}/{max_attempts}: {err}");
                tokio::time::sleep(Duration::from_millis(700)).await;
            }
            Err(err) => return Err(err),
        }
    }

    unreachable!()
}

fn active_session_event_key(session: &bee_connect::ActiveConnectSession) -> String {
    session.deployed_event_id.clone()
}

fn assert_no_duplicate_events(sessions: &[bee_connect::ActiveConnectSession]) {
    let mut seen = HashSet::new();
    for session in sessions {
        let key = active_session_event_key(session);
        assert!(seen.insert(key.clone()), "duplicate deploy event in page: {key}");
    }
}
