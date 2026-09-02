use ackinacki_kit::contracts::account::AccountStatus;
use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::authservice::profile::AuthProfile;
use ackinacki_kit::contracts::authservice::profile::ParamsOfQueryProfileEvents;
use ackinacki_kit::contracts::authservice::root::AuthServiceRoot;
use ackinacki_kit::contracts::authservice::root::ParamsOfDeployProfileByIdentity;
use ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress;
use ackinacki_kit::contracts::authservice::root::ParamsOfHashMultifactor;
use ackinacki_kit::contracts::authservice::root::ParamsOfHashPubkey;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSubmitTransaction;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::tvm_client::abi::Signer;

use crate::client::WalletContext;
use crate::errors::AppError;
use crate::errors::AppResult;
use crate::services;

const DESTROY_PROFILE_TRANSFER_NANO: u128 = 1_000_000_000;

pub(crate) struct ConnectModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> ConnectModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub fn decode_connect_payload_b64url(
        &self,
        payload_b64: impl AsRef<str>,
    ) -> AppResult<services::connect::ConnectPayload> {
        services::connect::decode_connect_payload_b64url(payload_b64)
    }

    pub async fn accept_shared_key_connect(
        &self,
        params: services::connect::ParamsOfAcceptSharedKeyConnect,
    ) -> AppResult<services::connect::ResultOfAcceptConnect> {
        self.ctx.acquire().await;
        services::connect::validate_shared_key_connect_payload(
            &params.payload,
            crate::infra::now_secs(),
        )?;

        self.accept_connect_common(
            params.payload,
            params.wallet_name,
            params.wallet_address,
            params.client_dh_public,
            params.max_attempts,
            params.interval_ms,
            params.challenge_signature,
            params.challenge_epk_public,
        )
        .await
    }

    pub async fn destroy_connect_profile(
        &self,
        params: services::connect::ParamsOfDestroyConnectProfile,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.ctx.acquire().await;
        let profile = AuthProfile::new_default(
            self.ctx.contract_context.clone(),
            params.profile_address.clone(),
        );
        if !profile.is_deployed().await {
            return Ok(crate::ResultOfBlockchainWrite::default());
        }

        let root = connect_auth_root(self.ctx);
        let details = profile
            .get_details()
            .await
            .map_err(|e| AppError::from(e).with_context("connect destroy profile.get_details"))?;
        let expected_multifactor_hash = root
            .hash_multifactor(ParamsOfHashMultifactor {
                multifactor: params.multifactor_address.clone(),
            })
            .await
            .map_err(|e| AppError::from(e).with_context("connect destroy hash_multifactor"))?
            .hash;

        if !details.multifactor_hash.eq_ignore_ascii_case(&expected_multifactor_hash) {
            return Err(AppError::new(format!(
                "AuthProfile multifactor mismatch: expected `{expected_multifactor_hash}`, got `{}`",
                details.multifactor_hash
            ))
            .with_kind("connect"));
        }

        let multifactor =
            Multifactor::new_default(self.ctx.contract_context.clone(), params.multifactor_address);
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public),
            })
            .await
            .map_err(|e| AppError::from(e).with_context("connect destroy get_epk_expire_at"))?
            .epk_expire_at;

        let result = multifactor
            .submit_transaction(
                ParamsOfSubmitTransaction {
                    dest: params.profile_address,
                    value: DESTROY_PROFILE_TRANSFER_NANO,
                    bounce: false,
                    all_balance: false,
                    epk_expire_at,
                    payload: String::new(),
                    ..Default::default()
                },
                Signer::Keys { keys: params.signer_keys },
            )
            .await
            .map_err(|e| {
                AppError::from(e).with_context("connect destroy multifactor.submit_transaction")
            })?;
        let result = crate::infra::ensure_tx_success(result, "connect destroy profile")?;

        let message_ids = result.message_hash.into_iter().collect();
        Ok(crate::ResultOfBlockchainWrite { message_ids, ..Default::default() })
    }

    pub async fn query_session_messages(
        &self,
        params: services::connect::ParamsOfQuerySessionMessages,
    ) -> AppResult<services::connect::ResultOfQuerySessionMessages> {
        self.ctx.acquire().await;
        services::connect::validate_session_message_params(
            &params.session_id,
            &params.description,
        )?;

        let root = connect_auth_root(self.ctx);
        let profile_address = root
            .get_profile_address(ParamsOfGetProfileAddress {
                description: params.description.clone(),
            })
            .await
            .map_err(|e| AppError::from(e).with_context("connect query get_profile_address"))?
            .profile;
        let profile = AuthProfile::new_default(self.ctx.contract_context.clone(), &profile_address);

        if !profile.is_deployed().await {
            return Ok(services::connect::ResultOfQuerySessionMessages {
                profile_address,
                messages: Vec::new(),
                next_before: None,
                updated_session_state: None,
            });
        }

        let limit = services::connect::normalize_query_session_messages_limit(params.limit);
        let query_result = profile
            .query_context_added_events(ParamsOfQueryProfileEvents {
                created_at_from: params.created_at_from,
                limit: Some(limit),
                before: params.before,
            })
            .await
            .map_err(|e| AppError::from(e).with_context("connect query_context_added_events"))?;
        let session_id = params.session_id.clone();
        let next_before = query_result.page_info.cursor;

        // Mutable re-key state for c2w messages.
        // Track whether any new message was successfully re-keyed + decrypted.
        let mut current_state = params.session_state.clone();
        let mut had_successful_rekey = false;

        let mut messages = Vec::new();
        for record in query_result.events {
            // Pre-parse envelope to check for dh_public on c2w messages
            let envelope_opt = serde_json::from_str::<serde_json::Value>(&record.data.text).ok();

            let needs_rekey = envelope_opt.as_ref().is_some_and(|envelope| {
                let is_c2w = envelope.get("dir").and_then(|v| v.as_str()) == Some("c2w");
                let has_dh = envelope.get("dh_public").and_then(|v| v.as_str()).is_some();
                let matches =
                    envelope.get("session_id").and_then(|v| v.as_str()) == Some(&session_id);
                is_c2w && has_dh && matches
            });

            if needs_rekey {
                if let Some(state) = &current_state {
                    let envelope = envelope_opt.as_ref().unwrap();
                    let peer_dh_pub = envelope.get("dh_public").and_then(|v| v.as_str()).unwrap();
                    let envelope_seq = envelope.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);

                    // Try rekey → decrypt with new root
                    if let Ok(rekey) = bee_connect::dh::rekey_inbound(
                        state,
                        peer_dh_pub,
                        &session_id,
                        envelope_seq,
                    ) {
                        // Try decrypt with re-keyed root
                        let parsed_with_rekey =
                            services::connect::parse_connect_session_message_with_secret(
                                &record.data.text,
                                &session_id,
                                Some(&rekey.message_encryption_root),
                                record.event.id.clone(),
                                record.event.created_at,
                            );

                        if let Some(mut msg) = parsed_with_rekey {
                            // parse returns Some for any valid envelope, even
                            // when body decrypt fails. Only advance the DH
                            // state if the body was actually decrypted. This
                            // must come from the parse itself: keying it off
                            // the typed body fields would drop every
                            // application-level msg_type this crate does not
                            // know, since none of them populate a typed field.
                            if msg.body_decrypted {
                                msg.session_state_after = Some(rekey.updated_state.clone());
                                current_state = Some(rekey.updated_state);
                                had_successful_rekey = true;
                                messages.push(msg);
                                continue;
                            }
                        }
                        // Body not decrypted after rekey → message already
                        // processed or corrupted. Do NOT advance state —
                        // fall through to best-effort parse without rekey.
                    }
                }
            }

            // Non-c2w message or already-processed c2w: parse with current root
            let encryption_root = current_state.as_ref().map(|s| s.encryption_root.as_str());
            let parsed = if let Some(secret) = encryption_root {
                services::connect::parse_connect_session_message_with_secret(
                    &record.data.text,
                    &session_id,
                    Some(secret),
                    record.event.id,
                    record.event.created_at,
                )
            } else {
                services::connect::parse_connect_session_message(
                    &record.data.text,
                    &session_id,
                    record.event.id,
                    record.event.created_at,
                )
            };
            if let Some(msg) = parsed {
                messages.push(msg);
            }
        }

        // Only return updated state if we actually re-keyed for new messages
        let updated_session_state =
            if had_successful_rekey { current_state } else { params.session_state };

        Ok(services::connect::ResultOfQuerySessionMessages {
            profile_address,
            messages,
            next_before,
            updated_session_state,
        })
    }
}

impl<'a> ConnectModule<'a> {
    #[allow(clippy::too_many_arguments)]
    async fn accept_connect_common(
        &self,
        payload: services::connect::ConnectPayload,
        wallet_name: String,
        wallet_address: String,
        client_dh_public: String,
        max_attempts: Option<u32>,
        interval_ms: Option<u64>,
        challenge_signature: Option<String>,
        challenge_epk_public: Option<String>,
    ) -> AppResult<services::connect::ResultOfAcceptConnect> {
        // ── DH key exchange ──
        let wallet_dh = bee_connect::dh::generate_dh_keypair()
            .map_err(|e| AppError::new(e).with_kind("connect"))?;
        let shared_secret =
            bee_connect::dh::compute_shared_secret(&wallet_dh.secret_hex, &client_dh_public)
                .map_err(|e| AppError::new(e).with_kind("connect"))?;
        let session_keys =
            bee_connect::dh::derive_session_keys(&shared_secret, &payload.session_id)
                .map_err(|e| AppError::new(e).with_kind("connect"))?;

        // Derived signing keypair for on-chain operations
        let owner_keys = ackinacki_kit::tvm_client::crypto::KeyPair {
            public: session_keys.signing_public_hex.clone(),
            secret: session_keys.signing_secret_hex.to_string(),
        };

        let root = connect_auth_root(self.ctx);
        let description = payload.description.clone();
        let profile_address = root
            .get_profile_address(ParamsOfGetProfileAddress { description: description.clone() })
            .await
            .map_err(|e| AppError::from(e).with_context("connect get_profile_address"))?
            .profile;
        let profile = AuthProfile::new_default(self.ctx.contract_context.clone(), &profile_address);

        let pubkey_hash = root
            .hash_pubkey(ParamsOfHashPubkey { pubkey: format!("0x{}", owner_keys.public) })
            .await
            .map_err(|e| AppError::from(e).with_context("connect hash_pubkey"))?
            .hash;
        let multifactor_hash = root
            .hash_multifactor(ParamsOfHashMultifactor { multifactor: wallet_address.clone() })
            .await
            .map_err(|e| AppError::from(e).with_context("connect hash_multifactor"))?
            .hash;

        let mut deploy_message_id = None;
        if !profile.is_deployed().await {
            let deploy_result = root
                .deploy_profile_by_identity(
                    ParamsOfDeployProfileByIdentity {
                        pubkey: format!("0x{}", owner_keys.public),
                        multifactor_address: wallet_address.clone(),
                        description,
                    },
                    Signer::None,
                )
                .await
                .map_err(|e| {
                    AppError::from(e).with_context("connect deploy_profile_by_identity")
                })?;

            let deploy_result = crate::infra::ensure_tx_success(
                deploy_result,
                "connect deploy_profile_by_identity",
            )?;
            deploy_message_id = deploy_result.message_hash.clone();

            wait_profile_active(&profile, max_attempts, interval_ms).await?;
        }

        let details = profile
            .get_details()
            .await
            .map_err(|e| AppError::from(e).with_context("connect profile.get_details"))?;
        if details.pubkey_hash != pubkey_hash {
            return Err(AppError::new(format!(
                "AuthProfile owner mismatch: expected pubkey_hash `{pubkey_hash}`, got `{}`",
                details.pubkey_hash
            ))
            .with_kind("connect"));
        }
        if !details.multifactor_hash.eq_ignore_ascii_case(&multifactor_hash) {
            return Err(AppError::new(format!(
                "AuthProfile multifactor mismatch: expected multifactor_hash `{multifactor_hash}`, got `{}`",
                details.multifactor_hash
            ))
            .with_kind("connect"));
        }

        let hello_seq = crate::infra::now_ms().map_err(|e| {
            AppError::new(format!("wallet_hello now_ms ({e})")).with_kind("connect")
        })?;

        let wallet_hello_json = services::connect::encode_wallet_hello_message(
            &payload.session_id,
            &wallet_name,
            &wallet_address,
            &session_keys.encryption_root_hex,
            &wallet_dh.public_hex,
            hello_seq,
            payload.nonce.as_deref(),
            challenge_signature.as_deref(),
            challenge_epk_public.as_deref(),
        )?;

        let hello_result = profile
            .add_context_text(&wallet_hello_json, Signer::Keys { keys: owner_keys.clone() })
            .await
            .map_err(|e| AppError::from(e).with_context("connect add_context_text wallet_hello"))?;
        let hello_result =
            crate::infra::ensure_tx_success(hello_result, "connect wallet_hello add_context")?;

        let mut session_state = bee_connect::dh::create_initial_state(
            &session_keys,
            &wallet_dh.secret_hex,
            &client_dh_public,
        );
        session_state.last_sent_seq = hello_seq;

        Ok(services::connect::ResultOfAcceptConnect {
            profile_address,
            deploy_message_id,
            wallet_hello_message_id: hello_result.message_hash,
            wallet_hello_json,
            session_state,
        })
    }
}

async fn wait_profile_active(
    profile: &AuthProfile,
    max_attempts: Option<u32>,
    interval_ms: Option<u64>,
) -> AppResult<()> {
    let attempts = max_attempts.unwrap_or(60).min(u8::MAX as u32) as u8;
    let attempts_timeout = interval_ms.unwrap_or(1_000);

    profile
        .wait_account(ParamsOfWaitAccount {
            status: AccountStatus::Active,
            attempts: Some(attempts),
            attempts_timeout: Some(attempts_timeout),
        })
        .await
        .map_err(|e| AppError::from(e).with_context("connect wait profile active"))?;

    Ok(())
}

fn connect_auth_root(ctx: &WalletContext) -> AuthServiceRoot {
    AuthServiceRoot::new_default(ctx.contract_context.clone())
}
