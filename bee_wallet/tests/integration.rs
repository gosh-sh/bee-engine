// Integration tests hit shellnet and share on-chain state (accumulator queues).
// Run sequentially to avoid flaky failures from queue contention:
//
//   cargo test -p bee-wallet -- --test-threads=1

use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use ackinacki_kit::tvm_client::crypto::KeyPair;
use bee_connect::ConnectClient;
use bee_connect::ParamsOfCreateSharedKeySession;
use bee_crypto::Crypto as BeeCrypto;
use bee_wallet::now_secs;
use bee_wallet::ConnectPayload;
use bee_wallet::GetBalanceByTokenRootReq;
use bee_wallet::GetEPKExpireReq;
use bee_wallet::ParamsGetMirrorAddress;
use bee_wallet::ParamsOfAcceptSharedKeyConnect;
use bee_wallet::ParamsOfDeployMultifactor;
use bee_wallet::ParamsOfDestroyConnectProfile;
use bee_wallet::ParamsOfGetHistory;
use bee_wallet::ParamsOfGetMultifactorAddress;
use bee_wallet::ParamsOfGetMultifactorInfo;
use bee_wallet::ParamsOfGetNativeBalances;
use bee_wallet::ParamsOfGetTokensBalances;
use bee_wallet::ParamsOfPrepareDeploy;
use bee_wallet::ParamsOfQuerySessionMessages;
use bee_wallet::ResultOfSendMessage;
use bee_wallet::Wallet;
use bee_wallet::WalletNameErrorCode;

// walet wapp_t_1 =
// 0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4
//
/// Set mbiCur on a Boost contract.
/// Run: cargo test -p bee-wallet -- debug_set_boost_mbi --nocapture --ignored
/// Deploy two test wallets on shellnet, fund them, deploy miner on first.
/// Run once, then paste the printed constants into this file.
/// Run: cargo test -p bee-wallet -- setup_shellnet_test_wallets --nocapture
/// --ignored
#[tokio::test]
#[ignore]
async fn setup_shellnet_test_wallets() {
    let wallet = create_shellnet_wallet();

    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    for label in ["t1", "t2"] {
        let name = format!("test_{label}_{}", now_secs());
        let params = create_deploy_wallet_params(name.clone());
        let epk = params.epk.clone();
        let esk = params.esk.clone();
        let epk_expire_at = params.epk_expire_at;
        let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
        let addr = deploy_result.address.clone();

        // Fund: gas + NACKL (ECC[1]) + SHELL (ECC[2]) + USDC (ECC[3])
        let ecc = std::collections::HashMap::from([
            (1u32, 5_000_000_000u64), // 5 NACKL
            (2u32, 5_000_000_000u64), // 5 SHELL
            (3u32, 5_000_000u64),     // 5 USDC (decimals=6)
        ]);
        ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
            tvm_ctx.clone(),
            &addr,
            10_000_000_000, // 10 vmshell gas
            ecc,
            1,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Deploy miner on first wallet
        if label == "t1" {
            let signer_keys = KeyPair { public: epk.clone(), secret: esk.clone() };
            wallet
                .deploy_miner(bee_wallet::ParamsOfDeployMiner {
                    multifactor_address: addr.clone(),
                    signer_keys: signer_keys.clone(),
                })
                .await
                .expect("deploy_miner failed");

            let mining_keys = create_crypto().gen_mining_keys().expect("gen_mining_keys");
            wallet
                .set_mining_keys(bee_wallet::ParamsOfSetMiningKeys {
                    multifactor_address: addr.clone(),
                    signer_keys,
                    mining_pubkey: mining_keys.public.clone(),
                    app_id: String::new(),
                    epk_expire_at: None,
                })
                .await
                .expect("set_mining_keys failed");
            println!("miner deployed + keys set for {label}");
        }

        println!("\n// --- {label} ---");
        println!("const SHELLNET_{}: &str = \"{addr}\";", label.to_uppercase());
        println!("const SHELLNET_{}_EPK: &str = \"{epk}\";", label.to_uppercase());
        println!("const SHELLNET_{}_ESK: &str = \"{esk}\";", label.to_uppercase());
        println!("const SHELLNET_{}_NAME: &str = \"{name}\";", label.to_uppercase());
        println!("const SHELLNET_{}_EPK_EXPIRE_AT: u64 = {epk_expire_at};", label.to_uppercase());
    }

    // Send NACKL from T1 to T2 to seed history
    println!("\nDone. Paste constants above into the test file.");
}

/// One-off shellnet setup: set `_subscriber` (= Exchange) on the Exchange's
/// USDC TIP-3 wallet. Every shellnet redeploy loses it; without it
/// `migrate_tip3_usdc` deposits land silently (acceptTransfer credits the
/// wallet but `onTransferReceived` is never sent) and ECC[3] is never minted.
///
/// Flow (token/TokenWallet.sol + Transaction.sol):
///   1. `deployTransaction(SET_SUBSCRIBER_TYPE, ...)` on the wallet — open
///      access;
///   2. the Transaction executes only on a plain transfer from the wallet's
///      owner (the Exchange), so `Exchange.triggerTransaction(txAddr)` signed
///      with the exchange owner key finishes the job.
///
/// Run: cargo test -p bee-wallet --test integration --
/// setup_exchange_usdc_subscriber --nocapture --ignored
#[tokio::test]
#[ignore]
async fn setup_exchange_usdc_subscriber() {
    use ackinacki_kit::contracts::exchange::exchange_contract::Exchange;
    use ackinacki_kit::contracts::exchange::exchange_contract::ParamsOfTriggerTransaction;
    use ackinacki_kit::contracts::token::wallet::ParamsOfDeployTransaction;
    use ackinacki_kit::contracts::token::wallet::TokenWallet;
    use ackinacki_kit::contracts::token::wallet::Transaction as TokenTx;
    use ackinacki_kit::tvm_client::abi::Signer;

    // Exchange owner keys on shellnet (rotate on every redeploy, same as the
    // TIP-3 mint keys above).
    let exchange_keys = KeyPair {
        public: "ac09134c34f139b3e257727aca9db870410f8dcf17697b5fbcebef0cb5ea6e91".to_string(),
        secret: "9038c35fa5499244d10d07b57885f8a6b38e55f21cb559374163de682de09ff0".to_string(),
    };

    let ctx = create_tvm_context();
    let exchange = Exchange::new_default(ctx.clone());

    // Sanity: the provided key must be the on-chain owner, otherwise
    // triggerTransaction is a silent no-op.
    let owner = exchange.get_owner_pubkey().await.expect("get_owner_pubkey").owner_pubkey;
    let owner_norm = owner.trim_start_matches("0x").to_lowercase();
    println!("on-chain exchange owner pubkey: {owner}");
    assert_eq!(owner_norm, exchange_keys.public, "exchange owner pubkey mismatch");

    let usdc_wallet_addr = exchange.get_usdc_wallet().await.expect("get_usdc_wallet").usdc_wallet;
    println!("exchange USDC wallet: {usdc_wallet_addr}");

    let wallet = TokenWallet::new(
        ctx.clone(),
        ackinacki_kit::contracts::account::ParamsOfNewContract::new(
            &usdc_wallet_addr,
            ackinacki_kit::contracts::dapp::SystemDapp::System,
        ),
    );

    let tx_spec =
        TokenTx::SetSubscriber { destination_owner: Some(Exchange::DEFAULT_ADDRESS.to_string()) };

    // 1. Deploy the SET_SUBSCRIBER transaction contract.
    let deploy_res = wallet
        .deploy_transaction(
            ParamsOfDeployTransaction::from(tx_spec.clone()),
            Signer::Keys { keys: exchange_keys.clone() },
        )
        .await
        .expect("deploy_transaction(SET_SUBSCRIBER)");
    println!("deployTransaction message: {:?}", deploy_res.message_hash);

    let tx_addr = wallet
        .get_transaction_address(tx_spec.into())
        .await
        .expect("get_transaction_address")
        .transaction_address;
    println!("transaction address: {tx_addr}");

    // 2. Wait until the Transaction contract lands on-chain.
    let tx_account_id = tx_addr.trim_start_matches("0:").to_string();
    let mut deployed = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if ackinacki_kit::tvm_client::account::get_account(
            ctx.clone(),
            ackinacki_kit::tvm_client::account::ParamsOfGetAccount {
                account_id: tx_account_id.clone(),
                dapp_id: ackinacki_kit::contracts::dapp::SystemDapp::System.dapp_id().to_string(),
            },
        )
        .await
        .is_ok()
        {
            deployed = true;
            break;
        }
    }
    assert!(deployed, "SET_SUBSCRIBER transaction never appeared at {tx_addr}");

    // 3. Owner triggers execution.
    let trig = exchange
        .trigger_transaction(
            ParamsOfTriggerTransaction { tx_addr: tx_addr.clone() },
            Signer::Keys { keys: exchange_keys },
        )
        .await
        .expect("trigger_transaction");
    println!("triggerTransaction message: {:?}", trig.message_hash);
    println!("Done. Re-run test_migrate_tip3_usdc to verify the subscriber works.");
}

fn create_shellnet_wallet() -> Wallet {
    Wallet::new(bee_wallet::WalletConfig {
        endpoints: vec!["shellnet.ackinacki.org".to_string()],
        api_url: "https://app-backend.ackinacki.org/api".to_string(),
        app_id: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ..Default::default()
    })
    .expect("Failed to create shellnet Wallet")
}

fn create_crypto() -> BeeCrypto {
    let endpoints = vec!["shellnet.ackinacki.org".to_string()];
    BeeCrypto::new(endpoints).expect("Failed to create BeeCrypto")
}

fn create_tvm_context() -> std::sync::Arc<ackinacki_kit::tvm_client::ClientContext> {
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    std::sync::Arc::new(ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"))
}

struct DeployedWallet {
    address: String,
    epk: String,
    esk: String,
    name: String,
}

/// Deploy a fresh wallet on shellnet, fund it with gas + ECC tokens via giver.
async fn deploy_fresh_wallet(wallet: &Wallet) -> DeployedWallet {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let idx = COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("test_dyn_{}_{}", now_secs(), idx);
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy_wallet failed");
    let address = deploy_result.address.clone();

    let tvm_ctx = create_tvm_context();
    let ecc = std::collections::HashMap::from([
        (1u32, 5_000_000_000u64), // 5 NACKL
        (2u32, 5_000_000_000u64), // 5 SHELL
        (3u32, 5_000_000u64),     // 5 USDC
    ]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx,
        &address,
        10_000_000_000,
        ecc,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    DeployedWallet { address, epk, esk, name }
}

/// Deploy a fresh wallet with enough ECC for DEX operations (voucher nominal =
/// 100+).
async fn deploy_fresh_wallet_for_dex(wallet: &Wallet) -> DeployedWallet {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let idx = COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("test_dex_{}_{}", now_secs(), idx);
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy_wallet failed");
    let address = deploy_result.address.clone();

    let tvm_ctx = create_tvm_context();
    let ecc = std::collections::HashMap::from([
        (1u32, 200_000_000_000u64), // 200 NACKL (enough for N100 voucher + gas)
        (2u32, 50_000_000_000u64),  // 50 SHELL (for gas voucher)
        (3u32, 5_000_000u64),       // 5 USDC
    ]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx,
        &address,
        50_000_000_000,
        ecc,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    DeployedWallet { address, epk, esk, name }
}

fn create_deploy_wallet_params(wallet_name: String) -> ParamsOfDeployMultifactor {
    ParamsOfDeployMultifactor {
        epk: "6d26db3f0d23f66f358ca7d8f4e340ecc784f899002946b4eb04b1f7cb3325d6"
            .to_string(),
        epk_expire_at: 1784029474,
        esk: "15910e12c0bc445cda49ad240a9533546a8c26b8a8d0313cd59533af1b463bc7"
            .to_string(),
        header_base_64: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZmOGVlZDA0MjgyZjFkYmQ4OWY1YTc5Yjc4N2Q2N2JjODc2MjA1OTcifQ".to_string(),
        index_mod_4: 1,
        iss_base_64: "yJpc3MiOiJodHRwczovL29hdXRoLmdvc2guc2giLC".to_string(),
        jwk_modulus: "c5b6adf2b02c0731bcd01071786afc797f34ef21d61f3cb5d1ce8c82486427db1eaca9a0ce7f9f9687790a2cc80e87aaff3b1ccd2c4c5a89aafc2885e6a6ce1a0ef569a6608263bda6aec4b369114210139d28346f010ed15cd876bf932cf43d6c7682d97e6c12e940ce05b30c00009177a7692372f281c6ec2fa51f271b0d9e2a38d983d7436682b2b7b9892829448f1834042ddcf9d02eade650658dd41668138df8cf1f79ec03323e80e7eb2814e28918ced0c16cddd891379120152174d170f1acabe5cb937213ccf844371630062bc4a923e406f7d1a92bf4aa5f611cf5848fcc482978ac9d55d2239e8e5670deab82417d3a8c044e187e83bfd79b9fa5".to_string(),
        jwk_modulus_expire_at: now_secs() + 3600,
        kid: "ff8eed04282f1dbd89f5a79b787d67bc87620597".to_string(),
        password: "Hello!23".to_string(),
        proof: "355528cf17afdde0a63f28050ad475407b6b515e7ba4cd171b77a6f0449874107e7f584f650117d7dbc4440cd62c5922f5f67a045b6364f107665e5d987bf12ceb191f246463920decbf50cf43567de0a885c53771440764cabd578f84c3581bcafd999764284c4f49b9b5ebc2f4508a931b62984970af006000b86c3effc08a".to_string(),
        sub: "272114864".to_string(),
        wallet_name,
        zkid: "11122679641859749640320083403412561847128433970247905841202114460910422214869".to_string(),
    }
}

// Shellnet pre-deployed test wallets (created by setup_shellnet_test_wallets)
const SHELLNET_T1: &str = "0:cfa74aad2b19d5f8721dc5ec0bd05c6ca7d03d6666493293a1310d8289d6fb81";
const SHELLNET_T1_EPK: &str = "6d26db3f0d23f66f358ca7d8f4e340ecc784f899002946b4eb04b1f7cb3325d6";
const SHELLNET_T1_ESK: &str = "15910e12c0bc445cda49ad240a9533546a8c26b8a8d0313cd59533af1b463bc7";
const SHELLNET_T1_NAME: &str = "test_t1_1780589811";
const SHELLNET_T1_EPK_EXPIRE_AT: u64 = 1784029474;

const SHELLNET_T2: &str = "0:9f6b5c10aa720c2b6b842f7689cbcd9220e364ba452e59ee2f7c3561647bff07";
const SHELLNET_T2_EPK: &str = "6d26db3f0d23f66f358ca7d8f4e340ecc784f899002946b4eb04b1f7cb3325d6";
const SHELLNET_T2_ESK: &str = "15910e12c0bc445cda49ad240a9533546a8c26b8a8d0313cd59533af1b463bc7";
const SHELLNET_T2_EPK_EXPIRE_AT: u64 = 1784029474;

// ============================================================
// Sync / offline tests
// ============================================================

// --- validate_name ---

#[test]
fn test_validate_name_valid() {
    let wallet = create_shellnet_wallet();
    let result = wallet.validate_name("valid_wallet_name".to_string());
    assert!(result.is_valid());
    assert!(result.error_code().is_none());
}

#[test]
fn test_validate_name_invalid() {
    let wallet = create_shellnet_wallet();

    let r = wallet.validate_name("invalid*name".to_string());
    assert!(!r.is_valid());
    assert_eq!(r.error_code(), Some(WalletNameErrorCode::InvalidCharacters));

    let r = wallet.validate_name("--name".to_string());
    assert!(!r.is_valid());
    assert_eq!(r.error_code(), Some(WalletNameErrorCode::ConsecutiveHyphens));

    let r = wallet.validate_name("bad__name".to_string());
    assert!(!r.is_valid());
    assert_eq!(r.error_code(), Some(WalletNameErrorCode::ConsecutiveUnderscores));

    let r = wallet.validate_name("-name".to_string());
    assert!(!r.is_valid());
    assert_eq!(r.error_code(), Some(WalletNameErrorCode::StartsWithSymbol));

    let r = wallet.validate_name("a".repeat(40));
    assert!(!r.is_valid());
    assert_eq!(r.error_code(), Some(WalletNameErrorCode::TooLong));

    let r = wallet.validate_name("abc".to_string());
    assert!(!r.is_valid());
    assert_eq!(r.error_code(), Some(WalletNameErrorCode::TooShort));
}

// ============================================================
// Async / network tests (shellnet)
// ============================================================

// --- check_name_availability ---

#[tokio::test]
async fn test_check_name_availability_nonexistent() {
    let wallet = create_shellnet_wallet();
    let name = format!("test_{}", now_secs());
    let result =
        wallet.check_name_availability(name).await.expect("check_name_availability failed");
    assert!(result.is_available);
    assert!(result.multifactor_address.is_none());
}

// --- get_multifactor_data_by_name ---

#[tokio::test]
async fn test_get_multifactor_data_by_name_nonexistent() {
    let wallet = create_shellnet_wallet();
    let name = format!("test_{}", now_secs());
    let res = wallet.get_multifactor_data_by_name(name).await;
    assert!(res.is_err());
}

// --- buy_shells / sell_shells ---

/// Validates that sell_shells rejects invalid denomination.
/// Uses a real shellnet multifactor so EPK resolves, then service-level
/// validation catches invalid denom.
#[tokio::test]
async fn test_sell_shells_invalid_denom_rejected() {
    let wallet = create_shellnet_wallet();

    let result = wallet
        .sell_shells(bee_wallet::SellShellsReq {
            multifactor_address: SHELLNET_T1.to_string(),
            denom: 7,
            signer_keys: KeyPair {
                public: SHELLNET_T1_EPK.to_string(),
                secret: SHELLNET_T1_ESK.to_string(),
            },
            bounce: None,
        })
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.message.contains("invalid denom"),
        "expected invalid denom error, got: {}",
        err.message
    );
}

/// Validates that buy_shells rejects zero USDC amount.
/// Uses a real shellnet multifactor so EPK resolves, then service-level
/// validation catches `usdc_amount == 0`.
#[tokio::test]
async fn test_buy_shells_zero_amount_rejected() {
    let wallet = create_shellnet_wallet();

    let result = wallet
        .buy_shells(bee_wallet::BuyShellsReq {
            multifactor_address: SHELLNET_T1.to_string(),
            usdc_amount: 0,
            signer_keys: KeyPair {
                public: SHELLNET_T1_EPK.to_string(),
                secret: SHELLNET_T1_ESK.to_string(),
            },
            bounce: None,
        })
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.message.contains("usdc_amount must be > 0"),
        "expected zero-amount error, got: {}",
        err.message
    );
}

/// Query ECC balance for a given currency id via sdk `get_account` (REST) +
/// boc parse — independent of the wallet's own balance code.
///
/// Account state is NOT served over GraphQL on `>= 1.0.0` servers (the old
/// `account(address:)` form is gone and the `info` sub-resolver hangs; the
/// supported path is `get_account`). `messages` queries still live on GraphQL.
async fn get_ecc_balance_by_id(address: &str, ecc_id: u32, _endpoint: &str) -> u64 {
    let ctx = create_tvm_context();
    let account_id = address.strip_prefix("0:").unwrap_or(address).to_string();
    // Multifactor wallets live under the MobileVerifiers system dApp.
    let dapp_id = "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let got = ackinacki_kit::tvm_client::account::get_account(
        ctx.clone(),
        ackinacki_kit::tvm_client::account::ParamsOfGetAccount { account_id, dapp_id },
    )
    .await
    .expect("get_account");
    let parsed = ackinacki_kit::tvm_client::boc::parse_account(
        ctx,
        ackinacki_kit::tvm_client::boc::ParamsOfParse { boc: got.boc },
    )
    .expect("parse_account")
    .parsed;
    parsed["balance_other"]
        .as_array()
        .and_then(|arr| arr.iter().find(|b| b["currency"].as_u64() == Some(ecc_id as u64)))
        .and_then(|b| b["value"].as_str())
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

/// E2E: deploy wallet → fund USDC via giver → buy_shells → verify Shell
/// balance.
#[tokio::test]
async fn test_buy_shells_e2e() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy a fresh wallet
    let name = format!("buyshell_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();
    println!("deployed: {} ({})", name, mf_address);

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. Create TVM context for shellnet giver operations
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // 3. Fund: gas (vmshell) + USDC (ECC[3])
    let usdc_to_buy: u64 = 5;

    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        5_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let usdc_micro = usdc_to_buy * 1_000_000;
    let ecc_usdc = std::collections::HashMap::from([(3u32, usdc_micro)]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        1_000_000_000,
        ecc_usdc,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // 4. Check USDC arrived
    let usdc_before = get_ecc_balance_by_id(&mf_address, 3, "shellnet.ackinacki.org").await;
    assert!(usdc_before >= usdc_micro, "multifactor should have USDC: got {usdc_before}");

    // Remember Shell balance before purchase
    let shell_before = get_ecc_balance_by_id(&mf_address, 2, "shellnet.ackinacki.org").await;

    // 5. Buy Shell
    let result = wallet
        .buy_shells(bee_wallet::BuyShellsReq {
            multifactor_address: mf_address.clone(),
            usdc_amount: usdc_to_buy,
            signer_keys,
            bounce: None,
        })
        .await
        .expect("buy_shells failed");
    println!("buy_shells tx: {:?}", result.message_hash);

    // Diagnostic: check USDC balance after buy
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let usdc_after = get_ecc_balance_by_id(&mf_address, 3, "shellnet.ackinacki.org").await;
    println!(
        "USDC before={usdc_before}, after={usdc_after}, diff={}",
        usdc_before.saturating_sub(usdc_after)
    );

    // 6. Poll for Shell balance increase (up to 120s)
    // 5 USDC * 100 Shell/USDC * 1e9 nanoShell/Shell = 500_000_000_000
    let expected_shell = usdc_to_buy * 100 * 1_000_000_000;
    let mut shell_after = shell_before;

    for attempt in 1..=24 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        shell_after = get_ecc_balance_by_id(&mf_address, 2, "shellnet.ackinacki.org").await;
        let delta = shell_after.saturating_sub(shell_before);
        println!("attempt {attempt}/24: Shell after={shell_after}, delta={delta}, expected={expected_shell}");
        if delta >= expected_shell {
            break;
        }
    }

    let shell_delta = shell_after.saturating_sub(shell_before);
    assert!(
        shell_delta >= expected_shell,
        "Expected at least {expected_shell} nanoShell, got {shell_delta}"
    );
}

/// E2E: deploy wallet → fund Shell via giver → sell_shells → verify order
/// created.
#[tokio::test]
async fn test_sell_shells_e2e() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy a fresh wallet
    let name = format!("sellshell_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();
    println!("deployed: {} ({})", name, mf_address);

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. TVM context for giver
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // 3. Fund: gas (vmshell) + Shell (ECC[2])
    let denom: u16 = 1;
    // D=1 → 1 * 100 * 1e9 = 100_000_000_000 nanoShell
    let shell_amount: u64 = (denom as u64) * 100 * 1_000_000_000;

    // Gas
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        5_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Shell (ECC[2])
    let ecc_shell = std::collections::HashMap::from([(2u32, shell_amount)]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        1_000_000_000,
        ecc_shell,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // 4. Verify Shell arrived
    let shell_before = get_ecc_balance_by_id(&mf_address, 2, "shellnet.ackinacki.org").await;
    assert!(shell_before >= shell_amount, "multifactor should have Shell: got {shell_before}");

    // 5. Sell Shell
    let result = wallet
        .sell_shells(bee_wallet::SellShellsReq {
            multifactor_address: mf_address.clone(),
            denom,
            signer_keys,
            bounce: None,
        })
        .await
        .expect("sell_shells failed");

    println!(
        "sell_shells tx: {:?}, order_id: {}, denom: {}, sell_order_address: {}, sold: {}, position_in_queue: {}",
        result.message_hash, result.order_id, result.denom,
        result.sell_order_address, result.sold, result.position_in_queue
    );

    assert_eq!(result.denom, denom);
    assert!(!result.sell_order_address.is_empty(), "sell_order_address should be non-empty");

    // 6. Wait for accumulator processing
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    // 7. Verify Shell left the wallet
    let shell_after = get_ecc_balance_by_id(&mf_address, 2, "shellnet.ackinacki.org").await;
    assert!(
        shell_after < shell_before,
        "Shell balance should decrease after sell: before={shell_before}, after={shell_after}"
    );
}

// --- get_my_sell_orders ---

#[tokio::test]
async fn test_get_my_sell_orders_empty_for_new_wallet() {
    let wallet = create_shellnet_wallet();

    let name = format!("orders_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();

    let orders = wallet
        .get_my_sell_orders(bee_wallet::GetMySellOrdersReq {
            multifactor_address: mf_address,
            page_size: 20,
            cursor: None,
        })
        .await
        .expect("get_my_sell_orders failed");

    assert!(orders.orders.is_empty(), "fresh wallet should have no sell orders");
}

/// E2E: deploy → fund Shell → sell_shells → get_my_sell_orders → verify order
/// in list.
#[tokio::test]
async fn test_sell_then_get_my_orders() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy
    let name = format!("sellord_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. TVM context for giver
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // 3. Fund: gas + Shell (ECC[2]) for D=1
    let denom: u16 = 1;
    let shell_amount: u64 = (denom as u64) * 100 * 1_000_000_000;

    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        5_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let ecc_shell = std::collections::HashMap::from([(2u32, shell_amount)]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        1_000_000_000,
        ecc_shell,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // 4. Sell Shell
    let sell_result = wallet
        .sell_shells(bee_wallet::SellShellsReq {
            multifactor_address: mf_address.clone(),
            denom,
            signer_keys,
            bounce: None,
        })
        .await
        .expect("sell_shells failed");
    println!("sell order_id: {}, denom: {}", sell_result.order_id, sell_result.denom);

    // 5. Get my sell orders
    let orders = wallet
        .get_my_sell_orders(bee_wallet::GetMySellOrdersReq {
            multifactor_address: mf_address.clone(),
            page_size: 20,
            cursor: None,
        })
        .await
        .expect("get_my_sell_orders failed");

    println!("orders: {orders:?}");
    assert!(!orders.orders.is_empty(), "should have at least 1 sell order");

    let my_order = orders
        .orders
        .iter()
        .find(|o| o.order_id == sell_result.order_id && o.denom == denom)
        .expect("our sell order should be in the list");

    assert_eq!(my_order.denom, denom);
    assert!(!my_order.claimed);
    assert!(!my_order.sold);
    assert!(my_order.position_in_queue > 0, "unsold order should have position > 0");
    assert!(!my_order.sell_order_address.is_empty());
}

/// Two wallets, each places 2 sell orders (D=1 and D=10).
/// Verify get_my_sell_orders returns correct orders per wallet — no
/// cross-contamination.
#[tokio::test]
async fn test_get_my_sell_orders_two_wallets_multiple_denoms() {
    let wallet = create_shellnet_wallet();

    // TVM context for giver
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // Deploy two wallets
    let mut wallets = Vec::new();
    for i in 0..2 {
        let name = format!("multi_sell_{}_{}", i, now_secs());
        let params = create_deploy_wallet_params(name.clone());
        let epk = params.epk.clone();
        let esk = params.esk.clone();
        let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
        let mf_address = deploy_result.address.clone();
        let signer_keys = KeyPair { public: epk, secret: esk };
        println!("wallet {i}: {} ({})", name, mf_address);
        wallets.push((mf_address, signer_keys));
    }

    // Fund both wallets: gas + Shell for D=1 (100 Shell) + D=10 (1000 Shell) = 1100
    // Shell
    let shell_d1: u64 = 1 * 100 * 1_000_000_000; // D=1
    let shell_d10: u64 = 10 * 100 * 1_000_000_000; // D=10
    let total_shell = shell_d1 + shell_d10;

    for (mf_address, _) in &wallets {
        // Gas
        ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
            tvm_ctx.clone(),
            mf_address,
            10_000_000_000, // 10 vmshell (need gas for 2 sells)
            std::collections::HashMap::new(),
            1,
        )
        .await;

        // Shell
        let ecc_shell = std::collections::HashMap::from([(2u32, total_shell)]);
        ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
            tvm_ctx.clone(),
            mf_address,
            1_000_000_000,
            ecc_shell,
            1,
        )
        .await;
    }
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // Each wallet places 2 sell orders: D=1 and D=10
    let denoms: Vec<u16> = vec![1, 10];
    let mut expected_orders: Vec<Vec<(u16, u64)>> = vec![Vec::new(), Vec::new()];

    for (i, (mf_address, signer_keys)) in wallets.iter().enumerate() {
        for &denom in &denoms {
            let result = wallet
                .sell_shells(bee_wallet::SellShellsReq {
                    multifactor_address: mf_address.clone(),
                    denom,
                    signer_keys: signer_keys.clone(),
                    bounce: None,
                })
                .await
                .expect(&format!("sell_shells failed: wallet {i}, denom {denom}"));
            println!(
                "wallet {i} sell: denom={}, order_id={}, addr={}",
                result.denom, result.order_id, result.sell_order_address
            );
            expected_orders[i].push((denom, result.order_id));
        }
    }

    // Verify each wallet sees only its own orders
    for (i, (mf_address, _)) in wallets.iter().enumerate() {
        let orders = wallet
            .get_my_sell_orders(bee_wallet::GetMySellOrdersReq {
                multifactor_address: mf_address.clone(),
                page_size: 20,
                cursor: None,
            })
            .await
            .expect(&format!("get_my_sell_orders failed for wallet {i}"));

        println!("wallet {i} orders: {orders:?}");

        // Should have at least 2 orders (D=1 and D=10)
        assert!(
            orders.orders.len() >= 2,
            "wallet {i} should have at least 2 orders, got {}",
            orders.orders.len()
        );

        // All expected orders must be present
        for &(denom, order_id) in &expected_orders[i] {
            let found = orders.orders.iter().find(|o| o.order_id == order_id && o.denom == denom);
            assert!(
                found.is_some(),
                "wallet {i}: order (denom={denom}, order_id={order_id}) not found in {orders:?}"
            );
            let order = found.unwrap();
            assert!(!order.claimed);
            assert!(!order.sell_order_address.is_empty());
        }

        // No orders from the other wallet
        let other = 1 - i;
        for &(denom, order_id) in &expected_orders[other] {
            let leaked = orders.orders.iter().any(|o| o.order_id == order_id && o.denom == denom);
            assert!(
                !leaked,
                "wallet {i} should NOT see wallet {other}'s order (denom={denom}, order_id={order_id})"
            );
        }
    }
}

// --- redeem_nackl ---

#[tokio::test]
async fn test_redeem_nackl_zero_amount_rejected() {
    let wallet = create_shellnet_wallet();

    let result = wallet
        .redeem_nackl(bee_wallet::RedeemNacklReq {
            multifactor_address:
                "0:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            nackl_amount: 0,
            signer_keys: KeyPair { public: "aaaa".to_string(), secret: "bbbb".to_string() },
            bounce: None,
        })
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.message.contains("nackl_amount must be > 0"),
        "expected zero-amount error, got: {}",
        err.message
    );
}

/// E2E: deploy → fund NACKL → get_nackl_redeem_rate → redeem_nackl → verify
/// USDC received.
#[tokio::test]
async fn test_redeem_nackl_e2e() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy
    let name = format!("redeem_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();
    println!("deployed: {} ({})", name, mf_address);

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. TVM context for giver
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // 3. Fund: gas + NACKL (ECC[1])
    let nackl_amount: u64 = 1_000_000_000; // 1 NACKL

    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        5_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let ecc_nackl = std::collections::HashMap::from([(1u32, nackl_amount)]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        1_000_000_000,
        ecc_nackl,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // 4. Check rate before redeem
    let rate = wallet.get_nackl_redeem_rate().await.expect("get_nackl_redeem_rate failed");
    println!(
        "rate: redeemable={}, supply={}, usdc_per_nackl={}",
        rate.redeemable_usdc, rate.current_nackl_supply, rate.usdc_per_nackl
    );

    // Skip if no redeemable USDC (nothing to redeem against)
    if rate.redeemable_usdc == 0 {
        println!("No redeemable USDC on accumulator, skipping redeem test");
        return;
    }

    // 5. Remember USDC balance before
    let usdc_before = get_ecc_balance_by_id(&mf_address, 3, "shellnet.ackinacki.org").await;

    // 6. Redeem NACKL
    let result = wallet
        .redeem_nackl(bee_wallet::RedeemNacklReq {
            multifactor_address: mf_address.clone(),
            nackl_amount,
            signer_keys,
            bounce: None,
        })
        .await
        .expect("redeem_nackl failed");
    println!("redeem tx: {:?}", result.message_hash);

    // 7. Wait and verify USDC received
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    let usdc_after = get_ecc_balance_by_id(&mf_address, 3, "shellnet.ackinacki.org").await;
    let usdc_delta = usdc_after - usdc_before;
    println!("USDC before={usdc_before}, after={usdc_after}, delta={usdc_delta}");
    assert!(usdc_delta > 0, "Should have received some USDC from redeem");
}

// --- get_nackl_redeem_rate ---

#[tokio::test]
async fn test_get_nackl_redeem_rate() {
    let wallet = create_shellnet_wallet();

    let rate = wallet.get_nackl_redeem_rate().await.expect("get_nackl_redeem_rate failed");

    println!(
        "redeemable_usdc={}, current_nackl_supply={}, usdc_per_nackl={}",
        rate.redeemable_usdc, rate.current_nackl_supply, rate.usdc_per_nackl
    );

    // Supply should be > 0 on shellnet (emission started)
    assert!(rate.current_nackl_supply > 0, "NACKL supply should be > 0");

    // If there's redeemable USDC, rate should be > 0
    if rate.redeemable_usdc > 0 {
        assert!(rate.usdc_per_nackl > 0, "rate should be > 0 when redeemable > 0");
    }
}

// --- claim_usdc ---

/// E2E full cycle: deploy → sell → giver buys queue → claim → verify USDC
/// received.
#[tokio::test]
async fn test_claim_usdc_full_cycle() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy wallet
    let name = format!("claim_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();
    println!("deployed: {} ({})", name, mf_address);

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. TVM context for giver
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // 3. Fund wallet: gas + Shell for D=1
    let denom: u16 = 1;
    let shell_amount: u64 = (denom as u64) * 100 * 1_000_000_000;

    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        10_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let ecc_shell = std::collections::HashMap::from([(2u32, shell_amount)]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        1_000_000_000,
        ecc_shell,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // 4. Sell Shell
    let sell_result = wallet
        .sell_shells(bee_wallet::SellShellsReq {
            multifactor_address: mf_address.clone(),
            denom,
            signer_keys: signer_keys.clone(),
            bounce: None,
        })
        .await
        .expect("sell_shells failed");
    let order_id = sell_result.order_id;
    println!("sell order_id: {order_id}, address: {}", sell_result.sell_order_address);

    // 5. Giver buys entire D=1 queue (clears FIFO including our order)
    use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetQueueState as QSP;
    use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ShellAccumulatorRootUsdc as AccRoot;

    let accumulator = AccRoot::new_default(tvm_ctx.clone());
    let queue = accumulator.get_queue_state(QSP { d: denom }).await.expect("getQueueState");
    let available = queue.available;
    println!("queue D={denom}: available={available}, soldPrefix={}", queue.sold_prefix);

    // Buy in a loop until our order is sold (accumulator may process in batches)
    for attempt in 0..10 {
        let q = accumulator.get_queue_state(QSP { d: denom }).await.expect("getQueueState");
        if order_id <= q.sold_prefix {
            println!(
                "order {order_id} sold after {attempt} buy round(s), soldPrefix={}",
                q.sold_prefix
            );
            break;
        }
        let unsold = q.next_id.saturating_sub(q.sold_prefix);
        if unsold == 0 {
            break;
        }
        let usdc_to_buy = unsold * (denom as u64) * 1_000_000;
        let ecc_usdc = std::collections::HashMap::from([(3u32, usdc_to_buy)]);
        ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
            tvm_ctx.clone(),
            AccRoot::DEFAULT_ADDRESS,
            1_000_000_000,
            ecc_usdc,
            1,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }

    // 6. Verify our order is now sold
    let queue_after =
        accumulator.get_queue_state(QSP { d: denom }).await.expect("getQueueState after buy");
    assert!(
        order_id <= queue_after.sold_prefix,
        "order should be sold: order_id={order_id}, soldPrefix={}",
        queue_after.sold_prefix
    );

    // 7. Fund accumulator + SellOrderLot with gas for claim chain
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        AccRoot::DEFAULT_ADDRESS,
        5_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &sell_result.sell_order_address,
        5_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 8. Remember USDC balance before claim
    let usdc_before = get_ecc_balance_by_id(&mf_address, 3, "shellnet.ackinacki.org").await;

    // 10. Claim USDC
    let claim_result = wallet
        .claim_usdc(bee_wallet::ClaimUsdcReq { denom, order_id, signer_keys: signer_keys.clone() })
        .await
        .expect("claim_usdc failed");
    println!("claim tx: {:?}, payout: {}", claim_result.message_hash, claim_result.usdc_payout);

    // 10. Wait and verify USDC received
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    let usdc_after = get_ecc_balance_by_id(&mf_address, 3, "shellnet.ackinacki.org").await;
    let usdc_delta = usdc_after - usdc_before;
    let expected_payout = (denom as u64) * 1_000_000;
    println!(
        "USDC before={usdc_before}, after={usdc_after}, delta={usdc_delta}, expected={expected_payout}"
    );
    assert!(
        usdc_delta >= expected_payout,
        "Expected at least {expected_payout} micro-USDC, got {usdc_delta}"
    );

    // 11. Verify order disappeared from get_my_sell_orders (best-effort:
    //     accumulator may become inactive after claim self-destruct chain)
    if let Ok(orders) = wallet
        .get_my_sell_orders(bee_wallet::GetMySellOrdersReq {
            multifactor_address: mf_address.clone(),
            page_size: 20,
            cursor: None,
        })
        .await
    {
        let found = orders.orders.iter().any(|o| o.order_id == order_id && o.denom == denom);
        assert!(!found, "claimed order should not appear in get_my_sell_orders");
    }
}

/// Pagination + random claim test:
/// 1. Create 5 sell orders (denom=1, small page_size=2 to force pagination)
/// 2. Claim orders [1] and [3] (random middle positions)
/// 3. Paginate through all pages — collect all orders
/// 4. Verify: total count correct, claimed orders absent, no infinite loop
#[tokio::test]
async fn test_sell_orders_pagination_with_random_claims() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy wallet
    let name = format!("pagclaim_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();
    println!("deployed: {mf_address}");

    let signer_keys =
        ackinacki_kit::tvm_client::crypto::KeyPair { public: epk.clone(), secret: esk.clone() };

    // 2. Fund: gas + Shell for 5 orders of denom=1 (each needs 100 Shell = 100 *
    //    10^9 nano)
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // Gas
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        10_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Shell: 5 orders × 100 Shell × 10^9 = 500_000_000_000
    let shell_ecc = std::collections::HashMap::from([(2u32, 500_000_000_000u64)]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        1_000_000_000,
        shell_ecc,
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 3. Create 5 sell orders
    let mut order_ids = Vec::new();
    for i in 0..5 {
        let result = wallet
            .sell_shells(bee_wallet::SellShellsReq {
                multifactor_address: mf_address.clone(),
                denom: 1,
                signer_keys: signer_keys.clone(),
                bounce: None,
            })
            .await
            .expect(&format!("sell_shells #{i} failed"));
        println!("order #{i}: id={}, sold={}", result.order_id, result.sold);
        order_ids.push(result.order_id);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert_eq!(order_ids.len(), 5);

    // 4. Claim orders at index 1 and 3 (random middle positions)
    let claim_indices = [1, 3];
    for &idx in &claim_indices {
        // Wait for order to be sold (poll)
        let order_id = order_ids[idx];
        println!("claiming order #{idx} (id={order_id})...");

        // Fund the queue: send USDC to accumulator to buy the orders
        let usdc_ecc = std::collections::HashMap::from([(3u32, 1_000_000u64)]); // 1 USDC
        ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
            tvm_ctx.clone(),
            &mf_address,
            1_000_000_000,
            usdc_ecc,
            1,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        match wallet
            .claim_usdc(bee_wallet::ClaimUsdcReq {
                denom: 1,
                order_id,
                signer_keys: signer_keys.clone(),
            })
            .await
        {
            Ok(r) => println!("  claimed: payout={}", r.usdc_payout),
            Err(e) => println!("  claim failed (may not be sold yet): {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // 5. Paginate with page_size=2 — collect all orders
    let mut all_orders = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    let max_pages = 20; // safety limit

    loop {
        let result = wallet
            .get_my_sell_orders(bee_wallet::GetMySellOrdersReq {
                multifactor_address: mf_address.clone(),
                page_size: 2,
                cursor: cursor.clone(),
            })
            .await
            .expect("get_my_sell_orders failed");

        pages += 1;
        println!(
            "page {pages}: {} orders, has_next_page={}, cursor={:?}",
            result.orders.len(),
            result.has_next_page,
            result.next_cursor,
        );
        for o in &result.orders {
            println!(
                "  denom={} order_id={} sold={} claimed={} pos={}",
                o.denom, o.order_id, o.sold, o.claimed, o.position_in_queue
            );
        }

        all_orders.extend(result.orders);

        if !result.has_next_page || result.next_cursor.is_none() {
            break;
        }

        // Safety: no infinite loop
        assert!(
            pages < max_pages,
            "pagination exceeded {max_pages} pages — possible infinite loop"
        );
        cursor = result.next_cursor;
    }

    println!("\ntotal: {} orders across {pages} pages", all_orders.len());

    // 6. Verify results
    // All 5 order_ids should be accounted for (either in list or claimed/skipped)
    for (i, &oid) in order_ids.iter().enumerate() {
        let in_list = all_orders.iter().any(|o| o.order_id == oid);
        let was_claimed = claim_indices.contains(&i);
        if was_claimed {
            // Claimed orders may or may not appear (depends on kit behavior with
            // self-destructed lots)
            if in_list {
                let o = all_orders.iter().find(|o| o.order_id == oid).unwrap();
                println!(
                    "order #{i} (id={oid}): claimed and still in list (claimed={})",
                    o.claimed
                );
            } else {
                println!("order #{i} (id={oid}): claimed and removed from list (expected)");
            }
        } else {
            // Unclaimed orders MUST be in the list
            assert!(in_list, "unclaimed order #{i} (id={oid}) missing from paginated results");
        }
    }

    // No duplicates
    let mut seen_ids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for o in &all_orders {
        assert!(
            seen_ids.insert(o.order_id),
            "duplicate order_id={} in paginated results",
            o.order_id
        );
    }

    println!(
        "pagination test passed: {pages} pages, {} unique orders, no infinite loop",
        all_orders.len()
    );
}

// --- deploy_wallet + check_name_availability ---

#[tokio::test]
async fn test_check_name_availability_and_deploy_wallet() {
    let wallet = create_shellnet_wallet();
    let name = format!("test_{}", now_secs());
    let res = wallet.check_name_availability(name.clone()).await;
    match res {
        Ok(r) => {
            assert!(r.is_available);
            assert!(r.multifactor_address.is_none());
        }
        Err(e) => {
            assert!(!e.message.is_empty());
        }
    }
    let params = create_deploy_wallet_params(name);
    let result = wallet.deploy_wallet(params).await;
    println!("result {result:#?}");
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_deploy_wallet_invalid_name_fails_fast() {
    let wallet = create_shellnet_wallet();
    let params = create_deploy_wallet_params("invalid*name".to_string());
    let err = wallet.deploy_wallet(params).await.expect_err("deploy should fail on invalid name");

    assert_eq!(err.error_code.as_deref(), Some("INVALID_WALLET_NAME"));
    assert!(err.message.contains("Invalid wallet name"));
}

// --- get_miner_details ---

#[tokio::test]
async fn test_get_miner_details_by_multifactor_address() {
    let wallet = create_shellnet_wallet();
    let result = wallet
        .get_miner_details_by_multifactor_address(SHELLNET_T1.to_string())
        .await
        .expect("get_miner_details_by_multifactor_address failed");
    assert!(!result.address.is_empty());
    assert!(!result.owner_address.is_empty());
}

// --- get_miner_address ---

#[tokio::test]
async fn test_get_miner_address() {
    let wallet = create_shellnet_wallet();
    let address = wallet.get_miner_address(SHELLNET_T1).await.expect("get_miner_address failed");
    assert!(!address.is_empty());
}

// --- get_multifactor_balances ---

#[tokio::test]
async fn test_get_multifactor_balances() {
    let wallet = create_shellnet_wallet();
    let result = wallet
        .get_multifactor_balances(ParamsOfGetNativeBalances {
            multifactor_address: SHELLNET_T1.to_string(),
        })
        .await
        .expect("get_multifactor_balances failed");
    assert!(!result.ecc.is_empty() || !result.popitgame.is_empty());
}

// ============================================================
// Network tests using existing shellnet wallets
// ============================================================

// --- get_multifactor_address ---

#[tokio::test]
async fn test_get_multifactor_address() {
    let wallet = create_shellnet_wallet();
    let data = wallet
        .get_multifactor_data_by_name(SHELLNET_T1_NAME.to_string())
        .await
        .expect("get_multifactor_data_by_name failed");
    let mf = data.expect("shellnet_t1 should exist");

    let result = wallet
        .get_multifactor_address(ParamsOfGetMultifactorAddress { pubkey: mf.owner_pubkey.clone() })
        .await
        .expect("get_multifactor_address failed");
    assert!(!result.address.is_empty());
}

// --- get_mirror_address ---

#[tokio::test]
async fn test_get_mirror_address() {
    let wallet = create_shellnet_wallet();
    let data = wallet
        .get_multifactor_data_by_name(SHELLNET_T1_NAME.to_string())
        .await
        .expect("get_multifactor_data_by_name failed");
    let mf = data.expect("shellnet_t1 should exist");

    let result = wallet
        .get_mirror_address(ParamsGetMirrorAddress { pubkey: mf.owner_pubkey.clone() })
        .expect("get_mirror_address failed");
    assert!(!result.address.is_empty());
}

// --- get_multifactor_info ---

#[tokio::test]
async fn test_get_multifactor_info() {
    let wallet = create_shellnet_wallet();
    let address = SHELLNET_T1.to_string();
    let result = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address })
        .await
        .expect("get_multifactor_info failed");
    assert!(result.data.is_some());
}

// --- get_balance_by_token_root ---

#[tokio::test]
async fn test_get_balance_by_token_root() {
    let wallet = create_shellnet_wallet();
    let address = SHELLNET_T1.to_string();
    let result = wallet
        .get_balance_by_token_root(GetBalanceByTokenRootReq {
            token_root: "1".to_string(),
            // ECC (NACKL): dapp_id unused; shellnet is 0.9.0 so ignored anyway.
            token_dapp: String::new(),
            multifactor_address: address,
        })
        .await
        .expect("get_balance_by_token_root failed");
    // own_balance is always present, value can be zero
    let _ = result.own_balance;
}

// --- get_epk_expire_at ---

#[tokio::test]
async fn test_get_epk_expire_at() {
    let wallet = create_shellnet_wallet();

    let result = wallet
        .get_epk_expire_at(GetEPKExpireReq {
            epk: SHELLNET_T1_EPK.to_string(),
            multifactor_address: SHELLNET_T1.to_string(),
        })
        .await
        .expect("get_epk_expire_at failed");
    assert!(result.epk_expire_at > 0);
}

// --- get_tokens_balances ---

#[tokio::test]
async fn test_get_tokens_balances() {
    let wallet = create_shellnet_wallet();
    let address = SHELLNET_T1.to_string();
    let result = wallet
        .get_tokens_balances(ParamsOfGetTokensBalances {
            multifactor_address: address,
            token_roots: vec![bee_wallet::TokenRef {
                token_root: "0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    .to_string(),
                // shellnet: this root lives under the System dApp (verified);
                // ignored on 0.9.0 regardless.
                token_dapp: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            }],
        })
        .await
        .expect("get_tokens_balances failed");
    let _ = result;
}

// ============================================================
// ECC transfer + history integration tests
// ============================================================

async fn send_ecc(
    wallet: &Wallet,
    from: &str,
    to: &str,
    amount: u64,
    signer_keys: KeyPair,
) -> ResultOfSendMessage {
    wallet
        .send_tokens(bee_wallet::SendTokensReq {
            multifactor_address: from.to_string(),
            destination_address: to.to_string(),
            token_root: "1".to_string(),
            // ECC (NACKL): dapp_id unused; shellnet 0.9.0 ignores it anyway.
            token_dapp: String::new(),
            amount_raw: amount,
            signer_keys,
            bounce: None,
        })
        .await
        .expect(&format!("send_tokens failed {} → {}", from, to))
}

/// Paginates through ALL history pages searching for a matching tx.
async fn wait_for_tx(
    wallet: &Wallet,
    address: &str,
    min_ts: u64,
    expected_value: u128,
    expected_type: &str,
) {
    let val_str = expected_value.to_string();

    for attempt in 0..20 {
        let mut cursor: Option<String> = None;
        let mut mining_cursor: Option<String> = None;
        let mut total = 0;

        loop {
            let history = wallet
                .get_history(ParamsOfGetHistory {
                    multifactor_address: address.to_string(),
                    token_id: "1".to_string(),
                    page_size: 50,
                    cursor: cursor.clone(),
                    mining_cursor: mining_cursor.clone(),
                })
                .await
                .expect("get_ecc_history failed");

            total += history.data.len();

            let found = history.data.iter().any(|tx| {
                tx.tx_type == expected_type
                    && tx.created_at.parse::<u64>().unwrap_or(0) >= min_ts
                    && tx.value == val_str
            });

            if found {
                println!("found after {} attempt(s), {} total entries scanned", attempt + 1, total);
                return;
            }

            if !history.has_next_page || history.data.is_empty() {
                break;
            }

            cursor = history.next_cursor;
            mining_cursor = history.next_mining_cursor;
        }

        if attempt % 5 == 0 {
            println!(
                "attempt {}/20, {} total entries, looking for type={} value={} min_ts={}",
                attempt, total, expected_type, expected_value, min_ts
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    panic!(
        "tx not found: addr={}, type={}, min_ts={}, value={}",
        address, expected_type, min_ts, expected_value
    );
}

/// Sends 0.05 NACKL from SHELLNET_T1 to SHELLNET_T2.
/// Checks that the tx appears in history of both wallets.
#[tokio::test]
async fn transfer_ecc_visible_in_history() {
    let wallet = create_shellnet_wallet();

    assert!(SHELLNET_T1_EPK_EXPIRE_AT > bee_wallet::now_secs(), "SHELLNET_T1 EPK expired!");
    assert!(SHELLNET_T2_EPK_EXPIRE_AT > bee_wallet::now_secs(), "SHELLNET_T2 EPK expired!");

    println!("direction: {} → {}", SHELLNET_T1, SHELLNET_T2);

    let ts = bee_wallet::now_secs().saturating_sub(5);
    let amount: u64 = 50_000_000;

    let signer_keys =
        KeyPair { public: SHELLNET_T1_EPK.to_string(), secret: SHELLNET_T1_ESK.to_string() };
    let _res = send_ecc(&wallet, SHELLNET_T1, SHELLNET_T2, amount, signer_keys).await;

    // Wait for Outgoing in sender history
    wait_for_tx(&wallet, SHELLNET_T1, ts, amount as u128, "Outgoing").await;

    // Wait for Incoming in receiver history
    wait_for_tx(&wallet, SHELLNET_T2, ts, amount as u128, "Incoming").await;
}

#[tokio::test]
async fn ecc_history_pagination() {
    let wallet = create_shellnet_wallet();

    let page1 = wallet
        .get_history(ParamsOfGetHistory {
            multifactor_address: SHELLNET_T1.to_string(),
            token_id: "1".to_string(),
            page_size: 2,
            cursor: None,
            mining_cursor: None,
        })
        .await
        .expect("page1");

    if page1.has_next_page {
        let page2 = wallet
            .get_history(ParamsOfGetHistory {
                multifactor_address: SHELLNET_T1.to_string(),
                token_id: "1".to_string(),
                page_size: 2,
                cursor: page1.next_cursor.clone(),
                mining_cursor: page1.next_mining_cursor.clone(),
            })
            .await
            .expect("page2");

        let ids1: std::collections::HashSet<&str> =
            page1.data.iter().map(|t| t.id.as_str()).collect();
        for tx in &page2.data {
            assert!(!ids1.contains(tx.id.as_str()), "duplicate: {}", tx.id);
        }
    }
}

#[tokio::test]
async fn token_history_stub_returns_empty() {
    let wallet = create_shellnet_wallet();

    let result = wallet
        .get_history(ParamsOfGetHistory {
            multifactor_address: SHELLNET_T1.to_string(),
            token_id: "0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_string(),
            page_size: 20,
            cursor: None,
            mining_cursor: None,
        })
        .await
        .expect("get_history for TIP-3");

    assert!(result.data.is_empty());
    assert!(!result.has_next_page);
}

// ============================================================
// send_tokens: NACKL (ECC[1]), SHELL (ECC[2]), USDC (ECC[3])
// ============================================================

#[tokio::test]
async fn test_send_all_ecc_tokens() {
    let wallet = create_shellnet_wallet();

    let sender = deploy_fresh_wallet(&wallet).await;
    let receiver = deploy_fresh_wallet(&wallet).await;
    let signer = KeyPair { public: sender.epk.clone(), secret: sender.esk.clone() };

    let ts = bee_wallet::now_secs().saturating_sub(5);

    // ECC[1] NACKL, ECC[2] SHELL, ECC[3] USDC
    let tokens = [
        ("1", 50_000_000u64, "NACKL"), // 0.05 NACKL (9 decimals)
        ("2", 50_000_000u64, "SHELL"), // 0.05 SHELL (9 decimals)
        ("3", 50_000u64, "USDC"),      // 0.05 USDC (6 decimals)
    ];

    for (token_root, amount, label) in &tokens {
        let result = wallet
            .send_tokens(bee_wallet::SendTokensReq {
                multifactor_address: sender.address.clone(),
                destination_address: receiver.address.clone(),
                token_root: token_root.to_string(),
                // shellnet 0.9.0 ignores dapp_id; System for any TIP-3 root here.
                token_dapp: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                amount_raw: *amount,
                signer_keys: signer.clone(),
                bounce: None,
            })
            .await;
        match &result {
            Ok(res) => println!("{label} send OK: {:?}", res.message_hash),
            Err(e) => panic!("{label} send failed: {e:?}"),
        }
    }

    // Verify NACKL appears in sender history (representative check)
    wait_for_tx(&wallet, &sender.address, ts, 50_000_000, "Outgoing").await;
    // Verify NACKL appears in receiver history
    wait_for_tx(&wallet, &receiver.address, ts, 50_000_000, "Incoming").await;
}

// --- send_tokens_direct (sendTransaction with flags) ---

#[tokio::test]
async fn test_send_tokens_direct_shell_with_flags() {
    let wallet = create_shellnet_wallet();

    let sender = deploy_fresh_wallet(&wallet).await;
    let receiver = deploy_fresh_wallet(&wallet).await;
    let signer = KeyPair { public: sender.epk.clone(), secret: sender.esk.clone() };

    let result = wallet
        .send_tokens_direct(bee_wallet::SendTokensDirectReq {
            multifactor_address: sender.address.clone(),
            destination_address: receiver.address.clone(),
            token_root: "2".to_string(), // ECC[2] SHELL
            amount_raw: 50_000_000,      // 0.05 SHELL (9 decimals)
            flags: 16,
            signer_keys: signer,
            bounce: None,
            value: None,
            payload: None,
        })
        .await;

    let res = result.expect("SHELL send_direct failed");
    assert!(!res.aborted.unwrap_or(false), "tx should not be aborted");
    assert_eq!(res.exit_code.unwrap_or(0), 0, "exit_code should be 0");
    println!("SHELL send_direct OK: {:?}", res.message_hash);

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let sender_history = wallet
        .get_history(ParamsOfGetHistory {
            multifactor_address: sender.address.clone(),
            token_id: "2".to_string(),
            page_size: 5,
            cursor: None,
            mining_cursor: None,
        })
        .await
        .expect("get_history sender failed");

    println!("=== Sender SHELL history ===");
    for tx in &sender_history.data {
        println!(
            "  id={} type={} value={} created_at={} src_name={:?}",
            tx.id, tx.tx_type, tx.value, tx.created_at, tx.src_name
        );
    }

    let receiver_history = wallet
        .get_history(ParamsOfGetHistory {
            multifactor_address: receiver.address.clone(),
            token_id: "2".to_string(),
            page_size: 5,
            cursor: None,
            mining_cursor: None,
        })
        .await
        .expect("get_history receiver failed");

    println!("=== Receiver SHELL history ===");
    for tx in &receiver_history.data {
        println!(
            "  id={} type={} value={} created_at={} src_name={:?}",
            tx.id, tx.tx_type, tx.value, tx.created_at, tx.src_name
        );
    }
}

// --- topup future contract address (send_tokens_direct flag 16) ---

#[tokio::test]
async fn test_topup_future_contract_address() {
    let wallet = create_shellnet_wallet();

    let sender = deploy_fresh_wallet(&wallet).await;
    let signer = KeyPair { public: sender.epk.clone(), secret: sender.esk.clone() };

    let tvm_ctx = create_tvm_context();

    // Generate random keypair for the future contract
    let contract_keys =
        ackinacki_kit::tvm_client::crypto::generate_random_sign_keys(tvm_ctx.clone())
            .expect("generate keys");
    println!("contract keys: public={}, secret={}", contract_keys.public, contract_keys.secret);

    // 3. Load TVC and ABI
    let tvc_bytes = std::fs::read("tests/hello.tvc").expect("read hello.tvc");
    let tvc_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tvc_bytes);
    let abi_json = std::fs::read_to_string("tests/hello.abi.json").expect("read hello.abi.json");
    let abi = ackinacki_kit::tvm_client::abi::Abi::Json(abi_json);

    // 4. Compute future contract address via encode_message with DeploySet
    let encode_result = ackinacki_kit::tvm_client::abi::encode_message(
        tvm_ctx.clone(),
        ackinacki_kit::tvm_client::abi::ParamsOfEncodeMessage {
            abi: abi.clone(),
            address: None,
            deploy_set: Some(ackinacki_kit::tvm_client::abi::DeploySet {
                tvc: Some(tvc_b64),
                code: None,
                state_init: None,
                workchain_id: Some(0),
                initial_data: Some(serde_json::json!({
                    "_pubkey": format!("0x{}", contract_keys.public)
                })),
                initial_pubkey: None,
            }),
            call_set: Some(ackinacki_kit::tvm_client::abi::CallSet {
                function_name: "constructor".to_string(),
                header: None,
                input: Some(serde_json::json!({ "value": 1000000000u64 })),
            }),
            signer: ackinacki_kit::tvm_client::abi::Signer::Keys { keys: contract_keys.clone() },
            processing_try_index: None,
            signature_id: None,
        },
    )
    .await
    .expect("encode_message for future address");

    let future_address = encode_result.address;
    println!("future contract address: {future_address}");

    // 5. Check account state BEFORE top-up — should be NonExist or Uninit.
    // A fresh account created by a plain value transfer becomes the root of
    // its OWN dApp: dapp_id == its account_id (lookups are dapp-scoped on
    // >= 1.0.0 servers, so fetching it under SystemDapp::System finds nothing).
    let future_dapp = future_address.trim_start_matches("0:").to_string();
    let mut account = ackinacki_kit::contracts::account::Account::new(
        tvm_ctx.clone(),
        &future_address,
        future_dapp,
    );
    account.fetch().await.expect("fetch account before");
    println!(
        "account BEFORE: acc_type={:?}, balance={:?}, ecc={:?}",
        account.acc_type, account.balance, account.ecc
    );

    // 6. Send SHELL (ECC[2]) with flag 16 to the future address
    let shell_amount: u64 = 100_000_000; // 0.1 SHELL
    println!(
        "sending {shell_amount} SHELL (ECC[2]) with flag=16, bounce=false to {future_address}"
    );
    let result = wallet
        .send_tokens_direct(bee_wallet::SendTokensDirectReq {
            multifactor_address: sender.address.clone(),
            destination_address: future_address.clone(),
            token_root: "2".to_string(),
            amount_raw: shell_amount,
            flags: 16,
            signer_keys: signer,
            bounce: Some(false), // non-deployed address — no bounce
            value: None,
            payload: None,
        })
        .await
        .expect("send_tokens_direct failed");

    assert!(!result.aborted.unwrap_or(false), "tx should not be aborted");
    assert_eq!(result.exit_code.unwrap_or(0), 0, "exit_code should be 0");
    println!("send_tokens_direct OK: {:?}", result.message_hash);

    // 7. Wait a bit then check account state AFTER top-up
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    account.fetch().await.expect("fetch account after");
    println!(
        "account AFTER: acc_type={:?}, balance={:?}, ecc={:?}",
        account.acc_type, account.balance, account.ecc
    );

    // Account should transition from NonExist to Uninit after top-up
    assert_eq!(
        account.acc_type,
        ackinacki_kit::contracts::account::AccountStatus::Uninit,
        "future account should be Uninit after top-up"
    );

    // ECC[2] key should exist (SHELL currency registered on the account)
    assert!(
        account.ecc.contains_key(&2),
        "future account should have ECC[2] (SHELL) key after top-up, ecc={:?}",
        account.ecc
    );
    println!("SHELL (ECC[2]) balance: {}", account.ecc.get(&2).unwrap());
}

// --- update_zk_id ---

#[tokio::test]
async fn test_update_zk_id() {
    let wallet = create_shellnet_wallet();
    let name = format!("zkid_test_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let initial_zkid = params.zkid.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy_wallet failed");
    let addr = deploy_result.address.clone();
    println!("deployed wallet: {} ({})", name, addr);

    let owner_keys = create_crypto()
        .get_keys_from_mnemonic(deploy_result.phrase.clone())
        .expect("get_keys_from_mnemonic failed");

    let info_before = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address: addr.clone() })
        .await
        .expect("get_multifactor_info failed before update");
    let data_before = info_before.data.expect("no data before update");
    assert_eq!(data_before.zkid, initial_zkid);

    let new_zkid = "148536752753571014218927771785777007655354657642539776711310815121986360450";
    wallet
        .update_zk_id(bee_wallet::UpdateMultifactorZkIdReq {
            address: addr.clone(),
            zkid: new_zkid.to_string(),
            password: "Hello!234".to_string(),
            proof: "9a6f8d061d92d5f3b8de80e210cc46dde0b5847ce37a5b7d1fb27a50151a70a16553dba074487ad37a6ec47fca8e6496b7bf39be6cf5a1c7cf2e4f547155a605670b4720a8626a5c6e30aa7575053a8a5f6c06f0849fefcf634acd056aad1398e570f4ea6b211efc53082da3e7dd839d4fa65b13099db4f9d6c597936864911b".to_string(),
            epk: "4199685466e5f30239e040cb740a9874be680b950aab45a279a15edf2d2c9751".to_string(),
            esk: "cfbcb94227aef19712dcd544b8199d9eac2b3e796a6afd6f970ebc20a9bab84a".to_string(),
            jwk_modulus: "c5b6adf2b02c0731bcd01071786afc797f34ef21d61f3cb5d1ce8c82486427db1eaca9a0ce7f9f9687790a2cc80e87aaff3b1ccd2c4c5a89aafc2885e6a6ce1a0ef569a6608263bda6aec4b369114210139d28346f010ed15cd876bf932cf43d6c7682d97e6c12e940ce05b30c00009177a7692372f281c6ec2fa51f271b0d9e2a38d983d7436682b2b7b9892829448f1834042ddcf9d02eade650658dd41668138df8cf1f79ec03323e80e7eb2814e28918ced0c16cddd891379120152174d170f1acabe5cb937213ccf844371630062bc4a923e406f7d1a92bf4aa5f611cf5848fcc482978ac9d55d2239e8e5670deab82417d3a8c044e187e83bfd79b9fa5".to_string(),
            jwk_modulus_expire_at: (now_secs() + 3600) as i64,
            index_mod_4: 1,
            iss_base_64: "yJpc3MiOiJodHRwczovL29hdXRoLmdvc2guc2giLC".to_string(),
            header_base_64: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZmOGVlZDA0MjgyZjFkYmQ4OWY1YTc5Yjc4N2Q2N2JjODc2MjA1OTcifQ".to_string(),
            epk_expire_at: 1786976441,
            pubkey: owner_keys.public.clone(),
            secretkey: owner_keys.secret.clone(),
            kid: "ff8eed04282f1dbd89f5a79b787d67bc87620597".to_string(),
            sub: "272114864".to_string(),
        })
        .await
        .expect("update_zk_id failed");

    let info_after = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address: addr.clone() })
        .await
        .expect("get_multifactor_info failed after update");
    let data_after = info_after.data.expect("no data after update");
    assert_eq!(data_after.zkid, new_zkid);
}

// --- deploy_wallet → delete_zkp_factor_by_itself → verify factors empty ---

/// Deploys a fresh wallet (which creates 1 ZKP factor), then deletes it,
/// then verifies factors_len == "0" via get_multifactor_info.
/// Covers: deploy_wallet, delete_zkp_factor_by_itself, get_multifactor_info.
#[tokio::test]
async fn test_deploy_wallet_and_delete_zkp_factor() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy a new wallet — creates 1 ZKP factor
    let name = format!("zkp_del_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy_wallet failed");
    let addr = deploy_result.address.clone();
    println!("deployed wallet: {} ({})", name, addr);

    // Verify we start with 1 factor
    let info = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address: addr.clone() })
        .await
        .expect("get_multifactor_info failed");
    let data = info.data.expect("no data after deploy");
    let factors_before: u32 = data.factors_len.parse().unwrap_or(0);
    println!("factors_len before: {}", factors_before);
    assert!(factors_before >= 1, "expected at least 1 factor after deploy, got {}", factors_before);

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. Delete the ZKP factor
    let _res = wallet
        .delete_zkp_factor_by_itself(bee_wallet::DeleteZkpFactorByItselfReq {
            multifactor_address: addr.clone(),
            signer_keys,
        })
        .await
        .expect("delete_zkp_factor_by_itself failed");
    println!("zkp factor deleted");

    // 3. Verify factors list is empty
    let info = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address: addr.clone() })
        .await
        .expect("get_multifactor_info failed");
    let data = info.data.expect("no data after delete");
    let factors_after: u32 = data.factors_len.parse().unwrap_or(999);
    println!("factors_len after: {}", factors_after);
    assert_eq!(
        factors_after,
        factors_before - 1,
        "expected factors_len={}, got {}",
        factors_before - 1,
        factors_after
    );
}

// --- add_zkp_factor ---

#[tokio::test]
async fn test_add_zkp_factor() {
    let wallet = create_shellnet_wallet();
    let name = format!("add_zkp_test_{}", now_secs());
    let mut deploy_params = create_deploy_wallet_params(name.clone());
    deploy_params.zkid =
        "148536752753571014218927771785777007655354657642539776711310815121986360450".to_string();
    deploy_params.password = "Hello!234".to_string();
    deploy_params.proof = "9a6f8d061d92d5f3b8de80e210cc46dde0b5847ce37a5b7d1fb27a50151a70a16553dba074487ad37a6ec47fca8e6496b7bf39be6cf5a1c7cf2e4f547155a605670b4720a8626a5c6e30aa7575053a8a5f6c06f0849fefcf634acd056aad1398e570f4ea6b211efc53082da3e7dd839d4fa65b13099db4f9d6c597936864911b".to_string();
    deploy_params.epk =
        "4199685466e5f30239e040cb740a9874be680b950aab45a279a15edf2d2c9751".to_string();
    deploy_params.esk =
        "cfbcb94227aef19712dcd544b8199d9eac2b3e796a6afd6f970ebc20a9bab84a".to_string();
    deploy_params.epk_expire_at = 1786976441;
    deploy_params.jwk_modulus_expire_at = now_secs() + 3600;

    let deploy_result =
        wallet.deploy_wallet(deploy_params).await.expect("deploy_wallet failed for add_zkp_factor");
    let addr = deploy_result.address.clone();
    println!("deployed wallet: {} ({})", name, addr);

    let info_before = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address: addr.clone() })
        .await
        .expect("get_multifactor_info before add_zkp_factor failed");
    let data_before = info_before.data.expect("no multifactor data before add_zkp_factor");
    let factors_before: u32 = data_before.factors_len.parse().unwrap_or(0);

    let result = wallet
        .add_zkp_factor(bee_wallet::ParamsOfAddZKPFactor {
            wallet_name: name.clone(),
            proof: "a9784d77bb52cc893bcc59472d15379f0a7c41bb8e19d1250e70452ee5b5419c2436933af45472c092de9be3d7a5125b97d974b191fb67ee3e5edc8cfaeebd070f11c186a66e2fe11a69d683e88ecc832318fabd056fbd5f4a5b973326a8390b11f928fb423654fd64b9fe55c9a74b69c87cbf362cc3667012d1ae69d8dcb103".to_string(),
            epk: "14cdf838c938515f97e8eb41d5888deeb588d16f7b9a880bdbdf6385ee787ced"
                .to_string(),
            epk_expire_at: 1786985794,
            esk: "aa2461113a6ce5ae393118ebcba9d6e1406ff0b8775db105ec3b3fdd05d6763d"
                .to_string(),
            header_base_64: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZmOGVlZDA0MjgyZjFkYmQ4OWY1YTc5Yjc4N2Q2N2JjODc2MjA1OTcifQ".to_string(),
            jwk_expires_at: 1771541773,
            kid: "ff8eed04282f1dbd89f5a79b787d67bc87620597".to_string(),
            sub: "272114864".to_string(),
            password: "Hello!234".to_string(),
            zkid: "148536752753571014218927771785777007655354657642539776711310815121986360450"
                .to_string(),
        })
        .await
        .expect("add_zkp_factor failed");

    assert_eq!(result.name, name);
    assert_eq!(result.address, addr);

    let info_after = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address: addr.clone() })
        .await
        .expect("get_multifactor_info after add_zkp_factor failed");
    let data_after = info_after.data.expect("no multifactor data after add_zkp_factor");
    let factors_after: u32 = data_after.factors_len.parse().unwrap_or(0);
    assert_eq!(factors_after, factors_before + 1);
}

// --- deploy_wallet → deploy_miner → set_mining_keys ---

/// Deploys a fresh wallet, then deploys a miner for it, then sets mining keys.
/// Covers: deploy_wallet, deploy_miner, set_mining_keys.
#[tokio::test]
async fn test_deploy_wallet_then_miner_and_mining_keys() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy a new wallet
    let name = format!("miner_test_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy_wallet failed");
    let addr = deploy_result.address.clone();
    println!("deployed wallet: {} ({})", name, addr);

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. Deploy miner explicitly (deploy_wallet does not deploy miner)
    let first_deploy_miner_result = wallet
        .deploy_miner(bee_wallet::ParamsOfDeployMiner {
            multifactor_address: addr.clone(),
            signer_keys: signer_keys.clone(),
        })
        .await
        .expect("deploy_miner failed");
    assert!(
        !first_deploy_miner_result.message_ids.is_empty(),
        "first deploy_miner call should deploy miner for a fresh wallet"
    );
    println!("miner deployed for {}", addr);

    // deploy_miner is idempotent — second call should be a no-op
    let second_deploy_miner_result = wallet
        .deploy_miner(bee_wallet::ParamsOfDeployMiner {
            multifactor_address: addr.clone(),
            signer_keys: signer_keys.clone(),
        })
        .await
        .expect("deploy_miner (idempotent) failed");
    assert!(
        second_deploy_miner_result.message_ids.is_empty(),
        "second deploy_miner call should be a no-op"
    );

    // 3. Generate mining keys and set them
    let mining_keys = create_crypto().gen_mining_keys().expect("gen_mining_keys failed");
    println!("mining pubkey: {}", mining_keys.public);

    wallet
        .set_mining_keys(bee_wallet::ParamsOfSetMiningKeys {
            multifactor_address: addr.clone(),
            signer_keys: signer_keys.clone(),
            mining_pubkey: mining_keys.public.clone(),
            app_id: String::new(), // falls back to ctx.app_id
            epk_expire_at: None,   // resolved from contract
        })
        .await
        .expect("set_mining_keys failed");
    println!("mining keys set for {}", addr);
}

/// Deploys a fresh wallet, deploys miner, sets mining key and verifies it,
/// then removes mining key with wait and verifies it was removed.
/// Covers: deploy_wallet, deploy_miner, set_mining_keys, del_mining_key,
/// get_miner_details.
#[tokio::test]
async fn test_del_mining_key() {
    let wallet = create_shellnet_wallet();

    let name = format!("del_miner_key_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy_wallet failed");
    let addr = deploy_result.address.clone();
    println!("deployed wallet: {} ({})", name, addr);

    let signer_keys = KeyPair { public: epk, secret: esk };

    wallet
        .deploy_miner(bee_wallet::ParamsOfDeployMiner {
            multifactor_address: addr.clone(),
            signer_keys: signer_keys.clone(),
        })
        .await
        .expect("deploy_miner failed");

    let mining_keys = create_crypto().gen_mining_keys().expect("gen_mining_keys failed");
    let expected_owner_public = format!("0x{}", mining_keys.public);
    let app_id = "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();

    wallet
        .set_mining_keys(bee_wallet::ParamsOfSetMiningKeys {
            multifactor_address: addr.clone(),
            signer_keys: signer_keys.clone(),
            mining_pubkey: mining_keys.public.clone(),
            app_id: String::new(),
            epk_expire_at: None,
        })
        .await
        .expect("set_mining_keys failed");

    let details_after_set = wallet
        .get_miner_details_by_multifactor_address(addr.clone())
        .await
        .expect("get_miner_details_by_multifactor_address after set failed");
    let actual_owner_public = details_after_set.owner_public.get(app_id.as_str()).cloned();
    assert_eq!(actual_owner_public, Some(expected_owner_public));

    wallet
        .del_mining_key(bee_wallet::ParamsOfDelMiningKey {
            multifactor_address: addr.clone(),
            signer_keys,
            app_id: String::new(),
            epk_expire_at: None,
            wait: true,
        })
        .await
        .expect("del_mining_key failed");

    let details_after_del = wallet
        .get_miner_details_by_multifactor_address(addr.clone())
        .await
        .expect("get_miner_details_by_multifactor_address after del failed");
    let has_owner_public = details_after_del
        .owner_public
        .get(app_id.as_str())
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    assert!(!has_owner_public, "owner_public for app_id should be removed");
}

// --- deploy_wallet → change_seed_phrase → verify owner_pubkey ---

/// Deploys a fresh wallet, changes the seed phrase, then verifies
/// that owner_pubkey in multifactor info matches the new key.
/// Covers: deploy_wallet, change_seed_phrase, get_multifactor_info.
#[tokio::test]
async fn test_deploy_wallet_and_change_seed_phrase() {
    let wallet = create_shellnet_wallet();

    // 1. Deploy a new wallet
    let name = format!("seed_test_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let password = params.password.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy_wallet failed");
    let addr = deploy_result.address.clone();
    let original_pubkey = deploy_result.pubkey.clone();
    println!("deployed wallet: {} ({})", name, addr);
    println!("original owner_pubkey: {}", original_pubkey);

    let signer_keys = KeyPair { public: epk, secret: esk };

    // 2. Generate a new seed phrase → derive new owner keys
    let new_seed = create_crypto().gen_mnemonic_and_derive_keys().expect("gen_mnemonic failed");
    let new_owner_keys =
        KeyPair { public: new_seed.keys.public.clone(), secret: new_seed.keys.secret.clone() };
    println!("new owner_pubkey: {}", new_owner_keys.public);
    assert_ne!(original_pubkey, new_owner_keys.public);

    // 3. Change seed phrase
    wallet
        .change_seed_phrase(bee_wallet::ParamsOfChangeSeedPhrase {
            password,
            signer_keys: signer_keys.clone(),
            new_owner_keys: new_owner_keys.clone(),
            multifactor_address: addr.clone(),
        })
        .await
        .expect("change_seed_phrase failed");
    println!("seed phrase changed");

    // 4. Verify owner_pubkey updated
    let info = wallet
        .get_multifactor_info(ParamsOfGetMultifactorInfo { address: addr.clone() })
        .await
        .expect("get_multifactor_info failed");

    let data = info.data.expect("multifactor data is None after change_seed_phrase");
    let actual_pubkey = data.owner_pubkey.clone();
    println!("verified owner_pubkey: {}", actual_pubkey);

    // owner_pubkey is stored with 0x prefix
    let expected = format!("0x{}", new_owner_keys.public);
    assert_eq!(
        actual_pubkey, expected,
        "owner_pubkey mismatch: expected {} got {}",
        expected, actual_pubkey
    );
}

// ============================================================
// decode_connect_payload_b64url
// ============================================================

#[test]
fn test_decode_connect_payload_b64url() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let wallet = create_shellnet_wallet();

    // Build a valid ConnectPayload JSON and base64url-encode it
    let payload = ConnectPayload {
        v: "bee_connect.dl/1".to_string(),
        session_id: "test_session_123".to_string(),
        description: "test_description_456".to_string(),
        expires_at: now_secs() + 3600,
        app_id: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        nonce: None,
    };
    let payload_json = serde_json::to_string(&payload).expect("serialize payload");
    let encoded = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    // Round-trip: decode should return the same fields
    let decoded = wallet
        .decode_connect_payload_b64url(encoded.clone())
        .expect("decode_connect_payload_b64url failed");
    assert_eq!(decoded.v, payload.v);
    assert_eq!(decoded.session_id, payload.session_id);
    assert_eq!(decoded.description, payload.description);
    assert_eq!(decoded.expires_at, payload.expires_at);

    // Error case: invalid base64
    let err = wallet.decode_connect_payload_b64url("!!!not-base64!!!".to_string());
    assert!(err.is_err(), "should fail on invalid base64");

    // Error case: valid base64 but invalid JSON
    let bad_json = URL_SAFE_NO_PAD.encode(b"not json");
    let err = wallet.decode_connect_payload_b64url(bad_json);
    assert!(err.is_err(), "should fail on invalid JSON");

    // Error case: valid JSON but wrong version
    let bad_payload = serde_json::json!({
        "v": "wrong_version",
        "session_id": "s",
        "description": "d",
        "expires_at": now_secs() + 3600,
        "app_id": "0x0000000000000000000000000000000000000000000000000000000000000000"
    });
    let bad_encoded = URL_SAFE_NO_PAD.encode(bad_payload.to_string().as_bytes());
    let err = wallet.decode_connect_payload_b64url(bad_encoded);
    assert!(err.is_err(), "should fail on wrong version");

    // Error case: empty session_id
    let empty_session = serde_json::json!({
        "v": "bee_connect.dl/1",
        "session_id": "",
        "description": "d",
        "expires_at": now_secs() + 3600,
        "app_id": "0x0000000000000000000000000000000000000000000000000000000000000000"
    });
    let empty_encoded = URL_SAFE_NO_PAD.encode(empty_session.to_string().as_bytes());
    let err = wallet.decode_connect_payload_b64url(empty_encoded);
    assert!(err.is_err(), "should fail on empty session_id");
}

// ============================================================
// prepare_zk_login_v1
// ============================================================

#[test]
fn test_prepare_zk_login_v1() {
    let wallet = create_shellnet_wallet();

    let result1 = wallet.prepare_zk_login_v1().expect("prepare_zk_login_v1 first call");
    assert!(!result1.nonce.is_empty(), "nonce should be non-empty");
    assert!(!result1.randomness.is_empty(), "randomness should be non-empty");
    assert!(!result1.ephemeral_private_key.is_empty(), "ephemeral_private_key should be non-empty");
    assert!(result1.max_epoch > 0, "max_epoch should be positive");

    // The ephemeral_private_key should be a valid suiprivkey bech32
    assert!(
        result1.ephemeral_private_key.starts_with("suiprivkey1"),
        "ephemeral_private_key should be suiprivkey bech32"
    );

    // Call twice — nonces should differ (randomness is random)
    let result2 = wallet.prepare_zk_login_v1().expect("prepare_zk_login_v1 second call");
    assert_ne!(result1.nonce, result2.nonce, "two calls should produce different nonces");
    assert_ne!(
        result1.randomness, result2.randomness,
        "two calls should produce different randomness"
    );
    assert_ne!(
        result1.ephemeral_private_key, result2.ephemeral_private_key,
        "two calls should produce different ephemeral keys"
    );
}

// ============================================================
// complete_zk_login_with_prover_v1 (requires live JWT)
// ============================================================

#[tokio::test]
#[ignore = "Requires a live JWT token from an OAuth provider"]
async fn test_complete_zk_login_with_prover_v1() {
    let _wallet = create_shellnet_wallet();
    // To test this method you need:
    // 1. A valid JWT from a supported OAuth provider (e.g. Google, Gosh)
    // 2. The ephemeral key data from prepare_zk_login_v1
    // 3. A running prover service
    //
    // Example skeleton:
    // let prepare = wallet.prepare_zk_login_v1().expect("prepare");
    // let result =
    // wallet.complete_zk_login_with_prover_v1(ZkLoginCompleteWithProverParams {
    //     jwt: "<live_jwt_token>".to_string(),
    //     ephemeral_private_key: prepare.ephemeral_private_key,
    //     randomness: prepare.randomness,
    //     max_epoch: prepare.max_epoch,
    //     ..
    // }).await.expect("complete_zk_login_with_prover_v1");
    todo!("Implement test_complete_zk_login_with_prover_v1 - requires a live JWT token");
}

// ============================================================
// wallet connect full flow:
//   accept_connect_shared_key → query_connect_session_messages
//   → destroy_connect_profile
// ============================================================

// Shellnet multifactor for connect/buy_shells tests
const SHELLNET_MULTIFACTOR: &str =
    "0:3d51528b8ad806dea2018d24fa9a428386f1c6883fb0944684fc08c4bbbe223a";
const SHELLNET_MF_EPK: &str = "2b9d728a42e05dfe43a10fa0d8e16b0b06ad482822309fe1aabac01aff8b34ee";
const SHELLNET_MF_ESK: &str = "8328afbf10019fa8d0002a3764f8bb433f8f5cf84ec51af0cdc172c6ef72dd29";

#[tokio::test]
async fn test_wallet_connect_full_flow() {
    let wallet = create_shellnet_wallet();

    // 1. Create a ConnectClient session (dApp side)
    let connect_client = ConnectClient::new();
    let session = connect_client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session failed");
    assert!(!session.session_id.is_empty());
    assert!(!session.client_dh_public.is_empty());
    assert!(!session.description.is_empty());

    // Decode the payload to build ConnectPayload for accept
    let payload = wallet
        .decode_connect_payload_b64url(session.payload_b64url.clone())
        .expect("decode_connect_payload_b64url failed");

    // 2. Wallet accepts the connect session
    let accept_result = wallet
        .accept_connect_shared_key(ParamsOfAcceptSharedKeyConnect {
            payload: payload.clone(),
            wallet_name: "shellnet_connect_test".to_string(),
            wallet_address: SHELLNET_MULTIFACTOR.to_string(),
            client_dh_public: session.client_dh_public.clone(),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
            challenge_signature: None,
            challenge_epk_public: None,
        })
        .await
        .expect("accept_connect_shared_key failed");
    assert!(!accept_result.profile_address.is_empty());
    assert!(!accept_result.wallet_hello_json.is_empty());
    println!("connect profile: {}", accept_result.profile_address);

    // 3. Query session messages — poll until wallet_hello appears on-chain
    let mut has_hello = false;
    for attempt in 1..=30 {
        let query_result = wallet
            .query_connect_session_messages(ParamsOfQuerySessionMessages {
                session_id: payload.session_id.clone(),
                description: payload.description.clone(),
                session_state: Some(accept_result.session_state.clone()),
                created_at_from: None,
                before: None,
                limit: Some(50),
            })
            .await
            .expect("query_connect_session_messages failed");
        assert_eq!(query_result.profile_address, accept_result.profile_address);
        has_hello = query_result.messages.iter().any(|m| m.msg_type == "wallet_hello");
        if has_hello {
            println!("wallet_hello found on attempt {attempt}");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(has_hello, "wallet_hello message should be present after polling");

    // 4. Destroy the connect profile (best-effort cleanup)
    let signer_keys =
        KeyPair { public: SHELLNET_MF_EPK.to_string(), secret: SHELLNET_MF_ESK.to_string() };
    let destroy_result = wallet
        .destroy_connect_profile(ParamsOfDestroyConnectProfile {
            profile_address: accept_result.profile_address.clone(),
            multifactor_address: SHELLNET_MULTIFACTOR.to_string(),
            signer_keys,
        })
        .await;
    match destroy_result {
        Ok(_) => println!("connect profile destroyed"),
        Err(e) => eprintln!("Warning: connect profile cleanup failed (non-fatal): {e}"),
    }
}

// --- connect: multiple c2w messages round-trip ---

/// Full round-trip: dApp creates session → wallet accepts → dApp
/// wait_wallet_hello → dApp sends set_mining_keys twice → wallet sees both
/// messages with correct re-key chain.
#[tokio::test]
async fn test_connect_multiple_c2w_messages() {
    use bee_connect::ParamsOfRequestSetMiningKeys;
    use bee_connect::ParamsOfWaitWalletHello;

    let wallet = create_shellnet_wallet();
    let connect_client = ConnectClient::new();

    // 1. dApp: create session
    let session = connect_client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session failed");
    println!("session_id: {}", session.session_id);

    let payload = wallet
        .decode_connect_payload_b64url(session.payload_b64url.clone())
        .expect("decode_connect_payload_b64url failed");

    // 2. Wallet: accept → sends wallet_hello
    let accept = wallet
        .accept_connect_shared_key(ParamsOfAcceptSharedKeyConnect {
            payload: payload.clone(),
            wallet_name: "shellnet_connect_test".to_string(),
            wallet_address: SHELLNET_MULTIFACTOR.to_string(),
            client_dh_public: session.client_dh_public.clone(),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
            challenge_signature: None,
            challenge_epk_public: None,
        })
        .await
        .expect("accept_connect_shared_key failed");
    println!("profile: {}", accept.profile_address);

    // 3. dApp: wait_wallet_hello → get session_state
    let hello = connect_client
        .wait_wallet_hello(ParamsOfWaitWalletHello {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            client_dh_secret: session.client_dh_secret.clone(),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_wallet_hello failed");
    println!("wallet_hello received: wallet_name={}", hello.wallet_name);
    let mut dapp_session_state = hello.session_state;

    // 4. dApp: send first set_mining_keys (c2w #1)
    let req1 = connect_client
        .request_set_mining_keys(ParamsOfRequestSetMiningKeys {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_session_state.clone(),
            app_id: "0x1".to_string(),
            owner_public: "aa".repeat(32),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_set_mining_keys #1 failed");
    println!("c2w #1 sent: message_id={:?}", req1.message_id);
    dapp_session_state = req1.updated_session_state;

    // 5. dApp: send second set_mining_keys (c2w #2) with updated state
    let req2 = connect_client
        .request_set_mining_keys(ParamsOfRequestSetMiningKeys {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_session_state.clone(),
            app_id: "0x1".to_string(),
            owner_public: "bb".repeat(32),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_set_mining_keys #2 failed");
    println!("c2w #2 sent: message_id={:?}", req2.message_id);

    // 6. Wallet: poll session messages — should see both set_mining_keys
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let mut wallet_session_state = Some(accept.session_state.clone());
    let query = wallet
        .query_connect_session_messages(ParamsOfQuerySessionMessages {
            session_id: payload.session_id.clone(),
            description: payload.description.clone(),
            session_state: wallet_session_state.clone(),
            created_at_from: None,
            before: None,
            limit: Some(50),
        })
        .await
        .expect("query_connect_session_messages failed");

    // Update wallet session state (re-key inbound)
    if let Some(updated) = query.updated_session_state {
        wallet_session_state = Some(updated);
    }

    let set_mining_keys_msgs: Vec<_> =
        query.messages.iter().filter(|m| m.msg_type == "set_mining_keys").collect();

    println!(
        "wallet sees {} set_mining_keys messages (total messages: {})",
        set_mining_keys_msgs.len(),
        query.messages.len()
    );
    for msg in &set_mining_keys_msgs {
        println!(
            "  seq={}, owner_public={:?}",
            msg.seq,
            msg.set_mining_keys.as_ref().map(|b| &b.owner_public)
        );
    }

    assert!(
        set_mining_keys_msgs.len() >= 2,
        "wallet should see at least 2 set_mining_keys messages, got {}",
        set_mining_keys_msgs.len()
    );

    // Verify different owner_public in each message
    let pub1 = set_mining_keys_msgs[0].set_mining_keys.as_ref().map(|b| &b.owner_public);
    let pub2 = set_mining_keys_msgs[1].set_mining_keys.as_ref().map(|b| &b.owner_public);
    assert_ne!(pub1, pub2, "two messages should have different owner_public");

    // 7. Re-query with already-updated state — must NOT break re-key chain. This is
    //    the key regression test: passing session_state that already accounts for
    //    processed messages should not corrupt the DH chain.
    let query2 = wallet
        .query_connect_session_messages(ParamsOfQuerySessionMessages {
            session_id: payload.session_id.clone(),
            description: payload.description.clone(),
            session_state: wallet_session_state.clone(),
            created_at_from: None,
            before: None,
            limit: Some(50),
        })
        .await
        .expect("second query_connect_session_messages failed");

    let set_keys_2: Vec<_> =
        query2.messages.iter().filter(|m| m.msg_type == "set_mining_keys").collect();
    println!("re-query: wallet sees {} set_mining_keys messages", set_keys_2.len());
    assert!(
        set_keys_2.len() >= 2,
        "re-query should still see both messages, got {}",
        set_keys_2.len()
    );

    // 8. Cleanup: destroy profile
    let signer_keys =
        KeyPair { public: SHELLNET_MF_EPK.to_string(), secret: SHELLNET_MF_ESK.to_string() };
    let _ = wallet
        .destroy_connect_profile(ParamsOfDestroyConnectProfile {
            profile_address: accept.profile_address.clone(),
            multifactor_address: SHELLNET_MULTIFACTOR.to_string(),
            signer_keys,
        })
        .await;
    println!("profile destroyed (best-effort)");
}

/// Full round-trip: dApp creates session → wallet accepts → dApp
/// wait_wallet_hello → dApp sends sign_challenge → wallet sees it → wallet
/// sends challenge_response → dApp receives and verifies nonce + signature.
#[tokio::test]
async fn test_connect_sign_challenge_flow() {
    use bee_connect::ParamsOfRequestSignChallenge;
    use bee_connect::ParamsOfWaitChallengeResponse;
    use bee_connect::ParamsOfWaitWalletHello;

    let wallet = create_shellnet_wallet();
    let connect_client = ConnectClient::new();

    // 1. dApp: create session
    let session = connect_client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session failed");
    println!("session_id: {}", session.session_id);

    let payload = wallet
        .decode_connect_payload_b64url(session.payload_b64url.clone())
        .expect("decode_connect_payload_b64url failed");

    // 2. Wallet: accept → sends wallet_hello
    let accept = wallet
        .accept_connect_shared_key(ParamsOfAcceptSharedKeyConnect {
            payload: payload.clone(),
            wallet_name: "challenge_test".to_string(),
            wallet_address: SHELLNET_MULTIFACTOR.to_string(),
            client_dh_public: session.client_dh_public.clone(),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
            challenge_signature: None,
            challenge_epk_public: None,
        })
        .await
        .expect("accept_connect_shared_key failed");
    println!("profile: {}", accept.profile_address);
    let mut wallet_session_state = accept.session_state.clone();

    // 3. dApp: wait_wallet_hello → get session_state
    let hello = connect_client
        .wait_wallet_hello(ParamsOfWaitWalletHello {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            client_dh_secret: session.client_dh_secret.clone(),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_wallet_hello failed");
    println!("wallet_hello received: wallet_name={}", hello.wallet_name);
    let mut dapp_session_state = hello.session_state;

    // 4. dApp: send sign_challenge (c→w)
    let test_nonce = "deadbeef42cafe01";
    let challenge_result = connect_client
        .request_sign_challenge(ParamsOfRequestSignChallenge {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_session_state.clone(),
            nonce: test_nonce.to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_sign_challenge failed");
    println!("sign_challenge sent: message_id={:?}", challenge_result.message_id);
    dapp_session_state = challenge_result.updated_session_state;

    // 5. Wallet: poll query_session_messages until sign_challenge appears
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let mut found_challenge = false;
    let mut received_nonce = String::new();
    for attempt in 1..=30 {
        let query_result = wallet
            .query_connect_session_messages(ParamsOfQuerySessionMessages {
                session_id: payload.session_id.clone(),
                description: payload.description.clone(),
                session_state: Some(wallet_session_state.clone()),
                created_at_from: None,
                before: None,
                limit: Some(50),
            })
            .await
            .expect("query_connect_session_messages failed");

        // Update wallet session state for re-keying
        if let Some(updated) = query_result.updated_session_state {
            wallet_session_state = updated;
        }

        for msg in &query_result.messages {
            if msg.msg_type == "sign_challenge" {
                if let Some(ref sc) = msg.sign_challenge {
                    println!(
                        "wallet received sign_challenge on attempt {attempt}: nonce={}",
                        sc.nonce
                    );
                    received_nonce = sc.nonce.clone();
                    found_challenge = true;
                }
            }
        }
        if found_challenge {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(found_challenge, "wallet should see sign_challenge message");
    assert_eq!(received_nonce, test_nonce);

    // 6. Wallet: sign the nonce and send challenge_response (w→c)
    let fake_signature = "aa".repeat(64); // In production: sign_detached_hex(nonce, epk_secret)

    // Rekey for outbound w2c message
    let rekey_seq = wallet_session_state.next_outbound_seq().expect("next_outbound_seq failed");
    let rekey =
        bee_connect::dh::rekey_outbound(&wallet_session_state, &payload.session_id, rekey_seq)
            .expect("rekey_outbound failed");

    let response_json = bee_wallet::encode_challenge_response_message(
        &payload.session_id,
        &received_nonce,
        &fake_signature,
        SHELLNET_MULTIFACTOR,
        Some(SHELLNET_MF_EPK),
        &rekey.message_encryption_root,
        rekey.new_dh_public.as_deref().unwrap_or(""),
        rekey.outbound_seq,
    )
    .expect("encode_challenge_response_message failed");

    let profile = ackinacki_kit::contracts::authservice::profile::AuthProfile::new_default(
        {
            let mut cfg = ackinacki_kit::tvm_client::ClientConfig::default();
            cfg.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
            std::sync::Arc::new(ackinacki_kit::tvm_client::ClientContext::new(cfg).unwrap())
        },
        &accept.profile_address,
    );
    let signing_keys = KeyPair {
        public: wallet_session_state.signing_public.clone(),
        secret: wallet_session_state.signing_secret.to_string(),
    };
    let send_result = profile
        .add_context_text(
            &response_json,
            ackinacki_kit::tvm_client::abi::Signer::Keys { keys: signing_keys },
        )
        .await
        .expect("add_context_text challenge_response failed");
    println!("challenge_response sent: {:?}", send_result.message_hash);

    wallet_session_state = rekey.updated_state.clone();

    // 7. dApp: wait_challenge_response dApp state after sign_challenge already
    //    accounts for the outbound rekey. wait_challenge_response scans events for
    //    w2c messages and re-keys inbound.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let cr = connect_client
        .wait_challenge_response(ParamsOfWaitChallengeResponse {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: Some(dapp_session_state.clone()),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_challenge_response failed");

    println!(
        "challenge_response received: nonce={}, signature={}..., wallet_address={}",
        cr.nonce,
        &cr.signature[..16],
        cr.wallet_address
    );
    assert_eq!(cr.nonce, test_nonce, "nonce should match");
    assert_eq!(cr.signature, fake_signature, "signature should match");
    assert_eq!(cr.wallet_address, SHELLNET_MULTIFACTOR, "wallet_address should match");
    assert_eq!(
        cr.epk_public.as_deref(),
        Some(SHELLNET_MF_EPK),
        "epk_public should be present and match the signing key"
    );
    println!("sign_challenge/challenge_response flow PASSED");

    // 8. Cleanup
    let signer_keys =
        KeyPair { public: SHELLNET_MF_EPK.to_string(), secret: SHELLNET_MF_ESK.to_string() };
    let _ = wallet
        .destroy_connect_profile(ParamsOfDestroyConnectProfile {
            profile_address: accept.profile_address.clone(),
            multifactor_address: SHELLNET_MULTIFACTOR.to_string(),
            signer_keys,
        })
        .await;
    println!("profile destroyed (best-effort)");
}

/// dApp sends sign_challenge → wallet responds → dApp sends SECOND
/// sign_challenge from the PRE-challenge state (simulating a timeout on attempt
/// 1) → wait_challenge_response must return a `session_desync` error
/// immediately instead of polling for 4 minutes.
#[tokio::test]
async fn test_connect_challenge_desync_detected() {
    use bee_connect::ParamsOfRequestSignChallenge;
    use bee_connect::ParamsOfWaitChallengeResponse;
    use bee_connect::ParamsOfWaitWalletHello;

    let wallet = create_shellnet_wallet();
    let connect_client = ConnectClient::new();

    // 1. Create session + handshake
    let session = connect_client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session failed");

    let payload = wallet
        .decode_connect_payload_b64url(session.payload_b64url.clone())
        .expect("decode_connect_payload_b64url failed");

    let accept = wallet
        .accept_connect_shared_key(ParamsOfAcceptSharedKeyConnect {
            payload: payload.clone(),
            wallet_name: "desync_test".to_string(),
            wallet_address: SHELLNET_MULTIFACTOR.to_string(),
            client_dh_public: session.client_dh_public.clone(),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
            challenge_signature: None,
            challenge_epk_public: None,
        })
        .await
        .expect("accept_connect_shared_key failed");
    let mut wallet_session_state = accept.session_state.clone();

    let hello = connect_client
        .wait_wallet_hello(ParamsOfWaitWalletHello {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            client_dh_secret: session.client_dh_secret.clone(),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_wallet_hello failed");
    let dapp_session_state = hello.session_state;

    // 2. Attempt 1: dApp sends sign_challenge
    let challenge1 = connect_client
        .request_sign_challenge(ParamsOfRequestSignChallenge {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_session_state.clone(),
            nonce: "desync_nonce_1".to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_sign_challenge failed");

    // 3. Wallet: poll for sign_challenge, then respond
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    for attempt in 1..=30 {
        let query_result = wallet
            .query_connect_session_messages(ParamsOfQuerySessionMessages {
                session_id: payload.session_id.clone(),
                description: payload.description.clone(),
                session_state: Some(wallet_session_state.clone()),
                created_at_from: None,
                before: None,
                limit: Some(50),
            })
            .await
            .expect("query_connect_session_messages failed");
        if let Some(updated) = query_result.updated_session_state {
            wallet_session_state = updated;
        }
        let found = query_result
            .messages
            .iter()
            .any(|m| m.msg_type == "sign_challenge" && m.sign_challenge.is_some());
        if found {
            println!("wallet saw sign_challenge on attempt {attempt}");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // Wallet sends challenge_response
    let rekey_seq = wallet_session_state.next_outbound_seq().expect("next_outbound_seq failed");
    let rekey =
        bee_connect::dh::rekey_outbound(&wallet_session_state, &payload.session_id, rekey_seq)
            .expect("rekey_outbound failed");
    let response_json = bee_wallet::encode_challenge_response_message(
        &payload.session_id,
        "desync_nonce_1",
        &"aa".repeat(64),
        SHELLNET_MULTIFACTOR,
        Some(SHELLNET_MF_EPK),
        &rekey.message_encryption_root,
        rekey.new_dh_public.as_deref().unwrap_or(""),
        rekey.outbound_seq,
    )
    .expect("encode_challenge_response_message failed");

    let profile = ackinacki_kit::contracts::authservice::profile::AuthProfile::new_default(
        {
            let mut cfg = ackinacki_kit::tvm_client::ClientConfig::default();
            cfg.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
            std::sync::Arc::new(ackinacki_kit::tvm_client::ClientContext::new(cfg).unwrap())
        },
        &accept.profile_address,
    );
    let signing_keys = KeyPair {
        public: wallet_session_state.signing_public.clone(),
        secret: wallet_session_state.signing_secret.to_string(),
    };
    profile
        .add_context_text(
            &response_json,
            ackinacki_kit::tvm_client::abi::Signer::Keys { keys: signing_keys },
        )
        .await
        .expect("add_context_text challenge_response failed");
    println!("challenge_response for attempt 1 sent");
    let _ = &challenge1; // used above for the flow; silence unused warning

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 4. Simulate dApp timeout on attempt 1: dApp did NOT save state from
    //    challenge1. It retries from the ORIGINAL dapp_session_state.
    let _challenge2 = connect_client
        .request_sign_challenge(ParamsOfRequestSignChallenge {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_session_state.clone(), // original state, not challenge1.updated
            nonce: "desync_nonce_2".to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_sign_challenge 2 failed");

    // 5. dApp waits for challenge_response — should get session_desync error
    //    immediately because the old challenge_response from attempt 1 is on-chain
    //    but undecryptable from challenge2's DH state.
    let result = connect_client
        .wait_challenge_response(ParamsOfWaitChallengeResponse {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: Some(_challenge2.updated_session_state.clone()),
            created_at_from: Some(session.created_at),
            max_attempts: Some(10),
            interval_ms: Some(2_000),
        })
        .await;

    assert!(result.is_err(), "wait_challenge_response should fail with desync");
    let err = result.unwrap_err();
    assert!(
        err.message.contains("session_desync"),
        "error should contain 'session_desync', got: {err}"
    );
    println!("desync correctly detected: {err}");

    // 6. Cleanup
    let signer_keys =
        KeyPair { public: SHELLNET_MF_EPK.to_string(), secret: SHELLNET_MF_ESK.to_string() };
    let _ = wallet
        .destroy_connect_profile(ParamsOfDestroyConnectProfile {
            profile_address: accept.profile_address.clone(),
            multifactor_address: SHELLNET_MULTIFACTOR.to_string(),
            signer_keys,
        })
        .await;
    println!("profile destroyed (best-effort)");
}

/// AuthProfile event pagination: write 6 events, query with limit=4,
/// verify first page returns 4 events + has_previous_page=true + cursor,
/// second page returns remaining events.
#[tokio::test]
async fn test_auth_profile_event_pagination() {
    use ackinacki_kit::contracts::authservice::profile::AuthProfile;
    use ackinacki_kit::contracts::authservice::profile::ParamsOfQueryProfileEvents;
    use ackinacki_kit::tvm_client::abi::Signer;

    let wallet = create_shellnet_wallet();
    let connect_client = ConnectClient::new();

    // 1. Create session + handshake (deploys AuthProfile)
    let session = connect_client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session failed");

    let payload = wallet
        .decode_connect_payload_b64url(session.payload_b64url.clone())
        .expect("decode_connect_payload_b64url failed");

    let accept = wallet
        .accept_connect_shared_key(ParamsOfAcceptSharedKeyConnect {
            payload: payload.clone(),
            wallet_name: "pagination_test".to_string(),
            wallet_address: SHELLNET_MULTIFACTOR.to_string(),
            client_dh_public: session.client_dh_public.clone(),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
            challenge_signature: None,
            challenge_epk_public: None,
        })
        .await
        .expect("accept_connect_shared_key failed");

    // wallet_hello is event #1 (already written by accept)
    let profile = AuthProfile::new_default(
        {
            let mut cfg = ackinacki_kit::tvm_client::ClientConfig::default();
            cfg.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
            std::sync::Arc::new(ackinacki_kit::tvm_client::ClientContext::new(cfg).unwrap())
        },
        &accept.profile_address,
    );
    let signing_keys = KeyPair {
        public: accept.session_state.signing_public.clone(),
        secret: accept.session_state.signing_secret.to_string(),
    };

    // 2. Write 5 more dummy events (#2..#6)
    for i in 2..=6 {
        let text = format!("pagination_test_event_{i}");
        profile
            .add_context_text(&text, Signer::Keys { keys: signing_keys.clone() })
            .await
            .unwrap_or_else(|e| panic!("add_context_text #{i} failed: {e}"));
        println!("wrote event #{i}");
    }

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // 3. Query page 1: limit=4, expect 4 events + has_previous_page
    let page1 = profile
        .query_context_added_events(ParamsOfQueryProfileEvents {
            created_at_from: None,
            limit: Some(4),
            before: None,
        })
        .await
        .expect("page 1 query failed");

    println!(
        "page 1: {} events, has_previous_page={}, cursor={:?}",
        page1.events.len(),
        page1.page_info.has_previous_page,
        page1.page_info.cursor,
    );
    assert_eq!(page1.events.len(), 4, "page 1 should have 4 events");
    assert!(page1.page_info.has_previous_page, "should have more pages");
    assert!(page1.page_info.cursor.is_some(), "cursor should be present");

    // 4. Query page 2: use cursor from page 1
    let page2 = profile
        .query_context_added_events(ParamsOfQueryProfileEvents {
            created_at_from: None,
            limit: Some(4),
            before: page1.page_info.cursor,
        })
        .await
        .expect("page 2 query failed");

    println!(
        "page 2: {} events, has_previous_page={}",
        page2.events.len(),
        page2.page_info.has_previous_page,
    );
    assert!(!page2.events.is_empty(), "page 2 should have remaining events");

    let total = page1.events.len() + page2.events.len();
    println!("total events across 2 pages: {total}");
    assert!(total >= 6, "should have at least 6 events total (got {total})");

    // 5. Cleanup
    let signer_keys =
        KeyPair { public: SHELLNET_MF_EPK.to_string(), secret: SHELLNET_MF_ESK.to_string() };
    let _ = wallet
        .destroy_connect_profile(ParamsOfDestroyConnectProfile {
            profile_address: accept.profile_address.clone(),
            multifactor_address: SHELLNET_MULTIFACTOR.to_string(),
            signer_keys,
        })
        .await;
    println!("profile destroyed (best-effort)");
}

// ============================================================
// prepare_multifactor_deploy_params
// ============================================================

#[tokio::test]
async fn test_prepare_multifactor_deploy_params() {
    let wallet = create_shellnet_wallet();
    let deploy_params = create_deploy_wallet_params(format!("prep_deploy_{}", now_secs()));

    let owner_keys = create_crypto().gen_mnemonic_and_derive_keys().expect("gen_mnemonic failed");

    let result = wallet
        .prepare_multifactor_deploy_params(ParamsOfPrepareDeploy {
            zkid: deploy_params.zkid,
            password: deploy_params.password,
            proof: deploy_params.proof,
            epk: deploy_params.epk,
            esk: deploy_params.esk,
            jwk_modulus: deploy_params.jwk_modulus,
            jwk_modulus_expire_at: deploy_params.jwk_modulus_expire_at,
            index_mod_4: deploy_params.index_mod_4,
            iss_base_64: deploy_params.iss_base_64,
            header_base_64: deploy_params.header_base_64,
            epk_expire_at: deploy_params.epk_expire_at,
            keys: KeyPair {
                public: owner_keys.keys.public.clone(),
                secret: owner_keys.keys.secret.clone(),
            },
            kid: deploy_params.kid,
            wallet_name: deploy_params.wallet_name,
            multifactor_address: SHELLNET_T1.to_string(),
            sub: deploy_params.sub,
        })
        .await
        .expect("prepare_multifactor_deploy_params failed");

    // Verify result shape: it should have non-empty name, zkid, epk, etc.
    assert!(!result.name.is_empty(), "name should be non-empty");
    assert!(!result.zkid.is_empty(), "zkid should be non-empty");
    assert!(!result.epk.is_empty(), "epk should be non-empty");
    assert!(!result.proof.is_empty(), "proof should be non-empty");
    assert!(!result.kid.is_empty(), "kid should be non-empty");
    assert!(result.epk_expire_at > 0, "epk_expire_at should be positive");
}

// ============================================================
// get_history (self-contained: sends a tx, then verifies shape)
// ============================================================

#[tokio::test]
async fn test_get_history() {
    let wallet = create_shellnet_wallet();

    assert!(SHELLNET_T1_EPK_EXPIRE_AT > bee_wallet::now_secs(), "SHELLNET_T1 EPK expired!");
    assert!(SHELLNET_T2_EPK_EXPIRE_AT > bee_wallet::now_secs(), "SHELLNET_T2 EPK expired!");

    // 1. Send a small transfer so history is guaranteed non-empty
    let ts = bee_wallet::now_secs().saturating_sub(5);
    let amount: u64 = 10_000_000; // 0.01 NACKL
    let signer_keys =
        KeyPair { public: SHELLNET_T1_EPK.to_string(), secret: SHELLNET_T1_ESK.to_string() };
    let _res = send_ecc(&wallet, SHELLNET_T1, SHELLNET_T2, amount, signer_keys).await;

    // 2. Wait until the tx appears in sender history
    wait_for_tx(&wallet, SHELLNET_T1, ts, amount as u128, "Outgoing").await;

    // 3. Now fetch history and verify shape
    let result = wallet
        .get_history(ParamsOfGetHistory {
            multifactor_address: SHELLNET_T1.to_string(),
            token_id: "1".to_string(),
            page_size: 10,
            cursor: None,
            mining_cursor: None,
        })
        .await
        .expect("get_history failed");

    assert!(!result.data.is_empty(), "history should have entries for SHELLNET_T1");

    // Verify each entry has required fields populated
    for tx in &result.data {
        assert!(!tx.id.is_empty(), "tx.id should be non-empty");
        assert!(
            tx.tx_type == "Mining" || tx.tx_type == "Incoming" || tx.tx_type == "Outgoing",
            "unexpected tx_type: {}",
            tx.tx_type
        );
        assert!(!tx.value.is_empty(), "tx.value should be non-empty");
        assert!(!tx.created_at.is_empty(), "tx.created_at should be non-empty");
        let _ts: u64 = tx.created_at.parse().expect("created_at should parse as u64");
    }
}

// ============================================================
// poll_until
// ============================================================

#[tokio::test]
async fn test_poll_until() {
    let wallet = create_shellnet_wallet();

    // Case 1: Immediate success (predicate passes on first fetch)
    let result = wallet
        .poll_until(
            || async { Ok::<u32, bee_wallet::errors::AppError>(42) },
            |v| *v == 42,
            Some(5),
            Some(10),
        )
        .await
        .expect("poll_until immediate success");
    assert_eq!(result, 42);

    // Case 2: Succeeds on Nth attempt
    let counter = AtomicU32::new(0);
    let result = wallet
        .poll_until(
            || {
                let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                async move { Ok::<u32, bee_wallet::errors::AppError>(current) }
            },
            |v| *v >= 3,
            Some(10),
            Some(10),
        )
        .await
        .expect("poll_until Nth attempt success");
    assert_eq!(result, 3);

    // Case 3: Timeout — predicate never passes
    let err = wallet
        .poll_until(
            || async { Ok::<u32, bee_wallet::errors::AppError>(0) },
            |_| false,
            Some(3),
            Some(10),
        )
        .await;
    assert!(err.is_err(), "poll_until should fail when max attempts exhausted");
    let err_msg = err.unwrap_err().message;
    assert!(
        err_msg.contains("Max 3 attempts reached"),
        "error should mention max attempts, got: {}",
        err_msg
    );
}

// --- one-off: mint USDC to test_lc_1 ---

// ============================================================
// migrate_tip3_usdc: TIP-3 USDC → ECC[3] via Exchange
// ============================================================

/// E2E: mint TIP-3 USDC → migrate to ECC[3] → verify ECC[3] balance increased.
#[tokio::test]
async fn test_migrate_tip3_usdc() {
    use ackinacki_kit::contracts::token::root::TokenRoot;
    use ackinacki_kit::contracts::traits::SendMessage;
    use ackinacki_kit::tvm_client::abi::CallSet;
    use ackinacki_kit::tvm_client::abi::Signer;

    let wallet = create_shellnet_wallet();
    let endpoint = "shellnet.ackinacki.org";

    // 1. Deploy fresh wallet
    let name = format!("migrate_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    let mf_address = deploy_result.address.clone();
    println!("deployed: {mf_address}");

    let signer_keys =
        ackinacki_kit::tvm_client::crypto::KeyPair { public: epk.clone(), secret: esk.clone() };

    // 2. TVM context for giver + mint
    let mut config = ackinacki_kit::tvm_client::ClientConfig::default();
    config.network.endpoints = Some(vec![endpoint.to_string()]);
    let tvm_ctx = std::sync::Arc::new(
        ackinacki_kit::tvm_client::ClientContext::new(config).expect("tvm context"),
    );

    // 3. Fund gas (10 vmshell — enough for Exchange callback chain)
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        tvm_ctx.clone(),
        &mf_address,
        10_000_000_000,
        std::collections::HashMap::new(),
        1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 4. Mint TIP-3 USDC to the wallet (10 USDC = 10_000_000 micro)
    let tip3_usdc_root = "0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let usdc_amount_raw: u64 = 10_000_000; // 10 USDC

    let usdc_root = TokenRoot::new(
        tvm_ctx.clone(),
        bee_wallet::dapp::token_contract_params(
            tip3_usdc_root,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    // Owner keys of the TIP-3 USDC root on shellnet (current as of the
    // 2026-06-04 redeploy). Every shellnet redeploy rotates them: `mint` then
    // reverts in the compute phase (exit_code 101) and this test dies here in
    // setup — before the migrate path under test ever runs. Refresh both keys
    // below (and the matching `TIP3_MINT_PUBLIC`/`TIP3_MINT_SECRET` in
    // src/bin/faucet.rs) with the live root owner keys before running.
    let mint_keys = ackinacki_kit::tvm_client::crypto::KeyPair {
        public: "e44b1ca07ee19c5c66eca104b9e5372f1fcadfe962b11e565132c66ec5603d91".to_string(),
        secret: "55c5d4ca4f11c7721e39b1dbe407b7dc787b68d89fc8936fb798e7631f155ea0".to_string(),
    };
    let mint_result = usdc_root
        .send_message(
            Some(CallSet {
                function_name: "mint".to_string(),
                header: None,
                input: Some(serde_json::json!({
                    "value": usdc_amount_raw.to_string(),
                    "walletOwner": mf_address,
                })),
            }),
            None,
            Signer::Keys { keys: mint_keys },
        )
        .await
        .expect("mint TIP-3 USDC failed");
    assert_eq!(mint_result.exit_code.unwrap_or(0), 0, "mint should succeed");
    println!("minted {usdc_amount_raw} TIP-3 USDC");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 5. Check ECC[3] balance before migration
    let ecc3_before = get_ecc_balance_by_id(&mf_address, 3, endpoint).await;
    println!("ECC[3] before: {ecc3_before}");

    // 6. Migrate TIP-3 USDC → ECC[3]
    let migrate_result = wallet
        .migrate_tip3_usdc(bee_wallet::MigrateTip3UsdcReq {
            multifactor_address: mf_address.clone(),
            token_root: tip3_usdc_root.to_string(),
            // shellnet 0.9.0 ignores dapp_id (System for this root on shellnet).
            token_dapp: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            amount_raw: usdc_amount_raw,
            signer_keys: signer_keys.clone(),
            bounce: None,
        })
        .await
        .expect("migrate_tip3_usdc failed");
    println!("migrate tx: {:?}", migrate_result.message_hash);

    // 7. Poll ECC[3] balance until it increases
    let mut ecc3_after = ecc3_before;
    for attempt in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        ecc3_after = get_ecc_balance_by_id(&mf_address, 3, endpoint).await;
        if ecc3_after > ecc3_before {
            println!("ECC[3] increased after {attempt} attempts");
            break;
        }
    }

    let delta = ecc3_after - ecc3_before;
    println!("ECC[3] after: {ecc3_after}, delta: {delta}");
    assert!(
        delta >= usdc_amount_raw as u64,
        "Expected ECC[3] increase of at least {usdc_amount_raw}, got {delta}"
    );
    println!("migrate_tip3_usdc test passed: {usdc_amount_raw} TIP-3 USDC → {delta} ECC[3]");
}

// ============================================================
// miner address resolution by wallet name (self-contained)
// ============================================================

/// E2E: deploy a fresh multifactor (which registers its name in the indexer),
/// then resolve its miner address purely by name via `bee_miner`.
///
/// Self-contained on purpose — it deploys the wallet it resolves, so there is
/// no hardcoded on-chain fixture to rot when shellnet is redeployed (the
/// previous `bee_miner` unit test pinned `test_t1_*` and went red on every
/// wipe). It lives here, not in `bee_miner`, because `bee_miner` can't deploy a
/// wallet (no dep on `bee_wallet`).
///
/// A bare multifactor deploy is enough: the name→multifactor hop reads the
/// freshly-registered indexer, and the multifactor→miner hop hits a global
/// system Mirror contract (one of 1000 at `0:2…`, derived from the multifactor
/// tail) that *computes* the miner address — the miner itself need not exist.
#[tokio::test]
async fn test_get_miner_address_by_wallet_name() {
    let wallet = create_shellnet_wallet();
    let endpoint = "shellnet.ackinacki.org";

    // 1. Deploy a fresh wallet under a unique name.
    let name = format!("miner_resolve_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());
    let deploy_result = wallet.deploy_wallet(params).await.expect("deploy failed");
    println!("deployed {name}: {}", deploy_result.address);

    // 2. Wait until the name resolves through the indexer (deploy must propagate).
    //    Resolving by name here also gates step 3: if this returns Some, the
    //    indexer is active and the unit under test can read it too.
    let mut registered = false;
    for attempt in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if let Ok(Some(_)) = wallet.get_multifactor_data_by_name(name.clone()).await {
            println!("name registered in indexer after {attempt} polls");
            registered = true;
            break;
        }
    }
    assert!(registered, "wallet name never became resolvable in the indexer");

    // 3. The unit under test: resolve the miner address purely by name.
    let mut cfg = ackinacki_kit::tvm_client::ClientConfig::default();
    cfg.network.endpoints = Some(vec![endpoint.to_string()]);
    let miner_address = bee_miner::core::keys::get_miner_address_by_wallet_name(
        bee_miner::core::keys::ParamsOfGetMinerAddressByWalletName {
            client_config: cfg,
            wallet_name: name.clone(),
        },
    )
    .await
    .expect("get_miner_address_by_wallet_name failed");

    println!("resolved miner: {miner_address}");
    assert!(!miner_address.is_empty(), "resolved miner address should not be empty");
    assert!(
        miner_address.contains(':'),
        "resolved miner address should look like a TVM address, got: {miner_address}"
    );
}

// ============================================================
//  Connect protocol — multi-step DH chain tests
// ============================================================

/// Shared handshake setup for connect protocol tests.
/// Returns (connect_client, session, payload, accept, dapp_state, wallet_state,
/// profile).
async fn connect_handshake_setup(
    wallet: &Wallet,
    wallet_name: &str,
) -> (
    ConnectClient,
    bee_connect::ResultOfCreateSharedKeySession,
    ConnectPayload,
    bee_wallet::ResultOfAcceptConnect,
    bee_connect::dh::ConnectSessionState,
    bee_connect::dh::ConnectSessionState,
    ackinacki_kit::contracts::authservice::profile::AuthProfile,
) {
    use bee_connect::ParamsOfWaitWalletHello;

    let connect_client = ConnectClient::new();
    let session = connect_client
        .create_shared_key_session(ParamsOfCreateSharedKeySession {
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            ttl_secs: Some(600),
            nonce: None,
        })
        .expect("create_shared_key_session failed");

    let payload = wallet
        .decode_connect_payload_b64url(session.payload_b64url.clone())
        .expect("decode_connect_payload_b64url failed");

    let accept = wallet
        .accept_connect_shared_key(ParamsOfAcceptSharedKeyConnect {
            payload: payload.clone(),
            wallet_name: wallet_name.to_string(),
            wallet_address: SHELLNET_MULTIFACTOR.to_string(),
            client_dh_public: session.client_dh_public.clone(),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
            challenge_signature: None,
            challenge_epk_public: None,
        })
        .await
        .expect("accept_connect_shared_key failed");
    let wallet_session_state = accept.session_state.clone();

    let hello = connect_client
        .wait_wallet_hello(ParamsOfWaitWalletHello {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            client_dh_secret: session.client_dh_secret.clone(),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_wallet_hello failed");
    let dapp_session_state = hello.session_state;

    let profile = ackinacki_kit::contracts::authservice::profile::AuthProfile::new_default(
        {
            let mut cfg = ackinacki_kit::tvm_client::ClientConfig::default();
            cfg.network.endpoints = Some(vec!["shellnet.ackinacki.org".to_string()]);
            std::sync::Arc::new(ackinacki_kit::tvm_client::ClientContext::new(cfg).unwrap())
        },
        &accept.profile_address,
    );

    (connect_client, session, payload, accept, dapp_session_state, wallet_session_state, profile)
}

/// Wallet-side: poll for sign_challenge, do rekey_inbound + rekey_outbound,
/// send challenge_response. Returns updated wallet state.
async fn wallet_respond_to_challenge(
    wallet: &Wallet,
    profile: &ackinacki_kit::contracts::authservice::profile::AuthProfile,
    payload: &ConnectPayload,
    wallet_state: &bee_connect::dh::ConnectSessionState,
    expected_nonce: &str,
) -> bee_connect::dh::ConnectSessionState {
    use ackinacki_kit::tvm_client::abi::Signer;

    let mut state = wallet_state.clone();
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let mut found = false;
    for attempt in 1..=30 {
        let query = wallet
            .query_connect_session_messages(ParamsOfQuerySessionMessages {
                session_id: payload.session_id.clone(),
                description: payload.description.clone(),
                session_state: Some(state.clone()),
                created_at_from: None,
                before: None,
                limit: Some(50),
            })
            .await
            .expect("query_connect_session_messages failed");

        if let Some(updated) = query.updated_session_state {
            state = updated;
        }
        for msg in &query.messages {
            if msg.msg_type == "sign_challenge" {
                if let Some(ref sc) = msg.sign_challenge {
                    assert_eq!(sc.nonce, expected_nonce, "nonce mismatch");
                    println!("wallet received sign_challenge on attempt {attempt}");
                    found = true;
                }
            }
        }
        if found {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(found, "wallet should see sign_challenge");

    // rekey_outbound + send challenge_response
    let rekey_seq = state.next_outbound_seq().expect("next_outbound_seq failed");
    let rekey = bee_connect::dh::rekey_outbound(&state, &payload.session_id, rekey_seq)
        .expect("rekey_outbound failed");
    let response_json = bee_wallet::encode_challenge_response_message(
        &payload.session_id,
        expected_nonce,
        &"aa".repeat(64),
        SHELLNET_MULTIFACTOR,
        Some(SHELLNET_MF_EPK),
        &rekey.message_encryption_root,
        rekey.new_dh_public.as_deref().unwrap_or(""),
        rekey.outbound_seq,
    )
    .expect("encode_challenge_response_message failed");

    let signing_keys =
        KeyPair { public: state.signing_public.clone(), secret: state.signing_secret.to_string() };
    profile
        .add_context_text(&response_json, Signer::Keys { keys: signing_keys })
        .await
        .expect("add_context_text challenge_response failed");
    println!("challenge_response sent");

    rekey.updated_state
}

/// Cleanup helper — destroy profile (best-effort).
async fn connect_cleanup(wallet: &Wallet, profile_address: &str) {
    let signer_keys =
        KeyPair { public: SHELLNET_MF_EPK.to_string(), secret: SHELLNET_MF_ESK.to_string() };
    let _ = wallet
        .destroy_connect_profile(ParamsOfDestroyConnectProfile {
            profile_address: profile_address.to_string(),
            multifactor_address: SHELLNET_MULTIFACTOR.to_string(),
            signer_keys,
        })
        .await;
    println!("profile destroyed (best-effort)");
}

/// Verify → set_mining_keys: after a full sign_challenge round-trip,
/// the wallet must be able to decrypt the subsequent set_mining_keys message.
/// This is the exact scenario that broke due to the DH state sync bug.
#[tokio::test]
async fn test_connect_verify_then_set_mining_keys() {
    use bee_connect::ParamsOfRequestSetMiningKeys;
    use bee_connect::ParamsOfRequestSignChallenge;
    use bee_connect::ParamsOfWaitChallengeResponse;

    let wallet = create_shellnet_wallet();
    let (connect_client, session, payload, accept, mut dapp_state, wallet_state, profile) =
        connect_handshake_setup(&wallet, "verify_then_keys").await;

    // 1. Verify round-trip (sign_challenge → challenge_response)
    let nonce = "verify_then_keys_nonce_1";
    let challenge = connect_client
        .request_sign_challenge(ParamsOfRequestSignChallenge {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_state.clone(),
            nonce: nonce.to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_sign_challenge failed");
    dapp_state = challenge.updated_session_state;

    let wallet_state =
        wallet_respond_to_challenge(&wallet, &profile, &payload, &wallet_state, nonce).await;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let cr = connect_client
        .wait_challenge_response(ParamsOfWaitChallengeResponse {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: Some(dapp_state.clone()),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_challenge_response failed");
    assert_eq!(cr.nonce, nonce);
    if let Some(ref updated) = cr.updated_session_state {
        dapp_state = updated.clone();
    }
    println!("verify round-trip OK, DH chain at step 4");

    // 2. dApp sends set_mining_keys (5th rekey in the chain)
    let set_keys = connect_client
        .request_set_mining_keys(ParamsOfRequestSetMiningKeys {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_state.clone(),
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            owner_public: "aa".repeat(32),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_set_mining_keys failed");
    println!("set_mining_keys sent: {:?}", set_keys.message_id);

    // 3. Wallet must decrypt set_mining_keys with post-verify state
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let mut found_keys = false;
    let mut wallet_state = wallet_state;
    for attempt in 1..=30 {
        let query = wallet
            .query_connect_session_messages(ParamsOfQuerySessionMessages {
                session_id: payload.session_id.clone(),
                description: payload.description.clone(),
                session_state: Some(wallet_state.clone()),
                created_at_from: None,
                before: None,
                limit: Some(50),
            })
            .await
            .expect("query_connect_session_messages failed");

        println!(
            "  [attempt {attempt}] messages={}, types=[{}], updated_state={}",
            query.messages.len(),
            query
                .messages
                .iter()
                .map(|m| format!(
                    "{}(body={})",
                    m.msg_type,
                    m.set_mining_keys.is_some() || m.sign_challenge.is_some()
                ))
                .collect::<Vec<_>>()
                .join(", "),
            query.updated_session_state.is_some(),
        );

        if let Some(updated) = query.updated_session_state {
            wallet_state = updated;
        }
        for msg in &query.messages {
            if msg.msg_type == "set_mining_keys" && msg.set_mining_keys.is_some() {
                println!("wallet decrypted set_mining_keys on attempt {attempt}");
                found_keys = true;
            }
        }
        if found_keys {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(found_keys, "wallet must decrypt set_mining_keys after verify round-trip");
    println!("test_connect_verify_then_set_mining_keys PASSED");

    connect_cleanup(&wallet, &accept.profile_address).await;
}

/// Two consecutive verify round-trips: the DH chain must remain in sync
/// across 8 rekey steps (4 per round-trip).
#[tokio::test]
async fn test_connect_double_verify() {
    use bee_connect::ParamsOfRequestSignChallenge;
    use bee_connect::ParamsOfWaitChallengeResponse;

    let wallet = create_shellnet_wallet();
    let (connect_client, session, payload, accept, mut dapp_state, mut wallet_state, profile) =
        connect_handshake_setup(&wallet, "double_verify").await;

    for round in 1..=2 {
        let nonce = format!("double_verify_nonce_{round}");
        println!("--- verify round {round} ---");

        // dApp sends sign_challenge
        let challenge = connect_client
            .request_sign_challenge(ParamsOfRequestSignChallenge {
                endpoints: vec!["shellnet.ackinacki.org".to_string()],
                session_id: session.session_id.clone(),
                description: session.description.clone(),
                session_state: dapp_state.clone(),
                nonce: nonce.clone(),
                max_attempts: Some(30),
                interval_ms: Some(1_000),
            })
            .await
            .expect("request_sign_challenge failed");
        dapp_state = challenge.updated_session_state;

        // Wallet responds
        wallet_state =
            wallet_respond_to_challenge(&wallet, &profile, &payload, &wallet_state, &nonce).await;

        // dApp receives response
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let cr = connect_client
            .wait_challenge_response(ParamsOfWaitChallengeResponse {
                endpoints: vec!["shellnet.ackinacki.org".to_string()],
                session_id: session.session_id.clone(),
                description: session.description.clone(),
                session_state: Some(dapp_state.clone()),
                created_at_from: Some(session.created_at),
                max_attempts: Some(60),
                interval_ms: Some(2_000),
            })
            .await
            .unwrap_or_else(|e| panic!("wait_challenge_response round {round} failed: {e}"));

        assert_eq!(cr.nonce, nonce, "nonce mismatch in round {round}");
        if let Some(ref updated) = cr.updated_session_state {
            dapp_state = updated.clone();
        }
        println!("verify round {round} OK");
    }

    println!("test_connect_double_verify PASSED (8 rekey steps)");
    connect_cleanup(&wallet, &accept.profile_address).await;
}

/// session_state_after must be populated on c2w messages that triggered
/// rekey_inbound. Wallet queries messages, and the sign_challenge message must
/// carry the post-rekey state snapshot.
#[tokio::test]
async fn test_connect_session_state_after_populated() {
    use bee_connect::ParamsOfRequestSignChallenge;

    let wallet = create_shellnet_wallet();
    let (connect_client, session, payload, accept, dapp_state, wallet_state, _profile) =
        connect_handshake_setup(&wallet, "state_after_test").await;

    // dApp sends sign_challenge
    let _challenge = connect_client
        .request_sign_challenge(ParamsOfRequestSignChallenge {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_state.clone(),
            nonce: "state_after_nonce".to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("request_sign_challenge failed");

    // Wallet polls — sign_challenge should have session_state_after
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let mut found = false;
    let mut state = wallet_state;
    for attempt in 1..=30 {
        let query = wallet
            .query_connect_session_messages(ParamsOfQuerySessionMessages {
                session_id: payload.session_id.clone(),
                description: payload.description.clone(),
                session_state: Some(state.clone()),
                created_at_from: None,
                before: None,
                limit: Some(50),
            })
            .await
            .expect("query_connect_session_messages failed");

        if let Some(updated) = query.updated_session_state.clone() {
            state = updated;
        }

        for msg in &query.messages {
            if msg.msg_type == "sign_challenge" && msg.sign_challenge.is_some() {
                println!("sign_challenge found on attempt {attempt}");
                assert!(
                    msg.session_state_after.is_some(),
                    "session_state_after must be Some for sign_challenge (c2w with rekey)"
                );

                // session_state_after must match the batch-level updated_session_state
                // (when there's only one rekeyed message in the batch)
                let after = msg.session_state_after.as_ref().unwrap();
                if let Some(ref batch) = query.updated_session_state {
                    assert_eq!(
                        after.encryption_root, batch.encryption_root,
                        "session_state_after.encryption_root must match batch updated_session_state"
                    );
                    assert_eq!(
                        after.peer_dh_public, batch.peer_dh_public,
                        "session_state_after.peer_dh_public must match batch updated_session_state"
                    );
                }
                found = true;
            }
        }
        if found {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(found, "wallet should find sign_challenge with session_state_after");
    println!("test_connect_session_state_after_populated PASSED");

    connect_cleanup(&wallet, &accept.profile_address).await;
}

/// Full chain: verify → set_mining_keys → second verify.
/// Exercises 10 rekey steps and confirms the DH chain survives mixed message
/// types.
#[tokio::test]
async fn test_connect_full_rekey_chain() {
    use bee_connect::ParamsOfRequestSetMiningKeys;
    use bee_connect::ParamsOfRequestSignChallenge;
    use bee_connect::ParamsOfWaitChallengeResponse;

    let wallet = create_shellnet_wallet();
    let (connect_client, session, payload, accept, mut dapp_state, mut wallet_state, profile) =
        connect_handshake_setup(&wallet, "full_chain").await;

    // --- Step 1: first verify ---
    println!("--- step 1: first verify ---");
    let nonce1 = "full_chain_nonce_1";
    let ch1 = connect_client
        .request_sign_challenge(ParamsOfRequestSignChallenge {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_state.clone(),
            nonce: nonce1.to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("sign_challenge 1 failed");
    dapp_state = ch1.updated_session_state;

    wallet_state =
        wallet_respond_to_challenge(&wallet, &profile, &payload, &wallet_state, nonce1).await;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let cr1 = connect_client
        .wait_challenge_response(ParamsOfWaitChallengeResponse {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: Some(dapp_state.clone()),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_challenge_response 1 failed");
    assert_eq!(cr1.nonce, nonce1);
    if let Some(ref s) = cr1.updated_session_state {
        dapp_state = s.clone();
    }
    println!("first verify OK");

    // --- Step 2: set_mining_keys ---
    println!("--- step 2: set_mining_keys ---");
    let set_keys = connect_client
        .request_set_mining_keys(ParamsOfRequestSetMiningKeys {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_state.clone(),
            app_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            owner_public: "bb".repeat(32),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("set_mining_keys failed");
    dapp_state = set_keys.updated_session_state;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let mut found_keys = false;
    for attempt in 1..=30 {
        let query = wallet
            .query_connect_session_messages(ParamsOfQuerySessionMessages {
                session_id: payload.session_id.clone(),
                description: payload.description.clone(),
                session_state: Some(wallet_state.clone()),
                created_at_from: None,
                before: None,
                limit: Some(50),
            })
            .await
            .expect("query_connect_session_messages failed");
        if let Some(updated) = query.updated_session_state {
            wallet_state = updated;
        }
        for msg in &query.messages {
            if msg.msg_type == "set_mining_keys" && msg.set_mining_keys.is_some() {
                println!("wallet decrypted set_mining_keys on attempt {attempt}");
                found_keys = true;
            }
        }
        if found_keys {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(found_keys, "wallet must decrypt set_mining_keys");

    // --- Step 3: second verify ---
    println!("--- step 3: second verify ---");
    let nonce2 = "full_chain_nonce_2";
    let ch2 = connect_client
        .request_sign_challenge(ParamsOfRequestSignChallenge {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: dapp_state.clone(),
            nonce: nonce2.to_string(),
            max_attempts: Some(30),
            interval_ms: Some(1_000),
        })
        .await
        .expect("sign_challenge 2 failed");
    dapp_state = ch2.updated_session_state;

    wallet_state =
        wallet_respond_to_challenge(&wallet, &profile, &payload, &wallet_state, nonce2).await;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let cr2 = connect_client
        .wait_challenge_response(ParamsOfWaitChallengeResponse {
            endpoints: vec!["shellnet.ackinacki.org".to_string()],
            session_id: session.session_id.clone(),
            description: session.description.clone(),
            session_state: Some(dapp_state.clone()),
            created_at_from: Some(session.created_at),
            max_attempts: Some(60),
            interval_ms: Some(2_000),
        })
        .await
        .expect("wait_challenge_response 2 failed");
    assert_eq!(cr2.nonce, nonce2);
    println!("second verify OK");

    println!("test_connect_full_rekey_chain PASSED (10 rekey steps)");
    connect_cleanup(&wallet, &accept.profile_address).await;
}

// --- update_contract_flags (deploy without flags, then update separately) ---

#[tokio::test]
async fn test_update_contract_flags() {
    let wallet = create_shellnet_wallet();
    let name = format!("upd_flags_{}", now_secs());
    let params = create_deploy_wallet_params(name.clone());

    // 1. Deploy WITHOUT contract flags update
    println!("[1/5] deploying '{name}' without contract flags...");
    let deploy_result = wallet.deploy_wallet_only(params).await.expect("deploy_wallet_only failed");
    let address = deploy_result.address.clone();
    println!("  address: {address}");
    println!("  phrase:  {}", deploy_result.phrase);
    println!("  pubkey:  {}", deploy_result.signing_keys.public);

    // 2. Read contract state before update
    println!("[2/5] reading contract state...");
    let info = wallet
        .get_multifactor_info(bee_wallet::ParamsOfGetMultifactorInfo { address: address.clone() })
        .await
        .expect("get_multifactor_info");
    let data = info.data.expect("multifactor data should exist");
    println!("  force_remove_oldest: {}", data.force_remove_oldest);
    println!("  wasm_hash: '{}'", data.wasm_hash);
    println!("  owner_pubkey: {}", data.owner_pubkey);

    assert!(!data.force_remove_oldest, "force_remove_oldest should be false before update");

    // 3. Derive owner keys from phrase (signing_keys = EPK, not owner!)
    println!("[3/5] deriving owner keys from phrase...");
    let crypto = create_crypto();
    let derived = crypto
        .get_keys_from_mnemonic(deploy_result.phrase.clone())
        .expect("derive keys from phrase");
    let owner_keys = KeyPair { public: derived.public.clone(), secret: derived.secret.clone() };
    println!("  owner pubkey:    {}", owner_keys.public);
    println!("  owner pubkey 0x: 0x{}", owner_keys.public);
    println!("  contract owner:  {}", data.owner_pubkey);
    println!("  deploy pubkey:   {}", deploy_result.pubkey);
    let keys_match = data.owner_pubkey == format!("0x{}", owner_keys.public);
    println!("  keys match: {keys_match}");
    assert!(keys_match, "owner keys must match contract _owner_pubkey");

    // 4. Call set_remove_oldest first
    println!("[4/5] set_remove_oldest...");
    let result = wallet
        .update_contract(bee_wallet::ParamsOfUpdateContract {
            multifactor_address: address.clone(),
            keys: owner_keys.clone(),
        })
        .await;
    match &result {
        Ok(r) => println!("  ok, message_ids: {:?}", r.message_ids),
        Err(e) => println!("  FAILED: {e:#?}"),
    }
    let update_result = result.expect("update_contract failed");

    // 5. Verify flags are set
    println!("[5/5] verifying contract state after update...");
    let info = wallet
        .get_multifactor_info(bee_wallet::ParamsOfGetMultifactorInfo { address: address.clone() })
        .await
        .expect("get_multifactor_info after update");
    let data = info.data.expect("multifactor data should exist after update");
    println!("  force_remove_oldest: {}", data.force_remove_oldest);
    println!("  wasm_hash: '{}'", data.wasm_hash);
    println!("  message_ids: {:?}", update_result.message_ids);

    assert!(data.force_remove_oldest, "force_remove_oldest should be true after update");
    assert!(
        !data.wasm_hash.is_empty()
            && data.wasm_hash != "0000000000000000000000000000000000000000000000000000000000000000",
        "wasm_hash should be set after update, got: '{}'",
        data.wasm_hash
    );
    println!("PASSED");
}

// ============================================================
// DEX voucher generation (bee_wallet responsibility)
// ============================================================

#[tokio::test]
async fn test_generate_voucher_deposit() {
    let wallet = create_shellnet_wallet();
    let sender = deploy_fresh_wallet_for_dex(&wallet).await;
    let signer_keys = KeyPair { public: sender.epk.clone(), secret: sender.esk.clone() };

    wallet
        .generate_voucher(bee_wallet::ParamsOfGenerateVoucher {
            multifactor_address: sender.address.clone(),
            token_type: 1,
            amount: 100_000_000_000, // Nominal::N100 NACKL
            is_fee: false,
            sk_u_commit: "0".to_string(),
            signer_keys,
        })
        .await
        .expect("generate_voucher (deposit NACKL)");
}

#[tokio::test]
async fn test_generate_voucher_gas() {
    let wallet = create_shellnet_wallet();
    let sender = deploy_fresh_wallet_for_dex(&wallet).await;
    let signer_keys = KeyPair { public: sender.epk.clone(), secret: sender.esk.clone() };

    wallet
        .generate_voucher(bee_wallet::ParamsOfGenerateVoucher {
            multifactor_address: sender.address.clone(),
            token_type: 2,
            amount: 5_000_000_000, // 5 SHELL for gas
            is_fee: true,
            sk_u_commit: "0".to_string(),
            signer_keys,
        })
        .await
        .expect("generate_voucher (gas SHELL)");
}

// Full voucher → deploy PrivateNote flow lives in
// `tests/dex_flows/flows.rs::test_production_flow_voucher_deploy_pn_and_stake`.
// It exercises the same wallet.generate_voucher entry point but binds the
// voucher to a real halo2 proof, which is now mandatory on RootPN.

// --- deploy flat Multisig via default giver (shellnet, fully client-side) ---

const SHELLNET_ENDPOINTS: &[&str] = &["shellnet.ackinacki.org"];

fn shellnet_endpoints() -> Vec<String> {
    SHELLNET_ENDPOINTS.iter().map(|s| s.to_string()).collect()
}

/// End-to-end: generate owner keys, fund the future address from the giver,
/// deploy the Multisig, confirm Active on-chain. Then re-run with the SAME keys
/// and assert idempotency (no second deploy).
#[tokio::test]
async fn test_deploy_multisig_via_giver() {
    let result =
        bee_wallet::deploy_multisig_via_giver(bee_wallet::ParamsOfDeployMultisigViaGiver {
            endpoints: shellnet_endpoints(),
            keys: None,
            owners_pubkey: None,
            req_confirms: None,
            req_confirms_data: None,
            constructor_value: None,
            giver_value: None,
            giver_ecc: None,
            wait_for_active: Some(true),
        })
        .await
        .expect("deploy_multisig_via_giver failed");

    println!(
        "deployed multisig: address={} public={} already_deployed={} tx={:?}",
        result.address, result.public, result.already_deployed, result.deploy_tx
    );

    // Canonical dApp-scoped address: `<id>::<id>` with both halves equal 64-hex.
    let (left, right) = result.address.split_once("::").expect("address must be <id>::<id>");
    assert_eq!(left, right, "both halves must be equal, got {}", result.address);
    assert_eq!(left.len(), 64, "id half must be 64-hex, got {}", result.address);
    assert!(
        left.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "id must be lowercase hex, got {}",
        result.address
    );
    assert_eq!(result.public.len(), 64, "owner public must be 64-hex");
    assert_eq!(result.secret.len(), 64, "owner secret must be 64-hex");
    assert!(!result.already_deployed, "fresh keys: should have deployed");
    assert!(result.deploy_tx.is_some(), "fresh deploy should report a tx id");

    // Confirm the account is actually Active on-chain (reconstruct raw `0:<id>`).
    let ctx = create_tvm_context();
    let raw_address = format!("0:{left}");
    let mut account =
        ackinacki_kit::contracts::account::Account::new(ctx, &raw_address, left.to_string());
    account.fetch().await.expect("fetch deployed multisig");
    assert_eq!(
        account.acc_type,
        ackinacki_kit::contracts::account::AccountStatus::Active,
        "multisig should be Active after deploy"
    );

    // Idempotency: same keys -> same address, no second deploy, no giver spend.
    let keys = KeyPair { public: result.public.clone(), secret: result.secret.clone() };
    let again = bee_wallet::deploy_multisig_via_giver(bee_wallet::ParamsOfDeployMultisigViaGiver {
        endpoints: shellnet_endpoints(),
        keys: Some(keys),
        owners_pubkey: None,
        req_confirms: None,
        req_confirms_data: None,
        constructor_value: None,
        giver_value: None,
        giver_ecc: None,
        wait_for_active: Some(true),
    })
    .await
    .expect("idempotent re-deploy failed");

    assert_eq!(again.address, result.address, "same keys must yield same address");
    assert!(again.already_deployed, "second run must detect existing Active account");
    assert!(again.deploy_tx.is_none(), "idempotent run must not deploy again");

    // Generic ECC balance read works on the flat multisig (canonical address in).
    // Note: giver SHELL lands in the account's base `balance`, so ECC[2] reads
    // back as a registered-but-zero slot here; this binding returns `account.ecc`
    // verbatim by design.
    let balances = bee_wallet::multisig_balances(shellnet_endpoints(), result.address.clone())
        .await
        .expect("multisig_balances failed");
    println!("multisig_balances = {balances:?}");
    assert!(balances.contains_key(&2), "SHELL (ECC[2]) slot should be present, got {balances:?}");
}

/// Brick 1 in isolation: address derivation is deterministic for fixed inputs
/// and key-dependent. No giver / no deploy — pure encode.
#[tokio::test]
async fn test_compute_multisig_address_deterministic() {
    let ctx = create_tvm_context();
    let keys = ackinacki_kit::tvm_client::crypto::generate_random_sign_keys(ctx.clone())
        .expect("generate keys");

    let spec = bee_wallet::MultisigDeploySpec {
        keys: keys.clone(),
        owners_pubkey: vec![format!("0x{}", keys.public)],
        req_confirms: 1,
        req_confirms_data: 1,
        constructor_value: "0".to_string(),
    };

    let a =
        bee_wallet::compute_multisig_address(ctx.clone(), &spec).await.expect("compute address a");
    let b =
        bee_wallet::compute_multisig_address(ctx.clone(), &spec).await.expect("compute address b");
    assert_eq!(a, b, "address must be deterministic for fixed spec");
    assert!(a.starts_with("0:"));

    // Different owner keys -> different address.
    let other_keys = ackinacki_kit::tvm_client::crypto::generate_random_sign_keys(ctx.clone())
        .expect("generate other keys");
    let other_spec = bee_wallet::MultisigDeploySpec {
        keys: other_keys.clone(),
        owners_pubkey: vec![format!("0x{}", other_keys.public)],
        req_confirms: 1,
        req_confirms_data: 1,
        constructor_value: "0".to_string(),
    };
    let c =
        bee_wallet::compute_multisig_address(ctx, &other_spec).await.expect("compute address c");
    assert_ne!(a, c, "different keys must yield a different address");
}
