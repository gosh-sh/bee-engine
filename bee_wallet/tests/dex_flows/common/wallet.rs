//! Multifactor-wallet helpers used by production-flow tests.

use crate::common::context::create_context;
use crate::common::context::ENDPOINT;
use crate::common::misc::now_unix;

pub fn create_wallet() -> bee_wallet::Wallet {
    bee_wallet::Wallet::new(bee_wallet::WalletConfig {
        endpoints: vec![ENDPOINT.to_string()],
        api_url: "https://app-backend.ackinacki.org/api".to_string(),
        app_id: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ..Default::default()
    })
    .expect("create Wallet")
}

pub fn deploy_wallet_params(name: String) -> bee_wallet::ParamsOfDeployMultifactor {
    bee_wallet::ParamsOfDeployMultifactor {
        epk: "6d26db3f0d23f66f358ca7d8f4e340ecc784f899002946b4eb04b1f7cb3325d6".to_string(),
        epk_expire_at: 1784029474,
        esk: "15910e12c0bc445cda49ad240a9533546a8c26b8a8d0313cd59533af1b463bc7".to_string(),
        header_base_64: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZmOGVlZDA0MjgyZjFkYmQ4OWY1YTc5Yjc4N2Q2N2JjODc2MjA1OTcifQ".to_string(),
        index_mod_4: 1,
        iss_base_64: "yJpc3MiOiJodHRwczovL29hdXRoLmdvc2guc2giLC".to_string(),
        jwk_modulus: "c5b6adf2b02c0731bcd01071786afc797f34ef21d61f3cb5d1ce8c82486427db1eaca9a0ce7f9f9687790a2cc80e87aaff3b1ccd2c4c5a89aafc2885e6a6ce1a0ef569a6608263bda6aec4b369114210139d28346f010ed15cd876bf932cf43d6c7682d97e6c12e940ce05b30c00009177a7692372f281c6ec2fa51f271b0d9e2a38d983d7436682b2b7b9892829448f1834042ddcf9d02eade650658dd41668138df8cf1f79ec03323e80e7eb2814e28918ced0c16cddd891379120152174d170f1acabe5cb937213ccf844371630062bc4a923e406f7d1a92bf4aa5f611cf5848fcc482978ac9d55d2239e8e5670deab82417d3a8c044e187e83bfd79b9fa5".to_string(),
        jwk_modulus_expire_at: now_unix() + 3600,
        kid: "ff8eed04282f1dbd89f5a79b787d67bc87620597".to_string(),
        password: "Hello!23".to_string(),
        proof: "355528cf17afdde0a63f28050ad475407b6b515e7ba4cd171b77a6f0449874107e7f584f650117d7dbc4440cd62c5922f5f67a045b6364f107665e5d987bf12ceb191f246463920decbf50cf43567de0a885c53771440764cabd578f84c3581bcafd999764284c4f49b9b5ebc2f4508a931b62984970af006000b86c3effc08a".to_string(),
        sub: "272114864".to_string(),
        wallet_name: name,
        zkid: "11122679641859749640320083403412561847128433970247905841202114460910422214869".to_string(),
    }
}

/// Deploy a fresh multifactor wallet funded for DEX operations.
pub async fn deploy_dex_wallet() -> (String, ackinacki_kit::tvm_client::crypto::KeyPair) {
    use std::sync::atomic::AtomicU32;
    static CTR: AtomicU32 = AtomicU32::new(0);

    let wallet = create_wallet();
    let idx = CTR.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let name = format!("dex_prod_{}_{}", now_unix(), idx);
    let params = deploy_wallet_params(name);
    let epk = params.epk.clone();
    let esk = params.esk.clone();
    let result = wallet.deploy_wallet(params).await.expect("deploy_wallet");
    let address = result.address;

    let ctx = create_context();
    let ecc = std::collections::HashMap::from([
        // 1500 NACKL — must cover at least one Nominal::N1000 deposit
        // voucher (1000G, used by user_flow PMP_DEPOSIT) plus headroom for
        // production_flow's Nominal::N100 (100G) and any per-message fees.
        (1u32, 1_500_000_000_000u64),
        (2u32, 200_000_000_000u64), /* 200 SHELL — covers Nominal::N100 SHELL
                                     * voucher (100G) + per-message fees. */
    ]);
    ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver(
        ctx,
        &address,
        50_000_000_000,
        ecc,
        1,
    )
    .await
    .expect("giver fund DEX wallet");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let keys = ackinacki_kit::tvm_client::crypto::KeyPair { public: epk, secret: esk };
    (address, keys)
}
