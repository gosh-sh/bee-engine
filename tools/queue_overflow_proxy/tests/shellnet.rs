use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use ackinacki_kit::contracts::giver::GiverV3;
use ackinacki_kit::contracts::giver::ParamsOfSendCurrencyWithFlag;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;
use queue_overflow_proxy::spawn;
use queue_overflow_proxy::ProxyConfig;

const FAIL_FIRST: usize = 3;

#[tokio::test]
#[ignore = "requires live shellnet and sends one giver message"]
async fn retries_the_same_prepared_message_through_real_tvm_transport() {
    let proxy = spawn(ProxyConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        upstream: "https://shellnet.ackinacki.org".to_owned(),
        fail_first: FAIL_FIRST,
    })
    .await
    .expect("start queue-overflow proxy");
    let observations = proxy.state();

    let mut config = ClientConfig::default();
    config.network.endpoints = Some(vec![proxy.endpoint().to_owned()]);
    config.network.max_reconnect_timeout = 0;
    let client = Arc::new(ClientContext::new(config).expect("create tvm client"));
    let giver = GiverV3::new_default(bee_infra::message_delivery::contract_context(client));
    let destination = unique_shellnet_destination();

    giver
        .send_currency_with_flag(
            ParamsOfSendCurrencyWithFlag {
                dest: destination,
                value: 1_000_000_000,
                ecc: HashMap::new(),
                flag: 1,
            },
            Signer::None,
        )
        .await
        .expect("the prepared message should be accepted after queue-overflow retries");

    let attempts = observations.attempts();
    assert_eq!(attempts.len(), FAIL_FIRST + 1, "unexpected proxy attempt count: {attempts:#?}");
    let message_id = &attempts[0].message_id;
    let body_hash = &attempts[0].body_hash;
    assert!(attempts.iter().all(|attempt| &attempt.message_id == message_id));
    assert!(attempts.iter().all(|attempt| &attempt.body_hash == body_hash));
    assert!(attempts[..FAIL_FIRST].iter().all(|attempt| !attempt.forwarded));
    assert!(attempts[FAIL_FIRST].forwarded);

    for pair in attempts.windows(2) {
        assert!(
            pair[1].observed_at.duration_since(pair[0].observed_at) >= Duration::from_millis(900),
            "retry interval was shorter than one second: {attempts:#?}",
        );
    }

    proxy.shutdown().await.expect("stop queue-overflow proxy");
}

fn unique_shellnet_destination() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let seed = format!("queue-overflow-e2e-{}-{now}", std::process::id());
    format!("0:{}", blake3::hash(seed.as_bytes()).to_hex())
}
