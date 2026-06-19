//! Wallet-coupled multi-step user flows: a real multifactor wallet drives
//! the voucher cycle end-to-end, halo2 proves against the wallet-emitted
//! event, and the DEX façade consumes the proof.
//!
//! - production flow: voucher → deploy PN → SHELL gas voucher.
//! - user flow: voucher → deploy PN → browse oracle events → deploy PMP.

use std::collections::HashMap;

use ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver;
use ackinacki_kit::contracts::giver::v3::top_up_native_with_giver_if_below;
use ackinacki_kit::tvm_client::abi::Signer;
use dodex_contracts::dex::oracle::Oracle;
use dodex_contracts::dex::oracle_event_list::OracleEventList;
use dodex_contracts::dex::oracle_event_list::ParamsOfAddEvent;
use dodex_contracts::dex::pmp::ParamsOfSubmitSetTimings;
use dodex_contracts::dex::pmp::Pmp;
use dodex_contracts::dex::private_note::ParamsOfDeployPmp;
use dodex_contracts::dex::private_note::PrivateNote;
use dodex_contracts::dex::root_oracle::ParamsOfDeployOracle;
use dodex_contracts::dex::root_oracle::RootOracle;
use dodex_contracts::dex::root_pn::ParamsOfDeployPrivateNote;
use dodex_contracts::dex::root_pn::ParamsOfGetPmpAddress;
use dodex_contracts::dex::root_pn::ParamsOfGetPrivateNoteAddress;
use dodex_contracts::dex::root_pn::ParamsOfSendEccShellToPrivateNote;
use dodex_contracts::dex::root_pn::RootPn;
use dodex_sdk::dex_contract_params;
use dodex_sdk::proof;

use crate::common::context::create_context;
use crate::common::context::create_dex;
use crate::common::context::CURRENCY_ID_NACKL;
use crate::common::context::CURRENCY_ID_SHELL;
use crate::common::context::DEPLOYER_SEED_AMOUNT;
use crate::common::context::ECC_SHELL_DEPOSIT;
use crate::common::context::PMP_DEPOSIT;
use crate::common::context::STAKE_PERIOD_LONG;
use crate::common::context::TOKEN_TYPE_NACKL;
use crate::common::keys::gen_keys;
use crate::common::misc::now_unix;
use crate::common::misc::pn_nackl;
use crate::common::misc::wait_active;
use crate::common::pn::ensure_root_pn_funded;
use crate::common::voucher::mint_voucher_via_multifactor;
use crate::common::wallet::create_wallet;
use crate::common::wallet::deploy_dex_wallet;

/// Production flow end-to-end: multifactor wallet emits a voucher,
/// halo2 proves *against that exact event* (no Giver shortcut anywhere in
/// the halo2 pipeline), `RootPN.deployPrivateNote` consumes the proof,
/// then a SHELL gas voucher follows the same path through the wallet
/// to fund the new PN.
#[tokio::test]
async fn test_production_flow_voucher_deploy_pn_and_stake() {
    let wallet = create_wallet();
    let dex = create_dex();
    let context = create_context();
    let root_pn = RootPn::new(context.clone(), dex_contract_params(RootPn::DEFAULT_ADDRESS));

    // 1. Deploy funded multifactor wallet.
    let (mf_address, mf_keys) = deploy_dex_wallet().await;
    println!("wallet: {mf_address}");

    // 2. Multifactor → RootPN.generateVoucher → halo2 prove for the deposit voucher
    //    (100 NACKL).
    //
    //    NOTE: deposit + gas voucher proofs MUST be minted sequentially.
    //    Each commits to `final_layer_historical_hash_root` at proof
    //    generation time; the contract validates it against the *current*
    //    root at submit. Parallel mint via `tokio::join!` worked CPU-wise
    //    but the second proof's root drifted during the first one's
    //    submit + wait_active (~10-15 sec, 2-3 blocks) → contract rejected
    //    the second proof with `ERR_INVALID_ZKPROOF (137)`.
    let zk = mint_voucher_via_multifactor(
        &wallet,
        &mf_address,
        &mf_keys,
        context.clone(),
        root_pn.clone(),
        CURRENCY_ID_NACKL,
        proof::Nominal::N100.raw_value(proof::TokenType::Nackl),
        false,
    )
    .await;
    println!("deposit voucher proven");

    // 3. Deploy PN against the wallet-bound proof.
    let dih_dec = proof::hex_u256_to_dec(&zk.deposit_identifier_hash_hex);
    let epk_dec = proof::pubkey_to_dec(&mf_keys.public);
    dex.deploy_private_note(
        ParamsOfDeployPrivateNote {
            zkproof: zk.proof,
            deposit_identifier_hash: dih_dec.clone(),
            final_layer_historical_hash_root: proof::hex_u256_to_dec(
                &zk.final_layer_historical_hash_root_hex,
            ),
            voucher_nominal_fr: proof::hex_u256_to_dec(&zk.voucher_nominal_fr_hex),
            token_type_fr: proof::hex_u256_to_dec(&zk.token_type_fr_hex),
            ephemeral_pubkey: epk_dec,
            value: zk.voucher_value,
            token_type: zk.voucher_token_type,
            layer_number: zk.layer_number,
        },
        Signer::Keys { keys: mf_keys.clone() },
    )
    .await
    .expect("deploy_pn");

    let pn_address = dex
        .get_private_note_address(ParamsOfGetPrivateNoteAddress {
            deposit_identifier_hash: dih_dec.clone(),
        })
        .await
        .expect("pn_address");
    println!("PN: {pn_address}");

    let pn = PrivateNote::new(context.clone(), dex_contract_params(&pn_address));
    wait_active(&pn, "PN").await;

    // 4. SHELL gas voucher: same path again, multifactor-emitted + wallet-bound
    //    halo2 proof (must be minted *now*, not earlier — see note in step 2).
    let ecc_zk = mint_voucher_via_multifactor(
        &wallet,
        &mf_address,
        &mf_keys,
        context.clone(),
        root_pn.clone(),
        CURRENCY_ID_SHELL,
        ECC_SHELL_DEPOSIT,
        true,
    )
    .await;
    println!("gas voucher proven");

    dex.send_ecc_shell(
        ParamsOfSendEccShellToPrivateNote {
            proof: ecc_zk.proof,
            nullifier_hash: proof::hex_u256_to_dec(&ecc_zk.deposit_identifier_hash_hex),
            deposit_identifier_hash: dih_dec,
            final_layer_historical_hash_root: proof::hex_u256_to_dec(
                &ecc_zk.final_layer_historical_hash_root_hex,
            ),
            voucher_nominal_fr: proof::hex_u256_to_dec(&ecc_zk.voucher_nominal_fr_hex),
            token_type_fr: proof::hex_u256_to_dec(&ecc_zk.token_type_fr_hex),
            value: ecc_zk.voucher_value,
            layer_number: ecc_zk.layer_number,
            recipient_ephemeral_pubkey: proof::pubkey_to_dec(&mf_keys.public),
        },
        Signer::Keys { keys: mf_keys.clone() },
    )
    .await
    .expect("send_ecc_shell");
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
    println!("PN funded");

    // 5. Verify deposit landed.
    let details = dex.get_private_note_details(&pn_address).await.expect("details");
    let nackl = details.balance.get("1").copied().unwrap_or_default();
    assert_eq!(nackl, 100_000_000_000u128);
    assert!(details.busy_address.is_none());
    println!("balance: {} NACKL — production flow complete", nackl);
}

/// Full user flow through the DEX façade: a real multifactor wallet
/// drives the voucher cycle (PN deploy + SHELL gas), then the user
/// browses oracle events and deploys their own PMP. No Giver-driven
/// voucher mint anywhere — only the production multifactor → halo2 path.
#[tokio::test]
async fn test_user_flow_deploy_pn_then_pmp_via_dex() {
    let wallet = create_wallet();
    let context = create_context();
    let dex = create_dex();
    let root_pn = RootPn::new(context.clone(), dex_contract_params(RootPn::DEFAULT_ADDRESS));
    ensure_root_pn_funded(&context).await;

    // --- Step 0: Deploy multifactor wallet (the user's signer for everything
    //     that goes through the DEX). All voucher mints below come from this
    //     wallet, mirroring how an end user actually drives the flow. ---
    let (mf_address, mf_keys) = deploy_dex_wallet().await;
    eprintln!("multifactor: {mf_address}");

    // --- Step 1: User mints a deposit voucher and deploys their PN against
    //     the wallet-bound halo2 proof. ---
    let zk = mint_voucher_via_multifactor(
        &wallet,
        &mf_address,
        &mf_keys,
        context.clone(),
        root_pn.clone(),
        CURRENCY_ID_NACKL,
        PMP_DEPOSIT,
        false,
    )
    .await;
    let dih_dec = proof::hex_u256_to_dec(&zk.deposit_identifier_hash_hex);
    let epk_dec = proof::pubkey_to_dec(&mf_keys.public);
    dex.deploy_private_note(
        ParamsOfDeployPrivateNote {
            zkproof: zk.proof,
            deposit_identifier_hash: dih_dec.clone(),
            final_layer_historical_hash_root: proof::hex_u256_to_dec(
                &zk.final_layer_historical_hash_root_hex,
            ),
            voucher_nominal_fr: proof::hex_u256_to_dec(&zk.voucher_nominal_fr_hex),
            token_type_fr: proof::hex_u256_to_dec(&zk.token_type_fr_hex),
            ephemeral_pubkey: epk_dec,
            value: zk.voucher_value,
            token_type: zk.voucher_token_type,
            layer_number: zk.layer_number,
        },
        Signer::Keys { keys: mf_keys.clone() },
    )
    .await
    .expect("deploy_pn");
    let pn_address = dex
        .get_private_note_address(ParamsOfGetPrivateNoteAddress {
            deposit_identifier_hash: dih_dec.clone(),
        })
        .await
        .expect("pn_address");
    let pn = PrivateNote::new(context.clone(), dex_contract_params(&pn_address));
    wait_active(&pn, "PN").await;

    let details = dex.get_private_note_details(&pn_address).await.expect("pn details");
    assert_eq!(pn_nackl(&details), PMP_DEPOSIT as u128);
    assert!(details.busy_address.is_none());
    eprintln!("step 1: PN deployed at {pn_address} with {} NACKL", pn_nackl(&details));

    // --- Step 2: Deploy two oracles with different fees ---
    let root_oracle =
        RootOracle::new(context.clone(), dex_contract_params(RootOracle::DEFAULT_ADDRESS));
    wait_active(&root_oracle, "RootOracle").await;
    top_up_native_with_giver_if_below(
        context.clone(),
        &root_oracle,
        120_000_000_000,
        50_000_000_000,
        "RootOracle",
    )
    .await
    .expect("top up RootOracle native gas (deploy-then-PMP flow)");

    // Oracle A: fee = 100
    let oracle_a_keys = gen_keys(context.clone());
    let run_id = now_unix();
    let oracle_a_name = format!("OracleA{run_id:x}");
    dex.deploy_oracle(
        ParamsOfDeployOracle {
            oracle_pubkey: proof::pubkey_to_dec(&oracle_a_keys.public),
            oracle_name: oracle_a_name.clone(),
        },
        Signer::Keys { keys: gen_keys(context.clone()) },
    )
    .await
    .expect("deploy oracle A");
    let oracle_a_addr = dex.get_oracle_address(oracle_a_name.clone()).await.expect("oracle A addr");
    let oracle_a = Oracle::new(context.clone(), dex_contract_params(&oracle_a_addr));
    wait_active(&oracle_a, "Oracle A").await;
    let el_a_addr = dex
        .get_event_list_address(
            &oracle_a_addr,
            dodex_contracts::dex::oracle::ParamsOfGetEventListAddress { index: 0 },
        )
        .await
        .expect("el A addr");
    let el_a = OracleEventList::new(context.clone(), dex_contract_params(&el_a_addr));
    wait_active(&el_a, "EventList A").await;

    let mut outcomes = HashMap::new();
    outcomes.insert(1u32, "Yes".to_string());
    outcomes.insert(2u32, "No".to_string());

    dex.add_event(
        &el_a_addr,
        ParamsOfAddEvent {
            event_name: format!("Event{run_id:x}"),
            oracle_fee: 150, // fee = 150 Shell
            deadline: 2_000_000_000,
            describe: "Test event".to_string(),
            outcome_names: outcomes.clone(),
            trust_addr: None,
        },
        Signer::Keys { keys: oracle_a_keys.clone() },
    )
    .await
    .expect("add event A");

    // --- Step 3: Browse events, read oracle_fee ---
    let mut event_id = String::new();
    let mut oracle_fee: u128 = 0;
    for _ in 0..15 {
        let events = dex.get_parsed_events(&el_a_addr).await.expect("events");
        if let Some(evt) = events.first() {
            event_id = evt.event_id.clone();
            oracle_fee = evt.oracle_fee;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(!event_id.is_empty());
    assert_eq!(oracle_fee, 150);
    eprintln!("step 3: found event {event_id} with oracle_fee={oracle_fee}");

    // --- Step 4: Fund PN with gas ---
    // oracle_fee goes to oracle on PMP approval. PN also needs Shell ECC for
    // internal messages. Use ECC_SHELL_DEPOSIT which covers oracle_fee + gas.
    let mut shell_ecc = HashMap::new();
    shell_ecc.insert(CURRENCY_ID_SHELL, ECC_SHELL_DEPOSIT * 2);
    send_currency_with_flag_from_default_giver(
        context.clone(),
        RootPn::DEFAULT_ADDRESS,
        2_000_000_000,
        shell_ecc,
        1,
    )
    .await
    .expect("giver top up RootPN SHELL (deploy-then-PMP flow)");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Mint a SHELL gas voucher through the multifactor wallet and route it
    // into the freshly-deployed PN via `dex.send_ecc_shell`. Mirrors what the
    // production flow does — no Giver-driven SHELL voucher anywhere.
    let ecc_zk = mint_voucher_via_multifactor(
        &wallet,
        &mf_address,
        &mf_keys,
        context.clone(),
        root_pn.clone(),
        CURRENCY_ID_SHELL,
        ECC_SHELL_DEPOSIT,
        true,
    )
    .await;
    dex.send_ecc_shell(
        ParamsOfSendEccShellToPrivateNote {
            proof: ecc_zk.proof,
            nullifier_hash: proof::hex_u256_to_dec(&ecc_zk.deposit_identifier_hash_hex),
            deposit_identifier_hash: dih_dec.clone(),
            final_layer_historical_hash_root: proof::hex_u256_to_dec(
                &ecc_zk.final_layer_historical_hash_root_hex,
            ),
            voucher_nominal_fr: proof::hex_u256_to_dec(&ecc_zk.voucher_nominal_fr_hex),
            token_type_fr: proof::hex_u256_to_dec(&ecc_zk.token_type_fr_hex),
            value: ecc_zk.voucher_value,
            layer_number: ecc_zk.layer_number,
            recipient_ephemeral_pubkey: proof::pubkey_to_dec(&mf_keys.public),
        },
        Signer::Keys { keys: mf_keys.clone() },
    )
    .await
    .expect("send_ecc_shell");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    // Native vmshell on the PN is compute fuel for its internal messages —
    // not part of the user's voucher cycle, top it up directly.
    send_currency_with_flag_from_default_giver(
        context.clone(),
        &pn_address,
        20_000_000_000,
        HashMap::new(),
        1,
    )
    .await
    .expect("giver fund PN native gas (deploy-then-PMP flow)");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    eprintln!("step 4: funded PN with {} Shell gas (oracle_fee={})", ECC_SHELL_DEPOSIT, oracle_fee);

    // --- Step 5: Deploy PMP ---
    dex.deploy_pmp(
        &pn_address,
        ParamsOfDeployPmp {
            event_id: event_id.clone(),
            oracle_fee: vec![oracle_fee],
            token_type: TOKEN_TYPE_NACKL,
            names: vec![oracle_a_name.clone()],
            index: vec![0],
            initial_stakes: vec![DEPLOYER_SEED_AMOUNT, DEPLOYER_SEED_AMOUNT],
        },
        Signer::Keys { keys: mf_keys.clone() },
    )
    .await
    .expect("deploy_pmp");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let pmp_address = root_pn
        .get_pmp_address(ParamsOfGetPmpAddress {
            event_id: event_id.clone(),
            names: vec![oracle_a_name],
            token_type: TOKEN_TYPE_NACKL,
        })
        .await
        .expect("pmp addr")
        .pmp_address;

    let pmp = Pmp::new(context.clone(), dex_contract_params(&pmp_address));
    wait_active(&pmp, "PMP").await;

    // Wait for approval
    for _ in 0..30 {
        let d = dex.get_pmp_details(&pmp_address).await.expect("pmp");
        if d.approved_oracle_events >= d.number_of_oracle_events && d.number_of_oracle_events > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    // Wait for oracle confirmation
    for _ in 0..30 {
        let d = dex.get_pmp_details(&pmp_address).await.expect("pmp");
        if d.approved_oracle_events >= d.number_of_oracle_events && d.number_of_oracle_events > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Oracle sets timings → _approved = true
    let result_start = now_unix() + STAKE_PERIOD_LONG;
    dex.submit_set_timings(
        &pmp_address,
        ParamsOfSubmitSetTimings { result_start },
        Signer::Keys { keys: oracle_a_keys },
    )
    .await
    .expect("submit_set_timings");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let pmp_details = dex.get_pmp_details(&pmp_address).await.expect("pmp details");
    assert!(pmp_details.approved, "PMP should be approved after set_timings");
    assert_eq!(pmp_details.num_outcomes, 2);
    assert_eq!(pmp_details.total_pool, 2 * DEPLOYER_SEED_AMOUNT);
    eprintln!("step 5: PMP deployed, oracle confirmed, timings set at {pmp_address}");

    // Verify PN balance decreased by initial stakes
    let after = dex.get_private_note_details(&pn_address).await.expect("pn after");
    assert!(pn_nackl(&after) < PMP_DEPOSIT as u128);
    eprintln!(
        "PN balance after PMP: {} NACKL (initial deposit was {})",
        pn_nackl(&after),
        PMP_DEPOSIT
    );

    // Check history — should have PmpDeployed
    let history = dex.get_notes_history(&[pn_address.clone()], 50, None).await.expect("history");
    assert!(
        history.events.iter().any(|e| e.event_type == "PmpDeployed"),
        "history should contain PmpDeployed"
    );
    eprintln!("user flow complete: deploy PN → browse events (fee={oracle_fee}) → fund gas → deploy PMP → verified");
}
