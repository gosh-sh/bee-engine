use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetIndexer;
use ackinacki_kit::contracts::token::root::TokenRoot;
use ackinacki_kit::contracts::traits::SendMessage;
use ackinacki_kit::tvm_client::abi::CallSet;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;

const NACKL_ECC_ID: u32 = 1;
const SHELL_ECC_ID: u32 = 2;
const USDC_ECC_ID: u32 = 3;

const NACKL_DECIMALS: u32 = 9;
const SHELL_DECIMALS: u32 = 9;
const USDC_DECIMALS: u32 = 6;
const TIP3_USDC_DECIMALS: u32 = 6;

/// TIP-3 USDC TokenRoot on shellnet.
const TIP3_USDC_ROOT: &str = "0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Server keys that can mint TIP-3 USDC on shellnet.
const TIP3_MINT_PUBLIC: &str = "e44b1ca07ee19c5c66eca104b9e5372f1fcadfe962b11e565132c66ec5603d91";
const TIP3_MINT_SECRET: &str = "55c5d4ca4f11c7721e39b1dbe407b7dc787b68d89fc8936fb798e7631f155ea0";

fn prompt(msg: &str) -> String {
    print!("{msg}");
    std::io::stdout().flush().unwrap();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

fn create_tvm_client(endpoint: &str) -> Arc<ClientContext> {
    let mut config = ClientConfig::default();
    config.network.endpoints = Some(vec![endpoint.to_string()]);
    Arc::new(ClientContext::new(config).expect("failed to create tvm client"))
}

async fn resolve_address(ctx: &Arc<ClientContext>, name: &str) -> Result<String, String> {
    let root = MobileVerifiersRoot::new_default(ctx.clone());
    let indexer = root
        .get_indexer(ParamsOfGetIndexer { name: name.to_string() })
        .await
        .map_err(|e| format!("get_indexer failed: {e}"))?;
    let details = indexer.get_details().await.map_err(|e| format!("get_details failed: {e}"))?;
    Ok(details.multifactor_address)
}

async fn send_ecc(
    ctx: &Arc<ClientContext>,
    address: &str,
    ecc_id: u32,
    raw_amount: u64,
    label: &str,
    amount: f64,
) {
    let gas: u64 = 1_000_000_000;

    print!("Sending gas... ");
    std::io::stdout().flush().unwrap();
    send_currency_with_flag_from_default_giver(ctx.clone(), address, gas, HashMap::new(), 1).await;
    println!("OK");

    let ecc = HashMap::from([(ecc_id, raw_amount)]);
    print!("Sending {amount} {label}... ");
    std::io::stdout().flush().unwrap();
    send_currency_with_flag_from_default_giver(ctx.clone(), address, gas, ecc, 1).await;
    println!("OK");
}

async fn mint_tip3_usdc(
    ctx: &Arc<ClientContext>,
    wallet_owner: &str,
    raw_amount: u64,
    amount: f64,
) {
    // Dev faucet: USDC token dApp is unconfirmed; System placeholder is fine
    // here (this bin only runs against < 1.0.0 dev nodes).
    let usdc_root = TokenRoot::new(
        ctx.clone(),
        bee_wallet::dapp::token_contract_params(
            TIP3_USDC_ROOT,
            ackinacki_kit::contracts::dapp::SystemDapp::System,
        ),
    );
    let keys =
        KeyPair { public: TIP3_MINT_PUBLIC.to_string(), secret: TIP3_MINT_SECRET.to_string() };

    print!("Minting {amount} TIP-3 USDC... ");
    std::io::stdout().flush().unwrap();

    let result = usdc_root
        .send_message(
            Some(CallSet {
                function_name: "mint".to_string(),
                header: None,
                input: Some(serde_json::json!({
                    "value": raw_amount.to_string(),
                    "walletOwner": wallet_owner,
                })),
            }),
            None,
            Signer::Keys { keys },
        )
        .await;

    match result {
        Ok(r) => {
            let exit_code = r.exit_code.unwrap_or(0);
            let aborted = r.aborted.unwrap_or(false);
            if aborted || exit_code > 0 {
                println!("FAILED (exit_code={exit_code}, aborted={aborted})");
            } else {
                println!("OK (msg: {:?})", r.message_hash.as_deref().unwrap_or("?"));
            }
        }
        Err(e) => {
            println!("FAILED ({e})");
        }
    }
}

#[tokio::main]
async fn main() {
    let endpoint = "shellnet.ackinacki.org";
    println!("Shellnet faucet (giver works only on shellnet)\n");
    let ctx = create_tvm_client(endpoint);

    let name = prompt("Wallet name: ");
    if name.is_empty() {
        eprintln!("Error: wallet name is empty");
        std::process::exit(1);
    }

    print!("Resolving '{name}'... ");
    std::io::stdout().flush().unwrap();
    let address = match resolve_address(&ctx, &name).await {
        Ok(addr) => {
            println!("{addr}");
            addr
        }
        Err(e) => {
            println!("FAILED");
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    println!("\nCurrency:");
    println!("  1) NACKL       (ECC, decimals=9)");
    println!("  2) SHELL       (ECC, decimals=9)");
    println!("  3) USDC        (ECC, decimals=6)");
    println!("  4) USDC TIP-3  (token mint, decimals=6)");
    let choice = prompt("Choose [1/2/3/4]: ");

    enum Mode {
        Ecc { ecc_id: u32, decimals: u32, label: &'static str },
        Tip3Usdc,
    }

    let mode = match choice.as_str() {
        "1" | "nackl" | "NACKL" => {
            Mode::Ecc { ecc_id: NACKL_ECC_ID, decimals: NACKL_DECIMALS, label: "NACKL" }
        }
        "2" | "shell" | "SHELL" => {
            Mode::Ecc { ecc_id: SHELL_ECC_ID, decimals: SHELL_DECIMALS, label: "SHELL" }
        }
        "3" | "usdc" | "USDC" => {
            Mode::Ecc { ecc_id: USDC_ECC_ID, decimals: USDC_DECIMALS, label: "USDC" }
        }
        "4" | "tip3" | "TIP3" => Mode::Tip3Usdc,
        _ => {
            eprintln!("Error: invalid choice '{choice}'");
            std::process::exit(1);
        }
    };

    let label = match &mode {
        Mode::Ecc { label, .. } => *label,
        Mode::Tip3Usdc => "USDC TIP-3",
    };

    let amount_str = prompt(&format!("How many {label}? (e.g. 1 = 1 {label}, 0.5 = half): "));
    let amount: f64 = match amount_str.parse() {
        Ok(v) if v > 0.0 => v,
        _ => {
            eprintln!("Error: invalid amount '{amount_str}'");
            std::process::exit(1);
        }
    };

    match mode {
        Mode::Ecc { ecc_id, decimals, label } => {
            let raw_amount = (amount * 10f64.powi(decimals as i32)) as u64;
            println!("\nSending {amount} {label} ({raw_amount} raw) to '{name}' ({address})\n");
            send_ecc(&ctx, &address, ecc_id, raw_amount, label, amount).await;
        }
        Mode::Tip3Usdc => {
            let raw_amount = (amount * 10f64.powi(TIP3_USDC_DECIMALS as i32)) as u64;
            println!("\nMinting {amount} TIP-3 USDC ({raw_amount} raw) to '{name}' ({address})\n");

            // Gas needed for wallet to receive TIP-3
            print!("Sending gas... ");
            std::io::stdout().flush().unwrap();
            send_currency_with_flag_from_default_giver(
                ctx.clone(),
                &address,
                1_000_000_000,
                HashMap::new(),
                1,
            )
            .await;
            println!("OK");

            mint_tip3_usdc(&ctx, &address, raw_amount, amount).await;
        }
    }

    println!("\nDone!");
}
