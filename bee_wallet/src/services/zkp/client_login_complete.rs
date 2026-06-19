use std::sync::OnceLock;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bech32::FromBase32;
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use serde::Deserialize;
use serde::Serialize;

use crate::errors::AppError;
use crate::errors::AppResult;
use crate::progress::ProgressEvent;
use crate::progress::ProgressSink;

/// Bound for the prover round-trip on every target. Native sets it on the
/// client builder too; `wasm32` reqwest has no client-level timeout, so it
/// must be applied per request (otherwise a hung prover spins forever).
const PROVER_TIMEOUT: Duration = Duration::from_secs(30);

const SUI_PRIVATE_KEY_PREFIX: &str = "suiprivkey";
const SUI_ED25519_FLAG: u8 = 0x00;
const BN254_FIELD_MODULUS_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const ZKP_CURVE_P_DECIMAL: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";
const MAX_KEY_CLAIM_NAME_LENGTH: usize = 32;
const MAX_KEY_CLAIM_VALUE_LENGTH: usize = 115;
const MAX_AUD_VALUE_LENGTH: usize = 145;
const PACK_WIDTH: usize = 248;
const N_ROUNDS_F: usize = 8;
const N_ROUNDS_P: [usize; 16] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginTempData {
    pub max_epoch: u64,
    pub randomness: String,
    pub ephemeral_private_key: String,
}

impl std::fmt::Debug for ZkLoginTempData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkLoginTempData")
            .field("max_epoch", &self.max_epoch)
            .field("randomness", &self.randomness)
            .field("ephemeral_private_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginCompleteLocalPrepareParams {
    pub saved_data: ZkLoginTempData,
    pub jwt: String,
    pub jwt_sub: String,
    pub jwt_aud: String,
    pub user_password: String,
}

impl std::fmt::Debug for ZkLoginCompleteLocalPrepareParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkLoginCompleteLocalPrepareParams")
            .field("saved_data", &self.saved_data)
            .field("jwt", &self.jwt)
            .field("jwt_sub", &self.jwt_sub)
            .field("jwt_aud", &self.jwt_aud)
            .field("user_password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginCompleteLocalPrepareResult {
    pub zkid: String,
    pub payload: String,
    pub max_epoch: u64,
    pub ephemeral_private_key: String,
    pub extended_ephemeral_public_key: String,
    pub ephemeral_public_key_in_hex: String,
    pub ephemeral_secret_key_in_hex: String,
}

impl std::fmt::Debug for ZkLoginCompleteLocalPrepareResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkLoginCompleteLocalPrepareResult")
            .field("zkid", &self.zkid)
            .field("payload", &self.payload)
            .field("max_epoch", &self.max_epoch)
            .field("ephemeral_private_key", &"[REDACTED]")
            .field("extended_ephemeral_public_key", &self.extended_ephemeral_public_key)
            .field("ephemeral_public_key_in_hex", &self.ephemeral_public_key_in_hex)
            .field("ephemeral_secret_key_in_hex", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofPoints {
    pub a: [String; 3],
    pub b: [[String; 2]; 3],
    pub c: [String; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssBase64Details {
    pub value: String,
    pub index_mod4: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkProof {
    pub proof_points: ProofPoints,
    pub iss_base64_details: IssBase64Details,
    pub header_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginCompleteLocalFinalizeParams {
    pub zk_proofs: ZkProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginCompleteLocalFinalizeResult {
    pub zk_proof_compressed: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginCompleteWithProverParams {
    pub saved_data: ZkLoginTempData,
    pub jwt: String,
    pub jwt_sub: String,
    pub jwt_aud: String,
    pub user_password: String,
    pub prover_url: String,
}

impl std::fmt::Debug for ZkLoginCompleteWithProverParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkLoginCompleteWithProverParams")
            .field("saved_data", &self.saved_data)
            .field("jwt", &self.jwt)
            .field("jwt_sub", &self.jwt_sub)
            .field("jwt_aud", &self.jwt_aud)
            .field("user_password", &"[REDACTED]")
            .field("prover_url", &self.prover_url)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginCompleteWithProverResult {
    pub zkid: String,
    pub max_epoch: u64,
    pub ephemeral_private_key: String,
    pub zk_proof_compressed: String,
    pub iss_base64_details: IssBase64Details,
    pub header_base64: String,
    pub ephemeral_public_key_in_hex: String,
    pub ephemeral_secret_key_in_hex: String,
}

impl std::fmt::Debug for ZkLoginCompleteWithProverResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkLoginCompleteWithProverResult")
            .field("zkid", &self.zkid)
            .field("max_epoch", &self.max_epoch)
            .field("ephemeral_private_key", &"[REDACTED]")
            .field("zk_proof_compressed", &self.zk_proof_compressed)
            .field("iss_base64_details", &self.iss_base64_details)
            .field("header_base64", &self.header_base64)
            .field("ephemeral_public_key_in_hex", &self.ephemeral_public_key_in_hex)
            .field("ephemeral_secret_key_in_hex", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProverPayload<'a> {
    jwt: &'a str,
    max_epoch: u64,
    jwt_randomness: &'a str,
    extended_ephemeral_public_key: &'a str,
    salt: &'a str,
    key_claim_name: &'a str,
}

pub fn zk_login_complete_local_prepare(
    params: ZkLoginCompleteLocalPrepareParams,
) -> AppResult<ZkLoginCompleteLocalPrepareResult> {
    let user_salt_dec = format_pwd_to_int(&params.user_password);
    let user_salt = parse_biguint_decimal(&user_salt_dec)?;

    let zkid =
        gen_address_seed(&user_salt, "sub", &params.jwt_sub, &params.jwt_aud)?.to_str_radix(10);

    let seed = decode_sui_private_key_ed25519(&params.saved_data.ephemeral_private_key)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let public_key_raw = verifying_key.to_bytes();

    let mut sui_public_key_bytes = Vec::with_capacity(33);
    sui_public_key_bytes.push(SUI_ED25519_FLAG);
    sui_public_key_bytes.extend_from_slice(&public_key_raw);
    let extended_ephemeral_public_key = BASE64_STANDARD.encode(&sui_public_key_bytes);

    let payload = serde_json::to_string(&ProverPayload {
        jwt: &params.jwt,
        max_epoch: params.saved_data.max_epoch,
        jwt_randomness: &params.saved_data.randomness,
        extended_ephemeral_public_key: &extended_ephemeral_public_key,
        salt: &user_salt_dec,
        key_claim_name: "sub",
    })
    .map_err(|e| {
        AppError::new(format!("Serialize prover payload ({e})")).with_kind("zk_login_complete")
    })?;

    Ok(ZkLoginCompleteLocalPrepareResult {
        zkid,
        payload,
        max_epoch: params.saved_data.max_epoch,
        ephemeral_private_key: params.saved_data.ephemeral_private_key,
        extended_ephemeral_public_key,
        ephemeral_public_key_in_hex: hex::encode(public_key_raw),
        ephemeral_secret_key_in_hex: hex::encode(seed),
    })
}

pub fn zk_login_complete_local_finalize(
    params: ZkLoginCompleteLocalFinalizeParams,
) -> AppResult<ZkLoginCompleteLocalFinalizeResult> {
    let zk_proof_compressed = prepare_compressed_proof(&params.zk_proofs)?;
    Ok(ZkLoginCompleteLocalFinalizeResult { zk_proof_compressed })
}

pub async fn zk_login_complete_with_prover(
    params: ZkLoginCompleteWithProverParams,
    progress: Option<ProgressSink>,
) -> AppResult<ZkLoginCompleteWithProverResult> {
    complete_with_prover_emitting(params, progress.as_ref(), |payload, prover_url| async move {
        fetch_zk_proofs(&payload, &prover_url).await
    })
    .await
}

/// Runs the prove pipeline emitting `prove` milestones, and a terminal
/// `prove:failed` (with the error message) on any error. `fetch` is injected
/// so the milestone/terminal logic is unit-testable without a live prover.
async fn complete_with_prover_emitting<F, Fut>(
    params: ZkLoginCompleteWithProverParams,
    progress: Option<&ProgressSink>,
    fetch: F,
) -> AppResult<ZkLoginCompleteWithProverResult>
where
    F: FnOnce(String, String) -> Fut,
    Fut: std::future::Future<Output = AppResult<ZkProof>>,
{
    let result = complete_with_prover_steps(params, progress, fetch).await;
    if let Err(ref e) = result {
        crate::progress::emit(
            progress,
            ProgressEvent::new("prove", "failed").with_detail(e.message.clone()),
        );
    }
    result
}

async fn complete_with_prover_steps<F, Fut>(
    params: ZkLoginCompleteWithProverParams,
    progress: Option<&ProgressSink>,
    fetch: F,
) -> AppResult<ZkLoginCompleteWithProverResult>
where
    F: FnOnce(String, String) -> Fut,
    Fut: std::future::Future<Output = AppResult<ZkProof>>,
{
    let prover_url = params.prover_url.clone();
    let local_prepared = zk_login_complete_local_prepare(ZkLoginCompleteLocalPrepareParams {
        saved_data: params.saved_data,
        jwt: params.jwt,
        jwt_sub: params.jwt_sub,
        jwt_aud: params.jwt_aud,
        user_password: params.user_password,
    })?;
    // Local witness inputs are ready. The heavy work (witness + halo2) then
    // happens inside the remote prover, which returns only a final JSON — so we
    // bracket the round-trip but can't report progress within it.
    crate::progress::emit(progress, ProgressEvent::new("prove", "prepared"));

    crate::progress::emit(progress, ProgressEvent::new("prove", "proving"));
    let zk_proofs = fetch(local_prepared.payload.clone(), prover_url).await?;
    crate::progress::emit(progress, ProgressEvent::new("prove", "proof_received"));

    let finalized = zk_login_complete_local_finalize(ZkLoginCompleteLocalFinalizeParams {
        zk_proofs: zk_proofs.clone(),
    })?;
    crate::progress::emit(progress, ProgressEvent::new("prove", "finished"));

    Ok(ZkLoginCompleteWithProverResult {
        zkid: local_prepared.zkid,
        max_epoch: local_prepared.max_epoch,
        ephemeral_private_key: local_prepared.ephemeral_private_key,
        zk_proof_compressed: finalized.zk_proof_compressed,
        iss_base64_details: zk_proofs.iss_base64_details,
        header_base64: zk_proofs.header_base64,
        ephemeral_public_key_in_hex: local_prepared.ephemeral_public_key_in_hex,
        ephemeral_secret_key_in_hex: local_prepared.ephemeral_secret_key_in_hex,
    })
}

async fn fetch_zk_proofs(payload: &str, prover_url: &str) -> AppResult<ZkProof> {
    #[cfg(target_arch = "wasm32")]
    let client = reqwest::Client::new();

    #[cfg(not(target_arch = "wasm32"))]
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(PROVER_TIMEOUT)
        .build()
        .map_err(|e| {
            AppError::new(format!("Build prover client ({e})")).with_kind("zk_login_complete")
        })?;

    let request = client
        .post(prover_url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(payload.to_owned());

    // wasm reqwest ignores client-level timeouts; bound this request explicitly
    // so a hung prover surfaces as an error instead of a permanently stuck UI.
    #[cfg(target_arch = "wasm32")]
    let request = request.timeout(PROVER_TIMEOUT);

    let response = request.send().await.map_err(|e| {
        AppError::new(format!("Fetch zk proofs ({e})")).with_kind("zk_login_complete")
    })?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "<failed to read body>".to_string());
        return Err(AppError::new(format!("HTTP error {}: {}", status.as_u16(), body))
            .with_kind("zk_login_complete"));
    }

    response.json::<ZkProof>().await.map_err(|e| {
        AppError::new(format!("Parse zk proofs response ({e})")).with_kind("zk_login_complete")
    })
}

fn format_pwd_to_int(password: &str) -> String {
    let mut out = String::new();
    for ch in password.chars() {
        out.push_str(&(ch as u32).to_string());
    }
    out
}

fn gen_address_seed(salt: &BigUint, name: &str, value: &str, aud: &str) -> AppResult<BigUint> {
    poseidon_lite_hash(&[
        hash_ascii_str_to_field(name, MAX_KEY_CLAIM_NAME_LENGTH)?,
        hash_ascii_str_to_field(value, MAX_KEY_CLAIM_VALUE_LENGTH)?,
        hash_ascii_str_to_field(aud, MAX_AUD_VALUE_LENGTH)?,
        poseidon_lite_hash(std::slice::from_ref(salt))?,
    ])
}

fn hash_ascii_str_to_field(value: &str, max_size: usize) -> AppResult<BigUint> {
    if value.len() > max_size {
        return Err(AppError::new(format!("String is longer than {max_size} chars"))
            .with_kind("zk_login_complete"));
    }

    let mut bytes = value.as_bytes().to_vec();
    bytes.resize(max_size, 0u8);
    let chunk_size = PACK_WIDTH / 8;
    let packed = chunk_array_first_shorter(&bytes, chunk_size)
        .into_iter()
        .map(|chunk| BigUint::from_bytes_be(&chunk))
        .collect::<Vec<_>>();
    poseidon_lite_hash(&packed)
}

fn chunk_array_first_shorter(bytes: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let rem = bytes.len() % chunk_size;
    let first = if rem == 0 { chunk_size } else { rem };
    let mut out = Vec::new();
    let mut idx = 0usize;
    out.push(bytes[idx..idx + first].to_vec());
    idx += first;
    while idx < bytes.len() {
        out.push(bytes[idx..idx + chunk_size].to_vec());
        idx += chunk_size;
    }
    out
}

fn poseidon_lite_hash(inputs: &[BigUint]) -> AppResult<BigUint> {
    if inputs.is_empty() || inputs.len() > 16 {
        return Err(
            AppError::new("poseidon-lite: invalid input length").with_kind("zk_login_complete")
        );
    }

    let modulus = bn254_field_modulus();
    let constants = poseidon_constants(inputs.len())?;
    let width = inputs.len() + 1;
    let n_rounds_p = N_ROUNDS_P[inputs.len() - 1];

    let mut state = Vec::with_capacity(width);
    state.push(BigUint::from(0u8));
    state.extend(inputs.iter().cloned());

    for round in 0..(N_ROUNDS_F + n_rounds_p) {
        #[allow(clippy::needless_range_loop)]
        for y in 0..width {
            state[y] = (&state[y] + &constants.c[round * width + y]) % modulus;
            let is_full_round = round < (N_ROUNDS_F / 2) || round >= (N_ROUNDS_F / 2 + n_rounds_p);
            if is_full_round || y == 0 {
                state[y] = mod_pow5(&state[y], modulus);
            }
        }
        state = mix_poseidon_state(&state, &constants.m, modulus);
    }

    Ok(state[0].clone())
}

fn mix_poseidon_state(
    state: &[BigUint],
    matrix: &[Vec<BigUint>],
    modulus: &BigUint,
) -> Vec<BigUint> {
    let mut out = Vec::with_capacity(state.len());
    for row in matrix {
        let mut acc = BigUint::from(0u8);
        for (m, s) in row.iter().zip(state.iter()) {
            acc = (acc + ((m * s) % modulus)) % modulus;
        }
        out.push(acc);
    }
    out
}

fn mod_pow5(v: &BigUint, modulus: &BigUint) -> BigUint {
    let v2 = (v * v) % modulus;
    let v4 = (&v2 * &v2) % modulus;
    (v * v4) % modulus
}

fn bn254_field_modulus() -> &'static BigUint {
    static V: OnceLock<BigUint> = OnceLock::new();
    V.get_or_init(|| parse_biguint_decimal(BN254_FIELD_MODULUS_DECIMAL).expect("valid modulus"))
}

fn zkp_curve_p() -> &'static BigUint {
    static V: OnceLock<BigUint> = OnceLock::new();
    V.get_or_init(|| parse_biguint_decimal(ZKP_CURVE_P_DECIMAL).expect("valid p"))
}

#[derive(Debug, Deserialize)]
struct PoseidonConstantsEncoded {
    #[serde(rename = "C")]
    c: Vec<String>,
    #[serde(rename = "M")]
    m: Vec<Vec<String>>,
}

#[derive(Debug)]
struct PoseidonConstantsDecoded {
    c: Vec<BigUint>,
    m: Vec<Vec<BigUint>>,
}

fn poseidon_constants(arity: usize) -> AppResult<&'static PoseidonConstantsDecoded> {
    static C1: OnceLock<PoseidonConstantsDecoded> = OnceLock::new();
    static C2: OnceLock<PoseidonConstantsDecoded> = OnceLock::new();
    static C4: OnceLock<PoseidonConstantsDecoded> = OnceLock::new();
    static C5: OnceLock<PoseidonConstantsDecoded> = OnceLock::new();

    let load = |raw: &str| -> PoseidonConstantsDecoded {
        let enc: PoseidonConstantsEncoded =
            serde_json::from_str(raw).expect("valid poseidon-lite constants json");
        PoseidonConstantsDecoded {
            c: enc.c.into_iter().map(|v| decode_poseidon_const(&v)).collect(),
            m: enc
                .m
                .into_iter()
                .map(|row| row.into_iter().map(|v| decode_poseidon_const(&v)).collect())
                .collect(),
        }
    };

    match arity {
        1 => Ok(C1.get_or_init(|| load(include_str!("poseidon_lite_constants_1.json")))),
        2 => Ok(C2.get_or_init(|| load(include_str!("poseidon_lite_constants_2.json")))),
        4 => Ok(C4.get_or_init(|| load(include_str!("poseidon_lite_constants_4.json")))),
        5 => Ok(C5.get_or_init(|| load(include_str!("poseidon_lite_constants_5.json")))),
        _ => Err(AppError::new(format!("Unsupported poseidon-lite arity: {arity}"))
            .with_kind("zk_login_complete")),
    }
}

fn decode_poseidon_const(value: &str) -> BigUint {
    let bytes = BASE64_STANDARD.decode(value).expect("valid base64 poseidon constant");
    BigUint::from_bytes_be(&bytes)
}

fn parse_biguint_decimal(value: &str) -> AppResult<BigUint> {
    BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| {
        AppError::new(format!("Invalid decimal bigint: {value}")).with_kind("zk_login_complete")
    })
}

fn decode_sui_private_key_ed25519(value: &str) -> AppResult<[u8; 32]> {
    let (prefix, words, _variant) = bech32::decode(value)
        .map_err(|e| AppError::new(format!("Decode suiprivkey bech32 ({e})")))?;
    if prefix != SUI_PRIVATE_KEY_PREFIX {
        return Err(AppError::new(format!("Invalid suiprivkey prefix: {prefix}")));
    }

    let bytes = Vec::<u8>::from_base32(&words)
        .map_err(|e| AppError::new(format!("Decode suiprivkey words ({e})")))?;
    if bytes.len() != 33 || bytes[0] != SUI_ED25519_FLAG {
        return Err(AppError::new("Invalid suiprivkey payload"));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[1..]);
    Ok(seed)
}

fn prepare_compressed_proof(proof: &ZkProof) -> AppResult<String> {
    let a_x = &proof.proof_points.a[0];
    let a_y = parse_biguint_decimal(&proof.proof_points.a[1])?;
    let b0_x = &proof.proof_points.b[0][0];
    let b1_x = &proof.proof_points.b[0][1];
    let b1_y = parse_biguint_decimal(&proof.proof_points.b[1][1])?;
    let c_x = &proof.proof_points.c[0];
    let c_y = parse_biguint_decimal(&proof.proof_points.c[1])?;

    let hex_ax = prepare_hex_representation(a_x, &a_y)?;
    let hex_b0x = prepare_hex_representation(b0_x, &BigUint::from(0u8))?;
    let hex_b1x = prepare_hex_representation(b1_x, &b1_y)?;
    let hex_cx = prepare_hex_representation(c_x, &c_y)?;

    Ok(format!("{hex_ax}{hex_b0x}{hex_b1x}{hex_cx}"))
}

fn prepare_hex_representation(init_x: &str, y: &BigUint) -> AppResult<String> {
    let x = parse_biguint_decimal(init_x)?;
    let mut bytes = to_big_endian_fixed_len(&x, 32);

    if y > &(zkp_curve_p() - y) {
        bytes[0] |= 0b1000_0000;
    } else {
        bytes[0] &= 0b0111_1111;
    }

    bytes.reverse();
    Ok(hex::encode(bytes))
}

fn to_big_endian_fixed_len(value: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_be();
    if bytes.len() > len {
        bytes = bytes.split_off(bytes.len() - len);
        return bytes;
    }
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        return padded;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    fn known_prover_params(prover_url: &str) -> ZkLoginCompleteWithProverParams {
        ZkLoginCompleteWithProverParams {
            saved_data: ZkLoginTempData {
                max_epoch: 1787347228,
                randomness: "251226222062428742376536481969159709164".to_string(),
                ephemeral_private_key:
                    "suiprivkey1qz70vq46cqnnkynx32su2awahlumavkz4nxc2xv8kkgwnxtln4pc7fpzyc8"
                        .to_string(),
            },
            jwt: "dummy.jwt.token".to_string(),
            jwt_sub: "104824947798240050903".to_string(),
            jwt_aud: "222414061721-4tu2gsfms6rvagqvt4mp0mjmbom6flbl.apps.googleusercontent.com"
                .to_string(),
            user_password: "Hello!23".to_string(),
            prover_url: prover_url.to_string(),
        }
    }

    fn canned_proof() -> ZkProof {
        ZkProof {
            proof_points: ProofPoints {
                a: ["123".to_string(), "456".to_string(), "1".to_string()],
                b: [
                    ["789".to_string(), "321".to_string()],
                    ["654".to_string(), "987".to_string()],
                    ["1".to_string(), "1".to_string()],
                ],
                c: ["111".to_string(), "222".to_string(), "1".to_string()],
            },
            iss_base64_details: IssBase64Details { value: "x".to_string(), index_mod4: 0 },
            header_base64: "y".to_string(),
        }
    }

    #[tokio::test]
    async fn prove_emits_all_milestones_on_success() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<crate::progress::ProgressEvent>();
        let res = complete_with_prover_emitting(
            known_prover_params("http://unused"),
            Some(&tx),
            |_payload, _url| async move { Ok::<ZkProof, AppError>(canned_proof()) },
        )
        .await;
        drop(tx);

        assert!(res.is_ok());
        let events: Vec<crate::progress::ProgressEvent> = rx.collect().await;
        let stages: Vec<&str> = events.iter().map(|e| e.stage.as_str()).collect();
        assert_eq!(stages, ["prepared", "proving", "proof_received", "finished"]);
        assert!(events.iter().all(|e| e.op == "prove"));
    }

    #[tokio::test]
    async fn prove_emits_failed_on_prover_error() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<crate::progress::ProgressEvent>();
        let res = complete_with_prover_emitting(
            known_prover_params("http://unused"),
            Some(&tx),
            |_payload, _url| async move {
                Err::<ZkProof, AppError>(AppError::new("boom").with_kind("zk_login_complete"))
            },
        )
        .await;
        drop(tx);

        assert!(res.is_err());
        let events: Vec<crate::progress::ProgressEvent> = rx.collect().await;
        let stages: Vec<&str> = events.iter().map(|e| e.stage.as_str()).collect();
        assert_eq!(stages, ["prepared", "proving", "failed"]);
        assert_eq!(events.last().unwrap().detail.as_deref(), Some("boom"));
    }

    #[test]
    fn local_prepare_matches_known_vector() {
        let result = zk_login_complete_local_prepare(ZkLoginCompleteLocalPrepareParams {
            saved_data: ZkLoginTempData {
                max_epoch: 1787347228,
                randomness: "251226222062428742376536481969159709164".to_string(),
                ephemeral_private_key:
                    "suiprivkey1qz70vq46cqnnkynx32su2awahlumavkz4nxc2xv8kkgwnxtln4pc7fpzyc8"
                        .to_string(),
            },
            jwt: "dummy.jwt.token".to_string(),
            jwt_sub: "104824947798240050903".to_string(),
            jwt_aud: "222414061721-4tu2gsfms6rvagqvt4mp0mjmbom6flbl.apps.googleusercontent.com"
                .to_string(),
            user_password: "Hello!23".to_string(),
        })
        .expect("local prepare");

        assert_eq!(
            result.zkid,
            "3232339675244503454337597888874283153045927740736964457203808240868199427174"
        );
        assert_eq!(
            result.extended_ephemeral_public_key,
            "ADYQ0ezspH3N2GD8HlSIiJ5uMwYvKM57qL4hAOIF+GXr"
        );
        assert!(result.payload.contains("\"salt\":\"72101108108111335051\""));
        assert!(result.payload.contains("\"keyClaimName\":\"sub\""));
        assert!(result.payload.contains("\"maxEpoch\":1787347228"));
        assert!(result
            .payload
            .contains("\"jwtRandomness\":\"251226222062428742376536481969159709164\""));
    }

    #[test]
    fn local_finalize_returns_hex_string() {
        let result = zk_login_complete_local_finalize(ZkLoginCompleteLocalFinalizeParams {
            zk_proofs: ZkProof {
                proof_points: ProofPoints {
                    a: ["123".to_string(), "456".to_string(), "1".to_string()],
                    b: [
                        ["789".to_string(), "321".to_string()],
                        ["654".to_string(), "987".to_string()],
                        ["1".to_string(), "1".to_string()],
                    ],
                    c: ["111".to_string(), "222".to_string(), "1".to_string()],
                },
                iss_base64_details: IssBase64Details { value: "x".to_string(), index_mod4: 0 },
                header_base64: "y".to_string(),
            },
        })
        .expect("finalize");

        assert_eq!(result.zk_proof_compressed.len(), 256);
        assert!(result.zk_proof_compressed.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
