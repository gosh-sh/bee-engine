use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use rand::random;
use serde::Deserialize;
use serde::Serialize;

use crate::errors::AppError;
use crate::errors::AppResult;

const SUI_PRIVATE_KEY_PREFIX: &str = "suiprivkey";
const SUI_ED25519_FLAG: u8 = 0x00;
const ZK_LOGIN_TEMP_TTL_DAYS: u64 = 179;
const MILLIS_IN_SECOND: u64 = 1000;
const MILLIS_IN_DAY: u64 = 24 * 60 * 60 * MILLIS_IN_SECOND;
const NONCE_BYTES_LEN: usize = 20;
const NONCE_LEN_B64URL_NO_PAD: usize = 27;
const TWO_POW_128_BITS: usize = 128;
const BN254_FIELD_MODULUS_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const POSEIDON_LITE_ARITY4_WIDTH: usize = 5;
const POSEIDON_LITE_FULL_ROUNDS: usize = 8;
const POSEIDON_LITE_PARTIAL_ROUNDS_ARITY4: usize = 60;
const POSEIDON_LITE_ROUNDS_ARITY4: usize =
    POSEIDON_LITE_FULL_ROUNDS + POSEIDON_LITE_PARTIAL_ROUNDS_ARITY4;

#[derive(Debug, Deserialize)]
struct PoseidonLite4ConstantsEncoded {
    #[serde(rename = "C")]
    c: Vec<String>,
    #[serde(rename = "M")]
    m: Vec<Vec<String>>,
}

#[derive(Debug)]
struct PoseidonLite4Constants {
    c: Vec<BigUint>,
    m: Vec<Vec<BigUint>>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginPrepareResult {
    pub nonce: String,
    pub max_epoch: u64,
    pub randomness: String,
    pub ephemeral_private_key: String,
}

impl std::fmt::Debug for ZkLoginPrepareResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkLoginPrepareResult")
            .field("nonce", &self.nonce)
            .field("max_epoch", &self.max_epoch)
            .field("randomness", &self.randomness)
            .field("ephemeral_private_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct ZkLoginPrepareDeterministicInput {
    pub max_epoch: u64,
    pub randomness: String,
    pub private_key_sui_bech32: String,
}

impl std::fmt::Debug for ZkLoginPrepareDeterministicInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkLoginPrepareDeterministicInput")
            .field("max_epoch", &self.max_epoch)
            .field("randomness", &self.randomness)
            .field("private_key_sui_bech32", &"[REDACTED]")
            .finish()
    }
}

pub fn prepare_zk_login_with_now_ms(now_ms: u64) -> AppResult<ZkLoginPrepareResult> {
    let seed: [u8; 32] = random();
    let randomness_bytes: [u8; 16] = random();
    let randomness = BigUint::from_bytes_be(&randomness_bytes).to_str_radix(10);
    let max_epoch = (now_ms + ZK_LOGIN_TEMP_TTL_DAYS * MILLIS_IN_DAY) / MILLIS_IN_SECOND;

    prepare_zk_login_with_inputs(ZkLoginPrepareDeterministicInput {
        max_epoch,
        randomness,
        private_key_sui_bech32: encode_sui_private_key_ed25519(&seed)?,
    })
}

pub fn prepare_zk_login_with_inputs(
    input: ZkLoginPrepareDeterministicInput,
) -> AppResult<ZkLoginPrepareResult> {
    let seed = decode_sui_private_key_ed25519(&input.private_key_sui_bech32)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let mut sui_public_key_bytes = vec![SUI_ED25519_FLAG];
    sui_public_key_bytes.extend_from_slice(&verifying_key.to_bytes());

    let nonce = build_zk_login_nonce(&sui_public_key_bytes, input.max_epoch, &input.randomness)?;

    // Defensive parity guard: Mysten generateNonce() returns base64url without
    // padding.
    if URL_SAFE_NO_PAD.decode(&nonce).is_err() {
        return Err(AppError::new("Generated nonce is not valid base64url-no-pad")
            .with_kind("zk_login_prepare"));
    }

    Ok(ZkLoginPrepareResult {
        nonce,
        max_epoch: input.max_epoch,
        randomness: input.randomness,
        ephemeral_private_key: input.private_key_sui_bech32,
    })
}

fn encode_sui_private_key_ed25519(seed: &[u8; 32]) -> AppResult<String> {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(SUI_ED25519_FLAG);
    bytes.extend_from_slice(seed);

    bech32::encode(SUI_PRIVATE_KEY_PREFIX, bytes.to_base32(), Variant::Bech32)
        .map_err(|e| AppError::new(format!("Encode suiprivkey bech32 ({e})")))
}

fn decode_sui_private_key_ed25519(value: &str) -> AppResult<[u8; 32]> {
    let (prefix, words, _variant) = bech32::decode(value)
        .map_err(|e| AppError::new(format!("Decode suiprivkey bech32 ({e})")))?;
    if prefix != SUI_PRIVATE_KEY_PREFIX {
        return Err(AppError::new(format!("Invalid suiprivkey prefix: {prefix}")));
    }

    let bytes = Vec::<u8>::from_base32(&words)
        .map_err(|e| AppError::new(format!("Decode suiprivkey words ({e})")))?;

    if bytes.len() != 33 {
        return Err(AppError::new(format!(
            "Invalid suiprivkey length: expected 33 bytes, got {}",
            bytes.len()
        )));
    }
    if bytes[0] != SUI_ED25519_FLAG {
        return Err(AppError::new(format!(
            "Invalid suiprivkey scheme flag: expected {SUI_ED25519_FLAG}, got {}",
            bytes[0]
        )));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[1..]);
    Ok(seed)
}

fn build_zk_login_nonce(
    sui_public_key_bytes: &[u8],
    max_epoch: u64,
    randomness: &str,
) -> AppResult<String> {
    let public_key_as_bigint = BigUint::from_bytes_be(sui_public_key_bytes);
    let split_base = BigUint::from(1u8) << TWO_POW_128_BITS;
    let eph_public_key_0 = &public_key_as_bigint / &split_base;
    let eph_public_key_1 = &public_key_as_bigint % &split_base;

    let hash = poseidon_lite_hash_4([
        eph_public_key_0,
        eph_public_key_1,
        BigUint::from(max_epoch),
        parse_biguint_decimal(randomness)?,
    ])?;

    let nonce_bytes = to_big_endian_fixed_len(&hash, NONCE_BYTES_LEN);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    if nonce.len() != NONCE_LEN_B64URL_NO_PAD {
        return Err(AppError::new(format!(
            "Invalid nonce length {} (expected {})",
            nonce.len(),
            NONCE_LEN_B64URL_NO_PAD
        ))
        .with_kind("zk_login_prepare"));
    }

    Ok(nonce)
}

fn poseidon_lite_hash_4(inputs: [BigUint; 4]) -> AppResult<BigUint> {
    let modulus = bn254_field_modulus();
    let constants = poseidon_lite4_constants();

    let mut state = Vec::with_capacity(POSEIDON_LITE_ARITY4_WIDTH);
    state.push(BigUint::from(0u8));
    state.extend(inputs);

    for round in 0..POSEIDON_LITE_ROUNDS_ARITY4 {
        #[allow(clippy::needless_range_loop)]
        for y in 0..POSEIDON_LITE_ARITY4_WIDTH {
            let c_idx = round * POSEIDON_LITE_ARITY4_WIDTH + y;
            state[y] = mod_add(&state[y], &constants.c[c_idx], modulus);
            #[allow(clippy::manual_range_contains)]
            let is_full_round = round < (POSEIDON_LITE_FULL_ROUNDS / 2)
                || round >= (POSEIDON_LITE_FULL_ROUNDS / 2 + POSEIDON_LITE_PARTIAL_ROUNDS_ARITY4);
            if is_full_round || y == 0 {
                state[y] = mod_pow5(&state[y], modulus);
            }
        }
        state = poseidon_lite_mix(&state, &constants.m, modulus);
    }

    state
        .into_iter()
        .next()
        .ok_or_else(|| AppError::new("Poseidon-lite state is empty").with_kind("zk_login_prepare"))
}

fn poseidon_lite_mix(
    state: &[BigUint],
    matrix: &[Vec<BigUint>],
    modulus: &BigUint,
) -> Vec<BigUint> {
    let mut out = Vec::with_capacity(state.len());
    for row in matrix {
        let mut acc = BigUint::from(0u8);
        for (col, state_item) in row.iter().zip(state.iter()) {
            let mul = (col * state_item) % modulus;
            acc = mod_add(&acc, &mul, modulus);
        }
        out.push(acc);
    }
    out
}

fn mod_add(left: &BigUint, right: &BigUint, modulus: &BigUint) -> BigUint {
    (left + right) % modulus
}

fn mod_pow5(value: &BigUint, modulus: &BigUint) -> BigUint {
    let v2 = (value * value) % modulus;
    let v4 = (&v2 * &v2) % modulus;
    (value * v4) % modulus
}

fn parse_biguint_decimal(value: &str) -> AppResult<BigUint> {
    BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| {
        AppError::new(format!("Invalid decimal bigint: {value}")).with_kind("zk_login_prepare")
    })
}

fn bn254_field_modulus() -> &'static BigUint {
    static MODULUS: OnceLock<BigUint> = OnceLock::new();
    MODULUS.get_or_init(|| {
        BigUint::parse_bytes(BN254_FIELD_MODULUS_DECIMAL.as_bytes(), 10)
            .expect("valid BN254 modulus constant")
    })
}

fn poseidon_lite4_constants() -> &'static PoseidonLite4Constants {
    static CONSTANTS: OnceLock<PoseidonLite4Constants> = OnceLock::new();
    CONSTANTS.get_or_init(|| {
        let encoded: PoseidonLite4ConstantsEncoded =
            serde_json::from_str(include_str!("poseidon_lite_constants_4.json"))
                .expect("valid poseidon-lite arity-4 constants json");

        let c = encoded.c.into_iter().map(|v| decode_poseidon_lite_bigint(&v)).collect();
        let m = encoded
            .m
            .into_iter()
            .map(|row| row.into_iter().map(|v| decode_poseidon_lite_bigint(&v)).collect())
            .collect();

        PoseidonLite4Constants { c, m }
    })
}

fn decode_poseidon_lite_bigint(value: &str) -> BigUint {
    let bytes = BASE64_STANDARD.decode(value).expect("poseidon-lite constant is valid base64");
    BigUint::from_bytes_be(&bytes)
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
    use super::*;

    #[test]
    fn prepares_zk_login_from_known_vector() {
        let result =
            prepare_zk_login_with_inputs(ZkLoginPrepareDeterministicInput {
                private_key_sui_bech32:
                    "suiprivkey1qqg83wnuw4f0h3w0wcz8lmyt7q82l0qwgwrwqd76kvv98uvcreh72l8k3uv"
                        .to_string(),
                max_epoch: 1787345514,
                randomness: "272376485534551742589579395044831478249".to_string(),
            })
            .expect("prepare zk login");

        assert_eq!(
            result.ephemeral_private_key,
            "suiprivkey1qqg83wnuw4f0h3w0wcz8lmyt7q82l0qwgwrwqd76kvv98uvcreh72l8k3uv"
        );
        assert_eq!(result.max_epoch, 1787345514);
        assert_eq!(result.randomness, "272376485534551742589579395044831478249".to_string());
        assert_eq!(result.nonce, "gVrxAdtrow48OUYB-nGNle9P6go".to_string());
    }

    #[test]
    fn nonce_output_has_expected_shape() {
        let nonce = build_zk_login_nonce(&[0u8; 33], 1, "1").expect("nonce");
        assert_eq!(nonce.len(), NONCE_LEN_B64URL_NO_PAD);
        assert!(URL_SAFE_NO_PAD.decode(nonce).is_ok());
    }
}
