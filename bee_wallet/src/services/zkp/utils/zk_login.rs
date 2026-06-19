// copid from https://github.com/tvmlabs/tvm-sdk/blob/main/tvm_vm/src/executor/zk_stuff/zk_login.rs
use itertools::Itertools;
use serde_json::Value;

use super::error::ZkCryptoError;
use super::error::ZkCryptoResult;

pub const BASE64_URL_CHARSET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn bitarray_to_bytearray(bits: &[u8]) -> ZkCryptoResult<Vec<u8>> {
    if bits.len() % 8 != 0 {
        return Err(ZkCryptoError::InvalidInput);
    }
    Ok(bits
        .chunks(8)
        .map(|chunk| {
            let mut byte = 0u8;
            for (i, bit) in chunk.iter().rev().enumerate() {
                byte |= bit << i;
            }
            byte
        })
        .collect())
}
fn base64_to_bitarray(input: &str) -> ZkCryptoResult<Vec<u8>> {
    input
        .chars()
        .map(|c| {
            BASE64_URL_CHARSET
                .find(c)
                .map(|index| index as u8)
                .map(|index| (0..6).rev().map(move |i| index >> i & 1))
                .ok_or(ZkCryptoError::InvalidInput)
        })
        .flatten_ok()
        .collect()
}

pub fn decode_base64_url(s: &str, i: &u8) -> Result<String, ZkCryptoError> {
    if s.len() < 2 {
        return Err(ZkCryptoError::GeneralError("Base64 string smaller than 2".to_string()));
    }
    let mut bits = base64_to_bitarray(s)?;
    match i {
        0 => {}
        1 => {
            bits.drain(..2);
        }
        2 => {
            bits.drain(..4);
        }
        _ => {
            return Err(ZkCryptoError::GeneralError("Invalid first_char_offset".to_string()));
        }
    }

    // Use usize arithmetic to avoid u8 truncation (s.len() may exceed 255)
    // and the resulting underflow when (s.len() as u8) wraps to 0.
    let last_char_offset = ((*i as usize + s.len() - 1) % 4) as u8;
    match last_char_offset {
        3 => {}
        2 => {
            bits.drain(bits.len() - 2..);
        }
        1 => {
            bits.drain(bits.len() - 4..);
        }
        _ => {
            return Err(ZkCryptoError::GeneralError("Invalid last_char_offset".to_string()));
        }
    }

    if bits.len() % 8 != 0 {
        return Err(ZkCryptoError::GeneralError("Invalid bits length".to_string()));
    }

    Ok(std::str::from_utf8(&bitarray_to_bytearray(&bits)?)
        .map_err(|_| ZkCryptoError::GeneralError("Invalid UTF8 string".to_string()))?
        .to_owned())
}

pub fn verify_extended_claim(
    extended_claim: &str,
    expected_key: &str,
) -> Result<String, ZkCryptoError> {
    // Last character of each extracted_claim must be '}' or ','
    if !(extended_claim.ends_with('}') || extended_claim.ends_with(',')) {
        return Err(ZkCryptoError::GeneralError("Invalid extended claim".to_string()));
    }

    let json_str = format!("{{{}}}", &extended_claim[..extended_claim.len() - 1]);
    let json: Value = serde_json::from_str(&json_str).map_err(|_| ZkCryptoError::InvalidInput)?;
    let value = json
        .as_object()
        .ok_or(ZkCryptoError::InvalidInput)?
        .get(expected_key)
        .ok_or(ZkCryptoError::InvalidInput)?
        .as_str()
        .ok_or(ZkCryptoError::InvalidInput)?;
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_base64_url_does_not_panic_on_long_input() {
        // A 256-char base64 string used to trigger `s.len() as u8` truncation
        // to 0, then `0 + 0 - 1` panicked with subtract overflow.
        let s: String = "A".repeat(256);
        let result = decode_base64_url(&s, &0);
        // It either decodes successfully or returns a clean error — never panics.
        assert!(result.is_ok() || result.is_err());

        // Also exercise other lengths around the u8 boundary.
        for len in [255usize, 256, 257, 1024] {
            for i in [0u8, 1, 2] {
                let s: String = "A".repeat(len);
                let _ = decode_base64_url(&s, &i);
            }
        }
    }
}
