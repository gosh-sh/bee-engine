use std::sync::Arc;

use ackinacki_kit::tvm_client::boc;
use ackinacki_kit::tvm_client::boc::BuilderOp;
use ackinacki_kit::tvm_client::boc::ParamsOfEncodeBoc;
use ackinacki_kit::tvm_client::boc::ParamsOfGetBocHash;
use ackinacki_kit::tvm_client::ClientContext;

pub fn get_boc_hash(
    tvm_client: Arc<ClientContext>,
    data: String,
) -> crate::errors::AppResult<String> {
    let bytes = hex::decode(&data)
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to hex decode"))?;

    let boc = boc::encode_boc(
        tvm_client.clone(),
        ParamsOfEncodeBoc {
            builder: vec![BuilderOp::Integer {
                size: bytes.len() as u32 * 8,
                value: format!("0x{}", data).into(),
            }],
            boc_cache: None,
        },
    )
    .map_err(|e| crate::errors::AppError::from(e).with_context("failed to encode boc"))?;

    let result = boc::get_boc_hash(tvm_client.clone(), ParamsOfGetBocHash { boc: boc.boc })
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to get_boc_hash"))?;

    Ok(result.hash)
}
