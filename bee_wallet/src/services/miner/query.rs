use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::miner::contract::ResultOfGetDetails as MinerDetails;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::ClientContext;
use serde::Deserialize;

use crate::services;

#[derive(Debug, Deserialize)]
pub struct ParamsOfGetMinerDetails {
    pub multifactor_address: String,
}

#[derive(Debug, Deserialize)]
pub struct ResultOfGetMinerDetails {
    pub address: String,
    pub details: MinerDetails,
}

pub async fn get_details_by_multifactor_address(
    tvm_client: Arc<ClientContext>,
    params: ParamsOfGetMinerDetails,
) -> crate::errors::AppResult<ResultOfGetMinerDetails> {
    let miner =
        services::resolvers::resolve_miner_for_multifactor(tvm_client, &params.multifactor_address)
            .await?;

    let details = miner
        .get_details()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Miner get details"))?;

    Ok(ResultOfGetMinerDetails { address: miner.address().to_string(), details })
}
