use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::processing::ResultOfSendMessage;

use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::services;

pub struct ParamsOfGenerateVoucher {
    pub multifactor_address: String,
    pub token_type: u32,
    pub amount: u64,
    pub is_fee: bool,
    /// `skUCommit` to embed in the `RootPN.generateVoucher` payload. For the
    /// halo2-bound production flow pass `format!("0x{}", poseidon_hex)`. Pass
    /// `"0"` when the call doesn't need to bind to a specific halo2 prover.
    pub sk_u_commit: String,
    pub signer_keys: KeyPair,
}

pub(crate) struct DexModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> DexModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub async fn generate_voucher(
        &self,
        params: ParamsOfGenerateVoucher,
    ) -> AppResult<ResultOfSendMessage> {
        self.ctx.acquire().await;

        let multifactor = Multifactor::new_default(
            self.ctx.contract_context.clone(),
            params.multifactor_address.clone(),
        );
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let multifactor_arc = Arc::new(multifactor);

        services::dex::generate_voucher(
            self.ctx.tvm_client.clone(),
            &multifactor_arc,
            services::dex::ParamsOfGenerateVoucher {
                multifactor_address: params.multifactor_address,
                token_type: params.token_type,
                amount: params.amount,
                is_fee: params.is_fee,
                sk_u_commit: params.sk_u_commit,
                signer_keys: params.signer_keys,
                epk_expire_at,
                mirror_index: 0,
            },
        )
        .await
    }
}
