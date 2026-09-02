use ackinacki_kit::contracts::delivery::ContractContext;
use ackinacki_kit::contracts::mvsystem::miner::contract::Miner;
use ackinacki_kit::contracts::mvsystem::mirror::Mirror;
use ackinacki_kit::contracts::mvsystem::mirror::ParamsOfGetMinerAddress;

pub enum MirrorSelector<'a> {
    ForMultifactorAddr(&'a str),
    ForPubkey(&'a str),
}

pub fn resolve_mirror(
    context: ContractContext,
    selector: MirrorSelector<'_>,
) -> crate::errors::AppResult<Mirror> {
    match selector {
        MirrorSelector::ForMultifactorAddr(multifactor_addres) => {
            let tail = address_tail(multifactor_addres)?;
            mirror_from_seed(context, tail)
        }

        MirrorSelector::ForPubkey(pubkey) => {
            let seed = normalize_pubkey(pubkey);
            mirror_from_seed(context, &seed)
        }
    }
}

pub async fn resolve_miner_for_multifactor(
    context: ContractContext,
    multifactor_address: &str,
) -> crate::errors::AppResult<Miner> {
    let mirror = resolve_mirror(context, MirrorSelector::ForMultifactorAddr(multifactor_address))?;

    mirror
        .get_miner(ParamsOfGetMinerAddress { multifactor_address: multifactor_address.to_string() })
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Resolve miner for multifactor"))
}

fn address_tail(addr: &str) -> crate::errors::AppResult<&str> {
    addr.rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("invalid address format: {addr}").into())
}

fn normalize_pubkey(s: &str) -> String {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s).to_string()
}

fn mirror_from_seed(context: ContractContext, seed: &str) -> crate::errors::AppResult<Mirror> {
    Mirror::new_default(context, seed).map_err(|e| {
        crate::errors::AppError::from(e).with_context(format!("Mirror::new_default(seed={seed})"))
    })
}
