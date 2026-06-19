use regex::Regex;

#[derive(Debug, Clone)]
pub enum WalletNameError {
    InvalidCharacters,
    ConsecutiveHyphens,
    ConsecutiveUnderscores,
    StartsWithSymbol,
    TooLong,
    TooShort,
}

pub fn verify_wallet_name(wallet_name: impl AsRef<str>) -> Result<(), WalletNameError> {
    let wallet_name = wallet_name.as_ref().trim().to_lowercase();

    // Allowed symbols
    let re_symbols = Regex::new(r"^[a-z0-9_-]+$").unwrap();
    if !re_symbols.is_match(&wallet_name) {
        return Err(WalletNameError::InvalidCharacters);
    }

    // No "--"
    let re_hyphens = Regex::new(r"-{2,}").unwrap();
    if re_hyphens.is_match(&wallet_name) {
        return Err(WalletNameError::ConsecutiveHyphens);
    }

    // No "__"
    let re_underscores = Regex::new(r"_{2,}").unwrap();
    if re_underscores.is_match(&wallet_name) {
        return Err(WalletNameError::ConsecutiveUnderscores);
    }

    // Cannot start with "-" or "_"
    if wallet_name.starts_with('-') || wallet_name.starts_with('_') {
        return Err(WalletNameError::StartsWithSymbol);
    }

    // Max length
    if wallet_name.len() > 39 {
        return Err(WalletNameError::TooLong);
    }

    // Min length
    if wallet_name.len() < 4 {
        return Err(WalletNameError::TooShort);
    }

    Ok(())
}
