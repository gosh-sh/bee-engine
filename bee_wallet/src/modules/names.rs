use crate::client::WalletContext;
use crate::services;
use crate::services::validate_name::WalletNameError;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WalletNameErrorCode {
    InvalidCharacters = 1,
    ConsecutiveHyphens = 2,
    ConsecutiveUnderscores = 3,
    StartsWithSymbol = 4,
    TooLong = 5,
    TooShort = 6,
}

#[derive(Clone)]
pub struct ResultOfValidateWalletName {
    is_valid: bool,
    error_code: Option<WalletNameErrorCode>,
}

impl ResultOfValidateWalletName {
    pub fn new(is_valid: bool, error_code: Option<WalletNameErrorCode>) -> Self {
        Self { is_valid, error_code }
    }

    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    pub fn error_code(&self) -> Option<WalletNameErrorCode> {
        self.error_code
    }
}

pub(crate) struct NamesModule<'a> {
    #[allow(dead_code)]
    ctx: &'a WalletContext,
}

impl<'a> NamesModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub fn validate_name(&self, wallet_name: String) -> ResultOfValidateWalletName {
        match services::validate_name::verify_wallet_name(wallet_name) {
            Ok(()) => ResultOfValidateWalletName::new(true, None),
            Err(err) => {
                let code = match err {
                    WalletNameError::InvalidCharacters => WalletNameErrorCode::InvalidCharacters,
                    WalletNameError::ConsecutiveHyphens => WalletNameErrorCode::ConsecutiveHyphens,
                    WalletNameError::ConsecutiveUnderscores => {
                        WalletNameErrorCode::ConsecutiveUnderscores
                    }
                    WalletNameError::StartsWithSymbol => WalletNameErrorCode::StartsWithSymbol,
                    WalletNameError::TooLong => WalletNameErrorCode::TooLong,
                    WalletNameError::TooShort => WalletNameErrorCode::TooShort,
                };

                ResultOfValidateWalletName::new(false, Some(code))
            }
        }
    }
}
