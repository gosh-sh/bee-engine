use wasm_bindgen::prelude::wasm_bindgen;

use crate::modules::names::ResultOfValidateWalletName as InnerResultOfValidateWalletName;
use crate::modules::names::WalletNameErrorCode as InnerWalletNameErrorCode;

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum WalletNameErrorCode {
    InvalidCharacters = 1,
    ConsecutiveHyphens = 2,
    ConsecutiveUnderscores = 3,
    StartsWithSymbol = 4,
    TooLong = 5,
    TooShort = 6,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfValidateWalletName {
    is_valid: bool,
    error_code: Option<WalletNameErrorCode>,
}

impl From<InnerResultOfValidateWalletName> for ResultOfValidateWalletName {
    fn from(value: InnerResultOfValidateWalletName) -> Self {
        let error_code = value.error_code().map(|code| match code {
            InnerWalletNameErrorCode::InvalidCharacters => WalletNameErrorCode::InvalidCharacters,
            InnerWalletNameErrorCode::ConsecutiveHyphens => WalletNameErrorCode::ConsecutiveHyphens,
            InnerWalletNameErrorCode::ConsecutiveUnderscores => {
                WalletNameErrorCode::ConsecutiveUnderscores
            }
            InnerWalletNameErrorCode::StartsWithSymbol => WalletNameErrorCode::StartsWithSymbol,
            InnerWalletNameErrorCode::TooLong => WalletNameErrorCode::TooLong,
            InnerWalletNameErrorCode::TooShort => WalletNameErrorCode::TooShort,
        });

        Self { is_valid: value.is_valid(), error_code }
    }
}

#[wasm_bindgen]
impl ResultOfValidateWalletName {
    #[wasm_bindgen(getter)]
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    #[wasm_bindgen(getter)]
    pub fn error_code(&self) -> Option<WalletNameErrorCode> {
        self.error_code
    }
}
