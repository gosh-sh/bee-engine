pub use bee_errors::AppError;
pub use bee_errors::AppResult;

// Crate-specific From impls that can't go in bee_errors.
use crate::services::zkp::utils::error::ZkCryptoError;

impl From<ZkCryptoError> for AppError {
    fn from(e: ZkCryptoError) -> Self {
        AppError::new(e.to_string()).with_kind("zk")
    }
}
