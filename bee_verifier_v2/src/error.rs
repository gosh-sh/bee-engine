#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum LibErrorCode {
    DeserializeRequest = 100,
    CheckRoot = 200,
    BuildMerkleProof = 301,
    CheckCheckpoint = 302,
    /// The reveal does not answer the intervals that were asked for.
    IntervalMismatch = 400,
    /// An interval carries a step count that is not `stride`.
    BadStrideLength = 401,
    /// The submission itself is malformed (stride of zero, no checkpoints).
    BadSubmit = 402,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LibError {
    code: LibErrorCode,
    message: Option<String>,
}

impl From<LibError> for Vec<u8> {
    fn from(value: LibError) -> Self {
        let mut result = vec![0, 0];
        result.extend_from_slice((value.code as u32).to_le_bytes().as_slice());
        result
    }
}

impl LibError {
    pub fn new(code: LibErrorCode, message: Option<String>) -> Self {
        Self { code, message }
    }
}
