#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum LibErrorCode {
    DeserializeRequest = 100,
    CheckRoot = 200,
    DeserializeProof = 300,
    BuildMerkleProof = 301,
    CheckLeaf = 302,
    GetFirstHardLeaf = 303,
    GetLastHardLeaf = 304,
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
