use base64::Engine;

#[inline]
pub(crate) fn b64_std_encode<T: AsRef<[u8]>>(data: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[inline]
pub(crate) fn b64_std_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}
