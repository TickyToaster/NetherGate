//! Base64 helpers that reject noncanonical encodings.
//!
//! Two alphabets are in play: JWK and signature material are unpadded base64url,
//! while the admission token body is standard base64.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncodingError {
    #[error("invalid base64")]
    Invalid,
    #[error("noncanonical base64")]
    NonCanonical,
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(input: &str) -> Result<Vec<u8>, EncodingError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| EncodingError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != input {
        return Err(EncodingError::NonCanonical);
    }
    Ok(decoded)
}

pub fn b64url_decode_fixed<const N: usize>(input: &str) -> Result<[u8; N], EncodingError> {
    let decoded = b64url_decode(input)?;
    decoded.try_into().map_err(|_| EncodingError::Invalid)
}

pub fn b64_standard_encode(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

pub fn b64_standard_encode_padded(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_standard_decode_any(input: &str) -> Result<Vec<u8>, EncodingError> {
    if input.contains('=') {
        STANDARD.decode(input).map_err(|_| EncodingError::Invalid)
    } else {
        STANDARD_NO_PAD
            .decode(input)
            .map_err(|_| EncodingError::Invalid)
    }
}

pub fn b64_standard_decode(input: &str) -> Result<Vec<u8>, EncodingError> {
    if input.contains('=') {
        return Err(EncodingError::Invalid);
    }
    let decoded = STANDARD_NO_PAD
        .decode(input)
        .map_err(|_| EncodingError::Invalid)?;
    if STANDARD_NO_PAD.encode(&decoded) != input {
        return Err(EncodingError::NonCanonical);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_padding_and_wrong_alphabet() {
        assert_eq!(b64url_decode("YQ=="), Err(EncodingError::Invalid));
        assert_eq!(b64url_decode("YQ"), Ok(vec![b'a']));
        assert_eq!(b64url_decode("YQ+"), Err(EncodingError::Invalid));
        assert_eq!(b64_standard_decode("YQ=="), Err(EncodingError::Invalid));
        assert_eq!(b64_standard_decode("YQ"), Ok(vec![b'a']));
    }
}
