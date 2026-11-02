//! Stateless admission sealing and derivation.
//!
//! AES-256-GCM protects the token body carried in the ICE username. The key is
//! derived from the ASCII bytes of the 43-character admission key, not from its
//! base64url decoding. The token body uses the standard base64 alphabet without
//! padding; JWK and signature material use base64url.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::encoding::{EncodingError, b64_standard_decode, b64_standard_encode};

type HmacSha256 = Hmac<Sha256>;

const CARRIER_PREFIX: &str = "NXS1";
const FIXED_PLAINTEXT_LEN: usize = 67;
const MIN_ICE_PWD: usize = 22;
const MAX_ICE_PWD: usize = 91;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("invalid admission key id")]
    InvalidKeyId,
    #[error("invalid admission secret")]
    InvalidSecret,
    #[error("invalid audience")]
    InvalidAudience,
    #[error("invalid claims: {0}")]
    InvalidClaims(&'static str),
    #[error("invalid base64: {0}")]
    Encoding(#[from] EncodingError),
    #[error("invalid token")]
    InvalidToken,
    #[error("token authentication failed")]
    Authentication,
}

#[derive(Debug, Clone, Copy)]
pub struct AdmissionContext<'a> {
    pub key_id: &'a str,
    pub secret: &'a str,
    pub audience: &'a str,
}

impl AdmissionContext<'_> {
    pub fn validate(&self) -> Result<(), AdmissionError> {
        if self.key_id.len() != 4
            || !self
                .key_id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return Err(AdmissionError::InvalidKeyId);
        }
        if self.secret.len() != 43
            || !self
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AdmissionError::InvalidSecret);
        }
        let incarnation = self
            .audience
            .strip_prefix("nxs-stateless-host-v1/")
            .ok_or(AdmissionError::InvalidAudience)?;
        if incarnation.len() != 32
            || !incarnation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AdmissionError::InvalidAudience);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AdmissionClaims<'a> {
    pub expires_at_ms: u64,
    pub client_fingerprint: [u8; 32],
    pub client_sctp_port: u16,
    pub client_max_message_size: u32,
    pub identity_binding: [u8; 16],
    pub network_id: u64,
    pub client_ice_pwd: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedAdmission {
    pub expires_at_ms: u64,
    pub client_fingerprint: [u8; 32],
    pub client_sctp_port: u16,
    pub client_max_message_size: u32,
    pub identity_binding: [u8; 16],
    pub network_id: u64,
    pub client_ice_pwd: String,
}

pub fn derive_aead_key(secret: &str, audience: &str) -> [u8; 32] {
    hmac_sha256(
        secret.as_bytes(),
        &[b"nxs-stateless-aead-v1", &[0], audience.as_bytes()],
    )
}

pub fn seal_token(
    context: &AdmissionContext<'_>,
    claims: &AdmissionClaims<'_>,
    client_ufrag: &str,
) -> Result<String, AdmissionError> {
    let nonce: [u8; NONCE_LEN] = rand::random();
    seal_token_with_nonce(context, claims, client_ufrag, &nonce)
}

pub fn seal_token_with_nonce(
    context: &AdmissionContext<'_>,
    claims: &AdmissionClaims<'_>,
    client_ufrag: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<String, AdmissionError> {
    context.validate()?;
    validate_claims(claims)?;

    let plaintext = encode_claims(claims)?;
    let header = format!("{CARRIER_PREFIX}{}", context.key_id);
    let aad = admission_aad(&header, context.audience, client_ufrag);
    let key = derive_aead_key(context.secret, context.audience);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AdmissionError::Authentication)?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AdmissionError::Authentication)?;

    let mut body = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    body.extend_from_slice(nonce);
    body.extend_from_slice(&ciphertext);

    Ok(format!("{header}{}", b64_standard_encode(&body)))
}

pub fn open_token(
    context: &AdmissionContext<'_>,
    answer_ufrag: &str,
    client_ufrag: &str,
) -> Result<OpenedAdmission, AdmissionError> {
    context.validate()?;

    let rest = answer_ufrag
        .strip_prefix(CARRIER_PREFIX)
        .ok_or(AdmissionError::InvalidToken)?;
    if rest.len() < 4 {
        return Err(AdmissionError::InvalidToken);
    }
    let (key_id, encoded) = rest.split_at(4);
    if key_id != context.key_id {
        return Err(AdmissionError::InvalidToken);
    }
    let body = b64_standard_decode(encoded)?;
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err(AdmissionError::InvalidToken);
    }
    let (nonce, ciphertext) = body.split_at(NONCE_LEN);

    let header = format!("{CARRIER_PREFIX}{}", context.key_id);
    let aad = admission_aad(&header, context.audience, client_ufrag);
    let key = derive_aead_key(context.secret, context.audience);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AdmissionError::Authentication)?;
    let plaintext = cipher
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| AdmissionError::InvalidToken)?,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| AdmissionError::Authentication)?;

    decode_claims(&plaintext)
}

pub fn derive_ice_pwd(secret: &str, audience: &str, answer_ufrag: &str) -> String {
    let digest = hmac_sha256(
        secret.as_bytes(),
        &[
            b"nxs-stateless-ice-v1",
            &[0],
            audience.as_bytes(),
            &[0],
            answer_ufrag.as_bytes(),
        ],
    );
    b64_standard_encode(&digest[..24])
}

pub fn identity_binding(secret: &str, audience: &str, canonical_cpk: &str) -> [u8; 16] {
    let digest = hmac_sha256(
        secret.as_bytes(),
        &[
            b"nxs-identity-binding-v1",
            &[0],
            audience.as_bytes(),
            &[0],
            canonical_cpk.as_bytes(),
        ],
    );
    let mut binding = [0u8; 16];
    binding.copy_from_slice(&digest[..16]);
    binding
}

pub fn ticket_correlation_id(answer_ufrag: &str) -> String {
    let digest = Sha256::digest(answer_ufrag.as_bytes());
    hex::encode(&digest[..16])
}

fn validate_claims(claims: &AdmissionClaims<'_>) -> Result<(), AdmissionError> {
    if !claims.expires_at_ms.is_multiple_of(1000)
        || claims.expires_at_ms / 1000 > u64::from(u32::MAX)
    {
        return Err(AdmissionError::InvalidClaims("expiry not representable"));
    }
    if claims.client_sctp_port == 0 {
        return Err(AdmissionError::InvalidClaims("invalid SCTP port"));
    }
    if !(1..=262_144).contains(&claims.client_max_message_size) {
        return Err(AdmissionError::InvalidClaims(
            "invalid maximum message size",
        ));
    }
    if claims.network_id == 0 {
        return Err(AdmissionError::InvalidClaims(
            "network id zero is reserved for diagnostics",
        ));
    }
    if !(MIN_ICE_PWD..=MAX_ICE_PWD).contains(&claims.client_ice_pwd.len())
        || !claims.client_ice_pwd.bytes().all(is_ice_char)
    {
        return Err(AdmissionError::InvalidClaims("invalid ICE password"));
    }
    Ok(())
}

fn encode_claims(claims: &AdmissionClaims<'_>) -> Result<Vec<u8>, AdmissionError> {
    let seconds = (claims.expires_at_ms / 1000) as u32;
    let pwd = claims.client_ice_pwd.as_bytes();
    let mut plaintext = vec![0u8; FIXED_PLAINTEXT_LEN + pwd.len()];
    plaintext[0..4].copy_from_slice(&seconds.to_be_bytes());
    plaintext[4..36].copy_from_slice(&claims.client_fingerprint);
    plaintext[36..38].copy_from_slice(&claims.client_sctp_port.to_be_bytes());
    plaintext[38..42].copy_from_slice(&claims.client_max_message_size.to_be_bytes());
    plaintext[42..58].copy_from_slice(&claims.identity_binding);
    plaintext[58..66].copy_from_slice(&claims.network_id.to_be_bytes());
    plaintext[66] = pwd.len() as u8;
    plaintext[67..].copy_from_slice(pwd);
    Ok(plaintext)
}

fn decode_claims(plaintext: &[u8]) -> Result<OpenedAdmission, AdmissionError> {
    if plaintext.len() < FIXED_PLAINTEXT_LEN {
        return Err(AdmissionError::InvalidToken);
    }
    let pwd_len = plaintext[66] as usize;
    if !(MIN_ICE_PWD..=MAX_ICE_PWD).contains(&pwd_len)
        || plaintext.len() != FIXED_PLAINTEXT_LEN + pwd_len
    {
        return Err(AdmissionError::InvalidToken);
    }
    let pwd = &plaintext[67..];
    if !pwd.iter().copied().all(is_ice_char) {
        return Err(AdmissionError::InvalidToken);
    }

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&plaintext[4..36]);
    let mut binding = [0u8; 16];
    binding.copy_from_slice(&plaintext[42..58]);
    let client_sctp_port = u16::from_be_bytes([plaintext[36], plaintext[37]]);
    if client_sctp_port == 0 {
        return Err(AdmissionError::InvalidToken);
    }
    let client_max_message_size =
        u32::from_be_bytes(plaintext[38..42].try_into().expect("four bytes"));
    if !(1..=262_144).contains(&client_max_message_size) {
        return Err(AdmissionError::InvalidToken);
    }
    let network_id = u64::from_be_bytes(plaintext[58..66].try_into().expect("eight bytes"));
    let expires_at_ms = u64::from(u32::from_be_bytes(
        plaintext[0..4].try_into().expect("four bytes"),
    )) * 1000;

    Ok(OpenedAdmission {
        expires_at_ms,
        client_fingerprint: fingerprint,
        client_sctp_port,
        client_max_message_size,
        identity_binding: binding,
        network_id,
        client_ice_pwd: String::from_utf8(pwd.to_vec())
            .map_err(|_| AdmissionError::InvalidToken)?,
    })
}

fn is_ice_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn admission_aad(header: &str, audience: &str, client_ufrag: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"nxs-stateless-admission-v1");
    aad.push(0);
    aad.extend_from_slice(header.as_bytes());
    aad.push(0);
    aad.extend_from_slice(audience.as_bytes());
    aad.push(0);
    aad.extend_from_slice(client_ufrag.as_bytes());
    aad
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
