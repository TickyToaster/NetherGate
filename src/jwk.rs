//! P-384 machine keys, RFC 7638 thumbprints and ES384 signatures.
//!
//! JWK members are canonical unpadded base64url. Signatures use the 96-byte
//! IEEE-P1363 `r || s` form, also unpadded base64url.

use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{
    EncodingError, b64_standard_decode_any, b64_standard_encode, b64url_decode_fixed, b64url_encode,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, thiserror::Error)]
pub enum JwkError {
    #[error("invalid JWK")]
    Invalid,
    #[error("invalid base64: {0}")]
    Encoding(#[from] EncodingError),
    #[error("invalid key material")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
}

impl PublicJwk {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, JwkError> {
        let jwk: Self = serde_json::from_value(value.clone()).map_err(|_| JwkError::Invalid)?;
        jwk.validate()?;
        Ok(jwk)
    }

    pub fn validate(&self) -> Result<(), JwkError> {
        if self.kty != "EC" || self.crv != "P-384" {
            return Err(JwkError::Invalid);
        }
        b64url_decode_fixed::<48>(&self.x)?;
        b64url_decode_fixed::<48>(&self.y)?;
        Ok(())
    }

    pub fn thumbprint(&self) -> Result<[u8; 32], JwkError> {
        self.validate()?;
        let canonical = format!(
            "{{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.x, self.y
        );
        Ok(Sha256::digest(canonical.as_bytes()).into())
    }

    pub fn thumbprint_b64url(&self) -> Result<String, JwkError> {
        Ok(b64url_encode(&self.thumbprint()?))
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, JwkError> {
        self.validate()?;
        let x = b64url_decode_fixed::<48>(&self.x)?;
        let y = b64url_decode_fixed::<48>(&self.y)?;
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..49].copy_from_slice(&x);
        sec1[49..97].copy_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| JwkError::InvalidKey)
    }
}

pub fn sign_es384(private_d: &str, payload: &[u8]) -> Result<[u8; 96], JwkError> {
    let d = b64url_decode_fixed::<48>(private_d)?;
    let signing_key = SigningKey::from_slice(&d).map_err(|_| JwkError::InvalidKey)?;
    let signature: Signature = signing_key.sign(payload);
    let bytes = signature.to_bytes();
    let mut output = [0u8; 96];
    output.copy_from_slice(&bytes);
    Ok(output)
}

pub fn verify_es384(jwk: &PublicJwk, payload: &[u8], signature: &[u8]) -> Result<(), JwkError> {
    let verifying_key = jwk.verifying_key()?;
    let signature = Signature::from_slice(signature).map_err(|_| JwkError::InvalidSignature)?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| JwkError::InvalidSignature)
}

impl PublicJwk {
    pub fn canonical_cpk(&self) -> Result<String, JwkError> {
        let x = b64url_decode_fixed::<48>(&self.x)?;
        let y = b64url_decode_fixed::<48>(&self.y)?;
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..49].copy_from_slice(&x);
        sec1[49..97].copy_from_slice(&y);
        let key = p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| JwkError::InvalidKey)?;
        let der = key.to_public_key_der().map_err(|_| JwkError::InvalidKey)?;
        Ok(b64_standard_encode(der.as_bytes()))
    }
}

pub fn canonical_cpk_from_spki_b64(input: &str) -> Result<String, JwkError> {
    let der = b64_standard_decode_any(input)?;
    let key = p384::PublicKey::from_public_key_der(&der).map_err(|_| JwkError::InvalidKey)?;
    let der = key.to_public_key_der().map_err(|_| JwkError::InvalidKey)?;
    Ok(b64_standard_encode(der.as_bytes()))
}

pub fn generate_keypair() -> Result<(PublicJwk, String), JwkError> {
    loop {
        let bytes: [u8; 48] = rand::random();
        let Ok(signing_key) = SigningKey::from_slice(&bytes) else {
            continue;
        };
        let point = signing_key.verifying_key().to_sec1_point(false);
        let x = point.x().ok_or(JwkError::InvalidKey)?;
        let y = point.y().ok_or(JwkError::InvalidKey)?;
        let jwk = PublicJwk {
            kty: "EC".to_owned(),
            crv: "P-384".to_owned(),
            x: b64url_encode(x),
            y: b64url_encode(y),
        };
        let d = b64url_encode(&signing_key.to_bytes());
        return Ok((jwk, d));
    }
}
