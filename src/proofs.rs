//! Signed proof payloads and proof of work.

use sha2::{Digest, Sha256};

use crate::canonical::join_array;
use crate::encoding::b64url_encode;

pub const PROTOCOL: &str = "nethernet-external-signaling-v1";
pub const SIGNATURE: &str = "nxs-es384-v1";

#[derive(Debug, Clone, Copy)]
pub struct CompleteInput<'a> {
    pub audience: &'a str,
    pub challenge_id: &'a str,
    pub nonce: &'a str,
    pub thumbprint: &'a str,
    pub context_digest: &'a str,
    pub expires_at: u64,
    pub proof_nonce: &'a str,
    pub idempotency_key: &'a str,
}

impl CompleteInput<'_> {
    pub fn payload(&self) -> String {
        join_array(&[
            PROTOCOL.into(),
            "complete".into(),
            self.audience.into(),
            self.challenge_id.into(),
            self.nonce.into(),
            self.thumbprint.into(),
            self.context_digest.into(),
            self.expires_at.into(),
            self.proof_nonce.into(),
            self.idempotency_key.into(),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct OperationInput<'a> {
    pub audience: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub timestamp: u64,
    pub instance_id: &'a str,
    pub key_id: &'a str,
    pub idempotency_key: &'a str,
    pub generation: u64,
    pub sequence: u64,
    pub body: &'a [u8],
}

impl OperationInput<'_> {
    pub fn payload(&self) -> String {
        join_array(&[
            PROTOCOL.into(),
            SIGNATURE.into(),
            self.audience.into(),
            self.method.into(),
            self.path.into(),
            self.timestamp.into(),
            self.instance_id.into(),
            self.key_id.into(),
            self.idempotency_key.into(),
            self.generation.into(),
            self.sequence.into(),
            b64url_encode(&Sha256::digest(self.body)).into(),
        ])
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RotateInput<'a> {
    pub audience: &'a str,
    pub instance_id: &'a str,
    pub old_key_id: &'a str,
    pub new_thumbprint: &'a str,
    pub generation: u64,
    pub idempotency_key: &'a str,
}

impl RotateInput<'_> {
    pub fn payload(&self) -> String {
        join_array(&[
            PROTOCOL.into(),
            "rotate".into(),
            self.audience.into(),
            self.instance_id.into(),
            self.old_key_id.into(),
            self.new_thumbprint.into(),
            self.generation.into(),
            self.idempotency_key.into(),
        ])
    }
}

pub fn context_digest(
    mode: &str,
    label: &str,
    authorization_id: &str,
    service_id: &str,
    registration_id: &str,
) -> [u8; 32] {
    let payload = join_array(&[
        mode.into(),
        label.into(),
        authorization_id.into(),
        service_id.into(),
        registration_id.into(),
    ]);
    Sha256::digest(payload.as_bytes()).into()
}

pub fn count_leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
            continue;
        }
        count += byte.leading_zeros();
        break;
    }
    count
}

pub fn verify_pow(payload: &[u8], difficulty: u8) -> bool {
    difficulty <= 24 && count_leading_zero_bits(&Sha256::digest(payload)) >= u32::from(difficulty)
}

pub fn solve_pow<F>(difficulty: u8, mut make_payload: F) -> Option<(String, String)>
where
    F: FnMut(&str) -> String,
{
    if difficulty > 24 {
        return None;
    }
    for counter in 0..=u64::MAX {
        let nonce = counter.to_string();
        let payload = make_payload(&nonce);
        if verify_pow(payload.as_bytes(), difficulty) {
            return Some((nonce, payload));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(count_leading_zero_bits(&[0x00, 0x0f]), 12);
        assert_eq!(count_leading_zero_bits(&[0x80]), 0);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn difficulty_zero_always_passes() {
        assert!(verify_pow(b"anything", 0));
        assert!(!verify_pow(b"anything", 25));
    }
}
