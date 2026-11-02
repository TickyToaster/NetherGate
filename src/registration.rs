use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::api::AppState;
use crate::encoding::{b64url_decode_fixed, b64url_encode};
use crate::error::ProviderError;
use crate::jwk::{PublicJwk, verify_es384};
use crate::proofs::{CompleteInput, PROTOCOL, SIGNATURE, context_digest, verify_pow};
use crate::store::{ChallengeRecord, InstanceRecord, NewChallenge, NewService, now_ms};

const CHALLENGE_TTL_MS: i64 = 120_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub protocol: String,
    pub public_key_jwk: Value,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub registration_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteRequest {
    pub protocol: String,
    pub challenge_id: String,
    pub proof_nonce: String,
    pub idempotency_key: String,
    pub signature: String,
}

pub async fn register(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<Value>, ProviderError> {
    let request: RegisterRequest = parse_body(&body, "register")?;
    validate_protocol(&request.protocol)?;
    if request.public_key_jwk.get("d").is_some() {
        return Err(ProviderError::InvalidRequest(
            "publicKeyJwk must not contain d".to_owned(),
        ));
    }
    let jwk = PublicJwk::from_json(&request.public_key_jwk)
        .map_err(|_| ProviderError::InvalidRequest("invalid publicKeyJwk".to_owned()))?;
    let thumbprint = jwk
        .thumbprint_b64url()
        .map_err(|_| ProviderError::InvalidRequest("invalid publicKeyJwk".to_owned()))?;

    let now = now_ms();
    let expires_at = now + CHALLENGE_TTL_MS;
    let (mode, label, service_id, registration_id, instance_id, pow_difficulty) =
        if let Some(reference) = request.registration_id.as_deref() {
            let instance = recoverable_instance(&state, reference)?;
            let stored =
                PublicJwk::from_json(&serde_json::from_str(&instance.public_jwk).map_err(
                    |_| ProviderError::Internal(anyhow::anyhow!("stored JWK is invalid")),
                )?)
                .map_err(|_| ProviderError::Internal(anyhow::anyhow!("stored JWK is invalid")))?;
            if stored.thumbprint_b64url().ok().as_deref() != Some(thumbprint.as_str()) {
                return Err(ProviderError::RecoveryUnavailable);
            }
            (
                "recover",
                instance.label.unwrap_or_default(),
                instance.service_id.unwrap_or_default(),
                instance.registration_id,
                Some(instance.instance_id),
                0,
            )
        } else {
            let label = request.label.unwrap_or_default();
            validate_label(&label)?;
            (
                "new-service",
                label,
                String::new(),
                String::new(),
                None,
                state.config.pow_difficulty,
            )
        };

    let challenge_id = random_id("challenge_");
    let nonce = random_nonce();
    let audience = state.config.public_origin.clone();
    let context = json!({
        "mode": mode,
        "label": label,
        "authorizationId": "",
        "serviceId": service_id,
        "registrationId": registration_id,
    });
    let digest = context_digest(mode, &label, "", &service_id, &registration_id);

    state.store.add_challenge(&NewChallenge {
        challenge_id: challenge_id.clone(),
        registration_id: (!registration_id.is_empty()).then(|| registration_id.clone()),
        instance_id: instance_id.clone(),
        mode: mode.to_owned(),
        nonce: nonce.clone(),
        audience: audience.clone(),
        thumbprint: thumbprint.clone(),
        public_jwk: serde_json::to_string(&request.public_key_jwk)
            .map_err(|error| ProviderError::Internal(error.into()))?,
        context_json: serde_json::to_string(&context)
            .map_err(|error| ProviderError::Internal(error.into()))?,
        context_digest: b64url_encode(&digest),
        pow_difficulty,
        authorization_id: String::new(),
        expires_at,
        server_time: now,
    })?;

    Ok(Json(json!({
        "protocol": PROTOCOL,
        "signature": SIGNATURE,
        "challengeId": challenge_id,
        "nonce": nonce,
        "audience": audience,
        "thumbprint": thumbprint,
        "context": context,
        "contextDigest": b64url_encode(&digest),
        "expiresAt": expires_at,
        "serverTime": now,
        "pow": { "difficulty": pow_difficulty },
    })))
}

pub async fn complete(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<Value>, ProviderError> {
    let request: CompleteRequest = parse_body(&body, "complete")?;
    validate_protocol(&request.protocol)?;
    validate_idempotency_key(&request.idempotency_key)?;
    if request.proof_nonce.chars().count() > 128 {
        return Err(ProviderError::InvalidRequest(
            "proofNonce is too long".to_owned(),
        ));
    }

    let challenge = state
        .store
        .challenge(&request.challenge_id)?
        .ok_or_else(|| ProviderError::InvalidRequest("unknown challenge".to_owned()))?;

    if challenge.consumed_at.is_some() {
        return Err(ProviderError::RecoveryRequired);
    }
    let now = now_ms();
    if now > challenge.expires_at {
        return Err(ProviderError::InvalidRequest(
            "challenge expired".to_owned(),
        ));
    }

    let payload = complete_payload(&challenge, &request.proof_nonce, &request.idempotency_key);
    if !verify_pow(payload.as_bytes(), challenge.pow_difficulty) {
        return Err(ProviderError::InvalidRequest(
            "proof of work does not meet difficulty".to_owned(),
        ));
    }

    let jwk = PublicJwk::from_json(
        &serde_json::from_str(&challenge.public_jwk)
            .map_err(|_| ProviderError::Internal(anyhow::anyhow!("stored JWK is invalid")))?,
    )
    .map_err(|_| ProviderError::Internal(anyhow::anyhow!("stored JWK is invalid")))?;
    let signature = b64url_decode_fixed::<96>(&request.signature)
        .map_err(|_| ProviderError::InvalidRequest("invalid signature encoding".to_owned()))?;
    verify_es384(&jwk, payload.as_bytes(), &signature)
        .map_err(|_| ProviderError::InvalidRequest("invalid signature".to_owned()))?;

    match challenge.mode.as_str() {
        "new-service" => {
            let service_id = random_id("svc_");
            let instance_id = random_id("inst_");
            let registration_id = random_id("reg_");
            let key_id = random_id("key_");
            let label = context_label(&challenge);

            state.store.finish_new_service(NewService {
                challenge_id: &challenge.challenge_id,
                now,
                service_id: &service_id,
                instance_id: &instance_id,
                registration_id: &registration_id,
                key_id: &key_id,
                label: &label,
            })?;

            Ok(Json(json!({
                "protocol": PROTOCOL,
                "provider": state.config.public_origin,
                "registrationId": registration_id,
                "instanceId": instance_id,
                "keyId": key_id,
                "leaseGeneration": 1,
                "extensions": {},
            })))
        }
        "recover" => {
            let instance_id = challenge
                .instance_id
                .clone()
                .ok_or(ProviderError::RecoveryUnavailable)?;
            let instance = state
                .store
                .instance_by_id(&instance_id)?
                .ok_or(ProviderError::RecoveryUnavailable)?;
            if instance.status != "active" {
                return Err(ProviderError::RecoveryUnavailable);
            }

            let lease_generation =
                state
                    .store
                    .finish_recovery(&challenge.challenge_id, now, &instance_id)?;

            Ok(Json(json!({
                "protocol": PROTOCOL,
                "provider": state.config.public_origin,
                "registrationId": instance.registration_id,
                "instanceId": instance.instance_id,
                "keyId": instance.key_id,
                "leaseGeneration": lease_generation,
                "extensions": {},
            })))
        }
        _ => Err(ProviderError::InvalidRequest(
            "unsupported challenge mode".to_owned(),
        )),
    }
}

fn complete_payload(
    challenge: &ChallengeRecord,
    proof_nonce: &str,
    idempotency_key: &str,
) -> String {
    CompleteInput {
        audience: &challenge.audience,
        challenge_id: &challenge.challenge_id,
        nonce: &challenge.nonce,
        thumbprint: &challenge.thumbprint,
        context_digest: &challenge.context_digest,
        expires_at: challenge.expires_at as u64,
        proof_nonce,
        idempotency_key,
    }
    .payload()
}

fn recoverable_instance(
    state: &AppState,
    reference: &str,
) -> Result<InstanceRecord, ProviderError> {
    let instance = match state.store.instance_by_registration(reference)? {
        Some(instance) => Some(instance),
        None => {
            let registration_id = state.store.registration_for_challenge(reference)?;
            match registration_id {
                Some(registration_id) => state.store.instance_by_registration(&registration_id)?,
                None => None,
            }
        }
    };

    match instance {
        Some(instance) if instance.status == "active" => Ok(instance),
        _ => Err(ProviderError::RecoveryUnavailable),
    }
}

fn context_label(challenge: &ChallengeRecord) -> String {
    serde_json::from_str::<Value>(&challenge.context_json)
        .ok()
        .and_then(|context| context["label"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn validate_protocol(protocol: &str) -> Result<(), ProviderError> {
    if protocol == PROTOCOL {
        Ok(())
    } else {
        Err(ProviderError::InvalidRequest(
            "unsupported protocol".to_owned(),
        ))
    }
}

fn validate_label(label: &str) -> Result<(), ProviderError> {
    if label.chars().count() > 128 || has_control_characters(label) {
        return Err(ProviderError::InvalidRequest("invalid label".to_owned()));
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), ProviderError> {
    let length = value.chars().count();
    if !(16..=128).contains(&length)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProviderError::InvalidRequest(
            "invalid idempotencyKey".to_owned(),
        ));
    }
    Ok(())
}

fn has_control_characters(value: &str) -> bool {
    value
        .chars()
        .any(|character| matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f))
}

fn random_id(prefix: &str) -> String {
    let bytes: [u8; 16] = rand::random();
    format!("{prefix}{}", hex::encode(bytes))
}

fn random_nonce() -> String {
    let bytes: [u8; 12] = rand::random();
    b64url_encode(&bytes)
}

fn parse_body<T: DeserializeOwned>(body: &[u8], operation: &str) -> Result<T, ProviderError> {
    serde_json::from_slice(body).map_err(|error| {
        let preview: String = String::from_utf8_lossy(body).chars().take(1024).collect();
        tracing::warn!(%operation, body = %preview, %error, "invalid request body");
        ProviderError::InvalidRequest("invalid request body".to_owned())
    })
}
