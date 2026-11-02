use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::AppState;
use crate::encoding::{b64url_decode_fixed, b64url_encode};
use crate::error::ProviderError;
use crate::jwk::{PublicJwk, verify_es384};
use crate::proofs::{OperationInput, SIGNATURE};
use crate::store::{
    HeartbeatUpdate, HostProfileInput, InstanceRecord, MintOutcome, RequestDecision, RequestMeta,
    now_ms,
};

const HEARTBEAT_AFTER_MS: i64 = 5_000;
const HEARTBEAT_LEASE_MS: i64 = 15_000;
const HEARTBEAT_MIN_UPDATE_MS: i64 = 1_000;
const MAX_CLOCK_SKEW_MS: i64 = 60_000;
const ADMISSION_KEY_OVERLAP_MS: i64 = 300_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatRequest {
    accepting_players: bool,
    capacity: u64,
    connected_players: ConnectedPlayers,
    #[serde(default)]
    host_profile: Option<Value>,
    #[serde(default)]
    host_profile_revision: Option<String>,
    #[serde(default)]
    installed_admission_key_ids: Option<Vec<String>>,
    #[serde(default)]
    admission_key_request_id: Option<String>,
    #[serde(default)]
    software: Option<Value>,
    #[serde(default)]
    location: Option<Value>,
    #[serde(default)]
    bedrock_protocols: Option<BedrockProtocols>,
    #[serde(default)]
    server_status: Option<ServerStatus>,
    #[serde(default)]
    game_outcomes: Option<String>,
    #[serde(default)]
    extensions: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectedPlayers {
    count: u64,
    sampled_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerStatus {
    name: String,
    level: String,
    max_player_count: u64,
    game_type: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BedrockProtocols {
    accepted: Vec<u32>,
    version: String,
}

struct Authenticated {
    instance: InstanceRecord,
    generation: i64,
    sequence: i64,
    idempotency_key: String,
    request_hash: String,
    timestamp: i64,
}

struct ProfileFields {
    incarnation: String,
    admission_key_id: String,
    dtls_fingerprint: String,
    sctp_port: i64,
    max_message_size: i64,
}

pub async fn heartbeat(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ProviderError> {
    let authenticated = authenticate(&state, &method, &uri, &headers, &body)?;

    let request: HeartbeatRequest = serde_json::from_slice(&body).map_err(|error| {
        let preview: String = String::from_utf8_lossy(&body).chars().take(1024).collect();
        tracing::warn!(body = %preview, %error, "invalid heartbeat body");
        ProviderError::InvalidRequest("invalid heartbeat body".to_owned())
    })?;
    validate_heartbeat(&request, authenticated.timestamp)?;

    let now = now_ms();
    let (profile_revision, profile) = resolve_profile(&state, &request, &authenticated.instance)?;

    let decision = state
        .store
        .accept_request(RequestMeta {
            instance_id: &authenticated.instance.instance_id,
            lease_generation: authenticated.generation,
            sequence: authenticated.sequence,
            idempotency_key: &authenticated.idempotency_key,
            operation: "heartbeat",
            request_hash: &authenticated.request_hash,
            now,
        })
        .map_err(ProviderError::from)?;

    match decision {
        RequestDecision::Replay(response) => {
            let value = serde_json::from_str(&response)
                .map_err(|error| ProviderError::Internal(error.into()))?;
            return Ok(Json(value));
        }
        RequestDecision::InFlight => {
            return Err(ProviderError::InvalidRequest(
                "request is still in flight".to_owned(),
            ));
        }
        RequestDecision::Accepted => {}
    }

    let admission_request = match &request.admission_key_request_id {
        Some(request_id) => {
            let outcome = state.store.mint_admission_key(
                &authenticated.instance.instance_id,
                request_id,
                now,
            )?;
            match outcome {
                MintOutcome::New { key_id, secret } => {
                    Some((request_id.clone(), key_id, Some(secret)))
                }
                MintOutcome::Existing { key_id } => Some((request_id.clone(), key_id, None)),
            }
        }
        None => None,
    };

    let reported_keys = request
        .installed_admission_key_ids
        .clone()
        .unwrap_or_default();
    let ack = state.store.acknowledge_admission_keys(
        &authenticated.instance.instance_id,
        &reported_keys,
        now,
        ADMISSION_KEY_OVERLAP_MS,
    )?;

    if let (Some(profile), Some(revision)) = (&profile, &profile_revision) {
        state.store.store_profile(
            &HostProfileInput {
                instance_id: authenticated.instance.instance_id.clone(),
                revision: revision.clone(),
                incarnation: profile.incarnation.clone(),
                admission_key_id: profile.admission_key_id.clone(),
                dtls_fingerprint: profile.dtls_fingerprint.clone(),
                sctp_port: profile.sctp_port,
                max_message_size: profile.max_message_size,
                profile_json: serde_json::to_string(&request.host_profile)
                    .map_err(|error| ProviderError::Internal(error.into()))?,
            },
            now,
        )?;
    }

    let profile_key = match (&profile, &profile_revision) {
        (Some(profile), _) => Some(profile.admission_key_id.clone()),
        (None, Some(revision)) => state
            .store
            .profile_admission_key_id(&authenticated.instance.instance_id, revision)?,
        (None, None) => None,
    };

    let mut reasons = Vec::new();
    if !request.accepting_players {
        reasons.push("not_accepting");
    }
    if profile_revision.is_none() {
        reasons.push("profile_missing");
    }
    match (&profile_key, &ack.active_key) {
        (Some(profile_key), Some(active_key)) if profile_key == active_key => {
            if !state
                .store
                .key_is_active(&authenticated.instance.instance_id, profile_key)?
            {
                reasons.push("admission_key_not_active");
            }
        }
        (Some(_), Some(_)) => reasons.push("admission_key_mismatch"),
        (Some(_), None) => reasons.push("admission_key_missing"),
        (None, _) => {}
    }
    let routable = reasons.is_empty();

    state.store.record_heartbeat(&HeartbeatUpdate {
        instance_id: authenticated.instance.instance_id.clone(),
        lease_generation: authenticated.generation,
        profile_revision: profile_revision.clone(),
        routable,
        accepting_players: request.accepting_players,
        capacity: request.capacity as i64,
        connected_players: request.connected_players.count as i64,
        sampled_at: request.connected_players.sampled_at,
        listing_name: request
            .server_status
            .as_ref()
            .map(|value| value.name.clone()),
        listing_level: request
            .server_status
            .as_ref()
            .map(|value| value.level.clone()),
        listing_max_players: request
            .server_status
            .as_ref()
            .map(|value| value.max_player_count as i64),
        listing_game_type: request
            .server_status
            .as_ref()
            .map(|value| value.game_type as i64),
        listing_protocol: request
            .bedrock_protocols
            .as_ref()
            .and_then(|value| value.accepted.last().copied())
            .map(i64::from),
        listing_version: request
            .bedrock_protocols
            .as_ref()
            .map(|value| value.version.clone()),
        now,
        lease_ms: HEARTBEAT_LEASE_MS,
    })?;

    let mut response = json!({
        "hostProfileRevision": profile_revision,
        "readiness": {
            "routable": routable,
            "reasons": reasons,
        },
        "admissionKeyRetirements": ack.retirements.iter().map(|(key_id, retire_after)| {
            json!({ "keyId": key_id, "retireAfter": retire_after })
        }).collect::<Vec<_>>(),
        "checkIn": {
            "afterMillis": HEARTBEAT_AFTER_MS,
            "leaseMillis": HEARTBEAT_LEASE_MS,
            "minUpdateIntervalMillis": HEARTBEAT_MIN_UPDATE_MS,
        },
        "extensions": {},
    });

    if let Some((request_id, key_id, secret)) = &admission_request {
        response["admissionKeyRequest"] = json!({
            "id": request_id,
            "keyId": key_id,
        });
        if let Some(secret) = secret {
            response["admissionKey"] = json!({
                "keyId": key_id,
                "secret": secret,
            });
        }
    }

    let mut replay_response = response.clone();
    if let Some(object) = replay_response.as_object_mut() {
        object.remove("admissionKey");
    }
    let response_json = serde_json::to_string(&replay_response)
        .map_err(|error| ProviderError::Internal(error.into()))?;
    state.store.store_request_response(
        &authenticated.instance.instance_id,
        &authenticated.idempotency_key,
        &response_json,
    )?;
    Ok(Json(response))
}

fn authenticate(
    state: &AppState,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Authenticated, ProviderError> {
    let instance_id = header(headers, "nxs-instance-id")?;
    let key_id = header(headers, "nxs-key-id")?;
    let timestamp = parse_i64(header(headers, "nxs-timestamp")?, "nxs-timestamp")?;
    let signature_version = header(headers, "nxs-signature-version")?;
    let generation = parse_i64(header(headers, "nxs-generation")?, "nxs-generation")?;
    let sequence = parse_i64(header(headers, "nxs-sequence")?, "nxs-sequence")?;
    let signature = header(headers, "nxs-signature")?;
    let idempotency_key = header(headers, "idempotency-key")?;

    if signature_version != SIGNATURE {
        return Err(ProviderError::InvalidRequest(
            "unsupported signature version".to_owned(),
        ));
    }
    validate_idempotency_key(idempotency_key)?;
    if generation < 1 || sequence < 1 {
        return Err(ProviderError::InvalidRequest(
            "generation and sequence must be positive".to_owned(),
        ));
    }

    let now = now_ms();
    if (now - timestamp).abs() > MAX_CLOCK_SKEW_MS {
        return Err(ProviderError::InvalidRequest(
            "timestamp outside allowed skew".to_owned(),
        ));
    }

    let instance = state
        .store
        .instance_by_id(instance_id)?
        .ok_or(ProviderError::InvalidRequest("unknown instance".to_owned()))?;
    if instance.status != "active" {
        return Err(ProviderError::InvalidRequest(
            "inactive instance".to_owned(),
        ));
    }
    if instance.key_id != key_id {
        return Err(ProviderError::InvalidRequest("unknown key id".to_owned()));
    }
    if state.store.latest_generation(instance_id)? != Some(generation) {
        return Err(ProviderError::GenerationFenced);
    }

    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let operation = OperationInput {
        audience: &state.config.public_origin,
        method: method.as_str(),
        path,
        timestamp: timestamp as u64,
        instance_id,
        key_id,
        idempotency_key,
        generation: generation as u64,
        sequence: sequence as u64,
        body,
    };
    let payload = operation.payload();

    let jwk = PublicJwk::from_json(
        &serde_json::from_str(&instance.public_jwk)
            .map_err(|_| ProviderError::Internal(anyhow::anyhow!("stored JWK is invalid")))?,
    )
    .map_err(|_| ProviderError::Internal(anyhow::anyhow!("stored JWK is invalid")))?;
    let signature = b64url_decode_fixed::<96>(signature)
        .map_err(|_| ProviderError::InvalidRequest("invalid signature encoding".to_owned()))?;
    verify_es384(&jwk, payload.as_bytes(), &signature)
        .map_err(|_| ProviderError::InvalidRequest("invalid signature".to_owned()))?;

    let request_hash = hex::encode(Sha256::digest(payload.as_bytes()));
    Ok(Authenticated {
        instance,
        generation,
        sequence,
        idempotency_key: idempotency_key.to_owned(),
        request_hash,
        timestamp,
    })
}

fn validate_heartbeat(
    request: &HeartbeatRequest,
    request_timestamp: i64,
) -> Result<(), ProviderError> {
    if request.capacity > 1_000_000 {
        return Err(ProviderError::InvalidRequest("invalid capacity".to_owned()));
    }
    if request.connected_players.count > 1_000_000 {
        return Err(ProviderError::InvalidRequest(
            "invalid connected player count".to_owned(),
        ));
    }
    if request.connected_players.sampled_at > request_timestamp {
        return Err(ProviderError::InvalidRequest(
            "sampledAt is after the request timestamp".to_owned(),
        ));
    }
    if let Some(keys) = &request.installed_admission_key_ids {
        if keys.len() > 8 {
            return Err(ProviderError::InvalidRequest(
                "too many installed admission keys".to_owned(),
            ));
        }
        let mut seen = HashSet::new();
        for key in keys {
            if key.len() != 4
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                || !seen.insert(key)
            {
                return Err(ProviderError::InvalidRequest(
                    "invalid installed admission key id".to_owned(),
                ));
            }
        }
    }
    if let Some(request_id) = &request.admission_key_request_id {
        validate_idempotency_key(request_id).map_err(|_| {
            ProviderError::InvalidRequest("invalid admissionKeyRequestId".to_owned())
        })?;
    }
    if let Some(revision) = &request.host_profile_revision
        && (revision.is_empty() || revision.len() > 184)
    {
        return Err(ProviderError::InvalidRequest(
            "invalid hostProfileRevision".to_owned(),
        ));
    }
    if let Some(status) = &request.server_status
        && (status.name.is_empty()
            || status.name.chars().count() > 128
            || has_control_characters(&status.name)
            || status.level.chars().count() > 128
            || has_control_characters(&status.level)
            || status.max_player_count > 1_000_000
            || status.game_type > 2)
    {
        return Err(ProviderError::InvalidRequest(
            "invalid serverStatus".to_owned(),
        ));
    }
    if let Some(protocols) = &request.bedrock_protocols
        && (protocols.accepted.is_empty()
            || protocols.accepted.len() > 512
            || protocols.accepted.windows(2).any(|pair| pair[0] >= pair[1])
            || protocols.accepted.contains(&0)
            || protocols.version.is_empty()
            || protocols.version.chars().count() > 64
            || has_control_characters(&protocols.version))
    {
        return Err(ProviderError::InvalidRequest(
            "invalid bedrockProtocols".to_owned(),
        ));
    }
    let _ = (
        &request.software,
        &request.location,
        &request.game_outcomes,
        &request.extensions,
    );
    Ok(())
}

fn resolve_profile(
    state: &AppState,
    request: &HeartbeatRequest,
    instance: &InstanceRecord,
) -> Result<(Option<String>, Option<ProfileFields>), ProviderError> {
    if let Some(profile) = &request.host_profile {
        let fields = validate_host_profile(profile)?;
        let revision = profile_revision(profile);
        return Ok((Some(revision), Some(fields)));
    }

    if let Some(revision) = &request.host_profile_revision {
        if !state
            .store
            .profile_revision_exists(&instance.instance_id, revision)?
        {
            return Err(ProviderError::InvalidRequest(
                "unknown hostProfileRevision".to_owned(),
            ));
        }
        return Ok((Some(revision.clone()), None));
    }

    Ok((
        state.store.lease_profile_revision(&instance.instance_id)?,
        None,
    ))
}

fn validate_host_profile(profile: &Value) -> Result<ProfileFields, ProviderError> {
    let object = profile
        .as_object()
        .ok_or_else(|| ProviderError::InvalidRequest("invalid hostProfile".to_owned()))?;

    let candidates = object
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| ProviderError::InvalidRequest("missing candidates".to_owned()))?;
    if candidates.len() > 32 {
        return Err(ProviderError::InvalidRequest(
            "too many candidates".to_owned(),
        ));
    }
    for candidate in candidates {
        validate_candidate(candidate)?;
    }

    let dtls_fingerprint = object
        .get("dtlsFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::InvalidRequest("missing dtlsFingerprint".to_owned()))?;
    if !valid_dtls_fingerprint(dtls_fingerprint) {
        return Err(ProviderError::InvalidRequest(
            "invalid dtlsFingerprint".to_owned(),
        ));
    }

    let admission_key_id = object
        .get("admissionKeyId")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::InvalidRequest("missing admissionKeyId".to_owned()))?;
    if admission_key_id.len() != 4
        || !admission_key_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(ProviderError::InvalidRequest(
            "invalid admissionKeyId".to_owned(),
        ));
    }

    let sctp_port = object
        .get("sctpPort")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProviderError::InvalidRequest("missing sctpPort".to_owned()))?;
    if !(1..=65535).contains(&sctp_port) {
        return Err(ProviderError::InvalidRequest("invalid sctpPort".to_owned()));
    }
    let max_message_size = object
        .get("maxMessageSize")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProviderError::InvalidRequest("missing maxMessageSize".to_owned()))?;
    if !(1..=262_144).contains(&max_message_size) {
        return Err(ProviderError::InvalidRequest(
            "invalid maxMessageSize".to_owned(),
        ));
    }

    let stateless = object
        .get("statelessAdmission")
        .and_then(Value::as_object)
        .ok_or_else(|| ProviderError::InvalidRequest("missing statelessAdmission".to_owned()))?;
    let capability = stateless
        .get("capability")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::InvalidRequest("missing capability".to_owned()))?;
    if capability != "nethernet.stateless-admission.v1" {
        return Err(ProviderError::InvalidRequest(
            "unsupported stateless capability".to_owned(),
        ));
    }
    let incarnation = stateless
        .get("incarnation")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::InvalidRequest("missing incarnation".to_owned()))?;
    if incarnation.len() != 32
        || !incarnation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderError::InvalidRequest(
            "invalid incarnation".to_owned(),
        ));
    }
    if let Some(families) = stateless.get("assistedFamilies") {
        let families = families
            .as_array()
            .ok_or_else(|| ProviderError::InvalidRequest("invalid assistedFamilies".to_owned()))?;
        if families.is_empty()
            || families
                .iter()
                .any(|family| !matches!(family.as_u64(), Some(4 | 6)))
        {
            return Err(ProviderError::InvalidRequest(
                "invalid assistedFamilies".to_owned(),
            ));
        }
    }

    Ok(ProfileFields {
        incarnation: incarnation.to_owned(),
        admission_key_id: admission_key_id.to_owned(),
        dtls_fingerprint: dtls_fingerprint.to_owned(),
        sctp_port: sctp_port as i64,
        max_message_size: max_message_size as i64,
    })
}

fn validate_candidate(candidate: &Value) -> Result<(), ProviderError> {
    let object = candidate
        .as_object()
        .ok_or_else(|| ProviderError::InvalidRequest("invalid candidate".to_owned()))?;
    let foundation = object
        .get("foundation")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::InvalidRequest("missing foundation".to_owned()))?;
    if foundation.is_empty()
        || foundation.len() > 32
        || !foundation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(ProviderError::InvalidRequest(
            "invalid candidate foundation".to_owned(),
        ));
    }
    let priority = object
        .get("priority")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProviderError::InvalidRequest("missing priority".to_owned()))?;
    if !(1..=2_147_483_647).contains(&priority) {
        return Err(ProviderError::InvalidRequest(
            "invalid candidate priority".to_owned(),
        ));
    }
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::InvalidRequest("missing address".to_owned()))?;
    let parsed = IpAddr::from_str(address)
        .map_err(|_| ProviderError::InvalidRequest("invalid candidate address".to_owned()))?;
    if parsed.is_unspecified() {
        return Err(ProviderError::InvalidRequest(
            "wildcard candidate address".to_owned(),
        ));
    }
    let port = object
        .get("port")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProviderError::InvalidRequest("missing port".to_owned()))?;
    if !(1..=65535).contains(&port) {
        return Err(ProviderError::InvalidRequest(
            "invalid candidate port".to_owned(),
        ));
    }
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::InvalidRequest("missing candidate type".to_owned()))?;
    if !matches!(kind, "host" | "srflx" | "relay") {
        return Err(ProviderError::InvalidRequest(
            "invalid candidate type".to_owned(),
        ));
    }
    Ok(())
}

fn valid_dtls_fingerprint(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("sha-256 ") else {
        return false;
    };
    let parts: Vec<&str> = rest.split(':').collect();
    parts.len() == 32
        && parts.iter().all(|part| {
            part.len() == 2
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
        })
}

fn profile_revision(profile: &Value) -> String {
    let bytes = serde_json::to_vec(profile).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    format!("rev_{}", b64url_encode(&digest[..18]))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ProviderError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ProviderError::InvalidRequest(format!("missing {name} header")))
}

fn parse_i64(value: &str, name: &str) -> Result<i64, ProviderError> {
    value
        .parse()
        .map_err(|_| ProviderError::InvalidRequest(format!("invalid {name} header")))
}

fn validate_idempotency_key(value: &str) -> Result<(), ProviderError> {
    let length = value.chars().count();
    if !(16..=128).contains(&length)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProviderError::InvalidRequest(
            "invalid idempotency-key header".to_owned(),
        ));
    }
    Ok(())
}

fn has_control_characters(value: &str) -> bool {
    value
        .chars()
        .any(|character| matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f))
}
