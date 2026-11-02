//! HTTP NetherNet join surface.
//!
//! `GET /v1/join` returns server-list JSON. `POST /v1/join/{clientNetworkId}`
//! accepts an `application/sdp` offer and returns a synthesised SDP answer. The
//! answer's ICE username is the admission token; the host validates it locally.
//! Media is never proxied.

use std::net::IpAddr;
use std::str::FromStr;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use p384::elliptic_curve::sec1::ToSec1Point;
use p384::pkcs8::DecodePublicKey;
use serde_json::{Value, json};

use crate::admission::{
    AdmissionClaims, AdmissionContext, derive_ice_pwd, identity_binding, seal_token,
};
use crate::api::AppState;
use crate::encoding::{
    b64_standard_decode_any, b64_standard_encode_padded, b64url_decode, b64url_encode,
};
use crate::jwk::{PublicJwk, canonical_cpk_from_spki_b64, sign_es384, verify_es384};
use crate::store::{RoutableProfile, now_ms};

const TOKEN_LIFETIME_MS: i64 = 60_000;

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("no routable host")]
    NoHost,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for JoinError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NoHost => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(error) => {
                tracing::error!(%error, "join failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (status, self.to_string()).into_response()
    }
}

pub async fn listing(State(state): State<AppState>) -> Result<Json<Value>, JoinError> {
    let Some(listing) = state.store.listing(now_ms())? else {
        return Ok(Json(json!({})));
    };
    Ok(Json(json!({
        "name": listing.name,
        "protocol": listing.protocol,
        "version": listing.version,
        "level": listing.level,
        "players": listing.players,
        "maxPlayers": listing.max_players,
        "gameType": listing.game_type,
    })))
}

pub async fn offer(
    State(state): State<AppState>,
    Path(network_id): Path<String>,
    body: Bytes,
) -> Result<Response, JoinError> {
    let network_id: u64 = network_id
        .parse()
        .map_err(|_| JoinError::BadRequest("invalid network id"))?;
    if network_id == 0 {
        return Err(JoinError::BadRequest("network id zero is reserved"));
    }
    let offer_text =
        std::str::from_utf8(&body).map_err(|_| JoinError::BadRequest("offer is not UTF-8"))?;
    let offer = parse_offer(offer_text, network_id)?;
    tracing::info!(
        setup = ?offer.setup,
        fingerprints = offer.fingerprints.len(),
        sctp_port = offer.sctp_port,
        max_message_size = offer.max_message_size,
        "join offer"
    );

    let claimed_cpk = verify_client_identity(&offer)?;
    let host = state
        .store
        .routable_profile(now_ms())?
        .ok_or(JoinError::NoHost)?;

    let answer = synthesize_answer(&state, &host, &offer, &claimed_cpk)?;
    Ok(([(header::CONTENT_TYPE, "application/sdp")], answer).into_response())
}

struct Offer {
    ufrag: String,
    pwd: String,
    sctp_port: u16,
    max_message_size: u32,
    fingerprints: Vec<(String, String)>,
    identity: String,
    setup: Option<String>,
    network_id: u64,
}

fn parse_offer(sdp: &str, network_id: u64) -> Result<Offer, JoinError> {
    let mut ufrag = None;
    let mut pwd = None;
    let mut sctp_port = 5000u16;
    let mut max_message_size = 262_144u32;
    let mut fingerprints = Vec::new();
    let mut identity = None;
    let mut setup = None;

    for line in sdp.split(['\r', '\n']) {
        if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            ufrag.get_or_insert_with(|| value.to_owned());
        } else if let Some(value) = line.strip_prefix("a=ice-pwd:") {
            pwd.get_or_insert_with(|| value.to_owned());
        } else if let Some(value) = line.strip_prefix("a=sctp-port:") {
            sctp_port = value
                .parse()
                .map_err(|_| JoinError::BadRequest("invalid sctp-port"))?;
        } else if let Some(value) = line.strip_prefix("a=max-message-size:") {
            max_message_size = value
                .parse()
                .map_err(|_| JoinError::BadRequest("invalid max-message-size"))?;
        } else if let Some(value) = line.strip_prefix("a=fingerprint:") {
            let (algorithm, digest) = value
                .split_once(' ')
                .ok_or(JoinError::BadRequest("invalid fingerprint"))?;
            fingerprints.push((algorithm.to_owned(), digest.to_owned()));
        } else if let Some(value) = line.strip_prefix("a=setup:") {
            setup.get_or_insert_with(|| value.to_owned());
        } else if let Some(value) = line.strip_prefix("a=identity:")
            && identity.replace(value.to_owned()).is_some()
        {
            return Err(JoinError::BadRequest("duplicate a=identity"));
        }
    }

    let ufrag = ufrag.ok_or(JoinError::BadRequest("missing ice-ufrag"))?;
    let pwd = pwd.ok_or(JoinError::BadRequest("missing ice-pwd"))?;
    if ufrag.len() < 4 || ufrag.len() > 256 {
        return Err(JoinError::BadRequest("invalid ice-ufrag"));
    }
    if !(22..=91).contains(&pwd.len())
        || !pwd
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return Err(JoinError::BadRequest("invalid ice-pwd"));
    }
    if !(1..=65535).contains(&sctp_port) || !(1..=262_144).contains(&max_message_size) {
        return Err(JoinError::BadRequest("invalid SCTP parameters"));
    }
    if fingerprints.is_empty() {
        return Err(JoinError::BadRequest("missing DTLS fingerprint"));
    }
    let identity = identity.ok_or(JoinError::BadRequest("missing a=identity"))?;

    Ok(Offer {
        ufrag,
        pwd,
        sctp_port,
        max_message_size,
        fingerprints,
        identity,
        setup,
        network_id,
    })
}

fn verify_client_identity(offer: &Offer) -> Result<String, JoinError> {
    let envelope_bytes = b64_standard_decode_any(&offer.identity)
        .map_err(|_| JoinError::BadRequest("invalid identity base64"))?;
    let envelope: Value = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| JoinError::BadRequest("invalid identity envelope"))?;
    if envelope["idp"]["protocol"] != "default" {
        return Err(JoinError::BadRequest("unsupported identity protocol"));
    }
    let assertion: Value = serde_json::from_str(
        envelope["assertion"]
            .as_str()
            .ok_or(JoinError::BadRequest("missing identity assertion"))?,
    )
    .map_err(|_| JoinError::BadRequest("invalid identity assertion"))?;

    let token = assertion["token"]
        .as_str()
        .ok_or(JoinError::BadRequest("missing identity token"))?;
    let jwt = parse_jwt(token)?;
    let cpk = cpk_from_claims(&jwt.claims)?;
    let jwk = cpk_jwk(&jwt.claims)?;

    if jwt.algorithm == "ES384" {
        verify_es384(&jwk, jwt.signing_input.as_bytes(), &jwt.signature)
            .map_err(|_| JoinError::BadRequest("invalid identity token signature"))?;
        if let Some(exp) = jwt.claims["exp"].as_i64()
            && exp * 1000 < now_ms()
        {
            return Err(JoinError::BadRequest("identity token expired"));
        }
    }

    let detached = assertion["fingerprints"]
        .as_str()
        .ok_or(JoinError::BadRequest("missing fingerprint assertion"))?;
    let mut parts = detached.split('.');
    let header = parts
        .next()
        .ok_or(JoinError::BadRequest("invalid fingerprint assertion"))?;
    let payload = parts
        .next()
        .ok_or(JoinError::BadRequest("invalid fingerprint assertion"))?;
    let signature = parts
        .next()
        .ok_or(JoinError::BadRequest("invalid fingerprint assertion"))?;
    if !payload.is_empty() || parts.next().is_some() {
        return Err(JoinError::BadRequest("invalid detached signature"));
    }
    let header_json: Value = serde_json::from_slice(
        &b64url_decode(header).map_err(|_| JoinError::BadRequest("invalid JWS header"))?,
    )
    .map_err(|_| JoinError::BadRequest("invalid JWS header"))?;
    if header_json["alg"] != "ES384" {
        return Err(JoinError::BadRequest("unsupported JWS algorithm"));
    }
    let payload_bytes = fingerprint_payload(&offer.fingerprints)?;
    let signing_input = format!("{header}.{}", b64url_encode(&payload_bytes));
    let signature =
        b64url_decode(signature).map_err(|_| JoinError::BadRequest("invalid JWS signature"))?;
    verify_es384(&jwk, signing_input.as_bytes(), &signature)
        .map_err(|_| JoinError::BadRequest("invalid fingerprint signature"))?;

    Ok(cpk)
}

struct ParsedJwt {
    algorithm: String,
    claims: Value,
    signing_input: String,
    signature: Vec<u8>,
}

fn parse_jwt(token: &str) -> Result<ParsedJwt, JoinError> {
    let mut parts = token.split('.');
    let header = parts
        .next()
        .ok_or(JoinError::BadRequest("invalid identity token"))?;
    let payload = parts
        .next()
        .ok_or(JoinError::BadRequest("invalid identity token"))?;
    let signature = parts
        .next()
        .ok_or(JoinError::BadRequest("invalid identity token"))?;
    if parts.next().is_some() {
        return Err(JoinError::BadRequest("invalid identity token"));
    }
    let header_json: Value = serde_json::from_slice(
        &b64url_decode(header).map_err(|_| JoinError::BadRequest("invalid token header"))?,
    )
    .map_err(|_| JoinError::BadRequest("invalid token header"))?;
    let claims: Value = serde_json::from_slice(
        &b64url_decode(payload).map_err(|_| JoinError::BadRequest("invalid token claims"))?,
    )
    .map_err(|_| JoinError::BadRequest("invalid token claims"))?;

    Ok(ParsedJwt {
        algorithm: header_json["alg"].as_str().unwrap_or_default().to_owned(),
        claims,
        signing_input: format!("{header}.{payload}"),
        signature: b64url_decode(signature)
            .map_err(|_| JoinError::BadRequest("invalid token signature"))?,
    })
}

fn cpk_from_claims(claims: &Value) -> Result<String, JoinError> {
    match &claims["cpk"] {
        Value::String(encoded) => {
            canonical_cpk_from_spki_b64(encoded).map_err(|_| JoinError::BadRequest("invalid cpk"))
        }
        Value::Object(_) => cpk_jwk(claims)?
            .canonical_cpk()
            .map_err(|_| JoinError::BadRequest("invalid cpk")),
        _ => Err(JoinError::BadRequest("missing cpk")),
    }
}

fn cpk_jwk(claims: &Value) -> Result<PublicJwk, JoinError> {
    match &claims["cpk"] {
        Value::Object(_) => {
            PublicJwk::from_json(&claims["cpk"]).map_err(|_| JoinError::BadRequest("invalid cpk"))
        }
        Value::String(encoded) => {
            let der = b64_standard_decode_any(encoded)
                .map_err(|_| JoinError::BadRequest("invalid cpk"))?;
            let key = p384::PublicKey::from_public_key_der(&der)
                .map_err(|_| JoinError::BadRequest("invalid cpk"))?;
            let point = key.to_sec1_point(false);
            PublicJwk {
                kty: "EC".to_owned(),
                crv: "P-384".to_owned(),
                x: b64url_encode(point.x().ok_or(JoinError::BadRequest("invalid cpk"))?),
                y: b64url_encode(point.y().ok_or(JoinError::BadRequest("invalid cpk"))?),
            }
            .validate()
            .map_err(|_| JoinError::BadRequest("invalid cpk"))?;
            Ok(PublicJwk {
                kty: "EC".to_owned(),
                crv: "P-384".to_owned(),
                x: b64url_encode(point.x().ok_or(JoinError::BadRequest("invalid cpk"))?),
                y: b64url_encode(point.y().ok_or(JoinError::BadRequest("invalid cpk"))?),
            })
        }
        _ => Err(JoinError::BadRequest("missing cpk")),
    }
}

fn fingerprint_payload(fingerprints: &[(String, String)]) -> Result<Vec<u8>, JoinError> {
    let mut payload = String::from("{\"fingerprint\":[");
    for (index, (algorithm, digest)) in fingerprints.iter().enumerate() {
        if !matches!(algorithm.as_str(), "sha-256" | "sha-1")
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
        {
            return Err(JoinError::BadRequest("invalid fingerprint"));
        }
        if index > 0 {
            payload.push(',');
        }
        payload.push_str(&format!(
            "{{\"algorithm\":\"{algorithm}\",\"digest\":\"{digest}\"}}"
        ));
    }
    payload.push_str("]}");
    Ok(payload.into_bytes())
}

fn synthesize_answer(
    state: &AppState,
    host: &RoutableProfile,
    offer: &Offer,
    cpk: &str,
) -> Result<String, JoinError> {
    let profile: Value = serde_json::from_str(&host.profile_json)
        .map_err(|_| JoinError::Internal(anyhow::anyhow!("stored profile is invalid")))?;
    let incarnation = profile["statelessAdmission"]["incarnation"]
        .as_str()
        .ok_or(JoinError::Internal(anyhow::anyhow!(
            "profile incarnation missing"
        )))?;
    let audience = format!("nxs-stateless-host-v1/{incarnation}");
    let context = AdmissionContext {
        key_id: &host.admission_key_id,
        secret: &host.secret,
        audience: &audience,
    };

    let now = now_ms();
    let expires_at_ms = ((now + TOKEN_LIFETIME_MS + 999) / 1000) * 1000;
    let fingerprint = sha256_fingerprint(&offer.fingerprints)?;
    let claims = AdmissionClaims {
        expires_at_ms: expires_at_ms as u64,
        client_fingerprint: fingerprint,
        client_sctp_port: offer.sctp_port,
        client_max_message_size: offer.max_message_size,
        identity_binding: identity_binding(&host.secret, &audience, cpk),
        network_id: offer.network_id,
        client_ice_pwd: &offer.pwd,
    };
    let answer_ufrag = seal_token(&context, &claims, &offer.ufrag)
        .map_err(|error| JoinError::Internal(anyhow::anyhow!("seal admission token: {error}")))?;
    let answer_pwd = derive_ice_pwd(&host.secret, &audience, &answer_ufrag);

    let dtls_fingerprint = profile["dtlsFingerprint"]
        .as_str()
        .ok_or(JoinError::Internal(anyhow::anyhow!(
            "profile fingerprint missing"
        )))?;
    let dtls_digest = dtls_fingerprint
        .strip_prefix("sha-256 ")
        .ok_or(JoinError::Internal(anyhow::anyhow!(
            "unsupported fingerprint"
        )))?;
    let sctp_port = profile["sctpPort"]
        .as_u64()
        .ok_or(JoinError::Internal(anyhow::anyhow!(
            "profile sctpPort missing"
        )))?;
    let max_message_size = profile["maxMessageSize"]
        .as_u64()
        .ok_or(JoinError::Internal(anyhow::anyhow!(
            "profile maxMessageSize missing"
        )))?;

    let identity = server_identity(state, dtls_digest, now)?;
    let answer_setup = match offer.setup.as_deref() {
        Some("active") => "passive",
        Some("passive") | Some("actpass") | None => "active",
        Some(_) => return Err(JoinError::BadRequest("invalid setup role")),
    };

    let mut lines = vec![
        "v=0".to_owned(),
        format!("o=- {} 2 IN IP4 127.0.0.1", random_u64()),
        "s=-".to_owned(),
        "t=0 0".to_owned(),
        "a=group:BUNDLE 0".to_owned(),
        format!("a=identity:{identity}"),
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel".to_owned(),
        "c=IN IP4 0.0.0.0".to_owned(),
        format!("a=ice-ufrag:{answer_ufrag}"),
        format!("a=ice-pwd:{answer_pwd}"),
        "a=ice-options:trickle".to_owned(),
        format!("a=fingerprint:sha-256 {dtls_digest}"),
        format!("a=setup:{answer_setup}"),
        "a=mid:0".to_owned(),
        format!("a=sctp-port:{sctp_port}"),
        format!("a=max-message-size:{max_message_size}"),
    ];

    if let Some(candidates) = profile["candidates"].as_array() {
        for candidate in candidates {
            let foundation = candidate["foundation"].as_str().unwrap_or("1");
            let priority = candidate["priority"].as_u64().unwrap_or(1);
            let address = candidate["address"].as_str().unwrap_or("0.0.0.0");
            let port = candidate["port"].as_u64().unwrap_or(9);
            let kind = candidate["type"].as_str().unwrap_or("host");
            if IpAddr::from_str(address).is_err() {
                continue;
            }
            lines.push(format!(
                "a=candidate:{foundation} 1 udp {priority} {address} {port} typ {kind} generation 0 ufrag {answer_ufrag} network-id 0 network-cost 0"
            ));
        }
    }
    lines.push("a=end-of-candidates".to_owned());

    Ok(format!("{}\r\n", lines.join("\r\n")))
}

fn server_identity(state: &AppState, dtls_digest: &str, now: i64) -> Result<String, JoinError> {
    let record = state.store.server_identity(now)?;
    let jwk = PublicJwk::from_json(
        &serde_json::from_str(&record.public_jwk)
            .map_err(|_| JoinError::Internal(anyhow::anyhow!("provider identity invalid")))?,
    )
    .map_err(|_| JoinError::Internal(anyhow::anyhow!("provider identity invalid")))?;

    let header = b64url_encode(br#"{"alg":"ES384"}"#);
    let claims = json!({
        "cpk": jwk,
        "iat": now / 1000,
        "exp": now / 1000 + 60,
    });
    let claims = b64url_encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{claims}");
    let signature = sign_es384(&record.private_d, signing_input.as_bytes())
        .map_err(|_| JoinError::Internal(anyhow::anyhow!("sign provider identity")))?;
    let token = format!("{signing_input}.{}", b64url_encode(&signature));

    let payload =
        format!("{{\"fingerprint\":[{{\"algorithm\":\"sha-256\",\"digest\":\"{dtls_digest}\"}}]}}");
    let detached_input = format!("{header}.{}", b64url_encode(payload.as_bytes()));
    let detached_signature = sign_es384(&record.private_d, detached_input.as_bytes())
        .map_err(|_| JoinError::Internal(anyhow::anyhow!("sign fingerprints")))?;
    let assertion = json!({
        "fingerprints": format!("{header}..{}", b64url_encode(&detached_signature)),
        "token": token,
    });
    let envelope = json!({
        "assertion": assertion.to_string(),
        "idp": { "domain": "", "protocol": "default" },
    });
    Ok(b64_standard_encode_padded(envelope.to_string().as_bytes()))
}

fn sha256_fingerprint(fingerprints: &[(String, String)]) -> Result<[u8; 32], JoinError> {
    let mut found = None;
    for (algorithm, digest) in fingerprints {
        if algorithm != "sha-256" {
            continue;
        }
        let bytes = digest
            .split(':')
            .map(|part| u8::from_str_radix(part, 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| JoinError::BadRequest("invalid fingerprint"))?;
        if bytes.len() != 32 {
            return Err(JoinError::BadRequest("invalid fingerprint"));
        }
        found = Some(bytes.try_into().expect("32 bytes"));
    }
    found.ok_or(JoinError::BadRequest("missing sha-256 fingerprint"))
}

fn random_u64() -> u64 {
    rand::random()
}
