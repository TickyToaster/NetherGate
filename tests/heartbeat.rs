use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use nxsd::api::{AppState, router};
use nxsd::config::Config;
use nxsd::encoding::b64url_encode;
use nxsd::jwk::sign_es384;
use nxsd::proofs::{CompleteInput, OperationInput, solve_pow};
use nxsd::store::{Store, now_ms};
use serde_json::{Value, json};
use tower::ServiceExt;

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vendor/upstream/docs/external-signaling/fixtures/nxs-v1.fixtures.json");
    serde_json::from_slice(&std::fs::read(path).expect("nxs fixture is vendored"))
        .expect("nxs fixture parses")
}

fn app(pow_difficulty: u8) -> (Router, Store) {
    let store = Store::open_in_memory().expect("in-memory store");
    store.migrate().expect("migrations");
    let config = Config {
        pow_difficulty,
        ..Config::default()
    };
    (router(AppState::new(config, store.clone())), store)
}

async fn post_json(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("request succeeds");
    read_response(response).await
}

async fn read_response(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn register(app: &Router, public_jwk: &Value) -> Value {
    let (status, challenge) = post_json(
        app,
        "/v1/nxs/register",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "publicKeyJwk": public_jwk,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    challenge
}

async fn complete(app: &Router, challenge: &Value, private_d: &str, idem: &str) -> Value {
    let difficulty = challenge["pow"]["difficulty"].as_u64().expect("difficulty") as u8;
    let make_payload = |proof_nonce: &str| {
        CompleteInput {
            audience: challenge["audience"].as_str().expect("audience"),
            challenge_id: challenge["challengeId"].as_str().expect("challengeId"),
            nonce: challenge["nonce"].as_str().expect("nonce"),
            thumbprint: challenge["thumbprint"].as_str().expect("thumbprint"),
            context_digest: challenge["contextDigest"].as_str().expect("contextDigest"),
            expires_at: challenge["expiresAt"].as_u64().expect("expiresAt"),
            proof_nonce,
            idempotency_key: idem,
        }
        .payload()
    };
    let (proof_nonce, payload) = solve_pow(difficulty, make_payload).expect("PoW solvable");
    let signature = sign_es384(private_d, payload.as_bytes()).expect("signs");
    let (status, registration) = post_json(
        app,
        "/v1/nxs/complete",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "challengeId": challenge["challengeId"],
            "proofNonce": proof_nonce,
            "idempotencyKey": idem,
            "signature": b64url_encode(&signature),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    registration
}

#[allow(clippy::too_many_arguments)]
async fn provision_key(
    app: &Router,
    instance_id: &str,
    key_id: &str,
    generation: u64,
    sequence: u64,
    idempotency_key: &str,
    request_id: &str,
    private_d: &str,
) -> (String, String) {
    let body = json!({
        "acceptingPlayers": true,
        "capacity": 20,
        "connectedPlayers": { "count": 0, "sampledAt": now_ms() },
        "admissionKeyRequestId": request_id,
    });
    let (status, response) = send(
        app,
        signed_heartbeat(
            instance_id,
            key_id,
            generation,
            sequence,
            idempotency_key,
            &body,
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let admission_key_id = response["admissionKey"]["keyId"]
        .as_str()
        .expect("admission key id")
        .to_owned();
    let secret = response["admissionKey"]["secret"]
        .as_str()
        .expect("admission key secret")
        .to_owned();
    (admission_key_id, secret)
}

fn heartbeat_body(accepting: bool, admission_key_id: &str) -> Value {
    heartbeat_body_with(accepting, admission_key_id, &[admission_key_id], None)
}

fn heartbeat_body_with(
    accepting: bool,
    profile_key: &str,
    installed: &[&str],
    admission_key_request_id: Option<&str>,
) -> Value {
    let mut body = json!({
        "acceptingPlayers": accepting,
        "capacity": 20,
        "connectedPlayers": { "count": 3, "sampledAt": now_ms() },
        "installedAdmissionKeyIds": installed,
        "hostProfile": {
            "candidates": [{
                "foundation": "1",
                "priority": 1,
                "address": "192.0.2.1",
                "port": 5000,
                "type": "host"
            }],
            "dtlsFingerprint": format!("sha-256 {}", vec!["AB"; 32].join(":")),
            "admissionKeyId": profile_key,
            "sctpPort": 5000,
            "maxMessageSize": 262144,
            "statelessAdmission": {
                "capability": "nethernet.stateless-admission.v1",
                "incarnation": "0123456789abcdef0123456789abcdef"
            }
        }
    });
    if let Some(request_id) = admission_key_request_id {
        body["admissionKeyRequestId"] = json!(request_id);
    }
    body
}

fn signed_heartbeat(
    instance_id: &str,
    key_id: &str,
    generation: u64,
    sequence: u64,
    idempotency_key: &str,
    body: &Value,
    private_d: &str,
) -> Request<Body> {
    signed_heartbeat_at(
        instance_id,
        key_id,
        generation,
        sequence,
        idempotency_key,
        body,
        private_d,
        now_ms() as u64,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_heartbeat_at(
    instance_id: &str,
    key_id: &str,
    generation: u64,
    sequence: u64,
    idempotency_key: &str,
    body: &Value,
    private_d: &str,
    timestamp: u64,
) -> Request<Body> {
    let body_bytes = serde_json::to_vec(body).expect("body serializes");
    let payload = OperationInput {
        audience: "http://localhost:8080",
        method: "POST",
        path: "/v1/nxs/heartbeat",
        timestamp,
        instance_id,
        key_id,
        idempotency_key,
        generation,
        sequence,
        body: &body_bytes,
    }
    .payload();
    let signature = sign_es384(private_d, payload.as_bytes()).expect("signs");

    Request::builder()
        .method("POST")
        .uri("/v1/nxs/heartbeat")
        .header("content-type", "application/json")
        .header("nxs-instance-id", instance_id)
        .header("nxs-key-id", key_id)
        .header("nxs-timestamp", timestamp.to_string())
        .header("nxs-signature-version", "nxs-es384-v1")
        .header("nxs-generation", generation.to_string())
        .header("nxs-sequence", sequence.to_string())
        .header("nxs-signature", b64url_encode(&signature))
        .header("idempotency-key", idempotency_key)
        .body(Body::from(body_bytes))
        .unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("request succeeds");
    read_response(response).await
}

#[tokio::test]
async fn heartbeat_publishes_profile_and_lease_expires_to_non_routable() {
    let fixture = fixture();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let (app, store) = app(0);

    let challenge = register(&app, &fixture["publicKeyJwk"]).await;
    let registration = complete(&app, &challenge, private_d, "intent_heartbeat_0001").await;
    let instance_id = registration["instanceId"].as_str().expect("instanceId");
    let key_id = registration["keyId"].as_str().expect("keyId");
    let (admission_key_id, _secret) = provision_key(
        &app,
        instance_id,
        key_id,
        1,
        1,
        "heartbeat_request_0000",
        "admission_request_0000",
        private_d,
    )
    .await;

    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            2,
            "heartbeat_request_0001",
            &heartbeat_body(true, &admission_key_id),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["readiness"]["routable"], true);
    assert_eq!(response["checkIn"]["afterMillis"], 5000);
    assert_eq!(response["checkIn"]["leaseMillis"], 15000);
    let revision = response["hostProfileRevision"]
        .as_str()
        .expect("revision")
        .to_owned();

    assert!(store.instance_routable(instance_id, now_ms()).unwrap());

    let profile_only = json!({
        "acceptingPlayers": true,
        "capacity": 20,
        "connectedPlayers": { "count": 3, "sampledAt": now_ms() },
        "hostProfileRevision": revision,
    });
    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            3,
            "heartbeat_request_0002",
            &profile_only,
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["readiness"]["routable"], true);
    assert_eq!(response["hostProfileRevision"], revision);

    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            4,
            "heartbeat_request_0003",
            &heartbeat_body(true, &admission_key_id),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let expired_at = now_ms() + 20_000;
    assert_eq!(store.expire_leases(expired_at).unwrap(), 1);
    assert!(!store.instance_routable(instance_id, expired_at).unwrap());
}

#[tokio::test]
async fn replayed_heartbeat_does_not_advance_sequence() {
    let fixture = fixture();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let (app, _store) = app(0);

    let challenge = register(&app, &fixture["publicKeyJwk"]).await;
    let registration = complete(&app, &challenge, private_d, "intent_heartbeat_0004").await;
    let instance_id = registration["instanceId"].as_str().expect("instanceId");
    let key_id = registration["keyId"].as_str().expect("keyId");
    let (admission_key_id, _secret) = provision_key(
        &app,
        instance_id,
        key_id,
        1,
        1,
        "heartbeat_request_0003",
        "admission_request_0003",
        private_d,
    )
    .await;
    let body = heartbeat_body(true, &admission_key_id);

    let timestamp = now_ms() as u64;
    let request = signed_heartbeat_at(
        instance_id,
        key_id,
        1,
        2,
        "heartbeat_request_0004",
        &body,
        private_d,
        timestamp,
    );
    let (status, first) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{first}");

    let (status, replay) = send(
        &app,
        signed_heartbeat_at(
            instance_id,
            key_id,
            1,
            2,
            "heartbeat_request_0004",
            &body,
            private_d,
            timestamp,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(first, replay);

    let (status, body) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            2,
            "heartbeat_request_0005",
            &heartbeat_body(true, &admission_key_id),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn rejects_not_accepting_stale_generation_and_bad_signature() {
    let fixture = fixture();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let (app, _store) = app(0);

    let challenge = register(&app, &fixture["publicKeyJwk"]).await;
    let registration = complete(&app, &challenge, private_d, "intent_heartbeat_0006").await;
    let instance_id = registration["instanceId"].as_str().expect("instanceId");
    let key_id = registration["keyId"].as_str().expect("keyId");
    let (admission_key_id, _secret) = provision_key(
        &app,
        instance_id,
        key_id,
        1,
        1,
        "heartbeat_request_0006",
        "admission_request_0006",
        private_d,
    )
    .await;

    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            2,
            "heartbeat_request_0007",
            &heartbeat_body(false, &admission_key_id),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["readiness"]["routable"], false);
    assert_eq!(response["readiness"]["reasons"][0], "not_accepting");

    let (status, body) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            2,
            3,
            "heartbeat_request_0008",
            &heartbeat_body(true, &admission_key_id),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "generation_fenced");

    let mut request = signed_heartbeat(
        instance_id,
        key_id,
        1,
        3,
        "heartbeat_request_0009",
        &heartbeat_body(true, &admission_key_id),
        private_d,
    );
    request
        .headers_mut()
        .insert("nxs-signature", "AAAA".parse().unwrap());
    let (status, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn admission_key_rotation_acks_new_epoch_and_retires_old_on_schedule() {
    let fixture = fixture();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let (app, store) = app(0);

    let challenge = register(&app, &fixture["publicKeyJwk"]).await;
    let registration = complete(&app, &challenge, private_d, "intent_keys_0001").await;
    let instance_id = registration["instanceId"].as_str().expect("instanceId");
    let key_id = registration["keyId"].as_str().expect("keyId");

    let (key1, secret1) = provision_key(
        &app,
        instance_id,
        key_id,
        1,
        1,
        "heartbeat_keys_0001",
        "admission_request_0001",
        private_d,
    )
    .await;
    assert_eq!(secret1.len(), 43);

    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            2,
            "heartbeat_keys_0002",
            &heartbeat_body(true, &key1),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["readiness"]["routable"], true);

    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            3,
            "heartbeat_keys_0003",
            &heartbeat_body_with(true, &key1, &[&key1], Some("admission_request_0002")),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let key2 = response["admissionKey"]["keyId"]
        .as_str()
        .expect("second key id")
        .to_owned();
    assert_eq!(response["admissionKeyRequest"]["keyId"], key2);
    assert_eq!(response["readiness"]["routable"], true);

    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            4,
            "heartbeat_keys_0004",
            &heartbeat_body_with(true, &key1, &[&key1], Some("admission_request_0002")),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["admissionKeyRequest"]["keyId"], key2);
    assert!(response.get("admissionKey").is_none(), "{response}");

    let (status, response) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            5,
            "heartbeat_keys_0005",
            &heartbeat_body_with(true, &key2, &[&key1, &key2], None),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["readiness"]["routable"], true);
    let retirements = response["admissionKeyRetirements"]
        .as_array()
        .expect("retirements");
    assert_eq!(retirements.len(), 1);
    assert_eq!(retirements[0]["keyId"], key1);
    let retire_after = retirements[0]["retireAfter"].as_i64().expect("retireAfter");

    let old = store.admission_key(instance_id, &key1).unwrap().unwrap();
    assert_eq!(old.state, "retiring");
    assert_eq!(old.retire_after, Some(retire_after));
    let new = store.admission_key(instance_id, &key2).unwrap().unwrap();
    assert_eq!(new.state, "active");

    assert_eq!(store.expire_admission_keys(retire_after + 1).unwrap(), 1);
    let old = store.admission_key(instance_id, &key1).unwrap().unwrap();
    assert_eq!(old.state, "retired");
    assert_eq!(old.secret, "");
    assert_eq!(
        store
            .admission_key(instance_id, &key2)
            .unwrap()
            .unwrap()
            .state,
        "active"
    );

    let (status, body) = send(
        &app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            6,
            "heartbeat_keys_0006",
            &heartbeat_body_with(true, &key1, &[&key1], None),
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");
}
