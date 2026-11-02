use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use nxsd::api::{AppState, router};
use nxsd::config::Config;
use nxsd::encoding::{b64_standard_encode_padded, b64url_encode};
use nxsd::jwk::{PublicJwk, generate_keypair, sign_es384};
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

fn app() -> Router {
    let store = Store::open_in_memory().expect("in-memory store");
    store.migrate().expect("migrations");
    let config = Config {
        pow_difficulty: 0,
        ..Config::default()
    };
    router(AppState::new(config, store))
}

async fn read_response(response: axum::response::Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
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
    let (status, body) = read_response(response).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
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

fn signed_heartbeat(
    instance_id: &str,
    key_id: &str,
    generation: u64,
    sequence: u64,
    idempotency_key: &str,
    body: &Value,
    private_d: &str,
) -> Request<Body> {
    let timestamp = now_ms() as u64;
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
    let (status, body) = read_response(response).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

async fn setup_routable_host(app: &Router) -> (String, String) {
    let fixture = fixture();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let challenge = register(app, &fixture["publicKeyJwk"]).await;
    let registration = complete(app, &challenge, private_d, "intent_join_0001").await;
    let instance_id = registration["instanceId"].as_str().expect("instanceId");
    let key_id = registration["keyId"].as_str().expect("keyId");

    let provision = json!({
        "acceptingPlayers": true,
        "capacity": 20,
        "connectedPlayers": { "count": 0, "sampledAt": now_ms() },
        "admissionKeyRequestId": "admission_request_join_0001",
    });
    let (status, response) = send(
        app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            1,
            "heartbeat_join_0001",
            &provision,
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let admission_key = response["admissionKey"]["keyId"]
        .as_str()
        .expect("admission key")
        .to_owned();

    let heartbeat = json!({
        "acceptingPlayers": true,
        "capacity": 20,
        "connectedPlayers": { "count": 3, "sampledAt": now_ms() },
        "installedAdmissionKeyIds": [admission_key],
        "serverStatus": {
            "name": "NetherGate test",
            "level": "world",
            "maxPlayerCount": 20,
            "gameType": 0,
        },
        "bedrockProtocols": {
            "accepted": [2193],
            "version": "1.26.0",
        },
        "hostProfile": {
            "candidates": [{
                "foundation": "1",
                "priority": 100,
                "address": "192.0.2.1",
                "port": 5000,
                "type": "host"
            }],
            "dtlsFingerprint": format!("sha-256 {}", vec!["AB"; 32].join(":")),
            "admissionKeyId": admission_key,
            "sctpPort": 5000,
            "maxMessageSize": 262144,
            "statelessAdmission": {
                "capability": "nethernet.stateless-admission.v1",
                "incarnation": "0123456789abcdef0123456789abcdef"
            }
        }
    });
    let (status, response) = send(
        app,
        signed_heartbeat(
            instance_id,
            key_id,
            1,
            2,
            "heartbeat_join_0002",
            &heartbeat,
            private_d,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["readiness"]["routable"], true);
    (instance_id.to_owned(), key_id.to_owned())
}

fn make_offer(fingerprint_digest: &str) -> String {
    let (jwk, private_d) = generate_keypair().expect("client identity key");
    let header = b64url_encode(br#"{"alg":"ES384"}"#);
    let fingerprint_payload = format!(
        "{{\"fingerprint\":[{{\"algorithm\":\"sha-256\",\"digest\":\"{fingerprint_digest}\"}}]}}"
    );
    let detached_input = format!("{header}.{}", b64url_encode(fingerprint_payload.as_bytes()));
    let detached_signature = sign_es384(&private_d, detached_input.as_bytes()).expect("signs");
    let assertion = json!({
        "fingerprints": format!("{header}..{}", b64url_encode(&detached_signature)),
        "token": make_token(&jwk, &private_d),
    });
    let envelope = json!({
        "assertion": assertion.to_string(),
        "idp": { "domain": "", "protocol": "default" },
    });
    let identity = b64_standard_encode_padded(envelope.to_string().as_bytes());

    [
        "v=0".to_owned(),
        "o=- 1 2 IN IP4 127.0.0.1".to_owned(),
        "s=-".to_owned(),
        "t=0 0".to_owned(),
        "a=group:BUNDLE 0".to_owned(),
        format!("a=identity:{identity}"),
        "m=application 50000 UDP/DTLS/SCTP webrtc-datachannel".to_owned(),
        "c=IN IP4 10.0.0.1".to_owned(),
        "a=ice-ufrag:clientUfrag".to_owned(),
        "a=ice-pwd:clientPassword01234567890".to_owned(),
        "a=ice-options:trickle".to_owned(),
        format!("a=fingerprint:sha-256 {fingerprint_digest}"),
        "a=setup:actpass".to_owned(),
        "a=mid:0".to_owned(),
        "a=sctp-port:5000".to_owned(),
        "a=max-message-size:262144".to_owned(),
    ]
    .join("\r\n")
}

fn make_token(jwk: &PublicJwk, private_d: &str) -> String {
    let header = b64url_encode(br#"{"alg":"ES384"}"#);
    let claims = json!({
        "cpk": jwk,
        "iat": now_ms() / 1000,
        "exp": now_ms() / 1000 + 60,
    });
    let claims = b64url_encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{claims}");
    let signature = sign_es384(private_d, signing_input.as_bytes()).expect("signs");
    format!("{signing_input}.{}", b64url_encode(&signature))
}

const DIGEST: &str = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

#[tokio::test]
async fn listing_and_synthesized_answer() {
    let app = app();
    setup_routable_host(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/join")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request succeeds");
    let (status, body) = read_response(response).await;
    assert_eq!(status, StatusCode::OK);
    let listing: Value = serde_json::from_str(&body).expect("listing json");
    assert_eq!(listing["name"], "NetherGate test");
    assert_eq!(listing["protocol"], 2193);
    assert_eq!(listing["players"], 3);
    assert_eq!(listing["maxPlayers"], 20);

    let offer = make_offer(DIGEST);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/join/123456789")
                .header("content-type", "application/sdp")
                .body(Body::from(offer))
                .unwrap(),
        )
        .await
        .expect("request succeeds");
    let (status, answer) = read_response(response).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(answer.starts_with("v=0\r\n"), "{answer}");
    assert!(answer.contains("a=ice-ufrag:NXS1"), "{answer}");
    assert!(answer.contains("a=ice-pwd:"), "{answer}");
    assert!(
        answer.contains("a=fingerprint:sha-256 AB:AB:AB"),
        "{answer}"
    );
    assert!(answer.contains("a=sctp-port:5000"), "{answer}");
    assert!(answer.contains("a=max-message-size:262144"), "{answer}");
    assert!(
        answer.contains("a=candidate:1 1 udp 100 192.0.2.1 5000"),
        "{answer}"
    );
    assert!(answer.contains("a=identity:"), "{answer}");
}

#[tokio::test]
async fn rejects_offer_without_identity_and_no_host() {
    let app = app();
    let offer = make_offer(DIGEST).replace("a=identity:", "a=x-identity:");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/join/123456789")
                .header("content-type", "application/sdp")
                .body(Body::from(offer))
                .unwrap(),
        )
        .await
        .expect("request succeeds");
    let (status, body) = read_response(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let offer = make_offer(DIGEST);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/join/123456789")
                .header("content-type", "application/sdp")
                .body(Body::from(offer))
                .unwrap(),
        )
        .await
        .expect("request succeeds");
    let (status, _) = read_response(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn empty_listing_returns_empty_object() {
    let app = app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/join")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request succeeds");
    let (status, body) = read_response(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "{}");
}
