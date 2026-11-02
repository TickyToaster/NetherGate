use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use nxsd::api::{AppState, router};
use nxsd::config::Config;
use nxsd::encoding::b64url_encode;
use nxsd::jwk::sign_es384;
use nxsd::proofs::{CompleteInput, solve_pow};
use nxsd::store::Store;
use serde_json::{Value, json};
use tower::ServiceExt;

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vendor/upstream/docs/external-signaling/fixtures/nxs-v1.fixtures.json");
    serde_json::from_slice(&std::fs::read(path).expect("nxs fixture is vendored"))
        .expect("nxs fixture parses")
}

fn app(pow_difficulty: u8) -> Router {
    let store = Store::open_in_memory().expect("in-memory store");
    store.migrate().expect("migrations");
    let config = Config {
        pow_difficulty,
        ..Config::default()
    };
    router(AppState::new(config, store))
}

async fn post(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
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

fn complete_request(
    challenge: &Value,
    private_d: &str,
    idempotency_key: &str,
    require_pow: bool,
) -> (Value, String) {
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
            idempotency_key,
        }
        .payload()
    };

    let (proof_nonce, payload) = if require_pow {
        solve_pow(difficulty, make_payload).expect("PoW is solvable")
    } else {
        let (nonce, payload) = (0u64..)
            .map(|counter| {
                let nonce = format!("unsolved-{counter}");
                let payload = make_payload(&nonce);
                (nonce, payload)
            })
            .find(|(_, payload)| !nxsd::proofs::verify_pow(payload.as_bytes(), difficulty))
            .expect("some nonce fails PoW");
        (nonce, payload)
    };

    let signature = sign_es384(private_d, payload.as_bytes()).expect("signs");
    (
        json!({
            "protocol": "nethernet-external-signaling-v1",
            "challengeId": challenge["challengeId"],
            "proofNonce": proof_nonce,
            "idempotencyKey": idempotency_key,
            "signature": b64url_encode(&signature),
        }),
        payload,
    )
}

#[tokio::test]
async fn fake_host_registers_completes_and_recovers() {
    let fixture = fixture();
    let public_jwk = fixture["publicKeyJwk"].clone();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let app = app(4);

    let (status, challenge) = post(
        &app,
        "/v1/nxs/register",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "publicKeyJwk": public_jwk,
            "label": "EU caf\u{e9} \u{1f98a}",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    assert_eq!(challenge["pow"]["difficulty"], 4);
    assert_eq!(challenge["context"]["mode"], "new-service");
    assert_eq!(challenge["audience"], "http://localhost:8080");

    let (complete, _) = complete_request(&challenge, private_d, "intent_fixture_0001", true);
    let (status, registration) = post(&app, "/v1/nxs/complete", &complete).await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    assert_eq!(registration["leaseGeneration"], 1);
    assert_eq!(registration["protocol"], "nethernet-external-signaling-v1");
    let registration_id = registration["registrationId"]
        .as_str()
        .expect("registrationId")
        .to_owned();
    let instance_id = registration["instanceId"]
        .as_str()
        .expect("instanceId")
        .to_owned();
    let key_id = registration["keyId"].as_str().expect("keyId").to_owned();

    let (status, body) = post(&app, "/v1/nxs/complete", &complete).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "recovery_required");

    let (status, recovery_challenge) = post(
        &app,
        "/v1/nxs/register",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "publicKeyJwk": fixture["publicKeyJwk"],
            "registrationId": registration_id,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{recovery_challenge}");
    assert_eq!(recovery_challenge["context"]["mode"], "recover");
    assert_eq!(
        recovery_challenge["context"]["registrationId"],
        registration_id
    );
    assert_eq!(recovery_challenge["pow"]["difficulty"], 0);

    let (complete, _) =
        complete_request(&recovery_challenge, private_d, "intent_fixture_0002", true);
    let (status, recovered) = post(&app, "/v1/nxs/complete", &complete).await;
    assert_eq!(status, StatusCode::OK, "{recovered}");
    assert_eq!(recovered["registrationId"], registration_id);
    assert_eq!(recovered["instanceId"], instance_id);
    assert_eq!(recovered["keyId"], key_id);
    assert_eq!(recovered["leaseGeneration"], 2);
}

#[tokio::test]
async fn recovery_by_saved_challenge_id_and_wrong_key_rejection() {
    let fixture = fixture();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let app = app(0);

    let (_, challenge) = post(
        &app,
        "/v1/nxs/register",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "publicKeyJwk": fixture["publicKeyJwk"],
        }),
    )
    .await;
    let (complete, _) = complete_request(&challenge, private_d, "intent_fixture_0003", true);
    let (status, registration) = post(&app, "/v1/nxs/complete", &complete).await;
    assert_eq!(status, StatusCode::OK, "{registration}");

    let challenge_id = challenge["challengeId"].as_str().expect("challengeId");
    let (status, recovery_challenge) = post(
        &app,
        "/v1/nxs/register",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "publicKeyJwk": fixture["publicKeyJwk"],
            "registrationId": challenge_id,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{recovery_challenge}");
    assert_eq!(
        recovery_challenge["context"]["registrationId"],
        registration["registrationId"]
    );

    let (status, body) = post(
        &app,
        "/v1/nxs/register",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "publicKeyJwk": fixture["rotation"]["replacementPublicKeyJwk"],
            "registrationId": registration["registrationId"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "recovery_unavailable");
}

#[tokio::test]
async fn rejects_insufficient_pow_and_bad_signature() {
    let fixture = fixture();
    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let app = app(8);

    let (_, challenge) = post(
        &app,
        "/v1/nxs/register",
        &json!({
            "protocol": "nethernet-external-signaling-v1",
            "publicKeyJwk": fixture["publicKeyJwk"],
        }),
    )
    .await;

    let (complete, _) = complete_request(&challenge, private_d, "intent_fixture_0004", false);
    let (status, body) = post(&app, "/v1/nxs/complete", &complete).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");

    let (mut complete, _) = complete_request(&challenge, private_d, "intent_fixture_0005", true);
    complete["signature"] = json!("not-a-signature");
    let (status, body) = post(&app, "/v1/nxs/complete", &complete).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");
}
