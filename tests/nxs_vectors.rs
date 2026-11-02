use std::path::Path;

use nxsd::encoding::b64url_decode;
use nxsd::jwk::{PublicJwk, sign_es384, verify_es384};
use nxsd::proofs::{CompleteInput, OperationInput, RotateInput, context_digest, verify_pow};

fn fixture() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vendor/upstream/docs/external-signaling/fixtures/nxs-v1.fixtures.json");
    serde_json::from_slice(&std::fs::read(path).expect("nxs fixture is vendored"))
        .expect("nxs fixture parses")
}

#[test]
fn thumbprint_matches_fixture() {
    let fixture = fixture();
    let jwk = PublicJwk::from_json(&fixture["publicKeyJwk"]).expect("public JWK is valid");
    assert_eq!(
        jwk.thumbprint_b64url().expect("thumbprint"),
        fixture["challenge"]["thumbprint"]
    );
}

#[test]
fn complete_payload_matches_fixture_and_verifies() {
    let fixture = fixture();
    let challenge = &fixture["challenge"];
    let context = &challenge["context"];

    let digest = context_digest(
        context["mode"].as_str().expect("mode"),
        context["label"].as_str().expect("label"),
        context["authorizationId"]
            .as_str()
            .expect("authorizationId"),
        context["serviceId"].as_str().expect("serviceId"),
        context["registrationId"].as_str().expect("registrationId"),
    );
    assert_eq!(
        nxsd::encoding::b64url_encode(&digest),
        challenge["contextDigest"]
    );

    let input = CompleteInput {
        audience: challenge["audience"].as_str().expect("audience"),
        challenge_id: challenge["challengeId"].as_str().expect("challengeId"),
        nonce: challenge["nonce"].as_str().expect("nonce"),
        thumbprint: challenge["thumbprint"].as_str().expect("thumbprint"),
        context_digest: challenge["contextDigest"].as_str().expect("contextDigest"),
        expires_at: challenge["expiresAt"].as_u64().expect("expiresAt"),
        proof_nonce: fixture["proofNonce"].as_str().expect("proofNonce"),
        idempotency_key: fixture["idempotencyKey"].as_str().expect("idempotencyKey"),
    };

    let payload = input.payload();
    assert_eq!(payload, fixture["proof"]["payload"]);
    assert!(verify_pow(
        payload.as_bytes(),
        challenge["pow"]["difficulty"].as_u64().expect("difficulty") as u8
    ));

    let jwk = PublicJwk::from_json(&fixture["publicKeyJwk"]).expect("public JWK");
    let signature = b64url_decode(fixture["proof"]["signature"].as_str().expect("signature"))
        .expect("signature decodes");
    verify_es384(&jwk, payload.as_bytes(), &signature).expect("fixture signature verifies");

    let private_d = fixture["privateKeyJwk"]["d"].as_str().expect("private d");
    let our_signature = sign_es384(private_d, payload.as_bytes()).expect("can sign");
    verify_es384(&jwk, payload.as_bytes(), &our_signature).expect("our signature verifies");
}

#[test]
fn operation_payload_matches_fixture_and_verifies() {
    let fixture = fixture();
    let request = &fixture["request"];
    let input = &request["input"];

    let body = input["body"].as_str().expect("body").as_bytes();
    let operation = OperationInput {
        audience: input["audience"].as_str().expect("audience"),
        method: input["method"].as_str().expect("method"),
        path: input["path"].as_str().expect("path"),
        timestamp: input["timestamp"].as_u64().expect("timestamp"),
        instance_id: input["instanceId"].as_str().expect("instanceId"),
        key_id: input["keyId"].as_str().expect("keyId"),
        idempotency_key: input["idempotencyKey"].as_str().expect("idempotencyKey"),
        generation: input["generation"].as_u64().expect("generation"),
        sequence: input["sequence"].as_u64().expect("sequence"),
        body,
    };

    let payload = operation.payload();
    assert_eq!(payload, request["payload"]);

    let jwk = PublicJwk::from_json(&fixture["publicKeyJwk"]).expect("public JWK");
    let signature =
        b64url_decode(request["signature"].as_str().expect("signature")).expect("signature");
    verify_es384(&jwk, payload.as_bytes(), &signature).expect("fixture signature verifies");
}

#[test]
fn rotation_payload_matches_fixture_and_verifies() {
    let fixture = fixture();
    let rotation = &fixture["rotation"];
    let input = &rotation["input"];
    let replacement =
        PublicJwk::from_json(&rotation["replacementPublicKeyJwk"]).expect("replacement JWK");

    let rotate = RotateInput {
        audience: input["audience"].as_str().expect("audience"),
        instance_id: input["instanceId"].as_str().expect("instanceId"),
        old_key_id: input["oldKeyId"].as_str().expect("oldKeyId"),
        new_thumbprint: &replacement.thumbprint_b64url().expect("thumbprint"),
        generation: input["generation"].as_u64().expect("generation"),
        idempotency_key: input["idempotencyKey"].as_str().expect("idempotencyKey"),
    };

    let payload = rotate.payload();
    assert_eq!(payload, rotation["payload"]);
    let signature =
        b64url_decode(rotation["signature"].as_str().expect("signature")).expect("signature");
    verify_es384(&replacement, payload.as_bytes(), &signature)
        .expect("replacement key verifies its own rotation proof");
}
