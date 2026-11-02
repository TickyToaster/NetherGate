use std::path::Path;

use nxsd::admission::{
    AdmissionClaims, AdmissionContext, derive_ice_pwd, identity_binding, open_token,
    seal_token_with_nonce,
};

fn fixture() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "vendor/upstream/docs/external-signaling/fixtures/stateless-admission-v1.fixtures.json",
    );
    serde_json::from_slice(&std::fs::read(path).expect("admission fixture is vendored"))
        .expect("admission fixture parses")
}

fn context<'a>(fixture: &'a serde_json::Value) -> AdmissionContext<'a> {
    AdmissionContext {
        key_id: fixture["context"]["keyId"].as_str().expect("keyId"),
        secret: fixture["context"]["secret"].as_str().expect("secret"),
        audience: fixture["context"]["audience"].as_str().expect("audience"),
    }
}

fn claims<'a>(fixture: &'a serde_json::Value) -> AdmissionClaims<'a> {
    let claims = &fixture["claims"];
    let fingerprint_hex = claims["clientFingerprintHex"]
        .as_str()
        .expect("clientFingerprintHex");
    let binding_hex = claims["identityBindingHex"]
        .as_str()
        .expect("identityBindingHex");
    AdmissionClaims {
        expires_at_ms: claims["expiresAt"].as_u64().expect("expiresAt"),
        client_fingerprint: hex::decode(fingerprint_hex)
            .expect("fingerprint hex")
            .try_into()
            .expect("32-byte fingerprint"),
        client_sctp_port: claims["clientSctpPort"].as_u64().expect("clientSctpPort") as u16,
        client_max_message_size: claims["clientMaxMessageSize"]
            .as_u64()
            .expect("clientMaxMessageSize") as u32,
        identity_binding: hex::decode(binding_hex)
            .expect("binding hex")
            .try_into()
            .expect("16-byte binding"),
        network_id: claims["networkId"]
            .as_str()
            .expect("networkId")
            .parse()
            .expect("u64 networkId"),
        client_ice_pwd: claims["clientIcePwd"].as_str().expect("clientIcePwd"),
    }
}

#[test]
fn seal_matches_fixture_ufrag_ice_pwd_and_binding() {
    let fixture = fixture();
    let context = context(&fixture);
    let claims = claims(&fixture);
    let nonce: [u8; 12] = hex::decode(fixture["nonceHex"].as_str().expect("nonceHex"))
        .expect("nonce hex")
        .try_into()
        .expect("12-byte nonce");
    let client_ufrag = fixture["clientIceUfrag"].as_str().expect("clientIceUfrag");

    let answer_ufrag =
        seal_token_with_nonce(&context, &claims, client_ufrag, &nonce).expect("seals");
    assert_eq!(answer_ufrag, fixture["expected"]["localUfrag"]);
    assert_eq!(
        answer_ufrag.len(),
        fixture["expected"]["ufragLength"]
            .as_u64()
            .expect("ufragLength") as usize
    );

    assert_eq!(
        derive_ice_pwd(context.secret, context.audience, &answer_ufrag),
        fixture["expected"]["icePwd"]
    );

    let binding = identity_binding(
        context.secret,
        context.audience,
        fixture["identity"]["canonicalCpk"]
            .as_str()
            .expect("canonicalCpk"),
    );
    assert_eq!(
        hex::encode(binding),
        fixture["claims"]["identityBindingHex"]
    );

    let opened = open_token(&context, &answer_ufrag, client_ufrag).expect("opens");
    assert_eq!(opened.expires_at_ms, claims.expires_at_ms);
    assert_eq!(opened.client_fingerprint, claims.client_fingerprint);
    assert_eq!(opened.client_sctp_port, claims.client_sctp_port);
    assert_eq!(
        opened.client_max_message_size,
        claims.client_max_message_size
    );
    assert_eq!(opened.identity_binding, claims.identity_binding);
    assert_eq!(opened.network_id, claims.network_id);
    assert_eq!(opened.client_ice_pwd, claims.client_ice_pwd);
}

#[test]
fn rejects_tampered_wrong_host_and_wrong_client_ufrag() {
    let fixture = fixture();
    let context = context(&fixture);
    let client_ufrag = fixture["clientIceUfrag"].as_str().expect("clientIceUfrag");
    let answer_ufrag = fixture["expected"]["localUfrag"]
        .as_str()
        .expect("localUfrag");

    let mut tampered = answer_ufrag.to_owned();
    let last = tampered.pop().expect("nonempty");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(open_token(&context, &tampered, client_ufrag).is_err());

    let wrong_host = AdmissionContext {
        audience: "nxs-stateless-host-v1/ffffffffffffffffffffffffffffffff",
        ..context
    };
    assert!(open_token(&wrong_host, answer_ufrag, client_ufrag).is_err());

    let wrong_key = AdmissionContext {
        secret: "BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        ..context
    };
    assert!(open_token(&wrong_key, answer_ufrag, client_ufrag).is_err());

    assert!(open_token(&context, answer_ufrag, "wrongClientUfrag").is_err());
}

#[test]
fn rejects_noncanonical_base64_and_over_budget_password() {
    let fixture = fixture();
    let context = context(&fixture);
    let client_ufrag = fixture["clientIceUfrag"].as_str().expect("clientIceUfrag");
    let answer_ufrag = fixture["expected"]["localUfrag"]
        .as_str()
        .expect("localUfrag");

    assert!(open_token(&context, &format!("{answer_ufrag}="), client_ufrag).is_err());

    let mut claims = claims(&fixture);
    let long_password = "A".repeat(92);
    claims.client_ice_pwd = &long_password;
    let nonce = [0u8; 12];
    assert!(seal_token_with_nonce(&context, &claims, client_ufrag, &nonce).is_err());
}
