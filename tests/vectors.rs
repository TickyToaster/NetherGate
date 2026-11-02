use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/upstream/docs/external-signaling/fixtures")
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(name)).expect("fixture is vendored")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn upstream_provenance_hashes_match_vendored_bytes() {
    let provenance: serde_json::Value =
        serde_json::from_slice(&read_fixture("provenance.json")).expect("provenance parses");
    let files = provenance["files"]
        .as_object()
        .expect("provenance has files");

    assert!(!files.is_empty());
    for (name, expected) in files {
        let expected = expected.as_str().expect("hash is a string");
        let actual = sha256_hex(&read_fixture(name));
        assert_eq!(actual, expected, "hash mismatch for {name}");
    }
}

#[test]
fn all_vendored_fixtures_parse_as_json() {
    for entry in std::fs::read_dir(fixtures_dir()).expect("fixtures directory exists") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("fixture is readable");
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()));
    }
}

#[test]
fn expected_v1_vectors_are_present() {
    let nxs: serde_json::Value =
        serde_json::from_slice(&read_fixture("nxs-v1.fixtures.json")).expect("nxs fixture parses");
    for key in ["challenge", "proof", "request", "rotation", "fleetExamples"] {
        assert!(nxs.get(key).is_some(), "nxs fixture missing {key}");
    }

    let origins: serde_json::Value = serde_json::from_slice(&read_fixture("origins.fixtures.json"))
        .expect("origins fixture parses");
    assert!(origins["vectors"].as_array().is_some_and(|v| !v.is_empty()));

    let admission: serde_json::Value =
        serde_json::from_slice(&read_fixture("stateless-admission-v1.fixtures.json"))
            .expect("admission fixture parses");
    for key in ["claims", "context", "expected", "rejections", "identity"] {
        assert!(
            admission.get(key).is_some(),
            "admission fixture missing {key}"
        );
    }
}
