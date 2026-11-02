use std::path::Path;

use nxsd::origin::Origin;

#[test]
fn passes_every_origin_vector() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vendor/upstream/docs/external-signaling/fixtures/origins.fixtures.json");
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("origin fixture is vendored"))
            .expect("origin fixture parses");
    let vectors = fixture["vectors"].as_array().expect("vectors array");

    let mut failures = Vec::new();
    for vector in vectors {
        let input = vector["origin"].as_str().expect("origin is a string");
        let accepted = vector["accepted"].as_bool().expect("accepted is boolean");
        let parsed = Origin::parse(input);
        if parsed.is_ok() != accepted {
            failures.push(format!(
                "{}: expected accepted={accepted}, got {:?}",
                input.escape_debug(),
                parsed
            ));
            continue;
        }
        if let Ok(origin) = parsed {
            assert_eq!(origin.as_str(), input, "accepted origin must retain bytes");
        }
    }

    assert!(
        failures.is_empty(),
        "{} origin vector failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
