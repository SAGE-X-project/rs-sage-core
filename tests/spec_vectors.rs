//! Runs the sage-spec test vectors (https://github.com/SAGE-X-project/sage-spec)
//! against this crate. The vectors directory is found through
//! `SAGE_SPEC_VECTORS`, else `.sage-spec/vectors` (CI checkout), else
//! `../sage-spec/vectors` (sibling checkout). Suites the crate does not
//! implement yet are listed in `NOT_YET` and reported, not failed; the list
//! shrinks with every alignment step.

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct File {
    suite: String,
    spec_version: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    mode: String,
    input: serde_json::Value,
    output: serde_json::Value,
}

/// Suites and vectors this crate does not implement yet (F-03 steps 3-7).
const NOT_YET: &[&str] = &["crypto", "rfc9421", "hpke", "session", "did"];

fn vectors_dir() -> PathBuf {
    if let Ok(d) = std::env::var("SAGE_SPEC_VECTORS") {
        return PathBuf::from(d);
    }
    for c in [".sage-spec/vectors", "../sage-spec/vectors"] {
        let p = PathBuf::from(c);
        if p.join("jcs.json").exists() {
            return p;
        }
    }
    panic!("sage-spec vectors not found: set SAGE_SPEC_VECTORS or check out sage-spec next to this repository");
}

fn load(suite: &str) -> File {
    let path = vectors_dir().join(format!("{suite}.json"));
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let f: File = serde_json::from_slice(&data).unwrap();
    assert_eq!(f.suite, suite);
    f
}

fn str_field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

#[test]
fn jcs_suite() {
    let f = load("jcs");
    println!("jcs: spec {}", f.spec_version);
    let mut failures = Vec::new();
    for v in &f.vectors {
        assert_eq!(v.mode, "deterministic", "{}", v.name);
        let input = str_field(&v.input, "json");
        let want = str_field(&v.output, "canonical");
        let want_hex = str_field(&v.output, "canonical_hex");
        match sage_crypto_core::jcs::canonicalize(input.as_bytes()) {
            Ok(got) => {
                if got != want.as_bytes() || hex::encode(&got) != want_hex {
                    failures.push(format!(
                        "{}: got {:?}, want {:?}",
                        v.name,
                        String::from_utf8_lossy(&got),
                        want
                    ));
                } else {
                    println!("pass jcs/{}", v.name);
                }
            }
            Err(e) => failures.push(format!("{}: {e}", v.name)),
        }
    }
    assert!(
        failures.is_empty(),
        "jcs vectors failed:\n{}",
        failures.join("\n")
    );
}

#[test]
fn unimplemented_suites_are_listed() {
    for suite in NOT_YET {
        let f = load(suite);
        println!(
            "skip {suite}: {} vectors not run yet (F-03)",
            f.vectors.len()
        );
    }
}
