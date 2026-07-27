//! Conformance against the `nostdb-spec` change-set fixtures.
//!
//! Every accepted fixture must be a document this build reads, and every rejected one must
//! be refused with the code the fixture declares. A contract with fixtures nothing runs is
//! documentation, so this is the gate that makes the published set mean something.

use nostdb_core::change_document::{DocumentError, code_for, parse};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn fixture_root() -> Option<PathBuf> {
    let raw = std::env::var("NOSTDB_SPEC_FIXTURES").ok()?;
    let directory = PathBuf::from(raw).join("change_set");
    directory.is_dir().then_some(directory)
}

/// The `key = value` lines beside a fixture.
fn expectations(path: &Path) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(path.with_extension("expected")).unwrap_or_else(|error| {
        panic!(
            "cannot read the expectation for {}: {error}",
            path.display()
        )
    });
    text.lines()
        .filter_map(|line| line.split_once(" = "))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn documents(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_accepted_fixture_is_read() {
    let Some(root) = fixture_root() else {
        println!("change set conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = documents(&root.join("valid"));
    assert!(!paths.is_empty(), "no accepted fixtures were found");
    for path in &paths {
        let expected = expectations(path);
        assert_eq!(expected.get("outcome").map(String::as_str), Some("accept"));
        let text = std::fs::read_to_string(path).expect("fixture is UTF-8");
        match parse(&text) {
            Ok(change_set) => assert!(
                !change_set.operations.is_empty(),
                "{} was read as proposing nothing",
                path.display()
            ),
            Err(errors) => panic!(
                "{} is accepted by the specification and refused here: {errors:?}",
                path.display()
            ),
        }
    }
    println!(
        "change set conformance: {} accepted fixtures verified",
        paths.len()
    );
}

#[test]
fn every_rejected_fixture_is_refused_with_the_declared_code() {
    // The code matters as much as the refusal. A caller branches on it, and reporting
    // `CHANGE_SET_INVALID` where the contract says the version is unreadable would send
    // somebody looking for a malformed operation that is not there.
    let Some(root) = fixture_root() else {
        println!("change set conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = documents(&root.join("invalid"));
    assert!(!paths.is_empty(), "no rejected fixtures were found");
    for path in &paths {
        let expected = expectations(path);
        assert_eq!(expected.get("outcome").map(String::as_str), Some("reject"));
        let declared = expected
            .get("code")
            .unwrap_or_else(|| panic!("{} declares no code", path.display()));

        let text = std::fs::read_to_string(path).expect("fixture is UTF-8");
        let Err(errors) = parse(&text) else {
            panic!(
                "{} is rejected by the specification and accepted here",
                path.display()
            );
        };
        let codes: Vec<&str> = errors
            .iter()
            .map(|error| code_for(error).as_str())
            .collect();
        assert!(
            codes.contains(&declared.as_str()),
            "{} declares {declared} and this build reported {codes:?}",
            path.display()
        );
    }
    println!(
        "change set conformance: {} rejected fixtures verified",
        paths.len()
    );
}

#[test]
fn a_batch_is_reported_in_one_pass() {
    // A producer fixing a document should not have to run it once per mistake.
    let text = r#"{
      "change_set_version": 1,
      "base_generation": 1,
      "owner": {"kind": "user"},
      "source_snapshot": "manual",
      "operations": [
        {"operation": "upsert_node", "labels": [], "source_unit": "u_00000000-0000-0000-0000-000000000000", "evidence": []},
        {"operation": "frobnicate"},
        {"operation": "upsert_edge", "relation": "CALLS", "source_unit": "u_00000000-0000-0000-0000-000000000000", "evidence": []}
      ]
    }"#;
    let errors = parse(text).expect_err("three operations are wrong");
    assert!(errors.len() >= 3, "{errors:?}");
}

#[test]
fn an_unreadable_version_is_reported_alone() {
    // Nothing after it is interpretable, and twenty consequential errors would bury the
    // one that matters.
    let text = r#"{"change_set_version": 99, "operations": []}"#;
    let errors = parse(text).expect_err("the version is not readable");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(matches!(
        errors[0],
        DocumentError::UnsupportedVersion { found: 99 }
    ));
}
