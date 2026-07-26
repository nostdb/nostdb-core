//! Conformance against the `nostdb-spec` Cypher fixtures.
//!
//! Fixtures are read from the path the superproject supplies in `NOSTDB_SPEC_FIXTURES`,
//! never copied here. The root verifier requires the confirmation line, so a skip in a
//! standalone clone cannot pass unnoticed.
//!
//! Positions are not compared, for the same reason as the `.nost` suite: where a parser
//! notices that a construct is outside the subset is an artifact of its design.

use nostdb_core::cypher::parse;
use nostdb_core::diagnostic::DiagnosticCode;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

fn category(name: &str) -> Option<PathBuf> {
    let raw = std::env::var("NOSTDB_SPEC_FIXTURES").ok()?;
    let directory = PathBuf::from(raw).join("cypher").join(name);
    directory.is_dir().then_some(directory)
}

fn fixtures(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("cypher"))
        .collect();
    paths.sort();
    paths
}

fn expectation(path: &Path) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(path.with_extension("expected")).unwrap_or_else(|error| {
        panic!(
            "cannot read the expectation for {}: {error}",
            path.display()
        )
    });
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    map
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn supported_fixtures_parse() {
    let Some(directory) = category("supported") else {
        println!("cypher conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = fixtures(&directory);
    assert!(paths.len() >= 15, "expected the published supported suite");

    for path in &paths {
        let name = path.display();
        assert_eq!(
            expectation(path).get("outcome").map(String::as_str),
            Some("accept"),
            "{name} must declare accept"
        );
        if let Err(error) = parse(&read(path)) {
            panic!("{name} must parse but was refused: {error}");
        }
    }
    println!(
        "cypher conformance: {} supported fixtures verified",
        paths.len()
    );
}

#[test]
fn unsupported_fixtures_are_refused_with_the_declared_code() {
    let Some(directory) = category("unsupported") else {
        println!("cypher conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = fixtures(&directory);
    assert!(paths.len() >= 13, "expected the published refusal suite");

    for path in &paths {
        let name = path.display();
        let declared = expectation(path);
        assert_eq!(
            declared.get("outcome").map(String::as_str),
            Some("reject"),
            "{name} must declare reject"
        );
        let expected = DiagnosticCode::from_str(
            declared
                .get("code")
                .unwrap_or_else(|| panic!("{name} declares no code")),
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));

        match parse(&read(path)) {
            Ok(_) => panic!("{name} must be refused but parsed"),
            Err(error) => {
                assert_eq!(
                    error.code, expected,
                    "{name} must be refused with {expected}, not {} ({error})",
                    error.code
                );
                // A usable range is required; its exact position is not.
                assert!(error.range.start().line >= 1, "{name} needs a range");
                assert!(!error.message.trim().is_empty(), "{name} needs a message");
            }
        }
    }
    println!(
        "cypher conformance: {} unsupported fixtures verified",
        paths.len()
    );
}

#[test]
fn a_refused_query_produces_no_plan() {
    // The guarantee the contract makes is that nothing executes. Expressed in the type
    // system: a refusal yields Err, so there is no partial query to run.
    let Some(directory) = category("unsupported") else {
        println!("cypher conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    for path in &fixtures(&directory) {
        assert!(
            parse(&read(path)).is_err(),
            "{} must yield no query",
            path.display()
        );
    }
}
