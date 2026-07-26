//! Conformance against the `nostdb-spec` `.nost` fixtures.
//!
//! The fixtures are read from the path the superproject supplies in
//! `NOSTDB_SPEC_FIXTURES`, never copied here. See `container_conformance.rs` for why
//! the skip-when-unset behavior is safe: the root verifier requires the confirmation
//! line, so a skip cannot pass unnoticed.
//!
//! # Positions are deliberately not compared
//!
//! The fixtures record `reference_line` and `reference_column`, and the language
//! contract marks both informative. They pin the behavior of the reference encoding in
//! `nostdb-spec`, which is a PEG and reports the furthest position it reached while
//! backtracking. This parser is recursive descent and reports the offending token, so
//! its positions legitimately differ. What is required is rejection with a range.

use nostdb_core::diagnostic::{DiagnosticCode, Severity};
use nostdb_core::nost::{format, parse, validate};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

fn category(name: &str) -> Option<PathBuf> {
    let raw = std::env::var("NOSTDB_SPEC_FIXTURES").ok()?;
    let directory = PathBuf::from(raw).join("nost").join(name);
    directory.is_dir().then_some(directory)
}

fn fixtures(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("nost"))
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
fn accepted_fixtures_parse_and_validate_cleanly() {
    let Some(directory) = category("valid") else {
        println!("nost conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = fixtures(&directory);
    assert!(paths.len() >= 9, "expected the published accepted suite");

    for path in &paths {
        let name = path.display();
        let expected = expectation(path);
        assert_eq!(
            expected.get("outcome").map(String::as_str),
            Some("accept"),
            "{name} must declare accept"
        );

        let file = parse(&read(path))
            .unwrap_or_else(|error| panic!("{name} must parse but did not: {error}"));
        let found = validate(&file);
        assert!(
            found.is_empty(),
            "{name} must raise no diagnostic, found {:?}",
            found.iter().map(|d| d.code).collect::<Vec<_>>()
        );
    }
    println!(
        "nost conformance: {} accepted fixtures verified",
        paths.len()
    );
}

#[test]
fn syntactically_invalid_fixtures_are_rejected_with_a_range() {
    let Some(directory) = category("invalid-syntax") else {
        println!("nost conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = fixtures(&directory);
    assert!(paths.len() >= 13, "expected the published rejection suite");

    for path in &paths {
        let name = path.display();
        let expected = expectation(path);
        assert_eq!(
            expected.get("outcome").map(String::as_str),
            Some("reject"),
            "{name} must declare reject"
        );
        assert_eq!(
            expected.get("code").map(String::as_str),
            Some("NOST_PARSE_ERROR"),
            "{name} must declare NOST_PARSE_ERROR"
        );

        match parse(&read(path)) {
            Ok(_) => panic!("{name} must be rejected but parsed"),
            Err(error) => {
                assert_eq!(error.code(), DiagnosticCode::NostParseError);
                // The requirement is a usable range, not a particular position.
                assert!(error.range.start().line >= 1, "{name} needs a range");
                assert!(error.range.start().column >= 1, "{name} needs a column");
                assert!(!error.message.trim().is_empty(), "{name} needs a message");
                let diagnostic = error.to_diagnostic();
                assert_eq!(diagnostic.severity, Severity::Error);
                assert!(diagnostic.range.is_some());
            }
        }
    }
    println!(
        "nost conformance: {} rejected fixtures verified",
        paths.len()
    );
}

#[test]
fn semantically_invalid_fixtures_parse_and_raise_the_declared_code() {
    let Some(directory) = category("invalid-semantic") else {
        println!("nost conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = fixtures(&directory);
    assert!(paths.len() >= 12, "expected the published semantic suite");

    for path in &paths {
        let name = path.display();
        let expected = expectation(path);
        assert_eq!(
            expected.get("outcome").map(String::as_str),
            Some("accept_then_diagnose"),
            "{name} must declare accept_then_diagnose"
        );
        let declared = expected
            .get("code")
            .unwrap_or_else(|| panic!("{name} declares no code"));
        let declared =
            DiagnosticCode::from_str(declared).unwrap_or_else(|error| panic!("{name}: {error}"));

        let file = parse(&read(path)).unwrap_or_else(|error| {
            panic!("{name} is semantically invalid but must parse: {error}")
        });
        let found = validate(&file);
        let codes: Vec<DiagnosticCode> = found.iter().map(|d| d.code).collect();
        assert!(
            codes.contains(&declared),
            "{name} must raise {declared}, found {codes:?}"
        );
        for entry in &found {
            assert!(
                entry.range.is_some(),
                "{name}: every diagnostic needs a range"
            );
        }
    }
    println!(
        "nost conformance: {} semantic fixtures verified",
        paths.len()
    );
}

#[test]
fn accepted_fixtures_round_trip_through_the_formatter() {
    let Some(directory) = category("valid") else {
        println!("nost conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };

    let mut comments_seen = 0_usize;
    for path in &fixtures(&directory) {
        let name = path.display();
        let original = parse(&read(path)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let before = original.all_comments().len();
        comments_seen += before;

        let once = format(&original);
        let reparsed = parse(&once)
            .unwrap_or_else(|error| panic!("{name}: formatted output must parse: {error}"));
        let twice = format(&reparsed);

        assert_eq!(once, twice, "{name}: formatting is not idempotent");
        assert_eq!(
            reparsed.all_comments().len(),
            before,
            "{name}: a comment was lost in the round trip"
        );
        assert!(
            once.ends_with('\n'),
            "{name}: output must end with one newline"
        );
        assert!(
            !once.contains('\r'),
            "{name}: output must not contain U+000D"
        );
        assert!(
            validate(&reparsed).is_empty(),
            "{name}: formatted output must still validate cleanly"
        );
    }
    assert!(
        comments_seen > 0,
        "the accepted suite should exercise comment preservation"
    );
    println!("nost conformance: round trip verified, {comments_seen} comments preserved");
}
