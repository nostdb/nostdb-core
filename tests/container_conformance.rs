//! Conformance against the `nostdb-spec` container fixtures.
//!
//! The fixtures are not copied here. `nostdb-spec` owns them, and copying them would
//! create a second conformance suite that could drift from the published one.
//!
//! Instead this test reads them from a path the superproject supplies through
//! `NOSTDB_SPEC_FIXTURES`, so it runs against the exact pinned commit. When the
//! variable is absent, which is the case for a standalone clone of this repository,
//! the test reports that it was skipped and passes: an independent build must not
//! require a sibling checkout.
//!
//! A skipped test proves nothing, so the root workspace verifier runs this with the
//! variable set and fails unless the "fixtures verified" line appears. That is what
//! keeps the skip from turning into a silent hole.

use nostdb_core::container::{Container, ContainerError};
use nostdb_core::diagnostic::DiagnosticCode;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

/// Fixture count the published suite is known to contain, used as a floor so a
/// truncated or mis-pointed fixture directory cannot pass quietly.
const MINIMUM_FIXTURES: usize = 20;

fn fixtures_directory() -> Option<PathBuf> {
    let raw = std::env::var("NOSTDB_SPEC_FIXTURES").ok()?;
    let directory = PathBuf::from(raw).join("nostdb").join("header");
    directory.is_dir().then_some(directory)
}

fn decode_hex(path: &Path) -> Vec<u8> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut digits = String::new();
    for line in text.lines() {
        let payload = line.split('#').next().unwrap_or("");
        for character in payload.chars() {
            if character.is_ascii_whitespace() {
                continue;
            }
            assert!(
                character.is_ascii_hexdigit(),
                "{} contains a non-hexadecimal character {character:?}",
                path.display()
            );
            digits.push(character);
        }
    }
    assert!(
        digits.len() % 2 == 0,
        "{} has an odd number of hexadecimal digits",
        path.display()
    );
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(text, 16).expect("hexadecimal byte")
        })
        .collect()
}

fn expectation(path: &Path) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
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

#[test]
fn every_container_fixture_reproduces_its_declared_outcome() {
    let Some(directory) = fixtures_directory() else {
        println!(
            "container conformance: skipped, NOSTDB_SPEC_FIXTURES is unset or does not \
             name a fixture directory"
        );
        return;
    };

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("hex"))
        .collect();
    paths.sort();

    let mut accepted = 0_usize;
    let mut rejected = 0_usize;

    for path in &paths {
        let name = path.display();
        let declared = expectation(&path.with_extension("expected"));
        let bytes = decode_hex(path);
        let outcome = Container::parse(&bytes);

        match declared.get("outcome").map(String::as_str) {
            Some("accept") => {
                let container = outcome.unwrap_or_else(|error| {
                    panic!("{name} must be accepted but was rejected: {error}")
                });
                // An accepted container must also be readable, not merely validated.
                for section in container.sections() {
                    assert_eq!(
                        container.section(section.kind).map(<[u8]>::len),
                        Some(section.payload.len()),
                        "{name}: a section was validated but is not retrievable"
                    );
                }
                accepted += 1;
            }
            Some("reject") => {
                let expected = declared
                    .get("code")
                    .unwrap_or_else(|| panic!("{name} declares reject with no code"));
                let expected = DiagnosticCode::from_str(expected)
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
                match outcome {
                    Ok(_) => panic!("{name} must be rejected but was accepted"),
                    Err(error) => assert_eq!(
                        error.code(),
                        expected,
                        "{name} must be rejected with {expected}, not {} ({error})",
                        error.code()
                    ),
                }
                rejected += 1;
            }
            other => panic!("{name} has unusable outcome {other:?}"),
        }
    }

    let total = accepted + rejected;
    assert!(
        total >= MINIMUM_FIXTURES,
        "expected at least {MINIMUM_FIXTURES} container fixtures, found {total} in {}",
        directory.display()
    );
    assert!(
        accepted >= 2,
        "the suite must accept more than one container"
    );
    assert!(rejected >= 10, "the suite must cover rejection broadly");

    println!(
        "container conformance: {total} fixtures verified, {accepted} accepted and \
         {rejected} rejected"
    );
}

#[test]
fn the_three_container_diagnostic_codes_are_all_exercised() {
    let Some(directory) = fixtures_directory() else {
        println!("container conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };

    let mut seen: Vec<DiagnosticCode> = Vec::new();
    for entry in std::fs::read_dir(&directory).expect("fixture directory") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("expected") {
            continue;
        }
        if let Some(code) = expectation(&path).get("code")
            && let Ok(code) = DiagnosticCode::from_str(code)
            && !seen.contains(&code)
        {
            seen.push(code);
        }
    }

    for required in [
        DiagnosticCode::NostdbCorrupt,
        DiagnosticCode::NostdbFormatUnsupported,
        DiagnosticCode::NostdbLimitExceeded,
    ] {
        assert!(
            seen.contains(&required),
            "no container fixture exercises {required}"
        );
    }
}

#[test]
fn a_rejected_fixture_never_yields_a_container() {
    // Guards against a reader that reports an error yet still hands back a partially
    // populated container, which a caller could mistake for a usable database.
    let Some(directory) = fixtures_directory() else {
        println!("container conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };

    for entry in std::fs::read_dir(&directory).expect("fixture directory") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("hex") {
            continue;
        }
        let declared = expectation(&path.with_extension("expected"));
        if declared.get("outcome").map(String::as_str) != Some("reject") {
            continue;
        }
        let result: Result<Container, ContainerError> = Container::parse(&decode_hex(&path));
        assert!(result.is_err(), "{} must not parse", path.display());
    }
}
