//! Conformance against the `nostdb-spec` settings fixtures.
//!
//! The fixtures are read from the path the superproject supplies in
//! `NOSTDB_SPEC_FIXTURES`, never copied here. The skip-when-unset behavior keeps a
//! standalone clone building; the root verifier requires the confirmation line, so a skip
//! cannot pass unnoticed.

use nostdb_core::diagnostic::DiagnosticCode;
use nostdb_core::settings::{SettingsDocument, SettingsError};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn category(name: &str) -> Option<PathBuf> {
    let raw = std::env::var("NOSTDB_SPEC_FIXTURES").ok()?;
    let directory = PathBuf::from(raw).join("settings").join(name);
    directory.is_dir().then_some(directory)
}

fn documents(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
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

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn accepted_fixtures_parse() {
    let Some(directory) = category("valid") else {
        println!("settings conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = documents(&directory);
    for path in &paths {
        let name = path.display();
        if let Err(error) = SettingsDocument::parse(&read(path)) {
            panic!("{name} must parse but did not: {error}");
        }
    }
    println!(
        "settings conformance: {} accepted fixtures verified",
        paths.len()
    );
}

#[test]
fn rejected_fixtures_are_refused_with_the_declared_code() {
    let Some(directory) = category("invalid") else {
        println!("settings conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = documents(&directory);
    for path in &paths {
        let name = path.display();
        let declared = expectation(&path.with_extension("expected"));
        let expected = declared
            .get("code")
            .unwrap_or_else(|| panic!("{name} must declare a code"));

        let error = match SettingsDocument::parse(&read(path)) {
            Ok(_) => panic!("{name} must be refused but parsed"),
            Err(error) => error,
        };
        assert_eq!(
            error.code().as_str(),
            expected,
            "{name}: refused with the wrong code: {error}"
        );
        assert!(
            matches!(error.code(), DiagnosticCode::SettingsInvalid)
                || matches!(error.code(), DiagnosticCode::SettingsVersionUnsupported),
            "{name}: {error}"
        );
        // A refusal names the field, so a message is actionable rather than "invalid".
        if let SettingsError::Invalid { field, .. } = &error {
            assert!(!field.is_empty(), "{name}: a refusal must name its field");
        }
    }
    println!(
        "settings conformance: {} rejected fixtures verified",
        paths.len()
    );
}

#[test]
fn merge_fixtures_produce_the_declared_effective_document() {
    let Some(directory) = category("merge") else {
        println!("settings conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };

    let mut count = 0_usize;
    let mut stems: Vec<String> = std::fs::read_dir(&directory)
        .expect("merge directory")
        .filter_map(|entry| {
            let path = entry.expect("directory entry").path();
            let name = path.file_name()?.to_str()?.to_owned();
            name.strip_suffix(".global.json").map(str::to_owned)
        })
        .collect();
    stems.sort();

    for stem in &stems {
        let global = SettingsDocument::parse(&read(&directory.join(format!("{stem}.global.json"))))
            .unwrap_or_else(|error| panic!("{stem}: the global document must parse: {error}"));
        let project =
            SettingsDocument::parse(&read(&directory.join(format!("{stem}.project.json"))))
                .unwrap_or_else(|error| panic!("{stem}: the project document must parse: {error}"));

        let effective = SettingsDocument::resolve(Some(&global), Some(&project));
        let expected: serde_json::Value =
            serde_json::from_str(&read(&directory.join(format!("{stem}.expected.json"))))
                .unwrap_or_else(|error| {
                    panic!("{stem}: the expected document must parse: {error}")
                });

        // Comparing whole documents is deliberate. Checking named fields would let one
        // pass while another quietly changed, which is the failure a merge rule invites.
        assert_eq!(
            effective.to_json(),
            expected,
            "{stem}: the effective document differs"
        );
        count += 1;
    }

    assert!(count > 0, "the merge suite is empty");
    println!("settings conformance: {count} merge fixtures verified");
}
