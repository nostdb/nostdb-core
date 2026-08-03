//! Conformance against the `nostdb-spec` result-envelope fixtures.
//!
//! The specification suite checks that each fixture has the shape the contract states.
//! This suite goes the other way: it applies the same rules to envelopes the Engine
//! actually produces, so a writer that could emit a rejected shape fails here rather than
//! being absorbed by a lenient reader.

use nostdb_core::diagnostic::{Diagnostic, DiagnosticCode, Severity};
use nostdb_core::execute::Scoped;
use nostdb_core::execute::{QueryValue, execute};
use nostdb_core::generation::Generation;
use nostdb_core::id::{LocalEdgeId, LocalNodeId};
use nostdb_core::mutate::WriteSummary;
use nostdb_core::property::FiniteF64;
use nostdb_core::result::ResultEnvelope;
use nostdb_core::text::NonEmptyText;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

const TAGS: [&str; 6] = [
    "bytes",
    "datetime",
    "node",
    "relationship",
    "path",
    "object",
];

fn fixture_root() -> Option<PathBuf> {
    let raw = std::env::var("NOSTDB_SPEC_FIXTURES").ok()?;
    let directory = PathBuf::from(raw).join("result");
    directory.is_dir().then_some(directory)
}

fn registry_codes() -> BTreeSet<String> {
    // The registry sits beside the fixtures, so the same variable locates both.
    let raw = std::env::var("NOSTDB_SPEC_FIXTURES").expect("checked by the caller");
    let registry = PathBuf::from(raw)
        .parent()
        .expect("fixtures has a parent")
        .join("diagnostics.json");
    let text = std::fs::read_to_string(&registry)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", registry.display()));
    let document: Value = serde_json::from_str(&text).expect("the registry is JSON");
    document["codes"]
        .as_array()
        .expect("codes array")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code string").to_owned())
        .collect()
}

/// The contract's rules, applied to a produced envelope.
///
/// Deliberately a separate implementation from the one in `nostdb-spec`. Sharing it would
/// make agreement automatic and therefore meaningless.
fn violation(document: &Value, codes: &BTreeSet<String>) -> Option<String> {
    let object = document.as_object()?;
    // Both supported versions are accepted. An envelope is a message rather than a stored
    // artifact, so version 1 stays readable: it carries nothing version 2 cannot express,
    // and a version 1 producer never emits the object form version 2 added.
    if !matches!(
        object.get("result_version").and_then(Value::as_u64),
        Some(1 | 2)
    ) {
        return Some("result_version must be 1 or 2".to_owned());
    }
    let columns = object.get("columns")?.as_array()?;
    let rows = object.get("rows")?.as_array()?;
    let summary = object.get("summary")?.as_object()?;
    let warnings = object.get("warnings")?.as_array()?;

    for (index, row) in rows.iter().enumerate() {
        let row = row.as_array()?;
        if row.len() != columns.len() {
            return Some(format!("row {index} does not match the column count"));
        }
        for value in row {
            if let Some(object) = value.as_object() {
                if object.len() != 1 {
                    return Some("a tagged value carries exactly one member".to_owned());
                }
                let tag = object.keys().next()?;
                if !TAGS.contains(&tag.as_str()) {
                    return Some(format!("`{tag}` is not a tagged form"));
                }
                if tag == "path" {
                    let path = object[tag].as_object()?;
                    let nodes = path.get("nodes")?.as_array()?.len();
                    let relationships = path.get("relationships")?.as_array()?.len();
                    if nodes != relationships + 1 {
                        return Some("a path alternates".to_owned());
                    }
                }
            }
        }
    }

    if summary.get("rows").and_then(Value::as_u64) != Some(rows.len() as u64) {
        return Some("the summary row count disagrees with the rows".to_owned());
    }
    for field in ["database_generation", "linked_databases_opened"] {
        summary.get(field)?.as_u64()?;
    }
    let partial = summary.get("partial")?.as_bool()?;
    if let Some(writes) = summary.get("writes")
        && writes
            .as_object()?
            .values()
            .all(|value| value.as_u64() == Some(0))
    {
        return Some("a read must omit `writes`".to_owned());
    }
    if partial && warnings.is_empty() {
        return Some("a partial result names no unreachable source".to_owned());
    }
    for warning in warnings {
        let code = warning.get("code")?.as_str()?;
        if !codes.contains(code) {
            return Some(format!("{code} is not registered"));
        }
        warning.get("message")?.as_str()?;
    }
    None
}

fn warning(code: DiagnosticCode) -> Diagnostic {
    Diagnostic {
        code,
        severity: Severity::Warning,
        message: NonEmptyText::new("a warning").unwrap(),
        source: None,
        range: None,
        details: Vec::new(),
    }
}

/// Envelopes covering every shape the Engine can produce.
fn produced() -> Vec<(&'static str, ResultEnvelope)> {
    let node = Scoped::root(LocalNodeId::from_bytes([1; 16]));
    let edge = Scoped::root(LocalEdgeId::from_bytes([2; 16]));
    vec![
        (
            "empty",
            ResultEnvelope {
                columns: Vec::new(),
                rows: Vec::new(),
                database_generation: 1,
                linked_databases_opened: 0,
                writes: None,
                warnings: Vec::new(),
            },
        ),
        (
            "every value form",
            ResultEnvelope {
                columns: vec![
                    "null".to_owned(),
                    "boolean".to_owned(),
                    "integer".to_owned(),
                    "double".to_owned(),
                    "text".to_owned(),
                    "list".to_owned(),
                    "node".to_owned(),
                    "relationship".to_owned(),
                    "path".to_owned(),
                ],
                rows: vec![vec![
                    QueryValue::Null,
                    QueryValue::Boolean(true),
                    QueryValue::Integer(-7),
                    QueryValue::Float(FiniteF64::new(0.5).unwrap()),
                    QueryValue::Text("login".to_owned()),
                    QueryValue::List(vec![QueryValue::Integer(1)]),
                    QueryValue::Node(node),
                    QueryValue::Relationship(edge),
                    QueryValue::Path {
                        nodes: vec![node],
                        relationships: Vec::new(),
                    },
                ]],
                database_generation: 42,
                linked_databases_opened: 2,
                writes: None,
                warnings: Vec::new(),
            },
        ),
        (
            "an object value, with a nested key that shadows a tag",
            ResultEnvelope {
                columns: vec!["detail".to_owned()],
                rows: vec![vec![QueryValue::Object(vec![
                    (
                        nostdb_core::PropertyKey::new("path").unwrap(),
                        QueryValue::Text("not a path".to_owned()),
                    ),
                    (
                        nostdb_core::PropertyKey::new("nested").unwrap(),
                        QueryValue::Object(vec![(
                            nostdb_core::PropertyKey::new("n").unwrap(),
                            QueryValue::Integer(1),
                        )]),
                    ),
                ])]],
                database_generation: 4,
                linked_databases_opened: 0,
                writes: None,
                warnings: Vec::new(),
            },
        ),
        (
            "partial with each link warning",
            ResultEnvelope {
                columns: vec!["n".to_owned()],
                rows: Vec::new(),
                database_generation: 3,
                linked_databases_opened: 1,
                writes: None,
                warnings: vec![
                    warning(DiagnosticCode::LinkUnavailable),
                    warning(DiagnosticCode::LinkCycle),
                    warning(DiagnosticCode::LinkLimitExceeded),
                ],
            },
        ),
        (
            "a write",
            ResultEnvelope {
                columns: Vec::new(),
                rows: Vec::new(),
                database_generation: 4,
                linked_databases_opened: 0,
                writes: Some(WriteSummary {
                    nodes_created: 2,
                    ..WriteSummary::default()
                }),
                warnings: Vec::new(),
            },
        ),
    ]
}

#[test]
fn every_envelope_the_engine_produces_satisfies_the_contract() {
    if fixture_root().is_none() {
        println!("result conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    }
    let codes = registry_codes();
    let cases = produced();
    for (name, envelope) in &cases {
        let rendered = envelope.to_json();
        assert_eq!(
            violation(&rendered, &codes),
            None,
            "{name} breaks the contract:\n{rendered:#}"
        );
    }
    println!(
        "result conformance: {} produced envelopes verified",
        cases.len()
    );
}

#[test]
fn a_real_query_produces_a_conforming_envelope() {
    // The shapes above are hand-built. This one comes out of the query engine, so it
    // proves the wiring rather than the renderer.
    if fixture_root().is_none() {
        println!("result conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    }
    let codes = registry_codes();
    let mut graph = nostdb_core::encoding::Graph::default();
    let context = nostdb_core::execute::DatabaseContext {
        generation: Some(Generation::from_raw(1)),
        source: None,
    };

    let query = nostdb_core::cypher::parse(
        "CREATE (a:Function {name: \"login\"}), (b:Function {name: \"other\"})",
    )
    .expect("must parse");
    let written = execute(
        &query,
        &mut graph,
        &nostdb_core::execute::Parameters::new(),
        &context,
    )
    .expect("must execute");
    let writes = written.writes;
    let envelope = ResultEnvelope::new(written, Generation::from_raw(2), Some(writes));
    let rendered = envelope.to_json();
    assert_eq!(violation(&rendered, &codes), None, "{rendered:#}");
    assert_eq!(rendered["summary"]["writes"]["nodes_created"], 2);

    let query = nostdb_core::cypher::parse("MATCH (n:Function) RETURN n.name ORDER BY n.name")
        .expect("must parse");
    let read = execute(
        &query,
        &mut graph,
        &nostdb_core::execute::Parameters::new(),
        &context,
    )
    .expect("must execute");
    let envelope = ResultEnvelope::new(read, Generation::from_raw(2), None);
    let rendered = envelope.to_json();
    assert_eq!(violation(&rendered, &codes), None, "{rendered:#}");
    assert_eq!(rendered["summary"]["rows"], 2);
    assert_eq!(rendered["rows"][0][0], "login");
    assert!(
        rendered["summary"].get("writes").is_none(),
        "a read reports no write summary"
    );
    println!("result conformance: a produced query envelope verified");
}

#[test]
fn every_accepted_fixture_is_a_shape_this_build_would_accept() {
    // Reading the published suite as well as writing against it: a fixture the Engine's
    // own rules would reject means the two disagree about the contract.
    let Some(root) = fixture_root() else {
        println!("result conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let codes = registry_codes();
    let mut count = 0_usize;
    let mut paths: Vec<PathBuf> = std::fs::read_dir(root.join("valid"))
        .expect("valid fixtures")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    paths.sort();
    for path in &paths {
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("fixture is UTF-8"))
                .expect("fixture is JSON");
        assert_eq!(
            violation(&document, &codes),
            None,
            "{} is accepted by the specification and rejected here",
            path.display()
        );
        count += 1;
    }
    assert!(count > 0, "no accepted fixtures were read");
    println!("result conformance: {count} published envelopes verified");
}
