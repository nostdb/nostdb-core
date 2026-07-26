//! Conformance against the `nostdb-spec` Cypher fixtures.
//!
//! Fixtures are read from the path the superproject supplies in `NOSTDB_SPEC_FIXTURES`,
//! never copied here. The root verifier requires the confirmation line, so a skip in a
//! standalone clone cannot pass unnoticed.
//!
//! Positions are not compared, for the same reason as the `.nost` suite: where a parser
//! notices that a construct is outside the subset is an artifact of its design.

use nostdb_core::cypher::{QueryError, parse};
use nostdb_core::diagnostic::DiagnosticCode;
use nostdb_core::encoding::Graph;
use nostdb_core::execute::{DatabaseContext, Parameters, execute};
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
    assert!(paths.len() >= 36, "expected the published supported suite");

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
    refused_suite("unsupported", 19);
}

/// The semantic suite covers the other refusal code the contract declares.
///
/// Every fixture in it is refused against any graph, including an empty one, which is what
/// lets the suite carry no graph. Some are refused while parsing and some while executing;
/// the contract makes the code and the outcome normative, not which pass notices.
#[test]
fn semantic_fixtures_are_refused_with_the_declared_code() {
    refused_suite("semantic", 10);
}

/// A refused semantic fixture changes nothing, even when it is a write.
///
/// Refusal while executing is only worth as much as what it leaves behind, so this asserts
/// the graph is still empty rather than only that an error came back.
#[test]
fn a_refused_semantic_fixture_leaves_the_graph_untouched() {
    let Some(directory) = category("semantic") else {
        println!("cypher conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    for path in &fixtures(&directory) {
        let Ok(query) = parse(&read(path)) else {
            continue;
        };
        let mut graph = Graph::default();
        assert!(
            run(&query, &mut graph).is_err(),
            "{} must be refused",
            path.display()
        );
        assert!(
            graph.is_empty(),
            "{} was refused but changed the graph",
            path.display()
        );
    }
}

fn run(
    query: &nostdb_core::cypher::Query,
    graph: &mut Graph,
) -> Result<nostdb_core::execute::QueryResult, QueryError> {
    execute(
        query,
        graph,
        &Parameters::new(),
        &DatabaseContext::default(),
    )
}

fn refused_suite(name: &str, least: usize) {
    let Some(directory) = category(name) else {
        println!("cypher conformance: skipped, NOSTDB_SPEC_FIXTURES is unset");
        return;
    };
    let paths = fixtures(&directory);
    assert!(
        paths.len() >= least,
        "expected the published {name} suite to hold at least {least} fixtures"
    );

    for path in &paths {
        let fixture = path.display();
        let declared = expectation(path);
        assert_eq!(
            declared.get("outcome").map(String::as_str),
            Some("reject"),
            "{fixture} must declare reject"
        );
        let expected = DiagnosticCode::from_str(
            declared
                .get("code")
                .unwrap_or_else(|| panic!("{fixture} declares no code")),
        )
        .unwrap_or_else(|error| panic!("{fixture}: {error}"));

        // A refusal while parsing and a refusal while executing are both refusals. The
        // contract makes the code normative, not which pass notices, so a fixture that
        // parses is executed against an empty graph and must be refused there.
        let refusal = match parse(&read(path)) {
            Err(error) => error,
            Ok(query) => run(&query, &mut Graph::default())
                .err()
                .unwrap_or_else(|| panic!("{fixture} must be refused but ran")),
        };

        assert_eq!(
            refusal.code, expected,
            "{fixture} must be refused with {expected}, not {} ({refusal})",
            refusal.code
        );
        // A usable range is required; its exact position is not.
        assert!(refusal.range.start().line >= 1, "{fixture} needs a range");
        assert!(
            !refusal.message.trim().is_empty(),
            "{fixture} needs a message"
        );
    }
    println!(
        "cypher conformance: {} {name} fixtures verified",
        paths.len()
    );
}

#[test]
fn an_unsupported_query_produces_no_plan() {
    // The guarantee the contract makes for an unsupported construct is that nothing runs
    // under a guessed alternative. Expressed in the type system: a refusal yields Err, so
    // there is no partial query to execute.
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
