//! The `nostdb` namespace: procedures called with `CALL`, and functions.
//!
//! NostDB-specific behavior lives in a namespace rather than in new syntax, so the query
//! language itself stays openCypher-compatible. The registry is published in the query
//! subset contract in `nostdb-spec`, section 12, and this module implements it.
//!
//! # An unknown name is refused, never guessed
//!
//! Calling something outside the registry is [`DiagnosticCode::CypherSemanticError`]: an
//! unknown procedure will not become known by retrying. A registered procedure this build
//! cannot run because it lacks a capability is [`DiagnosticCode::CypherUnsupported`],
//! because the same call against a more complete build succeeds. The two codes tell a
//! caller different things, so they are not interchangeable.

use crate::cypher::QueryError;
use crate::diagnostic::DiagnosticCode;
use crate::encoding::Graph;
use crate::evidence::{Confidence, Evidence, EvidenceMethod};
use crate::execute::{DatabaseContext, QueryValue};
use crate::graph::{Edge, Node};
use crate::id::{LocalEdgeId, LocalNodeId};
use crate::property::FiniteF64;

/// Most evidence rows one `nostdb.evidence` call yields.
///
/// A `.nostdb` file is untrusted input, so walking an unbounded number of stored records
/// would hand the query's memory budget to whoever wrote the file. The bound is published
/// in query contract section 12.3.
pub const EVIDENCE_ROW_LIMIT: usize = 256;

/// A procedure in the `nostdb` namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Procedure {
    /// The dotted name it is called by.
    pub name: &'static str,
    /// Its columns, in order.
    pub columns: &'static [&'static str],
    /// How many arguments it takes.
    pub arguments: usize,
    /// The capability it needs, when this build does not have one.
    pub capability: Option<&'static str>,
}

/// Every procedure the query contract declares, in section 12.1.
pub const PROCEDURES: [Procedure; 4] = [
    Procedure {
        name: "nostdb.links",
        columns: &["source", "alias", "remote"],
        arguments: 0,
        capability: None,
    },
    Procedure {
        name: "nostdb.build_status",
        columns: &["database_generation", "nodes", "edges", "links"],
        arguments: 0,
        capability: None,
    },
    Procedure {
        name: "nostdb.evidence",
        columns: &[
            "source",
            "path",
            "revision",
            "digest",
            "producer",
            "producer_version",
            "method",
            "confidence",
            "score",
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        ],
        arguments: 1,
        capability: None,
    },
    Procedure {
        name: "nostdb.refresh_links",
        columns: &["source", "refreshed", "revision"],
        arguments: 0,
        // Refreshing a link means resolving a ref to an immutable commit and fetching it,
        // which needs a source provider. This build has none, so the call is refused rather
        // than answered with a plausible "nothing changed".
        capability: Some("a source provider"),
    },
];

/// Every function the query contract declares, in section 12.2.
pub const FUNCTIONS: [&str; 5] = [
    "nostdb.source",
    "nostdb.source_location",
    "nostdb.source_revision",
    "nostdb.link_alias",
    "nostdb.is_available",
];

/// The namespace prefix everything here shares.
pub const NAMESPACE: &str = "nostdb.";

fn semantic(message: impl Into<String>, range: crate::evidence::SourceRange) -> QueryError {
    QueryError::at(DiagnosticCode::CypherSemanticError, message, range)
}

/// Looks up a procedure by name.
///
/// # Errors
///
/// Returns [`DiagnosticCode::CypherSemanticError`] when nothing by that name exists.
pub fn lookup(
    name: &str,
    range: crate::evidence::SourceRange,
) -> Result<&'static Procedure, QueryError> {
    PROCEDURES
        .iter()
        .find(|procedure| procedure.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| semantic(format!("unknown procedure `{name}`"), range))
}

/// Runs a procedure, returning one row per result in the procedure's column order.
///
/// # Errors
///
/// Returns [`DiagnosticCode::CypherUnsupported`] when the procedure needs a capability
/// this build lacks, and [`DiagnosticCode::CypherSemanticError`] for a wrong argument count
/// or an argument of the wrong kind.
pub fn run(
    procedure: &Procedure,
    arguments: &[QueryValue],
    graph: &Graph,
    context: &DatabaseContext,
    range: crate::evidence::SourceRange,
) -> Result<Vec<Vec<QueryValue>>, QueryError> {
    if let Some(capability) = procedure.capability {
        return Err(QueryError::at(
            DiagnosticCode::CypherUnsupported,
            format!(
                "`{}` needs {capability}, which this build does not have",
                procedure.name
            ),
            range,
        ));
    }
    if arguments.len() != procedure.arguments {
        return Err(semantic(
            format!(
                "`{}` takes {} argument(s), and {} were given",
                procedure.name,
                procedure.arguments,
                arguments.len()
            ),
            range,
        ));
    }

    match procedure.name {
        "nostdb.links" => Ok(graph
            .links
            .iter()
            .map(|link| {
                vec![
                    QueryValue::Text(link.source.as_str().to_owned()),
                    link.alias.as_ref().map_or(QueryValue::Null, |alias| {
                        QueryValue::Text(alias.as_str().to_owned())
                    }),
                    QueryValue::Boolean(link.is_remote()),
                ]
            })
            .collect()),
        "nostdb.build_status" => Ok(vec![vec![
            context.generation.map_or(QueryValue::Null, |generation| {
                integer(generation.get() as i64)
            }),
            integer(graph.nodes.len() as i64),
            integer(graph.edges.len() as i64),
            integer(graph.links.len() as i64),
        ]]),
        "nostdb.evidence" => evidence_rows(&arguments[0], graph, range),
        other => Err(semantic(format!("unknown procedure `{other}`"), range)),
    }
}

const fn integer(value: i64) -> QueryValue {
    QueryValue::Integer(value)
}

fn text(value: &str) -> QueryValue {
    QueryValue::Text(value.to_owned())
}

fn node_of(graph: &Graph, id: LocalNodeId) -> Option<&Node> {
    graph.nodes.iter().find(|node| node.id == id)
}

fn edge_of(graph: &Graph, id: LocalEdgeId) -> Option<&Edge> {
    graph.edges.iter().find(|edge| edge.id == id)
}

/// Every evidence record on a bound node or relationship, bounded by
/// [`EVIDENCE_ROW_LIMIT`].
fn evidence_rows(
    bound: &QueryValue,
    graph: &Graph,
    range: crate::evidence::SourceRange,
) -> Result<Vec<Vec<QueryValue>>, QueryError> {
    let evidence: Vec<&Evidence> = match bound {
        QueryValue::Node(id) => node_of(graph, *id)
            .map(|node| {
                node.contributions
                    .iter()
                    .flat_map(|contribution| contribution.evidence.iter())
                    .collect()
            })
            .unwrap_or_default(),
        QueryValue::Relationship(id) => edge_of(graph, *id)
            .map(|edge| {
                edge.contributions
                    .iter()
                    .flat_map(|contribution| contribution.evidence.iter())
                    .collect()
            })
            .unwrap_or_default(),
        // A null argument yields nothing rather than failing, so an unmatched
        // `OPTIONAL MATCH` row can still be piped into the call.
        QueryValue::Null => Vec::new(),
        other => {
            return Err(semantic(
                format!(
                    "`nostdb.evidence` takes a node or a relationship, and was given {}",
                    other.kind_name()
                ),
                range,
            ));
        }
    };

    Ok(evidence
        .into_iter()
        .take(EVIDENCE_ROW_LIMIT)
        .map(|item| {
            let (start, end) = item.range.map_or((None, None), |source_range| {
                (Some(source_range.start()), Some(source_range.end()))
            });
            vec![
                text(item.source.as_str()),
                optional_text(item.path.as_ref().map(|path| path.as_str())),
                optional_text(
                    item.resolved_revision
                        .as_ref()
                        .map(|revision| revision.as_str()),
                ),
                text(item.content_digest.as_str()),
                text(item.producer.as_str()),
                text(item.producer_version.as_str()),
                text(method_name(item.method)),
                text(confidence_name(&item.confidence)),
                score_value(&item.confidence),
                start.map_or(QueryValue::Null, |position| {
                    integer(i64::from(position.line))
                }),
                start.map_or(QueryValue::Null, |position| {
                    integer(i64::from(position.column))
                }),
                end.map_or(QueryValue::Null, |position| {
                    integer(i64::from(position.line))
                }),
                end.map_or(QueryValue::Null, |position| {
                    integer(i64::from(position.column))
                }),
            ]
        })
        .collect())
}

fn optional_text(value: Option<&str>) -> QueryValue {
    value.map_or(QueryValue::Null, text)
}

const fn method_name(method: EvidenceMethod) -> &'static str {
    match method {
        EvidenceMethod::Deterministic => "deterministic",
        EvidenceMethod::AiInferred => "ai_inferred",
        EvidenceMethod::UserDeclared => "user_declared",
    }
}

const fn confidence_name(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Extracted => "extracted",
        Confidence::Inferred { .. } => "inferred",
        Confidence::Ambiguous { .. } => "ambiguous",
    }
}

fn score_value(confidence: &Confidence) -> QueryValue {
    confidence.score().map_or(QueryValue::Null, |score| {
        FiniteF64::new(f64::from(score.get())).map_or(QueryValue::Null, QueryValue::Float)
    })
}

/// Evaluates a function in the namespace.
///
/// # Errors
///
/// Returns [`DiagnosticCode::CypherSemanticError`] for an unknown name, a wrong argument
/// count, or an argument that is not a node or relationship.
pub fn function(
    name: &str,
    arguments: &[QueryValue],
    graph: &Graph,
    context: &DatabaseContext,
    range: crate::evidence::SourceRange,
) -> Result<QueryValue, QueryError> {
    let lower = name.to_ascii_lowercase();
    if !FUNCTIONS.contains(&lower.as_str()) {
        return Err(semantic(format!("unknown function `{name}`"), range));
    }
    if arguments.len() != 1 {
        return Err(semantic(
            format!(
                "`{name}` takes one argument, and {} were given",
                arguments.len()
            ),
            range,
        ));
    }

    let bound = &arguments[0];
    // Every function here describes the record a value denotes, so anything that is not a
    // record has nothing to describe. Null propagates rather than failing.
    let first = match bound {
        QueryValue::Node(id) => node_of(graph, *id).and_then(|node| {
            node.contributions
                .first()
                .and_then(|contribution| contribution.evidence.first())
        }),
        QueryValue::Relationship(id) => edge_of(graph, *id).and_then(|edge| {
            edge.contributions
                .first()
                .and_then(|contribution| contribution.evidence.first())
        }),
        QueryValue::Null => None,
        other => {
            return Err(semantic(
                format!(
                    "`{name}` takes a node or a relationship, and was given {}",
                    other.kind_name()
                ),
                range,
            ));
        }
    };

    Ok(match lower.as_str() {
        // The source holding the record, which for a record of the root database is the
        // root itself. Federation is what would make this anything else.
        "nostdb.source" => context
            .source
            .as_ref()
            .map_or(QueryValue::Null, |source| text(source.as_str())),
        "nostdb.source_location" => optional_text(
            first
                .and_then(|item| item.path.as_ref())
                .map(|p| p.as_str()),
        ),
        "nostdb.source_revision" => optional_text(
            first
                .and_then(|item| item.resolved_revision.as_ref())
                .map(|revision| revision.as_str()),
        ),
        // A record of the root database was not reached through a link, so it has no alias.
        // Every record a query can bind today is a root record, so this is null until link
        // resolution lands. Searching the declared links for the root's own locator would
        // look like an implementation and could only ever answer from a self-link.
        "nostdb.link_alias" => QueryValue::Null,
        // The record is in a graph this query already opened, so its source was available.
        _ => QueryValue::Boolean(true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contribution::{Contribution, Owner};
    use crate::evidence::{ContentDigest, SourcePosition, SourceRange};
    use crate::id::SourceUnitId;
    use crate::link::Link;
    use crate::locator::CanonicalSourceLocator;
    use crate::name::{Label, LinkAlias};
    use crate::text::NonEmptyText;

    fn locator(value: &str) -> CanonicalSourceLocator {
        CanonicalSourceLocator::new(value).unwrap()
    }

    fn evidence() -> Evidence {
        Evidence {
            source: locator("./packages/child"),
            resolved_revision: Some(NonEmptyText::new("a1b2c3").unwrap()),
            path: Some(NonEmptyText::new("src/auth.rs").unwrap()),
            content_digest: ContentDigest::new("sha256:abcdef0123456789abcdef0123456789").unwrap(),
            range: SourceRange::new(
                SourcePosition {
                    line: 4,
                    column: 1,
                    offset: 30,
                },
                SourcePosition {
                    line: 9,
                    column: 2,
                    offset: 90,
                },
            )
            .ok(),
            producer: NonEmptyText::new("rust-structural").unwrap(),
            producer_version: NonEmptyText::new("0.1.0").unwrap(),
            method: EvidenceMethod::Deterministic,
            confidence: Confidence::Inferred {
                score: crate::evidence::Score::new(0.5).unwrap(),
            },
        }
    }

    fn graph() -> Graph {
        Graph {
            nodes: vec![Node {
                id: LocalNodeId::from_bytes([1; 16]),
                labels: vec![Label::new("Function").unwrap()],
                properties: Vec::new(),
                contributions: vec![Contribution {
                    owner: Owner::User,
                    source_unit: SourceUnitId::QUERY,
                    evidence: vec![evidence()],
                }],
            }],
            edges: Vec::new(),
            links: vec![
                Link::new(locator("./packages/child")),
                Link::with_alias(
                    locator("github://example/shared/?ref=main"),
                    LinkAlias::new("shared").unwrap(),
                ),
            ],
            schemas: Vec::new(),
        }
    }

    fn origin() -> SourceRange {
        SourceRange::ORIGIN
    }

    #[test]
    fn every_registered_procedure_declares_columns_and_a_unique_name() {
        let mut seen = std::collections::BTreeSet::new();
        for procedure in PROCEDURES {
            assert!(seen.insert(procedure.name), "{} twice", procedure.name);
            assert!(!procedure.columns.is_empty(), "{}", procedure.name);
            assert!(
                procedure.name.starts_with(NAMESPACE),
                "{} is outside the namespace",
                procedure.name
            );
        }
        for name in FUNCTIONS {
            assert!(
                name.starts_with(NAMESPACE),
                "{name} is outside the namespace"
            );
        }
    }

    #[test]
    fn links_yields_one_row_per_declaration_including_the_aliasless_one() {
        let graph = graph();
        let rows = run(
            lookup("nostdb.links", origin()).unwrap(),
            &[],
            &graph,
            &DatabaseContext::default(),
            origin(),
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][1], QueryValue::Null);
        assert_eq!(rows[0][2], QueryValue::Boolean(false));
        assert_eq!(rows[1][1], QueryValue::Text("shared".to_owned()));
        assert_eq!(rows[1][2], QueryValue::Boolean(true));
    }

    #[test]
    fn build_status_reports_the_generation_it_was_given_and_null_without_one() {
        let graph = graph();
        let known = DatabaseContext {
            generation: Some(crate::generation::Generation::from_raw(42)),
            source: None,
        };
        let rows = run(
            lookup("nostdb.build_status", origin()).unwrap(),
            &[],
            &graph,
            &known,
            origin(),
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], QueryValue::Integer(42));
        assert_eq!(rows[0][1], QueryValue::Integer(1));
        assert_eq!(rows[0][3], QueryValue::Integer(2));

        let rows = run(
            lookup("nostdb.build_status", origin()).unwrap(),
            &[],
            &graph,
            &DatabaseContext::default(),
            origin(),
        )
        .unwrap();
        assert_eq!(rows[0][0], QueryValue::Null);
    }

    #[test]
    fn evidence_yields_stored_metadata_and_never_source_content() {
        let graph = graph();
        let rows = run(
            lookup("nostdb.evidence", origin()).unwrap(),
            &[QueryValue::Node(LocalNodeId::from_bytes([1; 16]))],
            &graph,
            &DatabaseContext::default(),
            origin(),
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        let columns = PROCEDURES[2].columns;
        assert_eq!(rows[0].len(), columns.len());
        assert_eq!(rows[0][0], QueryValue::Text("./packages/child".to_owned()));
        assert_eq!(rows[0][1], QueryValue::Text("src/auth.rs".to_owned()));
        assert_eq!(rows[0][6], QueryValue::Text("deterministic".to_owned()));
        assert_eq!(rows[0][9], QueryValue::Integer(4));
        assert_eq!(rows[0][12], QueryValue::Integer(2));
    }

    #[test]
    fn a_capability_gated_procedure_is_unsupported_rather_than_a_plausible_answer() {
        let error = run(
            lookup("nostdb.refresh_links", origin()).unwrap(),
            &[],
            &graph(),
            &DatabaseContext::default(),
            origin(),
        )
        .unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherUnsupported);
        assert!(error.message.contains("source provider"), "{error}");
    }

    #[test]
    fn an_unknown_procedure_is_a_semantic_error_because_retrying_will_not_help() {
        let error = lookup("nostdb.invent", origin()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
    }

    #[test]
    fn a_wrong_argument_count_is_reported_rather_than_ignored() {
        let error = run(
            lookup("nostdb.links", origin()).unwrap(),
            &[QueryValue::Integer(1)],
            &graph(),
            &DatabaseContext::default(),
            origin(),
        )
        .unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
    }

    #[test]
    fn functions_read_the_first_evidence_and_the_context_source() {
        let graph = graph();
        let context = DatabaseContext {
            generation: None,
            source: Some(locator("./packages/child")),
        };
        let node = [QueryValue::Node(LocalNodeId::from_bytes([1; 16]))];

        assert_eq!(
            function("nostdb.source", &node, &graph, &context, origin()).unwrap(),
            QueryValue::Text("./packages/child".to_owned())
        );
        assert_eq!(
            function("nostdb.source_location", &node, &graph, &context, origin()).unwrap(),
            QueryValue::Text("src/auth.rs".to_owned())
        );
        assert_eq!(
            function("nostdb.source_revision", &node, &graph, &context, origin()).unwrap(),
            QueryValue::Text("a1b2c3".to_owned())
        );
        assert_eq!(
            function("nostdb.is_available", &node, &graph, &context, origin()).unwrap(),
            QueryValue::Boolean(true)
        );
    }

    #[test]
    fn source_is_null_when_the_caller_named_no_database() {
        let node = [QueryValue::Node(LocalNodeId::from_bytes([1; 16]))];
        assert_eq!(
            function(
                "nostdb.source",
                &node,
                &graph(),
                &DatabaseContext::default(),
                origin()
            )
            .unwrap(),
            QueryValue::Null
        );
    }

    #[test]
    fn a_null_argument_yields_null_rather_than_failing() {
        // An unmatched OPTIONAL MATCH row can be piped into these without a special case.
        assert_eq!(
            function(
                "nostdb.source_location",
                &[QueryValue::Null],
                &graph(),
                &DatabaseContext::default(),
                origin()
            )
            .unwrap(),
            QueryValue::Null
        );
        assert!(
            run(
                lookup("nostdb.evidence", origin()).unwrap(),
                &[QueryValue::Null],
                &graph(),
                &DatabaseContext::default(),
                origin()
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn a_value_that_is_not_a_record_is_refused() {
        let error = function(
            "nostdb.source_location",
            &[QueryValue::Integer(1)],
            &graph(),
            &DatabaseContext::default(),
            origin(),
        )
        .unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("integer"), "{error}");
    }

    #[test]
    fn the_evidence_row_limit_bounds_what_an_untrusted_file_can_ask_for() {
        let mut graph = graph();
        graph.nodes[0].contributions[0].evidence =
            (0..EVIDENCE_ROW_LIMIT + 50).map(|_| evidence()).collect();
        let rows = run(
            lookup("nostdb.evidence", origin()).unwrap(),
            &[QueryValue::Node(LocalNodeId::from_bytes([1; 16]))],
            &graph,
            &DatabaseContext::default(),
            origin(),
        )
        .unwrap();
        assert_eq!(rows.len(), EVIDENCE_ROW_LIMIT);
    }
}
