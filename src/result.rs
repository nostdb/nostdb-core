//! The machine-readable query result envelope.
//!
//! The contract is `result_version` in `nostdb-spec`. Every output format the command
//! surface offers is a rendering of this one shape, so the shape is built once, here,
//! rather than four times at the boundary.
//!
//! # Data and diagnostics never mix
//!
//! `rows` holds what the query asked for and `warnings` holds what the Engine wants to
//! say about producing it. A caller reading rows never has to filter commentary out of
//! them.
//!
//! # A read has no write summary
//!
//! `writes` appears only for a query that could write. A read reporting an all-zero
//! summary would say "changed nothing" where the truth is "could not change anything",
//! and those are different claims to a caller deciding whether to commit.

use crate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::execute::{QueryResult, QueryValue};
use crate::generation::Generation;
use crate::mutate::WriteSummary;
use serde_json::{Map, Value, json};

/// The envelope version this build writes.
pub const RESULT_VERSION: u64 = 1;

/// Warnings that make a result partial.
///
/// The contract names exactly these three: a result is partial when some declared source
/// was not fully traversed, and nothing else sets the flag.
pub const PARTIAL_CODES: [DiagnosticCode; 3] = [
    DiagnosticCode::LinkUnavailable,
    DiagnosticCode::LinkCycle,
    DiagnosticCode::LinkLimitExceeded,
];

/// A query result rendered as the published envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct ResultEnvelope {
    /// Column names, in projection order.
    pub columns: Vec<String>,
    /// Rows, each the same length as `columns`.
    pub rows: Vec<Vec<QueryValue>>,
    /// The generation the query read.
    pub database_generation: u64,
    /// Linked databases opened, excluding the root.
    pub linked_databases_opened: u64,
    /// What the query changed, when it could change anything.
    pub writes: Option<WriteSummary>,
    /// Non-fatal findings.
    pub warnings: Vec<Diagnostic>,
}

impl ResultEnvelope {
    /// Wraps a query result.
    ///
    /// `writes` is supplied by the caller rather than taken from the result, because only
    /// the caller knows whether the query was permitted to write. A read executed against
    /// a shared graph cannot have written, and saying so is more useful than reporting
    /// eight zeroes.
    #[must_use]
    pub fn new(result: QueryResult, generation: Generation, writes: Option<WriteSummary>) -> Self {
        Self {
            columns: result.columns,
            rows: result.rows,
            database_generation: generation.get(),
            linked_databases_opened: 0,
            writes,
            warnings: result.warnings,
        }
    }

    /// Reports whether some declared source was not fully traversed.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.warnings
            .iter()
            .any(|warning| PARTIAL_CODES.contains(&warning.code))
    }

    /// The whole envelope as JSON.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "result_version": RESULT_VERSION,
            "columns": self.columns,
            "rows": self.rows_json(),
            "summary": self.summary_json(),
            "warnings": self.warnings_json(),
        })
    }

    /// The rows alone, as JSON arrays.
    #[must_use]
    pub fn rows_json(&self) -> Vec<Value> {
        self.rows
            .iter()
            .map(|row| Value::Array(row.iter().map(value_json).collect()))
            .collect()
    }

    /// The summary object.
    #[must_use]
    pub fn summary_json(&self) -> Value {
        let mut summary = Map::new();
        summary.insert("rows".to_owned(), json!(self.rows.len()));
        summary.insert(
            "database_generation".to_owned(),
            json!(self.database_generation),
        );
        summary.insert(
            "linked_databases_opened".to_owned(),
            json!(self.linked_databases_opened),
        );
        summary.insert("partial".to_owned(), json!(self.is_partial()));
        if let Some(writes) = self.writes {
            summary.insert(
                "writes".to_owned(),
                json!({
                    "nodes_created": writes.nodes_created,
                    "nodes_deleted": writes.nodes_deleted,
                    "edges_created": writes.edges_created,
                    "edges_deleted": writes.edges_deleted,
                    "properties_set": writes.properties_set,
                    "properties_removed": writes.properties_removed,
                    "labels_added": writes.labels_added,
                    "labels_removed": writes.labels_removed,
                }),
            );
        }
        Value::Object(summary)
    }

    /// The warnings array.
    #[must_use]
    pub fn warnings_json(&self) -> Vec<Value> {
        self.warnings
            .iter()
            .map(|warning| {
                let mut entry = Map::new();
                entry.insert("code".to_owned(), json!(warning.code.as_str()));
                entry.insert("message".to_owned(), json!(warning.message.as_str()));
                if let Some(source) = &warning.source {
                    entry.insert("source".to_owned(), json!(source.as_str()));
                }
                if let Some(range) = warning.range {
                    entry.insert(
                        "range".to_owned(),
                        json!({
                            "start": position_json(range.start()),
                            "end": position_json(range.end()),
                        }),
                    );
                }
                Value::Object(entry)
            })
            .collect()
    }

    /// The JSONL header line, which binds column names before the first row.
    #[must_use]
    pub fn jsonl_header(&self) -> Value {
        json!({ "result_version": RESULT_VERSION, "columns": self.columns })
    }

    /// The JSONL trailer line, which cannot be known until the rows are.
    #[must_use]
    pub fn jsonl_trailer(&self) -> Value {
        json!({ "summary": self.summary_json(), "warnings": self.warnings_json() })
    }
}

fn position_json(position: crate::evidence::SourcePosition) -> Value {
    json!({
        "line": position.line,
        "column": position.column,
        "offset": position.offset,
    })
}

/// Renders one value in its published form.
///
/// A byte string, a timestamp, a node, and a relationship are tagged, because all four
/// would otherwise be strings a consumer could not tell from text that happens to look
/// like one.
#[must_use]
pub fn value_json(value: &QueryValue) -> Value {
    match value {
        QueryValue::Null => Value::Null,
        QueryValue::Boolean(flag) => json!(flag),
        QueryValue::Integer(number) => json!(number),
        // Carried as a JSON float, which renders an integral value as `20.0` rather than
        // `20`. The contract asks for that so a reader keeping the integer-double
        // distinction can see it, and a test asserts the rendering rather than the value.
        //
        // `from_f64` returns `None` only for an infinity or a NaN, which `FiniteF64`
        // makes unrepresentable; the fallback exists so this stays panic-free.
        QueryValue::Float(number) => {
            serde_json::Number::from_f64(number.get()).map_or(Value::Null, Value::Number)
        }
        QueryValue::Text(text) => json!(text),
        QueryValue::List(items) => Value::Array(items.iter().map(value_json).collect()),
        QueryValue::Node(id) => json!({ "node": id.to_string() }),
        QueryValue::Relationship(id) => json!({ "relationship": id.to_string() }),
        QueryValue::Path {
            nodes,
            relationships,
        } => json!({
            "path": {
                "nodes": nodes.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "relationships": relationships
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            }
        }),
    }
}

/// Renders one value the way a CSV field carries it.
///
/// A string is written bare rather than quoted as JSON, and null is an empty field. Every
/// other form keeps its JSON rendering, so a tagged value stays recognizable.
#[must_use]
pub fn value_csv(value: &QueryValue) -> String {
    match value {
        QueryValue::Null => String::new(),
        QueryValue::Text(text) => text.clone(),
        other => value_json(other).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Severity;
    use crate::id::{LocalEdgeId, LocalNodeId};
    use crate::property::FiniteF64;
    use crate::text::NonEmptyText;

    fn warning(code: DiagnosticCode, message: &str) -> Diagnostic {
        Diagnostic {
            code,
            severity: Severity::Warning,
            message: NonEmptyText::new(message).unwrap(),
            source: None,
            range: None,
            details: Vec::new(),
        }
    }

    fn envelope(rows: Vec<Vec<QueryValue>>, warnings: Vec<Diagnostic>) -> ResultEnvelope {
        ResultEnvelope {
            columns: vec!["v".to_owned()],
            rows,
            database_generation: 7,
            linked_databases_opened: 0,
            writes: None,
            warnings,
        }
    }

    #[test]
    fn an_empty_result_states_every_member() {
        let rendered = ResultEnvelope {
            columns: Vec::new(),
            rows: Vec::new(),
            database_generation: 1,
            linked_databases_opened: 0,
            writes: None,
            warnings: Vec::new(),
        }
        .to_json();
        for member in ["result_version", "columns", "rows", "summary", "warnings"] {
            assert!(rendered.get(member).is_some(), "{member} is missing");
        }
        assert_eq!(rendered["columns"], json!([]));
        assert_eq!(rendered["rows"], json!([]));
        assert_eq!(rendered["warnings"], json!([]));
    }

    #[test]
    fn the_summary_row_count_matches_the_rows() {
        let rendered = envelope(
            vec![vec![QueryValue::Integer(1)], vec![QueryValue::Integer(2)]],
            Vec::new(),
        )
        .to_json();
        assert_eq!(rendered["summary"]["rows"], json!(2));
        assert_eq!(rendered["rows"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn a_read_omits_the_write_summary_entirely() {
        // Reporting eight zeroes would say "changed nothing" where the truth is "could
        // not change anything".
        let read = envelope(Vec::new(), Vec::new()).to_json();
        assert!(read["summary"].get("writes").is_none(), "{read}");

        let mut written = envelope(Vec::new(), Vec::new());
        written.writes = Some(WriteSummary {
            nodes_created: 2,
            ..WriteSummary::default()
        });
        let rendered = written.to_json();
        assert_eq!(rendered["summary"]["writes"]["nodes_created"], json!(2));
        assert_eq!(rendered["summary"]["writes"]["labels_removed"], json!(0));
    }

    #[test]
    fn exactly_the_three_link_warnings_make_a_result_partial() {
        for code in PARTIAL_CODES {
            let rendered = envelope(Vec::new(), vec![warning(code, "unreachable")]).to_json();
            assert_eq!(rendered["summary"]["partial"], json!(true), "{code}");
        }
        // Any other warning leaves the result complete.
        let rendered = envelope(
            Vec::new(),
            vec![warning(DiagnosticCode::OrphanLinkSettings, "stale entry")],
        )
        .to_json();
        assert_eq!(rendered["summary"]["partial"], json!(false), "{rendered}");
    }

    #[test]
    fn each_tagged_form_carries_exactly_one_member() {
        let node = LocalNodeId::from_bytes([1; 16]);
        let edge = LocalEdgeId::from_bytes([2; 16]);
        for value in [
            QueryValue::Node(node),
            QueryValue::Relationship(edge),
            QueryValue::Path {
                nodes: vec![node],
                relationships: Vec::new(),
            },
        ] {
            let rendered = value_json(&value);
            let object = rendered.as_object().expect("a tagged form is an object");
            assert_eq!(object.len(), 1, "{rendered}");
        }
    }

    #[test]
    fn a_path_alternates_so_it_has_one_fewer_relationship_than_nodes() {
        let rendered = value_json(&QueryValue::Path {
            nodes: vec![
                LocalNodeId::from_bytes([1; 16]),
                LocalNodeId::from_bytes([2; 16]),
            ],
            relationships: vec![LocalEdgeId::from_bytes([3; 16])],
        });
        assert_eq!(rendered["path"]["nodes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            rendered["path"]["relationships"].as_array().map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn untagged_forms_stay_untagged() {
        assert_eq!(value_json(&QueryValue::Null), Value::Null);
        assert_eq!(value_json(&QueryValue::Boolean(true)), json!(true));
        assert_eq!(value_json(&QueryValue::Integer(-7)), json!(-7));
        assert_eq!(value_json(&QueryValue::Text("x".to_owned())), json!("x"));
        assert_eq!(
            value_json(&QueryValue::List(vec![QueryValue::Integer(1)])),
            json!([1])
        );
    }

    #[test]
    fn a_warning_renders_its_code_and_message_and_omits_what_it_lacks() {
        let rendered = envelope(
            Vec::new(),
            vec![warning(DiagnosticCode::LinkUnavailable, "could not open")],
        )
        .to_json();
        let entry = &rendered["warnings"][0];
        assert_eq!(entry["code"], json!("LINK_UNAVAILABLE"));
        assert_eq!(entry["message"], json!("could not open"));
        assert!(entry.get("source").is_none(), "{entry}");
        assert!(entry.get("range").is_none(), "{entry}");
    }

    #[test]
    fn jsonl_binds_columns_before_the_rows_and_summarizes_after_them() {
        let rendered = envelope(vec![vec![QueryValue::Integer(1)]], Vec::new());
        let header = rendered.jsonl_header();
        assert_eq!(header["columns"], json!(["v"]));
        assert!(header.get("summary").is_none(), "a header cannot summarize");

        let trailer = rendered.jsonl_trailer();
        assert_eq!(trailer["summary"]["rows"], json!(1));
        assert!(trailer.get("columns").is_none(), "the header bound those");
    }

    #[test]
    fn csv_writes_a_string_bare_and_null_as_an_empty_field() {
        assert_eq!(value_csv(&QueryValue::Text("login".to_owned())), "login");
        assert_eq!(value_csv(&QueryValue::Null), "");
        assert_eq!(value_csv(&QueryValue::Integer(42)), "42");
        // A tagged form keeps its JSON rendering, so it stays recognizable in CSV.
        assert!(
            value_csv(&QueryValue::Node(LocalNodeId::from_bytes([1; 16])))
                .starts_with("{\"node\":")
        );
    }

    #[test]
    fn a_double_renders_with_a_decimal_point_even_when_integral() {
        // The contract asks for this so a reader keeping the integer-double distinction
        // can see it. Asserting the value alone would pass while `20` was written.
        assert_eq!(
            value_json(&QueryValue::Float(FiniteF64::new(20.0).unwrap())).to_string(),
            "20.0"
        );
        assert_eq!(
            value_json(&QueryValue::Float(FiniteF64::new(0.5).unwrap())).to_string(),
            "0.5"
        );
        // And an integer stays an integer, so the two remain distinguishable.
        assert_eq!(value_json(&QueryValue::Integer(20)).to_string(), "20");
    }
}
