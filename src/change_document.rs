//! Reading a change set from a document.
//!
//! [`crate::change::GraphChangeSet`] is the in-memory form a producer inside the Engine
//! builds. This reads the on-disk form `change_set_version` publishes, which is what
//! `nostdb apply` is handed and what an out-of-process Skill writes.
//!
//! # Reading is not applying
//!
//! Everything decidable by reading the document is decided here, and nothing else is. A
//! document this module accepts may still be refused by [`crate::apply::apply`] — for a
//! stale baseline, a missing endpoint, a Constraint it would break. The contract says so
//! outright, and the reason is that a producer must not be able to widen its own authority
//! by writing a well-formed file.
//!
//! # Every problem, not the first
//!
//! A producer fixing a batch should need one pass. Decoding therefore collects errors
//! rather than returning at the first, which is also how [`crate::change::GraphChangeSet`]
//! validates the result once it exists.

use crate::change::{
    CHANGE_SET_VERSION, EdgeDraft, GraphChangeSet, GraphOperation, LinkDraft, NodeDraft,
    PlaceholderOutcome, PlaceholderResolution, SUPPORTED_CHANGE_SET_VERSIONS,
};
use crate::contribution::{ContributionKey, Owner};
use crate::evidence::{Confidence, ContentDigest, Evidence, EvidenceMethod};
use crate::graph::{NodeReference, ScopedNodeId};
use crate::id::{LocalEdgeId, LocalNodeId, SourceUnitId};
use crate::locator::CanonicalSourceLocator;
use crate::name::{Label, LinkAlias, PropertyKey, RelationName};
use crate::property::PropertyValue;
use crate::text::NonEmptyText;
use serde_json::Value;
use std::fmt;
use std::str::FromStr;

/// Why a document is not a change set this build can read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocumentError {
    /// The text is not JSON.
    NotJson {
        /// What the parser reported.
        reason: String,
    },
    /// The `change_set_version` is not one this build reads.
    UnsupportedVersion {
        /// The version found.
        found: u64,
    },
    /// A member is absent, of the wrong type, or states something impossible.
    Invalid {
        /// Which member, in dotted form.
        field: String,
        /// Why.
        reason: String,
    },
}

impl fmt::Display for DocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson { reason } => write!(formatter, "the document is not JSON: {reason}"),
            Self::UnsupportedVersion { found } => write!(
                formatter,
                "change_set_version {found} is not supported; this build reads \
                 {SUPPORTED_CHANGE_SET_VERSIONS:?}"
            ),
            Self::Invalid { field, reason } => write!(formatter, "{field}: {reason}"),
        }
    }
}

impl std::error::Error for DocumentError {}

/// The diagnostic code a failure carries.
#[must_use]
pub fn code_for(error: &DocumentError) -> crate::diagnostic::DiagnosticCode {
    match error {
        DocumentError::UnsupportedVersion { .. } => {
            crate::diagnostic::DiagnosticCode::ChangeSetVersionUnsupported
        }
        _ => crate::diagnostic::DiagnosticCode::ChangeSetInvalid,
    }
}

fn invalid(field: &str, reason: &str) -> DocumentError {
    DocumentError::Invalid {
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Reads a change set from a document.
///
/// # Errors
///
/// Returns every [`DocumentError`] found, so a producer can fix a batch in one pass. An
/// unsupported version is returned alone, because nothing after it is interpretable.
pub fn parse(text: &str) -> Result<GraphChangeSet, Vec<DocumentError>> {
    let document: Value = serde_json::from_str(text).map_err(|error| {
        vec![DocumentError::NotJson {
            reason: error.to_string(),
        }]
    })?;
    let Some(root) = document.as_object() else {
        return Err(vec![invalid("<root>", "expected an object")]);
    };

    let version = match root.get("change_set_version").and_then(Value::as_u64) {
        Some(found) => found,
        None => {
            return Err(vec![invalid(
                "change_set_version",
                "expected a positive integer",
            )]);
        }
    };
    if u32::try_from(version).is_ok_and(|found| SUPPORTED_CHANGE_SET_VERSIONS.contains(&found)) {
    } else {
        // Alone: nothing after an unreadable version is interpretable, and reporting
        // twenty consequential errors would bury the one that matters.
        return Err(vec![DocumentError::UnsupportedVersion { found: version }]);
    }

    let mut errors = Vec::new();
    let base_generation = root
        .get("base_generation")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            errors.push(invalid(
                "base_generation",
                "expected a non-negative integer",
            ));
            0
        });
    let owner = match root.get("owner") {
        Some(value) => read_owner(value).unwrap_or_else(|error| {
            errors.push(error);
            Owner::user()
        }),
        None => {
            errors.push(invalid("owner", "expected an object"));
            Owner::user()
        }
    };
    let snapshot = root
        .get("source_snapshot")
        .and_then(Value::as_str)
        .and_then(|text| NonEmptyText::new(text).ok())
        .unwrap_or_else(|| {
            errors.push(invalid("source_snapshot", "expected a non-empty string"));
            NonEmptyText::literal("unknown")
        });

    let mut change_set = GraphChangeSet::new(owner.clone(), snapshot, base_generation);
    match root.get("operations") {
        Some(Value::Array(entries)) => {
            for (at, entry) in entries.iter().enumerate() {
                match read_operation(entry, at, &owner) {
                    Ok(operation) => change_set.push(operation),
                    Err(found) => errors.extend(found),
                }
            }
        }
        _ => errors.push(invalid("operations", "expected an array")),
    }

    // The in-memory validator owns every rule that is about the batch rather than about one
    // member: an empty set, a repeated identifier, two link operations in conflict. Running
    // it here rather than restating those rules is what keeps one set of answers.
    if let Err(found) = change_set.validate() {
        errors.extend(found.into_iter().map(|error| DocumentError::Invalid {
            field: "operations".to_owned(),
            reason: error.to_string(),
        }));
    }

    if errors.is_empty() {
        Ok(change_set)
    } else {
        Err(errors)
    }
}

/// The owner a change set declares: one name.
///
/// An earlier schema wrote an object with a `kind`, and a `name` and `version` beside it. There is no reader
/// for it, so a document carrying one is refused for the name it does not supply rather than silently applied
/// under an owner nothing can withdraw.
fn read_owner(value: &Value) -> Result<Owner, DocumentError> {
    value
        .as_str()
        .and_then(|name| NonEmptyText::new(name).ok())
        .map(Owner::new)
        .ok_or_else(|| invalid("owner", "expected a non-empty owner name"))
}

fn read_operation(
    entry: &Value,
    at: usize,
    owner: &Owner,
) -> Result<GraphOperation, Vec<DocumentError>> {
    let where_ = format!("operations[{at}]");
    let one = |error: DocumentError| vec![error];
    let object = entry
        .as_object()
        .ok_or_else(|| one(invalid(&where_, "expected an object")))?;
    let field = |key: &str| format!("{where_}.{key}");

    let unit = |key: &str| -> Result<SourceUnitId, DocumentError> {
        object
            .get(key)
            .and_then(Value::as_str)
            .and_then(|found| SourceUnitId::from_str(found).ok())
            .ok_or_else(|| invalid(&field(key), "expected a source unit identifier"))
    };
    let evidence = |key: &str| -> Result<Vec<Evidence>, DocumentError> {
        let entries = match object.get(key) {
            Some(Value::Array(entries)) => entries,
            _ => return Err(invalid(&field(key), "expected an array")),
        };
        let found: Result<Vec<Evidence>, DocumentError> = entries
            .iter()
            .map(|value| read_evidence(value, &field(key)))
            .collect();
        let found = found?;
        // Section 2.2: a fact with nothing behind it is indistinguishable from one somebody
        // made up, so a producer that is not a person must say where it came from.
        if owner.requires_evidence() && found.is_empty() {
            return Err(invalid(
                &field(key),
                "an analyzer-owned or AI-owned operation must carry evidence",
            ));
        }
        Ok(found)
    };

    match object.get("operation").and_then(Value::as_str) {
        Some("upsert_node") => {
            let labels = read_labels(object.get("labels"), &field("labels"))?;
            Ok(GraphOperation::UpsertNode(NodeDraft {
                id: read_optional_id(object.get("id"), &field("id"))?,
                labels,
                properties: read_properties(object.get("properties"), &field("properties"))
                    .map_err(one)?,
                source_unit: unit("source_unit").map_err(one)?,
                evidence: evidence("evidence").map_err(one)?,
            }))
        }
        Some("upsert_edge") => Ok(GraphOperation::UpsertEdge(EdgeDraft {
            id: read_optional_edge_id(object.get("id"), &field("id"))?,
            source: read_endpoint(object.get("source"), &field("source")).map_err(one)?,
            target: read_endpoint(object.get("target"), &field("target")).map_err(one)?,
            relation: object
                .get("relation")
                .and_then(Value::as_str)
                .and_then(|found| RelationName::new(found).ok())
                .ok_or_else(|| one(invalid(&field("relation"), "expected a relation name")))?,
            properties: read_properties(object.get("properties"), &field("properties"))
                .map_err(one)?,
            source_unit: unit("source_unit").map_err(one)?,
            evidence: evidence("evidence").map_err(one)?,
        })),
        Some("remove_contribution") => Ok(GraphOperation::RemoveContribution(ContributionKey {
            owner: owner.clone(),
            source_unit: unit("source_unit").map_err(one)?,
        })),
        Some("resolve_placeholder") => {
            Ok(GraphOperation::ResolvePlaceholder(PlaceholderResolution {
                placeholder: read_id(object.get("placeholder"), &field("placeholder"))
                    .map_err(one)?,
                outcome: read_outcome(object.get("outcome"), &field("outcome")).map_err(one)?,
                source_unit: unit("source_unit").map_err(one)?,
                evidence: evidence("evidence").map_err(one)?,
            }))
        }
        Some("upsert_link") => Ok(GraphOperation::UpsertLink(LinkDraft {
            source: read_locator(object.get("source"), &field("source")).map_err(one)?,
            alias: match object.get("alias") {
                None | Some(Value::Null) => None,
                Some(Value::String(text)) => Some(
                    LinkAlias::new(text)
                        .map_err(|error| one(invalid(&field("alias"), &error.to_string())))?,
                ),
                Some(_) => return Err(one(invalid(&field("alias"), "expected a string"))),
            },
        })),
        Some("remove_link") => Ok(GraphOperation::RemoveLink(
            read_locator(object.get("source"), &field("source")).map_err(one)?,
        )),
        Some(other) => Err(one(invalid(
            &field("operation"),
            &format!("`{other}` is not an operation this build reads"),
        ))),
        None => Err(one(invalid(&field("operation"), "expected a string"))),
    }
}

fn read_labels(value: Option<&Value>, field: &str) -> Result<Vec<Label>, Vec<DocumentError>> {
    let Some(Value::Array(entries)) = value else {
        return Err(vec![invalid(field, "expected an array")]);
    };
    let mut labels = Vec::with_capacity(entries.len());
    let mut errors = Vec::new();
    for entry in entries {
        match entry.as_str().map(Label::new) {
            Some(Ok(label)) => labels.push(label),
            Some(Err(error)) => errors.push(invalid(field, &error.to_string())),
            None => errors.push(invalid(field, "expected a string")),
        }
    }
    if errors.is_empty() {
        Ok(labels)
    } else {
        Err(errors)
    }
}

fn read_id(value: Option<&Value>, field: &str) -> Result<LocalNodeId, DocumentError> {
    value
        .and_then(Value::as_str)
        .and_then(|found| LocalNodeId::from_str(found).ok())
        .ok_or_else(|| invalid(field, "expected a node identifier"))
}

fn read_optional_id(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<LocalNodeId>, Vec<DocumentError>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(found) => read_id(Some(found), field)
            .map(Some)
            .map_err(|error| vec![error]),
    }
}

fn read_optional_edge_id(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<LocalEdgeId>, Vec<DocumentError>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(found) => found
            .as_str()
            .and_then(|text| LocalEdgeId::from_str(text).ok())
            .map(Some)
            .ok_or_else(|| vec![invalid(field, "expected an edge identifier")]),
    }
}

fn read_endpoint(value: Option<&Value>, field: &str) -> Result<NodeReference, DocumentError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(field, "an edge endpoint is never absent"))?;
    let local = object
        .get("local")
        .and_then(Value::as_str)
        .and_then(|found| LocalNodeId::from_str(found).ok())
        .ok_or_else(|| invalid(field, "expected a node identifier in `local`"))?;
    match object.get("source") {
        None | Some(Value::Null) => Ok(NodeReference::Local(local)),
        Some(Value::String(text)) => Ok(NodeReference::External(ScopedNodeId {
            source: CanonicalSourceLocator::new(text.as_str())
                .map_err(|error| invalid(field, &error.to_string()))?,
            local,
        })),
        Some(_) => Err(invalid(field, "expected a string in `source`")),
    }
}

fn read_locator(
    value: Option<&Value>,
    field: &str,
) -> Result<CanonicalSourceLocator, DocumentError> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(field, "expected a string"))
        .and_then(|text| {
            CanonicalSourceLocator::new(text).map_err(|error| invalid(field, &error.to_string()))
        })
}

fn read_outcome(value: Option<&Value>, field: &str) -> Result<PlaceholderOutcome, DocumentError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(field, "expected an object"))?;
    if let Some(replacement) = object.get("replacement") {
        return Ok(PlaceholderOutcome::Replaced {
            replacement: read_id(Some(replacement), field)?,
        });
    }
    if object.get("preserved").and_then(Value::as_bool) == Some(true) {
        return Ok(PlaceholderOutcome::Preserved);
    }
    Err(invalid(
        field,
        "expected `{\\\"preserved\\\": true}` or `{\\\"replacement\\\": \\\"n_...\\\"}`",
    ))
}

fn read_properties(
    value: Option<&Value>,
    field: &str,
) -> Result<Vec<(PropertyKey, PropertyValue)>, DocumentError> {
    let object = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Object(object)) => object,
        Some(_) => return Err(invalid(field, "expected an object")),
    };
    let mut properties = Vec::with_capacity(object.len());
    for (key, held) in object {
        let key = PropertyKey::new(key.as_str())
            .map_err(|error| invalid(&format!("{field}.{key}"), &error.to_string()))?;
        properties.push((
            key,
            read_property_value(held, field)
                .ok_or_else(|| invalid(field, "unsupported property value"))?,
        ));
    }
    Ok(properties)
}

fn read_property_value(value: &Value, _field: &str) -> Option<PropertyValue> {
    Some(match value {
        Value::Bool(found) => PropertyValue::Boolean(*found),
        Value::String(found) => PropertyValue::String(found.clone()),
        Value::Number(found) => match found.as_i64() {
            Some(integer) => PropertyValue::Integer(integer),
            None => PropertyValue::Float(crate::property::FiniteF64::new(found.as_f64()?).ok()?),
        },
        _ => return None,
    })
}

fn read_evidence(value: &Value, field: &str) -> Result<Evidence, DocumentError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(field, "expected an object"))?;
    let text = |key: &str| -> Result<NonEmptyText, DocumentError> {
        object
            .get(key)
            .and_then(Value::as_str)
            .and_then(|found| NonEmptyText::new(found).ok())
            .ok_or_else(|| invalid(&format!("{field}.{key}"), "expected a non-empty string"))
    };
    Ok(Evidence {
        source: read_locator(object.get("source"), &format!("{field}.source"))?,
        resolved_revision: object
            .get("resolved_revision")
            .and_then(Value::as_str)
            .and_then(|found| NonEmptyText::new(found).ok()),
        path: object
            .get("path")
            .and_then(Value::as_str)
            .and_then(|found| NonEmptyText::new(found).ok()),
        content_digest: object
            .get("content_digest")
            .and_then(Value::as_str)
            .and_then(|found| ContentDigest::new(found).ok())
            .ok_or_else(|| invalid(&format!("{field}.content_digest"), "expected a digest"))?,
        // Also read rather than dropped. A range is half of what evidence is for: a proposal that names a file
        // and not a place in it cannot be checked against the source it claims to have read.
        range: match object.get("range") {
            None => None,
            Some(value) => {
                let text = value.as_str().ok_or_else(|| {
                    invalid(
                        &format!("{field}.range"),
                        "expected line:column:offset-line:column:offset",
                    )
                })?;
                Some(
                    crate::evidence::SourceRange::from_text(text)
                        .map_err(|error| invalid(&format!("{field}.range"), &error))?,
                )
            }
        },
        producer: text("producer")?,
        producer_version: text("producer_version")?,
        method: match object.get("method").and_then(Value::as_str) {
            Some("deterministic") => EvidenceMethod::Deterministic,
            Some("ai_inferred") => EvidenceMethod::AiInferred,
            Some("user_declared") => EvidenceMethod::UserDeclared,
            _ => {
                return Err(invalid(
                    &format!("{field}.method"),
                    "expected `deterministic`, `ai_inferred`, or `user_declared`",
                ));
            }
        },
        // Read rather than substituted. This was `Confidence::Extracted` unconditionally, which stored every
        // proposal at the confidence reserved for a fact read directly out of source — so an AI's inference
        // and an analyzer's extraction were indistinguishable in the graph, which the root contract's
        // section 17.3 forbids in as many words.
        //
        // Absent means `extracted`, which is what the published fixture declares and what a deterministic
        // producer means. A malformed one is refused rather than downgraded: a producer that wrote a score of
        // 1.4 has a defect, and recording `extracted` instead would bury it.
        confidence: match object.get("confidence") {
            None => Confidence::Extracted,
            Some(value) => {
                let text = value.as_str().ok_or_else(|| {
                    invalid(
                        &format!("{field}.confidence"),
                        "expected `extracted`, `inferred(<score>)`, or `ambiguous(<score>)`",
                    )
                })?;
                Confidence::from_text(text)
                    .map_err(|error| invalid(&format!("{field}.confidence"), &error))?
            }
        },
    })
}

/// The version this build writes.
#[must_use]
pub const fn writes_version() -> u32 {
    CHANGE_SET_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::GraphOperation;

    /// One node operation whose evidence carries whatever is passed in.
    fn document(evidence: &str) -> String {
        format!(
            r#"{{
              "change_set_version": 1,
              "base_generation": 1,
              "owner": "ai:sha256:abababababababababababababababab",
              "source_snapshot": "tree:sha256:abababababababababababababababab",
              "operations": [{{
                "operation": "upsert_node",
                "labels": ["Request"],
                "properties": {{ "name": "NewUser" }},
                "source_unit": "u_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d",
                "evidence": [{{
                  "source": ".",
                  "path": "src/Api.java",
                  "content_digest": "sha256:abababababababababababababababab",
                  "producer": "springboot-preset",
                  "producer_version": "1",
                  "method": "ai_inferred"{evidence}
                }}]
              }}]
            }}"#
        )
    }

    fn only_evidence(text: &str) -> crate::evidence::Evidence {
        let set = parse(text).expect("a document this test built");
        match set.operations.into_iter().next().expect("one operation") {
            GraphOperation::UpsertNode(draft) => {
                draft.evidence.into_iter().next().expect("one evidence")
            }
            other => panic!("expected a node draft, found {other:?}"),
        }
    }

    #[test]
    fn a_declared_confidence_survives_rather_than_being_replaced() {
        // This read `Confidence::Extracted` unconditionally, so an AI's inference was stored at the
        // confidence reserved for a fact read directly out of source. Nothing caught it: the contract never
        // said what an evidence entry contains, and the one published fixture declares `extracted` — the
        // single value the substitution happened to produce.
        let held = only_evidence(&document(r#", "confidence": "inferred(0.82)""#));
        match held.confidence {
            Confidence::Inferred { score } => assert!((score.get() - 0.82).abs() < 1e-6),
            other => panic!("expected an inferred confidence, found {other:?}"),
        }

        let held = only_evidence(&document(r#", "confidence": "ambiguous(0.4)""#));
        assert!(matches!(held.confidence, Confidence::Ambiguous { .. }));
    }

    #[test]
    fn an_absent_confidence_is_extracted_and_an_absent_range_is_none() {
        // Absent is what a deterministic producer means and what the published fixture relies on, so this is
        // the one case where the old behavior was right.
        let held = only_evidence(&document(""));
        assert_eq!(held.confidence, Confidence::Extracted);
        assert_eq!(held.range, None);
    }

    #[test]
    fn a_declared_range_survives_rather_than_being_dropped() {
        // A range is half of what evidence is for. A proposal naming a file and not a place in it cannot be
        // checked against the source it claims to have read.
        let held = only_evidence(&document(r#", "range": "12:1:340-40:2:1180""#));
        let range = held.range.expect("a range this test declared");
        assert_eq!(range.start().line, 12);
        assert_eq!(range.end().offset, 1180);
    }

    #[test]
    fn a_score_outside_the_range_is_refused_rather_than_clamped() {
        // A producer that computed 1.4 has a defect. Clamping to 1.0 would store a confident claim and hide
        // it; storing `extracted` — which is what happened before — would store a *more* confident one.
        let errors = parse(&document(r#", "confidence": "inferred(1.4)""#))
            .expect_err("a score above one is refused");
        assert!(
            errors
                .iter()
                .any(|error| format!("{error}").contains("confidence")),
            "the refusal names the field: {errors:?}"
        );
    }

    #[test]
    fn a_confidence_that_is_not_one_of_the_three_is_refused() {
        for spelled in ["certain", "inferred", "extracted(0.5)", "inferred()"] {
            let text = document(&format!(r#", "confidence": "{spelled}""#));
            assert!(
                parse(&text).is_err(),
                "`{spelled}` is not a confidence and must be refused"
            );
        }
    }

    #[test]
    fn a_malformed_range_is_refused_rather_than_ignored() {
        for spelled in ["12:1:340", "12:1-40:2", "not a range"] {
            let text = document(&format!(r#", "range": "{spelled}""#));
            assert!(
                parse(&text).is_err(),
                "`{spelled}` is not a range and must be refused"
            );
        }
    }
}
