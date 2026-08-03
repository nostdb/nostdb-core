//! Conversion between a parsed `.nost` document and a [`Graph`].
//!
//! This is what `nostdb convert` stands on, in both directions, and what root PRD
//! section 30.2 requires be covered by tests.
//!
//! # What round-trips, and in what sense
//!
//! Graph content round-trips exactly: identifiers, labels, properties, links, Schemas,
//! contributions, and evidence all survive `.nost` to graph and back.
//!
//! The *text* does not round-trip byte for byte on the first pass, and cannot. Two
//! things a `.nost` file carries are file-local rather than graph data:
//!
//! - a node's declaration name, which exists so an edge can reference it. The model has
//!   no field for it, so export regenerates one from the record identifier;
//! - which of a record's labels were written as schema names and which in the reserved
//!   `labels` property. The model stores one label set and does not remember the split,
//!   so export puts every label matching a declared Schema in the schema list and the
//!   rest in `labels`.
//!
//! Both are stable after one pass: exporting, importing, and exporting again reproduces
//! the second output byte for byte. That fixed point is what [`to_graph`] and
//! [`from_graph`] guarantee, and it is what synchronization needs.
//!
//! # What this build cannot convert yet
//!
//! An aliased or locator endpoint names a declaration *inside a linked source*, and
//! turning that name into a [`ScopedNodeId`] means opening that source. Link resolution
//! is Stage 7 increment 4, so importing one is refused with
//! [`ConversionError::ExternalEndpoint`] rather than quietly degraded into a local
//! Placeholder that would export as something else.
//!
//! Export handles an external reference fine, because a [`ScopedNodeId`] already carries
//! the identifier a locator needs. The asymmetry is real and is recorded rather than
//! hidden.

use super::{Comments, DeclarationRef, LANGUAGE_VERSION};
use super::{
    ContributionBlock, EdgeDeclaration, Endpoint, EvidenceBlock, EvidenceValue, LinkDeclaration,
    NodeDeclaration, ObjectType, ObjectValue, OwnerDeclaration, Property, RecordBody,
    SchemaDeclaration, SchemaField, SourceFile, Spanned, Value,
};
use crate::contribution::{Contribution, Owner};
use crate::encoding::Graph;
use crate::evidence::{
    Confidence, ContentDigest, Evidence, EvidenceMethod, Score, SourcePosition, SourceRange,
};
use crate::graph::{Edge, Node, NodeReference, ScopedNodeId};
use crate::id::{LocalEdgeId, LocalNodeId, Minter, SourceUnitId};
use crate::link::Link;
use crate::locator::CanonicalSourceLocator;
use crate::name::{DeclarationName, Label, LinkAlias, PropertyKey, RelationName};
use crate::property::{DateTime, FiniteF64, PropertyScalar, PropertyValue};
use crate::schema::{EndpointConstraint, Schema};
use crate::text::NonEmptyText;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// The reserved property key holding a record identifier.
pub const ID_KEY: &str = "id";

/// The reserved property key holding labels beyond a record's schema names.
pub const LABELS_KEY: &str = "labels";

/// Why a document could not be turned into a graph.
///
/// These are caller-contract violations rather than findings about analyzed content, so
/// they are typed errors. A document that merely breaks a semantic rule is reported by
/// [`super::validate`] with a registered diagnostic code instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConversionError {
    /// The document declares a language version this build does not implement.
    UnsupportedVersion {
        /// The version declared.
        found: u32,
    },
    /// A value could not be represented in the model.
    InvalidValue {
        /// Where the value appeared.
        range: SourceRange,
        /// What was wrong with it.
        reason: String,
    },
    /// An aliased or locator endpoint needs link resolution, which is not implemented.
    ExternalEndpoint {
        /// Where the endpoint appeared.
        range: SourceRange,
        /// The link the endpoint names.
        link: String,
    },
}

impl ConversionError {
    /// Where the problem is, when it has a position.
    #[must_use]
    pub const fn range(&self) -> Option<SourceRange> {
        match self {
            Self::UnsupportedVersion { .. } => None,
            Self::InvalidValue { range, .. } | Self::ExternalEndpoint { range, .. } => Some(*range),
        }
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => write!(
                formatter,
                "language version {found} is not supported; this build implements \
                 {LANGUAGE_VERSION}"
            ),
            Self::InvalidValue { reason, .. } => formatter.write_str(reason),
            Self::ExternalEndpoint { link, .. } => write!(
                formatter,
                "the endpoint in {link} names a declaration in a linked source, and resolving \
                 one needs link resolution, which this build does not implement"
            ),
        }
    }
}

impl std::error::Error for ConversionError {}

fn invalid(range: SourceRange, reason: impl Into<String>) -> ConversionError {
    ConversionError::InvalidValue {
        range,
        reason: reason.into(),
    }
}

// -- .nost to graph ----------------------------------------------------------------

/// The declaration name export gives a record, derived from its identifier.
///
/// A declaration name is file-local: it exists so an edge can reference a node, and the
/// model has nowhere to keep one. Deriving it from the identifier makes it unique
/// without a counter and stable across exports.
#[must_use]
pub fn generated_name(id: LocalNodeId) -> DeclarationName {
    let mut text = String::with_capacity(2 + 32);
    text.push_str(LocalNodeId::PREFIX);
    for byte in id.as_bytes() {
        text.push_str(&format!("{byte:02x}"));
    }
    // Provably valid: an `n` start, then `_` and lower-case hexadecimal digits, none of
    // which is a reserved word.
    DeclarationName::literal(text)
}

fn scalar(value: &Spanned<Value>) -> Result<PropertyScalar, ConversionError> {
    Ok(match &value.value {
        Value::Boolean(flag) => PropertyScalar::Boolean(*flag),
        Value::Integer(text) => PropertyScalar::Integer(text.parse::<i64>().map_err(|_| {
            invalid(
                value.range,
                format!("the integer {text} does not fit in a signed 64-bit value"),
            )
        })?),
        Value::Float(text) => {
            let number = text
                .parse::<f64>()
                .map_err(|_| invalid(value.range, format!("{text} is not a number")))?;
            PropertyScalar::Float(
                FiniteF64::new(number)
                    .map_err(|error| invalid(value.range, format!("{text}: {error}")))?,
            )
        }
        Value::String(text) => PropertyScalar::String(text.clone()),
        Value::Bytes { decoded, .. } => PropertyScalar::Bytes(decoded.clone()),
        Value::DateTime(text) => PropertyScalar::DateTime(
            DateTime::new(text.clone())
                .map_err(|error| invalid(value.range, format!("{text}: {error}")))?,
        ),
        // Reached only where a scalar is the only thing that fits. `property_value`
        // handles a container before it ever calls this, so this arm is the guard for a
        // position that genuinely admits no container rather than a rule about lists.
        Value::List(_) | Value::Map(_) => {
            return Err(invalid(
                value.range,
                format!("expected a scalar, found a {}", value.value.kind_name()),
            ));
        }
    })
}

/// Turns a written value into a stored one, recursing through lists and objects.
///
/// The parser has already refused anything nesting past `MAX_NESTING_DEPTH`, so the
/// recursion here is bounded by that check rather than by its own counter. A value
/// reaching this function from anywhere other than the parser would need the same
/// guarantee.
fn property_value(value: &Spanned<Value>) -> Result<PropertyValue, ConversionError> {
    match &value.value {
        Value::List(items) => {
            let mut list = Vec::with_capacity(items.len());
            for item in items {
                list.push(property_value(item)?);
            }
            Ok(PropertyValue::List(list))
        }
        Value::Map(object) => {
            let mut entries = Vec::with_capacity(object.entries.len());
            for entry in &object.entries {
                let key = PropertyKey::new(entry.key.value.as_str()).map_err(|error| {
                    invalid(
                        entry.key.range,
                        format!("{} is not a property key: {error}", entry.key.value),
                    )
                })?;
                entries.push((key, property_value(&entry.value)?));
            }
            Ok(PropertyValue::Map(entries))
        }
        _ => Ok(match scalar(value)? {
            PropertyScalar::Boolean(flag) => PropertyValue::Boolean(flag),
            PropertyScalar::Integer(number) => PropertyValue::Integer(number),
            PropertyScalar::Float(number) => PropertyValue::Float(number),
            PropertyScalar::String(text) => PropertyValue::String(text),
            PropertyScalar::Bytes(bytes) => PropertyValue::Bytes(bytes),
            PropertyScalar::DateTime(moment) => PropertyValue::DateTime(moment),
        }),
    }
}

/// The labels and ordinary properties a record body carries.
struct RecordParts {
    id: Option<String>,
    extra_labels: Vec<String>,
    properties: Vec<(PropertyKey, PropertyValue)>,
}

fn split_record(record: &RecordBody) -> Result<RecordParts, ConversionError> {
    let mut parts = RecordParts {
        id: None,
        extra_labels: Vec::new(),
        properties: Vec::new(),
    };
    for property in &record.properties {
        match property.key.value.as_str() {
            ID_KEY => {
                let Value::String(text) = &property.value.value else {
                    return Err(invalid(
                        property.value.range,
                        "the reserved key `id` holds a quoted identifier",
                    ));
                };
                parts.id = Some(text.clone());
            }
            LABELS_KEY => {
                let Value::List(items) = &property.value.value else {
                    return Err(invalid(
                        property.value.range,
                        "the reserved key `labels` holds a list of strings",
                    ));
                };
                for item in items {
                    let Value::String(text) = &item.value else {
                        return Err(invalid(
                            item.range,
                            "the reserved key `labels` holds a list of strings",
                        ));
                    };
                    parts.extra_labels.push(text.clone());
                }
            }
            other => {
                let key = PropertyKey::new(other).map_err(|error| {
                    invalid(
                        property.key.range,
                        format!("{other} is not a property key: {error}"),
                    )
                })?;
                parts
                    .properties
                    .push((key, property_value(&property.value)?));
            }
        }
    }
    Ok(parts)
}

fn labels_for(
    named: &[Spanned<String>],
    extra: &[String],
    range: SourceRange,
) -> Result<Vec<Label>, ConversionError> {
    let mut labels: Vec<Label> = Vec::with_capacity(named.len() + extra.len());
    for name in named {
        let label = Label::new(name.value.as_str()).map_err(|error| {
            invalid(
                name.range,
                format!("{} is not a label: {error}", name.value),
            )
        })?;
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    for text in extra {
        let label = Label::new(text.as_str())
            .map_err(|error| invalid(range, format!("{text} is not a label: {error}")))?;
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    Ok(labels)
}

fn owner(declaration: &OwnerDeclaration) -> Result<Owner, ConversionError> {
    Ok(Owner::new(
        NonEmptyText::new(declaration.name.value.clone())
            .map_err(|error| invalid(declaration.name.range, format!("an owner name {error}")))?,
    ))
}

fn parse_range(text: &str, at: SourceRange) -> Result<SourceRange, ConversionError> {
    // The spelling lives on `SourceRange`, so this reader and the change-set reader cannot disagree about it.
    SourceRange::from_text(text).map_err(|error| invalid(at, error))
}

fn evidence_text<'a>(
    fields: &'a [super::EvidenceField],
    key: &str,
) -> Option<(&'a str, SourceRange)> {
    fields
        .iter()
        .find(|field| field.key.value == key)
        .and_then(|field| match &field.value.value {
            EvidenceValue::Text(text) => Some((text.as_str(), field.value.range)),
            EvidenceValue::Enumerator { .. } => None,
        })
}

fn evidence_word<'a>(
    fields: &'a [super::EvidenceField],
    key: &str,
) -> Option<(&'a str, Option<&'a str>, SourceRange)> {
    fields
        .iter()
        .find(|field| field.key.value == key)
        .and_then(|field| match &field.value.value {
            EvidenceValue::Enumerator { name, score } => {
                Some((name.as_str(), score.as_deref(), field.value.range))
            }
            EvidenceValue::Text(_) => None,
        })
}

fn evidence(block: &EvidenceBlock, inherited: Option<&str>) -> Result<Evidence, ConversionError> {
    let at = block.range;
    let (source_text, source_range) = evidence_text(&block.fields, "source")
        .ok_or_else(|| invalid(at, "an evidence block must state `source`"))?;
    let source = CanonicalSourceLocator::new(source_text)
        .map_err(|error| invalid(source_range, format!("{source_text}: {error}")))?;

    let (digest_text, digest_range) = evidence_text(&block.fields, "digest")
        .ok_or_else(|| invalid(at, "an evidence block must state `digest`"))?;
    let content_digest = ContentDigest::new(digest_text)
        .map_err(|error| invalid(digest_range, format!("{digest_text}: {error}")))?;

    let optional = |key: &str| -> Result<Option<NonEmptyText>, ConversionError> {
        match evidence_text(&block.fields, key) {
            None => Ok(None),
            Some((text, range)) => {
                Ok(Some(NonEmptyText::new(text).map_err(|error| {
                    invalid(range, format!("`{key}` {error}"))
                })?))
            }
        }
    };
    let resolved_revision = optional("revision")?;
    let path = optional("path")?;

    let range = match evidence_text(&block.fields, "range") {
        None => None,
        Some((text, at)) => Some(parse_range(text, at)?),
    };

    let named_producer = evidence_text(&block.fields, "producer");
    let named_version = evidence_text(&block.fields, "producer_version");
    // An owner names a producer and carries no version, so a block always states its version and may omit
    // the producer when an analyzer owner supplies one. Only an analyzer does: an AI owner's name is the
    // digest of the contract that ran, and a user has no name at all.
    let (producer, producer_version) = match (named_producer, named_version, inherited) {
        (Some((name, _)), Some((version, _)), _) => (name.to_owned(), version.to_owned()),
        (None, Some((version, _)), Some(name)) => (name.to_owned(), version.to_owned()),
        _ => {
            return Err(invalid(
                at,
                "an evidence block must state `producer_version`, and `producer` unless its \
                 owner is an analyzer to inherit one from",
            ));
        }
    };

    let (method_word, method_score, method_range) = evidence_word(&block.fields, "method")
        .ok_or_else(|| invalid(at, "an evidence block must state `method`"))?;
    if method_score.is_some() {
        return Err(invalid(method_range, "a method carries no score"));
    }
    let method = match method_word {
        "deterministic" => EvidenceMethod::Deterministic,
        "ai_inferred" => EvidenceMethod::AiInferred,
        "user_declared" => EvidenceMethod::UserDeclared,
        other => return Err(invalid(method_range, format!("`{other}` is not a method"))),
    };

    let (confidence_word, confidence_score, confidence_range) =
        evidence_word(&block.fields, "confidence")
            .ok_or_else(|| invalid(at, "an evidence block must state `confidence`"))?;
    let score = |text: Option<&str>| -> Result<Score, ConversionError> {
        let text = text.ok_or_else(|| {
            invalid(
                confidence_range,
                format!("`{confidence_word}` requires a score"),
            )
        })?;
        let number = text.parse::<f32>().map_err(|_| {
            invalid(
                confidence_range,
                format!("{text} is not a confidence score"),
            )
        })?;
        Score::new(number).map_err(|error| invalid(confidence_range, format!("{text}: {error}")))
    };
    // Which three words exist and which carry a score is `Confidence`'s rule, so both readers into a graph
    // apply the same one. This reader has the word and the score apart already, which is why it calls
    // `from_parts` rather than the text form the change-set reader uses.
    let confidence = {
        let held = match confidence_score {
            None => None,
            Some(_) => Some(score(confidence_score)?),
        };
        Confidence::from_parts(confidence_word, held)
            .map_err(|error| invalid(confidence_range, error))?
    };

    Ok(Evidence {
        source,
        resolved_revision,
        path,
        content_digest,
        range,
        producer: NonEmptyText::new(producer)
            .map_err(|error| invalid(at, format!("a producer {error}")))?,
        producer_version: NonEmptyText::new(producer_version)
            .map_err(|error| invalid(at, format!("a producer version {error}")))?,
        method,
        confidence,
    })
}

fn contribution(block: &ContributionBlock) -> Result<Contribution, ConversionError> {
    let owner = owner(&block.owner)?;
    let source_unit = match &block.unit {
        None => SourceUnitId::QUERY,
        Some(unit) => SourceUnitId::from_str(&unit.value)
            .map_err(|error| invalid(unit.range, format!("{}: {error}", unit.value)))?,
    };
    // Only an analyzer supplies a producer name — the same rule `validate` applies, which this has to agree
    // with or a document validates and then loses a field on the way in. A version comes only from the
    // keyword form, which wrote one.
    let inherited = (block.owner.kind() == crate::contribution::OwnerKind::Analyzer)
        .then_some(block.owner.name.value.as_str());
    let mut collected = Vec::with_capacity(block.evidence.len());
    for entry in &block.evidence {
        collected.push(evidence(entry, inherited)?);
    }
    Ok(Contribution {
        owner,
        source_unit,
        evidence: collected,
    })
}

fn contributions(record: &RecordBody) -> Result<Vec<Contribution>, ConversionError> {
    let mut collected = Vec::with_capacity(record.contributions.len());
    for block in &record.contributions {
        collected.push(contribution(block)?);
    }
    Ok(collected)
}

fn schema(declaration: &SchemaDeclaration) -> Result<Schema, ConversionError> {
    let name = Label::new(declaration.name.value.as_str()).map_err(|error| {
        invalid(
            declaration.name.range,
            format!("{} is not a schema name: {error}", declaration.name.value),
        )
    })?;
    let endpoints = match &declaration.endpoints {
        None => None,
        Some(constraint) => Some(EndpointConstraint {
            source: Label::new(constraint.source.value.as_str())
                .map_err(|error| invalid(constraint.source.range, format!("{error}")))?,
            target: Label::new(constraint.target.value.as_str())
                .map_err(|error| invalid(constraint.target.range, format!("{error}")))?,
        }),
    };
    let mut fields = Vec::with_capacity(declaration.fields.len());
    for field in &declaration.fields {
        fields.push(crate::schema::SchemaField {
            key: PropertyKey::new(field.key.value.as_str()).map_err(|error| {
                invalid(
                    field.key.range,
                    format!("{} is not a field key: {error}", field.key.value),
                )
            })?,
            field_type: model_field_type(&field.field_type)?,
            required: !field.optional,
        });
    }
    Ok(Schema {
        name,
        endpoints,
        fields,
    })
}

/// Turns a parsed document into a graph.
///
/// A declaration that states no `id` receives a minted one, so converting the same
/// document twice produces graphs that differ only in those identifiers. Writing the
/// result back out records them, and every later round trip carries them.
///
/// An endpoint naming no declaration in this document becomes a Placeholder Node, which
/// is what root PRD section 11.5 requires of an unresolved reference.
///
/// # Errors
///
/// Returns [`ConversionError::UnsupportedVersion`] for a version this build does not
/// implement, [`ConversionError::InvalidValue`] for a value the model refuses, and
/// [`ConversionError::ExternalEndpoint`] for an endpoint that needs link resolution.
pub fn to_graph(file: &SourceFile) -> Result<Graph, ConversionError> {
    to_graph_with(file, &mut Minter::new())
}

/// Turns a parsed document into a graph, minting through `minter`.
///
/// Exposed so a test can supply a sequential minter and assert exact identifiers.
///
/// # Errors
///
/// The same as [`to_graph`].
pub fn to_graph_with(file: &SourceFile, minter: &mut Minter) -> Result<Graph, ConversionError> {
    if file.version.value != LANGUAGE_VERSION {
        return Err(ConversionError::UnsupportedVersion {
            found: file.version.value,
        });
    }

    let mut graph = Graph::default();

    for link in &file.links {
        let source = CanonicalSourceLocator::new(link.source.value.as_str()).map_err(|error| {
            invalid(link.source.range, format!("{}: {error}", link.source.value))
        })?;
        let alias = match &link.alias {
            None => None,
            Some(alias) => Some(
                LinkAlias::new(alias.value.as_str())
                    .map_err(|error| invalid(alias.range, format!("{}: {error}", alias.value)))?,
            ),
        };
        graph.links.push(Link { source, alias });
    }

    for declaration in &file.schemas {
        graph.schemas.push(schema(declaration)?);
    }

    // Declaration name to record identifier, so an edge can resolve its endpoints.
    let mut by_name: BTreeMap<&str, LocalNodeId> = BTreeMap::new();

    for declaration in &file.nodes {
        let parts = split_record(&declaration.record)?;
        let id = match &parts.id {
            None => minter.node(),
            Some(text) => LocalNodeId::from_str(text)
                .map_err(|error| invalid(declaration.name.range, format!("{text}: {error}")))?,
        };
        let labels = labels_for(
            &declaration.schemas,
            &parts.extra_labels,
            declaration.name.range,
        )?;
        by_name.insert(declaration.name.value.as_str(), id);
        graph.nodes.push(Node {
            id,
            labels,
            properties: parts.properties,
            contributions: contributions(&declaration.record)?,
        });
    }

    for declaration in &file.edges {
        let parts = split_record(&declaration.record)?;
        let id = match &parts.id {
            None => minter.edge(),
            Some(text) => LocalEdgeId::from_str(text)
                .map_err(|error| invalid(declaration.relation.range, format!("{text}: {error}")))?,
        };
        let relation = RelationName::new(declaration.relation.value.as_str()).map_err(|error| {
            invalid(
                declaration.relation.range,
                format!(
                    "{} is not a relation name: {error}",
                    declaration.relation.value
                ),
            )
        })?;
        let source = endpoint(&declaration.source, &mut by_name, &mut graph, minter)?;
        let target = endpoint(&declaration.target, &mut by_name, &mut graph, minter)?;
        graph.edges.push(Edge {
            id,
            source,
            target,
            relation,
            properties: parts.properties,
            contributions: contributions(&declaration.record)?,
        });
    }

    // Order the result canonically rather than keeping the order the file happened to
    // use. Two things follow. A round trip is a fixed point at the graph level, because
    // re-importing whatever order the canonical writer chose sorts back to this one. And
    // the same content written in any declaration order commits to identical bytes,
    // which is what lets synchronization compare digests.
    graph
        .schemas
        .sort_by(|left, right| left.name.cmp(&right.name));
    for schema in &mut graph.schemas {
        schema
            .fields
            .sort_by(|left, right| left.key.cmp(&right.key));
    }
    graph.nodes.sort_by_key(|node| node.id);
    graph.edges.sort_by_key(|edge| edge.id);
    for node in &mut graph.nodes {
        // Labels are a set: the language contract says order is not meaning, so the
        // order they were written in is not something to preserve.
        node.labels.sort();
        canonicalize(&mut node.properties, &mut node.contributions);
    }
    for edge in &mut graph.edges {
        canonicalize(&mut edge.properties, &mut edge.contributions);
    }

    Ok(graph)
}

/// Orders a record's properties and contributions.
///
/// Evidence inside a contribution is left in the order it was written, because nothing
/// reorders it: the canonical writer emits evidence blocks in order and reading one back
/// looks its fields up by key.
fn canonicalize(
    properties: &mut [(PropertyKey, PropertyValue)],
    contributions: &mut [Contribution],
) {
    properties.sort_by(|left, right| left.0.cmp(&right.0));
    contributions.sort_by_key(owner_key);
}

/// A total order over contributions, matching what the canonical writer emits.
fn owner_key(contribution: &Contribution) -> (u8, String, [u8; 16]) {
    // Ranked by kind so analyzers come before AI and the user comes last, then by the name itself. The
    // kind is derived from the name, so this stays the order the canonical writer emitted before an owner
    // became one string.
    let rank = match contribution.owner.kind() {
        crate::contribution::OwnerKind::Analyzer => 0,
        crate::contribution::OwnerKind::AiAnalysis => 1,
        crate::contribution::OwnerKind::User => 2,
    };
    (
        rank,
        contribution.owner.as_str().to_owned(),
        contribution.source_unit.to_bytes(),
    )
}

/// The Placeholder label an unresolved endpoint receives.
pub const PLACEHOLDER_LABEL: &str = "Placeholder";

fn endpoint(
    endpoint: &Endpoint,
    by_name: &mut BTreeMap<&str, LocalNodeId>,
    graph: &mut Graph,
    minter: &mut Minter,
) -> Result<NodeReference, ConversionError> {
    match endpoint {
        Endpoint::Local(name) => {
            if let Some(id) = by_name.get(name.value.as_str()) {
                return Ok(NodeReference::Local(*id));
            }
            // Root PRD section 11.5: an unresolved reference becomes a typed Placeholder
            // Node. An Edge is never stored with a null endpoint.
            let id = minter.node();
            graph.nodes.push(Node {
                id,
                labels: vec![Label::literal(PLACEHOLDER_LABEL)],
                properties: Vec::new(),
                contributions: Vec::new(),
            });
            Ok(NodeReference::Local(id))
        }
        Endpoint::Aliased { alias, .. } => Err(ConversionError::ExternalEndpoint {
            range: alias.range,
            link: alias.value.clone(),
        }),
        Endpoint::Locator { locator, .. } => Err(ConversionError::ExternalEndpoint {
            range: locator.range,
            link: locator.value.clone(),
        }),
    }
}

// -- graph to .nost ----------------------------------------------------------------

fn spanned<T>(value: T) -> Spanned<T> {
    Spanned {
        value,
        range: SourceRange::ORIGIN,
    }
}

/// Turns a written field type into a stored one, dropping the spans and comments the
/// model does not carry.
///
/// A nested field key is validated here rather than at parse time, because the parser's
/// job is that it is an identifier and the model's is that it is a [`PropertyKey`]. The
/// two rules differ, and the diagnostic points at the key that failed.
fn model_field_type(
    written: &Spanned<super::FieldType>,
) -> Result<crate::schema::FieldType, ConversionError> {
    use crate::schema::FieldType as Model;
    Ok(match &written.value {
        super::FieldType::Scalar(scalar) => Model::Scalar(*scalar),
        super::FieldType::Array(inner) => Model::Array(Box::new(model_field_type(&Spanned {
            value: inner.as_ref().clone(),
            range: written.range,
        })?)),
        super::FieldType::Object(object) => {
            let mut fields = Vec::with_capacity(object.fields.len());
            for field in &object.fields {
                fields.push(crate::schema::SchemaField {
                    key: PropertyKey::new(field.key.value.as_str()).map_err(|error| {
                        invalid(
                            field.key.range,
                            format!("{} is not a field key: {error}", field.key.value),
                        )
                    })?,
                    field_type: model_field_type(&field.field_type)?,
                    required: !field.optional,
                });
            }
            Model::Object(fields)
        }
    })
}

/// Turns a stored field type into a written one, with no comments to restore.
///
/// A field type exported from a database has never been written by a person, so there is
/// nothing to preserve. A field type read from a document keeps its own CST.
fn written_field_type(model: &crate::schema::FieldType) -> super::FieldType {
    use crate::schema::FieldType as Model;
    match model {
        Model::Scalar(scalar) => super::FieldType::Scalar(*scalar),
        Model::Array(inner) => super::FieldType::Array(Box::new(written_field_type(inner))),
        Model::Object(fields) => super::FieldType::Object(ObjectType {
            fields: fields
                .iter()
                .map(|field| SchemaField {
                    key: spanned(field.key.as_str().to_owned()),
                    optional: !field.required,
                    field_type: spanned(written_field_type(&field.field_type)),
                    comments: Comments::default(),
                })
                .collect(),
            block_comments: Vec::new(),
        }),
    }
}

fn value_of(value: &PropertyValue) -> Value {
    match value {
        PropertyValue::Boolean(flag) => Value::Boolean(*flag),
        PropertyValue::Integer(number) => Value::Integer(number.to_string()),
        PropertyValue::Float(number) => Value::Float(format!("{:?}", number.get())),
        PropertyValue::String(text) => Value::String(text.clone()),
        PropertyValue::Bytes(bytes) => Value::Bytes {
            decoded: bytes.clone(),
            digits: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        },
        PropertyValue::DateTime(moment) => Value::DateTime(moment.as_str().to_owned()),
        PropertyValue::List(items) => {
            Value::List(items.iter().map(|item| spanned(value_of(item))).collect())
        }
        PropertyValue::Map(entries) => Value::Map(ObjectValue {
            entries: entries
                .iter()
                .map(|(key, held)| property(key.as_str(), value_of(held)))
                .collect(),
            block_comments: Vec::new(),
        }),
    }
}

fn property(key: &str, value: Value) -> Property {
    Property {
        key: spanned(key.to_owned()),
        value: spanned(value),
        comments: Comments::default(),
    }
}

fn evidence_field(key: &str, value: EvidenceValue) -> super::EvidenceField {
    super::EvidenceField {
        key: spanned(key.to_owned()),
        value: spanned(value),
        comments: Comments::default(),
    }
}

fn render_position(position: SourcePosition) -> String {
    format!("{}:{}:{}", position.line, position.column, position.offset)
}

fn evidence_block(entry: &Evidence, inherited: Option<&str>) -> EvidenceBlock {
    let mut fields = vec![evidence_field(
        "source",
        EvidenceValue::Text(entry.source.as_str().to_owned()),
    )];
    if let Some(revision) = &entry.resolved_revision {
        fields.push(evidence_field(
            "revision",
            EvidenceValue::Text(revision.as_str().to_owned()),
        ));
    }
    if let Some(path) = &entry.path {
        fields.push(evidence_field(
            "path",
            EvidenceValue::Text(path.as_str().to_owned()),
        ));
    }
    fields.push(evidence_field(
        "digest",
        EvidenceValue::Text(entry.content_digest.as_str().to_owned()),
    ));
    if let Some(range) = entry.range {
        fields.push(evidence_field(
            "range",
            EvidenceValue::Text(format!(
                "{}-{}",
                render_position(range.start()),
                render_position(range.end())
            )),
        ));
    }
    // A producer equal to what the owner supplies is left out, which is what the
    // contract's inheritance rule exists for. Writing it anyway would be noise, and
    // reading it back produces the same value either way.
    let inherits_producer = inherited == Some(entry.producer.as_str());
    if !inherits_producer {
        fields.push(evidence_field(
            "producer",
            EvidenceValue::Text(entry.producer.as_str().to_owned()),
        ));
    }
    fields.push(evidence_field(
        "producer_version",
        EvidenceValue::Text(entry.producer_version.as_str().to_owned()),
    ));
    fields.push(evidence_field(
        "method",
        EvidenceValue::Enumerator {
            name: match entry.method {
                EvidenceMethod::Deterministic => "deterministic",
                EvidenceMethod::AiInferred => "ai_inferred",
                EvidenceMethod::UserDeclared => "user_declared",
            }
            .to_owned(),
            score: None,
        },
    ));
    fields.push(evidence_field(
        "confidence",
        match entry.confidence {
            Confidence::Extracted => EvidenceValue::Enumerator {
                name: "extracted".to_owned(),
                score: None,
            },
            Confidence::Inferred { score } => EvidenceValue::Enumerator {
                name: "inferred".to_owned(),
                score: Some(format!("{:?}", f64::from(score.get()))),
            },
            Confidence::Ambiguous { score } => EvidenceValue::Enumerator {
                name: "ambiguous".to_owned(),
                score: Some(format!("{:?}", f64::from(score.get()))),
            },
        },
    ));

    EvidenceBlock {
        fields,
        range: SourceRange::ORIGIN,
        comments: Comments::default(),
        block_comments: Vec::new(),
    }
}

fn contribution_block(entry: &Contribution) -> ContributionBlock {
    let owner = OwnerDeclaration {
        name: spanned(entry.owner.as_str().to_owned()),
    };
    // The owner supplies the producer name and no version, so a block writes its own version. See the
    // resolution in `evidence`, which this has to agree with or a round trip loses a field.
    let inherited = (entry.owner.kind() == crate::contribution::OwnerKind::Analyzer)
        .then(|| entry.owner.as_str());
    // The nil source unit is what a contribution with no stated unit reads back as, so
    // writing it would be redundant.
    let unit =
        (entry.source_unit != SourceUnitId::QUERY).then(|| spanned(entry.source_unit.to_string()));
    ContributionBlock {
        owner,
        unit,
        evidence: entry
            .evidence
            .iter()
            .map(|item| evidence_block(item, inherited))
            .collect(),
        comments: Comments::default(),
        block_comments: Vec::new(),
    }
}

fn record_body(
    id: String,
    properties: &[(PropertyKey, PropertyValue)],
    extra_labels: &[Label],
    contributions: &[Contribution],
) -> RecordBody {
    let mut written = vec![property(ID_KEY, Value::String(id))];
    if !extra_labels.is_empty() {
        written.push(property(
            LABELS_KEY,
            Value::List(
                extra_labels
                    .iter()
                    .map(|label| spanned(Value::String(label.as_str().to_owned())))
                    .collect(),
            ),
        ));
    }
    for (key, value) in properties {
        written.push(property(key.as_str(), value_of(value)));
    }
    RecordBody {
        properties: written,
        contributions: contributions.iter().map(contribution_block).collect(),
        comments: Comments::default(),
        block_comments: Vec::new(),
    }
}

/// Renders a graph as a `.nost` document.
///
/// Declaration names are generated from record identifiers, and a record's labels are
/// split between its schema list and the reserved `labels` property by whether a Schema
/// declares them. Neither is stored in the model, so neither can be recovered; both are
/// stable, so a second pass reproduces the first byte for byte.
#[must_use]
pub fn from_graph(graph: &Graph) -> SourceFile {
    let declared: Vec<&Label> = graph.schemas.iter().map(|schema| &schema.name).collect();

    let links = graph
        .links
        .iter()
        .map(|link| LinkDeclaration {
            source: spanned(link.source.as_str().to_owned()),
            alias: link
                .alias
                .as_ref()
                .map(|alias| spanned(alias.as_str().to_owned())),
            comments: Comments::default(),
        })
        .collect();

    let schemas: Vec<SchemaDeclaration> = graph
        .schemas
        .iter()
        .map(|schema| SchemaDeclaration {
            name: spanned(schema.name.as_str().to_owned()),
            endpoints: schema
                .endpoints
                .as_ref()
                .map(|constraint| super::EndpointConstraint {
                    source: spanned(constraint.source.as_str().to_owned()),
                    target: spanned(constraint.target.as_str().to_owned()),
                }),
            fields: schema
                .fields
                .iter()
                .map(|field| SchemaField {
                    key: spanned(field.key.as_str().to_owned()),
                    optional: !field.required,
                    field_type: spanned(written_field_type(&field.field_type)),
                    comments: Comments::default(),
                })
                .collect(),
            comments: Comments::default(),
            block_comments: Vec::new(),
        })
        .collect();

    let nodes: Vec<NodeDeclaration> = graph
        .nodes
        .iter()
        .map(|node| {
            let (named, extra) = split_labels(&node.labels, &declared);
            NodeDeclaration {
                name: spanned(generated_name(node.id).as_str().to_owned()),
                schemas: named
                    .iter()
                    .map(|label| spanned((*label).as_str().to_owned()))
                    .collect(),
                record: record_body(
                    node.id.to_string(),
                    &node.properties,
                    &extra,
                    &node.contributions,
                ),
            }
        })
        .collect();

    let edges: Vec<EdgeDeclaration> = graph
        .edges
        .iter()
        .map(|edge| EdgeDeclaration {
            source: reference_endpoint(&edge.source, graph),
            target: reference_endpoint(&edge.target, graph),
            relation: spanned(edge.relation.as_str().to_owned()),
            record: record_body(
                edge.id.to_string(),
                &edge.properties,
                &[],
                &edge.contributions,
            ),
        })
        .collect();

    let order = schemas
        .iter()
        .enumerate()
        .map(|(index, _)| DeclarationRef::Schema(index))
        .chain(
            nodes
                .iter()
                .enumerate()
                .map(|(index, _)| DeclarationRef::Node(index)),
        )
        .chain(
            edges
                .iter()
                .enumerate()
                .map(|(index, _)| DeclarationRef::Edge(index)),
        )
        .collect();

    SourceFile {
        version: spanned(LANGUAGE_VERSION),
        version_comments: Comments::default(),
        links,
        schemas,
        nodes,
        edges,
        order,
        trailing_comments: Vec::new(),
    }
}

/// Splits a record's labels into those a Schema declares and the rest.
///
/// A record with no Schema-matching label still needs one name in `node n: X`, so its
/// first label is used. The split is a pure function of the label set and the declared
/// Schemas, which is what makes the second export pass reproduce the first.
fn split_labels<'a>(labels: &'a [Label], declared: &[&Label]) -> (Vec<&'a Label>, Vec<Label>) {
    let mut named: Vec<&Label> = labels
        .iter()
        .filter(|label| declared.contains(label))
        .collect();
    if named.is_empty() {
        if let Some(first) = labels.first() {
            named.push(first);
        }
    }
    let extra = labels
        .iter()
        .filter(|label| !named.contains(label))
        .cloned()
        .collect();
    (named, extra)
}

fn reference_endpoint(reference: &NodeReference, graph: &Graph) -> Endpoint {
    match reference {
        NodeReference::Local(id) => {
            Endpoint::Local(spanned(generated_name(*id).as_str().to_owned()))
        }
        NodeReference::External(ScopedNodeId { source, local }) => {
            let name = spanned(generated_name(*local).as_str().to_owned());
            match graph
                .links
                .iter()
                .find(|link| link.source == *source)
                .and_then(|link| link.alias.as_ref())
            {
                Some(alias) => Endpoint::Aliased {
                    alias: spanned(alias.as_str().to_owned()),
                    name,
                },
                None => Endpoint::Locator {
                    locator: spanned(source.as_str().to_owned()),
                    name,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{format, parse};
    use super::*;
    use crate::schema::{FieldType, ScalarType};

    fn graph_of(source: &str) -> Graph {
        let file = parse(source).expect("must parse");
        to_graph(&file).expect("must convert")
    }

    #[test]
    fn an_empty_document_converts_to_an_empty_graph() {
        assert!(graph_of("@nost 4\n").is_empty());
    }

    #[test]
    fn version_one_is_refused() {
        let file = parse("@nost 1\n").unwrap();
        assert_eq!(
            to_graph(&file),
            Err(ConversionError::UnsupportedVersion { found: 1 })
        );
    }

    #[test]
    fn a_stated_identifier_is_kept_and_an_absent_one_is_minted() {
        let stated = "n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let graph = graph_of(&format!(
            "@nost 4\nnode a: L {{\n id: \"{stated}\",\n}}\nnode b: L {{}}\n"
        ));
        assert_eq!(graph.nodes[0].id.to_string(), stated);
        assert_ne!(graph.nodes[1].id.to_string(), stated);
        assert_eq!(graph.nodes[1].id.to_bytes()[6] >> 4, 0x7);
    }

    #[test]
    fn schema_names_and_the_labels_key_both_become_labels() {
        let graph = graph_of("@nost 4\nnode a: Alpha, Beta {\n labels: [\"Gamma\"],\n}\n");
        let labels: Vec<&str> = graph.nodes[0]
            .labels
            .iter()
            .map(crate::name::Label::as_str)
            .collect();
        assert_eq!(labels, ["Alpha", "Beta", "Gamma"]);
        assert!(graph.nodes[0].properties.is_empty());
    }

    #[test]
    fn a_repeated_label_is_kept_once() {
        let graph = graph_of("@nost 4\nnode a: Alpha {\n labels: [\"Alpha\"],\n}\n");
        assert_eq!(graph.nodes[0].labels.len(), 1);
    }

    #[test]
    fn every_property_value_type_converts() {
        let graph = graph_of(
            "@nost 4\nnode a: L {\n flag: true,\n count: 42,\n ratio: 0.5,\n name: \"x\",\n \
             payload: bytes\"dead\",\n at: datetime\"2026-07-27T00:00:00Z\",\n \
             tags: [\"a\", 1],\n}\n",
        );
        let values: BTreeMap<&str, &PropertyValue> = graph.nodes[0]
            .properties
            .iter()
            .map(|(key, value)| (key.as_str(), value))
            .collect();
        assert_eq!(values["flag"], &PropertyValue::Boolean(true));
        assert_eq!(values["count"], &PropertyValue::Integer(42));
        assert_eq!(values["payload"], &PropertyValue::Bytes(vec![0xDE, 0xAD]));
        assert!(matches!(values["ratio"], PropertyValue::Float(_)));
        assert!(matches!(values["at"], PropertyValue::DateTime(_)));
        assert!(matches!(values["tags"], PropertyValue::List(items) if items.len() == 2));
    }

    #[test]
    fn an_out_of_range_integer_is_a_conversion_error_not_a_panic() {
        let file = parse("@nost 4\nnode a: L {\n k: 9223372036854775808,\n}\n").unwrap();
        let error = to_graph(&file).unwrap_err();
        assert!(matches!(error, ConversionError::InvalidValue { .. }));
        assert!(error.range().is_some());
    }

    #[test]
    fn an_unresolved_endpoint_becomes_a_placeholder_node() {
        let graph = graph_of("@nost 4\nnode a: L {}\nedge a -> gone :R {}\n");
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.nodes[1].labels[0].as_str(), PLACEHOLDER_LABEL);
        // Never a null endpoint.
        assert!(matches!(graph.edges[0].target, NodeReference::Local(_)));
    }

    #[test]
    fn an_external_endpoint_is_refused_rather_than_degraded() {
        for source in [
            "@nost 4\n@link \"./s\" as s\nnode a: L {}\nedge a -> s::x :R {}\n",
            "@nost 4\n@link \"./c\"\nnode a: L {}\nedge a -> \"./c\"::x :R {}\n",
        ] {
            let file = parse(source).unwrap();
            let error = to_graph(&file).unwrap_err();
            assert!(
                matches!(error, ConversionError::ExternalEndpoint { .. }),
                "{error:?}"
            );
        }
    }

    #[test]
    fn links_and_schemas_convert() {
        let graph = graph_of(
            "@nost 4\n@link \"./c\"\n@link \"./s\" as s\n\
             schema Function {\n name: string,\n tags?: string[],\n}\n\
             schema CALLS (Function -> Function) {}\n",
        );
        assert_eq!(graph.links.len(), 2);
        assert_eq!(graph.links[1].alias.as_ref().unwrap().as_str(), "s");

        // Conversion orders schemas by name, so CALLS precedes Function whatever order
        // the document used.
        assert_eq!(graph.schemas.len(), 2);
        assert_eq!(graph.schemas[0].name.as_str(), "CALLS");
        let constraint = graph.schemas[0].endpoints.as_ref().unwrap();
        assert_eq!(constraint.source.as_str(), "Function");

        let function = &graph.schemas[1];
        assert_eq!(function.name.as_str(), "Function");
        assert_eq!(function.fields[0].key.as_str(), "name");
        assert_eq!(
            function.fields[0].field_type,
            FieldType::scalar(ScalarType::String)
        );
        assert!(function.fields[0].required);
        assert_eq!(function.fields[1].key.as_str(), "tags");
        assert!(!function.fields[1].required);
        assert_eq!(
            function.fields[1].field_type,
            FieldType::array(ScalarType::String)
        );
    }

    #[test]
    fn contributions_and_evidence_convert() {
        let graph = graph_of(
            "@nost 4\nnode a: L {\n \
             @by \"rust\" unit \"u_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b\" {\n  \
             @evidence {\n   source: \"./\",\n   path: \"src/a.rs\",\n   \
             digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   \
             range: \"1:1:0-2:1:10\",\n   producer_version: \"1\",\n   method: deterministic,\n   confidence: extracted,\n  }\n \
             }\n \
             @by \"user\" {}\n}\n",
        );
        let contributions = &graph.nodes[0].contributions;
        assert_eq!(contributions.len(), 2);

        let analyzer = &contributions[0];
        assert_eq!(
            analyzer.owner.kind(),
            crate::contribution::OwnerKind::Analyzer
        );
        assert_ne!(analyzer.source_unit, SourceUnitId::QUERY);
        let evidence = &analyzer.evidence[0];
        // The producer is inherited from the analyzer owner; the version is stated, because no owner carries
        // one to inherit.
        assert_eq!(evidence.producer.as_str(), "rust");
        assert_eq!(evidence.producer_version.as_str(), "1");
        assert_eq!(evidence.method, EvidenceMethod::Deterministic);
        assert_eq!(evidence.confidence, Confidence::Extracted);
        assert_eq!(evidence.range.unwrap().byte_length(), 10);

        assert_eq!(contributions[1].owner, Owner::user());
        assert_eq!(contributions[1].source_unit, SourceUnitId::QUERY);
    }

    #[test]
    fn a_score_carrying_confidence_converts() {
        let graph = graph_of(
            "@nost 4\nnode a: L {\n @by \"ai:sha256:abcdef0123456789abcdef0123456789\" {\n  \
             @evidence {\n   source: \"./\",\n   \
             digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   producer: \"p\",\n   \
             producer_version: \"1\",\n   method: ai_inferred,\n   confidence: inferred(0.25),\n  \
             }\n }\n}\n",
        );
        match graph.nodes[0].contributions[0].evidence[0].confidence {
            Confidence::Inferred { score } => assert!((score.get() - 0.25).abs() < f32::EPSILON),
            other => panic!("expected an inferred confidence, found {other:?}"),
        }
    }

    // -- round trips ---------------------------------------------------------------

    fn round_trip(source: &str) -> (Graph, String) {
        let graph = graph_of(source);
        let exported = format(&from_graph(&graph));
        let reimported = to_graph(&parse(&exported).expect("exported text must parse"))
            .expect("exported text must convert");
        assert_eq!(reimported, graph, "graph content changed:\n{exported}");
        let again = format(&from_graph(&reimported));
        assert_eq!(again, exported, "export is not a fixed point:\n{exported}");
        (graph, exported)
    }

    #[test]
    fn graph_content_survives_a_round_trip() {
        round_trip(
            "@nost 4\n@link \"./c\"\n@link \"./s\" as s\n\
             schema Function {\n name: string,\n tags?: string[],\n}\n\
             node login: Function {\n id: \"n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b\",\n \
             name: \"login\",\n tags: [\"a\"],\n labels: [\"Public\"],\n}\n\
             node other: Function {\n id: \"n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c\",\n \
             name: \"other\",\n}\n\
             edge login -> other :CALLS {\n \
             id: \"e_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d\",\n}\n",
        );
    }

    #[test]
    fn contributions_survive_a_round_trip() {
        round_trip(
            "@nost 4\nnode a: L {\n id: \"n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b\",\n \
             @by \"rust\" unit \"u_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b\" {\n  \
             @evidence {\n   source: \"./\",\n   path: \"src/a.rs\",\n   \
             revision: \"abc\",\n   \
             digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   \
             range: \"1:1:0-2:1:10\",\n   producer_version: \"1\",\n   method: deterministic,\n   \
             confidence: ambiguous(0.5),\n  }\n }\n \
             @by \"user\" {}\n}\n",
        );
    }

    #[test]
    fn a_round_trip_preserves_ownership_rather_than_collapsing_it() {
        // The reason contribution blocks exist at all: without them every contribution
        // would come back owned by the user, and an analyzer refresh would then be free
        // to replace work a person did by hand.
        let (graph, _) = round_trip(
            "@nost 4\nnode a: L {\n id: \"n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b\",\n \
             @by \"rust\" {\n  @evidence {\n   source: \"./\",\n   \
             digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   \
             producer_version: \"1\",\n   method: deterministic,\n   \
             confidence: extracted,\n  }\n }\n \
             @by \"user\" {}\n}\n",
        );
        let owners: Vec<_> = graph.nodes[0]
            .contributions
            .iter()
            .map(|contribution| contribution.owner.kind())
            .collect();
        assert_eq!(
            owners,
            vec![
                crate::contribution::OwnerKind::Analyzer,
                crate::contribution::OwnerKind::User
            ]
        );
    }

    #[test]
    fn a_minted_identifier_is_written_out_so_the_next_pass_carries_it() {
        // The first export is where a minted identifier becomes durable. Before it, two
        // conversions of the same text produce different graphs; after it, they do not.
        let source = "@nost 4\nnode a: L {}\n";
        let exported = format(&from_graph(&graph_of(source)));
        assert!(exported.contains("id: \"n_"), "{exported}");
        assert_eq!(graph_of(&exported), graph_of(&exported));
    }

    #[test]
    fn an_external_reference_exports_through_its_alias_or_its_locator() {
        let locator = CanonicalSourceLocator::new("./shared").unwrap();
        let mut graph = Graph {
            nodes: vec![Node {
                id: LocalNodeId::from_bytes([1; 16]),
                labels: vec![Label::new("L").unwrap()],
                properties: Vec::new(),
                contributions: Vec::new(),
            }],
            edges: vec![Edge {
                id: LocalEdgeId::from_bytes([2; 16]),
                source: NodeReference::Local(LocalNodeId::from_bytes([1; 16])),
                target: NodeReference::External(ScopedNodeId {
                    source: locator.clone(),
                    local: LocalNodeId::from_bytes([3; 16]),
                }),
                relation: RelationName::new("CALLS").unwrap(),
                properties: Vec::new(),
                contributions: Vec::new(),
            }],
            links: vec![Link::new(locator.clone())],
            schemas: Vec::new(),
        };

        let bare = format(&from_graph(&graph));
        assert!(bare.contains("\"./shared\"::n_"), "{bare}");

        graph.links = vec![Link::with_alias(locator, LinkAlias::new("shared").unwrap())];
        let aliased = format(&from_graph(&graph));
        assert!(aliased.contains("shared::n_"), "{aliased}");
    }

    #[test]
    fn a_generated_declaration_name_is_a_valid_identifier_and_unique_per_record() {
        let first = generated_name(LocalNodeId::from_bytes([0xAB; 16]));
        let second = generated_name(LocalNodeId::from_bytes([0xCD; 16]));
        assert_ne!(first, second);
        assert!(first.as_str().starts_with("n_"));
        assert!(DeclarationName::new(first.as_str()).is_ok());
    }
}
