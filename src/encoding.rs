//! Section payload encodings.
//!
//! Stage 4 gave the container an envelope and left payloads opaque. This is the
//! encoding that fills them, so a graph round-trips through a `.nostdb` file.
//!
//! # Shape
//!
//! Strings are interned once in a string table and referenced by index everywhere else,
//! because labels, relation names, property keys, and locators repeat heavily across
//! records.
//!
//! Properties and contributions are encoded inline within their node or edge rather
//! than in separate sections. The container reserves `properties`, `evidence`, and
//! `contributions` kinds for a later layout, such as a columnar store supporting
//! indexed property search; nothing in the container contract requires a kind to be
//! present, and inlining keeps a record readable in one pass.
//!
//! # Decoding is validation
//!
//! Every decoded value is rebuilt through the same typed constructors the model uses.
//! A label goes through [`Label`], a score through [`Score`], a timestamp through
//! [`DateTime`]. A corrupt or hostile file therefore cannot produce a model that
//! violates an invariant: it produces an error instead.
//!
//! Every count is checked against the bytes that remain before anything is allocated,
//! so a corrupt length cannot drive a large allocation.

use crate::container::{Container, Section, SectionKind};
use crate::contribution::{Contribution, Owner};
use crate::diagnostic::DiagnosticCode;
use crate::evidence::{
    Confidence, ContentDigest, DigestError, Evidence, EvidenceMethod, RangeError, Score,
    ScoreError, SourcePosition, SourceRange,
};
use crate::generation::Generation;
use crate::graph::{Edge, Node, NodeReference, ScopedNodeId};
use crate::id::{LocalEdgeId, LocalNodeId, SourceUnitId};
use crate::link::Link;
use crate::locator::{CanonicalSourceLocator, LocatorError};
use crate::name::{Label, LinkAlias, NameError, PropertyKey, RelationName};
use crate::property::{
    DateTime, DateTimeError, FiniteF64, MAX_NESTING_DEPTH, NumberError, PropertyScalar,
    PropertyValue,
};
use crate::schema::{EndpointConstraint, FieldType, ScalarType, Schema, SchemaField};
use crate::storage::{Database, StorageError};
use crate::text::{NonEmptyText, TextError};
use std::collections::BTreeMap;
use std::fmt;

/// Sentinel for an absent string reference.
const NO_STRING: u32 = u32::MAX;

const VALUE_BOOLEAN: u8 = 1;
const VALUE_INTEGER: u8 = 2;
const VALUE_FLOAT: u8 = 3;
const VALUE_STRING: u8 = 4;
const VALUE_BYTES: u8 = 5;
const VALUE_DATETIME: u8 = 6;
const VALUE_LIST: u8 = 7;
const VALUE_MAP: u8 = 8;

/// Field type tags, written only by `nostdb_format_version` 3 and later.
///
/// Version 2 wrote a scalar discriminant and an array flag, two `u32`s with no tag, which
/// a recursive type cannot be spelled in. The tags start at 1 so a zero byte is never a
/// valid type, which is what makes a truncated payload read as an unknown tag rather than
/// as a scalar.
const TYPE_SCALAR: u8 = 1;
const TYPE_ARRAY: u8 = 2;
const TYPE_OBJECT: u8 = 3;

/// The fewest bytes one schema field can occupy, for bounding an allocation before it
/// is made: an interned key, the smallest type, and a required flag.
const MIN_FIELD_BYTES: usize = 13;

/// An owner as one interned name, which is the only shape this format holds.
///
/// Three earlier tags carried a name and a version, a bare contract digest, and the user. They were read for
/// one release and are gone: `nostdb_format_version` moved with them, so a database holding them reports an
/// unsupported version rather than this tag being unknown.
const OWNER_NAME: u8 = 4;

const METHOD_DETERMINISTIC: u8 = 1;
const METHOD_AI: u8 = 2;
const METHOD_USER: u8 = 3;

const CONFIDENCE_EXTRACTED: u8 = 1;
const CONFIDENCE_INFERRED: u8 = 2;
const CONFIDENCE_AMBIGUOUS: u8 = 3;

const REFERENCE_LOCAL: u8 = 1;
const REFERENCE_EXTERNAL: u8 = 2;

/// A graph as stored in one database.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Graph {
    /// Node records.
    pub nodes: Vec<Node>,
    /// Edge records.
    pub edges: Vec<Edge>,
    /// Declared links.
    pub links: Vec<Link>,
    /// Declared Schemas.
    pub schemas: Vec<Schema>,
}

impl Graph {
    /// Reports whether the graph holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
            && self.edges.is_empty()
            && self.links.is_empty()
            && self.schemas.is_empty()
    }
}

/// Why a payload could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload ended before a value was complete.
    Truncated,
    /// The payload had bytes left after its last record.
    TrailingBytes,
    /// A discriminant named nothing this build knows.
    UnknownTag {
        /// What was being decoded.
        what: &'static str,
        /// The value found.
        tag: u32,
    },
    /// A string reference pointed outside the string table.
    StringIndexOutOfRange {
        /// The index found.
        index: u32,
    },
    /// A record count exceeded what the remaining bytes could hold.
    CountTooLarge {
        /// The count found.
        count: u64,
    },
    /// A required section was absent.
    MissingSection {
        /// Which section.
        kind: SectionKind,
    },
    /// A decoded name was not a valid identifier.
    InvalidName(NameError),
    /// A decoded locator was invalid.
    InvalidLocator(LocatorError),
    /// A decoded text value was empty or malformed.
    InvalidText(TextError),
    /// A decoded number was not finite.
    InvalidNumber(NumberError),
    /// A decoded timestamp was not RFC 3339.
    InvalidDateTime(DateTimeError),
    /// A decoded confidence score was out of range.
    InvalidScore(ScoreError),
    /// A decoded digest was malformed.
    InvalidDigest(DigestError),
    /// A decoded source range was inverted or zero-based.
    InvalidRange(RangeError),
    /// A decoded string was not valid UTF-8.
    InvalidUtf8,
    /// A value or a declared type nested past the permitted depth.
    ///
    /// Checked while reading rather than afterwards. A container is untrusted input, and
    /// nothing in a length or a count bounds how deeply a list may be nested inside a
    /// list, so a reader that measured the finished value would already have recursed as
    /// deep as the bytes asked before it could object.
    NestingTooDeep {
        /// The depth that was reached.
        depth: usize,
    },
}

impl DecodeError {
    /// The stable diagnostic code for a decoding failure.
    ///
    /// Every failure here means the container's bytes do not describe a valid graph,
    /// which is corruption regardless of which value was bad.
    #[must_use]
    pub const fn code(&self) -> DiagnosticCode {
        DiagnosticCode::NostdbCorrupt
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NestingTooDeep { depth } => write!(
                formatter,
                "a value nests {depth} levels, and the maximum is {MAX_NESTING_DEPTH}"
            ),
            Self::Truncated => formatter.write_str("a payload ended mid-value"),
            Self::TrailingBytes => formatter.write_str("a payload had unread trailing bytes"),
            Self::UnknownTag { what, tag } => {
                write!(formatter, "unknown {what} discriminant {tag}")
            }
            Self::StringIndexOutOfRange { index } => {
                write!(
                    formatter,
                    "string index {index} is outside the string table"
                )
            }
            Self::CountTooLarge { count } => write!(
                formatter,
                "a record count of {count} exceeds the remaining bytes"
            ),
            Self::MissingSection { kind } => write!(formatter, "the {kind:?} section is absent"),
            Self::InvalidName(error) => write!(formatter, "{error}"),
            Self::InvalidLocator(error) => write!(formatter, "{error}"),
            Self::InvalidText(error) => write!(formatter, "{error}"),
            Self::InvalidNumber(error) => write!(formatter, "{error}"),
            Self::InvalidDateTime(error) => write!(formatter, "{error}"),
            Self::InvalidScore(error) => write!(formatter, "{error}"),
            Self::InvalidDigest(error) => write!(formatter, "{error}"),
            Self::InvalidRange(error) => write!(formatter, "{error}"),
            Self::InvalidUtf8 => formatter.write_str("a stored string was not valid UTF-8"),
        }
    }
}

impl std::error::Error for DecodeError {}

macro_rules! decode_from {
    ($from:ty, $variant:ident) => {
        impl From<$from> for DecodeError {
            fn from(error: $from) -> Self {
                Self::$variant(error)
            }
        }
    };
}

decode_from!(NameError, InvalidName);
decode_from!(LocatorError, InvalidLocator);
decode_from!(TextError, InvalidText);
decode_from!(NumberError, InvalidNumber);
decode_from!(DateTimeError, InvalidDateTime);
decode_from!(ScoreError, InvalidScore);
decode_from!(DigestError, InvalidDigest);
decode_from!(RangeError, InvalidRange);

// -- writing ---------------------------------------------------------------------

#[derive(Default)]
struct Strings {
    entries: Vec<String>,
    index: BTreeMap<String, u32>,
}

impl Strings {
    fn intern(&mut self, value: &str) -> u32 {
        if let Some(&found) = self.index.get(value) {
            return found;
        }
        // A table larger than u32::MAX - 1 entries is not reachable from any real
        // graph; saturating keeps the encoder free of a panic path.
        let next = u32::try_from(self.entries.len()).unwrap_or(NO_STRING - 1);
        self.entries.push(value.to_owned());
        self.index.insert(value.to_owned(), next);
        next
    }

    fn optional(&mut self, value: Option<&str>) -> u32 {
        value.map_or(NO_STRING, |text| self.intern(text))
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, self.entries.len() as u32);
        for entry in &self.entries {
            put_u32(&mut out, entry.len() as u32);
            out.extend_from_slice(entry.as_bytes());
        }
        out
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_scalar(out: &mut Vec<u8>, strings: &mut Strings, scalar: &PropertyScalar) {
    match scalar {
        PropertyScalar::Boolean(value) => {
            out.push(VALUE_BOOLEAN);
            out.push(u8::from(*value));
        }
        PropertyScalar::Integer(value) => {
            out.push(VALUE_INTEGER);
            out.extend_from_slice(&value.to_le_bytes());
        }
        PropertyScalar::Float(value) => {
            out.push(VALUE_FLOAT);
            out.extend_from_slice(&value.get().to_le_bytes());
        }
        PropertyScalar::String(value) => {
            out.push(VALUE_STRING);
            put_u32(out, strings.intern(value));
        }
        PropertyScalar::Bytes(value) => {
            out.push(VALUE_BYTES);
            put_u32(out, value.len() as u32);
            out.extend_from_slice(value);
        }
        PropertyScalar::DateTime(value) => {
            out.push(VALUE_DATETIME);
            put_u32(out, strings.intern(value.as_str()));
        }
    }
}

/// Writes one schema field: its key, its declared type, and whether it is required.
fn put_field(out: &mut Vec<u8>, strings: &mut Strings, field: &SchemaField) {
    put_u32(out, strings.intern(field.key.as_str()));
    put_field_type(out, strings, &field.field_type);
    put_u32(out, u32::from(field.required));
}

/// Writes a declared field type, tagged so a recursive shape is readable.
fn put_field_type(out: &mut Vec<u8>, strings: &mut Strings, declared: &FieldType) {
    match declared {
        FieldType::Scalar(scalar) => {
            out.push(TYPE_SCALAR);
            put_u32(out, scalar.raw());
        }
        FieldType::Array(inner) => {
            out.push(TYPE_ARRAY);
            put_field_type(out, strings, inner);
        }
        FieldType::Object(fields) => {
            out.push(TYPE_OBJECT);
            put_u32(out, fields.len() as u32);
            for field in fields {
                put_field(out, strings, field);
            }
        }
    }
}

fn put_value(out: &mut Vec<u8>, strings: &mut Strings, value: &PropertyValue) {
    match value {
        PropertyValue::List(items) => {
            out.push(VALUE_LIST);
            put_u32(out, items.len() as u32);
            for item in items {
                put_value(out, strings, item);
            }
        }
        PropertyValue::Map(entries) => {
            out.push(VALUE_MAP);
            put_u32(out, entries.len() as u32);
            for (key, held) in entries {
                put_u32(out, strings.intern(key.as_str()));
                put_value(out, strings, held);
            }
        }
        PropertyValue::Boolean(inner) => put_scalar(out, strings, &PropertyScalar::Boolean(*inner)),
        PropertyValue::Integer(inner) => put_scalar(out, strings, &PropertyScalar::Integer(*inner)),
        PropertyValue::Float(inner) => put_scalar(out, strings, &PropertyScalar::Float(*inner)),
        PropertyValue::String(inner) => {
            put_scalar(out, strings, &PropertyScalar::String(inner.clone()));
        }
        PropertyValue::Bytes(inner) => {
            put_scalar(out, strings, &PropertyScalar::Bytes(inner.clone()));
        }
        PropertyValue::DateTime(inner) => {
            put_scalar(out, strings, &PropertyScalar::DateTime(inner.clone()));
        }
    }
}

fn put_properties(
    out: &mut Vec<u8>,
    strings: &mut Strings,
    properties: &[(PropertyKey, PropertyValue)],
) {
    put_u32(out, properties.len() as u32);
    for (key, value) in properties {
        put_u32(out, strings.intern(key.as_str()));
        put_value(out, strings, value);
    }
}

fn put_evidence(out: &mut Vec<u8>, strings: &mut Strings, evidence: &Evidence) {
    put_u32(out, strings.intern(evidence.source.as_str()));
    put_u32(
        out,
        strings.optional(
            evidence
                .resolved_revision
                .as_ref()
                .map(NonEmptyText::as_str),
        ),
    );
    put_u32(
        out,
        strings.optional(evidence.path.as_ref().map(NonEmptyText::as_str)),
    );
    put_u32(out, strings.intern(evidence.content_digest.as_str()));
    match &evidence.range {
        Some(range) => {
            out.push(1);
            for position in [range.start(), range.end()] {
                put_u32(out, position.line);
                put_u32(out, position.column);
                put_u64(out, position.offset);
            }
        }
        None => out.push(0),
    }
    put_u32(out, strings.intern(evidence.producer.as_str()));
    put_u32(out, strings.intern(evidence.producer_version.as_str()));
    out.push(match evidence.method {
        EvidenceMethod::Deterministic => METHOD_DETERMINISTIC,
        EvidenceMethod::AiInferred => METHOD_AI,
        EvidenceMethod::UserDeclared => METHOD_USER,
    });
    match evidence.confidence {
        Confidence::Extracted => out.push(CONFIDENCE_EXTRACTED),
        Confidence::Inferred { score } => {
            out.push(CONFIDENCE_INFERRED);
            out.extend_from_slice(&score.get().to_le_bytes());
        }
        Confidence::Ambiguous { score } => {
            out.push(CONFIDENCE_AMBIGUOUS);
            out.extend_from_slice(&score.get().to_le_bytes());
        }
    }
}

fn put_contributions(out: &mut Vec<u8>, strings: &mut Strings, contributions: &[Contribution]) {
    put_u32(out, contributions.len() as u32);
    for contribution in contributions {
        // One tag and one interned name. The three legacy tags are read and never written, so a database
        // converts the first time this build rewrites it.
        out.push(OWNER_NAME);
        put_u32(out, strings.intern(contribution.owner.as_str()));
        out.extend_from_slice(contribution.source_unit.as_bytes());
        put_u32(out, contribution.evidence.len() as u32);
        for evidence in &contribution.evidence {
            put_evidence(out, strings, evidence);
        }
    }
}

fn put_reference(out: &mut Vec<u8>, strings: &mut Strings, reference: &NodeReference) {
    match reference {
        NodeReference::Local(id) => {
            out.push(REFERENCE_LOCAL);
            out.extend_from_slice(id.as_bytes());
        }
        NodeReference::External(scoped) => {
            out.push(REFERENCE_EXTERNAL);
            put_u32(out, strings.intern(scoped.source.as_str()));
            out.extend_from_slice(scoped.local.as_bytes());
        }
    }
}

/// Encodes a graph into container sections.
///
/// The result always contains a string table, and contains node, edge, and link
/// sections only when they hold records, so an empty graph produces a minimal
/// container.
#[must_use]
pub fn encode_graph(graph: &Graph) -> Vec<Section> {
    let mut strings = Strings::default();

    let mut nodes = Vec::new();
    put_u32(&mut nodes, graph.nodes.len() as u32);
    for node in &graph.nodes {
        nodes.extend_from_slice(node.id.as_bytes());
        put_u32(&mut nodes, node.labels.len() as u32);
        for label in &node.labels {
            put_u32(&mut nodes, strings.intern(label.as_str()));
        }
        put_properties(&mut nodes, &mut strings, &node.properties);
        put_contributions(&mut nodes, &mut strings, &node.contributions);
    }

    let mut edges = Vec::new();
    put_u32(&mut edges, graph.edges.len() as u32);
    for edge in &graph.edges {
        edges.extend_from_slice(edge.id.as_bytes());
        put_reference(&mut edges, &mut strings, &edge.source);
        put_reference(&mut edges, &mut strings, &edge.target);
        put_u32(&mut edges, strings.intern(edge.relation.as_str()));
        put_properties(&mut edges, &mut strings, &edge.properties);
        put_contributions(&mut edges, &mut strings, &edge.contributions);
    }

    let mut links = Vec::new();
    put_u32(&mut links, graph.links.len() as u32);
    for link in &graph.links {
        put_u32(&mut links, strings.intern(link.source.as_str()));
        put_u32(
            &mut links,
            strings.optional(link.alias.as_ref().map(LinkAlias::as_str)),
        );
    }

    let mut schemas = Vec::new();
    put_u32(&mut schemas, graph.schemas.len() as u32);
    for schema in &graph.schemas {
        put_u32(&mut schemas, strings.intern(schema.name.as_str()));
        match &schema.endpoints {
            None => put_u32(&mut schemas, 0),
            Some(constraint) => {
                put_u32(&mut schemas, 1);
                put_u32(&mut schemas, strings.intern(constraint.source.as_str()));
                put_u32(&mut schemas, strings.intern(constraint.target.as_str()));
            }
        }
        put_u32(&mut schemas, schema.fields.len() as u32);
        for field in &schema.fields {
            put_field(&mut schemas, &mut strings, field);
        }
    }

    // The string table is built last because encoding the records is what populates it.
    let mut sections = vec![Section {
        kind: SectionKind::StringTable,
        payload: strings.encode(),
    }];
    if !graph.nodes.is_empty() {
        sections.push(Section {
            kind: SectionKind::Nodes,
            payload: nodes,
        });
    }
    if !graph.edges.is_empty() {
        sections.push(Section {
            kind: SectionKind::Edges,
            payload: edges,
        });
    }
    if !graph.links.is_empty() {
        sections.push(Section {
            kind: SectionKind::Links,
            payload: links,
        });
    }
    if !graph.schemas.is_empty() {
        sections.push(Section {
            kind: SectionKind::Schemas,
            payload: schemas,
        });
    }
    sections
}

// -- reading ---------------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.at.checked_add(length).ok_or(DecodeError::Truncated)?;
        let slice = self.bytes.get(self.at..end).ok_or(DecodeError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?.first().copied().unwrap_or_default())
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let array: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u32::from_le_bytes(array))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let array: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u64::from_le_bytes(array))
    }

    fn i64(&mut self) -> Result<i64, DecodeError> {
        let array: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(i64::from_le_bytes(array))
    }

    fn f32(&mut self) -> Result<f32, DecodeError> {
        let array: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(f32::from_le_bytes(array))
    }

    fn f64(&mut self) -> Result<f64, DecodeError> {
        let array: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(f64::from_le_bytes(array))
    }

    fn id16(&mut self) -> Result<[u8; 16], DecodeError> {
        self.take(16)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)
    }

    /// Reads a count and refuses one larger than the remaining bytes could describe.
    ///
    /// Every record occupies at least one byte, so this bounds an allocation before it
    /// happens without needing to know a record's exact size.
    fn count(&mut self, minimum_record_bytes: usize) -> Result<usize, DecodeError> {
        let count = u64::from(self.u32()?);
        let capacity = (self.remaining() / minimum_record_bytes.max(1)) as u64;
        if count > capacity {
            return Err(DecodeError::CountTooLarge { count });
        }
        usize::try_from(count).map_err(|_| DecodeError::CountTooLarge { count })
    }

    fn finish(&self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

struct Table {
    entries: Vec<String>,
}

impl Table {
    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(payload);
        let count = reader.count(4)?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::try_from(reader.u32()?).map_err(|_| DecodeError::Truncated)?;
            let bytes = reader.take(length)?;
            entries.push(
                std::str::from_utf8(bytes)
                    .map_err(|_| DecodeError::InvalidUtf8)?
                    .to_owned(),
            );
        }
        reader.finish()?;
        Ok(Self { entries })
    }

    fn get(&self, index: u32) -> Result<&str, DecodeError> {
        let position =
            usize::try_from(index).map_err(|_| DecodeError::StringIndexOutOfRange { index })?;
        self.entries
            .get(position)
            .map(String::as_str)
            .ok_or(DecodeError::StringIndexOutOfRange { index })
    }

    fn optional(&self, index: u32) -> Result<Option<&str>, DecodeError> {
        if index == NO_STRING {
            return Ok(None);
        }
        self.get(index).map(Some)
    }
}

fn read_scalar(reader: &mut Reader<'_>, table: &Table) -> Result<PropertyScalar, DecodeError> {
    let tag = reader.u8()?;
    Ok(match tag {
        VALUE_BOOLEAN => PropertyScalar::Boolean(reader.u8()? != 0),
        VALUE_INTEGER => PropertyScalar::Integer(reader.i64()?),
        VALUE_FLOAT => PropertyScalar::Float(FiniteF64::new(reader.f64()?)?),
        VALUE_STRING => PropertyScalar::String(table.get(reader.u32()?)?.to_owned()),
        VALUE_BYTES => {
            let length = usize::try_from(reader.u32()?).map_err(|_| DecodeError::Truncated)?;
            PropertyScalar::Bytes(reader.take(length)?.to_vec())
        }
        VALUE_DATETIME => PropertyScalar::DateTime(DateTime::new(table.get(reader.u32()?)?)?),
        other => {
            return Err(DecodeError::UnknownTag {
                what: "property scalar",
                tag: u32::from(other),
            });
        }
    })
}

/// Reads one property value, recursing through lists and objects.
///
/// Version-independent, and that is a property of the encoding rather than luck. A version
/// 2 list wrote its elements with the scalar writer, and a scalar's bytes are the same
/// whether they are read as a scalar or as a value — the tags are disjoint, so the peek
/// below falls through to [`read_scalar`] for exactly the bytes version 2 could produce.
/// A version 2 container has no `VALUE_MAP` in it because no writer could emit one.
///
/// `depth` is the level being entered, so the outermost call passes 0 and refuses the
/// first container that would exceed [`MAX_NESTING_DEPTH`].
fn read_value(
    reader: &mut Reader<'_>,
    table: &Table,
    depth: usize,
) -> Result<PropertyValue, DecodeError> {
    // The two container tags are distinct from every scalar tag, so peek without consuming.
    match reader.bytes.get(reader.at).copied() {
        Some(tag @ (VALUE_LIST | VALUE_MAP)) => {
            let entered = depth + 1;
            if entered > MAX_NESTING_DEPTH {
                return Err(DecodeError::NestingTooDeep { depth: entered });
            }
            reader.at += 1;
            if tag == VALUE_LIST {
                let count = reader.count(2)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(read_value(reader, table, entered)?);
                }
                return Ok(PropertyValue::List(items));
            }
            let count = reader.count(6)?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let key = PropertyKey::new(table.get(reader.u32()?)?)?;
                entries.push((key, read_value(reader, table, entered)?));
            }
            Ok(PropertyValue::Map(entries))
        }
        _ => Ok(PropertyValue::from(read_scalar(reader, table)?)),
    }
}

fn read_properties(
    reader: &mut Reader<'_>,
    table: &Table,
) -> Result<Vec<(PropertyKey, PropertyValue)>, DecodeError> {
    let count = reader.count(6)?;
    let mut properties = Vec::with_capacity(count);
    for _ in 0..count {
        let key = PropertyKey::new(table.get(reader.u32()?)?)?;
        properties.push((key, read_value(reader, table, 0)?));
    }
    Ok(properties)
}

fn read_evidence(reader: &mut Reader<'_>, table: &Table) -> Result<Evidence, DecodeError> {
    let source = CanonicalSourceLocator::new(table.get(reader.u32()?)?)?;
    let resolved_revision = table
        .optional(reader.u32()?)?
        .map(NonEmptyText::new)
        .transpose()?;
    let path = table
        .optional(reader.u32()?)?
        .map(NonEmptyText::new)
        .transpose()?;
    let content_digest = ContentDigest::new(table.get(reader.u32()?)?)?;
    let range = if reader.u8()? == 0 {
        None
    } else {
        let mut position = || -> Result<SourcePosition, DecodeError> {
            Ok(SourcePosition {
                line: reader.u32()?,
                column: reader.u32()?,
                offset: reader.u64()?,
            })
        };
        let start = position()?;
        let end = position()?;
        Some(SourceRange::new(start, end)?)
    };
    let producer = NonEmptyText::new(table.get(reader.u32()?)?)?;
    let producer_version = NonEmptyText::new(table.get(reader.u32()?)?)?;
    let method = match reader.u8()? {
        METHOD_DETERMINISTIC => EvidenceMethod::Deterministic,
        METHOD_AI => EvidenceMethod::AiInferred,
        METHOD_USER => EvidenceMethod::UserDeclared,
        other => {
            return Err(DecodeError::UnknownTag {
                what: "evidence method",
                tag: u32::from(other),
            });
        }
    };
    let confidence = match reader.u8()? {
        CONFIDENCE_EXTRACTED => Confidence::Extracted,
        CONFIDENCE_INFERRED => Confidence::Inferred {
            score: Score::new(reader.f32()?)?,
        },
        CONFIDENCE_AMBIGUOUS => Confidence::Ambiguous {
            score: Score::new(reader.f32()?)?,
        },
        other => {
            return Err(DecodeError::UnknownTag {
                what: "confidence",
                tag: u32::from(other),
            });
        }
    };
    Ok(Evidence {
        source,
        resolved_revision,
        path,
        content_digest,
        range,
        producer,
        producer_version,
        method,
        confidence,
    })
}

/// One contribution's owner.
fn decode_owner(reader: &mut Reader<'_>, table: &Table) -> Result<Owner, DecodeError> {
    match reader.u8()? {
        OWNER_NAME => Ok(Owner::new(NonEmptyText::new(table.get(reader.u32()?)?)?)),
        other => Err(DecodeError::UnknownTag {
            what: "owner",
            tag: u32::from(other),
        }),
    }
}

fn read_contributions(
    reader: &mut Reader<'_>,
    table: &Table,
) -> Result<Vec<Contribution>, DecodeError> {
    let count = reader.count(21)?;
    let mut contributions = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_owner(reader, table)?;
        let source_unit = SourceUnitId::from_bytes(reader.id16()?);
        let evidence_count = reader.count(24)?;
        let mut evidence = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            evidence.push(read_evidence(reader, table)?);
        }
        contributions.push(Contribution {
            owner,
            source_unit,
            evidence,
        });
    }
    Ok(contributions)
}

fn read_reference(reader: &mut Reader<'_>, table: &Table) -> Result<NodeReference, DecodeError> {
    Ok(match reader.u8()? {
        REFERENCE_LOCAL => NodeReference::Local(LocalNodeId::from_bytes(reader.id16()?)),
        REFERENCE_EXTERNAL => NodeReference::External(ScopedNodeId {
            source: CanonicalSourceLocator::new(table.get(reader.u32()?)?)?,
            local: LocalNodeId::from_bytes(reader.id16()?),
        }),
        other => {
            return Err(DecodeError::UnknownTag {
                what: "node reference",
                tag: u32::from(other),
            });
        }
    })
}

/// Decodes a graph from a validated container.
///
/// # Errors
///
/// Returns a [`DecodeError`] when a payload is truncated, carries trailing bytes, names
/// an unknown discriminant, references a string outside the table, or holds a value the
/// model rejects. Use [`DecodeError::code`] for the stable diagnostic code.
pub fn decode_graph(container: &Container) -> Result<Graph, DecodeError> {
    let table = match container.section(SectionKind::StringTable) {
        Some(payload) => Table::decode(payload)?,
        None if container.section(SectionKind::Nodes).is_none()
            && container.section(SectionKind::Edges).is_none()
            && container.section(SectionKind::Links).is_none() =>
        {
            // A container with no graph sections at all needs no string table.
            Table {
                entries: Vec::new(),
            }
        }
        None => {
            return Err(DecodeError::MissingSection {
                kind: SectionKind::StringTable,
            });
        }
    };

    let mut graph = Graph::default();

    if let Some(payload) = container.section(SectionKind::Nodes) {
        let mut reader = Reader::new(payload);
        let count = reader.count(28)?;
        graph.nodes.reserve(count);
        for _ in 0..count {
            let id = LocalNodeId::from_bytes(reader.id16()?);
            let label_count = reader.count(4)?;
            let mut labels = Vec::with_capacity(label_count);
            for _ in 0..label_count {
                labels.push(Label::new(table.get(reader.u32()?)?)?);
            }
            graph.nodes.push(Node {
                id,
                labels,
                properties: read_properties(&mut reader, &table)?,
                contributions: read_contributions(&mut reader, &table)?,
            });
        }
        reader.finish()?;
    }

    if let Some(payload) = container.section(SectionKind::Edges) {
        let mut reader = Reader::new(payload);
        let count = reader.count(40)?;
        graph.edges.reserve(count);
        for _ in 0..count {
            let id = LocalEdgeId::from_bytes(reader.id16()?);
            let source = read_reference(&mut reader, &table)?;
            let target = read_reference(&mut reader, &table)?;
            let relation = RelationName::new(table.get(reader.u32()?)?)?;
            graph.edges.push(Edge {
                id,
                source,
                target,
                relation,
                properties: read_properties(&mut reader, &table)?,
                contributions: read_contributions(&mut reader, &table)?,
            });
        }
        reader.finish()?;
    }

    if let Some(payload) = container.section(SectionKind::Links) {
        let mut reader = Reader::new(payload);
        let count = reader.count(8)?;
        graph.links.reserve(count);
        for _ in 0..count {
            let source = CanonicalSourceLocator::new(table.get(reader.u32()?)?)?;
            let alias = table
                .optional(reader.u32()?)?
                .map(LinkAlias::new)
                .transpose()?;
            graph.links.push(Link { source, alias });
        }
        reader.finish()?;
    }

    if let Some(payload) = container.section(SectionKind::Schemas) {
        let mut reader = Reader::new(payload);
        let count = reader.count(12)?;
        graph.schemas.reserve(count);
        for _ in 0..count {
            let name = Label::new(table.get(reader.u32()?)?)?;
            let endpoints = match reader.u32()? {
                0 => None,
                1 => Some(EndpointConstraint {
                    source: Label::new(table.get(reader.u32()?)?)?,
                    target: Label::new(table.get(reader.u32()?)?)?,
                }),
                tag => {
                    return Err(DecodeError::UnknownTag {
                        what: "schema endpoint constraint",
                        tag,
                    });
                }
            };
            // 13 bytes is the smallest a field can be at either version: an interned
            // key, a type, and a required flag, where the smallest type is a tag and
            // one `u32`. Version 2's fields were 16 bytes each, and keeping that
            // number here rejected a valid version 3 section — the guard bounds an
            // allocation, so the smaller of the two is the one that is never wrong.
            let field_count = reader.count(MIN_FIELD_BYTES)?;
            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                fields.push(read_field(&mut reader, &table, container.version(), 0)?);
            }
            graph.schemas.push(Schema {
                name,
                endpoints,
                fields,
            });
        }
        reader.finish()?;
    }

    Ok(graph)
}

/// Reads one schema field at the given container version.
fn read_field(
    reader: &mut Reader<'_>,
    table: &Table,
    version: u32,
    depth: usize,
) -> Result<SchemaField, DecodeError> {
    let key = PropertyKey::new(table.get(reader.u32()?)?)?;
    let field_type = read_field_type(reader, table, version, depth)?;
    let required = read_flag(reader, "schema field required marker")?;
    Ok(SchemaField {
        key,
        field_type,
        required,
    })
}

/// Reads a declared field type, in the shape the container's version wrote.
///
/// This is the one place a version branch is needed. Version 2 wrote a scalar
/// discriminant and an array flag, which cannot express an object type; version 3 writes a
/// tagged recursive shape. Every other section reads identically, which is why a version 2
/// container opens rather than being refused.
fn read_field_type(
    reader: &mut Reader<'_>,
    table: &Table,
    version: u32,
    depth: usize,
) -> Result<FieldType, DecodeError> {
    if version < 3 {
        let raw = reader.u32()?;
        let scalar = ScalarType::from_raw(raw).ok_or(DecodeError::UnknownTag {
            what: "scalar type",
            tag: raw,
        })?;
        let array = read_flag(reader, "schema field array marker")?;
        return Ok(if array {
            FieldType::array(scalar)
        } else {
            FieldType::Scalar(scalar)
        });
    }

    let tag = reader.u8()?;
    match tag {
        TYPE_SCALAR => {
            let raw = reader.u32()?;
            let scalar = ScalarType::from_raw(raw).ok_or(DecodeError::UnknownTag {
                what: "scalar type",
                tag: raw,
            })?;
            Ok(FieldType::Scalar(scalar))
        }
        TYPE_ARRAY | TYPE_OBJECT => {
            let entered = depth + 1;
            if entered > MAX_NESTING_DEPTH {
                return Err(DecodeError::NestingTooDeep { depth: entered });
            }
            if tag == TYPE_ARRAY {
                return Ok(FieldType::Array(Box::new(read_field_type(
                    reader, table, version, entered,
                )?)));
            }
            let count = reader.count(MIN_FIELD_BYTES)?;
            let mut fields = Vec::with_capacity(count);
            for _ in 0..count {
                fields.push(read_field(reader, table, version, entered)?);
            }
            Ok(FieldType::Object(fields))
        }
        other => Err(DecodeError::UnknownTag {
            what: "field type",
            tag: u32::from(other),
        }),
    }
}

/// Reads a boolean stored as a `u32`, refusing any value but 0 and 1.
///
/// A hostile container could put anything there, and quietly reading it as truthy would
/// let one set of bytes decode two ways.
fn read_flag(reader: &mut Reader<'_>, what: &'static str) -> Result<bool, DecodeError> {
    match reader.u32()? {
        0 => Ok(false),
        1 => Ok(true),
        tag => Err(DecodeError::UnknownTag { what, tag }),
    }
}

/// Commits a graph, advancing the generation by one.
///
/// # Errors
///
/// Returns whatever [`Database::commit`] reports.
pub fn commit_graph(database: &mut Database, graph: &Graph) -> Result<Generation, StorageError> {
    database.commit(encode_graph(graph))
}

/// Reads the graph an open database holds.
///
/// # Errors
///
/// Returns a [`DecodeError`] when the container's payloads do not describe a valid
/// graph.
pub fn read_graph(database: &Database) -> Result<Graph, DecodeError> {
    decode_graph(database.container())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{Container, ContainerBuilder};

    fn text(value: &str) -> NonEmptyText {
        NonEmptyText::new(value).unwrap()
    }

    fn locator(value: &str) -> CanonicalSourceLocator {
        CanonicalSourceLocator::new(value).unwrap()
    }

    fn digest() -> ContentDigest {
        ContentDigest::new("sha256:abcdef0123456789abcdef0123456789").unwrap()
    }

    fn evidence() -> Evidence {
        Evidence {
            source: locator("./packages/child"),
            resolved_revision: Some(text("a1b2c3")),
            path: Some(text("src/auth.rs")),
            content_digest: digest(),
            range: Some(
                SourceRange::new(
                    SourcePosition {
                        line: 3,
                        column: 5,
                        offset: 42,
                    },
                    SourcePosition {
                        line: 3,
                        column: 9,
                        offset: 46,
                    },
                )
                .unwrap(),
            ),
            producer: text("rust-structural"),
            producer_version: text("0.1.0"),
            method: EvidenceMethod::Deterministic,
            confidence: Confidence::Inferred {
                score: Score::new(0.75).unwrap(),
            },
        }
    }

    fn rich_graph() -> Graph {
        let node_a = LocalNodeId::from_bytes([1; 16]);
        let node_b = LocalNodeId::from_bytes([2; 16]);
        Graph {
            nodes: vec![
                Node {
                    id: node_a,
                    labels: vec![
                        Label::new("Function").unwrap(),
                        Label::new("Public").unwrap(),
                    ],
                    properties: vec![
                        (
                            PropertyKey::new("name").unwrap(),
                            PropertyValue::from("login"),
                        ),
                        (
                            PropertyKey::new("count").unwrap(),
                            PropertyValue::Integer(-7),
                        ),
                        (
                            PropertyKey::new("ratio").unwrap(),
                            PropertyValue::Float(FiniteF64::new(0.75).unwrap()),
                        ),
                        (
                            PropertyKey::new("flag").unwrap(),
                            PropertyValue::Boolean(true),
                        ),
                        (
                            PropertyKey::new("blob").unwrap(),
                            PropertyValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                        ),
                        (
                            PropertyKey::new("seen").unwrap(),
                            PropertyValue::DateTime(DateTime::new("2026-07-26T09:00:00Z").unwrap()),
                        ),
                        (
                            PropertyKey::new("tags").unwrap(),
                            PropertyValue::List(vec![
                                PropertyValue::String("auth".to_owned()),
                                PropertyValue::Integer(1),
                                PropertyValue::Boolean(false),
                            ]),
                        ),
                        (
                            PropertyKey::new("empty").unwrap(),
                            PropertyValue::List(Vec::new()),
                        ),
                    ],
                    contributions: vec![
                        Contribution {
                            owner: Owner::new(text("rust-structural")),
                            source_unit: SourceUnitId::from_bytes([9; 16]),
                            evidence: vec![evidence()],
                        },
                        Contribution {
                            owner: Owner::user(),
                            source_unit: SourceUnitId::from_bytes([8; 16]),
                            evidence: Vec::new(),
                        },
                        Contribution {
                            owner: Owner::ai(&digest()),
                            source_unit: SourceUnitId::from_bytes([7; 16]),
                            evidence: vec![Evidence {
                                confidence: Confidence::Ambiguous {
                                    score: Score::new(0.25).unwrap(),
                                },
                                method: EvidenceMethod::AiInferred,
                                range: None,
                                resolved_revision: None,
                                path: None,
                                ..evidence()
                            }],
                        },
                    ],
                },
                Node {
                    id: node_b,
                    labels: vec![Label::new("Database").unwrap()],
                    properties: Vec::new(),
                    contributions: vec![Contribution {
                        owner: Owner::user(),
                        source_unit: SourceUnitId::from_bytes([1; 16]),
                        evidence: Vec::new(),
                    }],
                },
            ],
            edges: vec![
                Edge {
                    id: LocalEdgeId::from_bytes([3; 16]),
                    source: NodeReference::Local(node_a),
                    target: NodeReference::Local(node_b),
                    relation: RelationName::new("CALLS").unwrap(),
                    properties: Vec::new(),
                    contributions: vec![Contribution {
                        owner: Owner::user(),
                        source_unit: SourceUnitId::from_bytes([1; 16]),
                        evidence: Vec::new(),
                    }],
                },
                Edge {
                    id: LocalEdgeId::from_bytes([4; 16]),
                    source: NodeReference::Local(node_a),
                    target: NodeReference::External(ScopedNodeId {
                        source: locator("./packages/shared"),
                        local: LocalNodeId::from_bytes([5; 16]),
                    }),
                    relation: RelationName::new("CALLS").unwrap(),
                    properties: vec![(
                        PropertyKey::new("confidence").unwrap(),
                        PropertyValue::from("inferred"),
                    )],
                    contributions: vec![Contribution {
                        owner: Owner::user(),
                        source_unit: SourceUnitId::from_bytes([1; 16]),
                        evidence: Vec::new(),
                    }],
                },
            ],
            links: vec![
                Link::new(locator("./packages/child")),
                Link::with_alias(
                    locator("./packages/shared"),
                    LinkAlias::new("shared").unwrap(),
                ),
            ],
            schemas: vec![Schema {
                name: Label::new("Function").unwrap(),
                endpoints: None,
                fields: vec![
                    SchemaField {
                        key: PropertyKey::new("name").unwrap(),
                        field_type: FieldType::scalar(ScalarType::String),
                        required: true,
                    },
                    SchemaField {
                        key: PropertyKey::new("tags").unwrap(),
                        field_type: FieldType::array(ScalarType::String),
                        required: false,
                    },
                ],
            }],
        }
    }

    fn build(graph: &Graph) -> Container {
        let mut builder = ContainerBuilder::new(Generation::INITIAL);
        for section in encode_graph(graph) {
            builder.push_section(section.kind, section.payload).unwrap();
        }
        Container::parse(&builder.build().unwrap()).unwrap()
    }

    #[test]
    fn a_rich_graph_round_trips_exactly() {
        let original = rich_graph();
        let decoded = decode_graph(&build(&original)).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn an_empty_graph_round_trips() {
        let original = Graph::default();
        let sections = encode_graph(&original);
        // Only the string table is written.
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].kind, SectionKind::StringTable);
        assert_eq!(decode_graph(&build(&original)).unwrap(), original);
    }

    #[test]
    fn encoding_is_deterministic() {
        let graph = rich_graph();
        assert_eq!(encode_graph(&graph), encode_graph(&graph));
    }

    #[test]
    fn strings_are_interned_once() {
        let graph = rich_graph();
        let sections = encode_graph(&graph);
        let table = Table::decode(&sections[0].payload).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for entry in &table.entries {
            assert!(seen.insert(entry.clone()), "{entry} appears twice");
        }
        // Both nodes use the analyzer name and both edges the same relation.
        assert!(table.entries.iter().any(|e| e == "CALLS"));
    }

    #[test]
    fn a_container_without_graph_sections_decodes_to_an_empty_graph() {
        let builder = ContainerBuilder::new(Generation::INITIAL);
        let container = Container::parse(&builder.build().unwrap()).unwrap();
        assert_eq!(decode_graph(&container).unwrap(), Graph::default());
    }

    #[test]
    fn a_missing_string_table_is_reported_when_records_need_it() {
        let mut builder = ContainerBuilder::new(Generation::INITIAL);
        builder
            .push_section(SectionKind::Nodes, vec![0, 0, 0, 0])
            .unwrap();
        let container = Container::parse(&builder.build().unwrap()).unwrap();
        assert_eq!(
            decode_graph(&container),
            Err(DecodeError::MissingSection {
                kind: SectionKind::StringTable
            })
        );
    }

    #[test]
    fn a_count_larger_than_the_payload_is_refused_before_allocating() {
        let mut builder = ContainerBuilder::new(Generation::INITIAL);
        builder
            .push_section(SectionKind::StringTable, vec![0, 0, 0, 0])
            .unwrap();
        // Claim four billion nodes in a four-byte payload.
        builder
            .push_section(SectionKind::Nodes, u32::MAX.to_le_bytes().to_vec())
            .unwrap();
        let container = Container::parse(&builder.build().unwrap()).unwrap();
        assert_eq!(
            decode_graph(&container),
            Err(DecodeError::CountTooLarge {
                count: u64::from(u32::MAX)
            })
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let graph = rich_graph();
        let mut sections = encode_graph(&graph);
        for section in &mut sections {
            if section.kind == SectionKind::Links {
                section.payload.push(0);
            }
        }
        let mut builder = ContainerBuilder::new(Generation::INITIAL);
        for section in sections {
            builder.push_section(section.kind, section.payload).unwrap();
        }
        let container = Container::parse(&builder.build().unwrap()).unwrap();
        assert_eq!(decode_graph(&container), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn an_out_of_range_string_index_is_refused() {
        let mut builder = ContainerBuilder::new(Generation::INITIAL);
        builder
            .push_section(SectionKind::StringTable, vec![0, 0, 0, 0])
            .unwrap();
        let mut links = Vec::new();
        put_u32(&mut links, 1);
        put_u32(&mut links, 5);
        put_u32(&mut links, NO_STRING);
        builder.push_section(SectionKind::Links, links).unwrap();
        let container = Container::parse(&builder.build().unwrap()).unwrap();
        assert_eq!(
            decode_graph(&container),
            Err(DecodeError::StringIndexOutOfRange { index: 5 })
        );
    }

    #[test]
    fn decoding_re_validates_through_the_model_so_a_corrupt_value_cannot_get_in() {
        // A label that is a reserved word must be refused even though the bytes are
        // structurally fine.
        let mut strings = Strings::default();
        // `schema` is reserved in language version 2; `module` no longer is.
        let label = strings.intern("schema");
        let mut nodes = Vec::new();
        put_u32(&mut nodes, 1);
        nodes.extend_from_slice(&[1_u8; 16]);
        put_u32(&mut nodes, 1);
        put_u32(&mut nodes, label);
        put_u32(&mut nodes, 0);
        put_u32(&mut nodes, 0);

        let mut builder = ContainerBuilder::new(Generation::INITIAL);
        builder
            .push_section(SectionKind::StringTable, strings.encode())
            .unwrap();
        builder.push_section(SectionKind::Nodes, nodes).unwrap();
        let container = Container::parse(&builder.build().unwrap()).unwrap();
        assert_eq!(
            decode_graph(&container),
            Err(DecodeError::InvalidName(NameError::Reserved))
        );
    }

    #[test]
    fn mutating_any_payload_byte_never_panics_and_never_yields_an_invalid_graph() {
        let graph = rich_graph();
        let sections = encode_graph(&graph);

        for index in 0..sections.len() {
            let payload_length = sections[index].payload.len();
            for offset in 0..payload_length {
                let mut mutated = sections.clone();
                mutated[index].payload[offset] ^= 0xFF;

                let mut builder = ContainerBuilder::new(Generation::INITIAL);
                let mut buildable = true;
                for section in mutated {
                    if builder.push_section(section.kind, section.payload).is_err() {
                        buildable = false;
                        break;
                    }
                }
                if !buildable {
                    continue;
                }
                let Ok(bytes) = builder.build() else { continue };
                let Ok(container) = Container::parse(&bytes) else {
                    continue;
                };

                // Either an error, or a graph that is itself round-trippable. The
                // second half is the real property: a decoded graph re-encodes to
                // something that decodes back identically, so a mutated file can never
                // produce a graph the encoder could not have written.
                if let Ok(decoded) = decode_graph(&container) {
                    let again = decode_graph(&build(&decoded))
                        .expect("a decoded graph must re-encode and decode");
                    assert_eq!(
                        again, decoded,
                        "section {index} byte {offset}: decoding is not stable"
                    );
                }
            }
        }
    }
}
