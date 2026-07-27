//! The `.nost` language: lexer, comment-preserving tree, validation, and canonical
//! formatter.
//!
//! The language contract lives in `nostdb-spec`, and its fixture suite is the
//! conformance gate. This module implements the contract; it does not restate it.
//!
//! # Why comments are part of the tree
//!
//! `.nost` exists so a graph can be reviewed and edited in Git. A formatter that
//! dropped comments would make the format unusable for that, so every comment is
//! retained with its attachment and reproduced on output.
//!
//! Attachment follows the contract: a comment on its own line leads the next
//! declaration or property in the same block, or trails the block when nothing
//! follows; a comment after something on the same line trails it.
//!
//! # Syntax and semantics are separate
//!
//! Parsing reports only what the grammar can express. An integer that does not fit in
//! 64 bits, a duplicate alias, and a malformed timestamp all parse, because rejecting
//! them needs meaning rather than shape. [`validate`] reports those, each with the
//! stable diagnostic code the contract assigns.

pub mod convert;
pub mod format;
pub mod lexer;
pub mod parser;
pub mod validate;

use crate::diagnostic::{Diagnostic, DiagnosticCode, Severity};
use crate::evidence::SourceRange;
pub use crate::schema::{FieldType, ScalarType};
use crate::text::NonEmptyText;
use std::fmt;

pub use convert::{ConversionError, from_graph, to_graph};
pub use format::format;
pub use parser::parse;
pub use validate::validate;

/// A syntax error.
///
/// Every syntax error carries a range. Where inside a construct that range begins is
/// this implementation's own quality decision: the language contract marks the
/// positions recorded in its fixtures informative, because the point at which a parser
/// notices a syntax error is an artifact of its technology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// What went wrong.
    pub message: String,
    /// Where it went wrong.
    pub range: SourceRange,
}

impl ParseError {
    /// The stable diagnostic code for a syntax error.
    #[must_use]
    pub const fn code(&self) -> DiagnosticCode {
        DiagnosticCode::NostParseError
    }

    /// Renders this error as a diagnostic.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic {
        let message = NonEmptyText::new(self.message.clone())
            .unwrap_or_else(|_| NonEmptyText::literal("a syntax error"));
        Diagnostic {
            code: self.code(),
            severity: Severity::Error,
            message,
            source: None,
            range: Some(self.range),
            details: Vec::new(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}: {}",
            self.range.start().line,
            self.range.start().column,
            self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// A comment, with enough context to place it again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comment {
    /// The comment text, without its delimiters.
    pub text: String,
    /// Whether it was written as a block comment.
    pub block: bool,
    /// Where it appeared.
    pub range: SourceRange,
}

/// Comments attached to one construct.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comments {
    /// Own-line comments immediately before the construct.
    pub leading: Vec<Comment>,
    /// A comment on the same line, after the construct.
    pub trailing: Option<Comment>,
}

impl Comments {
    /// Reports whether any comment is attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leading.is_empty() && self.trailing.is_none()
    }

    /// Total number of comments attached.
    #[must_use]
    pub fn count(&self) -> usize {
        self.leading.len() + usize::from(self.trailing.is_some())
    }
}

/// A value with the range it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spanned<T> {
    /// The value.
    pub value: T,
    /// Where it came from.
    pub range: SourceRange,
}

/// The language version this build reads and writes.
///
/// Version 1 is refused rather than parsed best-effort, because it required a module
/// declaration version 2 has no production for.
pub const LANGUAGE_VERSION: u32 = 2;

/// A parsed `.nost` file.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceFile {
    /// The declared language version.
    pub version: Spanned<u32>,
    /// Comments attached to the version header.
    pub version_comments: Comments,
    /// Link declarations, in source order.
    pub links: Vec<LinkDeclaration>,
    /// Schema declarations, in source order.
    pub schemas: Vec<SchemaDeclaration>,
    /// Node declarations, in source order.
    pub nodes: Vec<NodeDeclaration>,
    /// Edge declarations, in source order.
    pub edges: Vec<EdgeDeclaration>,
    /// The order the schema, node, and edge declarations appeared in.
    ///
    /// Parsing keeps this so a round trip can reproduce the file as written, while the
    /// three typed lists stay convenient for everything that does not care about order.
    pub order: Vec<DeclarationRef>,
    /// Own-line comments after the last declaration.
    pub trailing_comments: Vec<Comment>,
}

/// Which declaration list an entry in [`SourceFile::order`] points into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclarationRef {
    /// An index into [`SourceFile::schemas`].
    Schema(usize),
    /// An index into [`SourceFile::nodes`].
    Node(usize),
    /// An index into [`SourceFile::edges`].
    Edge(usize),
}

impl SourceFile {
    /// Every comment in the file, in source order.
    ///
    /// Used to prove a round trip preserves all of them.
    #[must_use]
    pub fn all_comments(&self) -> Vec<&Comment> {
        let mut found: Vec<&Comment> = Vec::new();
        found.extend(self.version_comments.leading.iter());
        found.extend(self.version_comments.trailing.iter());
        for link in &self.links {
            found.extend(link.comments.leading.iter());
            found.extend(link.comments.trailing.iter());
        }
        for entry in &self.order {
            match *entry {
                DeclarationRef::Schema(index) => {
                    let schema = &self.schemas[index];
                    found.extend(schema.comments.leading.iter());
                    found.extend(schema.comments.trailing.iter());
                    for field in &schema.fields {
                        found.extend(field.comments.leading.iter());
                        found.extend(field.comments.trailing.iter());
                    }
                    found.extend(schema.block_comments.iter());
                }
                DeclarationRef::Node(index) => {
                    collect_record(&mut found, &self.nodes[index].record);
                }
                DeclarationRef::Edge(index) => {
                    collect_record(&mut found, &self.edges[index].record);
                }
            }
        }
        found.extend(self.trailing_comments.iter());
        found
    }
}

fn collect_record<'a>(found: &mut Vec<&'a Comment>, record: &'a RecordBody) {
    found.extend(record.comments.leading.iter());
    found.extend(record.comments.trailing.iter());
    for property in &record.properties {
        found.extend(property.comments.leading.iter());
        found.extend(property.comments.trailing.iter());
    }
    for contribution in &record.contributions {
        found.extend(contribution.comments.leading.iter());
        found.extend(contribution.comments.trailing.iter());
        for evidence in &contribution.evidence {
            found.extend(evidence.comments.leading.iter());
            found.extend(evidence.comments.trailing.iter());
            for field in &evidence.fields {
                found.extend(field.comments.leading.iter());
                found.extend(field.comments.trailing.iter());
            }
            found.extend(evidence.block_comments.iter());
        }
        found.extend(contribution.block_comments.iter());
    }
    found.extend(record.block_comments.iter());
}

/// A link declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkDeclaration {
    /// The canonical locator, which is the link's identity.
    pub source: Spanned<String>,
    /// The optional alias.
    pub alias: Option<Spanned<String>>,
    /// Attached comments.
    pub comments: Comments,
}

/// A schema declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaDeclaration {
    /// The schema name, which is also the label its records carry.
    pub name: Spanned<String>,
    /// The endpoint constraint, when this schema describes an edge.
    pub endpoints: Option<EndpointConstraint>,
    /// Fields, in source order.
    pub fields: Vec<SchemaField>,
    /// Attached comments.
    pub comments: Comments,
    /// Own-line comments left at the end of the field block.
    pub block_comments: Vec<Comment>,
}

/// The schemas an edge's endpoints must carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointConstraint {
    /// The schema the source record must carry.
    pub source: Spanned<String>,
    /// The schema the target record must carry.
    pub target: Spanned<String>,
}

/// One typed field of a schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaField {
    /// The field key.
    pub key: Spanned<String>,
    /// Whether a record may omit it.
    pub optional: bool,
    /// The declared type.
    pub field_type: Spanned<FieldType>,
    /// Attached comments.
    pub comments: Comments,
}

/// The body every record declaration shares.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordBody {
    /// Properties, in source order.
    pub properties: Vec<Property>,
    /// Contribution blocks, in source order.
    pub contributions: Vec<ContributionBlock>,
    /// Attached comments.
    pub comments: Comments,
    /// Own-line comments left at the end of the record block.
    pub block_comments: Vec<Comment>,
}

/// A node declaration.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDeclaration {
    /// The declaration name.
    pub name: Spanned<String>,
    /// One or more schema names, each of which is also a label.
    pub schemas: Vec<Spanned<String>>,
    /// Properties and contributions.
    pub record: RecordBody,
}

/// An edge declaration.
///
/// An edge carries no declaration name, because nothing references one: an endpoint
/// names a node.
#[derive(Clone, Debug, PartialEq)]
pub struct EdgeDeclaration {
    /// Where the relation starts.
    pub source: Endpoint,
    /// Where the relation ends.
    pub target: Endpoint,
    /// The single relation type, which is also the edge's schema name.
    pub relation: Spanned<String>,
    /// Properties and contributions.
    pub record: RecordBody,
}

/// One producer's contribution to a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionBlock {
    /// Who produced it.
    pub owner: OwnerDeclaration,
    /// The source unit it derives from, when stated.
    pub unit: Option<Spanned<String>>,
    /// Evidence blocks, in source order.
    pub evidence: Vec<EvidenceBlock>,
    /// Attached comments.
    pub comments: Comments,
    /// Own-line comments left at the end of the contribution block.
    pub block_comments: Vec<Comment>,
}

/// Who produced a contribution, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerDeclaration {
    /// `analyzer "<name>" "<version>"`
    Analyzer {
        /// The analyzer name.
        name: Spanned<String>,
        /// The analyzer version, which is part of its identity.
        version: Spanned<String>,
    },
    /// `ai "<contract-digest>"`
    Ai {
        /// Digest of the analysis contract the run used.
        contract_digest: Spanned<String>,
    },
    /// `user`
    User {
        /// Where the keyword appeared.
        range: SourceRange,
    },
}

impl OwnerDeclaration {
    /// The keyword this owner is written with.
    #[must_use]
    pub const fn keyword(&self) -> &'static str {
        match self {
            Self::Analyzer { .. } => "analyzer",
            Self::Ai { .. } => "ai",
            Self::User { .. } => "user",
        }
    }

    /// Where the owner was written.
    #[must_use]
    pub const fn range(&self) -> SourceRange {
        match self {
            Self::Analyzer { name, .. } => name.range,
            Self::Ai { contract_digest } => contract_digest.range,
            Self::User { range } => *range,
        }
    }
}

/// Provenance for one contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceBlock {
    /// Fields, in source order.
    pub fields: Vec<EvidenceField>,
    /// Where the block began.
    pub range: SourceRange,
    /// Attached comments.
    pub comments: Comments,
    /// Own-line comments left at the end of the evidence block.
    pub block_comments: Vec<Comment>,
}

/// One key and value inside an evidence block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceField {
    /// The key.
    pub key: Spanned<String>,
    /// The value.
    pub value: Spanned<EvidenceValue>,
    /// Attached comments.
    pub comments: Comments,
}

/// An evidence value as written.
///
/// The grammar admits a quoted string or a bare enumerator with an optional score. Which
/// keys accept which is a semantic rule, so the shape here stays open and
/// [`super::validate`] reports a mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceValue {
    /// A quoted string.
    Text(String),
    /// A bare word, optionally carrying a score, such as `inferred(0.82)`.
    Enumerator {
        /// The word.
        name: String,
        /// The score, as written, when one was supplied.
        score: Option<String>,
    },
}

/// An edge endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A declaration in the same file.
    Local(Spanned<String>),
    /// A declaration in a linked source, named through that link's alias.
    Aliased {
        /// The link alias.
        alias: Spanned<String>,
        /// The declaration name in that source.
        name: Spanned<String>,
    },
    /// A declaration in a linked source, named by canonical locator.
    ///
    /// This is the aliasless form the language contract defines.
    Locator {
        /// The canonical locator.
        locator: Spanned<String>,
        /// The declaration name in that source.
        name: Spanned<String>,
    },
}

/// A property.
#[derive(Clone, Debug, PartialEq)]
pub struct Property {
    /// The key.
    pub key: Spanned<String>,
    /// The value.
    pub value: Spanned<Value>,
    /// Attached comments.
    pub comments: Comments,
}

/// A property value as written.
///
/// Numbers and timestamps keep their source text, because a range violation or a
/// malformed timestamp is a semantic diagnostic rather than a syntax error, and
/// converting here would lose the text a diagnostic should quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `true` or `false`.
    Boolean(bool),
    /// An integer literal, as written.
    Integer(String),
    /// A float literal, as written.
    Float(String),
    /// A string literal, unescaped.
    String(String),
    /// A `bytes` literal, decoded, with its original digits.
    Bytes {
        /// The decoded bytes.
        decoded: Vec<u8>,
        /// The digits as written, so canonical output can normalize their case.
        digits: String,
    },
    /// A `datetime` literal, as written.
    DateTime(String),
    /// A list of scalars, which does not nest.
    List(Vec<Spanned<Value>>),
}

impl Value {
    /// The name of this value's kind, for diagnostics.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Boolean(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Bytes { .. } => "bytes",
            Self::DateTime(_) => "datetime",
            Self::List(_) => "list",
        }
    }
}
