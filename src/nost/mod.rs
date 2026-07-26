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

pub mod format;
pub mod lexer;
pub mod parser;
pub mod validate;

use crate::diagnostic::{Diagnostic, DiagnosticCode, Severity};
use crate::evidence::SourceRange;
use crate::text::NonEmptyText;
use std::fmt;

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

/// A parsed `.nost` file.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceFile {
    /// The declared language version.
    pub version: Spanned<u32>,
    /// Comments attached to the version header.
    pub version_comments: Comments,
    /// Link declarations, in source order.
    pub links: Vec<LinkDeclaration>,
    /// Module declarations, in source order.
    pub modules: Vec<ModuleDeclaration>,
    /// Own-line comments after the last declaration.
    pub trailing_comments: Vec<Comment>,
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
        for module in &self.modules {
            found.extend(module.comments.leading.iter());
            found.extend(module.comments.trailing.iter());
            for node in &module.nodes {
                found.extend(node.comments.leading.iter());
                found.extend(node.comments.trailing.iter());
                for property in &node.properties {
                    found.extend(property.comments.leading.iter());
                    found.extend(property.comments.trailing.iter());
                }
                found.extend(node.block_comments.iter());
            }
            for edge in &module.edges {
                found.extend(edge.comments.leading.iter());
                found.extend(edge.comments.trailing.iter());
                for property in &edge.properties {
                    found.extend(property.comments.leading.iter());
                    found.extend(property.comments.trailing.iter());
                }
                found.extend(edge.block_comments.iter());
            }
            found.extend(module.block_comments.iter());
        }
        found.extend(self.trailing_comments.iter());
        found
    }
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

/// A module declaration.
#[derive(Clone, Debug, PartialEq)]
pub struct ModuleDeclaration {
    /// The declaration name.
    pub name: Spanned<String>,
    /// The opaque record identifier.
    pub id: Spanned<String>,
    /// The optional source locator.
    pub source: Option<Spanned<String>>,
    /// Node declarations, in source order.
    pub nodes: Vec<NodeDeclaration>,
    /// Edge declarations, in source order.
    pub edges: Vec<EdgeDeclaration>,
    /// Attached comments.
    pub comments: Comments,
    /// Own-line comments left at the end of the block.
    pub block_comments: Vec<Comment>,
}

/// A node declaration.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDeclaration {
    /// The declaration name.
    pub name: Spanned<String>,
    /// The opaque record identifier.
    pub id: Spanned<String>,
    /// One or more labels.
    pub labels: Vec<Spanned<String>>,
    /// Properties, in source order.
    pub properties: Vec<Property>,
    /// Attached comments.
    pub comments: Comments,
    /// Own-line comments left at the end of the property block.
    pub block_comments: Vec<Comment>,
}

/// An edge declaration.
#[derive(Clone, Debug, PartialEq)]
pub struct EdgeDeclaration {
    /// The declaration name.
    pub name: Spanned<String>,
    /// The opaque record identifier.
    pub id: Spanned<String>,
    /// The single relation type.
    pub relation: Spanned<String>,
    /// Where the relation starts.
    pub source: Endpoint,
    /// Where the relation ends.
    pub target: Endpoint,
    /// Properties, in source order.
    pub properties: Vec<Property>,
    /// Attached comments.
    pub comments: Comments,
    /// Own-line comments left at the end of the property block.
    pub block_comments: Vec<Comment>,
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
