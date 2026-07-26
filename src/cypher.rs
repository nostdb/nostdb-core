//! The openCypher subset parser.
//!
//! The subset is a closed list, published in the query contract in `nostdb-spec`.
//! Anything outside it is refused with [`DiagnosticCode::CypherUnsupported`] and a source
//! range, and nothing executes.
//!
//! # Refusal is structural, not a check that could be forgotten
//!
//! There is no code path that parses an unsupported construct into something
//! approximately equivalent. A construct outside the subset produces a
//! [`QueryError`] and no query plan at all, so a caller cannot receive a result that
//! silently approximated a clause.
//!
//! # What this parses
//!
//! The whole published subset: `MATCH`, `OPTIONAL MATCH`, `WHERE`, `WITH`, `UNWIND`,
//! `RETURN`, `DISTINCT`, `ORDER BY`, `SKIP`, `LIMIT`, `UNION`, parameters, inline property
//! maps, aggregation, `CALL` with `YIELD`, and the write clauses `CREATE`, `MERGE`, `SET`,
//! `REMOVE`, `DELETE`, and `DETACH DELETE`.
//!
//! # Where a rule lives
//!
//! A rule this parser can decide from the query text alone is decided here. A rule needing
//! the graph, such as whether a variable is bound or whether a deleted node still has a
//! relationship, is decided in [`crate::execute`]. The split is not aesthetic: a parser
//! that guessed at a binding would have to guess wrong sometimes.

use crate::diagnostic::{Diagnostic, DiagnosticCode, Severity};
use crate::evidence::{SourcePosition, SourceRange};
use crate::text::NonEmptyText;
use std::fmt;

/// Why a query was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryError {
    /// Which refusal this is.
    pub code: DiagnosticCode,
    /// What was wrong.
    pub message: String,
    /// Where it was wrong.
    pub range: SourceRange,
}

impl QueryError {
    /// A refusal with an explicit code and position.
    #[must_use]
    pub fn at(code: DiagnosticCode, message: impl Into<String>, range: SourceRange) -> Self {
        Self {
            code,
            message: message.into(),
            range,
        }
    }

    fn unsupported(message: impl Into<String>, range: SourceRange) -> Self {
        Self::at(DiagnosticCode::CypherUnsupported, message, range)
    }

    fn semantic(message: impl Into<String>, range: SourceRange) -> Self {
        Self::at(DiagnosticCode::CypherSemanticError, message, range)
    }

    /// Renders this refusal as a diagnostic.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic {
        Diagnostic {
            code: self.code,
            severity: Severity::Error,
            message: NonEmptyText::new(self.message.clone())
                .unwrap_or_else(|_| NonEmptyText::literal("the query was refused")),
            source: None,
            range: Some(self.range),
            details: Vec::new(),
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}: {}: {}",
            self.range.start().line,
            self.range.start().column,
            self.code,
            self.message
        )
    }
}

impl std::error::Error for QueryError {}

/// A word the subset recognizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Word {
    /// `MATCH`
    Match,
    /// `OPTIONAL`
    Optional,
    /// `WHERE`
    Where,
    /// `WITH`
    With,
    /// `RETURN`
    Return,
    /// `DISTINCT`
    Distinct,
    /// `ORDER`
    Order,
    /// `BY`
    By,
    /// `ASC`
    Asc,
    /// `DESC`
    Desc,
    /// `SKIP`
    Skip,
    /// `LIMIT`
    Limit,
    /// `UNWIND`
    Unwind,
    /// `UNION`
    Union,
    /// `ALL`
    All,
    /// `AS`
    As,
    /// `AND`
    And,
    /// `OR`
    Or,
    /// `NOT`
    Not,
    /// `IN`
    In,
    /// `TRUE`
    True,
    /// `FALSE`
    False,
    /// `NULL`
    Null,
    /// `CALL`
    Call,
    /// `YIELD`
    Yield,
    /// `ON`, which only ever introduces a construct outside the subset.
    On,
    /// A write clause keyword.
    Write(WriteWord),
    /// A word the subset excludes outright.
    Excluded(ExcludedWord),
}

/// A write clause keyword.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteWord {
    /// `CREATE`
    Create,
    /// `MERGE`
    Merge,
    /// `SET`
    Set,
    /// `REMOVE`
    Remove,
    /// `DELETE`
    Delete,
    /// `DETACH`
    Detach,
}

/// A keyword the subset excludes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExcludedWord {
    /// `FOREACH`
    Foreach,
    /// `LOAD`
    Load,
    /// `CSV`
    Csv,
    /// `CASE`
    Case,
    /// `WHEN`
    When,
    /// `THEN`
    Then,
    /// `ELSE`
    Else,
    /// `END`
    End,
    /// `EXISTS`
    Exists,
    /// `USE`
    Use,
    /// `INDEX`
    Index,
    /// `CONSTRAINT`
    Constraint,
}

impl ExcludedWord {
    const fn spelling(self) -> &'static str {
        match self {
            Self::Foreach => "FOREACH",
            Self::Load => "LOAD",
            Self::Csv => "CSV",
            Self::Case => "CASE",
            Self::When => "WHEN",
            Self::Then => "THEN",
            Self::Else => "ELSE",
            Self::End => "END",
            Self::Exists => "EXISTS",
            Self::Use => "USE",
            Self::Index => "INDEX",
            Self::Constraint => "CONSTRAINT",
        }
    }
}

fn word_of(text: &str) -> Option<Word> {
    let upper = text.to_ascii_uppercase();
    Some(match upper.as_str() {
        "MATCH" => Word::Match,
        "OPTIONAL" => Word::Optional,
        "WHERE" => Word::Where,
        "WITH" => Word::With,
        "RETURN" => Word::Return,
        "DISTINCT" => Word::Distinct,
        "ORDER" => Word::Order,
        "BY" => Word::By,
        "ASC" | "ASCENDING" => Word::Asc,
        "DESC" | "DESCENDING" => Word::Desc,
        "SKIP" => Word::Skip,
        "LIMIT" => Word::Limit,
        "UNWIND" => Word::Unwind,
        "UNION" => Word::Union,
        "ALL" => Word::All,
        "AS" => Word::As,
        "AND" => Word::And,
        "OR" => Word::Or,
        "NOT" => Word::Not,
        "IN" => Word::In,
        "TRUE" => Word::True,
        "FALSE" => Word::False,
        "NULL" => Word::Null,
        "CALL" => Word::Call,
        "YIELD" => Word::Yield,
        "ON" => Word::On,
        "CREATE" => Word::Write(WriteWord::Create),
        "MERGE" => Word::Write(WriteWord::Merge),
        "SET" => Word::Write(WriteWord::Set),
        "REMOVE" => Word::Write(WriteWord::Remove),
        "DELETE" => Word::Write(WriteWord::Delete),
        "DETACH" => Word::Write(WriteWord::Detach),
        "FOREACH" => Word::Excluded(ExcludedWord::Foreach),
        "LOAD" => Word::Excluded(ExcludedWord::Load),
        "CSV" => Word::Excluded(ExcludedWord::Csv),
        "CASE" => Word::Excluded(ExcludedWord::Case),
        "WHEN" => Word::Excluded(ExcludedWord::When),
        "THEN" => Word::Excluded(ExcludedWord::Then),
        "ELSE" => Word::Excluded(ExcludedWord::Else),
        "END" => Word::Excluded(ExcludedWord::End),
        "EXISTS" => Word::Excluded(ExcludedWord::Exists),
        "USE" => Word::Excluded(ExcludedWord::Use),
        "INDEX" => Word::Excluded(ExcludedWord::Index),
        "CONSTRAINT" => Word::Excluded(ExcludedWord::Constraint),
        _ => return None,
    })
}

/// Functions the subset excludes, because they imply unbounded or specialised traversal.
const EXCLUDED_FUNCTIONS: [&str; 2] = ["shortestpath", "allshortestpaths"];

/// The aggregate functions the query contract declares, in section 9.1.
///
/// This list lives here rather than in the executor because both need it: the parser
/// enforces where an aggregate may appear, and the executor groups by what is left.
pub const AGGREGATE_FUNCTIONS: [&str; 6] = ["count", "sum", "avg", "min", "max", "collect"];

/// Reports whether a function name is an aggregate, ignoring case as Cypher does.
#[must_use]
pub fn is_aggregate(name: &str) -> bool {
    AGGREGATE_FUNCTIONS.contains(&name.to_ascii_lowercase().as_str())
}

/// How `count(*)` records its argument.
///
/// A star is not a variable name the lexer can produce, so this cannot collide with
/// anything a caller wrote.
pub const STAR_ARGUMENT: &str = "*";

/// A lexical token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Word(Word),
    Identifier,
    Integer,
    Float,
    Text,
    Parameter,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    LeftBrace,
    RightBrace,
    Comma,
    Dot,
    DotDot,
    Colon,
    Pipe,
    Star,
    Plus,
    Minus,
    Slash,
    Percent,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    ArrowRight,
    ArrowLeft,
    Eof,
}

#[derive(Clone, Debug)]
struct Token {
    kind: Kind,
    text: String,
    range: SourceRange,
}

struct Scanner<'a> {
    characters: Vec<(usize, char)>,
    source: &'a str,
    index: usize,
    line: u32,
    column: u32,
}

impl<'a> Scanner<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            characters: source.char_indices().collect(),
            source,
            index: 0,
            line: 1,
            column: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        self.characters.get(self.index).map(|&(_, c)| c)
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.characters.get(self.index + ahead).map(|&(_, c)| c)
    }

    fn position(&self) -> SourcePosition {
        SourcePosition {
            line: self.line,
            column: self.column,
            offset: self
                .characters
                .get(self.index)
                .map_or(self.source.len(), |&(offset, _)| offset) as u64,
        }
    }

    fn advance(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.index += 1;
        if character == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(character)
    }

    fn range(&self, start: SourcePosition) -> SourceRange {
        SourceRange::new(start, self.position()).unwrap_or(SourceRange::ORIGIN)
    }
}

fn tokenize(source: &str) -> Result<Vec<Token>, QueryError> {
    let mut scanner = Scanner::new(source);
    let mut tokens = Vec::new();

    loop {
        while scanner.peek().is_some_and(char::is_whitespace) {
            scanner.advance();
        }
        // A line comment, which openCypher writes with two slashes.
        if scanner.peek() == Some('/') && scanner.peek_at(1) == Some('/') {
            while scanner.peek().is_some_and(|c| c != '\n') {
                scanner.advance();
            }
            continue;
        }

        let start = scanner.position();
        let Some(character) = scanner.peek() else {
            tokens.push(Token {
                kind: Kind::Eof,
                text: String::new(),
                range: scanner.range(start),
            });
            return Ok(tokens);
        };

        let simple = |scanner: &mut Scanner<'_>, kind: Kind, length: usize| {
            for _ in 0..length {
                scanner.advance();
            }
            kind
        };

        let kind = match character {
            '(' => simple(&mut scanner, Kind::LeftParen, 1),
            ')' => simple(&mut scanner, Kind::RightParen, 1),
            '[' => simple(&mut scanner, Kind::LeftBracket, 1),
            ']' => simple(&mut scanner, Kind::RightBracket, 1),
            '{' => simple(&mut scanner, Kind::LeftBrace, 1),
            '}' => simple(&mut scanner, Kind::RightBrace, 1),
            ',' => simple(&mut scanner, Kind::Comma, 1),
            ':' => simple(&mut scanner, Kind::Colon, 1),
            '|' => simple(&mut scanner, Kind::Pipe, 1),
            '*' => simple(&mut scanner, Kind::Star, 1),
            '+' => simple(&mut scanner, Kind::Plus, 1),
            '/' => simple(&mut scanner, Kind::Slash, 1),
            '%' => simple(&mut scanner, Kind::Percent, 1),
            '=' => simple(&mut scanner, Kind::Equal, 1),
            '.' if scanner.peek_at(1) == Some('.') => simple(&mut scanner, Kind::DotDot, 2),
            '.' => simple(&mut scanner, Kind::Dot, 1),
            '-' if scanner.peek_at(1) == Some('>') => simple(&mut scanner, Kind::ArrowRight, 2),
            '-' => simple(&mut scanner, Kind::Minus, 1),
            '<' if scanner.peek_at(1) == Some('-') => simple(&mut scanner, Kind::ArrowLeft, 2),
            '<' if scanner.peek_at(1) == Some('>') => simple(&mut scanner, Kind::NotEqual, 2),
            '<' if scanner.peek_at(1) == Some('=') => simple(&mut scanner, Kind::LessEqual, 2),
            '<' => simple(&mut scanner, Kind::Less, 1),
            '>' if scanner.peek_at(1) == Some('=') => simple(&mut scanner, Kind::GreaterEqual, 2),
            '>' => simple(&mut scanner, Kind::Greater, 1),
            '$' => {
                scanner.advance();
                let mut name = String::new();
                while scanner
                    .peek()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    name.push(scanner.advance().unwrap_or('_'));
                }
                if name.is_empty() {
                    return Err(QueryError::semantic(
                        "a parameter needs a name after `$`",
                        scanner.range(start),
                    ));
                }
                tokens.push(Token {
                    kind: Kind::Parameter,
                    text: name,
                    range: scanner.range(start),
                });
                continue;
            }
            '"' | '\'' => {
                let quote = character;
                scanner.advance();
                let mut text = String::new();
                loop {
                    let Some(next) = scanner.advance() else {
                        return Err(QueryError::semantic(
                            "an unterminated string literal",
                            scanner.range(start),
                        ));
                    };
                    if next == quote {
                        break;
                    }
                    if next == '\\' {
                        match scanner.advance() {
                            Some('n') => text.push('\n'),
                            Some('t') => text.push('\t'),
                            Some('r') => text.push('\r'),
                            Some(other) => text.push(other),
                            None => {
                                return Err(QueryError::semantic(
                                    "an unterminated escape sequence",
                                    scanner.range(start),
                                ));
                            }
                        }
                        continue;
                    }
                    text.push(next);
                }
                tokens.push(Token {
                    kind: Kind::Text,
                    text,
                    range: scanner.range(start),
                });
                continue;
            }
            c if c.is_ascii_digit() => {
                let mut text = String::new();
                let mut float = false;
                while scanner.peek().is_some_and(|c| c.is_ascii_digit()) {
                    text.push(scanner.advance().unwrap_or('0'));
                }
                // A dot followed by a digit is a fraction; `..` is a range operator.
                if scanner.peek() == Some('.')
                    && scanner.peek_at(1).is_some_and(|c| c.is_ascii_digit())
                {
                    float = true;
                    text.push(scanner.advance().unwrap_or('.'));
                    while scanner.peek().is_some_and(|c| c.is_ascii_digit()) {
                        text.push(scanner.advance().unwrap_or('0'));
                    }
                }
                tokens.push(Token {
                    kind: if float { Kind::Float } else { Kind::Integer },
                    text,
                    range: scanner.range(start),
                });
                continue;
            }
            c if c.is_alphabetic() || c == '_' => {
                let mut text = String::new();
                while scanner
                    .peek()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    text.push(scanner.advance().unwrap_or('_'));
                }
                let kind = word_of(&text).map_or(Kind::Identifier, Kind::Word);
                tokens.push(Token {
                    kind,
                    text,
                    range: scanner.range(start),
                });
                continue;
            }
            other => {
                return Err(QueryError::semantic(
                    format!("unexpected character {other:?}"),
                    scanner.range(start),
                ));
            }
        };

        tokens.push(Token {
            kind,
            text: character.to_string(),
            range: scanner.range(start),
        });
    }
}

/// A parsed query.
#[derive(Clone, Debug, PartialEq)]
pub struct Query {
    /// One or more parts, combined by `UNION`.
    pub parts: Vec<QueryPart>,
    /// Whether each `UNION` kept duplicates.
    pub union_all: Vec<bool>,
}

impl Query {
    /// Reports whether this query modifies the database.
    ///
    /// A caller holding a read-only graph therefore cannot be surprised by a write: it
    /// can ask before executing, and it has no `&mut Graph` to execute one with anyway.
    #[must_use]
    pub fn is_writing(&self) -> bool {
        self.parts.iter().any(QueryPart::is_writing)
    }
}

/// One `UNION` operand.
#[derive(Clone, Debug, PartialEq)]
pub struct QueryPart {
    /// Clauses, in the order they were written and the order they run in.
    pub clauses: Vec<Clause>,
    /// The projection this part returns, when it has a `RETURN`.
    ///
    /// A part containing a write clause, or ending in a `CALL`, may have none.
    pub result: Option<Projection>,
}

impl QueryPart {
    /// Reports whether this part modifies the database.
    #[must_use]
    pub fn is_writing(&self) -> bool {
        self.clauses.iter().any(Clause::is_writing)
    }
}

/// One clause.
#[derive(Clone, Debug, PartialEq)]
pub enum Clause {
    /// `MATCH` or `OPTIONAL MATCH`.
    Match {
        /// Whether unmatched rows survive with `null` bindings.
        optional: bool,
        /// The patterns to match.
        patterns: Vec<Pattern>,
        /// An optional predicate.
        predicate: Option<Expression>,
    },
    /// `WITH`, which opens a new scope.
    With(Projection),
    /// `UNWIND`, which turns a list into rows.
    Unwind {
        /// The list expression.
        list: Expression,
        /// The variable each element binds to.
        variable: String,
    },
    /// `CALL`, optionally with `YIELD`.
    Call(ProcedureCall),
    /// `CREATE`, which creates every unbound node and relationship in its patterns.
    Create {
        /// The patterns to create.
        patterns: Vec<Pattern>,
        /// Where the clause was written, so a refusal can point at it.
        range: SourceRange,
    },
    /// `MERGE`, which matches one pattern or creates it once.
    Merge {
        /// The pattern to match or create.
        pattern: Pattern,
        /// Where the clause was written.
        range: SourceRange,
    },
    /// `SET`, which assigns properties and adds labels.
    Set {
        /// The assignments, in order.
        items: Vec<SetItem>,
        /// Where the clause was written.
        range: SourceRange,
    },
    /// `REMOVE`, which removes properties and labels.
    Remove {
        /// The targets, in order.
        items: Vec<RemoveItem>,
        /// Where the clause was written.
        range: SourceRange,
    },
    /// `DELETE` or `DETACH DELETE`.
    Delete {
        /// Whether incident relationships are deleted along with a node.
        detach: bool,
        /// What to delete.
        targets: Vec<Expression>,
        /// Where the clause was written.
        range: SourceRange,
    },
}

impl Clause {
    /// Reports whether this clause modifies the database.
    ///
    /// `CALL` counts as reading. The only procedure that would change anything is
    /// capability-gated and refused by this build, and a procedure that writes would have
    /// to declare it, per query contract section 12.
    #[must_use]
    pub const fn is_writing(&self) -> bool {
        matches!(
            self,
            Self::Create { .. }
                | Self::Merge { .. }
                | Self::Set { .. }
                | Self::Remove { .. }
                | Self::Delete { .. }
        )
    }
}

/// A procedure invocation.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcedureCall {
    /// The dotted procedure name.
    pub name: String,
    /// Its arguments.
    pub arguments: Vec<Expression>,
    /// The columns `YIELD` kept, empty when there was no `YIELD`.
    pub yields: Vec<YieldItem>,
    /// Where the call was written, so a refusal can point at it.
    pub range: SourceRange,
}

/// One `YIELD` item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YieldItem {
    /// The procedure column to keep.
    pub column: String,
    /// The name to bind it to, when `AS` renamed it.
    pub alias: Option<String>,
}

impl YieldItem {
    /// The name this item binds.
    #[must_use]
    pub fn bound_name(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.column)
    }
}

/// One `SET` assignment.
#[derive(Clone, Debug, PartialEq)]
pub enum SetItem {
    /// `SET n.key = expression`, where a `null` value removes the property.
    Property {
        /// The record being modified.
        variable: String,
        /// The property key.
        key: String,
        /// The value to assign.
        value: Expression,
    },
    /// `SET n:Label`.
    Label {
        /// The record being modified.
        variable: String,
        /// The label to add.
        label: String,
    },
}

/// One `REMOVE` target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoveItem {
    /// `REMOVE n.key`.
    Property {
        /// The record being modified.
        variable: String,
        /// The property key.
        key: String,
    },
    /// `REMOVE n:Label`.
    Label {
        /// The record being modified.
        variable: String,
        /// The label to remove.
        label: String,
    },
}

/// A projection, used by both `WITH` and `RETURN`.
#[derive(Clone, Debug, PartialEq)]
pub struct Projection {
    /// Whether duplicate rows are removed.
    pub distinct: bool,
    /// The projected items.
    pub items: Vec<ProjectionItem>,
    /// An optional predicate, valid on `WITH` only.
    pub predicate: Option<Expression>,
    /// Sort keys.
    pub order_by: Vec<SortItem>,
    /// Rows to skip.
    pub skip: Option<Expression>,
    /// Maximum rows to return.
    pub limit: Option<Expression>,
}

/// One projected item.
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectionItem {
    /// What is projected.
    pub expression: Expression,
    /// The column name, when one was given.
    pub alias: Option<String>,
}

/// One sort key.
#[derive(Clone, Debug, PartialEq)]
pub struct SortItem {
    /// What to sort by.
    pub expression: Expression,
    /// Whether the order is descending.
    pub descending: bool,
}

/// A graph pattern.
#[derive(Clone, Debug, PartialEq)]
pub struct Pattern {
    /// The path variable, when the pattern was named.
    pub path_variable: Option<String>,
    /// The first node.
    pub start: NodePattern,
    /// Relationship and node pairs following it.
    pub steps: Vec<(RelationshipPattern, NodePattern)>,
}

/// A node pattern.
#[derive(Clone, Debug, PartialEq)]
pub struct NodePattern {
    /// The bound variable, when named.
    pub variable: Option<String>,
    /// Required labels.
    pub labels: Vec<String>,
    /// An inline property map: a filter when reading, values when writing.
    pub properties: Vec<(String, Expression)>,
}

/// Which way a relationship points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// `-[...]->`
    Outgoing,
    /// `<-[...]-`
    Incoming,
    /// `-[...]-`
    Either,
}

/// A relationship pattern.
#[derive(Clone, Debug, PartialEq)]
pub struct RelationshipPattern {
    /// The bound variable, when named.
    pub variable: Option<String>,
    /// Acceptable relation types; empty means any.
    pub types: Vec<String>,
    /// Which way it points.
    pub direction: Direction,
    /// The bounded length range, when the pattern is variable-length.
    pub length: Option<LengthRange>,
    /// An inline property map: a filter when reading, values when writing.
    pub properties: Vec<(String, Expression)>,
}

/// A bounded variable-length range.
///
/// Both bounds are required. See the query contract, section 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthRange {
    /// Minimum hops.
    pub minimum: u32,
    /// Maximum hops.
    pub maximum: u32,
}

/// An expression.
#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    /// An integer literal.
    Integer(i64),
    /// A float literal, as written.
    Float(String),
    /// A string literal.
    Text(String),
    /// `true` or `false`.
    Boolean(bool),
    /// `null`.
    Null,
    /// A parameter, written `$name`.
    Parameter(String),
    /// A bound variable.
    Variable(String),
    /// A property access, such as `n.name`.
    Property {
        /// The variable being accessed.
        variable: String,
        /// The property key.
        key: String,
    },
    /// A list literal.
    List(Vec<Expression>),
    /// A function call, such as `count(n)` or `nostdb.source(n)`.
    Call {
        /// The dotted function name.
        name: String,
        /// Its arguments.
        arguments: Vec<Expression>,
    },
    /// A unary `NOT`.
    Not(Box<Expression>),
    /// A binary operation.
    Binary {
        /// The operator.
        operator: BinaryOperator,
        /// Left operand.
        left: Box<Expression>,
        /// Right operand.
        right: Box<Expression>,
    },
}

impl Expression {
    /// Reports whether this expression contains an aggregate anywhere inside it.
    #[must_use]
    pub fn contains_aggregate(&self) -> bool {
        match self {
            Self::Call { name, arguments } => {
                is_aggregate(name) || arguments.iter().any(Self::contains_aggregate)
            }
            Self::List(items) => items.iter().any(Self::contains_aggregate),
            Self::Not(inner) => inner.contains_aggregate(),
            Self::Binary { left, right, .. } => {
                left.contains_aggregate() || right.contains_aggregate()
            }
            Self::Integer(_)
            | Self::Float(_)
            | Self::Text(_)
            | Self::Boolean(_)
            | Self::Null
            | Self::Parameter(_)
            | Self::Variable(_)
            | Self::Property { .. } => false,
        }
    }

    /// Renders this expression back to query text.
    ///
    /// This is what an unaliased column is named, which is how openCypher names one. The
    /// rendering does not have to reproduce the original spacing; it has to be something a
    /// caller can read in a column header and match to what they wrote.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Integer(value) => value.to_string(),
            Self::Float(text) => text.clone(),
            Self::Text(value) => format!("{value:?}"),
            Self::Boolean(value) => value.to_string(),
            Self::Null => "null".to_owned(),
            Self::Parameter(name) => format!("${name}"),
            Self::Variable(name) => name.clone(),
            Self::Property { variable, key } => format!("{variable}.{key}"),
            Self::List(items) => {
                let rendered: Vec<String> = items.iter().map(Self::render).collect();
                format!("[{}]", rendered.join(", "))
            }
            Self::Call { name, arguments } => {
                let rendered: Vec<String> = arguments.iter().map(Self::render).collect();
                format!("{name}({})", rendered.join(", "))
            }
            Self::Not(inner) => format!("NOT {}", inner.render()),
            Self::Binary {
                operator,
                left,
                right,
            } => format!(
                "{} {} {}",
                left.render(),
                operator.spelling(),
                right.render()
            ),
        }
    }
}

/// A binary operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOperator {
    /// `AND`
    And,
    /// `OR`
    Or,
    /// `=`
    Equal,
    /// `<>`
    NotEqual,
    /// `<`
    Less,
    /// `<=`
    LessEqual,
    /// `>`
    Greater,
    /// `>=`
    GreaterEqual,
    /// `IN`
    In,
    /// `+`
    Add,
    /// `-`
    Subtract,
    /// `*`
    Multiply,
    /// `/`
    Divide,
    /// `%`
    Modulo,
}

impl BinaryOperator {
    /// How this operator is written.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            Self::And => "AND",
            Self::Or => "OR",
            Self::Equal => "=",
            Self::NotEqual => "<>",
            Self::Less => "<",
            Self::LessEqual => "<=",
            Self::Greater => ">",
            Self::GreaterEqual => ">=",
            Self::In => "IN",
            Self::Add => "+",
            Self::Subtract => "-",
            Self::Multiply => "*",
            Self::Divide => "/",
            Self::Modulo => "%",
        }
    }
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
}

impl Parser {
    fn current(&self) -> &Token {
        self.tokens
            .get(self.index)
            .or_else(|| self.tokens.last())
            .unwrap_or(&EOF)
    }

    fn kind(&self) -> Kind {
        self.current().kind
    }

    fn range(&self) -> SourceRange {
        self.current().range
    }

    fn at(&self, word: Word) -> bool {
        self.kind() == Kind::Word(word)
    }

    fn eat(&mut self, kind: Kind) -> bool {
        if self.kind() == kind {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn eat_word(&mut self, word: Word) -> bool {
        self.eat(Kind::Word(word))
    }

    fn expect(&mut self, kind: Kind, what: &str) -> Result<Token, QueryError> {
        if self.kind() == kind {
            let token = self.current().clone();
            self.index += 1;
            Ok(token)
        } else {
            Err(QueryError::semantic(
                format!("expected {what}"),
                self.range(),
            ))
        }
    }

    fn expect_name(&mut self, what: &str) -> Result<String, QueryError> {
        // A non-reserved keyword is a valid name in openCypher, but keeping names to
        // identifiers avoids ambiguity this subset gains nothing from.
        if self.kind() == Kind::Identifier {
            let token = self.current().clone();
            self.index += 1;
            return Ok(token.text);
        }
        Err(QueryError::semantic(
            format!("expected {what}"),
            self.range(),
        ))
    }
}

static EOF: Token = Token {
    kind: Kind::Eof,
    text: String::new(),
    range: SourceRange::ORIGIN,
};

/// Parses a query in the declared subset.
///
/// # Errors
///
/// Returns [`DiagnosticCode::CypherUnsupported`] for a construct outside the subset, and
/// [`DiagnosticCode::CypherSemanticError`] for a query inside the subset that is
/// malformed. Either way nothing is produced, so an unsupported construct cannot run
/// under a guessed alternative.
pub fn parse(source: &str) -> Result<Query, QueryError> {
    let tokens = tokenize(source)?;

    // An excluded keyword or function anywhere refuses the whole query. Refusing before
    // parsing means there is no path on which an excluded construct is partly interpreted.
    //
    // The function scan belongs here rather than where calls are parsed, because an
    // excluded function can appear in a pattern position, as `shortestPath((a)-->(b))`
    // does, which the expression parser never reaches.
    for (index, token) in tokens.iter().enumerate() {
        if let Kind::Word(Word::Excluded(word)) = token.kind {
            return Err(QueryError::unsupported(
                format!("`{}` is outside the declared query subset", word.spelling()),
                token.range,
            ));
        }
        if token.kind == Kind::Identifier
            && EXCLUDED_FUNCTIONS.contains(&token.text.to_ascii_lowercase().as_str())
            && tokens.get(index + 1).map(|next| next.kind) == Some(Kind::LeftParen)
        {
            return Err(QueryError::unsupported(
                format!("`{}` is outside the declared query subset", token.text),
                token.range,
            ));
        }
    }

    let mut parser = Parser { tokens, index: 0 };
    let mut parts = vec![parse_part(&mut parser)?];
    let mut union_all = Vec::new();

    while parser.at(Word::Union) {
        parser.index += 1;
        union_all.push(parser.eat_word(Word::All));
        parts.push(parse_part(&mut parser)?);
    }

    if parser.kind() != Kind::Eof {
        return Err(QueryError::semantic(
            "expected the end of the query",
            parser.range(),
        ));
    }

    // A UNION operand that wrote would make the result depend on which operand ran first,
    // so the contract keeps every operand read-only.
    if parts.len() > 1 && parts.iter().any(QueryPart::is_writing) {
        return Err(QueryError::unsupported(
            "every `UNION` operand must be read-only",
            parser.range(),
        ));
    }

    // Every operand must project the same column names, which the contract requires and
    // a caller cannot work around.
    if let Some(expected) = parts.first().and_then(|part| part.result.as_ref()) {
        let expected = column_names(expected);
        for part in parts.iter().skip(1) {
            let found = part.result.as_ref().map(column_names).unwrap_or_default();
            if found != expected {
                return Err(QueryError::semantic(
                    "UNION operands must project the same column names",
                    parser.range(),
                ));
            }
        }
    }

    Ok(Query { parts, union_all })
}

/// The column names a projection produces.
pub(crate) fn column_names(projection: &Projection) -> Vec<String> {
    projection.items.iter().map(column_name).collect()
}

/// The name one projected item produces.
///
/// An unaliased item is named by its own text, which is what openCypher does. An earlier
/// version fell back to the Rust debug rendering of the expression, so a caller who wrote
/// `RETURN toUpper(n.name)` received a column named `Call { name: "toUpper", .. }`.
pub(crate) fn column_name(item: &ProjectionItem) -> String {
    item.alias
        .clone()
        .unwrap_or_else(|| item.expression.render())
}

fn parse_part(parser: &mut Parser) -> Result<QueryPart, QueryError> {
    let mut clauses = Vec::new();

    loop {
        if parser.at(Word::Match) || parser.at(Word::Optional) {
            clauses.push(parse_match(parser)?);
            continue;
        }
        if parser.at(Word::Unwind) {
            parser.index += 1;
            let list = parse_expression(parser)?;
            reject_aggregate(&list, "an `UNWIND` list", parser.range())?;
            if !parser.eat_word(Word::As) {
                return Err(QueryError::semantic(
                    "expected `AS` after an UNWIND list",
                    parser.range(),
                ));
            }
            let variable = parser.expect_name("a variable name")?;
            clauses.push(Clause::Unwind { list, variable });
            continue;
        }
        if parser.at(Word::With) {
            parser.index += 1;
            clauses.push(Clause::With(parse_projection(parser, true)?));
            continue;
        }
        if parser.at(Word::Call) {
            clauses.push(parse_procedure_call(parser)?);
            continue;
        }
        if let Kind::Word(Word::Write(word)) = parser.kind() {
            clauses.push(parse_write(parser, word)?);
            continue;
        }
        break;
    }

    let result = if parser.at(Word::Return) {
        parser.index += 1;
        Some(parse_projection(parser, false)?)
    } else {
        None
    };

    if result.is_none() {
        // A write reports what it did through its own summary, and a `CALL` produces the
        // columns it yields, so either may end a part. A read that projects nothing has
        // asked a question with no answer, which is far more likely a mistake than intent.
        let ends_in_call = matches!(clauses.last(), Some(Clause::Call(_)));
        if !clauses.iter().any(Clause::is_writing) && !ends_in_call {
            return Err(QueryError::semantic(
                "a read-only query part must end with `RETURN`",
                parser.range(),
            ));
        }
    }

    if clauses.is_empty() && result.is_none() {
        return Err(QueryError::semantic("expected a query", parser.range()));
    }

    Ok(QueryPart { clauses, result })
}

fn parse_match(parser: &mut Parser) -> Result<Clause, QueryError> {
    let optional = parser.eat_word(Word::Optional);
    if optional && !parser.at(Word::Match) {
        return Err(QueryError::semantic(
            "expected `MATCH` after `OPTIONAL`",
            parser.range(),
        ));
    }
    parser.index += 1;
    let mut patterns = vec![parse_pattern(parser)?];
    while parser.eat(Kind::Comma) {
        patterns.push(parse_pattern(parser)?);
    }
    let predicate = if parser.eat_word(Word::Where) {
        let where_range = parser.range();
        let predicate = parse_expression(parser)?;
        // The predicate runs before any grouping exists, so an aggregate here has nothing
        // to aggregate over. The contract sends this through `WITH` instead.
        reject_aggregate(
            &predicate,
            "a `WHERE` on `MATCH`; use `WITH` to filter on an aggregate",
            where_range,
        )?;
        Some(predicate)
    } else {
        None
    };
    Ok(Clause::Match {
        optional,
        patterns,
        predicate,
    })
}

fn reject_aggregate(
    expression: &Expression,
    where_it_was: &str,
    range: SourceRange,
) -> Result<(), QueryError> {
    if expression.contains_aggregate() {
        return Err(QueryError::semantic(
            format!("an aggregate is not allowed in {where_it_was}"),
            range,
        ));
    }
    Ok(())
}

fn parse_procedure_call(parser: &mut Parser) -> Result<Clause, QueryError> {
    let range = parser.range();
    parser.index += 1;

    if parser.kind() == Kind::LeftBrace {
        return Err(QueryError::unsupported(
            "a `CALL {}` subquery is outside the declared query subset",
            parser.range(),
        ));
    }

    let mut name = parser.expect_name("a procedure name")?;
    while parser.eat(Kind::Dot) {
        name.push('.');
        name.push_str(&parser.expect_name("a procedure name")?);
    }

    parser.expect(Kind::LeftParen, "`(` after a procedure name")?;
    let mut arguments = Vec::new();
    if parser.kind() != Kind::RightParen {
        loop {
            let argument = parse_expression(parser)?;
            reject_aggregate(&argument, "a procedure argument", range)?;
            arguments.push(argument);
            if !parser.eat(Kind::Comma) {
                break;
            }
        }
    }
    parser.expect(Kind::RightParen, "`)` to close a procedure call")?;

    let mut yields = Vec::new();
    if parser.eat_word(Word::Yield) {
        loop {
            let column = parser.expect_name("a yielded column name")?;
            let alias = if parser.eat_word(Word::As) {
                Some(parser.expect_name("a column name")?)
            } else {
                None
            };
            yields.push(YieldItem { column, alias });
            if !parser.eat(Kind::Comma) {
                break;
            }
        }
    }

    Ok(Clause::Call(ProcedureCall {
        name,
        arguments,
        yields,
        range,
    }))
}

fn parse_write(parser: &mut Parser, word: WriteWord) -> Result<Clause, QueryError> {
    let range = parser.range();
    parser.index += 1;

    match word {
        WriteWord::Create => {
            let mut patterns = vec![parse_write_pattern(parser)?];
            while parser.eat(Kind::Comma) {
                patterns.push(parse_write_pattern(parser)?);
            }
            Ok(Clause::Create { patterns, range })
        }
        WriteWord::Merge => {
            let pattern = parse_write_pattern(parser)?;
            if parser.at(Word::On) {
                return Err(QueryError::unsupported(
                    "`ON CREATE` and `ON MATCH` are outside the declared query subset",
                    parser.range(),
                ));
            }
            Ok(Clause::Merge { pattern, range })
        }
        WriteWord::Set => {
            let mut items = vec![parse_set_item(parser)?];
            while parser.eat(Kind::Comma) {
                items.push(parse_set_item(parser)?);
            }
            Ok(Clause::Set { items, range })
        }
        WriteWord::Remove => {
            let mut items = vec![parse_remove_item(parser)?];
            while parser.eat(Kind::Comma) {
                items.push(parse_remove_item(parser)?);
            }
            Ok(Clause::Remove { items, range })
        }
        WriteWord::Delete => Ok(Clause::Delete {
            detach: false,
            targets: parse_delete_targets(parser)?,
            range,
        }),
        WriteWord::Detach => {
            if !parser.eat(Kind::Word(Word::Write(WriteWord::Delete))) {
                return Err(QueryError::semantic(
                    "expected `DELETE` after `DETACH`",
                    range,
                ));
            }
            Ok(Clause::Delete {
                detach: true,
                targets: parse_delete_targets(parser)?,
                range,
            })
        }
    }
}

fn parse_delete_targets(parser: &mut Parser) -> Result<Vec<Expression>, QueryError> {
    let mut targets = vec![parse_expression(parser)?];
    while parser.eat(Kind::Comma) {
        targets.push(parse_expression(parser)?);
    }
    Ok(targets)
}

/// A pattern in a write clause.
///
/// The refusals here are the rules decidable from the query text alone. A variable-length
/// pattern names no single relationship to create; a named path would bind a path over
/// records the clause is still creating; and an Edge has a source and a target, so an
/// undirected or untyped relationship names nothing storable however the graph looks.
///
/// The remaining model rule, that a created node carries a label, is not here. It depends on
/// whether the variable is already bound, which the parser does not know: `CREATE (a)-[:R]->(b)`
/// after a `MATCH` binding both is legitimate.
fn parse_write_pattern(parser: &mut Parser) -> Result<Pattern, QueryError> {
    let range = parser.range();
    let pattern = parse_pattern(parser)?;

    if pattern.path_variable.is_some() {
        return Err(QueryError::unsupported(
            "a named path in a write clause is outside the declared query subset",
            range,
        ));
    }
    for (relationship, _) in &pattern.steps {
        if relationship.length.is_some() {
            return Err(QueryError::unsupported(
                "a variable-length pattern in a write clause has no single relationship to \
                 create",
                range,
            ));
        }
        if relationship.direction == Direction::Either {
            return Err(QueryError::semantic(
                "a relationship in a write clause must be directed, written `->` or `<-`, \
                 because an Edge has a source and a target",
                range,
            ));
        }
        if relationship.types.len() != 1 {
            return Err(QueryError::semantic(
                "a relationship in a write clause names exactly one relation type",
                range,
            ));
        }
    }
    Ok(pattern)
}

fn parse_set_item(parser: &mut Parser) -> Result<SetItem, QueryError> {
    let variable = parser.expect_name("a variable name")?;

    if parser.eat(Kind::Colon) {
        return Ok(SetItem::Label {
            variable,
            label: parser.expect_name("a label")?,
        });
    }

    // `SET n = {...}` and `SET n += {...}` differ only in what happens to a property the
    // map omits, and choosing wrongly silently loses exactly that data.
    if parser.kind() == Kind::Equal || parser.kind() == Kind::Plus {
        return Err(QueryError::unsupported(
            "assigning a whole record with `SET n = {...}` or `SET n += {...}` is outside \
             the declared query subset; set each property",
            parser.range(),
        ));
    }

    parser.expect(Kind::Dot, "`.` or `:` after a variable in `SET`")?;
    let key = parser.expect_name("a property key")?;
    parser.expect(Kind::Equal, "`=` in a `SET` assignment")?;
    let value_range = parser.range();
    let value = parse_expression(parser)?;
    reject_aggregate(&value, "a `SET` value", value_range)?;

    Ok(SetItem::Property {
        variable,
        key,
        value,
    })
}

fn parse_remove_item(parser: &mut Parser) -> Result<RemoveItem, QueryError> {
    let variable = parser.expect_name("a variable name")?;
    if parser.eat(Kind::Colon) {
        return Ok(RemoveItem::Label {
            variable,
            label: parser.expect_name("a label")?,
        });
    }
    parser.expect(Kind::Dot, "`.` or `:` after a variable in `REMOVE`")?;
    Ok(RemoveItem::Property {
        variable,
        key: parser.expect_name("a property key")?,
    })
}

fn parse_projection(parser: &mut Parser, allow_where: bool) -> Result<Projection, QueryError> {
    let distinct = parser.eat_word(Word::Distinct);
    let mut items = Vec::new();
    loop {
        let expression = parse_expression(parser)?;
        let alias = if parser.eat_word(Word::As) {
            Some(parser.expect_name("a column name")?)
        } else {
            None
        };
        items.push(ProjectionItem { expression, alias });
        if !parser.eat(Kind::Comma) {
            break;
        }
    }

    let predicate = if parser.at(Word::Where) {
        if !allow_where {
            return Err(QueryError::semantic(
                "`WHERE` is not valid on `RETURN`; use it on `MATCH` or `WITH`",
                parser.range(),
            ));
        }
        parser.index += 1;
        Some(parse_expression(parser)?)
    } else {
        None
    };

    let mut order_by = Vec::new();
    if parser.at(Word::Order) {
        parser.index += 1;
        if !parser.eat_word(Word::By) {
            return Err(QueryError::semantic(
                "expected `BY` after `ORDER`",
                parser.range(),
            ));
        }
        loop {
            let expression = parse_expression(parser)?;
            let descending = if parser.eat_word(Word::Desc) {
                true
            } else {
                parser.eat_word(Word::Asc);
                false
            };
            order_by.push(SortItem {
                expression,
                descending,
            });
            if !parser.eat(Kind::Comma) {
                break;
            }
        }
    }

    let skip = parse_row_count(parser, Word::Skip, "a `SKIP` count")?;
    let limit = parse_row_count(parser, Word::Limit, "a `LIMIT` count")?;

    Ok(Projection {
        distinct,
        items,
        predicate,
        order_by,
        skip,
        limit,
    })
}

fn parse_row_count(
    parser: &mut Parser,
    word: Word,
    what: &str,
) -> Result<Option<Expression>, QueryError> {
    if !parser.eat_word(word) {
        return Ok(None);
    }
    let range = parser.range();
    let expression = parse_expression(parser)?;
    reject_aggregate(&expression, what, range)?;
    Ok(Some(expression))
}

fn parse_pattern(parser: &mut Parser) -> Result<Pattern, QueryError> {
    // A named path is written `p = (...)`. Only an identifier can precede `=`.
    let path_variable = if parser.kind() == Kind::Identifier
        && parser.tokens.get(parser.index + 1).map(|t| t.kind) == Some(Kind::Equal)
    {
        let name = parser.expect_name("a path variable")?;
        parser.index += 1;
        Some(name)
    } else {
        None
    };

    let start = parse_node(parser)?;
    let mut steps = Vec::new();
    while matches!(parser.kind(), Kind::Minus | Kind::ArrowLeft) {
        let relationship = parse_relationship(parser)?;
        let node = parse_node(parser)?;
        steps.push((relationship, node));
    }

    Ok(Pattern {
        path_variable,
        start,
        steps,
    })
}

fn parse_node(parser: &mut Parser) -> Result<NodePattern, QueryError> {
    parser.expect(Kind::LeftParen, "`(` to open a node pattern")?;
    let variable = if parser.kind() == Kind::Identifier {
        Some(parser.expect_name("a variable name")?)
    } else {
        None
    };
    let mut labels = Vec::new();
    while parser.eat(Kind::Colon) {
        labels.push(parser.expect_name("a label")?);
    }
    let properties = parse_property_map(parser)?;
    parser.expect(Kind::RightParen, "`)` to close a node pattern")?;
    Ok(NodePattern {
        variable,
        labels,
        properties,
    })
}

/// An inline property map, when the pattern has one.
///
/// The map means a filter in a reading clause and values in a writing one, per query
/// contract section 8. The parser records it once; which meaning applies is decided by the
/// clause that holds the pattern.
fn parse_property_map(parser: &mut Parser) -> Result<Vec<(String, Expression)>, QueryError> {
    if parser.kind() != Kind::LeftBrace {
        return Ok(Vec::new());
    }
    let open = parser.range();
    parser.index += 1;

    let mut entries: Vec<(String, Expression)> = Vec::new();
    if parser.kind() != Kind::RightBrace {
        loop {
            let key = parser.expect_name("a property key")?;
            parser.expect(Kind::Colon, "`:` after a property key")?;
            let value_range = parser.range();
            let value = parse_expression(parser)?;
            reject_aggregate(&value, "a property map", value_range)?;

            // The last value must not silently win: the model reports a repeated key as a
            // violation rather than resolving it, and so does the language.
            if entries.iter().any(|(existing, _)| *existing == key) {
                return Err(QueryError::semantic(
                    format!("the property key `{key}` is set more than once in one map"),
                    value_range,
                ));
            }
            entries.push((key, value));
            if !parser.eat(Kind::Comma) {
                break;
            }
        }
    }
    parser.expect(Kind::RightBrace, "`}` to close a property map")?;
    let _ = open;
    Ok(entries)
}

fn parse_relationship(parser: &mut Parser) -> Result<RelationshipPattern, QueryError> {
    let incoming = parser.kind() == Kind::ArrowLeft;
    parser.index += 1;

    if parser.kind() != Kind::LeftBracket {
        // A bare arrow, such as `-->` or `--`.
        let direction = if parser.eat(Kind::ArrowRight) {
            Direction::Outgoing
        } else if incoming {
            Direction::Incoming
        } else if parser.eat(Kind::Minus) {
            Direction::Either
        } else {
            return Err(QueryError::semantic(
                "expected a relationship pattern",
                parser.range(),
            ));
        };
        return Ok(RelationshipPattern {
            variable: None,
            types: Vec::new(),
            direction,
            length: None,
            properties: Vec::new(),
        });
    }

    parser.index += 1;
    let variable = if parser.kind() == Kind::Identifier {
        Some(parser.expect_name("a relationship variable")?)
    } else {
        None
    };
    let mut types = Vec::new();
    if parser.eat(Kind::Colon) {
        types.push(parser.expect_name("a relation type")?);
        while parser.eat(Kind::Pipe) {
            types.push(parser.expect_name("a relation type")?);
        }
    }

    let length = if parser.kind() == Kind::Star {
        let star = parser.range();
        parser.index += 1;
        Some(parse_length(parser, star)?)
    } else {
        None
    };

    let properties = parse_property_map(parser)?;
    parser.expect(Kind::RightBracket, "`]` to close a relationship pattern")?;

    let direction = if parser.eat(Kind::ArrowRight) {
        Direction::Outgoing
    } else if parser.eat(Kind::Minus) {
        if incoming {
            Direction::Incoming
        } else {
            Direction::Either
        }
    } else {
        return Err(QueryError::semantic(
            "expected `->` or `-` after a relationship pattern",
            parser.range(),
        ));
    };

    Ok(RelationshipPattern {
        variable,
        types,
        direction,
        length,
        properties,
    })
}

fn parse_length(parser: &mut Parser, star: SourceRange) -> Result<LengthRange, QueryError> {
    let unbounded = QueryError::unsupported(
        "a variable-length pattern must declare both bounds, as in `*1..5`, because an \
         unbounded traversal has no cost ceiling",
        star,
    );

    if parser.kind() != Kind::Integer {
        // `*`, `*..5`, or `*]`.
        return Err(unbounded);
    }
    let minimum =
        parser.current().text.parse::<u32>().map_err(|_| {
            QueryError::semantic("a pattern bound must fit in 32 bits", parser.range())
        })?;
    parser.index += 1;

    if !parser.eat(Kind::DotDot) {
        return Err(unbounded);
    }
    if parser.kind() != Kind::Integer {
        // `*1..`
        return Err(unbounded);
    }
    let maximum =
        parser.current().text.parse::<u32>().map_err(|_| {
            QueryError::semantic("a pattern bound must fit in 32 bits", parser.range())
        })?;
    let maximum_range = parser.range();
    parser.index += 1;

    if maximum < minimum {
        return Err(QueryError::semantic(
            "a pattern's upper bound must not be below its lower bound",
            maximum_range,
        ));
    }
    Ok(LengthRange { minimum, maximum })
}

fn parse_expression(parser: &mut Parser) -> Result<Expression, QueryError> {
    parse_or(parser)
}

fn parse_or(parser: &mut Parser) -> Result<Expression, QueryError> {
    let mut left = parse_and(parser)?;
    while parser.eat_word(Word::Or) {
        let right = parse_and(parser)?;
        left = Expression::Binary {
            operator: BinaryOperator::Or,
            left: Box::new(left),
            right: Box::new(right),
        };
    }
    Ok(left)
}

fn parse_and(parser: &mut Parser) -> Result<Expression, QueryError> {
    let mut left = parse_not(parser)?;
    while parser.eat_word(Word::And) {
        let right = parse_not(parser)?;
        left = Expression::Binary {
            operator: BinaryOperator::And,
            left: Box::new(left),
            right: Box::new(right),
        };
    }
    Ok(left)
}

fn parse_not(parser: &mut Parser) -> Result<Expression, QueryError> {
    if parser.eat_word(Word::Not) {
        return Ok(Expression::Not(Box::new(parse_not(parser)?)));
    }
    parse_comparison(parser)
}

fn parse_comparison(parser: &mut Parser) -> Result<Expression, QueryError> {
    let left = parse_additive(parser)?;
    let operator = match parser.kind() {
        Kind::Equal => BinaryOperator::Equal,
        Kind::NotEqual => BinaryOperator::NotEqual,
        Kind::Less => BinaryOperator::Less,
        Kind::LessEqual => BinaryOperator::LessEqual,
        Kind::Greater => BinaryOperator::Greater,
        Kind::GreaterEqual => BinaryOperator::GreaterEqual,
        Kind::Word(Word::In) => BinaryOperator::In,
        _ => return Ok(left),
    };
    parser.index += 1;
    let right = parse_additive(parser)?;
    Ok(Expression::Binary {
        operator,
        left: Box::new(left),
        right: Box::new(right),
    })
}

fn parse_additive(parser: &mut Parser) -> Result<Expression, QueryError> {
    let mut left = parse_primary(parser)?;
    loop {
        let operator = match parser.kind() {
            Kind::Plus => BinaryOperator::Add,
            Kind::Minus => BinaryOperator::Subtract,
            Kind::Star => BinaryOperator::Multiply,
            Kind::Slash => BinaryOperator::Divide,
            Kind::Percent => BinaryOperator::Modulo,
            _ => return Ok(left),
        };
        parser.index += 1;
        let right = parse_primary(parser)?;
        left = Expression::Binary {
            operator,
            left: Box::new(left),
            right: Box::new(right),
        };
    }
}

fn parse_primary(parser: &mut Parser) -> Result<Expression, QueryError> {
    let token = parser.current().clone();

    // A leading minus makes a negative literal. Without this, `LIMIT -1` would fail as a
    // syntax error, hiding the more useful complaint that the value must not be negative.
    if token.kind == Kind::Minus {
        parser.index += 1;
        let inner = parse_primary(parser)?;
        return Ok(match inner {
            Expression::Integer(value) => Expression::Integer(-value),
            Expression::Float(text) => Expression::Float(format!("-{text}")),
            other => Expression::Binary {
                operator: BinaryOperator::Subtract,
                left: Box::new(Expression::Integer(0)),
                right: Box::new(other),
            },
        });
    }

    match token.kind {
        Kind::Integer => {
            parser.index += 1;
            let value = token.text.parse::<i64>().map_err(|_| {
                QueryError::semantic("an integer literal is out of range", token.range)
            })?;
            Ok(Expression::Integer(value))
        }
        Kind::Float => {
            parser.index += 1;
            Ok(Expression::Float(token.text))
        }
        Kind::Text => {
            parser.index += 1;
            Ok(Expression::Text(token.text))
        }
        Kind::Parameter => {
            parser.index += 1;
            Ok(Expression::Parameter(token.text))
        }
        Kind::Word(Word::True) => {
            parser.index += 1;
            Ok(Expression::Boolean(true))
        }
        Kind::Word(Word::False) => {
            parser.index += 1;
            Ok(Expression::Boolean(false))
        }
        Kind::Word(Word::Null) => {
            parser.index += 1;
            Ok(Expression::Null)
        }
        Kind::Star => {
            // `RETURN *` projects every binding, which needs scope tracking this
            // increment does not have.
            Err(QueryError::unsupported(
                "`*` as a projection is not in this build's subset; name the columns",
                token.range,
            ))
        }
        Kind::LeftParen => {
            parser.index += 1;
            let inner = parse_expression(parser)?;
            parser.expect(Kind::RightParen, "`)`")?;
            Ok(inner)
        }
        Kind::LeftBracket => parse_list(parser),
        Kind::Identifier => parse_identifier_expression(parser),
        _ => Err(QueryError::semantic("expected an expression", token.range)),
    }
}

fn parse_list(parser: &mut Parser) -> Result<Expression, QueryError> {
    let open = parser.range();
    parser.index += 1;

    // A pattern comprehension opens with a pattern; a list comprehension puts `IN` after
    // its variable. Both are outside the subset, and both are detected before any element
    // is interpreted.
    if parser.kind() == Kind::LeftParen {
        return Err(QueryError::unsupported(
            "a pattern comprehension is outside the declared query subset",
            open,
        ));
    }
    if parser.kind() == Kind::Identifier
        && parser.tokens.get(parser.index + 1).map(|t| t.kind) == Some(Kind::Word(Word::In))
    {
        return Err(QueryError::unsupported(
            "a list comprehension is outside the declared query subset",
            open,
        ));
    }

    let mut items = Vec::new();
    if parser.kind() != Kind::RightBracket {
        loop {
            items.push(parse_expression(parser)?);
            if !parser.eat(Kind::Comma) {
                break;
            }
        }
    }
    parser.expect(Kind::RightBracket, "`]` to close a list")?;
    Ok(Expression::List(items))
}

fn parse_identifier_expression(parser: &mut Parser) -> Result<Expression, QueryError> {
    let first = parser.current().clone();
    parser.index += 1;

    // A dotted name is either a property access or a namespaced function.
    if parser.kind() == Kind::Dot {
        parser.index += 1;
        let second = parser.expect_name("a property key or function name")?;
        if parser.kind() == Kind::LeftParen {
            return parse_call(parser, format!("{}.{second}", first.text), first.range);
        }
        return Ok(Expression::Property {
            variable: first.text,
            key: second,
        });
    }

    if parser.kind() == Kind::LeftParen {
        return parse_call(parser, first.text, first.range);
    }

    Ok(Expression::Variable(first.text))
}

fn parse_call(
    parser: &mut Parser,
    name: String,
    range: SourceRange,
) -> Result<Expression, QueryError> {
    if EXCLUDED_FUNCTIONS.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(QueryError::unsupported(
            format!("`{name}` is outside the declared query subset"),
            range,
        ));
    }
    parser.index += 1;
    let aggregate = is_aggregate(&name);

    if aggregate && parser.at(Word::Distinct) {
        return Err(QueryError::unsupported(
            format!("`DISTINCT` inside `{name}` is outside the declared query subset"),
            parser.range(),
        ));
    }

    let mut arguments = Vec::new();
    if parser.kind() != Kind::RightParen {
        loop {
            // `count(*)` is the one place a star is an argument.
            if parser.kind() == Kind::Star {
                parser.index += 1;
                arguments.push(Expression::Variable(STAR_ARGUMENT.to_owned()));
            } else {
                let argument_range = parser.range();
                let argument = parse_expression(parser)?;
                if aggregate {
                    reject_aggregate(&argument, "another aggregate", argument_range)?;
                }
                arguments.push(argument);
            }
            if !parser.eat(Kind::Comma) {
                break;
            }
        }
    }
    parser.expect(Kind::RightParen, "`)` to close a call")?;
    Ok(Expression::Call { name, arguments })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsupported(source: &str) -> QueryError {
        let error = parse(source).expect_err("must be refused");
        assert_eq!(
            error.code,
            DiagnosticCode::CypherUnsupported,
            "{source}: {error}"
        );
        error
    }

    fn semantic_error(source: &str) -> QueryError {
        let error = parse(source).expect_err("must be refused");
        assert_eq!(
            error.code,
            DiagnosticCode::CypherSemanticError,
            "{source}: {error}"
        );
        error
    }

    fn clauses(source: &str) -> Vec<Clause> {
        parse(source)
            .unwrap_or_else(|error| panic!("{source}: {error}"))
            .parts
            .swap_remove(0)
            .clauses
    }

    #[test]
    fn parses_the_smallest_reading_query() {
        let query = parse("MATCH (n:Function) RETURN n.name").unwrap();
        assert_eq!(query.parts.len(), 1);
        assert_eq!(query.parts[0].clauses.len(), 1);
        assert_eq!(query.parts[0].result.as_ref().unwrap().items.len(), 1);
        assert!(!query.is_writing());
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert!(parse("match (n) return n").is_ok());
        assert!(parse("MaTcH (n) ReTuRn n").is_ok());
        assert!(parse("create (n:A) return n").is_ok());
    }

    #[test]
    fn parses_a_bounded_variable_length_pattern() {
        let query = parse("MATCH p = (a)-[:CALLS*1..5]->(b) RETURN p").unwrap();
        let Clause::Match { patterns, .. } = &query.parts[0].clauses[0] else {
            panic!("expected a match clause");
        };
        assert_eq!(patterns[0].path_variable.as_deref(), Some("p"));
        assert_eq!(
            patterns[0].steps[0].0.length,
            Some(LengthRange {
                minimum: 1,
                maximum: 5
            })
        );
    }

    #[test]
    fn every_unbounded_pattern_form_is_refused() {
        for source in [
            "MATCH (a)-[:CALLS*]->(b) RETURN b",
            "MATCH (a)-[:CALLS*1..]->(b) RETURN b",
            "MATCH (a)-[:CALLS*..5]->(b) RETURN b",
        ] {
            let error = unsupported(source);
            assert!(error.message.contains("both bounds"), "{source}: {error}");
        }
    }

    #[test]
    fn an_inverted_bound_is_a_semantic_error_not_an_unsupported_one() {
        // The construct is in the subset; the values are wrong. A caller retrying against
        // a newer build would not be helped, which is what the code distinction means.
        semantic_error("MATCH (a)-[:CALLS*5..1]->(b) RETURN b");
    }

    #[test]
    fn every_excluded_keyword_is_refused() {
        for source in [
            "MATCH (n) FOREACH (x IN [1] | SET n.a = x) RETURN n",
            "LOAD CSV FROM \"f\" AS row RETURN row",
            "MATCH (n) RETURN CASE n.a WHEN 1 THEN 2 ELSE 3 END",
            "MATCH (n) WHERE EXISTS { MATCH (n) } RETURN n",
            "USE other MATCH (n) RETURN n",
            "CREATE INDEX i FOR (n:A) ON (n.b)",
        ] {
            unsupported(source);
        }
    }

    #[test]
    fn comprehensions_and_excluded_functions_are_refused() {
        let error = unsupported("MATCH (n) RETURN [x IN n.tags WHERE x <> \"\"] AS kept");
        assert!(error.message.contains("list comprehension"), "{error}");

        let error = unsupported("MATCH (n) RETURN [(n)-[:CALLS]->(m) | m.name] AS called");
        assert!(error.message.contains("pattern comprehension"), "{error}");

        let error = unsupported("MATCH p = shortestPath((a)-[:CALLS*1..5]->(b)) RETURN p");
        assert!(error.message.contains("shortestPath"), "{error}");
    }

    #[test]
    fn a_refused_query_yields_no_plan_at_all() {
        // The type system carries this: parse returns Result, so there is no partial
        // query to accidentally execute.
        assert!(parse("MATCH (a)-[:CALLS*]->(b) RETURN b").is_err());
    }

    #[test]
    fn parses_the_full_reading_pipeline() {
        let query = parse(
            "MATCH (n:Function) WHERE n.language = $language \
             WITH n.language AS language, n WHERE language = \"rust\" \
             UNWIND [1, 2] AS number \
             RETURN DISTINCT n.name AS name, number ORDER BY name DESC SKIP 1 LIMIT 10",
        )
        .unwrap();
        let part = &query.parts[0];
        assert_eq!(part.clauses.len(), 3);
        let result = part.result.as_ref().unwrap();
        assert!(result.distinct);
        assert_eq!(result.order_by.len(), 1);
        assert!(result.order_by[0].descending);
        assert!(result.skip.is_some());
        assert!(result.limit.is_some());
    }

    #[test]
    fn union_requires_matching_column_names() {
        assert!(parse("MATCH (n:A) RETURN n.name UNION MATCH (n:B) RETURN n.name").is_ok());
        assert!(parse("MATCH (n:A) RETURN n.name UNION ALL MATCH (n:B) RETURN n.name").is_ok());

        let error = semantic_error("MATCH (n:A) RETURN n.name UNION MATCH (n:B) RETURN n.title");
        assert!(error.message.contains("same column names"), "{error}");
    }

    #[test]
    fn union_all_flags_are_recorded_per_operator() {
        // Aliases are required here: `a.n` and `b.n` are genuinely different column names
        // in Cypher, so without them this would be a semantic error rather than a UNION.
        let query = parse(
            "MATCH (a:A) RETURN a.n AS n UNION ALL MATCH (b:B) RETURN b.n AS n \
             UNION MATCH (c:C) RETURN c.n AS n",
        )
        .unwrap();
        assert_eq!(query.parts.len(), 3);
        assert_eq!(query.union_all, vec![true, false]);
    }

    #[test]
    fn a_writing_union_operand_is_refused() {
        let error = unsupported(
            "MATCH (n:A) RETURN n.name AS name UNION CREATE (m:A {name: \"x\"}) RETURN m.name AS name",
        );
        assert!(error.message.contains("read-only"), "{error}");
    }

    #[test]
    fn where_is_refused_on_return() {
        semantic_error("MATCH (n) RETURN n WHERE n.a = 1");
    }

    #[test]
    fn parses_directions_and_types() {
        let query =
            parse("MATCH (a)-[r:CALLS|USES]-(b), (c)<-[:OWNS]-(d) RETURN a, b, c, d").unwrap();
        let Clause::Match { patterns, .. } = &query.parts[0].clauses[0] else {
            panic!("expected a match clause");
        };
        assert_eq!(patterns[0].steps[0].0.direction, Direction::Either);
        assert_eq!(patterns[0].steps[0].0.types, vec!["CALLS", "USES"]);
        assert_eq!(patterns[0].steps[0].0.variable.as_deref(), Some("r"));
        assert_eq!(patterns[1].steps[0].0.direction, Direction::Incoming);
    }

    #[test]
    fn a_read_only_query_without_return_is_refused() {
        let error = semantic_error("MATCH (n)");
        assert!(error.message.contains("RETURN"), "{error}");
    }

    #[test]
    fn every_refusal_carries_a_range_and_renders_as_a_diagnostic() {
        for source in [
            "MATCH (a)-[:CALLS*]->(b) RETURN b",
            "MATCH (n)",
            "USE other MATCH (n) RETURN n",
            "MATCH (n) SET n = {a: 1}",
            "MERGE (n:A) ON CREATE SET n.a = 1",
        ] {
            let error = parse(source).unwrap_err();
            assert!(error.range.start().line >= 1, "{source}");
            assert!(error.range.start().column >= 1, "{source}");
            let diagnostic = error.to_diagnostic();
            assert_eq!(diagnostic.severity, Severity::Error);
            assert!(diagnostic.range.is_some());
        }
    }

    #[test]
    fn line_comments_and_multiple_lines_are_handled() {
        let query = parse("MATCH (n:Function) // a comment\nRETURN n.name").unwrap();
        assert_eq!(query.parts[0].result.as_ref().unwrap().items.len(), 1);
    }

    #[test]
    fn parses_an_inline_property_map_in_both_positions() {
        let query = parse(
            "MATCH (a:Service {name: \"alpha\", live: true})-[r:CALLS {kind: \"direct\"}]->(b) \
             RETURN b",
        )
        .unwrap();
        let Clause::Match { patterns, .. } = &query.parts[0].clauses[0] else {
            panic!("expected a match clause");
        };
        assert_eq!(patterns[0].start.properties.len(), 2);
        assert_eq!(patterns[0].start.properties[0].0, "name");
        assert_eq!(patterns[0].steps[0].0.properties.len(), 1);
    }

    #[test]
    fn a_repeated_key_in_one_map_is_reported_rather_than_letting_the_last_value_win() {
        let error = semantic_error("MATCH (n:A {name: \"one\", name: \"two\"}) RETURN n");
        assert!(error.message.contains("more than once"), "{error}");
    }

    #[test]
    fn parses_every_write_clause() {
        assert!(matches!(
            clauses("CREATE (n:Function {name: \"login\"})").as_slice(),
            [Clause::Create { .. }]
        ));
        assert!(matches!(
            clauses("MERGE (n:Function {name: \"login\"})").as_slice(),
            [Clause::Merge { .. }]
        ));
        assert!(matches!(
            clauses("MATCH (n) SET n.a = 1, n:Reviewed").as_slice(),
            [Clause::Match { .. }, Clause::Set { .. }]
        ));
        assert!(matches!(
            clauses("MATCH (n) REMOVE n.a, n:Reviewed").as_slice(),
            [Clause::Match { .. }, Clause::Remove { .. }]
        ));
        assert!(matches!(
            clauses("MATCH (n) DELETE n").as_slice(),
            [Clause::Match { .. }, Clause::Delete { detach: false, .. }]
        ));
        assert!(matches!(
            clauses("MATCH (n) DETACH DELETE n").as_slice(),
            [Clause::Match { .. }, Clause::Delete { detach: true, .. }]
        ));
    }

    #[test]
    fn a_write_query_may_omit_return_and_is_reported_as_writing() {
        let query = parse("MATCH (n:Function) SET n.seen = true").unwrap();
        assert!(query.parts[0].result.is_none());
        assert!(query.is_writing());

        let reading = parse("MATCH (n:Function) RETURN n").unwrap();
        assert!(!reading.is_writing());
    }

    #[test]
    fn set_items_record_which_variable_and_key_they_name() {
        let Clause::Set { items, .. } = &clauses("MATCH (n) SET n.reviewed = true")[1] else {
            panic!("expected a set clause");
        };
        assert_eq!(
            items[0],
            SetItem::Property {
                variable: "n".to_owned(),
                key: "reviewed".to_owned(),
                value: Expression::Boolean(true)
            }
        );
    }

    #[test]
    fn whole_record_assignment_is_refused_in_both_spellings() {
        for source in [
            "MATCH (n) SET n = {name: \"x\"}",
            "MATCH (n) SET n += {name: \"x\"}",
        ] {
            let error = unsupported(source);
            assert!(error.message.contains("whole record"), "{source}: {error}");
        }
    }

    #[test]
    fn merge_refuses_on_create_and_on_match() {
        for source in [
            "MERGE (n:A {name: \"x\"}) ON CREATE SET n.made = true",
            "MERGE (n:A {name: \"x\"}) ON MATCH SET n.seen = true",
        ] {
            let error = unsupported(source);
            assert!(error.message.contains("ON CREATE"), "{source}: {error}");
        }
    }

    #[test]
    fn a_write_pattern_may_not_be_variable_length_or_a_named_path() {
        let error = unsupported("MATCH (a), (b) CREATE (a)-[:R*1..2]->(b)");
        assert!(error.message.contains("variable-length"), "{error}");

        let error = unsupported("CREATE p = (a:A)-[:R]->(b:B)");
        assert!(error.message.contains("named path"), "{error}");
    }

    #[test]
    fn detach_must_be_followed_by_delete() {
        semantic_error("MATCH (n) DETACH n");
    }

    #[test]
    fn parses_a_call_with_and_without_yield() {
        let Clause::Call(call) = &clauses("CALL nostdb.build_status()")[0] else {
            panic!("expected a call clause");
        };
        assert_eq!(call.name, "nostdb.build_status");
        assert!(call.yields.is_empty());
        assert!(call.arguments.is_empty());

        let Clause::Call(call) = &clauses("CALL nostdb.links() YIELD source AS s RETURN s")[0]
        else {
            panic!("expected a call clause");
        };
        assert_eq!(call.yields.len(), 1);
        assert_eq!(call.yields[0].column, "source");
        assert_eq!(call.yields[0].bound_name(), "s");
    }

    #[test]
    fn a_call_subquery_is_still_refused() {
        let error = unsupported("CALL { MATCH (n) RETURN n } RETURN n");
        assert!(error.message.contains("subquery"), "{error}");
    }

    #[test]
    fn an_aggregate_is_refused_everywhere_the_contract_forbids_one() {
        // In a MATCH predicate, because grouping does not exist yet.
        let error = semantic_error("MATCH (n)-[:CALLS]->(m) WHERE count(m) > 3 RETURN n");
        assert!(error.message.contains("WITH"), "{error}");

        // Inside another aggregate.
        semantic_error("MATCH (n) RETURN sum(count(n))");
        // In an UNWIND list, a SKIP, a LIMIT, a SET value, and a property map.
        semantic_error("MATCH (n) UNWIND collect(n) AS each RETURN each");
        semantic_error("MATCH (n) RETURN n LIMIT count(n)");
        semantic_error("MATCH (n) RETURN n SKIP count(n)");
        semantic_error("MATCH (n) SET n.total = count(n)");
        semantic_error("MATCH (n) CREATE (m:A {total: count(n)})");
    }

    #[test]
    fn distinct_inside_an_aggregate_is_unsupported_rather_than_ignored() {
        let error =
            unsupported("MATCH (n)-[:CALLS]->(m) RETURN n.name AS n, count(DISTINCT m) AS c");
        assert!(error.message.contains("DISTINCT"), "{error}");
    }

    #[test]
    fn an_aggregate_is_detected_through_a_surrounding_expression() {
        let query = parse("MATCH (n) RETURN count(n) + 1 AS more").unwrap();
        let items = &query.parts[0].result.as_ref().unwrap().items;
        assert!(items[0].expression.contains_aggregate());

        let query = parse("MATCH (n) RETURN n.name AS name").unwrap();
        let items = &query.parts[0].result.as_ref().unwrap().items;
        assert!(!items[0].expression.contains_aggregate());
    }

    #[test]
    fn an_unaliased_column_is_named_by_its_own_text_not_a_debug_rendering() {
        let query = parse("MATCH (n) RETURN toUpper(n.name), n.age + 1, count(*)").unwrap();
        assert_eq!(
            column_names(query.parts[0].result.as_ref().unwrap()),
            vec!["toUpper(n.name)", "n.age + 1", "count(*)"]
        );
    }

    #[test]
    fn a_rendered_expression_reads_back_as_the_query_text() {
        for source in [
            "n.name",
            "$wanted",
            "[1, 2]",
            "NOT n.live",
            "n.a AND n.b",
            "count(*)",
            "null",
        ] {
            let query = parse(&format!("MATCH (n) RETURN {source}")).unwrap();
            let items = &query.parts[0].result.as_ref().unwrap().items;
            assert_eq!(items[0].expression.render(), source);
        }
    }
}
