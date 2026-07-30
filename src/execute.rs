//! Query execution over a graph.
//!
//! # Result order is undefined without `ORDER BY`
//!
//! The query contract says so, and this module is deliberately built so that a caller
//! cannot come to rely on an incidental order: [`QueryResult::rows`] is only sorted when
//! the query asked for it. A test asserts that a query without `ORDER BY` still produces
//! the same *set* of rows, which is the guarantee, rather than the same sequence.
//!
//! # Unbound is a semantic error, not an empty result
//!
//! Referring to a variable nothing bound is `CYPHER_SEMANTIC_ERROR`. Returning zero rows
//! instead would look like a legitimate answer to a query that is simply wrong.
//!
//! # A read-only caller cannot execute a write by accident
//!
//! [`execute`] takes `&mut Graph`, so a caller holding a shared graph has nothing to call
//! it with. That is the structural version of the rule that writes affect only the root
//! database: there is no read-only entry point that could be handed a writing query.
//! [`crate::cypher::Query::is_writing`] lets a caller ask in advance.
//!
//! # Where the reading and writing halves meet
//!
//! A read builds an index over the graph; a write moves records underneath it. The two
//! therefore cannot hold the graph at the same time, and the clause loop alternates: it
//! evaluates everything a write needs, drops the reader, and then applies the write.
//!
//! That alternation also fixes a semantic question rather than leaving it to evaluation
//! order. The values a write clause assigns are evaluated against the graph as the clause
//! found it, so one row's write cannot change what another row assigns. `MERGE` is the one
//! exception, because matching per row is what keeps it from creating a duplicate for a
//! repeated row.
//!
//! Building the index once per clause rather than once per query is a simplicity choice.
//! It is the obvious thing to revisit when there is a benchmark to justify a change, which
//! the root product contract defers to a measured baseline.

use crate::cancel::{Never, ShouldStop};
use crate::cypher::{
    BinaryOperator, Clause, Direction, Expression, LengthRange, NodePattern, Pattern,
    ProcedureCall, Projection, ProjectionItem, Query, QueryError, QueryPart, RelationshipPattern,
    STAR_ARGUMENT, column_name, column_names, is_aggregate,
};
use crate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::encoding::Graph;
use crate::evidence::SourceRange;
use crate::generation::Generation;
use crate::graph::{Edge, Node, NodeReference};
use crate::id::{LocalEdgeId, LocalNodeId, Minter};
use crate::locator::CanonicalSourceLocator;
use crate::mutate::{
    PatternValues, WriteSummary, Writer, remove_variable, set_value, set_variable,
};
use crate::procedure;
use crate::property::{FiniteF64, PropertyValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Functions this build evaluates.
const SCALAR_FUNCTIONS: [&str; 6] = ["toupper", "tolower", "size", "labels", "type", "coalesce"];

/// A linked source a read may see beside the root.
///
/// Defined here rather than taken from `federation`, so the executor depends on the shape
/// of a source and not on how one is discovered. A caller that has resolved a
/// `Federation` hands over a slice of these; a caller with no links hands over nothing.
#[derive(Clone, Copy, Debug)]
pub struct LinkedSource<'a> {
    /// The canonical locator, which is the source's identity.
    pub locator: &'a CanonicalSourceLocator,
    /// The records it holds.
    pub graph: &'a Graph,
}

/// The root and its linked sources, in the order the executor indexes them.
fn source_list<'a>(
    root: &'a Graph,
    linked: &[LinkedSource<'a>],
) -> Vec<(Option<&'a CanonicalSourceLocator>, &'a Graph)> {
    std::iter::once((None, root))
        .chain(
            linked
                .iter()
                .map(|source| (Some(source.locator), source.graph)),
        )
        .collect()
}

/// A record handle inside a query, carrying which source it came from.
///
/// A `LocalNodeId` is unique within one database and nowhere else. A federated query sees
/// several, and two of them may carry the same identifier: a database copied and then
/// linked from its original does exactly that, and root PRD section 18.4 says the two
/// remain distinct sources however identical their bytes. A bound record therefore has to
/// name its source as well as its identifier.
///
/// `source` is an index into the query's source list, and `0` is always the root. An
/// index rather than a locator keeps the handle `Copy` and cheap to compare; the locator
/// is recovered from the executor when a caller asks for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scoped<T> {
    /// Which source, indexed from the root at zero.
    pub source: u32,
    /// The record's identifier within that source.
    pub id: T,
}

impl<T> Scoped<T> {
    /// A handle to a record in the root database.
    pub const fn root(id: T) -> Self {
        Self { source: 0, id }
    }

    /// Reports whether this record belongs to the root rather than a linked source.
    ///
    /// A write may only touch the root, so this is what a refusal turns on.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.source == 0
    }
}

impl<T: fmt::Display> Scoped<T> {
    /// A total-order key that keeps two sources apart.
    ///
    /// [`fmt::Display`] renders the identifier alone, because that is what a caller sees
    /// and what the result envelope carries. Sorting cannot use it: two sources may hold
    /// the same identifier, and a key that rendered both the same would let `ORDER BY`
    /// and `DISTINCT` treat two records as one.
    #[must_use]
    pub fn sort_key(&self) -> String {
        // A separator no identifier can contain, so the two fields cannot run together.
        // The source is zero padded so the key orders numerically, and a colon cannot
        // appear in an identifier, so the two fields cannot run together.
        format!("{:010}:{}", self.source, self.id)
    }
}

/// Renders the identifier alone.
///
/// The source is deliberately absent: `nostdb.source(n)` reports it, and the result
/// envelope carries the identifier in the form the record itself uses.
impl<T: fmt::Display> fmt::Display for Scoped<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

/// A bound node.
pub type ScopedNode = Scoped<LocalNodeId>;

/// A bound relationship.
pub type ScopedEdge = Scoped<LocalEdgeId>;

/// A value a query can produce.
#[derive(Clone, Debug)]
pub enum QueryValue {
    /// Missing or non-applicable. Only a query result carries this; stored data cannot.
    Null,
    /// A boolean.
    Boolean(bool),
    /// An integer.
    Integer(i64),
    /// A finite number.
    Float(FiniteF64),
    /// Text.
    Text(String),
    /// A list.
    List(Vec<QueryValue>),
    /// A bound node.
    Node(ScopedNode),
    /// A bound relationship.
    Relationship(ScopedEdge),
    /// A bound path: alternating nodes and relationships.
    Path {
        /// Nodes along the path, in order.
        nodes: Vec<ScopedNode>,
        /// Relationships between them, in order.
        relationships: Vec<ScopedEdge>,
    },
}

impl QueryValue {
    /// Interprets this value as a predicate outcome.
    ///
    /// Only `true` is true. `null` is not, which is what keeps an unmatched
    /// `OPTIONAL MATCH` row from passing a predicate by accident.
    #[must_use]
    pub const fn is_truthy(&self) -> bool {
        matches!(self, Self::Boolean(true))
    }

    /// What kind of value this is, for a diagnostic that has to name it.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean(_) => "a boolean",
            Self::Integer(_) => "an integer",
            Self::Float(_) => "a number",
            Self::Text(_) => "text",
            Self::List(_) => "a list",
            Self::Node(_) => "a node",
            Self::Relationship(_) => "a relationship",
            Self::Path { .. } => "a path",
        }
    }

    fn from_property(value: &PropertyValue) -> Self {
        match value {
            PropertyValue::Boolean(inner) => Self::Boolean(*inner),
            PropertyValue::Integer(inner) => Self::Integer(*inner),
            PropertyValue::Float(inner) => Self::Float(*inner),
            PropertyValue::String(inner) => Self::Text(inner.clone()),
            PropertyValue::Bytes(inner) => Self::Text(
                inner
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            ),
            PropertyValue::DateTime(inner) => Self::Text(inner.as_str().to_owned()),
            PropertyValue::List(items) => Self::List(
                items
                    .iter()
                    .map(|item| Self::from_property(&PropertyValue::from(item.clone())))
                    .collect(),
            ),
        }
    }

    /// A sort key that orders values of different kinds deterministically.
    ///
    /// Cypher leaves cross-type ordering loosely specified, so the query contract fixes
    /// one total order in section 9.4 and this produces it. Without one, `ORDER BY` over a
    /// mixed column would not be reproducible.
    fn sort_key(&self) -> SortKey {
        match self {
            Self::Null => SortKey::Null,
            Self::Boolean(value) => SortKey::Boolean(*value),
            Self::Integer(value) => SortKey::Number(Number::Integer(*value)),
            Self::Float(value) => SortKey::Number(Number::Float(value.get())),
            Self::Text(value) => SortKey::Text(value.clone()),
            Self::List(items) => SortKey::List(items.iter().map(Self::sort_key).collect()),
            Self::Node(id) => SortKey::Node(id.sort_key()),
            Self::Relationship(id) => SortKey::Relationship(id.sort_key()),
            Self::Path { nodes, .. } => SortKey::Path(nodes.iter().map(Scoped::sort_key).collect()),
        }
    }

    /// This value as a number, when it is one.
    const fn as_number(&self) -> Option<Number> {
        match self {
            Self::Integer(value) => Some(Number::Integer(*value)),
            Self::Float(value) => Some(Number::Float(value.get())),
            _ => None,
        }
    }
}

/// Values compare by what they mean, so an integer equals the float of the same value.
///
/// Cypher says `1 = 1.0`, and the ordering in [`SortKey`] agrees, so equality has to as
/// well. Deriving this instead would leave `DISTINCT` folding two values together that `=`
/// reported as different.
impl PartialEq for QueryValue {
    fn eq(&self, other: &Self) -> bool {
        match (self.as_number(), other.as_number()) {
            (Some(left), Some(right)) => left.cmp(&right).is_eq(),
            (None, None) => match (self, other) {
                (Self::Null, Self::Null) => true,
                (Self::Boolean(left), Self::Boolean(right)) => left == right,
                (Self::Text(left), Self::Text(right)) => left == right,
                (Self::List(left), Self::List(right)) => left == right,
                (Self::Node(left), Self::Node(right)) => left == right,
                (Self::Relationship(left), Self::Relationship(right)) => left == right,
                (
                    Self::Path {
                        nodes: left_nodes,
                        relationships: left_edges,
                    },
                    Self::Path {
                        nodes: right_nodes,
                        relationships: right_edges,
                    },
                ) => left_nodes == right_nodes && left_edges == right_edges,
                _ => false,
            },
            _ => false,
        }
    }
}

/// A comparable key standing in for a value, so ordering is total and reproducible.
///
/// The variant order is the cross-kind order the query contract fixes in section 9.4. It is
/// expressed as an enumeration rather than a formatted string because a string cannot order
/// numbers: the previous encoding put `-3` before `-5`, and had no way to compare an integer
/// against a float at all.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SortKey {
    Null,
    Boolean(bool),
    Number(Number),
    Text(String),
    List(Vec<SortKey>),
    Node(String),
    Relationship(String),
    Path(Vec<String>),
}

/// A numeric value, compared by value across both representations.
#[derive(Clone, Copy, Debug)]
enum Number {
    Integer(i64),
    Float(f64),
}

/// One past the largest `i64`, which `i64::MAX as f64` rounds to.
const BEYOND_I64: f64 = 9_223_372_036_854_775_808.0;

impl Ord for Number {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (*self, *other) {
            (Self::Integer(left), Self::Integer(right)) => left.cmp(&right),
            // Neither can be a NaN: FiniteF64 refuses one, and an integer is not one.
            (Self::Float(left), Self::Float(right)) => left.total_cmp(&right),
            (Self::Integer(left), Self::Float(right)) => compare_integer_to_float(left, right),
            (Self::Float(left), Self::Integer(right)) => {
                compare_integer_to_float(right, left).reverse()
            }
        }
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Number {}

/// Compares an integer against a float exactly.
///
/// Converting the integer to a float would be wrong above 2^53, where two distinct integers
/// share one float, so the comparison splits the float instead: whole part against the
/// integer, and the fraction as the tiebreak.
fn compare_integer_to_float(integer: i64, float: f64) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    if float >= BEYOND_I64 {
        return Ordering::Less;
    }
    if float < -BEYOND_I64 {
        return Ordering::Greater;
    }
    let whole = float.trunc();
    // In range and truncated, so this conversion is exact.
    let ordering = integer.cmp(&(whole as i64));
    if ordering != Ordering::Equal {
        return ordering;
    }
    // The fraction carries the float's sign, so it says which side of the integer it is on.
    let fraction = float - whole;
    if fraction > 0.0 {
        Ordering::Less
    } else if fraction < 0.0 {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

impl fmt::Display for QueryValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("null"),
            Self::Boolean(value) => write!(formatter, "{value}"),
            Self::Integer(value) => write!(formatter, "{value}"),
            Self::Float(value) => write!(formatter, "{value}"),
            Self::Text(value) => write!(formatter, "{value}"),
            Self::List(items) => {
                let rendered: Vec<String> = items.iter().map(ToString::to_string).collect();
                write!(formatter, "[{}]", rendered.join(", "))
            }
            Self::Node(id) => write!(formatter, "{id}"),
            Self::Relationship(id) => write!(formatter, "{id}"),
            Self::Path { nodes, .. } => {
                let rendered: Vec<String> = nodes.iter().map(ToString::to_string).collect();
                write!(formatter, "{}", rendered.join("-"))
            }
        }
    }
}

/// Parameter values a query was given, keyed by name without the `$`.
pub type Parameters = BTreeMap<String, QueryValue>;

/// What a row has bound, keyed by variable name.
pub type Bindings = BTreeMap<String, QueryValue>;

/// What a query knows about the database beyond its graph.
///
/// Both fields are optional because a caller may execute against a graph that is not a
/// file: a test, or a change set being validated. A procedure that needs one reports `null`
/// rather than inventing a value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatabaseContext {
    /// The generation the graph was read at.
    pub generation: Option<Generation>,
    /// The canonical locator of the database holding the graph.
    pub source: Option<CanonicalSourceLocator>,
}

/// What a query produced.
#[derive(Clone, Debug, PartialEq)]
pub struct QueryResult {
    /// Column names, in projection order.
    pub columns: Vec<String>,
    /// Rows, each the same length as `columns`.
    ///
    /// Ordered only when the query contained `ORDER BY`.
    pub rows: Vec<Vec<QueryValue>>,
    /// Non-fatal findings, such as a link that could not be reached.
    pub warnings: Vec<Diagnostic>,
    /// What the query changed.
    pub writes: WriteSummary,
}

impl QueryResult {
    /// Number of rows produced.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

/// A row paired with the sort key computed for it.
type KeyedRow = (Vec<SortKey>, Vec<QueryValue>);

/// Turns one endpoint into a scoped handle, or `None` when its source was not opened.
fn resolve_endpoint(
    reference: &NodeReference,
    own_source: u32,
    index_of: &impl Fn(&CanonicalSourceLocator) -> Option<u32>,
) -> Option<ScopedNode> {
    match reference {
        NodeReference::Local(id) => Some(Scoped {
            source: own_source,
            id: *id,
        }),
        NodeReference::External(scoped) => index_of(&scoped.source).map(|source| Scoped {
            source,
            id: scoped.local,
        }),
    }
}

struct Executor<'a> {
    /// Every source a read may see. Index zero is always the root.
    sources: Vec<&'a Graph>,
    /// The locator of each source. The root has none.
    locators: Vec<Option<&'a CanonicalSourceLocator>>,
    parameters: &'a Parameters,
    context: &'a DatabaseContext,
    nodes: BTreeMap<ScopedNode, &'a Node>,
    edges: BTreeMap<ScopedEdge, &'a Edge>,
    outgoing: BTreeMap<ScopedNode, Vec<ScopedEdge>>,
    incoming: BTreeMap<ScopedNode, Vec<ScopedEdge>>,
}

impl<'a> Executor<'a> {
    /// Indexes the root and every linked source.
    ///
    /// An edge's endpoint is resolved here rather than during traversal, because an
    /// external reference names another source by locator and that lookup should happen
    /// once. An endpoint naming a source that was not opened is dropped: the edge stays
    /// in its own source's records, and traversal simply cannot leave through it, which
    /// is what a partial result means.
    fn new(
        sources: Vec<(Option<&'a CanonicalSourceLocator>, &'a Graph)>,
        parameters: &'a Parameters,
        context: &'a DatabaseContext,
    ) -> Self {
        let locators: Vec<Option<&CanonicalSourceLocator>> =
            sources.iter().map(|(locator, _)| *locator).collect();
        let graphs: Vec<&Graph> = sources.iter().map(|(_, graph)| *graph).collect();

        let index_of = |locator: &CanonicalSourceLocator| -> Option<u32> {
            locators
                .iter()
                .position(|held| held.is_some_and(|held| held == locator))
                .and_then(|position| u32::try_from(position).ok())
        };

        let mut nodes = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut outgoing: BTreeMap<ScopedNode, Vec<ScopedEdge>> = BTreeMap::new();
        let mut incoming: BTreeMap<ScopedNode, Vec<ScopedEdge>> = BTreeMap::new();

        for (position, graph) in graphs.iter().enumerate() {
            let source = u32::try_from(position).unwrap_or(u32::MAX);
            for node in &graph.nodes {
                nodes.insert(
                    Scoped {
                        source,
                        id: node.id,
                    },
                    node,
                );
            }
            for edge in &graph.edges {
                let handle = Scoped {
                    source,
                    id: edge.id,
                };
                edges.insert(handle, edge);
                if let Some(from) = resolve_endpoint(&edge.source, source, &index_of) {
                    outgoing.entry(from).or_default().push(handle);
                }
                if let Some(to) = resolve_endpoint(&edge.target, source, &index_of) {
                    incoming.entry(to).or_default().push(handle);
                }
            }
        }

        Self {
            sources: graphs,
            locators,
            parameters,
            context,
            nodes,
            edges,
            outgoing,
            incoming,
        }
    }

    /// The root graph, which is the only one a write may touch.
    fn root(&self) -> &'a Graph {
        self.sources[0]
    }

    /// The locator of a bound record's source, when it is not the root.
    fn locator_of(&self, source: u32) -> Option<&'a CanonicalSourceLocator> {
        self.locators.get(source as usize).copied().flatten()
    }

    fn node_matches(
        &self,
        node: &Node,
        pattern: &NodePattern,
        bindings: &Bindings,
    ) -> Result<bool, QueryError> {
        if !pattern
            .labels
            .iter()
            .all(|wanted| node.labels.iter().any(|label| label.as_str() == wanted))
        {
            return Ok(false);
        }
        self.properties_match(&node.properties, &pattern.properties, bindings)
    }

    /// Whether a stored property set satisfies an inline map.
    ///
    /// A map in a reading clause is a filter on equality, per query contract section 8. A
    /// `null` value is refused rather than compared, because no stored property can equal
    /// it and silently matching nothing would look like an empty database.
    fn properties_match(
        &self,
        stored: &[(crate::name::PropertyKey, PropertyValue)],
        wanted: &[(String, Expression)],
        bindings: &Bindings,
    ) -> Result<bool, QueryError> {
        for (key, expression) in wanted {
            let expected = self.evaluate(expression, bindings)?;
            if expected == QueryValue::Null {
                return Err(unbound(format!(
                    "the property `{key}` in a pattern is null, and no stored property can \
                     equal null"
                )));
            }
            let found = stored
                .iter()
                .find(|(stored_key, _)| stored_key.as_str() == key)
                .map(|(_, value)| QueryValue::from_property(value));
            if found != Some(expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Every edge leaving `from` that the pattern admits, with the node it reaches.
    ///
    /// Both handles are scoped, so a traversal that crosses into a linked source keeps
    /// saying which source each record came from.
    fn edges_from(
        &self,
        from: ScopedNode,
        pattern: &RelationshipPattern,
        bindings: &Bindings,
    ) -> Result<Vec<(ScopedEdge, ScopedNode)>, QueryError> {
        let mut found = Vec::new();
        let type_matches = |edge: &Edge| {
            pattern.types.is_empty()
                || pattern
                    .types
                    .iter()
                    .any(|wanted| edge.relation.as_str() == wanted)
        };

        let consider = |handles: Option<&Vec<ScopedEdge>>,
                        take_target: bool,
                        found: &mut Vec<(ScopedEdge, ScopedNode)>|
         -> Result<(), QueryError> {
            for handle in handles.into_iter().flatten() {
                let Some(edge) = self.edges.get(handle) else {
                    continue;
                };
                if !type_matches(edge)
                    || !self.properties_match(&edge.properties, &pattern.properties, bindings)?
                {
                    continue;
                }
                let reference = if take_target {
                    &edge.target
                } else {
                    &edge.source
                };
                if let Some(other) = self.endpoint(reference, handle.source) {
                    found.push((*handle, other));
                }
            }
            Ok(())
        };

        if matches!(pattern.direction, Direction::Outgoing | Direction::Either) {
            consider(self.outgoing.get(&from), true, &mut found)?;
        }
        if matches!(pattern.direction, Direction::Incoming | Direction::Either) {
            consider(self.incoming.get(&from), false, &mut found)?;
        }
        Ok(found)
    }

    /// Answers `nostdb.source` and `nostdb.link_alias` from a bound record's own source.
    ///
    /// Returns `None` for anything else, so the caller falls through to the procedure
    /// registry. A record of the root reports the root's own locator, which is what
    /// `DatabaseContext` carries; a record reached through a link reports that link's.
    fn source_function(&self, lower: &str, values: &[QueryValue]) -> Option<QueryValue> {
        if !matches!(lower, "nostdb.source" | "nostdb.link_alias") {
            return None;
        }
        let source = match values.first() {
            Some(QueryValue::Node(handle)) => handle.source,
            Some(QueryValue::Relationship(handle)) => handle.source,
            // A null argument yields null rather than failing, so an unmatched
            // `OPTIONAL MATCH` row can still be piped in.
            Some(QueryValue::Null) | None => return Some(QueryValue::Null),
            Some(_) => return None,
        };

        Some(match (lower, self.locator_of(source)) {
            // A root record was not reached through a link, so it has no alias.
            ("nostdb.link_alias", None) => QueryValue::Null,
            ("nostdb.link_alias", Some(locator)) => self
                .root()
                .links
                .iter()
                .find(|link| link.source == *locator)
                .and_then(|link| link.alias.as_ref())
                .map_or(QueryValue::Null, |alias| {
                    QueryValue::Text(alias.as_str().to_owned())
                }),
            (_, Some(locator)) => QueryValue::Text(locator.as_str().to_owned()),
            (_, None) => self
                .context
                .source
                .as_ref()
                .map_or(QueryValue::Null, |source| {
                    QueryValue::Text(source.as_str().to_owned())
                }),
        })
    }

    /// Resolves an endpoint against the sources this query opened.
    fn endpoint(&self, reference: &NodeReference, own_source: u32) -> Option<ScopedNode> {
        match reference {
            NodeReference::Local(id) => Some(Scoped {
                source: own_source,
                id: *id,
            }),
            NodeReference::External(scoped) => self
                .locators
                .iter()
                .position(|held| held.is_some_and(|held| *held == scoped.source))
                .and_then(|position| u32::try_from(position).ok())
                .map(|source| Scoped {
                    source,
                    id: scoped.local,
                }),
        }
    }

    /// Enumerates every way `pattern` can be satisfied, extending `base`.
    fn match_pattern(
        &self,
        pattern: &Pattern,
        base: &Bindings,
    ) -> Result<Vec<Bindings>, QueryError> {
        let mut partial: Vec<(Bindings, ScopedNode, Vec<ScopedNode>, Vec<ScopedEdge>)> = Vec::new();

        // Every source contributes candidates, which is what makes a match federated.
        // Order across sources is not meaning: a query without ORDER BY promises a row
        // set, and the root simply happens to come first.
        for (handle, node) in &self.nodes {
            if !self.node_matches(node, &pattern.start, base)? {
                continue;
            }
            let mut bindings = base.clone();
            if let Some(name) = &pattern.start.variable {
                if let Some(existing) = bindings.get(name) {
                    if *existing != QueryValue::Node(*handle) {
                        continue;
                    }
                } else {
                    bindings.insert(name.clone(), QueryValue::Node(*handle));
                }
            }
            partial.push((bindings, *handle, vec![*handle], Vec::new()));
        }

        for (relationship, next_node) in &pattern.steps {
            let mut extended = Vec::new();
            for (bindings, current, path_nodes, path_edges) in partial {
                let reached = match relationship.length {
                    None => self
                        .edges_from(current, relationship, &bindings)?
                        .into_iter()
                        .map(|(edge, other)| (vec![edge], other))
                        .collect(),
                    Some(range) => self.walk(current, relationship, range, &bindings)?,
                };

                for (edge_ids, other) in reached {
                    let Some(node) = self.nodes.get(&other) else {
                        continue;
                    };
                    if !self.node_matches(node, next_node, &bindings)? {
                        continue;
                    }
                    let mut next_bindings = bindings.clone();
                    if let Some(name) = &next_node.variable {
                        if let Some(existing) = next_bindings.get(name) {
                            if *existing != QueryValue::Node(other) {
                                continue;
                            }
                        } else {
                            next_bindings.insert(name.clone(), QueryValue::Node(other));
                        }
                    }
                    if let Some(name) = &relationship.variable {
                        // A variable-length pattern binds a list of relationships.
                        let value = if edge_ids.len() == 1 && relationship.length.is_none() {
                            QueryValue::Relationship(edge_ids[0])
                        } else {
                            QueryValue::List(
                                edge_ids
                                    .iter()
                                    .map(|id| QueryValue::Relationship(*id))
                                    .collect(),
                            )
                        };
                        next_bindings.insert(name.clone(), value);
                    }
                    let mut next_path_nodes = path_nodes.clone();
                    next_path_nodes.push(other);
                    let mut next_path_edges = path_edges.clone();
                    next_path_edges.extend(edge_ids);
                    extended.push((next_bindings, other, next_path_nodes, next_path_edges));
                }
            }
            partial = extended;
        }

        let mut results = Vec::new();
        for (mut bindings, _, path_nodes, path_edges) in partial {
            if let Some(name) = &pattern.path_variable {
                bindings.insert(
                    name.clone(),
                    QueryValue::Path {
                        nodes: path_nodes,
                        relationships: path_edges,
                    },
                );
            }
            results.push(bindings);
        }
        Ok(results)
    }

    /// Walks a bounded variable-length pattern.
    ///
    /// The bound is what makes this terminate. A visited set per walk also prevents a
    /// cycle from producing the same node repeatedly within one path.
    fn walk(
        &self,
        from: ScopedNode,
        pattern: &RelationshipPattern,
        range: LengthRange,
        bindings: &Bindings,
    ) -> Result<Vec<(Vec<ScopedEdge>, ScopedNode)>, QueryError> {
        let mut found = Vec::new();
        // The visited set is scoped, so a walk that reaches the same identifier in two
        // sources treats them as two nodes rather than as a cycle.
        let mut frontier: Vec<(Vec<ScopedEdge>, ScopedNode, BTreeSet<ScopedNode>)> =
            vec![(Vec::new(), from, BTreeSet::from([from]))];

        for depth in 1..=range.maximum {
            let mut next = Vec::new();
            for (edges, current, visited) in frontier {
                for (edge, other) in self.edges_from(current, pattern, bindings)? {
                    if visited.contains(&other) {
                        continue;
                    }
                    let mut edge_ids = edges.clone();
                    edge_ids.push(edge);
                    let mut seen = visited.clone();
                    seen.insert(other);
                    if depth >= range.minimum {
                        found.push((edge_ids.clone(), other));
                    }
                    next.push((edge_ids, other, seen));
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        Ok(found)
    }

    fn evaluate(
        &self,
        expression: &Expression,
        bindings: &Bindings,
    ) -> Result<QueryValue, QueryError> {
        Ok(match expression {
            Expression::Integer(value) => QueryValue::Integer(*value),
            Expression::Float(text) => text
                .parse::<f64>()
                .ok()
                .and_then(|number| FiniteF64::new(number).ok().map(QueryValue::Float))
                .unwrap_or(QueryValue::Null),
            Expression::Text(value) => QueryValue::Text(value.clone()),
            Expression::Boolean(value) => QueryValue::Boolean(*value),
            Expression::Null => QueryValue::Null,
            Expression::Parameter(name) => self
                .parameters
                .get(name)
                .cloned()
                .ok_or_else(|| unbound(format!("the parameter `${name}` was not supplied")))?,
            Expression::Variable(name) => bindings
                .get(name)
                .cloned()
                .ok_or_else(|| unbound(format!("`{name}` is not bound")))?,
            Expression::Property { variable, key } => {
                let bound = bindings
                    .get(variable)
                    .ok_or_else(|| unbound(format!("`{variable}` is not bound")))?;
                self.property_of(bound, key)
            }
            Expression::List(items) => QueryValue::List(
                items
                    .iter()
                    .map(|item| self.evaluate(item, bindings))
                    .collect::<Result<_, _>>()?,
            ),
            Expression::Not(inner) => {
                QueryValue::Boolean(!self.evaluate(inner, bindings)?.is_truthy())
            }
            Expression::Call { name, arguments } => self.call(name, arguments, bindings)?,
            Expression::Binary {
                operator,
                left,
                right,
            } => self.binary(*operator, left, right, bindings)?,
        })
    }

    fn property_of(&self, bound: &QueryValue, key: &str) -> QueryValue {
        match bound {
            QueryValue::Node(id) => self
                .nodes
                .get(id)
                .and_then(|node| {
                    node.properties
                        .iter()
                        .find(|(property_key, _)| property_key.as_str() == key)
                })
                .map_or(QueryValue::Null, |(_, value)| {
                    QueryValue::from_property(value)
                }),
            QueryValue::Relationship(id) => self
                .edges
                .get(id)
                .and_then(|edge| {
                    edge.properties
                        .iter()
                        .find(|(property_key, _)| property_key.as_str() == key)
                })
                .map_or(QueryValue::Null, |(_, value)| {
                    QueryValue::from_property(value)
                }),
            // A property of null is null, not an error, which is what keeps an unmatched
            // OPTIONAL MATCH row usable.
            _ => QueryValue::Null,
        }
    }

    fn call(
        &self,
        name: &str,
        arguments: &[Expression],
        bindings: &Bindings,
    ) -> Result<QueryValue, QueryError> {
        let lower = name.to_ascii_lowercase();

        // An aggregate reaching here would mean a projection failed to group it, which the
        // parser and the projection between them prevent. Refusing rather than evaluating
        // it row by row keeps a grouping mistake from returning a plausible number.
        if is_aggregate(&lower) {
            return Err(QueryError::at(
                DiagnosticCode::CypherSemanticError,
                format!("`{name}` is an aggregate and is not allowed here"),
                SourceRange::ORIGIN,
            ));
        }

        let values: Vec<QueryValue> = arguments
            .iter()
            .map(|argument| self.evaluate(argument, bindings))
            .collect::<Result<_, _>>()?;

        if lower.starts_with(procedure::NAMESPACE) {
            // Two functions answer questions about *where* a record came from, and only
            // the executor knows: the bound handle carries a source index, and the
            // locators live here. Everything else is about the record's content and is
            // answered against the graph holding it.
            if let Some(answer) = self.source_function(&lower, &values) {
                return Ok(answer);
            }
            return procedure::function(
                &lower,
                &values,
                self.root(),
                self.context,
                SourceRange::ORIGIN,
            );
        }
        if !SCALAR_FUNCTIONS.contains(&lower.as_str()) {
            return Err(QueryError::at(
                DiagnosticCode::CypherSemanticError,
                format!("unknown function `{name}`"),
                SourceRange::ORIGIN,
            ));
        }

        let first = values.first().cloned().unwrap_or(QueryValue::Null);

        Ok(match lower.as_str() {
            "toupper" => match first {
                QueryValue::Text(text) => QueryValue::Text(text.to_uppercase()),
                _ => QueryValue::Null,
            },
            "tolower" => match first {
                QueryValue::Text(text) => QueryValue::Text(text.to_lowercase()),
                _ => QueryValue::Null,
            },
            "size" => match first {
                QueryValue::List(items) => QueryValue::Integer(items.len() as i64),
                QueryValue::Text(text) => QueryValue::Integer(text.chars().count() as i64),
                _ => QueryValue::Null,
            },
            "labels" => match first {
                QueryValue::Node(id) => self.nodes.get(&id).map_or(QueryValue::Null, |node| {
                    QueryValue::List(
                        node.labels
                            .iter()
                            .map(|label| QueryValue::Text(label.as_str().to_owned()))
                            .collect(),
                    )
                }),
                _ => QueryValue::Null,
            },
            "type" => match first {
                QueryValue::Relationship(id) => {
                    self.edges.get(&id).map_or(QueryValue::Null, |edge| {
                        QueryValue::Text(edge.relation.as_str().to_owned())
                    })
                }
                _ => QueryValue::Null,
            },
            // `coalesce` returns its first non-null argument.
            _ => values
                .into_iter()
                .find(|value| *value != QueryValue::Null)
                .unwrap_or(QueryValue::Null),
        })
    }

    fn binary(
        &self,
        operator: BinaryOperator,
        left: &Expression,
        right: &Expression,
        bindings: &Bindings,
    ) -> Result<QueryValue, QueryError> {
        // Short-circuit, so `false AND <unbound>` does not fail on the unbound side.
        if operator == BinaryOperator::And {
            let left_value = self.evaluate(left, bindings)?;
            if !left_value.is_truthy() {
                return Ok(QueryValue::Boolean(false));
            }
            return Ok(QueryValue::Boolean(
                self.evaluate(right, bindings)?.is_truthy(),
            ));
        }
        if operator == BinaryOperator::Or {
            let left_value = self.evaluate(left, bindings)?;
            if left_value.is_truthy() {
                return Ok(QueryValue::Boolean(true));
            }
            return Ok(QueryValue::Boolean(
                self.evaluate(right, bindings)?.is_truthy(),
            ));
        }

        let left_value = self.evaluate(left, bindings)?;
        let right_value = self.evaluate(right, bindings)?;

        Ok(match operator {
            BinaryOperator::Equal => QueryValue::Boolean(left_value == right_value),
            BinaryOperator::NotEqual => QueryValue::Boolean(left_value != right_value),
            BinaryOperator::Less
            | BinaryOperator::LessEqual
            | BinaryOperator::Greater
            | BinaryOperator::GreaterEqual => {
                // A comparison against null is null in Cypher, and null is not truthy, so
                // the row simply does not pass.
                if left_value == QueryValue::Null || right_value == QueryValue::Null {
                    return Ok(QueryValue::Null);
                }
                let ordering = left_value.sort_key().cmp(&right_value.sort_key());
                QueryValue::Boolean(match operator {
                    BinaryOperator::Less => ordering.is_lt(),
                    BinaryOperator::LessEqual => ordering.is_le(),
                    BinaryOperator::Greater => ordering.is_gt(),
                    _ => ordering.is_ge(),
                })
            }
            BinaryOperator::In => match right_value {
                QueryValue::List(items) => QueryValue::Boolean(items.contains(&left_value)),
                _ => QueryValue::Null,
            },
            BinaryOperator::Add
            | BinaryOperator::Subtract
            | BinaryOperator::Multiply
            | BinaryOperator::Divide
            | BinaryOperator::Modulo => arithmetic(operator, &left_value, &right_value),
            BinaryOperator::And | BinaryOperator::Or => QueryValue::Null,
        })
    }

    /// Every inline map in a pattern, evaluated against one row.
    ///
    /// A write needs these before the graph is borrowed mutably, which is why they are
    /// values here rather than expressions the writer would evaluate later.
    fn pattern_values(
        &self,
        pattern: &Pattern,
        bindings: &Bindings,
    ) -> Result<PatternValues, QueryError> {
        let mut steps = Vec::with_capacity(pattern.steps.len());
        for (relationship, node) in &pattern.steps {
            steps.push((
                self.map_values(&relationship.properties, bindings)?,
                self.map_values(&node.properties, bindings)?,
            ));
        }
        Ok(PatternValues {
            start: self.map_values(&pattern.start.properties, bindings)?,
            steps,
        })
    }

    fn map_values(
        &self,
        map: &[(String, Expression)],
        bindings: &Bindings,
    ) -> Result<Vec<(String, QueryValue)>, QueryError> {
        map.iter()
            .map(|(key, expression)| Ok((key.clone(), self.evaluate(expression, bindings)?)))
            .collect()
    }

    /// Runs a `CALL`, once per incoming row.
    ///
    /// A procedure yielding no row for an incoming row drops that row, which is what a
    /// `CALL` means in Cypher.
    fn run_call(
        &self,
        call: &ProcedureCall,
        rows: Vec<Bindings>,
    ) -> Result<(Vec<String>, Vec<Bindings>), QueryError> {
        let found = procedure::lookup(&call.name, call.range)?;

        let kept: Vec<(usize, String)> = if call.yields.is_empty() {
            found
                .columns
                .iter()
                .enumerate()
                .map(|(index, column)| (index, (*column).to_owned()))
                .collect()
        } else {
            call.yields
                .iter()
                .map(|item| {
                    let index = found
                        .columns
                        .iter()
                        .position(|column| *column == item.column)
                        .ok_or_else(|| {
                            QueryError::at(
                                DiagnosticCode::CypherSemanticError,
                                format!(
                                    "`{}` yields no column `{}`; it yields {}",
                                    found.name,
                                    item.column,
                                    found.columns.join(", ")
                                ),
                                call.range,
                            )
                        })?;
                    Ok((index, item.bound_name().to_owned()))
                })
                .collect::<Result<_, QueryError>>()?
        };
        let names: Vec<String> = kept.iter().map(|(_, name)| name.clone()).collect();

        let mut next = Vec::new();
        for row in rows {
            let arguments: Vec<QueryValue> = call
                .arguments
                .iter()
                .map(|argument| self.evaluate(argument, &row))
                .collect::<Result<_, _>>()?;
            for produced in
                procedure::run(found, &arguments, self.root(), self.context, call.range)?
            {
                let mut extended = row.clone();
                for (index, name) in &kept {
                    extended.insert(
                        name.clone(),
                        produced.get(*index).cloned().unwrap_or(QueryValue::Null),
                    );
                }
                next.push(extended);
            }
        }
        Ok((names, next))
    }
}

fn arithmetic(operator: BinaryOperator, left: &QueryValue, right: &QueryValue) -> QueryValue {
    // Text concatenation is the one non-numeric addition Cypher defines.
    if operator == BinaryOperator::Add
        && let (QueryValue::Text(a), QueryValue::Text(b)) = (left, right)
    {
        return QueryValue::Text(format!("{a}{b}"));
    }
    let (QueryValue::Integer(a), QueryValue::Integer(b)) = (left, right) else {
        return QueryValue::Null;
    };
    let result = match operator {
        BinaryOperator::Add => a.checked_add(*b),
        BinaryOperator::Subtract => a.checked_sub(*b),
        BinaryOperator::Multiply => a.checked_mul(*b),
        BinaryOperator::Divide => a.checked_div(*b),
        BinaryOperator::Modulo => a.checked_rem(*b),
        _ => None,
    };
    // Overflow and division by zero produce null rather than a panic.
    result.map_or(QueryValue::Null, QueryValue::Integer)
}

/// Every variable a set of patterns would bind, including relationship and path names.
fn pattern_variables(patterns: &[Pattern]) -> Vec<String> {
    let mut names = Vec::new();
    for pattern in patterns {
        names.extend(pattern.path_variable.clone());
        names.extend(pattern.start.variable.clone());
        for (relationship, node) in &pattern.steps {
            names.extend(relationship.variable.clone());
            names.extend(node.variable.clone());
        }
    }
    names
}

fn unbound(message: String) -> QueryError {
    QueryError::at(
        DiagnosticCode::CypherSemanticError,
        message,
        SourceRange::ORIGIN,
    )
}

/// How an aggregate is stood in for while a projection is evaluated.
///
/// A `\0` cannot appear in a name the lexer produces, so a placeholder cannot collide with
/// a variable a caller wrote.
fn placeholder(index: usize) -> String {
    format!("\u{0}aggregate{index}")
}

/// A projection that aggregates, decomposed so each part can be evaluated separately.
struct Aggregation {
    /// Each projected expression, with every aggregate replaced by a placeholder.
    items: Vec<Expression>,
    /// The aggregate calls, in placeholder order.
    calls: Vec<(String, Vec<Expression>)>,
    /// Indices of the items carrying no aggregate. These are the grouping key.
    grouping: Vec<usize>,
}

/// Decomposes a projection, or `None` when it does not aggregate.
fn plan_aggregation(items: &[ProjectionItem]) -> Option<Aggregation> {
    if !items
        .iter()
        .any(|item| item.expression.contains_aggregate())
    {
        return None;
    }
    let mut calls = Vec::new();
    let mut rewritten = Vec::with_capacity(items.len());
    let mut grouping = Vec::new();
    for (index, item) in items.iter().enumerate() {
        if !item.expression.contains_aggregate() {
            grouping.push(index);
        }
        rewritten.push(lift_aggregates(&item.expression, &mut calls));
    }
    Some(Aggregation {
        items: rewritten,
        calls,
        grouping,
    })
}

/// Replaces each aggregate call with a placeholder, collecting the calls.
fn lift_aggregates(
    expression: &Expression,
    calls: &mut Vec<(String, Vec<Expression>)>,
) -> Expression {
    match expression {
        Expression::Call { name, arguments } if is_aggregate(name) => {
            calls.push((name.clone(), arguments.clone()));
            Expression::Variable(placeholder(calls.len() - 1))
        }
        Expression::Call { name, arguments } => Expression::Call {
            name: name.clone(),
            arguments: arguments
                .iter()
                .map(|argument| lift_aggregates(argument, calls))
                .collect(),
        },
        Expression::List(items) => Expression::List(
            items
                .iter()
                .map(|item| lift_aggregates(item, calls))
                .collect(),
        ),
        Expression::Not(inner) => Expression::Not(Box::new(lift_aggregates(inner, calls))),
        Expression::Binary {
            operator,
            left,
            right,
        } => Expression::Binary {
            operator: *operator,
            left: Box::new(lift_aggregates(left, calls)),
            right: Box::new(lift_aggregates(right, calls)),
        },
        other => other.clone(),
    }
}

/// Folds one aggregate over the rows of one group.
fn fold_aggregate(
    executor: &Executor<'_>,
    name: &str,
    arguments: &[Expression],
    group: &[Bindings],
) -> Result<QueryValue, QueryError> {
    let lower = name.to_ascii_lowercase();
    let star = matches!(arguments, [Expression::Variable(only)] if only == STAR_ARGUMENT);

    if star {
        if lower != "count" {
            return Err(unbound(format!(
                "`{name}(*)` is not defined; only `count(*)` is"
            )));
        }
        // count(*) counts rows, including a row whose every value is null.
        return Ok(QueryValue::Integer(group.len() as i64));
    }
    let [argument] = arguments else {
        return Err(unbound(format!(
            "`{name}` takes one argument, and {} were given",
            arguments.len()
        )));
    };

    // Every aggregate but count(*) ignores null rather than treating it as a value.
    let mut values = Vec::with_capacity(group.len());
    for bindings in group {
        let value = executor.evaluate(argument, bindings)?;
        if value != QueryValue::Null {
            values.push(value);
        }
    }

    Ok(match lower.as_str() {
        "count" => QueryValue::Integer(values.len() as i64),
        "collect" => QueryValue::List(values),
        "min" => values
            .into_iter()
            .min_by_key(QueryValue::sort_key)
            .unwrap_or(QueryValue::Null),
        "max" => values
            .into_iter()
            .max_by_key(QueryValue::sort_key)
            .unwrap_or(QueryValue::Null),
        "sum" => numeric_total(name, &values)?.map_or(QueryValue::Integer(0), |total| total),
        // The mean of nothing is not zero, so avg over no values is null rather than 0.
        _ => {
            let count = values.len();
            if count == 0 {
                QueryValue::Null
            } else {
                let total = numeric_sum(name, &values)?;
                FiniteF64::new(total / count as f64).map_or(QueryValue::Null, QueryValue::Float)
            }
        }
    })
}

/// The total of numeric values, as an integer when every value was one and it fits.
fn numeric_total(name: &str, values: &[QueryValue]) -> Result<Option<QueryValue>, QueryError> {
    if values.is_empty() {
        return Ok(None);
    }
    let mut integers: i128 = 0;
    let mut floats = 0.0_f64;
    let mut saw_float = false;
    for value in values {
        match numeric(name, value)? {
            Number::Integer(inner) => integers += i128::from(inner),
            Number::Float(inner) => {
                saw_float = true;
                floats += inner;
            }
        }
    }
    if !saw_float && let Ok(exact) = i64::try_from(integers) {
        return Ok(Some(QueryValue::Integer(exact)));
    }
    Ok(Some(
        FiniteF64::new(integers as f64 + floats).map_or(QueryValue::Null, QueryValue::Float),
    ))
}

fn numeric_sum(name: &str, values: &[QueryValue]) -> Result<f64, QueryError> {
    let mut total = 0.0_f64;
    for value in values {
        total += match numeric(name, value)? {
            Number::Integer(inner) => inner as f64,
            Number::Float(inner) => inner,
        };
    }
    Ok(total)
}

fn numeric(name: &str, value: &QueryValue) -> Result<Number, QueryError> {
    value.as_number().ok_or_else(|| {
        unbound(format!(
            "`{name}` takes numbers, and one value was {}",
            value.kind_name()
        ))
    })
}

fn apply_projection(
    executor: &Executor<'_>,
    projection: &Projection,
    rows: Vec<Bindings>,
) -> Result<(Vec<String>, Vec<Vec<QueryValue>>), QueryError> {
    let columns: Vec<String> = projection.items.iter().map(column_name).collect();

    let mut projected: Vec<(Vec<QueryValue>, Bindings)> = match plan_aggregation(&projection.items)
    {
        Some(plan) => aggregate_rows(executor, projection, &plan, &columns, rows)?,
        None => {
            // Projection happens before the predicate and the sort keys are evaluated,
            // because a `WITH ... WHERE` and an `ORDER BY` may both name a column the
            // projection introduced. Evaluating the predicate first would leave that alias
            // unbound.
            //
            // The scope used for both is the incoming bindings plus the new column names,
            // so `ORDER BY n.age` still works alongside `ORDER BY alias`.
            let mut plain = Vec::with_capacity(rows.len());
            for bindings in rows {
                let mut row = Vec::with_capacity(projection.items.len());
                for item in &projection.items {
                    row.push(executor.evaluate(&item.expression, &bindings)?);
                }
                let mut scope = bindings;
                for (name, value) in columns.iter().zip(&row) {
                    scope.insert(name.clone(), value.clone());
                }
                plain.push((row, scope));
            }
            plain
        }
    };

    if let Some(predicate) = &projection.predicate {
        let mut kept = Vec::new();
        for (row, scope) in projected {
            if executor.evaluate(predicate, &scope)?.is_truthy() {
                kept.push((row, scope));
            }
        }
        projected = kept;
    }

    if projection.distinct {
        let mut seen: BTreeSet<Vec<SortKey>> = BTreeSet::new();
        projected.retain(|(row, _)| seen.insert(row.iter().map(QueryValue::sort_key).collect()));
    }

    if !projection.order_by.is_empty() {
        let mut keyed: Vec<KeyedRow> = Vec::new();
        for (row, bindings) in projected {
            let mut key = Vec::with_capacity(projection.order_by.len());
            for sort in &projection.order_by {
                key.push(executor.evaluate(&sort.expression, &bindings)?.sort_key());
            }
            keyed.push((key, row));
        }
        // One comparator that knows each key's direction, rather than a reversible encoding
        // of the keys. A key is a value, not a string, so there is nothing to complement.
        keyed.sort_by(|left, right| {
            for ((left_key, right_key), sort) in
                left.0.iter().zip(&right.0).zip(&projection.order_by)
            {
                let ordering = if sort.descending {
                    right_key.cmp(left_key)
                } else {
                    left_key.cmp(right_key)
                };
                if ordering != std::cmp::Ordering::Equal {
                    return ordering;
                }
            }
            std::cmp::Ordering::Equal
        });
        projected = keyed
            .into_iter()
            .map(|(_, row)| (row, Bindings::new()))
            .collect();
    }

    let mut rows: Vec<Vec<QueryValue>> = projected.into_iter().map(|(row, _)| row).collect();

    if let Some(skip) = &projection.skip {
        let count = non_negative(executor, skip, "SKIP")?;
        rows = rows.into_iter().skip(count).collect();
    }
    if let Some(limit) = &projection.limit {
        let count = non_negative(executor, limit, "LIMIT")?;
        rows.truncate(count);
    }

    Ok((columns, rows))
}

/// Groups rows and evaluates an aggregating projection.
///
/// The scope a later `WHERE` or `ORDER BY` sees is the projected column names alone. The
/// incoming bindings no longer exist after grouping: several of them collapsed into one
/// row, so naming one would be naming an arbitrary member of the group.
fn aggregate_rows(
    executor: &Executor<'_>,
    projection: &Projection,
    plan: &Aggregation,
    columns: &[String],
    rows: Vec<Bindings>,
) -> Result<Vec<(Vec<QueryValue>, Bindings)>, QueryError> {
    let mut groups: BTreeMap<Vec<SortKey>, Vec<Bindings>> = BTreeMap::new();
    for bindings in rows {
        let mut key = Vec::with_capacity(plan.grouping.len());
        for &index in &plan.grouping {
            key.push(
                executor
                    .evaluate(&projection.items[index].expression, &bindings)?
                    .sort_key(),
            );
        }
        groups.entry(key).or_default().push(bindings);
    }

    // With no grouping key there is exactly one group, even over no rows at all: `RETURN
    // count(*)` over an empty graph answers zero rather than answering nothing.
    if groups.is_empty() && plan.grouping.is_empty() {
        groups.insert(Vec::new(), Vec::new());
    }

    let mut output = Vec::with_capacity(groups.len());
    for group in groups.into_values() {
        // A grouping-key expression evaluates identically across the group by
        // construction, so the first row answers for all of them.
        let mut scope = group.first().cloned().unwrap_or_default();
        for (index, (name, arguments)) in plan.calls.iter().enumerate() {
            let value = fold_aggregate(executor, name, arguments, &group)?;
            scope.insert(placeholder(index), value);
        }

        let mut row = Vec::with_capacity(plan.items.len());
        for item in &plan.items {
            row.push(executor.evaluate(item, &scope)?);
        }

        let projected_scope: Bindings = columns.iter().cloned().zip(row.clone()).collect();
        output.push((row, projected_scope));
    }
    Ok(output)
}

fn non_negative(
    executor: &Executor<'_>,
    expression: &Expression,
    what: &str,
) -> Result<usize, QueryError> {
    let value = executor.evaluate(expression, &Bindings::new())?;
    match value {
        QueryValue::Integer(number) if number >= 0 => {
            usize::try_from(number).map_err(|_| unbound(format!("{what} is too large")))
        }
        QueryValue::Integer(_) => Err(QueryError::at(
            DiagnosticCode::CypherSemanticError,
            format!("{what} must not be negative"),
            SourceRange::ORIGIN,
        )),
        _ => Err(QueryError::at(
            DiagnosticCode::CypherSemanticError,
            format!("{what} must be an integer"),
            SourceRange::ORIGIN,
        )),
    }
}

/// Executes a parsed query against a graph, applying any writes it contains.
///
/// The graph is borrowed mutably because a query in the subset may write. A caller holding
/// a read-only graph therefore cannot execute a writing query at all, rather than being
/// told it may not.
///
/// # Errors
///
/// Returns [`DiagnosticCode::CypherSemanticError`] for a query that is in the subset but
/// meaningless: an unbound variable, a missing parameter, an unknown function or procedure,
/// a negative `SKIP` or `LIMIT`, a created node without a label, or deleting a node that
/// still has a relationship. Returns [`DiagnosticCode::CypherUnsupported`] for a procedure
/// needing a capability this build does not have.
///
/// A refusal leaves the graph as it was for every clause that had not yet run, and the
/// caller decides whether to keep the partial change or discard it. A
/// [`crate::transaction::Transaction`] discards it, which is why a write belongs in one.
pub fn execute(
    query: &Query,
    graph: &mut Graph,
    parameters: &Parameters,
    context: &DatabaseContext,
) -> Result<QueryResult, QueryError> {
    execute_federated(query, graph, &[], parameters, context)
}

/// Runs a query that can be asked to stop.
///
/// The cancellation is cooperative and is observed at part, clause, and match-row boundaries.
/// [`crate::cancel`] states the granularity and why it is stated rather than implied.
///
/// # Errors
///
/// The same as [`execute`], plus `QUERY_CANCELLED` when `cancel` asks it to stop.
pub fn execute_cancellable(
    query: &Query,
    graph: &mut Graph,
    parameters: &Parameters,
    context: &DatabaseContext,
    cancel: &dyn ShouldStop,
) -> Result<QueryResult, QueryError> {
    execute_federated_cancellable(query, graph, &[], parameters, context, cancel)
}

/// Runs a query over the root and every linked source it was given.
///
/// A read sees the union; a write touches the root alone. A write naming a record from a
/// linked source is refused with `LINKED_DATABASE_READ_ONLY`, which is the rule in root
/// PRD section 18.8 and is enforced by the type: a bound record carries its source, and
/// the writer refuses any handle whose source is not zero.
///
/// # Errors
///
/// The same as [`execute`].
pub fn execute_federated(
    query: &Query,
    graph: &mut Graph,
    linked: &[LinkedSource<'_>],
    parameters: &Parameters,
    context: &DatabaseContext,
) -> Result<QueryResult, QueryError> {
    execute_federated_cancellable(query, graph, linked, parameters, context, &Never)
}

/// Runs a federated query that can be asked to stop.
///
/// # Errors
///
/// The same as [`execute_federated`], plus `QUERY_CANCELLED` when `cancel` asks it to stop.
pub fn execute_federated_cancellable(
    query: &Query,
    graph: &mut Graph,
    linked: &[LinkedSource<'_>],
    parameters: &Parameters,
    context: &DatabaseContext,
    cancel: &dyn ShouldStop,
) -> Result<QueryResult, QueryError> {
    // Records this query creates receive a minted UUID version 7. The generation they
    // commit at no longer takes part, because an identifier is no longer derived from it.
    let mut minter = Minter::new();
    let mut writes = WriteSummary::default();

    let mut columns: Vec<String> = Vec::new();
    let mut all_rows: Vec<Vec<QueryValue>> = Vec::new();

    for (index, part) in query.parts.iter().enumerate() {
        stop_if_asked(cancel)?;
        let (part_columns, part_rows) = run_part(
            part,
            graph,
            &Run {
                linked,
                parameters,
                context,
                cancel,
            },
            &mut minter,
            &mut writes,
        )?;
        if index == 0 {
            columns = part_columns;
        }
        all_rows.extend(part_rows);
    }

    // A UNION without ALL removes duplicates across the whole result.
    if query.union_all.iter().any(|all| !all) {
        let mut seen: BTreeSet<Vec<SortKey>> = BTreeSet::new();
        all_rows.retain(|row| seen.insert(row.iter().map(QueryValue::sort_key).collect()));
    }

    // A label no record carries, reported after execution rather than refused before it.
    //
    // Zero rows is otherwise indistinguishable from zero rows: nothing in the result tells a caller
    // whether the project has none of that thing or whether the word means nothing to this database.
    // Both are legitimate answers and they call for opposite responses.
    //
    // Every label in the graph, not only the ones this query bound, because a pattern that matched
    // nothing never reaches the matcher — and that is exactly the case worth reporting.
    let present: BTreeSet<&str> = graph
        .nodes
        .iter()
        .flat_map(|node| node.labels.iter())
        .map(crate::name::Label::as_str)
        .collect();
    let warnings = query
        .required_labels()
        .into_iter()
        .filter(|wanted| !present.contains(wanted))
        .map(|absent| {
            Diagnostic::new(
                DiagnosticCode::CypherUnknownLabel,
                crate::text::NonEmptyText::new(format!(
                    "no record in this database carries the label `{absent}`"
                ))
                .unwrap_or_else(|_| crate::text::NonEmptyText::literal("unknown label")),
            )
        })
        .collect();

    Ok(QueryResult {
        columns,
        rows: all_rows,
        warnings,
        writes,
    })
}

/// Asks whether to stop, and reports `QUERY_CANCELLED` if so.
///
/// The range is [`SourceRange::ORIGIN`] because a cancellation is not a fault in the source:
/// nothing in the query is wrong, and pointing at a token would send a reader looking for a
/// mistake that is not there.
fn stop_if_asked(cancel: &dyn ShouldStop) -> Result<(), QueryError> {
    if cancel.should_stop() {
        return Err(QueryError::at(
            DiagnosticCode::QueryCancelled,
            cancel.reason(),
            SourceRange::ORIGIN,
        ));
    }
    Ok(())
}

/// The parts of one execution that every clause reads and no clause changes.
///
/// Grouped rather than passed one by one. Threading the cancellation token through pushed the
/// argument list past what is readable, and four of the arguments were already travelling together
/// unchanged from the top of the query to the innermost clause.
struct Run<'a> {
    linked: &'a [LinkedSource<'a>],
    parameters: &'a Parameters,
    context: &'a DatabaseContext,
    cancel: &'a dyn ShouldStop,
}

fn run_part(
    part: &QueryPart,
    graph: &mut Graph,
    run: &Run<'_>,
    minter: &mut Minter,
    writes: &mut WriteSummary,
) -> Result<(Vec<String>, Vec<Vec<QueryValue>>), QueryError> {
    let mut rows: Vec<Bindings> = vec![Bindings::new()];
    // Set only while the most recent clause was a `CALL`, so a trailing call can produce
    // the part's columns without a `RETURN`.
    let mut call_columns: Option<Vec<String>> = None;

    for clause in &part.clauses {
        stop_if_asked(run.cancel)?;
        let was_call = matches!(clause, Clause::Call(_));
        match clause {
            Clause::Match {
                optional,
                patterns,
                predicate,
            } => {
                let executor =
                    Executor::new(source_list(graph, run.linked), run.parameters, run.context);
                rows = run_match(
                    &executor,
                    *optional,
                    patterns,
                    predicate.as_ref(),
                    rows,
                    run.cancel,
                )?;
            }
            Clause::Unwind { list, variable } => {
                let executor =
                    Executor::new(source_list(graph, run.linked), run.parameters, run.context);
                let mut next = Vec::new();
                for bindings in rows {
                    // UNWIND of a non-list produces no rows, matching Cypher's treatment
                    // of null.
                    if let QueryValue::List(items) = executor.evaluate(list, &bindings)? {
                        for item in items {
                            let mut extended = bindings.clone();
                            extended.insert(variable.clone(), item);
                            next.push(extended);
                        }
                    }
                }
                rows = next;
            }
            Clause::With(projection) => {
                let executor =
                    Executor::new(source_list(graph, run.linked), run.parameters, run.context);
                let (names, projected) = apply_projection(&executor, projection, rows)?;
                // WITH opens a new scope: only the projected names survive.
                rows = projected
                    .into_iter()
                    .map(|row| names.iter().cloned().zip(row).collect::<Bindings>())
                    .collect();
            }
            Clause::Call(call) => {
                let executor =
                    Executor::new(source_list(graph, run.linked), run.parameters, run.context);
                let (names, next) = executor.run_call(call, rows)?;
                rows = next;
                call_columns = Some(names);
            }
            Clause::Create { patterns, range } => {
                // Every map value is evaluated against the graph as this clause found it,
                // so one row's write cannot change what another row assigns.
                let evaluated: Vec<Vec<PatternValues>> = {
                    let executor =
                        Executor::new(source_list(graph, run.linked), run.parameters, run.context);
                    rows.iter()
                        .map(|bindings| {
                            patterns
                                .iter()
                                .map(|pattern| executor.pattern_values(pattern, bindings))
                                .collect::<Result<_, _>>()
                        })
                        .collect::<Result<_, _>>()?
                };
                let mut writer = Writer::new(graph, minter, writes);
                for (bindings, values) in rows.iter_mut().zip(evaluated) {
                    for (pattern, value) in patterns.iter().zip(&values) {
                        writer.create(pattern, bindings, value, *range)?;
                    }
                }
            }
            Clause::Merge { pattern, range } => {
                // Matching per row is what keeps a repeated row from creating a duplicate:
                // the second row finds what the first one created.
                let mut next = Vec::with_capacity(rows.len());
                for bindings in rows {
                    let found = {
                        let executor = Executor::new(
                            source_list(graph, run.linked),
                            run.parameters,
                            run.context,
                        );
                        executor.match_pattern(pattern, &bindings)?
                    };
                    if !found.is_empty() {
                        next.extend(found);
                        continue;
                    }
                    let values = {
                        let executor = Executor::new(
                            source_list(graph, run.linked),
                            run.parameters,
                            run.context,
                        );
                        executor.pattern_values(pattern, &bindings)?
                    };
                    let mut created = bindings;
                    let mut writer = Writer::new(graph, minter, writes);
                    writer.create(pattern, &mut created, &values, *range)?;
                    next.push(created);
                }
                rows = next;
            }
            Clause::Set { items, range } => {
                let evaluated: Vec<Vec<Option<QueryValue>>> = {
                    let executor =
                        Executor::new(source_list(graph, run.linked), run.parameters, run.context);
                    rows.iter()
                        .map(|bindings| {
                            items
                                .iter()
                                .map(|item| match set_value(item) {
                                    Some(expression) => {
                                        executor.evaluate(expression, bindings).map(Some)
                                    }
                                    None => Ok(None),
                                })
                                .collect::<Result<_, _>>()
                        })
                        .collect::<Result<_, _>>()?
                };
                let mut writer = Writer::new(graph, minter, writes);
                for (bindings, values) in rows.iter().zip(evaluated) {
                    for (item, value) in items.iter().zip(values) {
                        let variable = set_variable(item);
                        let bound = bindings
                            .get(variable)
                            .cloned()
                            .ok_or_else(|| unbound(format!("`{variable}` is not bound")))?;
                        writer.set(item, variable, &bound, value, *range)?;
                    }
                }
            }
            Clause::Remove { items, range } => {
                let mut writer = Writer::new(graph, minter, writes);
                for bindings in &rows {
                    for item in items {
                        let variable = remove_variable(item);
                        let bound = bindings
                            .get(variable)
                            .cloned()
                            .ok_or_else(|| unbound(format!("`{variable}` is not bound")))?;
                        writer.remove(item, variable, &bound, *range)?;
                    }
                }
            }
            Clause::Delete {
                detach,
                targets,
                range,
            } => {
                let evaluated: Vec<Vec<QueryValue>> = {
                    let executor =
                        Executor::new(source_list(graph, run.linked), run.parameters, run.context);
                    rows.iter()
                        .map(|bindings| {
                            targets
                                .iter()
                                .map(|target| executor.evaluate(target, bindings))
                                .collect::<Result<_, _>>()
                        })
                        .collect::<Result<_, _>>()?
                };
                let mut writer = Writer::new(graph, minter, writes);
                for values in evaluated {
                    for value in values {
                        writer.delete(&value, *detach, *range)?;
                    }
                }
            }
        }
        if !was_call {
            call_columns = None;
        }
    }

    match &part.result {
        Some(projection) => {
            let executor =
                Executor::new(source_list(graph, run.linked), run.parameters, run.context);
            apply_projection(&executor, projection, rows)
        }
        // A trailing `CALL` produces the columns it yields.
        None => match call_columns {
            Some(names) => {
                let values = rows
                    .into_iter()
                    .map(|row| {
                        names
                            .iter()
                            .map(|name| row.get(name).cloned().unwrap_or(QueryValue::Null))
                            .collect()
                    })
                    .collect();
                Ok((names, values))
            }
            // A write with no `RETURN` reports itself through the write summary.
            None => Ok((Vec::new(), Vec::new())),
        },
    }
}

fn run_match(
    executor: &Executor<'_>,
    optional: bool,
    patterns: &[Pattern],
    predicate: Option<&Expression>,
    rows: Vec<Bindings>,
    cancel: &dyn ShouldStop,
) -> Result<Vec<Bindings>, QueryError> {
    let mut next = Vec::new();
    for bindings in rows {
        stop_if_asked(cancel)?;
        let mut expanded = vec![bindings.clone()];
        for pattern in patterns {
            let mut grown = Vec::new();
            for candidate in &expanded {
                grown.extend(executor.match_pattern(pattern, candidate)?);
            }
            expanded = grown;
        }
        if let Some(predicate) = predicate {
            let mut kept = Vec::new();
            for candidate in expanded {
                if executor.evaluate(predicate, &candidate)?.is_truthy() {
                    kept.push(candidate);
                }
            }
            expanded = kept;
        }
        if expanded.is_empty() && optional {
            // An unmatched optional pattern keeps the row and binds every variable the
            // pattern would have introduced to null. Leaving them absent instead would make
            // a later `x.name` an unbound variable error rather than the null the language
            // promises.
            let mut widened = bindings;
            for name in pattern_variables(patterns) {
                widened.entry(name).or_insert(QueryValue::Null);
            }
            next.push(widened);
        } else {
            next.extend(expanded);
        }
    }
    Ok(next)
}

/// The column names a projection produces, for a caller that needs them without executing.
#[must_use]
pub fn projected_columns(projection: &Projection) -> Vec<String> {
    column_names(projection)
}

#[cfg(test)]
mod tests {
    /// A label no record carries warns, and one that is carried does not.
    ///
    /// The case this exists for: `MATCH (e:Endpoint)` returned zero rows, the empty table looked like a
    /// data problem, and the diagnosis produced from it named the wrong cause. Nothing in the result had
    /// said the label was unknown.
    #[test]
    fn a_label_no_record_carries_warns_and_still_executes() {
        let mut graph = Graph::default();
        graph.nodes.push(node(1, &["File"], &[]));

        let query = crate::cypher::parse("MATCH (n:Endpoint) RETURN n").expect("parses");
        let result = super::execute(
            &query,
            &mut graph,
            &Parameters::default(),
            &DatabaseContext::default(),
        )
        .expect("it executes rather than refusing");
        assert!(result.rows.is_empty(), "and finds nothing");
        assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
        assert_eq!(
            result.warnings[0].code.as_str(),
            "CYPHER_UNKNOWN_LABEL",
            "{:?}",
            result.warnings[0]
        );
        assert!(
            result.warnings[0].message.as_str().contains("Endpoint"),
            "it names the label: {:?}",
            result.warnings[0]
        );

        // A label the database does carry warns about nothing, even when the match finds no rows for
        // another reason. Absence of records is not absence of the label.
        let query = crate::cypher::parse("MATCH (n:File) WHERE n.path = 'absent' RETURN n")
            .expect("parses");
        let result = super::execute(
            &query,
            &mut graph,
            &Parameters::default(),
            &DatabaseContext::default(),
        )
        .expect("executes");
        assert!(result.rows.is_empty());
        assert!(
            result.warnings.is_empty(),
            "a carried label warns about nothing: {:?}",
            result.warnings
        );
    }

    #[test]
    fn a_label_a_query_creates_is_not_warned_about() {
        // The one case where absence is the expected state: the record is about to be written.
        let mut graph = Graph::default();
        let query = crate::cypher::parse("CREATE (n:Brand {name: 'x'}) RETURN n").expect("parses");
        let result = super::execute(
            &query,
            &mut graph,
            &Parameters::default(),
            &DatabaseContext::default(),
        )
        .expect("executes");
        assert!(
            result.warnings.is_empty(),
            "warning here would be warning about the record being created: {:?}",
            result.warnings
        );
    }

    use super::*;
    use crate::contribution::{Contribution, Owner};
    use crate::cypher::parse;
    use crate::id::SourceUnitId;
    use crate::link::Link;
    use crate::name::{Label, PropertyKey, RelationName};

    fn contribution() -> Contribution {
        Contribution {
            owner: Owner::user(),
            source_unit: SourceUnitId::from_bytes([1; 16]),
            evidence: Vec::new(),
        }
    }

    fn node(byte: u8, labels: &[&str], properties: &[(&str, PropertyValue)]) -> Node {
        Node {
            id: LocalNodeId::from_bytes([byte; 16]),
            labels: labels.iter().map(|l| Label::new(*l).unwrap()).collect(),
            properties: properties
                .iter()
                .map(|(key, value)| (PropertyKey::new(*key).unwrap(), value.clone()))
                .collect(),
            contributions: vec![contribution()],
        }
    }

    fn edge(byte: u8, from: u8, to: u8, relation: &str) -> Edge {
        Edge {
            id: LocalEdgeId::from_bytes([byte; 16]),
            source: NodeReference::Local(LocalNodeId::from_bytes([from; 16])),
            target: NodeReference::Local(LocalNodeId::from_bytes([to; 16])),
            relation: RelationName::new(relation).unwrap(),
            properties: Vec::new(),
            contributions: vec![contribution()],
        }
    }

    /// a:Service -> b:Service -> c:Database, plus d:Database standing alone.
    fn graph() -> Graph {
        Graph {
            nodes: vec![
                node(0xA, &["Service"], &[("name", PropertyValue::from("alpha"))]),
                node(0xB, &["Service"], &[("name", PropertyValue::from("beta"))]),
                node(
                    0xC,
                    &["Database"],
                    &[
                        ("name", PropertyValue::from("primary")),
                        ("size", PropertyValue::Integer(10)),
                    ],
                ),
                node(
                    0xD,
                    &["Database"],
                    &[
                        ("name", PropertyValue::from("lonely")),
                        ("size", PropertyValue::Integer(4)),
                    ],
                ),
            ],
            edges: vec![edge(0x1, 0xA, 0xB, "CALLS"), edge(0x2, 0xB, 0xC, "CALLS")],
            links: vec![Link::new(
                crate::locator::CanonicalSourceLocator::new("./packages/child").unwrap(),
            )],
            schemas: Vec::new(),
        }
    }

    fn run(source: &str) -> QueryResult {
        run_on(&mut graph(), source)
    }

    fn run_on(graph: &mut Graph, source: &str) -> QueryResult {
        let query = parse(source).unwrap_or_else(|error| panic!("{source}: {error}"));
        execute(
            &query,
            graph,
            &Parameters::new(),
            &DatabaseContext::default(),
        )
        .unwrap_or_else(|error| panic!("{source}: {error}"))
    }

    fn refuse(source: &str) -> QueryError {
        refuse_on(&mut graph(), source)
    }

    fn refuse_on(graph: &mut Graph, source: &str) -> QueryError {
        let query = parse(source).unwrap_or_else(|error| panic!("{source}: {error}"));
        execute(
            &query,
            graph,
            &Parameters::new(),
            &DatabaseContext::default(),
        )
        .expect_err(source)
    }

    fn run_with(source: &str, parameters: Parameters) -> QueryResult {
        let query = parse(source).unwrap();
        execute(
            &query,
            &mut graph(),
            &parameters,
            &DatabaseContext::default(),
        )
        .unwrap()
    }

    fn texts(result: &QueryResult) -> Vec<String> {
        result
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .collect()
    }

    #[test]
    fn matches_by_label_and_projects_a_property() {
        let result = run("MATCH (n:Service) RETURN n.name ORDER BY n.name");
        assert_eq!(result.columns, vec!["n.name"]);
        assert_eq!(texts(&result), vec!["alpha", "beta"]);
        assert!(result.writes.is_empty());
    }

    #[test]
    fn a_pattern_requiring_two_labels_matches_nothing_here() {
        assert_eq!(
            run("MATCH (n:Service:Database) RETURN n.name").row_count(),
            0
        );
    }

    #[test]
    fn traverses_a_relationship_in_both_directions() {
        assert_eq!(
            texts(&run(
                "MATCH (a:Service)-[:CALLS]->(b) RETURN a.name, b.name ORDER BY a.name"
            )),
            vec!["alpha|beta", "beta|primary"]
        );
        assert_eq!(
            texts(&run(
                "MATCH (a)<-[:CALLS]-(b:Service) RETURN a.name ORDER BY a.name"
            )),
            vec!["beta", "primary"]
        );
        // Undirected sees both.
        assert_eq!(
            run("MATCH (a:Service)-[:CALLS]-(b) RETURN a.name").row_count(),
            3
        );
    }

    #[test]
    fn a_bounded_variable_length_pattern_walks_up_to_its_maximum() {
        // alpha reaches beta at one hop and primary at two.
        assert_eq!(
            texts(&run(
                "MATCH (a:Service)-[:CALLS*1..2]->(b) WHERE a.name = \"alpha\" RETURN b.name ORDER BY b.name"
            )),
            vec!["beta", "primary"]
        );
        assert_eq!(
            texts(&run(
                "MATCH (a:Service)-[:CALLS*1..1]->(b) WHERE a.name = \"alpha\" RETURN b.name"
            )),
            vec!["beta"]
        );
    }

    #[test]
    fn an_optional_match_keeps_the_row_and_yields_null() {
        let result = run(
            "MATCH (d:Database) OPTIONAL MATCH (d)-[:CALLS]->(x) RETURN d.name, x.name ORDER BY d.name",
        );
        assert_eq!(texts(&result), vec!["lonely|null", "primary|null"]);
    }

    #[test]
    fn where_filters_and_null_never_passes() {
        assert_eq!(
            texts(&run("MATCH (n) WHERE n.size > 5 RETURN n.name")),
            vec!["primary"]
        );
        // alpha and beta have no `size`, so their comparison is null and the row drops.
        assert_eq!(
            run("MATCH (n) WHERE n.size < 100 RETURN n.name").row_count(),
            2
        );
    }

    #[test]
    fn distinct_removes_duplicate_rows() {
        assert_eq!(run("MATCH (n) RETURN n.name").row_count(), 4);
        assert_eq!(
            run("MATCH (a:Service)-[:CALLS]-(b) RETURN DISTINCT a.name").row_count(),
            2
        );
    }

    #[test]
    fn order_by_descending_reverses_the_ascending_order() {
        let ascending = texts(&run("MATCH (n) RETURN n.name ORDER BY n.name"));
        let descending = texts(&run("MATCH (n) RETURN n.name ORDER BY n.name DESC"));
        let mut reversed = ascending.clone();
        reversed.reverse();
        assert_eq!(descending, reversed);
        assert_eq!(ascending, vec!["alpha", "beta", "lonely", "primary"]);
    }

    #[test]
    fn skip_and_limit_page_through_an_ordered_result() {
        assert_eq!(
            texts(&run(
                "MATCH (n) RETURN n.name ORDER BY n.name SKIP 1 LIMIT 2"
            )),
            vec!["beta", "lonely"]
        );
        assert_eq!(
            run("MATCH (n) RETURN n.name ORDER BY n.name SKIP 10").row_count(),
            0
        );
    }

    #[test]
    fn a_negative_limit_is_a_semantic_error() {
        assert_eq!(
            refuse("MATCH (n) RETURN n.name LIMIT -1").code,
            DiagnosticCode::CypherSemanticError
        );
    }

    #[test]
    fn negative_numbers_order_by_value() {
        // The previous string-encoded key put -3 before -5, because it compared digits
        // rather than magnitudes.
        assert_eq!(
            texts(&run("UNWIND [-5, 3, -3, 0, 5] AS n RETURN n ORDER BY n")),
            vec!["-5", "-3", "0", "3", "5"]
        );
        assert_eq!(
            texts(&run("UNWIND [-5, -3] AS n RETURN n ORDER BY n DESC")),
            vec!["-3", "-5"]
        );
    }

    #[test]
    fn an_integer_and_a_float_order_and_compare_by_value() {
        assert_eq!(
            texts(&run("UNWIND [2, 1.5, -0.5, 1] AS n RETURN n ORDER BY n")),
            vec!["-0.5", "1", "1.5", "2"]
        );
        // `1 = 1.0` is true in Cypher, and DISTINCT agrees rather than contradicting it.
        assert_eq!(texts(&run("UNWIND [1] AS n RETURN n = 1.0")), vec!["true"]);
        assert_eq!(run("UNWIND [1, 1.0] AS n RETURN DISTINCT n").row_count(), 1);
    }

    #[test]
    fn a_large_integer_is_compared_exactly_rather_than_through_a_float() {
        // These two differ by one and share a float, so converting to compare would call
        // them equal.
        let result = run(&format!(
            "UNWIND [{}, {}] AS n RETURN DISTINCT n",
            i64::MAX,
            i64::MAX - 1
        ));
        assert_eq!(result.row_count(), 2);
        // Every i64 is below 2^63, which is the smallest float above the range.
        assert_eq!(
            texts(&run(&format!(
                "UNWIND [{}] AS n RETURN n < 9223372036854775808.0",
                i64::MAX
            ))),
            vec!["true"]
        );
    }

    #[test]
    fn the_cross_kind_order_is_the_one_the_contract_fixes() {
        // null < boolean < number < string < list, per query contract section 9.4.
        let result = run("UNWIND [[1], \"text\", 7, true, null] AS n RETURN n ORDER BY n");
        assert_eq!(texts(&result), vec!["null", "true", "7", "text", "[1]"]);
    }

    #[test]
    fn without_order_by_the_row_set_is_stable_even_though_the_order_is_undefined() {
        // The contract promises a set, not a sequence, so this asserts the set.
        let first: BTreeSet<String> = texts(&run("MATCH (n) RETURN n.name")).into_iter().collect();
        let second: BTreeSet<String> = texts(&run("MATCH (n) RETURN n.name")).into_iter().collect();
        assert_eq!(first, second);
        assert_eq!(first.len(), 4);
    }

    #[test]
    fn unwind_turns_a_list_into_rows() {
        assert_eq!(
            texts(&run(
                "UNWIND [1, 2, 3] AS number RETURN number ORDER BY number"
            )),
            vec!["1", "2", "3"]
        );
    }

    #[test]
    fn with_opens_a_new_scope() {
        assert_eq!(
            texts(&run(
                "MATCH (n:Service) WITH n.name AS name WHERE name = \"beta\" RETURN name"
            )),
            vec!["beta"]
        );
        // A variable dropped by WITH is no longer bound.
        assert_eq!(
            refuse("MATCH (n:Service) WITH n.name AS name RETURN n.name").code,
            DiagnosticCode::CypherSemanticError
        );
    }

    #[test]
    fn union_concatenates_and_union_distinct_deduplicates() {
        let all = run(
            "MATCH (n:Service) RETURN n.name AS name UNION ALL MATCH (n:Service) RETURN n.name AS name",
        );
        assert_eq!(all.row_count(), 4);
        let distinct = run(
            "MATCH (n:Service) RETURN n.name AS name UNION MATCH (n:Service) RETURN n.name AS name",
        );
        assert_eq!(distinct.row_count(), 2);
    }

    #[test]
    fn parameters_are_substituted_and_a_missing_one_is_an_error() {
        let mut parameters = Parameters::new();
        parameters.insert("wanted".to_owned(), QueryValue::Text("beta".to_owned()));
        assert_eq!(
            texts(&run_with(
                "MATCH (n) WHERE n.name = $wanted RETURN n.name",
                parameters
            )),
            vec!["beta"]
        );

        let error = refuse("MATCH (n) WHERE n.name = $absent RETURN n.name");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("$absent"), "{error}");
    }

    #[test]
    fn an_unbound_variable_is_an_error_rather_than_an_empty_result() {
        let error = refuse("MATCH (n) RETURN missing.name");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("not bound"), "{error}");
    }

    #[test]
    fn scalar_functions_evaluate_and_an_unknown_one_is_refused() {
        assert_eq!(
            texts(&run(
                "MATCH (n:Database) RETURN toUpper(n.name) ORDER BY n.name"
            )),
            vec!["LONELY", "PRIMARY"]
        );
        assert_eq!(
            texts(&run(
                "MATCH (n:Service) WHERE n.name = \"alpha\" RETURN size(labels(n))"
            )),
            vec!["1"]
        );
        assert_eq!(
            refuse("MATCH (n) RETURN nonesuch(n)").code,
            DiagnosticCode::CypherSemanticError
        );
    }

    #[test]
    fn arithmetic_overflow_and_division_by_zero_yield_null_rather_than_panicking() {
        assert_eq!(texts(&run("UNWIND [1] AS x RETURN x / 0")), vec!["null"]);
        assert_eq!(texts(&run("UNWIND [1] AS x RETURN x + 1")), vec!["2"]);
        assert_eq!(
            texts(&run("UNWIND [\"a\"] AS x RETURN x + \"b\"")),
            vec!["ab"]
        );
    }

    #[test]
    fn a_named_path_binds_its_nodes() {
        let result = run("MATCH p = (a:Service)-[:CALLS]->(b) RETURN p ORDER BY a.name");
        assert_eq!(result.row_count(), 2);
        assert!(matches!(result.rows[0][0], QueryValue::Path { .. }));
    }

    #[test]
    fn a_cycle_does_not_make_a_bounded_walk_diverge() {
        let mut cyclic = graph();
        cyclic.edges.push(edge(0x3, 0xC, 0xA, "CALLS"));
        // Terminates, because a walk never revisits a node within one path.
        assert!(
            run_on(
                &mut cyclic,
                "MATCH (a:Service)-[:CALLS*1..10]->(b) RETURN b.name"
            )
            .row_count()
                > 0
        );
    }

    #[test]
    fn an_external_endpoint_is_skipped_rather_than_treated_as_local() {
        let mut federated = graph();
        federated.edges.push(Edge {
            id: LocalEdgeId::from_bytes([0x9; 16]),
            source: NodeReference::Local(LocalNodeId::from_bytes([0xA; 16])),
            target: NodeReference::External(crate::graph::ScopedNodeId {
                source: crate::locator::CanonicalSourceLocator::new("./packages/shared").unwrap(),
                local: LocalNodeId::from_bytes([0xE; 16]),
            }),
            relation: RelationName::new("CALLS").unwrap(),
            properties: Vec::new(),
            contributions: vec![contribution()],
        });
        // The linked target is not in this database, so it contributes no row. Resolving it
        // needs link traversal, which is a later Stage.
        assert_eq!(
            run_on(
                &mut federated,
                "MATCH (a:Service)-[:CALLS]->(b) RETURN b.name"
            )
            .row_count(),
            2
        );
    }

    // Inline property maps.

    #[test]
    fn an_inline_map_filters_a_reading_pattern() {
        assert_eq!(
            texts(&run("MATCH (n {name: \"beta\"}) RETURN n.name")),
            vec!["beta"]
        );
        assert_eq!(
            run("MATCH (n:Service {name: \"primary\"}) RETURN n.name").row_count(),
            0
        );
        // Every entry must match, not just one.
        assert_eq!(
            run("MATCH (n:Database {name: \"primary\", size: 4}) RETURN n.name").row_count(),
            0
        );
        assert_eq!(
            run("MATCH (n:Database {name: \"primary\", size: 10}) RETURN n.name").row_count(),
            1
        );
    }

    #[test]
    fn a_relationship_map_filters_too() {
        let mut annotated = graph();
        annotated.edges[0].properties.push((
            PropertyKey::new("kind").unwrap(),
            PropertyValue::from("direct"),
        ));
        assert_eq!(
            run_on(
                &mut annotated,
                "MATCH ()-[r:CALLS {kind: \"direct\"}]->(b) RETURN b.name"
            )
            .row_count(),
            1
        );
    }

    #[test]
    fn a_null_map_value_is_refused_rather_than_matching_nothing() {
        // Matching nothing would look like an empty database instead of a wrong query.
        let error = refuse("MATCH (n {name: null}) RETURN n");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("null"), "{error}");
    }

    // Aggregation.

    #[test]
    fn an_aggregate_without_a_grouping_key_returns_exactly_one_row() {
        let result = run("MATCH (n) RETURN count(n) AS total");
        assert_eq!(result.columns, vec!["total"]);
        assert_eq!(texts(&result), vec!["4"]);
    }

    #[test]
    fn count_over_an_empty_graph_answers_zero_rather_than_answering_nothing() {
        let mut empty = Graph::default();
        assert_eq!(
            texts(&run_on(&mut empty, "MATCH (n) RETURN count(n) AS total")),
            vec!["0"]
        );
        assert_eq!(
            texts(&run_on(&mut empty, "MATCH (n) RETURN count(*) AS rows")),
            vec!["0"]
        );
        assert_eq!(
            texts(&run_on(
                &mut empty,
                "MATCH (n) RETURN collect(n.name) AS names"
            )),
            vec!["[]"]
        );
        assert_eq!(
            texts(&run_on(&mut empty, "MATCH (n) RETURN sum(n.size) AS total")),
            vec!["0"]
        );
        // The mean of nothing is not zero.
        assert_eq!(
            texts(&run_on(&mut empty, "MATCH (n) RETURN avg(n.size) AS mean")),
            vec!["null"]
        );
        assert_eq!(
            texts(&run_on(&mut empty, "MATCH (n) RETURN min(n.size) AS least")),
            vec!["null"]
        );
    }

    #[test]
    fn a_grouping_key_produces_no_row_over_no_input() {
        let mut empty = Graph::default();
        assert_eq!(
            run_on(
                &mut empty,
                "MATCH (n) RETURN n.name AS name, count(n) AS total"
            )
            .row_count(),
            0
        );
    }

    #[test]
    fn the_non_aggregate_items_are_the_grouping_key() {
        let result = run("MATCH (n) RETURN labels(n) AS labels, count(n) AS total ORDER BY labels");
        assert_eq!(texts(&result), vec!["[Database]|2", "[Service]|2"]);
    }

    #[test]
    fn count_of_a_value_ignores_null_and_count_star_does_not() {
        // alpha and beta carry no `size`.
        assert_eq!(
            texts(&run(
                "MATCH (n) RETURN count(n.size) AS sized, count(*) AS rows"
            )),
            vec!["2|4"]
        );
    }

    #[test]
    fn every_numeric_aggregate_agrees_with_the_values_it_summed() {
        assert_eq!(
            texts(&run(
                "MATCH (n:Database) RETURN sum(n.size) AS total, min(n.size) AS least, \
                 max(n.size) AS most, avg(n.size) AS mean"
            )),
            vec!["14|4|10|7"]
        );
    }

    #[test]
    fn a_sum_of_integers_stays_an_integer_and_a_float_makes_it_a_float() {
        let mut mixed = Graph::default();
        mixed.nodes.push(node(
            0x1,
            &["Measure"],
            &[("value", PropertyValue::Integer(2))],
        ));
        assert!(matches!(
            run_on(&mut mixed, "MATCH (n) RETURN sum(n.value) AS total").rows[0][0],
            QueryValue::Integer(2)
        ));

        mixed.nodes.push(node(
            0x2,
            &["Measure"],
            &[("value", PropertyValue::Float(FiniteF64::new(0.5).unwrap()))],
        ));
        assert!(matches!(
            run_on(&mut mixed, "MATCH (n) RETURN sum(n.value) AS total").rows[0][0],
            QueryValue::Float(_)
        ));
    }

    #[test]
    fn a_non_numeric_value_in_a_numeric_aggregate_is_refused_rather_than_skipped() {
        let error = refuse("MATCH (n) RETURN sum(n.name) AS total");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("numbers"), "{error}");
    }

    #[test]
    fn collect_gathers_in_row_order_and_skips_null() {
        let result = run("MATCH (n) WITH n ORDER BY n.name RETURN collect(n.name) AS names");
        assert_eq!(texts(&result), vec!["[alpha, beta, lonely, primary]"]);

        let result = run("MATCH (n) RETURN size(collect(n.size)) AS sized");
        assert_eq!(texts(&result), vec!["2"]);
    }

    #[test]
    fn an_aggregate_may_be_part_of_a_larger_expression() {
        assert_eq!(
            texts(&run("MATCH (n) RETURN count(n) + 1 AS more")),
            vec!["5"]
        );
    }

    #[test]
    fn filtering_on_an_aggregate_goes_through_with() {
        assert_eq!(
            texts(&run(
                "MATCH (n)-[:CALLS]->(m) WITH n, count(m) AS calls WHERE calls > 0 \
                 RETURN n.name AS name, calls ORDER BY name"
            )),
            vec!["alpha|1", "beta|1"]
        );
        assert_eq!(
            run("MATCH (n)-[:CALLS]->(m) WITH n, count(m) AS calls WHERE calls > 5 RETURN calls")
                .row_count(),
            0
        );
    }

    #[test]
    fn after_grouping_order_by_names_a_projected_column() {
        assert_eq!(
            texts(&run(
                "MATCH (n) RETURN labels(n) AS labels, count(n) AS total ORDER BY total DESC, labels"
            )),
            vec!["[Database]|2", "[Service]|2"]
        );
        // The incoming bindings are gone after grouping, because several of them collapsed
        // into one row.
        assert_eq!(
            refuse("MATCH (n) RETURN count(n) AS total ORDER BY n.name").code,
            DiagnosticCode::CypherSemanticError
        );
    }

    // Procedures and functions.

    #[test]
    fn a_bare_call_produces_the_procedure_columns() {
        let result = run("CALL nostdb.build_status()");
        assert_eq!(
            result.columns,
            vec!["database_generation", "nodes", "edges", "links"]
        );
        assert_eq!(texts(&result), vec!["null|4|2|1"]);
    }

    #[test]
    fn a_call_with_yield_keeps_and_renames_columns() {
        let result = run("CALL nostdb.links() YIELD source AS locator RETURN locator");
        assert_eq!(result.columns, vec!["locator"]);
        assert_eq!(texts(&result), vec!["./packages/child"]);
    }

    #[test]
    fn a_call_runs_once_per_incoming_row() {
        let mut with_evidence = graph();
        with_evidence.nodes[0].contributions[0]
            .evidence
            .push(sample_evidence());
        let result = run_on(
            &mut with_evidence,
            "MATCH (n:Service) CALL nostdb.evidence(n) YIELD path RETURN n.name, path",
        );
        // Only alpha carries evidence, so beta's row is dropped by the call.
        assert_eq!(texts(&result), vec!["alpha|src/auth.rs"]);
    }

    #[test]
    fn yielding_a_column_a_procedure_does_not_produce_is_refused() {
        let error = refuse("CALL nostdb.links() YIELD invented RETURN invented");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("yields no column"), "{error}");
    }

    #[test]
    fn a_capability_gated_procedure_is_unsupported_rather_than_answered() {
        let error = refuse("CALL nostdb.refresh_links() YIELD source RETURN source");
        assert_eq!(error.code, DiagnosticCode::CypherUnsupported);
        assert!(error.message.contains("provider"), "{error}");
    }

    #[test]
    fn an_unknown_procedure_is_a_semantic_error() {
        assert_eq!(
            refuse("CALL nostdb.invented() YIELD x RETURN x").code,
            DiagnosticCode::CypherSemanticError
        );
        assert_eq!(
            refuse("CALL other.thing() YIELD x RETURN x").code,
            DiagnosticCode::CypherSemanticError
        );
    }

    #[test]
    fn the_nostdb_functions_report_the_context_and_the_stored_evidence() {
        let mut with_evidence = graph();
        with_evidence.nodes[0].contributions[0]
            .evidence
            .push(sample_evidence());
        let query = parse(
            "MATCH (n:Service {name: \"alpha\"}) RETURN nostdb.source(n) AS source, \
             nostdb.source_location(n) AS path, nostdb.source_revision(n) AS revision, \
             nostdb.link_alias(n) AS alias, nostdb.is_available(n) AS available",
        )
        .unwrap();
        let context = DatabaseContext {
            generation: Some(Generation::from_raw(9)),
            source: Some(crate::locator::CanonicalSourceLocator::new("./root.nostdb").unwrap()),
        };
        let result = execute(&query, &mut with_evidence, &Parameters::new(), &context).unwrap();
        assert_eq!(
            texts(&result),
            vec!["./root.nostdb|src/auth.rs|a1b2c3|null|true"]
        );
    }

    fn sample_evidence() -> crate::evidence::Evidence {
        crate::evidence::Evidence {
            source: crate::locator::CanonicalSourceLocator::new("./packages/child").unwrap(),
            resolved_revision: Some(crate::text::NonEmptyText::new("a1b2c3").unwrap()),
            path: Some(crate::text::NonEmptyText::new("src/auth.rs").unwrap()),
            content_digest: crate::evidence::ContentDigest::new(
                "sha256:abcdef0123456789abcdef0123456789",
            )
            .unwrap(),
            range: None,
            producer: crate::text::NonEmptyText::new("rust-structural").unwrap(),
            producer_version: crate::text::NonEmptyText::new("0.1.0").unwrap(),
            method: crate::evidence::EvidenceMethod::Deterministic,
            confidence: crate::evidence::Confidence::Extracted,
        }
    }

    // Write clauses.

    #[test]
    fn create_adds_a_node_with_its_labels_and_properties() {
        let mut target = Graph::default();
        let result = run_on(
            &mut target,
            "CREATE (n:Function:Reviewed {name: \"login\", lines: 12}) RETURN n.name",
        );
        assert_eq!(result.writes.nodes_created, 1);
        assert_eq!(texts(&result), vec!["login"]);

        assert_eq!(target.nodes.len(), 1);
        assert_eq!(target.nodes[0].labels.len(), 2);
        assert_eq!(target.nodes[0].properties.len(), 2);
        assert_eq!(target.nodes[0].violations(), Vec::new());
    }

    #[test]
    fn a_created_record_is_user_owned_and_needs_no_evidence() {
        let mut target = Graph::default();
        run_on(&mut target, "CREATE (n:Function {name: \"login\"})");
        let contribution = &target.nodes[0].contributions[0];
        assert_eq!(contribution.owner, Owner::user());
        assert_eq!(contribution.source_unit, SourceUnitId::QUERY);
        assert!(contribution.evidence.is_empty());
        assert!(!contribution.owner.requires_evidence());
    }

    #[test]
    fn create_reuses_a_bound_endpoint_rather_than_duplicating_it() {
        let mut target = graph();
        let result = run_on(
            &mut target,
            "MATCH (a:Service {name: \"alpha\"}), (d:Database {name: \"lonely\"}) \
             CREATE (a)-[:USES]->(d)",
        );
        assert_eq!(result.writes.edges_created, 1);
        assert_eq!(result.writes.nodes_created, 0);
        assert_eq!(target.nodes.len(), 4);
        assert_eq!(target.edges.len(), 3);
    }

    #[test]
    fn create_makes_a_whole_path_at_once() {
        let mut target = Graph::default();
        let result = run_on(
            &mut target,
            "CREATE (a:Service {name: \"alpha\"})-[:CALLS]->(b:Database {name: \"primary\"})",
        );
        assert_eq!(result.writes.nodes_created, 2);
        assert_eq!(result.writes.edges_created, 1);
        assert_eq!(target.edges[0].violations(), Vec::new());
        assert!(!target.edges[0].crosses_sources());
    }

    #[test]
    fn a_created_node_must_carry_a_label() {
        let mut target = Graph::default();
        let error = refuse_on(&mut target, "CREATE (n) RETURN n");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("label"), "{error}");
        assert!(target.nodes.is_empty());
    }

    /// The writer refuses an undirected or untyped relationship even though the parser
    /// already does.
    ///
    /// [`Writer`] is public and takes a pattern, so a caller can build one without going
    /// through the parser. Two lines of defence for a rule that decides whether a stored
    /// Edge has two endpoints is the right number.
    #[test]
    fn the_writer_refuses_a_relationship_no_edge_could_represent() {
        use crate::cypher::{NodePattern, RelationshipPattern};

        let labelled = |label: &str| NodePattern {
            variable: None,
            labels: vec![label.to_owned()],
            properties: Vec::new(),
        };
        let step = |direction: Direction, types: Vec<String>| RelationshipPattern {
            variable: None,
            types,
            direction,
            length: None,
            properties: Vec::new(),
        };

        for (relationship, expected) in [
            (step(Direction::Either, vec!["USES".to_owned()]), "directed"),
            (step(Direction::Outgoing, Vec::new()), "one relation type"),
        ] {
            let pattern = Pattern {
                path_variable: None,
                start: labelled("Service"),
                steps: vec![(relationship, labelled("Database"))],
            };
            let mut target = Graph::default();
            let mut minter = Minter::sequential(1);
            let mut summary = WriteSummary::default();
            let mut writer = Writer::new(&mut target, &mut minter, &mut summary);
            let error = writer
                .create(
                    &pattern,
                    &mut Bindings::new(),
                    &PatternValues {
                        start: Vec::new(),
                        steps: vec![(Vec::new(), Vec::new())],
                    },
                    SourceRange::ORIGIN,
                )
                .expect_err("must be refused");
            assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
            assert!(error.message.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_null_property_in_a_created_record_is_refused() {
        let mut target = Graph::default();
        let error = refuse_on(&mut target, "CREATE (n:Function {name: null})");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("null"), "{error}");
        assert!(target.nodes.is_empty());
    }

    #[test]
    fn merge_creates_once_and_then_matches() {
        let mut target = Graph::default();
        let first = run_on(
            &mut target,
            "MERGE (n:Service {name: \"alpha\"}) RETURN n.name",
        );
        assert_eq!(first.writes.nodes_created, 1);

        let second = run_on(
            &mut target,
            "MERGE (n:Service {name: \"alpha\"}) RETURN n.name",
        );
        assert_eq!(second.writes.nodes_created, 0);
        assert_eq!(texts(&second), vec!["alpha"]);
        assert_eq!(target.nodes.len(), 1);
    }

    #[test]
    fn merge_over_repeated_rows_creates_one_record() {
        // Matching per row is what makes this work: the second row finds what the first
        // created.
        let mut target = Graph::default();
        let result = run_on(
            &mut target,
            "UNWIND [\"alpha\", \"alpha\", \"beta\"] AS name MERGE (n:Service {name: name})",
        );
        assert_eq!(result.writes.nodes_created, 2);
        assert_eq!(target.nodes.len(), 2);
    }

    #[test]
    fn set_assigns_a_property_and_overwrites_an_existing_one() {
        let mut target = graph();
        let result = run_on(&mut target, "MATCH (n:Service) SET n.reviewed = true");
        assert_eq!(result.writes.properties_set, 2);
        assert!(result.columns.is_empty());
        assert!(result.rows.is_empty());

        let result = run_on(
            &mut target,
            "MATCH (n:Database {name: \"primary\"}) SET n.size = 11 RETURN n.size",
        );
        assert_eq!(texts(&result), vec!["11"]);
        let primary = target
            .nodes
            .iter()
            .find(|node| node.id == LocalNodeId::from_bytes([0xC; 16]))
            .unwrap();
        assert_eq!(
            primary
                .properties
                .iter()
                .filter(|(key, _)| key.as_str() == "size")
                .count(),
            1
        );
    }

    #[test]
    fn assigning_null_removes_the_property() {
        let mut target = graph();
        let result = run_on(&mut target, "MATCH (n:Database) SET n.size = null");
        assert_eq!(result.writes.properties_removed, 2);
        assert!(target.nodes.iter().all(|node| {
            node.properties
                .iter()
                .all(|(key, _)| key.as_str() != "size")
        }));
    }

    #[test]
    fn set_and_remove_handle_labels_and_keep_a_node_storable() {
        let mut target = graph();
        let result = run_on(&mut target, "MATCH (n:Service) SET n:Reviewed");
        assert_eq!(result.writes.labels_added, 2);

        let result = run_on(&mut target, "MATCH (n:Reviewed) REMOVE n:Reviewed");
        assert_eq!(result.writes.labels_removed, 2);

        // Removing the last label would leave a Node NostDB cannot store.
        let error = refuse_on(&mut target, "MATCH (n:Service) REMOVE n:Service");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("last label"), "{error}");
    }

    #[test]
    fn a_user_write_preserves_an_analyzer_contribution() {
        let mut target = Graph::default();
        let mut analyzed = node(
            0x1,
            &["Function"],
            &[("name", PropertyValue::from("login"))],
        );
        analyzed.contributions = vec![Contribution {
            owner: Owner::new(crate::text::NonEmptyText::new("rust-structural").unwrap()),
            source_unit: SourceUnitId::from_bytes([7; 16]),
            evidence: vec![sample_evidence()],
        }];
        target.nodes.push(analyzed);

        run_on(&mut target, "MATCH (n:Function) SET n.reviewed = true");
        let contributions = &target.nodes[0].contributions;
        assert_eq!(contributions.len(), 2);
        assert!(contributions[0].owner.kind() == crate::contribution::OwnerKind::Analyzer);
        assert_eq!(contributions[1].owner, Owner::user());

        // A second write does not add a second user contribution.
        run_on(&mut target, "MATCH (n:Function) SET n.seen = true");
        assert_eq!(target.nodes[0].contributions.len(), 2);
    }

    #[test]
    fn remove_takes_a_property_away() {
        let mut target = graph();
        let result = run_on(&mut target, "MATCH (n:Database) REMOVE n.size");
        assert_eq!(result.writes.properties_removed, 2);
        // Removing something absent is not an error and counts nothing.
        let result = run_on(&mut target, "MATCH (n:Database) REMOVE n.size");
        assert_eq!(result.writes.properties_removed, 0);
    }

    #[test]
    fn delete_removes_a_relationship_and_leaves_its_endpoints() {
        let mut target = graph();
        let result = run_on(
            &mut target,
            "MATCH (:Service)-[r:CALLS]->(:Database) DELETE r",
        );
        assert_eq!(result.writes.edges_deleted, 1);
        assert_eq!(target.nodes.len(), 4);
        assert_eq!(target.edges.len(), 1);
    }

    #[test]
    fn deleting_a_node_with_a_relationship_needs_detach() {
        let mut target = graph();
        let error = refuse_on(&mut target, "MATCH (n:Service {name: \"alpha\"}) DELETE n");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("DETACH DELETE"), "{error}");
        assert_eq!(target.nodes.len(), 4);

        let result = run_on(
            &mut target,
            "MATCH (n:Service {name: \"alpha\"}) DETACH DELETE n",
        );
        assert_eq!(result.writes.nodes_deleted, 1);
        assert_eq!(result.writes.edges_deleted, 1);
        assert_eq!(target.nodes.len(), 3);
        assert_eq!(target.edges.len(), 1);
    }

    #[test]
    fn deleting_an_isolated_node_needs_no_detach() {
        let mut target = graph();
        let result = run_on(
            &mut target,
            "MATCH (n:Database {name: \"lonely\"}) DELETE n",
        );
        assert_eq!(result.writes.nodes_deleted, 1);
    }

    #[test]
    fn detach_delete_removes_an_edge_pointing_into_a_linked_source() {
        // The edge is a record of the root database, so deleting it is a root write.
        let mut federated = graph();
        federated.edges.push(Edge {
            id: LocalEdgeId::from_bytes([0x9; 16]),
            source: NodeReference::Local(LocalNodeId::from_bytes([0xD; 16])),
            target: NodeReference::External(crate::graph::ScopedNodeId {
                source: crate::locator::CanonicalSourceLocator::new("./packages/shared").unwrap(),
                local: LocalNodeId::from_bytes([0xE; 16]),
            }),
            relation: RelationName::new("CALLS").unwrap(),
            properties: Vec::new(),
            contributions: vec![contribution()],
        });
        let result = run_on(
            &mut federated,
            "MATCH (n:Database {name: \"lonely\"}) DETACH DELETE n",
        );
        assert_eq!(result.writes.nodes_deleted, 1);
        assert_eq!(result.writes.edges_deleted, 1);
        assert!(federated.edges.iter().all(|edge| !edge.crosses_sources()));
    }

    #[test]
    fn deleting_the_same_record_twice_in_one_query_is_harmless() {
        let mut target = graph();
        let result = run_on(
            &mut target,
            "MATCH (n:Database {name: \"lonely\"}) DELETE n, n",
        );
        assert_eq!(result.writes.nodes_deleted, 1);
    }

    #[test]
    fn deleting_something_that_is_not_a_record_is_refused() {
        let mut target = graph();
        let error = refuse_on(&mut target, "MATCH (n) DELETE n.name");
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("node or a relationship"), "{error}");
    }

    #[test]
    fn a_later_clause_sees_what_an_earlier_one_wrote() {
        let mut target = Graph::default();
        let result = run_on(
            &mut target,
            "CREATE (n:Function {name: \"login\"}) WITH n MATCH (m:Function) RETURN m.name",
        );
        assert_eq!(texts(&result), vec!["login"]);
    }

    #[test]
    fn one_rows_write_does_not_change_what_another_row_assigns() {
        // Values are evaluated against the graph as the clause found it, so this is a
        // stated rule rather than an accident of evaluation order.
        let mut target = graph();
        run_on(
            &mut target,
            "MATCH (a:Database {name: \"primary\"}), (b:Database {name: \"lonely\"}) \
             SET a.size = b.size, b.size = a.size",
        );
        let sizes: BTreeSet<String> = target
            .nodes
            .iter()
            .filter(|node| node.labels.iter().any(|label| label.as_str() == "Database"))
            .flat_map(|node| {
                node.properties
                    .iter()
                    .filter(|(key, _)| key.as_str() == "size")
                    .map(|(_, value)| QueryValue::from_property(value).to_string())
            })
            .collect();
        // The two swapped rather than both taking one value.
        assert_eq!(sizes.len(), 2);
    }

    #[test]
    fn minted_identifiers_are_distinct_version_7_uuids() {
        let mut target = Graph::default();
        let query = parse("CREATE (a:A {n: 1}), (b:B {n: 2})").unwrap();
        let context = DatabaseContext {
            generation: Some(Generation::from_raw(4)),
            source: None,
        };
        execute(&query, &mut target, &Parameters::new(), &context).unwrap();

        // The generation no longer takes part, so there is no exact value to assert.
        // What the caller relies on is that each record gets its own well-formed one.
        assert_ne!(target.nodes[0].id, target.nodes[1].id);
        for node in &target.nodes {
            let bytes = node.id.to_bytes();
            assert_eq!(bytes[6] >> 4, 0x7, "version nibble must be 7");
            assert_eq!(bytes[8] >> 6, 0b10, "variant bits must be 0b10");
        }
    }

    #[test]
    fn minting_skips_an_identifier_a_stated_record_already_uses() {
        // Driven through a sequential minter rather than through `execute`, because the
        // default minter's next value is unpredictable, and a test cannot occupy a value
        // it cannot name. The skip path is the same one either minter feeds.
        let mut target = Graph::default();
        let mut probe = Minter::sequential(5);
        let occupied = probe.node();
        target.nodes.push(node(0x0, &["Existing"], &[]));
        target.nodes[0].id = occupied;

        let mut minter = Minter::sequential(5);
        let mut summary = WriteSummary::default();
        let mut writer = Writer::new(&mut target, &mut minter, &mut summary);
        writer
            .create(
                &Pattern {
                    path_variable: None,
                    start: NodePattern {
                        variable: None,
                        labels: vec!["Created".to_owned()],
                        properties: Vec::new(),
                    },
                    steps: Vec::new(),
                },
                &mut Bindings::new(),
                &PatternValues {
                    start: Vec::new(),
                    steps: Vec::new(),
                },
                SourceRange::ORIGIN,
            )
            .unwrap();

        assert_eq!(target.nodes.len(), 2);
        assert_ne!(target.nodes[1].id, occupied);
    }

    #[test]
    fn a_write_that_changes_nothing_leaves_the_graph_exactly_as_it_was() {
        // A transaction decides whether to advance the generation from the summary, so the
        // summary saying "nothing changed" has to mean the graph is untouched, contributions
        // included.
        let mut target = graph();
        let before = target.clone();

        for source in [
            "MATCH (n:Service) SET n.absent = null",
            "MATCH (n:Service) REMOVE n.absent",
            "MATCH (n:Service) SET n:Service",
        ] {
            let result = run_on(&mut target, source);
            assert!(result.writes.is_empty(), "{source} reported a change");
            assert_eq!(target, before, "{source} changed the graph");
        }
    }

    #[test]
    fn a_write_naming_an_unmatched_optional_row_does_nothing_rather_than_failing() {
        let mut target = graph();
        let result = run_on(
            &mut target,
            "MATCH (d:Database) OPTIONAL MATCH (d)-[:CALLS]->(x) SET x.seen = true",
        );
        assert!(result.writes.is_empty());

        let result = run_on(
            &mut target,
            "MATCH (d:Database) OPTIONAL MATCH (d)-[:CALLS]->(x) REMOVE x.seen",
        );
        assert!(result.writes.is_empty());

        let result = run_on(
            &mut target,
            "MATCH (d:Database) OPTIONAL MATCH (d)-[:CALLS]->(x) DELETE x",
        );
        assert!(result.writes.is_empty());
    }

    #[test]
    fn a_write_summary_reports_nothing_for_a_read() {
        assert!(run("MATCH (n) RETURN n.name").writes.is_empty());
        let mut target = Graph::default();
        assert!(!run_on(&mut target, "CREATE (n:A {n: 1})").writes.is_empty());
    }

    // -- federated reads -----------------------------------------------------------

    mod federated {
        use super::*;
        use crate::link::Link;
        use crate::locator::CanonicalSourceLocator;

        fn locator(value: &str) -> CanonicalSourceLocator {
            CanonicalSourceLocator::new(value).unwrap()
        }

        fn linked_graph(marker: u8, label: &str, name: &str) -> Graph {
            Graph {
                nodes: vec![node(
                    marker,
                    &[label],
                    &[("name", PropertyValue::from(name))],
                )],
                edges: Vec::new(),
                links: Vec::new(),
                schemas: Vec::new(),
            }
        }

        fn run_over(
            source: &str,
            root: &mut Graph,
            linked: &[(CanonicalSourceLocator, Graph)],
        ) -> QueryResult {
            let held: Vec<LinkedSource<'_>> = linked
                .iter()
                .map(|(locator, graph)| LinkedSource { locator, graph })
                .collect();
            let query = parse(source).expect("must parse");
            execute_federated(
                &query,
                root,
                &held,
                &Parameters::new(),
                &DatabaseContext {
                    generation: Some(Generation::from_raw(1)),
                    source: Some(locator("./root.nostdb")),
                },
            )
            .expect("must execute")
        }

        #[test]
        fn a_read_sees_the_root_and_every_linked_source() {
            let mut root = linked_graph(0x1, "Function", "root-node");
            let linked = vec![
                (locator("./a"), linked_graph(0x2, "Function", "a-node")),
                (locator("./b"), linked_graph(0x3, "Function", "b-node")),
            ];
            let result = run_over(
                "MATCH (n:Function) RETURN n.name ORDER BY n.name",
                &mut root,
                &linked,
            );
            let names: Vec<String> = result.rows.iter().map(|row| row[0].to_string()).collect();
            assert_eq!(names, ["a-node", "b-node", "root-node"]);
        }

        #[test]
        fn two_sources_carrying_one_identifier_produce_two_rows() {
            // A database copied and linked from its original. Without a scoped handle the
            // two would collapse into one row, or worse, one would shadow the other.
            let mut root = linked_graph(0x7, "Function", "original");
            let linked = vec![(locator("./copy"), linked_graph(0x7, "Function", "copy"))];
            let result = run_over(
                "MATCH (n) RETURN n.name ORDER BY n.name",
                &mut root,
                &linked,
            );
            assert_eq!(result.rows.len(), 2, "{:?}", result.rows);

            // And DISTINCT over the bound nodes keeps them apart, because the sort key
            // carries the source.
            let distinct = run_over("MATCH (n) RETURN DISTINCT n", &mut root, &linked);
            assert_eq!(distinct.rows.len(), 2, "{:?}", distinct.rows);
        }

        #[test]
        fn nostdb_source_reports_the_locator_a_record_came_through() {
            let mut root = linked_graph(0x1, "Function", "root-node");
            let linked = vec![(
                locator("./child"),
                linked_graph(0x2, "Function", "child-node"),
            )];
            let result = run_over(
                "MATCH (n) RETURN n.name, nostdb.source(n) ORDER BY n.name",
                &mut root,
                &linked,
            );
            assert_eq!(result.rows[0][0].to_string(), "child-node");
            assert_eq!(result.rows[0][1].to_string(), "./child");
            assert_eq!(result.rows[1][0].to_string(), "root-node");
            assert_eq!(result.rows[1][1].to_string(), "./root.nostdb");
        }

        #[test]
        fn a_write_naming_a_linked_record_is_refused_and_changes_nothing() {
            let mut root = linked_graph(0x1, "Function", "root-node");
            let linked = [(locator("./child"), linked_graph(0x2, "Other", "child-node"))];
            let held: Vec<LinkedSource<'_>> = linked
                .iter()
                .map(|(locator, graph)| LinkedSource { locator, graph })
                .collect();
            let query = parse("MATCH (n:Other) SET n.name = \"changed\"").expect("must parse");
            let error = execute_federated(
                &query,
                &mut root,
                &held,
                &Parameters::new(),
                &DatabaseContext {
                    generation: Some(Generation::from_raw(1)),
                    source: None,
                },
            )
            .expect_err("a linked write is refused");
            assert_eq!(error.code, DiagnosticCode::LinkedDatabaseReadOnly);
            assert_eq!(
                linked[0].1.nodes[0].properties[0].1,
                PropertyValue::from("child-node")
            );
        }

        #[test]
        fn a_write_naming_a_root_record_still_works_alongside_a_link() {
            let mut root = linked_graph(0x1, "Function", "root-node");
            let linked = [(locator("./child"), linked_graph(0x2, "Other", "child-node"))];
            let result = run_over(
                "MATCH (n:Function) SET n.name = \"renamed\" RETURN n.name",
                &mut root,
                &linked,
            );
            assert_eq!(result.rows[0][0].to_string(), "renamed");
            assert_eq!(result.writes.properties_set, 1);
        }

        #[test]
        fn an_edge_naming_a_linked_node_traverses_into_it() {
            // The root declares the link, and an edge crosses into it by locator.
            let child_id = LocalNodeId::from_bytes([0x2; 16]);
            let mut root = Graph {
                nodes: vec![node(
                    0x1,
                    &["Function"],
                    &[("name", PropertyValue::from("caller"))],
                )],
                edges: vec![Edge {
                    id: LocalEdgeId::from_bytes([0x9; 16]),
                    source: NodeReference::Local(LocalNodeId::from_bytes([0x1; 16])),
                    target: NodeReference::External(crate::graph::ScopedNodeId {
                        source: locator("./child"),
                        local: child_id,
                    }),
                    relation: crate::name::RelationName::new("CALLS").unwrap(),
                    properties: Vec::new(),
                    contributions: Vec::new(),
                }],
                links: vec![Link::new(locator("./child"))],
                schemas: Vec::new(),
            };
            let linked = vec![(locator("./child"), linked_graph(0x2, "Other", "callee"))];
            let result = run_over("MATCH (a)-[:CALLS]->(b) RETURN b.name", &mut root, &linked);
            assert_eq!(result.rows.len(), 1, "{:?}", result.rows);
            assert_eq!(result.rows[0][0].to_string(), "callee");
        }

        #[test]
        fn an_edge_naming_a_source_that_was_not_opened_leads_nowhere() {
            // The link is declared and unreachable, so the edge stays in the root's
            // records and traversal simply cannot leave through it. That is what a
            // partial result means, and it is not an error.
            let mut root = Graph {
                nodes: vec![node(0x1, &["Function"], &[])],
                edges: vec![Edge {
                    id: LocalEdgeId::from_bytes([0x9; 16]),
                    source: NodeReference::Local(LocalNodeId::from_bytes([0x1; 16])),
                    target: NodeReference::External(crate::graph::ScopedNodeId {
                        source: locator("./absent"),
                        local: LocalNodeId::from_bytes([0x2; 16]),
                    }),
                    relation: crate::name::RelationName::new("CALLS").unwrap(),
                    properties: Vec::new(),
                    contributions: Vec::new(),
                }],
                links: vec![Link::new(locator("./absent"))],
                schemas: Vec::new(),
            };
            let result = run_over("MATCH (a)-[:CALLS]->(b) RETURN b", &mut root, &[]);
            assert!(result.rows.is_empty(), "{:?}", result.rows);
        }

        #[test]
        fn with_no_links_a_query_behaves_exactly_as_before() {
            let mut root = linked_graph(0x1, "Function", "only");
            let result = run_over("MATCH (n) RETURN n.name", &mut root, &[]);
            assert_eq!(result.rows.len(), 1);
            assert_eq!(result.rows[0][0].to_string(), "only");
        }
    }
}
