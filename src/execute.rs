//! Query execution over an in-memory graph.
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
//! # What this increment executes
//!
//! Reading: pattern matching including bounded variable-length traversal, `WHERE`,
//! `WITH`, `UNWIND`, projection, `DISTINCT`, `ORDER BY`, `SKIP`, `LIMIT`, and `UNION`.
//! Aggregation is refused with a message saying so, because a wrong grouping would give a
//! plausible number rather than an error.

use crate::cypher::{
    BinaryOperator, Direction, Expression, LengthRange, NodePattern, Pattern, Projection,
    ProjectionItem, Query, QueryError, ReadingClause, RelationshipPattern,
};
use crate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::encoding::Graph;
use crate::evidence::SourceRange;
use crate::graph::{Edge, Node, NodeReference};
use crate::id::{LocalEdgeId, LocalNodeId};
use crate::property::{FiniteF64, PropertyValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Functions this build evaluates.
const SCALAR_FUNCTIONS: [&str; 6] = ["toupper", "tolower", "size", "labels", "type", "coalesce"];

/// Aggregate functions the language has and this build does not yet evaluate.
const AGGREGATE_FUNCTIONS: [&str; 6] = ["count", "sum", "avg", "min", "max", "collect"];

/// A value a query can produce.
#[derive(Clone, Debug, PartialEq)]
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
    Node(LocalNodeId),
    /// A bound relationship.
    Relationship(LocalEdgeId),
    /// A bound path: alternating nodes and relationships.
    Path {
        /// Nodes along the path, in order.
        nodes: Vec<LocalNodeId>,
        /// Relationships between them, in order.
        relationships: Vec<LocalEdgeId>,
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
    /// Cypher leaves cross-type ordering loosely specified, so a total order is imposed
    /// here rather than left to whatever comparison happens to run first. Without one,
    /// `ORDER BY` over a mixed column would not be reproducible.
    fn sort_key(&self) -> SortKey {
        match self {
            Self::Null => (0, String::new()),
            Self::Boolean(value) => (1, value.to_string()),
            Self::Integer(value) => (2, format!("{value:+021}")),
            Self::Float(value) => (2, format!("{:+021.6}", value.get())),
            Self::Text(value) => (3, value.clone()),
            Self::List(items) => (
                4,
                items
                    .iter()
                    .map(|item| item.sort_key().1)
                    .collect::<Vec<_>>()
                    .join("\u{1}"),
            ),
            Self::Node(id) => (5, id.to_string()),
            Self::Relationship(id) => (6, id.to_string()),
            Self::Path { nodes, .. } => (
                7,
                nodes
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("-"),
            ),
        }
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
}

impl QueryResult {
    /// Number of rows produced.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

type Bindings = BTreeMap<String, QueryValue>;

/// A comparable key standing in for a value, so ordering is total and reproducible.
type SortKey = (u8, String);

/// A row paired with the sort key computed for it.
type KeyedRow = (Vec<SortKey>, Vec<QueryValue>);

struct Executor<'a> {
    graph: &'a Graph,
    parameters: &'a BTreeMap<String, QueryValue>,
    nodes: BTreeMap<LocalNodeId, &'a Node>,
    outgoing: BTreeMap<LocalNodeId, Vec<&'a Edge>>,
    incoming: BTreeMap<LocalNodeId, Vec<&'a Edge>>,
}

impl<'a> Executor<'a> {
    fn new(graph: &'a Graph, parameters: &'a BTreeMap<String, QueryValue>) -> Self {
        let mut nodes = BTreeMap::new();
        for node in &graph.nodes {
            nodes.insert(node.id, node);
        }
        let mut outgoing: BTreeMap<LocalNodeId, Vec<&Edge>> = BTreeMap::new();
        let mut incoming: BTreeMap<LocalNodeId, Vec<&Edge>> = BTreeMap::new();
        for edge in &graph.edges {
            if let NodeReference::Local(from) = edge.source {
                outgoing.entry(from).or_default().push(edge);
            }
            if let NodeReference::Local(to) = edge.target {
                incoming.entry(to).or_default().push(edge);
            }
        }
        Self {
            graph,
            parameters,
            nodes,
            outgoing,
            incoming,
        }
    }

    fn node_matches(&self, node: &Node, pattern: &NodePattern) -> bool {
        pattern
            .labels
            .iter()
            .all(|wanted| node.labels.iter().any(|label| label.as_str() == wanted))
    }

    fn edges_from(
        &self,
        from: LocalNodeId,
        pattern: &RelationshipPattern,
    ) -> Vec<(&'a Edge, LocalNodeId)> {
        let mut found = Vec::new();
        let type_matches = |edge: &Edge| {
            pattern.types.is_empty()
                || pattern
                    .types
                    .iter()
                    .any(|wanted| edge.relation.as_str() == wanted)
        };

        if matches!(pattern.direction, Direction::Outgoing | Direction::Either) {
            for edge in self.outgoing.get(&from).into_iter().flatten() {
                if type_matches(edge)
                    && let NodeReference::Local(other) = edge.target
                {
                    found.push((*edge, other));
                }
            }
        }
        if matches!(pattern.direction, Direction::Incoming | Direction::Either) {
            for edge in self.incoming.get(&from).into_iter().flatten() {
                if type_matches(edge)
                    && let NodeReference::Local(other) = edge.source
                {
                    found.push((*edge, other));
                }
            }
        }
        found
    }

    /// Enumerates every way `pattern` can be satisfied, extending `base`.
    fn match_pattern(
        &self,
        pattern: &Pattern,
        base: &Bindings,
    ) -> Result<Vec<Bindings>, QueryError> {
        let mut partial: Vec<(Bindings, LocalNodeId, Vec<LocalNodeId>, Vec<LocalEdgeId>)> =
            Vec::new();

        for node in &self.graph.nodes {
            if !self.node_matches(node, &pattern.start) {
                continue;
            }
            let mut bindings = base.clone();
            if let Some(name) = &pattern.start.variable {
                if let Some(existing) = bindings.get(name) {
                    if *existing != QueryValue::Node(node.id) {
                        continue;
                    }
                } else {
                    bindings.insert(name.clone(), QueryValue::Node(node.id));
                }
            }
            partial.push((bindings, node.id, vec![node.id], Vec::new()));
        }

        for (relationship, next_node) in &pattern.steps {
            let mut extended = Vec::new();
            for (bindings, current, path_nodes, path_edges) in partial {
                let reached = match relationship.length {
                    None => self
                        .edges_from(current, relationship)
                        .into_iter()
                        .map(|(edge, other)| (vec![edge.id], other))
                        .collect(),
                    Some(range) => self.walk(current, relationship, range),
                };

                for (edge_ids, other) in reached {
                    let Some(node) = self.nodes.get(&other) else {
                        continue;
                    };
                    if !self.node_matches(node, next_node) {
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
        from: LocalNodeId,
        pattern: &RelationshipPattern,
        range: LengthRange,
    ) -> Vec<(Vec<LocalEdgeId>, LocalNodeId)> {
        let mut found = Vec::new();
        let mut frontier: Vec<(Vec<LocalEdgeId>, LocalNodeId, BTreeSet<LocalNodeId>)> =
            vec![(Vec::new(), from, BTreeSet::from([from]))];

        for depth in 1..=range.maximum {
            let mut next = Vec::new();
            for (edges, current, visited) in frontier {
                for (edge, other) in self.edges_from(current, pattern) {
                    if visited.contains(&other) {
                        continue;
                    }
                    let mut edge_ids = edges.clone();
                    edge_ids.push(edge.id);
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
        found
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
                .graph
                .edges
                .iter()
                .find(|edge| edge.id == *id)
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
        if AGGREGATE_FUNCTIONS.contains(&lower.as_str()) {
            return Err(QueryError {
                code: DiagnosticCode::CypherUnsupported,
                message: format!(
                    "`{name}` is an aggregate function, which this build does not evaluate yet; a \
                     wrong grouping would return a plausible number rather than an error"
                ),
                range: SourceRange::ORIGIN,
            });
        }
        if !SCALAR_FUNCTIONS.contains(&lower.as_str()) {
            return Err(QueryError {
                code: DiagnosticCode::CypherSemanticError,
                message: format!("unknown function `{name}`"),
                range: SourceRange::ORIGIN,
            });
        }

        let values: Vec<QueryValue> = arguments
            .iter()
            .map(|argument| self.evaluate(argument, bindings))
            .collect::<Result<_, _>>()?;
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
                QueryValue::Relationship(id) => self
                    .graph
                    .edges
                    .iter()
                    .find(|edge| edge.id == id)
                    .map_or(QueryValue::Null, |edge| {
                        QueryValue::Text(edge.relation.as_str().to_owned())
                    }),
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
    QueryError {
        code: DiagnosticCode::CypherSemanticError,
        message,
        range: SourceRange::ORIGIN,
    }
}

fn column_name(item: &ProjectionItem) -> String {
    item.alias
        .clone()
        .unwrap_or_else(|| match &item.expression {
            Expression::Variable(name) => name.clone(),
            Expression::Property { variable, key } => format!("{variable}.{key}"),
            other => format!("{other:?}"),
        })
}

fn apply_projection(
    executor: &Executor<'_>,
    projection: &Projection,
    rows: Vec<Bindings>,
) -> Result<(Vec<String>, Vec<Vec<QueryValue>>), QueryError> {
    let columns: Vec<String> = projection.items.iter().map(column_name).collect();

    // Projection happens before the predicate and the sort keys are evaluated, because a
    // `WITH ... WHERE` and an `ORDER BY` may both name a column the projection introduced.
    // Evaluating the predicate first would leave that alias unbound.
    //
    // The scope used for both is the incoming bindings plus the new column names, so
    // `ORDER BY n.age` still works alongside `ORDER BY alias`.
    let mut projected: Vec<(Vec<QueryValue>, Bindings)> = Vec::new();
    for bindings in rows {
        let mut row = Vec::with_capacity(projection.items.len());
        for item in &projection.items {
            row.push(executor.evaluate(&item.expression, &bindings)?);
        }
        let mut scope = bindings;
        for (name, value) in columns.iter().zip(&row) {
            scope.insert(name.clone(), value.clone());
        }
        projected.push((row, scope));
    }

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
            let mut key = Vec::new();
            for sort in &projection.order_by {
                let value = executor.evaluate(&sort.expression, &bindings)?;
                let mut part = value.sort_key();
                if sort.descending {
                    // Invert by complementing, so one ascending sort handles both
                    // directions without an unstable multi-pass sort.
                    part = (u8::MAX - part.0, invert(&part.1));
                }
                key.push(part);
            }
            keyed.push((key, row));
        }
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
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

/// Inverts a sort string so a descending order can be expressed as an ascending one.
fn invert(text: &str) -> String {
    text.chars()
        .map(|character| {
            char::from_u32(0x0010_FFFE_u32.saturating_sub(u32::from(character))).unwrap_or('\u{0}')
        })
        .collect()
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
        QueryValue::Integer(_) => Err(QueryError {
            code: DiagnosticCode::CypherSemanticError,
            message: format!("{what} must not be negative"),
            range: SourceRange::ORIGIN,
        }),
        _ => Err(QueryError {
            code: DiagnosticCode::CypherSemanticError,
            message: format!("{what} must be an integer"),
            range: SourceRange::ORIGIN,
        }),
    }
}

/// Executes a parsed query against a graph.
///
/// # Errors
///
/// Returns [`DiagnosticCode::CypherSemanticError`] for an unbound variable, a missing
/// parameter, an unknown function, or a negative `SKIP` or `LIMIT`, and
/// [`DiagnosticCode::CypherUnsupported`] for an aggregate function this build does not
/// evaluate.
pub fn execute(
    query: &Query,
    graph: &Graph,
    parameters: &BTreeMap<String, QueryValue>,
) -> Result<QueryResult, QueryError> {
    let executor = Executor::new(graph, parameters);
    let mut columns: Vec<String> = Vec::new();
    let mut all_rows: Vec<Vec<QueryValue>> = Vec::new();

    for (index, part) in query.parts.iter().enumerate() {
        let mut rows: Vec<Bindings> = vec![Bindings::new()];

        for clause in &part.reading {
            match clause {
                ReadingClause::Match {
                    optional,
                    patterns,
                    predicate,
                } => {
                    let mut next = Vec::new();
                    for bindings in rows {
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
                        if expanded.is_empty() && *optional {
                            // An unmatched optional pattern keeps the row and binds every
                            // variable the pattern would have introduced to null. Leaving
                            // them absent instead would make a later `x.name` an unbound
                            // variable error rather than the null the language promises.
                            let mut widened = bindings;
                            for name in pattern_variables(patterns) {
                                widened.entry(name).or_insert(QueryValue::Null);
                            }
                            next.push(widened);
                        } else {
                            next.extend(expanded);
                        }
                    }
                    rows = next;
                }
                ReadingClause::Unwind { list, variable } => {
                    let mut next = Vec::new();
                    for bindings in rows {
                        // UNWIND of a non-list produces no rows, matching Cypher's
                        // treatment of null.
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
                ReadingClause::With(projection) => {
                    let (names, projected) = apply_projection(&executor, projection, rows)?;
                    // WITH opens a new scope: only the projected names survive.
                    rows = projected
                        .into_iter()
                        .map(|row| names.iter().cloned().zip(row).collect::<Bindings>())
                        .collect();
                }
            }
        }

        let (part_columns, part_rows) = apply_projection(&executor, &part.result, rows)?;
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

    Ok(QueryResult {
        columns,
        rows: all_rows,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contribution::{Contribution, Owner};
    use crate::cypher::parse;
    use crate::id::SourceUnitId;
    use crate::link::Link;
    use crate::name::{Label, PropertyKey, RelationName};

    fn contribution() -> Contribution {
        Contribution {
            owner: Owner::User,
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
                    &[("name", PropertyValue::from("lonely"))],
                ),
            ],
            edges: vec![edge(0x1, 0xA, 0xB, "CALLS"), edge(0x2, 0xB, 0xC, "CALLS")],
            links: vec![Link::new(
                crate::locator::CanonicalSourceLocator::new("./packages/child").unwrap(),
            )],
        }
    }

    fn run(source: &str) -> QueryResult {
        let query = parse(source).unwrap_or_else(|error| panic!("{source}: {error}"));
        execute(&query, &graph(), &BTreeMap::new())
            .unwrap_or_else(|error| panic!("{source}: {error}"))
    }

    fn run_with(source: &str, parameters: BTreeMap<String, QueryValue>) -> QueryResult {
        let query = parse(source).unwrap();
        execute(&query, &graph(), &parameters).unwrap()
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
    }

    #[test]
    fn a_pattern_requiring_two_labels_matches_nothing_here() {
        let result = run("MATCH (n:Service:Database) RETURN n.name");
        assert_eq!(result.row_count(), 0);
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
        // One hop only reaches beta.
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
        // Both databases survive, and neither calls anything.
        assert_eq!(texts(&result), vec!["lonely|null", "primary|null"]);
    }

    #[test]
    fn where_filters_and_null_never_passes() {
        assert_eq!(
            texts(&run("MATCH (n) WHERE n.size > 5 RETURN n.name")),
            vec!["primary"]
        );
        // Every other node has no `size`, so the comparison is null and the row drops.
        assert_eq!(
            run("MATCH (n) WHERE n.size < 100 RETURN n.name").row_count(),
            1
        );
    }

    #[test]
    fn distinct_removes_duplicate_rows() {
        let all = run("MATCH (n) RETURN n.name").row_count();
        assert_eq!(all, 4);
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
        let query = parse("MATCH (n) RETURN n.name LIMIT -1").unwrap();
        let error = execute(&query, &graph(), &BTreeMap::new()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
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
        let query = parse("MATCH (n:Service) WITH n.name AS name RETURN n.name").unwrap();
        let error = execute(&query, &graph(), &BTreeMap::new()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
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
        let mut parameters = BTreeMap::new();
        parameters.insert("wanted".to_owned(), QueryValue::Text("beta".to_owned()));
        assert_eq!(
            texts(&run_with(
                "MATCH (n) WHERE n.name = $wanted RETURN n.name",
                parameters
            )),
            vec!["beta"]
        );

        let query = parse("MATCH (n) WHERE n.name = $absent RETURN n.name").unwrap();
        let error = execute(&query, &graph(), &BTreeMap::new()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("$absent"), "{error}");
    }

    #[test]
    fn an_unbound_variable_is_an_error_rather_than_an_empty_result() {
        let query = parse("MATCH (n) RETURN missing.name").unwrap();
        let error = execute(&query, &graph(), &BTreeMap::new()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
        assert!(error.message.contains("not bound"), "{error}");
    }

    #[test]
    fn scalar_functions_evaluate_and_an_aggregate_is_refused_with_a_reason() {
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

        let query = parse("MATCH (n) RETURN count(n)").unwrap();
        let error = execute(&query, &graph(), &BTreeMap::new()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherUnsupported);
        assert!(error.message.contains("aggregate"), "{error}");

        let query = parse("MATCH (n) RETURN nonesuch(n)").unwrap();
        let error = execute(&query, &graph(), &BTreeMap::new()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::CypherSemanticError);
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
        let query = parse("MATCH (a:Service)-[:CALLS*1..10]->(b) RETURN b.name").unwrap();
        // Terminates, because a walk never revisits a node within one path.
        let result = execute(&query, &cyclic, &BTreeMap::new()).unwrap();
        assert!(result.row_count() > 0);
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
        let query = parse("MATCH (a:Service)-[:CALLS]->(b) RETURN b.name").unwrap();
        let result = execute(&query, &federated, &BTreeMap::new()).unwrap();
        // The linked target is not in this database, so it contributes no row. Resolving
        // it needs link traversal, which is a later Stage.
        assert_eq!(result.row_count(), 2);
    }
}
