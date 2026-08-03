//! Applying write clauses to a graph.
//!
//! # What a Cypher write owns
//!
//! A write made through the query language is user-owned. It adds or updates a
//! [`Owner::user()`] contribution and leaves every other contribution in place, so refreshing
//! an analyzer later still replaces only that analyzer's work. Nothing here can produce an
//! analyzer-owned or AI-owned contribution, which is why the ownership separation the root
//! product contract requires cannot be broken by a query.
//!
//! # Why the model's rules surface as refusals
//!
//! NostDB requires every Node to carry a label and every Edge to have two endpoints.
//! openCypher permits `CREATE (n)` and an undirected created relationship, and neither can
//! be stored. Accepting them would mean inventing a label or picking an endpoint order, so
//! they are refused with a source range instead. The rules are published in query contract
//! section 10.
//!
//! The parser refuses the two that a pattern settles on its own, an undirected or untyped
//! relationship, so a query never reaches here carrying one. The checks below stay because
//! this is a public API taking a pattern: a caller can build one without a parser, and the
//! rule decides whether a stored Edge has two endpoints.
//!
//! # Linked records
//!
//! Every mutation here resolves through the root graph. A record of a linked source is
//! never reachable, which is a stronger guarantee than a check that could be forgotten. The
//! one place a linked reference can appear at all is an existing Edge endpoint, and that
//! Edge is itself a record of the root database, so deleting it is a root write.

use crate::contribution::{Contribution, Owner};
use crate::cypher::{
    Direction, Expression, NodePattern, Pattern, RelationshipPattern, RemoveItem, SetItem,
};
use crate::diagnostic::DiagnosticCode;
use crate::encoding::Graph;
use crate::evidence::SourceRange;
use crate::execute::{Bindings, QueryValue};
use crate::graph::{Edge, Node, NodeReference};
use crate::id::{LocalEdgeId, LocalNodeId, Minter, SourceUnitId};
use crate::name::{Label, PropertyKey, RelationName};
use crate::property::PropertyValue;
use crate::{cypher::QueryError, name::NameError};

/// What a query changed.
///
/// A caller needs this to report a write, and a test needs it to assert that a clause did
/// what it said. It is an in-memory summary; the machine-readable result envelope is a
/// separate contract that `nostdb-spec` has not authored yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteSummary {
    /// Nodes created.
    pub nodes_created: u64,
    /// Nodes deleted.
    pub nodes_deleted: u64,
    /// Relationships created.
    pub edges_created: u64,
    /// Relationships deleted.
    pub edges_deleted: u64,
    /// Properties set, counting an overwrite.
    pub properties_set: u64,
    /// Properties removed, including by assigning `null`.
    pub properties_removed: u64,
    /// Labels added.
    pub labels_added: u64,
    /// Labels removed.
    pub labels_removed: u64,
}

impl WriteSummary {
    /// Reports whether anything changed.
    ///
    /// A transaction that changed nothing commits without advancing the generation, so
    /// that a read cannot look like a change to synchronization.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes_created == 0
            && self.nodes_deleted == 0
            && self.edges_created == 0
            && self.edges_deleted == 0
            && self.properties_set == 0
            && self.properties_removed == 0
            && self.labels_added == 0
            && self.labels_removed == 0
    }
}

fn semantic(message: impl Into<String>, range: SourceRange) -> QueryError {
    QueryError::at(DiagnosticCode::CypherSemanticError, message, range)
}

fn invalid_name(what: &str, value: &str, error: NameError, range: SourceRange) -> QueryError {
    semantic(format!("{what} `{value}` is invalid: {error}"), range)
}

/// The contribution a query-authored record carries.
fn user_contribution() -> Contribution {
    Contribution {
        owner: Owner::user(),
        source_unit: SourceUnitId::QUERY,
        evidence: Vec::new(),
    }
}

/// Adds a user contribution to a record that does not already carry one.
///
/// Every other contribution stays, which is what keeps an analyzer's work intact when a
/// user edits the record it produced.
fn note_user_ownership(contributions: &mut Vec<Contribution>) {
    let already = contributions
        .iter()
        .any(|contribution| contribution.owner == Owner::user());
    if !already {
        contributions.push(user_contribution());
    }
}

/// Applies the write side of a graph, one clause at a time.
///
/// Held separately from the reading executor because the two need different borrows of the
/// graph: a read builds an index over it, and a write moves records around underneath.
/// The minter and the summary are borrowed rather than owned, because one query may hold
/// several write clauses and a minter that restarted between them would issue the same
/// identifier twice.
#[derive(Debug)]
pub struct Writer<'a> {
    graph: &'a mut Graph,
    minter: &'a mut Minter,
    summary: &'a mut WriteSummary,
}

/// The identifier of a bound record, refused when it belongs to a linked source.
///
/// Root PRD section 18.8: a root transaction may write only to its root database, and a
/// write naming a linked record returns `LINKED_DATABASE_READ_ONLY`. The check lives here
/// because this is the only place a write turns a binding into something it will modify.
fn writable<T: Copy>(
    scoped: &crate::execute::Scoped<T>,
    what: &str,
    range: SourceRange,
) -> Result<T, QueryError> {
    if scoped.is_root() {
        return Ok(scoped.id);
    }
    Err(QueryError::at(
        DiagnosticCode::LinkedDatabaseReadOnly,
        format!(
            "{what} belongs to a linked source, and a root transaction writes only to its \
             root database"
        ),
        range,
    ))
}

impl<'a> Writer<'a> {
    /// A writer over `graph`, continuing an existing minter and summary.
    pub fn new(
        graph: &'a mut Graph,
        minter: &'a mut Minter,
        summary: &'a mut WriteSummary,
    ) -> Self {
        Self {
            graph,
            minter,
            summary,
        }
    }

    /// A minted Node identifier no record already uses.
    ///
    /// A `.nost` file may state an identifier explicitly, so a minted value is checked
    /// against the graph rather than assumed free. The counter never repeats, so this
    /// terminates.
    fn fresh_node_id(&mut self) -> LocalNodeId {
        loop {
            let candidate = self.minter.node();
            if !self.graph.nodes.iter().any(|node| node.id == candidate) {
                return candidate;
            }
        }
    }

    fn fresh_edge_id(&mut self) -> LocalEdgeId {
        loop {
            let candidate = self.minter.edge();
            if !self.graph.edges.iter().any(|edge| edge.id == candidate) {
                return candidate;
            }
        }
    }

    /// Creates every node and relationship in `pattern` that is not already bound.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticCode::CypherSemanticError`] when the pattern breaks a model
    /// rule: a node without a label, a relationship without exactly one type, an
    /// undirected relationship, an invalid name, or a `null` property value.
    pub fn create(
        &mut self,
        pattern: &Pattern,
        bindings: &mut Bindings,
        properties: &PatternValues,
        range: SourceRange,
    ) -> Result<(), QueryError> {
        let mut previous = self.create_node(&pattern.start, bindings, &properties.start, range)?;

        for (index, (relationship, node)) in pattern.steps.iter().enumerate() {
            let target = self.create_node(node, bindings, &properties.steps[index].1, range)?;
            let (from, to) = match relationship.direction {
                Direction::Outgoing => (previous, target),
                Direction::Incoming => (target, previous),
                Direction::Either => {
                    return Err(semantic(
                        "a created relationship must be directed, written `->` or `<-`, \
                         because an Edge has a source and a target",
                        range,
                    ));
                }
            };
            self.create_edge(
                relationship,
                from,
                to,
                bindings,
                &properties.steps[index].0,
                range,
            )?;
            previous = target;
        }
        Ok(())
    }

    /// Creates one node, or returns the identifier a bound variable already names.
    fn create_node(
        &mut self,
        pattern: &NodePattern,
        bindings: &mut Bindings,
        properties: &[(String, QueryValue)],
        range: SourceRange,
    ) -> Result<LocalNodeId, QueryError> {
        if let Some(name) = &pattern.variable
            && let Some(existing) = bindings.get(name)
        {
            // An already-bound variable is reused. Re-declaring it with labels or
            // properties would be two records claiming one name.
            if !pattern.labels.is_empty() || !properties.is_empty() {
                return Err(semantic(
                    format!("`{name}` is already bound, so it cannot be created again"),
                    range,
                ));
            }
            return match existing {
                QueryValue::Node(id) => writable(id, "the bound node", range),
                other => Err(semantic(
                    format!(
                        "`{name}` is bound to {}, which is not a node",
                        other.kind_name()
                    ),
                    range,
                )),
            };
        }

        if pattern.labels.is_empty() {
            return Err(semantic(
                "a created node must carry at least one label, because NostDB requires \
                 every Node to have one",
                range,
            ));
        }

        let mut labels = Vec::new();
        for label in &pattern.labels {
            let parsed = Label::new(label.clone())
                .map_err(|error| invalid_name("a label", label, error, range))?;
            if !labels.contains(&parsed) {
                labels.push(parsed);
            }
        }

        let id = self.fresh_node_id();
        self.graph.nodes.push(Node {
            id,
            labels,
            properties: stored_properties(properties, range)?,
            contributions: vec![user_contribution()],
        });
        self.summary.nodes_created += 1;

        if let Some(name) = &pattern.variable {
            bindings.insert(
                name.clone(),
                QueryValue::Node(crate::execute::Scoped::root(id)),
            );
        }
        Ok(id)
    }

    fn create_edge(
        &mut self,
        pattern: &RelationshipPattern,
        from: LocalNodeId,
        to: LocalNodeId,
        bindings: &mut Bindings,
        properties: &[(String, QueryValue)],
        range: SourceRange,
    ) -> Result<LocalEdgeId, QueryError> {
        let [relation] = pattern.types.as_slice() else {
            return Err(semantic(
                "a created relationship names exactly one relation type",
                range,
            ));
        };
        let relation = RelationName::new(relation.clone())
            .map_err(|error| invalid_name("a relation type", relation, error, range))?;

        let id = self.fresh_edge_id();
        self.graph.edges.push(Edge {
            id,
            source: NodeReference::Local(from),
            target: NodeReference::Local(to),
            relation,
            properties: stored_properties(properties, range)?,
            contributions: vec![user_contribution()],
        });
        self.summary.edges_created += 1;

        if let Some(name) = &pattern.variable {
            bindings.insert(
                name.clone(),
                QueryValue::Relationship(crate::execute::Scoped::root(id)),
            );
        }
        Ok(id)
    }

    /// Applies one `SET` item.
    ///
    /// A `null` binding is a no-op rather than an error, which is what keeps an unmatched
    /// `OPTIONAL MATCH` row usable in a write.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticCode::CypherSemanticError`] when the value is not a record, or
    /// when a name is invalid.
    pub fn set(
        &mut self,
        item: &SetItem,
        variable: &str,
        bound: &QueryValue,
        value: Option<QueryValue>,
        range: SourceRange,
    ) -> Result<(), QueryError> {
        if *bound == QueryValue::Null {
            return Ok(());
        }
        match item {
            SetItem::Property { key, .. } => {
                let key = PropertyKey::new(key.clone())
                    .map_err(|error| invalid_name("a property key", key, error, range))?;
                // Assigning null removes the property, because a stored null is
                // unrepresentable. Storing a placeholder instead would invent a value.
                let stored = stored_value(&value.unwrap_or(QueryValue::Null), range)?;

                let target = Self::record_mut(self.graph, variable, bound, range)?;
                let (properties, contributions) = target.parts();

                let change = match stored {
                    None => {
                        let before = properties.len();
                        properties.retain(|(existing, _)| *existing != key);
                        (properties.len() != before).then_some(Change::PropertyRemoved)
                    }
                    Some(stored) => {
                        if let Some(slot) = properties
                            .iter_mut()
                            .find(|(existing, _)| *existing == key)
                            .map(|(_, slot)| slot)
                        {
                            *slot = stored;
                        } else {
                            properties.push((key, stored));
                        }
                        Some(Change::PropertySet)
                    }
                };
                Self::record(self.summary, change, contributions);
                Ok(())
            }
            SetItem::Label { label, .. } => {
                let label = Label::new(label.clone())
                    .map_err(|error| invalid_name("a label", label, error, range))?;
                match Self::record_mut(self.graph, variable, bound, range)? {
                    RecordMut::Node(node) => {
                        let change = if node.labels.contains(&label) {
                            None
                        } else {
                            node.labels.push(label);
                            Some(Change::LabelAdded)
                        };
                        Self::record(self.summary, change, &mut node.contributions);
                        Ok(())
                    }
                    RecordMut::Edge(_) => Err(semantic(
                        "a relationship has one relation type and carries no labels",
                        range,
                    )),
                }
            }
        }
    }

    /// Counts a change and marks the record user-owned, when anything actually changed.
    ///
    /// Nothing is recorded for a write that changed nothing. Otherwise
    /// [`WriteSummary::is_empty`] would say a query changed nothing while the graph held a
    /// new contribution, and a transaction relies on those two agreeing to decide whether
    /// to advance the generation.
    fn record(
        summary: &mut WriteSummary,
        change: Option<Change>,
        contributions: &mut Vec<Contribution>,
    ) {
        let Some(change) = change else {
            return;
        };
        note_user_ownership(contributions);
        match change {
            Change::PropertySet => summary.properties_set += 1,
            Change::PropertyRemoved => summary.properties_removed += 1,
            Change::LabelAdded => summary.labels_added += 1,
            Change::LabelRemoved => summary.labels_removed += 1,
        }
    }

    /// Applies one `REMOVE` item.
    ///
    /// A `null` binding is a no-op, as it is for [`Writer::set`].
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticCode::CypherSemanticError`] when the value is not a record, when
    /// a name is invalid, or when removing a node's last label.
    pub fn remove(
        &mut self,
        item: &RemoveItem,
        variable: &str,
        bound: &QueryValue,
        range: SourceRange,
    ) -> Result<(), QueryError> {
        if *bound == QueryValue::Null {
            return Ok(());
        }
        match item {
            RemoveItem::Property { key, .. } => {
                let key = PropertyKey::new(key.clone())
                    .map_err(|error| invalid_name("a property key", key, error, range))?;
                let (properties, contributions) =
                    Self::record_mut(self.graph, variable, bound, range)?.parts();
                let before = properties.len();
                properties.retain(|(existing, _)| *existing != key);
                let change = (properties.len() != before).then_some(Change::PropertyRemoved);
                Self::record(self.summary, change, contributions);
                Ok(())
            }
            RemoveItem::Label { label, .. } => {
                let label = Label::new(label.clone())
                    .map_err(|error| invalid_name("a label", label, error, range))?;
                match Self::record_mut(self.graph, variable, bound, range)? {
                    RecordMut::Node(node) => {
                        if node.labels.len() == 1 && node.labels.contains(&label) {
                            return Err(semantic(
                                "removing a node's last label would leave a Node NostDB \
                                 cannot store",
                                range,
                            ));
                        }
                        let before = node.labels.len();
                        node.labels.retain(|existing| *existing != label);
                        let change = (node.labels.len() != before).then_some(Change::LabelRemoved);
                        Self::record(self.summary, change, &mut node.contributions);
                        Ok(())
                    }
                    RecordMut::Edge(_) => Err(semantic(
                        "a relationship has one relation type and carries no labels",
                        range,
                    )),
                }
            }
        }
    }

    /// Deletes one bound value.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticCode::CypherSemanticError`] when the value is not a record, or
    /// when a node still has a relationship and `DETACH` was not given.
    pub fn delete(
        &mut self,
        bound: &QueryValue,
        detach: bool,
        range: SourceRange,
    ) -> Result<(), QueryError> {
        match bound {
            QueryValue::Node(handle) => {
                let id = &writable(handle, "the node named by `DELETE`", range)?;
                let incident: Vec<LocalEdgeId> = self
                    .graph
                    .edges
                    .iter()
                    .filter(|edge| {
                        edge.source == NodeReference::Local(*id)
                            || edge.target == NodeReference::Local(*id)
                    })
                    .map(|edge| edge.id)
                    .collect();

                if !incident.is_empty() && !detach {
                    return Err(semantic(
                        "this node still has a relationship; an Edge always has two \
                         non-null endpoints, so use `DETACH DELETE` to remove both",
                        range,
                    ));
                }
                for edge in incident {
                    self.delete_edge(edge);
                }

                let before = self.graph.nodes.len();
                self.graph.nodes.retain(|node| node.id != *id);
                if self.graph.nodes.len() != before {
                    self.summary.nodes_deleted += 1;
                }
                Ok(())
            }
            QueryValue::Relationship(handle) => {
                self.delete_edge(writable(
                    handle,
                    "the relationship named by `DELETE`",
                    range,
                )?);
                Ok(())
            }
            // Deleting null is a no-op, which is what makes deleting the same record twice
            // in one query harmless.
            QueryValue::Null => Ok(()),
            other => Err(semantic(
                format!(
                    "`DELETE` takes a node or a relationship, and was given {}",
                    other.kind_name()
                ),
                range,
            )),
        }
    }

    fn delete_edge(&mut self, id: LocalEdgeId) {
        let before = self.graph.edges.len();
        self.graph.edges.retain(|edge| edge.id != id);
        if self.graph.edges.len() != before {
            self.summary.edges_deleted += 1;
        }
    }

    fn record_mut<'graph>(
        graph: &'graph mut Graph,
        variable: &str,
        bound: &QueryValue,
        range: SourceRange,
    ) -> Result<RecordMut<'graph>, QueryError> {
        match bound {
            QueryValue::Node(handle) => {
                let id = writable(handle, format!("`{variable}`").as_str(), range)?;
                graph
                    .nodes
                    .iter_mut()
                    .find(|node| node.id == id)
                    .map(RecordMut::Node)
                    .ok_or_else(|| {
                        semantic(
                            format!("`{variable}` names a node this database no longer holds"),
                            range,
                        )
                    })
            }
            QueryValue::Relationship(handle) => {
                let id = writable(handle, format!("`{variable}`").as_str(), range)?;
                graph
                    .edges
                    .iter_mut()
                    .find(|edge| edge.id == id)
                    .map(RecordMut::Edge)
                    .ok_or_else(|| {
                        semantic(
                            format!(
                                "`{variable}` names a relationship this database no longer holds"
                            ),
                            range,
                        )
                    })
            }
            other => Err(semantic(
                format!(
                    "`{variable}` is bound to {}, which is not a record to modify",
                    other.kind_name()
                ),
                range,
            )),
        }
    }
}

enum RecordMut<'a> {
    Node(&'a mut Node),
    Edge(&'a mut Edge),
}

impl<'a> RecordMut<'a> {
    /// The two fields a property write touches, whichever kind of record this is.
    fn parts(
        self,
    ) -> (
        &'a mut Vec<(PropertyKey, PropertyValue)>,
        &'a mut Vec<Contribution>,
    ) {
        match self {
            Self::Node(node) => (&mut node.properties, &mut node.contributions),
            Self::Edge(edge) => (&mut edge.properties, &mut edge.contributions),
        }
    }
}

/// What a write actually changed, when it changed anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    PropertySet,
    PropertyRemoved,
    LabelAdded,
    LabelRemoved,
}

/// The evaluated property maps of one pattern.
///
/// Map values are expressions, so they are evaluated against the row's bindings before the
/// graph is borrowed mutably. Keeping them in one structure means the writer never needs the
/// reading executor.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PatternValues {
    /// The first node's map.
    pub start: MapValues,
    /// Each relationship and node pair's maps, in pattern order.
    pub steps: Vec<(MapValues, MapValues)>,
}

/// One evaluated inline property map.
pub type MapValues = Vec<(String, QueryValue)>;

/// Turns evaluated map values into stored properties.
fn stored_properties(
    values: &[(String, QueryValue)],
    range: SourceRange,
) -> Result<Vec<(PropertyKey, PropertyValue)>, QueryError> {
    let mut stored = Vec::with_capacity(values.len());
    for (key, value) in values {
        let key = PropertyKey::new(key.clone())
            .map_err(|error| invalid_name("a property key", key, error, range))?;
        let Some(value) = stored_value(value, range)? else {
            return Err(semantic(
                format!("the property `{key}` is null, and a stored null is unrepresentable"),
                range,
            ));
        };
        stored.push((key, value));
    }
    Ok(stored)
}

/// A query value as a stored property, or `None` when it is null.
///
/// # Errors
///
/// Returns [`DiagnosticCode::CypherSemanticError`] for a value no property can hold: a
/// bound record, a path, or a list of them.
pub fn stored_value(
    value: &QueryValue,
    range: SourceRange,
) -> Result<Option<PropertyValue>, QueryError> {
    use crate::property::PropertyScalar;

    Ok(Some(match value {
        QueryValue::Null => return Ok(None),
        QueryValue::Boolean(inner) => PropertyValue::Boolean(*inner),
        QueryValue::Integer(inner) => PropertyValue::Integer(*inner),
        QueryValue::Float(inner) => PropertyValue::Float(*inner),
        QueryValue::Text(inner) => PropertyValue::String(inner.clone()),
        QueryValue::List(items) => {
            let mut scalars = Vec::with_capacity(items.len());
            for item in items {
                let scalar = match item {
                    QueryValue::Boolean(inner) => PropertyScalar::Boolean(*inner),
                    QueryValue::Integer(inner) => PropertyScalar::Integer(*inner),
                    QueryValue::Float(inner) => PropertyScalar::Float(*inner),
                    QueryValue::Text(inner) => PropertyScalar::String(inner.clone()),
                    other => {
                        return Err(semantic(
                            format!(
                                "a list property holds scalars, and this list holds {}",
                                other.kind_name()
                            ),
                            range,
                        ));
                    }
                };
                // A list element is a value in the stored model, and the query language
                // has no object literal in an expression position, so a list a query
                // builds still holds scalars only. The conversion says that rather than
                // the element type saying it.
                scalars.push(PropertyValue::from(scalar));
            }
            PropertyValue::List(scalars)
        }
        other => {
            return Err(semantic(
                format!("a property cannot hold {}", other.kind_name()),
                range,
            ));
        }
    }))
}

/// Every variable a `SET` or `REMOVE` item names.
pub(crate) const fn set_variable(item: &SetItem) -> &String {
    match item {
        SetItem::Property { variable, .. } | SetItem::Label { variable, .. } => variable,
    }
}

/// Every variable a `REMOVE` item names.
pub(crate) const fn remove_variable(item: &RemoveItem) -> &String {
    match item {
        RemoveItem::Property { variable, .. } | RemoveItem::Label { variable, .. } => variable,
    }
}

/// The value expression a `SET` item assigns, when it assigns one.
pub(crate) const fn set_value(item: &SetItem) -> Option<&Expression> {
    match item {
        SetItem::Property { value, .. } => Some(value),
        SetItem::Label { .. } => None,
    }
}
