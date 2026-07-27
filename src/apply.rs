//! Applying a validated change set to a graph.
//!
//! [`crate::change::GraphChangeSet`] states what a producer proposes. This carries it out,
//! and it is the only place ownership is enforced against real records.
//!
//! # The ownership rule, concretely
//!
//! An analyzer refresh replaces **only its own contributions for its own source units**.
//! Root PRD section 11 states it; here it means [`GraphOperation::RemoveContribution`]
//! drops one `(owner, source unit)` pair from every record and leaves every other
//! contribution alone. A record that has no contributions left is gone, because nothing
//! asserts it any more — but a record a user also contributed to survives an analyzer
//! removing its own claim, which is the whole point of the separation.
//!
//! # Why a removal can delete an edge it never named
//!
//! An Edge always has two non-null endpoints. When a removal deletes a Node, every Edge
//! touching it would otherwise be left pointing at nothing, so those Edges go with it and
//! the count is reported. Leaving them would break an invariant the storage layer is
//! entitled to rely on; silently dropping them without saying so would make a build report
//! fewer deletions than it performed.
//!
//! # Failure preserves the previous generation
//!
//! Nothing here writes. It transforms a [`Graph`] in memory and the caller commits the
//! result, so a change set that turns out to be invalid costs the database nothing.

use crate::change::{ChangeSetError, EdgeDraft, GraphChangeSet, GraphOperation, NodeDraft};
use crate::contribution::{Contribution, ContributionKey, Owner};
use crate::encoding::Graph;
use crate::graph::{Edge, Node};
use crate::id::{LocalEdgeId, LocalNodeId, Minter};
use crate::name::PropertyKey;
use crate::property::PropertyValue;
use std::collections::BTreeSet;
use std::fmt;

/// What applying a change set did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplySummary {
    /// Nodes that did not exist before.
    pub nodes_created: u64,
    /// Nodes whose labels, properties, or contributions changed.
    pub nodes_updated: u64,
    /// Nodes removed because nothing asserted them any more.
    pub nodes_deleted: u64,
    /// Edges that did not exist before.
    pub edges_created: u64,
    /// Edges whose properties or contributions changed.
    pub edges_updated: u64,
    /// Edges removed, including those that lost an endpoint.
    pub edges_deleted: u64,
    /// Links declared or updated.
    pub links_upserted: u64,
    /// Links removed.
    pub links_removed: u64,
    /// Placeholder resolutions recorded.
    pub placeholders_resolved: u64,
}

impl ApplySummary {
    /// Reports whether anything changed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes_created == 0
            && self.nodes_updated == 0
            && self.nodes_deleted == 0
            && self.edges_created == 0
            && self.edges_updated == 0
            && self.edges_deleted == 0
            && self.links_upserted == 0
            && self.links_removed == 0
            && self.placeholders_resolved == 0
    }
}

/// Why a change set could not be applied.
#[derive(Clone, Debug, PartialEq)]
pub enum ApplyError {
    /// The set did not satisfy the checks that need no database.
    Invalid(Vec<ChangeSetError>),
    /// The set was computed against a different generation.
    ///
    /// Applying it anyway would mean resolving references against a graph that has moved,
    /// which is how a stale analysis overwrites work it never saw.
    StaleBaseline {
        /// The generation the set was computed against.
        expected: u64,
        /// The generation the graph is at.
        found: u64,
    },
    /// An edge named an endpoint that does not exist and was not created by this set.
    MissingEndpoint {
        /// The identifier that resolved to nothing.
        node: LocalNodeId,
        /// The relation the edge would have carried.
        relation: String,
    },
    /// A resolution named a Placeholder that is not in the graph.
    MissingPlaceholder {
        /// The identifier that resolved to nothing.
        placeholder: LocalNodeId,
    },
    /// An endpoint named a linked source, which a write may never touch.
    LinkedEndpoint {
        /// The source that was named.
        source: String,
    },
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(errors) => {
                write!(
                    formatter,
                    "the change set is invalid: {} problems",
                    errors.len()
                )
            }
            Self::StaleBaseline { expected, found } => write!(
                formatter,
                "the change set was computed against generation {expected} and the \
                 database is at {found}"
            ),
            Self::MissingEndpoint { node, relation } => write!(
                formatter,
                "the `{relation}` edge names {node}, which does not exist"
            ),
            Self::MissingPlaceholder { placeholder } => {
                write!(formatter, "{placeholder} is not a record in this database")
            }
            Self::LinkedEndpoint { source } => write!(
                formatter,
                "`{source}` is a linked source, and a write affects only the root database"
            ),
        }
    }
}

impl std::error::Error for ApplyError {}

/// Applies a change set to a graph.
///
/// The graph is modified only when every operation succeeds: a copy is worked on and
/// swapped in at the end, so a failure halfway through leaves the caller's graph exactly as
/// it was. That is what lets a caller commit the result without a rollback path.
///
/// # Errors
///
/// Returns [`ApplyError::Invalid`] when the set fails its own validation,
/// [`ApplyError::StaleBaseline`] when it was computed against another generation, and a
/// resolution error when an operation names a record that is not there.
pub fn apply(
    graph: &mut Graph,
    change_set: &GraphChangeSet,
    generation: u64,
    minter: &mut Minter,
) -> Result<ApplySummary, ApplyError> {
    change_set.validate().map_err(ApplyError::Invalid)?;
    if change_set.base_generation != generation {
        return Err(ApplyError::StaleBaseline {
            expected: change_set.base_generation,
            found: generation,
        });
    }

    let mut working = graph.clone();
    let mut summary = ApplySummary::default();
    // A rebuild withdraws its previous claim and then restates it, so a record it
    // re-asserts was deleted and created within one set. Reporting that as a deletion and
    // a creation would make an unchanged rebuild read as though it churned the whole
    // database; the net effect is an update, and that is what is counted.
    let mut retired = Retired::default();

    for operation in &change_set.operations {
        match operation {
            GraphOperation::UpsertNode(draft) => {
                upsert_node(
                    &mut working,
                    draft,
                    &change_set.owner,
                    minter,
                    &mut summary,
                    &mut retired,
                );
            }
            GraphOperation::UpsertEdge(draft) => {
                upsert_edge(
                    &mut working,
                    draft,
                    &change_set.owner,
                    minter,
                    &mut summary,
                    &mut retired,
                )?;
            }
            GraphOperation::RemoveContribution(key) => {
                remove_contribution(&mut working, key, &mut summary, &mut retired);
            }
            GraphOperation::ResolvePlaceholder(resolution) => {
                if !working
                    .nodes
                    .iter()
                    .any(|node| node.id == resolution.placeholder)
                {
                    return Err(ApplyError::MissingPlaceholder {
                        placeholder: resolution.placeholder,
                    });
                }
                summary.placeholders_resolved += 1;
            }
            GraphOperation::UpsertLink(draft) => {
                let existing = working
                    .links
                    .iter_mut()
                    .find(|link| link.source == draft.source);
                match existing {
                    Some(link) => link.alias = draft.alias.clone(),
                    None => working.links.push(crate::link::Link {
                        source: draft.source.clone(),
                        alias: draft.alias.clone(),
                    }),
                }
                summary.links_upserted += 1;
            }
            GraphOperation::RemoveLink(locator) => {
                let before = working.links.len();
                working.links.retain(|link| &link.source != locator);
                summary.links_removed += (before - working.links.len()) as u64;
            }
        }
    }

    *graph = working;
    Ok(summary)
}

/// Records deleted earlier in the same set, so restating one counts as an update.
#[derive(Default)]
struct Retired {
    nodes: BTreeSet<LocalNodeId>,
    edges: BTreeSet<LocalEdgeId>,
}

/// Merges one producer's claim into a node, creating it when it is not there.
fn upsert_node(
    graph: &mut Graph,
    draft: &NodeDraft,
    owner: &Owner,
    minter: &mut Minter,
    summary: &mut ApplySummary,
    retired: &mut Retired,
) {
    let contribution = Contribution {
        owner: owner.clone(),
        source_unit: draft.source_unit,
        evidence: draft.evidence.clone(),
    };
    let id = draft.id.unwrap_or_else(|| minter.node());

    if let Some(node) = graph.nodes.iter_mut().find(|node| node.id == id) {
        // Labels are a set and are unioned: two producers may each know a record carries a
        // label, and the second must not erase what the first asserted.
        for label in &draft.labels {
            if !node.labels.contains(label) {
                node.labels.push(label.clone());
            }
        }
        set_properties(&mut node.properties, &draft.properties);
        replace_contribution(&mut node.contributions, contribution);
        summary.nodes_updated += 1;
        return;
    }

    graph.nodes.push(Node {
        id,
        labels: draft.labels.clone(),
        properties: draft.properties.clone(),
        contributions: vec![contribution],
    });
    if retired.nodes.remove(&id) {
        summary.nodes_deleted -= 1;
        summary.nodes_updated += 1;
    } else {
        summary.nodes_created += 1;
    }
}

/// Merges one producer's claim into an edge, creating it when it is not there.
fn upsert_edge(
    graph: &mut Graph,
    draft: &EdgeDraft,
    owner: &Owner,
    minter: &mut Minter,
    summary: &mut ApplySummary,
    retired: &mut Retired,
) -> Result<(), ApplyError> {
    for endpoint in [&draft.source, &draft.target] {
        match endpoint {
            crate::graph::NodeReference::Local(id) => {
                if !graph.nodes.iter().any(|node| node.id == *id) {
                    return Err(ApplyError::MissingEndpoint {
                        node: *id,
                        relation: draft.relation.to_string(),
                    });
                }
            }
            // A write affects only the root database, which the query engine enforces for
            // a query and this enforces for a change set.
            crate::graph::NodeReference::External(scoped) => {
                return Err(ApplyError::LinkedEndpoint {
                    source: scoped.source.as_str().to_owned(),
                });
            }
        }
    }

    let contribution = Contribution {
        owner: owner.clone(),
        source_unit: draft.source_unit,
        evidence: draft.evidence.clone(),
    };
    let id = draft.id.unwrap_or_else(|| minter.edge());

    if let Some(edge) = graph.edges.iter_mut().find(|edge| edge.id == id) {
        set_properties(&mut edge.properties, &draft.properties);
        replace_contribution(&mut edge.contributions, contribution);
        summary.edges_updated += 1;
        return Ok(());
    }

    graph.edges.push(Edge {
        id,
        source: draft.source.clone(),
        target: draft.target.clone(),
        relation: draft.relation.clone(),
        properties: draft.properties.clone(),
        contributions: vec![contribution],
    });
    if retired.edges.remove(&id) {
        summary.edges_deleted -= 1;
        summary.edges_updated += 1;
    } else {
        summary.edges_created += 1;
    }
    Ok(())
}

/// Drops one `(owner, source unit)` claim from every record, deleting what nothing asserts.
fn remove_contribution(
    graph: &mut Graph,
    key: &ContributionKey,
    summary: &mut ApplySummary,
    retired: &mut Retired,
) {
    let matches = |contribution: &Contribution| {
        contribution.owner == key.owner && contribution.source_unit == key.source_unit
    };

    for node in &mut graph.nodes {
        node.contributions.retain(|held| !matches(held));
    }
    for edge in &mut graph.edges {
        edge.contributions.retain(|held| !matches(held));
    }

    let orphaned: BTreeSet<LocalNodeId> = graph
        .nodes
        .iter()
        .filter(|node| node.contributions.is_empty())
        .map(|node| node.id)
        .collect();
    let orphaned_edges: BTreeSet<LocalEdgeId> = graph
        .edges
        .iter()
        .filter(|edge| edge.contributions.is_empty() || touches(edge, &orphaned))
        .map(|edge| edge.id)
        .collect();

    summary.nodes_deleted += orphaned.len() as u64;
    summary.edges_deleted += orphaned_edges.len() as u64;
    retired.nodes.extend(orphaned.iter().copied());
    retired.edges.extend(orphaned_edges.iter().copied());
    graph.nodes.retain(|node| !orphaned.contains(&node.id));
    graph
        .edges
        .retain(|edge| !orphaned_edges.contains(&edge.id));
}

/// Reports whether an edge has an endpoint among a set of nodes.
fn touches(edge: &Edge, nodes: &BTreeSet<LocalNodeId>) -> bool {
    [&edge.source, &edge.target].iter().any(
        |endpoint| matches!(endpoint, crate::graph::NodeReference::Local(id) if nodes.contains(id)),
    )
}

/// Sets each proposed property, leaving keys the draft did not mention.
///
/// A producer states what it knows. A key it did not mention is a key it has no opinion
/// about, and clearing it would let one analyzer erase another's facts by omission.
fn set_properties(
    properties: &mut Vec<(PropertyKey, PropertyValue)>,
    proposed: &[(PropertyKey, PropertyValue)],
) {
    for (key, value) in proposed {
        match properties.iter_mut().find(|(held, _)| held == key) {
            Some(entry) => entry.1 = value.clone(),
            None => properties.push((key.clone(), value.clone())),
        }
    }
}

/// Replaces this producer's claim, leaving every other producer's alone.
fn replace_contribution(contributions: &mut Vec<Contribution>, contribution: Contribution) {
    let key = contribution.key();
    match contributions
        .iter_mut()
        .find(|held| held.owner == key.owner && held.source_unit == key.source_unit)
    {
        Some(held) => *held = contribution,
        None => contributions.push(contribution),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::LinkDraft;
    use crate::evidence::Evidence;
    use crate::graph::NodeReference;
    use crate::id::SourceUnitId;
    use crate::name::{Label, RelationName};
    use crate::text::NonEmptyText;

    fn analyzer() -> Owner {
        Owner::Analyzer {
            name: NonEmptyText::new("rust").unwrap(),
            version: NonEmptyText::new("1").unwrap(),
        }
    }

    fn unit(byte: u8) -> SourceUnitId {
        SourceUnitId::from_bytes([byte; 16])
    }

    fn evidence() -> Vec<Evidence> {
        vec![Evidence {
            source: crate::locator::CanonicalSourceLocator::new(".").unwrap(),
            resolved_revision: None,
            path: NonEmptyText::new("src/main.rs").ok(),
            content_digest: crate::sync::digest_bytes(b"fn main() {}"),
            range: None,
            producer: NonEmptyText::new("rust").unwrap(),
            producer_version: NonEmptyText::new("1").unwrap(),
            method: crate::evidence::EvidenceMethod::Deterministic,
            confidence: crate::evidence::Confidence::Extracted,
        }]
    }

    fn node_draft(id: Option<LocalNodeId>, name: &str, source_unit: SourceUnitId) -> NodeDraft {
        NodeDraft {
            id,
            labels: vec![Label::new("Function").unwrap()],
            properties: vec![(
                PropertyKey::new("name").unwrap(),
                PropertyValue::String(name.to_owned()),
            )],
            source_unit,
            evidence: evidence(),
        }
    }

    fn set(owner: Owner, operations: Vec<GraphOperation>) -> GraphChangeSet {
        let mut change_set =
            GraphChangeSet::new(owner, NonEmptyText::new("tree:sha256:abc").unwrap(), 1);
        for operation in operations {
            change_set.push(operation);
        }
        change_set
    }

    fn run(graph: &mut Graph, change_set: &GraphChangeSet) -> ApplySummary {
        let mut minter = Minter::sequential(1);
        apply(graph, change_set, 1, &mut minter).expect("the set applies")
    }

    #[test]
    fn an_upsert_with_no_identifier_mints_one() {
        let mut graph = Graph::default();
        let summary = run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    None,
                    "main",
                    unit(1),
                ))],
            ),
        );
        assert_eq!(summary.nodes_created, 1);
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].contributions.len(), 1);
    }

    #[test]
    fn an_upsert_naming_an_identifier_keeps_it_across_a_rebuild() {
        // This is what makes a rebuild preserve identity: the builder finds the existing
        // record and names its identifier, so every edge pointing at it stays valid.
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    None,
                    "main",
                    unit(1),
                ))],
            ),
        );
        let id = graph.nodes[0].id;

        let summary = run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    Some(id),
                    "renamed",
                    unit(1),
                ))],
            ),
        );
        assert_eq!(summary.nodes_created, 0);
        assert_eq!(summary.nodes_updated, 1);
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].id, id);
        assert_eq!(
            graph.nodes[0].properties[0].1,
            PropertyValue::String("renamed".to_owned())
        );
    }

    #[test]
    fn removing_a_contribution_deletes_what_nothing_asserts_any_more() {
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    None,
                    "gone",
                    unit(1),
                ))],
            ),
        );
        let summary = run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::RemoveContribution(ContributionKey {
                    owner: analyzer(),
                    source_unit: unit(1),
                })],
            ),
        );
        assert_eq!(summary.nodes_deleted, 1);
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn a_removal_leaves_another_producers_contribution_and_the_record_it_holds() {
        // The whole point of separating ownership: a refresh must not delete what a person
        // wrote about the same record.
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    None,
                    "shared",
                    unit(1),
                ))],
            ),
        );
        let id = graph.nodes[0].id;
        run(
            &mut graph,
            &set(
                Owner::User,
                vec![GraphOperation::UpsertNode(NodeDraft {
                    id: Some(id),
                    labels: vec![Label::new("Reviewed").unwrap()],
                    properties: vec![(
                        PropertyKey::new("note").unwrap(),
                        PropertyValue::String("checked".to_owned()),
                    )],
                    source_unit: SourceUnitId::QUERY,
                    evidence: Vec::new(),
                })],
            ),
        );
        assert_eq!(graph.nodes[0].contributions.len(), 2);

        let summary = run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::RemoveContribution(ContributionKey {
                    owner: analyzer(),
                    source_unit: unit(1),
                })],
            ),
        );
        assert_eq!(summary.nodes_deleted, 0);
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].contributions.len(), 1);
        assert_eq!(graph.nodes[0].contributions[0].owner, Owner::User);
        assert!(
            graph.nodes[0]
                .labels
                .iter()
                .any(|l| l.as_str() == "Reviewed"),
            "labels are a set, so the second producer added to them rather than replacing"
        );
    }

    #[test]
    fn a_removal_for_another_source_unit_changes_nothing() {
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    None,
                    "kept",
                    unit(1),
                ))],
            ),
        );
        let summary = run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::RemoveContribution(ContributionKey {
                    owner: analyzer(),
                    source_unit: unit(2),
                })],
            ),
        );
        assert_eq!(summary.nodes_deleted, 0);
        assert_eq!(graph.nodes.len(), 1);
    }

    #[test]
    fn an_edge_that_loses_an_endpoint_goes_with_it_and_is_counted() {
        // An Edge always has two non-null endpoints. Leaving it would break an invariant
        // storage relies on; deleting it without saying so would under-report the build.
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![
                    GraphOperation::UpsertNode(node_draft(None, "caller", unit(1))),
                    GraphOperation::UpsertNode(node_draft(None, "callee", unit(2))),
                ],
            ),
        );
        let (caller, callee) = (graph.nodes[0].id, graph.nodes[1].id);
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertEdge(EdgeDraft {
                    id: None,
                    source: NodeReference::Local(caller),
                    target: NodeReference::Local(callee),
                    relation: RelationName::new("CALLS").unwrap(),
                    properties: Vec::new(),
                    source_unit: unit(1),
                    evidence: evidence(),
                })],
            ),
        );
        assert_eq!(graph.edges.len(), 1);

        // Removing unit 2 deletes the callee, and the edge cannot survive it.
        let summary = run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::RemoveContribution(ContributionKey {
                    owner: analyzer(),
                    source_unit: unit(2),
                })],
            ),
        );
        assert_eq!(summary.nodes_deleted, 1);
        assert_eq!(summary.edges_deleted, 1);
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn an_edge_naming_an_endpoint_that_does_not_exist_is_refused() {
        let mut graph = Graph::default();
        let absent = LocalNodeId::from_bytes([9; 16]);
        let change_set = set(
            analyzer(),
            vec![GraphOperation::UpsertEdge(EdgeDraft {
                id: None,
                source: NodeReference::Local(absent),
                target: NodeReference::Local(absent),
                relation: RelationName::new("CALLS").unwrap(),
                properties: Vec::new(),
                source_unit: unit(1),
                evidence: evidence(),
            })],
        );
        let mut minter = Minter::sequential(1);
        assert!(matches!(
            apply(&mut graph, &change_set, 1, &mut minter),
            Err(ApplyError::MissingEndpoint { .. })
        ));
    }

    #[test]
    fn a_refused_set_leaves_the_graph_exactly_as_it_was() {
        // A copy is worked on and swapped in, so a failure halfway through costs nothing.
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    None,
                    "kept",
                    unit(1),
                ))],
            ),
        );
        let before = graph.clone();

        let absent = LocalNodeId::from_bytes([9; 16]);
        let change_set = set(
            analyzer(),
            vec![
                GraphOperation::UpsertNode(node_draft(None, "would-be-added", unit(1))),
                GraphOperation::UpsertEdge(EdgeDraft {
                    id: None,
                    source: NodeReference::Local(absent),
                    target: NodeReference::Local(absent),
                    relation: RelationName::new("CALLS").unwrap(),
                    properties: Vec::new(),
                    source_unit: unit(1),
                    evidence: evidence(),
                }),
            ],
        );
        let mut minter = Minter::sequential(1);
        assert!(apply(&mut graph, &change_set, 1, &mut minter).is_err());
        assert_eq!(graph, before, "the first operation must not have landed");
    }

    #[test]
    fn a_set_computed_against_another_generation_is_refused() {
        // A stale analysis resolving references against a graph that has moved is how work
        // nobody saw gets overwritten.
        let mut graph = Graph::default();
        let change_set = set(
            analyzer(),
            vec![GraphOperation::UpsertNode(node_draft(None, "a", unit(1)))],
        );
        let mut minter = Minter::sequential(1);
        assert!(matches!(
            apply(&mut graph, &change_set, 7, &mut minter),
            Err(ApplyError::StaleBaseline {
                expected: 1,
                found: 7
            })
        ));
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn an_endpoint_naming_a_linked_source_is_refused() {
        // Writes affect only the root database.
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    None,
                    "here",
                    unit(1),
                ))],
            ),
        );
        let here = graph.nodes[0].id;
        let change_set = set(
            analyzer(),
            vec![GraphOperation::UpsertEdge(EdgeDraft {
                id: None,
                source: NodeReference::Local(here),
                target: NodeReference::External(crate::graph::ScopedNodeId {
                    source: crate::locator::CanonicalSourceLocator::new("./child").unwrap(),
                    local: LocalNodeId::from_bytes([3; 16]),
                }),
                relation: RelationName::new("CALLS").unwrap(),
                properties: Vec::new(),
                source_unit: unit(1),
                evidence: evidence(),
            })],
        );
        let mut minter = Minter::sequential(1);
        assert!(matches!(
            apply(&mut graph, &change_set, 1, &mut minter),
            Err(ApplyError::LinkedEndpoint { .. })
        ));
    }

    #[test]
    fn a_property_the_draft_did_not_mention_is_left_alone() {
        // A producer states what it knows. Clearing a key it had no opinion about would
        // let one analyzer erase another's facts by omission.
        let mut graph = Graph::default();
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(None, "a", unit(1)))],
            ),
        );
        let id = graph.nodes[0].id;
        run(
            &mut graph,
            &set(
                Owner::User,
                vec![GraphOperation::UpsertNode(NodeDraft {
                    id: Some(id),
                    // At least one label is required of every draft, so a second producer
                    // restates one rather than contributing an unlabelled claim.
                    labels: vec![Label::new("Function").unwrap()],
                    properties: vec![(
                        PropertyKey::new("note").unwrap(),
                        PropertyValue::String("kept".to_owned()),
                    )],
                    source_unit: SourceUnitId::QUERY,
                    evidence: Vec::new(),
                })],
            ),
        );
        run(
            &mut graph,
            &set(
                analyzer(),
                vec![GraphOperation::UpsertNode(node_draft(
                    Some(id),
                    "a",
                    unit(1),
                ))],
            ),
        );
        let keys: Vec<&str> = graph.nodes[0]
            .properties
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(keys, ["name", "note"]);
    }

    #[test]
    fn a_link_is_declared_updated_and_removed() {
        let mut graph = Graph::default();
        let locator = crate::locator::CanonicalSourceLocator::new("./child").unwrap();
        let summary = run(
            &mut graph,
            &set(
                Owner::User,
                vec![GraphOperation::UpsertLink(LinkDraft {
                    source: locator.clone(),
                    alias: None,
                })],
            ),
        );
        assert_eq!(summary.links_upserted, 1);
        assert_eq!(graph.links.len(), 1);

        run(
            &mut graph,
            &set(
                Owner::User,
                vec![GraphOperation::UpsertLink(LinkDraft {
                    source: locator.clone(),
                    alias: Some(crate::name::LinkAlias::new("child").unwrap()),
                })],
            ),
        );
        assert_eq!(graph.links.len(), 1, "identity is the locator");
        assert!(graph.links[0].alias.is_some());

        let summary = run(
            &mut graph,
            &set(Owner::User, vec![GraphOperation::RemoveLink(locator)]),
        );
        assert_eq!(summary.links_removed, 1);
        assert!(graph.links.is_empty());
    }

    #[test]
    fn an_empty_set_is_refused_rather_than_treated_as_a_no_op() {
        // Proposing nothing is a caller mistake, and the change-set contract says so. An
        // applier that accepted it would turn a bug in whoever built the set into silence.
        let mut graph = Graph::default();
        let mut minter = Minter::sequential(1);
        assert!(matches!(
            apply(&mut graph, &set(analyzer(), Vec::new()), 1, &mut minter),
            Err(ApplyError::Invalid(_))
        ));
        assert_eq!(graph, Graph::default());
        assert!(ApplySummary::default().is_empty());
    }
}
