//! Graph records.
//!
//! # An Edge always has two endpoints
//!
//! [`Edge::source`] and [`Edge::target`] are [`NodeReference`], not
//! `Option<NodeReference>`. An Edge with a missing endpoint is therefore
//! unrepresentable rather than rejected by a check, which is the strongest form the
//! root PRD invariant in section 7 can take. When a reference cannot be resolved,
//! the Engine creates a Placeholder Node and points the Edge at it.
//!
//! # Collection rules are reported, not enforced at construction
//!
//! A Node needing at least one label, and a property block not setting one key
//! twice, are reported by [`Node::violations`] and [`Edge::violations`]. The Engine
//! has to surface those as diagnostics against real source positions, so refusing
//! construction would discard the context a caller needs to report them well.

use crate::contribution::Contribution;
use crate::id::{LocalEdgeId, LocalNodeId};
use crate::locator::CanonicalSourceLocator;
use crate::name::{Label, PropertyKey, RelationName};
use crate::property::PropertyValue;
use std::collections::BTreeSet;
use std::fmt;

/// A node identified within a specific source.
///
/// A linked node is identified in a logical union by the pair of canonical source
/// locator and local node identifier. The target database's own identity is never
/// used, per the root PRD section 11.2.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopedNodeId {
    /// The source the node belongs to.
    pub source: CanonicalSourceLocator,
    /// The node's identifier within that source.
    pub local: LocalNodeId,
}

impl fmt::Display for ScopedNodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}#{}", self.source, self.local)
    }
}

/// An Edge endpoint.
///
/// There is no variant for a missing endpoint.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeReference {
    /// A node in the same database.
    Local(LocalNodeId),
    /// A node in a linked source, which is read-only from the root transaction.
    External(ScopedNodeId),
}

impl NodeReference {
    /// Reports whether this endpoint points into a linked source.
    #[must_use]
    pub const fn is_external(&self) -> bool {
        matches!(self, Self::External(_))
    }

    /// The local identifier, when this endpoint is in the same database.
    #[must_use]
    pub const fn local(&self) -> Option<LocalNodeId> {
        match self {
            Self::Local(id) => Some(*id),
            Self::External(_) => None,
        }
    }
}

impl fmt::Display for NodeReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(id) => write!(formatter, "{id}"),
            Self::External(scoped) => write!(formatter, "{scoped}"),
        }
    }
}

/// A stored Node.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    /// Opaque persistent identifier.
    pub id: LocalNodeId,
    /// Labels, treated as a set. At least one is required.
    pub labels: Vec<Label>,
    /// Properties, in a caller-defined order. A key must not repeat.
    pub properties: Vec<(PropertyKey, PropertyValue)>,
    /// Contributions from each producer.
    pub contributions: Vec<Contribution>,
}

impl Node {
    /// Reports every collection rule this record breaks.
    ///
    /// An empty result means the record satisfies every rule this type can check
    /// without consulting the rest of the database.
    #[must_use]
    pub fn violations(&self) -> Vec<RecordViolation> {
        let mut found = Vec::new();
        if self.labels.is_empty() {
            found.push(RecordViolation::NodeWithoutLabel);
        }
        collect_duplicate_labels(&self.labels, &mut found);
        collect_duplicate_property_keys(&self.properties, &mut found);
        if self.contributions.is_empty() {
            found.push(RecordViolation::NoContribution);
        }
        found
    }
}

/// A stored Edge.
#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    /// Opaque persistent identifier.
    pub id: LocalEdgeId,
    /// Where the relation starts. Never absent.
    pub source: NodeReference,
    /// Where the relation ends. Never absent.
    pub target: NodeReference,
    /// The single relation type.
    pub relation: RelationName,
    /// Properties, in a caller-defined order. A key must not repeat.
    pub properties: Vec<(PropertyKey, PropertyValue)>,
    /// Contributions from each producer.
    pub contributions: Vec<Contribution>,
}

impl Edge {
    /// Reports every collection rule this record breaks.
    #[must_use]
    pub fn violations(&self) -> Vec<RecordViolation> {
        let mut found = Vec::new();
        collect_duplicate_property_keys(&self.properties, &mut found);
        if self.contributions.is_empty() {
            found.push(RecordViolation::NoContribution);
        }
        found
    }

    /// Reports whether either endpoint points into a linked source.
    ///
    /// An Edge with an external endpoint cannot be written through a linked
    /// database, because linked records are read-only from the root transaction.
    #[must_use]
    pub const fn crosses_sources(&self) -> bool {
        self.source.is_external() || self.target.is_external()
    }
}

/// Reports each label that appears more than once, once per repeated label.
///
/// Shared with the change contract so a drafted record and a stored record cannot
/// disagree about what a duplicate is.
pub(crate) fn collect_duplicate_labels(labels: &[Label], found: &mut Vec<RecordViolation>) {
    let mut seen: BTreeSet<&Label> = BTreeSet::new();
    let mut reported: BTreeSet<&Label> = BTreeSet::new();
    for label in labels {
        if !seen.insert(label) && reported.insert(label) {
            found.push(RecordViolation::DuplicateLabel {
                label: label.clone(),
            });
        }
    }
}

/// Reports each property key that is set more than once, once per repeated key.
///
/// Shared with the change contract for the same reason as
/// [`collect_duplicate_labels`].
pub(crate) fn collect_duplicate_property_keys(
    properties: &[(PropertyKey, PropertyValue)],
    found: &mut Vec<RecordViolation>,
) {
    let mut seen: BTreeSet<&PropertyKey> = BTreeSet::new();
    let mut reported: BTreeSet<&PropertyKey> = BTreeSet::new();
    for (key, _) in properties {
        if !seen.insert(key) && reported.insert(key) {
            found.push(RecordViolation::DuplicatePropertyKey { key: key.clone() });
        }
    }
}

/// A collection rule a record breaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordViolation {
    /// A Node carried no label, but at least one is required.
    NodeWithoutLabel,
    /// A label appeared more than once, but labels are a set.
    DuplicateLabel {
        /// The repeated label.
        label: Label,
    },
    /// A property key was set more than once.
    ///
    /// The last value must not silently win, which is why this is reported rather
    /// than resolved.
    DuplicatePropertyKey {
        /// The repeated key.
        key: PropertyKey,
    },
    /// A record carried no contribution, so nothing owns it.
    ///
    /// A record no contribution requires is a record the Engine would remove.
    NoContribution,
}

impl fmt::Display for RecordViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeWithoutLabel => formatter.write_str("a Node requires at least one label"),
            Self::DuplicateLabel { label } => {
                write!(formatter, "the label {label} appears more than once")
            }
            Self::DuplicatePropertyKey { key } => {
                write!(formatter, "the property key {key} is set more than once")
            }
            Self::NoContribution => {
                formatter.write_str("a record requires at least one contribution")
            }
        }
    }
}

impl std::error::Error for RecordViolation {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contribution::Owner;
    use crate::id::SourceUnitId;

    fn contribution() -> Contribution {
        Contribution {
            owner: Owner::User,
            source_unit: SourceUnitId::from_bytes([1; 16]),
            evidence: Vec::new(),
        }
    }

    fn label(text: &str) -> Label {
        Label::new(text).unwrap()
    }

    fn key(text: &str) -> PropertyKey {
        PropertyKey::new(text).unwrap()
    }

    fn node(labels: Vec<Label>, properties: Vec<(PropertyKey, PropertyValue)>) -> Node {
        Node {
            id: LocalNodeId::from_bytes([2; 16]),
            labels,
            properties,
            contributions: vec![contribution()],
        }
    }

    #[test]
    fn a_well_formed_node_has_no_violations() {
        let subject = node(
            vec![label("Function")],
            vec![(key("name"), PropertyValue::from("login"))],
        );
        assert_eq!(subject.violations(), Vec::new());
    }

    #[test]
    fn a_node_requires_a_label() {
        let subject = node(Vec::new(), Vec::new());
        assert_eq!(
            subject.violations(),
            vec![RecordViolation::NodeWithoutLabel]
        );
    }

    #[test]
    fn a_repeated_label_is_reported_once() {
        let subject = node(
            vec![label("Function"), label("Function"), label("Function")],
            Vec::new(),
        );
        assert_eq!(
            subject.violations(),
            vec![RecordViolation::DuplicateLabel {
                label: label("Function")
            }]
        );
    }

    #[test]
    fn a_repeated_property_key_is_reported_rather_than_resolved() {
        let subject = node(
            vec![label("Function")],
            vec![
                (key("name"), PropertyValue::from("first")),
                (key("name"), PropertyValue::from("second")),
            ],
        );
        assert_eq!(
            subject.violations(),
            vec![RecordViolation::DuplicatePropertyKey { key: key("name") }]
        );
    }

    #[test]
    fn a_record_without_a_contribution_is_reported() {
        let subject = Node {
            id: LocalNodeId::from_bytes([2; 16]),
            labels: vec![label("Function")],
            properties: Vec::new(),
            contributions: Vec::new(),
        };
        assert_eq!(subject.violations(), vec![RecordViolation::NoContribution]);
    }

    #[test]
    fn an_edge_endpoint_is_never_optional_and_external_edges_are_detectable() {
        let local = NodeReference::Local(LocalNodeId::from_bytes([3; 16]));
        let external = NodeReference::External(ScopedNodeId {
            source: CanonicalSourceLocator::new("./packages/shared").unwrap(),
            local: LocalNodeId::from_bytes([4; 16]),
        });

        let edge = Edge {
            id: LocalEdgeId::from_bytes([5; 16]),
            source: local.clone(),
            target: external.clone(),
            relation: RelationName::new("CALLS").unwrap(),
            properties: Vec::new(),
            contributions: vec![contribution()],
        };

        assert_eq!(edge.violations(), Vec::new());
        assert!(edge.crosses_sources());
        assert!(!local.is_external());
        assert!(external.is_external());
        assert_eq!(local.local(), Some(LocalNodeId::from_bytes([3; 16])));
        assert_eq!(external.local(), None);
    }

    #[test]
    fn a_self_loop_is_representable() {
        let same = NodeReference::Local(LocalNodeId::from_bytes([6; 16]));
        let edge = Edge {
            id: LocalEdgeId::from_bytes([7; 16]),
            source: same.clone(),
            target: same,
            relation: RelationName::new("RECURSES").unwrap(),
            properties: Vec::new(),
            contributions: vec![contribution()],
        };
        assert_eq!(edge.violations(), Vec::new());
        assert!(!edge.crosses_sources());
    }
}
