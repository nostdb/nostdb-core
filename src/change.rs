//! The typed change contract.
//!
//! A [`GraphChangeSet`] is an interchange artifact, not a database. An analyzer, a
//! Skill, or a synchronizer proposes one; the Engine validates it and commits it.
//! It cannot be renamed to `.nostdb` and opened, which is the rule in the root PRD
//! section 17.9.
//!
//! # What validation here does and does not cover
//!
//! [`GraphChangeSet::validate`] checks everything decidable from the change set
//! alone: the contract version, whether operations are present, per-record
//! collection rules, the evidence requirement implied by the owner, duplicate
//! identifiers and links within the set, and the ownership boundary on removal.
//!
//! It cannot check anything requiring the database. Whether `base_generation` is
//! still current, whether an endpoint resolves, and whether a Schema or Constraint
//! permits the result are decided at commit time against a real generation.
//! Reporting a stale generation is a conflict, never a silent rebase.
//!
//! # Errors, not diagnostic codes
//!
//! Validation returns typed errors. A change set that breaks these rules is a
//! caller contract violation, and the change-set contract has no published
//! diagnostic codes yet, so inventing unregistered ones would put this crate ahead
//! of `nostdb-spec`.

use crate::contribution::{ContributionKey, Owner};
use crate::evidence::Evidence;
use crate::graph::{
    NodeReference, RecordViolation, collect_duplicate_labels, collect_duplicate_property_keys,
};
use crate::id::{LocalEdgeId, LocalNodeId, SourceUnitId};
use crate::locator::CanonicalSourceLocator;
use crate::name::{Label, LinkAlias, PropertyKey, RelationName};
use crate::property::PropertyValue;
use crate::text::NonEmptyText;
use std::collections::BTreeSet;
use std::fmt;

/// Current `change_set_version`.
pub const CHANGE_SET_VERSION: u32 = 1;

/// Change set versions this build accepts.
pub const SUPPORTED_CHANGE_SET_VERSIONS: [u32; 1] = [CHANGE_SET_VERSION];

/// A proposed Node.
///
/// `id` is optional. `None` asks the Engine to assign an identifier, which is what
/// an analyzer discovering a new symbol does. `Some` names an existing record, or a
/// user-authored `.nost` declaration that states its own identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDraft {
    /// The identifier to upsert, or `None` to have one assigned.
    pub id: Option<LocalNodeId>,
    /// Labels. At least one is required.
    pub labels: Vec<Label>,
    /// Properties. A key must not repeat.
    pub properties: Vec<(PropertyKey, PropertyValue)>,
    /// The source unit this contribution derives from.
    pub source_unit: SourceUnitId,
    /// Provenance.
    pub evidence: Vec<Evidence>,
}

/// A proposed Edge.
#[derive(Clone, Debug, PartialEq)]
pub struct EdgeDraft {
    /// The identifier to upsert, or `None` to have one assigned.
    pub id: Option<LocalEdgeId>,
    /// Where the relation starts. Never absent.
    pub source: NodeReference,
    /// Where the relation ends. Never absent.
    pub target: NodeReference,
    /// The single relation type.
    pub relation: RelationName,
    /// Properties. A key must not repeat.
    pub properties: Vec<(PropertyKey, PropertyValue)>,
    /// The source unit this contribution derives from.
    pub source_unit: SourceUnitId,
    /// Provenance.
    pub evidence: Vec<Evidence>,
}

/// A proposed link declaration.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkDraft {
    /// The canonical locator, which is the link's identity.
    pub source: CanonicalSourceLocator,
    /// The optional alias, which lives in the graph and never in settings.
    pub alias: Option<LinkAlias>,
}

/// What happened to a Placeholder's identity when it resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaceholderOutcome {
    /// The identifier is preserved and the record is no longer a Placeholder.
    ///
    /// This is the preferred outcome, because every Edge already pointing at the
    /// Placeholder stays valid.
    Preserved,
    /// The identifier could not be preserved, so the record is replaced.
    ///
    /// The transaction records this as an explicit identity replacement rather than
    /// merging two identities silently.
    Replaced {
        /// The identifier that replaces the Placeholder.
        replacement: LocalNodeId,
    },
}

/// A resolved Placeholder.
#[derive(Clone, Debug, PartialEq)]
pub struct PlaceholderResolution {
    /// The Placeholder being resolved.
    pub placeholder: LocalNodeId,
    /// What happened to its identity.
    pub outcome: PlaceholderOutcome,
    /// The source unit that resolved it.
    pub source_unit: SourceUnitId,
    /// Provenance for the resolution.
    pub evidence: Vec<Evidence>,
}

/// One operation in a change set.
#[derive(Clone, Debug, PartialEq)]
pub enum GraphOperation {
    /// Create or update a Node.
    UpsertNode(NodeDraft),
    /// Create or update an Edge.
    UpsertEdge(EdgeDraft),
    /// Remove one producer's contribution for one source unit.
    RemoveContribution(ContributionKey),
    /// Record that a Placeholder resolved.
    ResolvePlaceholder(PlaceholderResolution),
    /// Declare or update a link.
    UpsertLink(LinkDraft),
    /// Remove a link declaration, named by its canonical locator.
    RemoveLink(CanonicalSourceLocator),
}

/// A versioned batch of proposed graph changes.
#[derive(Clone, Debug, PartialEq)]
pub struct GraphChangeSet {
    /// Version of this contract.
    pub change_set_version: u32,
    /// The generation this set was computed against.
    pub base_generation: u64,
    /// Who is proposing the changes. Every contribution in the set belongs to them.
    pub owner: Owner,
    /// The immutable source snapshot the changes were derived from.
    pub source_snapshot: NonEmptyText,
    /// The operations, applied in order.
    pub operations: Vec<GraphOperation>,
}

impl GraphChangeSet {
    /// Starts an empty change set at the current contract version.
    #[must_use]
    pub const fn new(owner: Owner, source_snapshot: NonEmptyText, base_generation: u64) -> Self {
        Self {
            change_set_version: CHANGE_SET_VERSION,
            base_generation,
            owner,
            source_snapshot,
            operations: Vec::new(),
        }
    }

    /// Appends an operation.
    pub fn push(&mut self, operation: GraphOperation) {
        self.operations.push(operation);
    }

    /// Validates everything decidable without the database.
    ///
    /// Every problem found is reported, rather than only the first, so a caller can
    /// fix a batch in one pass.
    ///
    /// # Errors
    ///
    /// Returns every [`ChangeSetError`] found. See the module documentation for
    /// what this cannot check.
    pub fn validate(&self) -> Result<(), Vec<ChangeSetError>> {
        let mut errors = Vec::new();

        if !SUPPORTED_CHANGE_SET_VERSIONS.contains(&self.change_set_version) {
            errors.push(ChangeSetError::UnsupportedVersion {
                found: self.change_set_version,
            });
        }
        if self.operations.is_empty() {
            errors.push(ChangeSetError::Empty);
        }

        let mut node_ids: BTreeSet<LocalNodeId> = BTreeSet::new();
        let mut edge_ids: BTreeSet<LocalEdgeId> = BTreeSet::new();
        let mut link_sources: BTreeSet<CanonicalSourceLocator> = BTreeSet::new();
        let mut link_aliases: BTreeSet<LinkAlias> = BTreeSet::new();
        let mut removed_links: BTreeSet<CanonicalSourceLocator> = BTreeSet::new();

        for (index, operation) in self.operations.iter().enumerate() {
            match operation {
                GraphOperation::UpsertNode(draft) => {
                    let mut violations = Vec::new();
                    if draft.labels.is_empty() {
                        violations.push(RecordViolation::NodeWithoutLabel);
                    }
                    collect_duplicate_labels(&draft.labels, &mut violations);
                    collect_duplicate_property_keys(&draft.properties, &mut violations);
                    for violation in violations {
                        errors.push(ChangeSetError::Record { index, violation });
                    }
                    self.check_evidence(index, &draft.evidence, &mut errors);
                    if let Some(id) = draft.id
                        && !node_ids.insert(id)
                    {
                        errors.push(ChangeSetError::DuplicateNodeId { id });
                    }
                }
                GraphOperation::UpsertEdge(draft) => {
                    let mut violations = Vec::new();
                    collect_duplicate_property_keys(&draft.properties, &mut violations);
                    for violation in violations {
                        errors.push(ChangeSetError::Record { index, violation });
                    }
                    self.check_evidence(index, &draft.evidence, &mut errors);
                    if let Some(id) = draft.id
                        && !edge_ids.insert(id)
                    {
                        errors.push(ChangeSetError::DuplicateEdgeId { id });
                    }
                }
                GraphOperation::RemoveContribution(key) => {
                    if key.owner != self.owner {
                        errors.push(ChangeSetError::OwnershipViolation { index });
                    }
                }
                GraphOperation::ResolvePlaceholder(resolution) => {
                    if let PlaceholderOutcome::Replaced { replacement } = resolution.outcome
                        && replacement == resolution.placeholder
                    {
                        errors.push(ChangeSetError::PlaceholderReplacedByItself {
                            id: resolution.placeholder,
                        });
                    }
                    self.check_evidence(index, &resolution.evidence, &mut errors);
                }
                GraphOperation::UpsertLink(draft) => {
                    if !link_sources.insert(draft.source.clone()) {
                        errors.push(ChangeSetError::DuplicateLinkSource {
                            source: draft.source.clone(),
                        });
                    }
                    if let Some(alias) = &draft.alias
                        && !link_aliases.insert(alias.clone())
                    {
                        errors.push(ChangeSetError::DuplicateLinkAlias {
                            alias: alias.clone(),
                        });
                    }
                }
                GraphOperation::RemoveLink(source) => {
                    removed_links.insert(source.clone());
                }
            }
        }

        for source in link_sources.intersection(&removed_links) {
            errors.push(ChangeSetError::ConflictingLinkOperations {
                source: source.clone(),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn check_evidence(
        &self,
        index: usize,
        evidence: &[Evidence],
        errors: &mut Vec<ChangeSetError>,
    ) {
        if self.owner.requires_evidence() && evidence.is_empty() {
            errors.push(ChangeSetError::MissingEvidence { index });
        }
    }
}

/// Why a change set was rejected.
#[derive(Clone, Debug, PartialEq)]
pub enum ChangeSetError {
    /// The contract version is not supported.
    UnsupportedVersion {
        /// The version found.
        found: u32,
    },
    /// The change set carried no operations.
    Empty,
    /// A drafted record breaks a collection rule.
    Record {
        /// Index of the offending operation.
        index: usize,
        /// What it breaks.
        violation: RecordViolation,
    },
    /// An analyzer-owned or AI-owned operation carried no evidence.
    MissingEvidence {
        /// Index of the offending operation.
        index: usize,
    },
    /// Two operations upsert the same Node identifier.
    DuplicateNodeId {
        /// The repeated identifier.
        id: LocalNodeId,
    },
    /// Two operations upsert the same Edge identifier.
    DuplicateEdgeId {
        /// The repeated identifier.
        id: LocalEdgeId,
    },
    /// Two operations declare the same link locator.
    DuplicateLinkSource {
        /// The repeated locator.
        source: CanonicalSourceLocator,
    },
    /// Two link declarations claim the same alias.
    DuplicateLinkAlias {
        /// The repeated alias.
        alias: LinkAlias,
    },
    /// One change set both declares and removes the same link.
    ConflictingLinkOperations {
        /// The locator named by both operations.
        source: CanonicalSourceLocator,
    },
    /// A removal names a contribution this change set's owner does not own.
    OwnershipViolation {
        /// Index of the offending operation.
        index: usize,
    },
    /// A Placeholder resolution replaced an identifier with itself.
    ///
    /// That is a preserved resolution stated incorrectly, and treating it as a
    /// replacement would record a spurious identity event.
    PlaceholderReplacedByItself {
        /// The identifier named twice.
        id: LocalNodeId,
    },
}

impl fmt::Display for ChangeSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => {
                write!(formatter, "change_set_version {found} is not supported")
            }
            Self::Empty => formatter.write_str("a change set must carry at least one operation"),
            Self::Record { index, violation } => {
                write!(formatter, "operation {index}: {violation}")
            }
            Self::MissingEvidence { index } => write!(
                formatter,
                "operation {index}: an analyzer-owned or AI-owned change requires evidence"
            ),
            Self::DuplicateNodeId { id } => {
                write!(formatter, "the Node identifier {id} is upserted twice")
            }
            Self::DuplicateEdgeId { id } => {
                write!(formatter, "the Edge identifier {id} is upserted twice")
            }
            Self::DuplicateLinkSource { source } => {
                write!(formatter, "the link {source} is declared twice")
            }
            Self::DuplicateLinkAlias { alias } => {
                write!(formatter, "the link alias {alias} is claimed twice")
            }
            Self::ConflictingLinkOperations { source } => write!(
                formatter,
                "the link {source} is both declared and removed in one change set"
            ),
            Self::OwnershipViolation { index } => write!(
                formatter,
                "operation {index}: a change set may only remove contributions it owns"
            ),
            Self::PlaceholderReplacedByItself { id } => write!(
                formatter,
                "the Placeholder {id} is recorded as replaced by itself"
            ),
        }
    }
}

impl std::error::Error for ChangeSetError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Confidence, ContentDigest, EvidenceMethod};

    fn text(value: &str) -> NonEmptyText {
        NonEmptyText::new(value).unwrap()
    }

    fn analyzer() -> Owner {
        Owner::Analyzer {
            name: text("rust-structural"),
            version: text("0.1.0"),
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            source: CanonicalSourceLocator::new("./packages/child").unwrap(),
            resolved_revision: None,
            path: Some(text("src/auth.rs")),
            content_digest: ContentDigest::new("sha256:abcdef0123456789abcdef0123456789").unwrap(),
            range: None,
            producer: text("rust-structural"),
            producer_version: text("0.1.0"),
            method: EvidenceMethod::Deterministic,
            confidence: Confidence::Extracted,
        }
    }

    fn unit() -> SourceUnitId {
        SourceUnitId::from_bytes([9; 16])
    }

    fn node_draft(id: Option<LocalNodeId>, labels: Vec<&str>) -> NodeDraft {
        NodeDraft {
            id,
            labels: labels.into_iter().map(|l| Label::new(l).unwrap()).collect(),
            properties: Vec::new(),
            source_unit: unit(),
            evidence: vec![evidence()],
        }
    }

    fn set(owner: Owner, operations: Vec<GraphOperation>) -> GraphChangeSet {
        let mut change = GraphChangeSet::new(owner, text("snapshot-1"), 41);
        change.operations = operations;
        change
    }

    #[test]
    fn a_well_formed_set_validates() {
        let change = set(
            analyzer(),
            vec![GraphOperation::UpsertNode(node_draft(
                None,
                vec!["Function"],
            ))],
        );
        assert_eq!(change.validate(), Ok(()));
        assert_eq!(change.change_set_version, CHANGE_SET_VERSION);
        assert_eq!(change.base_generation, 41);
    }

    #[test]
    fn an_empty_set_and_an_unsupported_version_are_both_reported() {
        let mut change = set(analyzer(), Vec::new());
        change.change_set_version = 99;
        let errors = change.validate().unwrap_err();
        assert!(errors.contains(&ChangeSetError::UnsupportedVersion { found: 99 }));
        assert!(errors.contains(&ChangeSetError::Empty));
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let mut draft = node_draft(None, Vec::new());
        draft.evidence = Vec::new();
        let change = set(analyzer(), vec![GraphOperation::UpsertNode(draft)]);
        let errors = change.validate().unwrap_err();
        assert!(errors.contains(&ChangeSetError::Record {
            index: 0,
            violation: RecordViolation::NodeWithoutLabel
        }));
        assert!(errors.contains(&ChangeSetError::MissingEvidence { index: 0 }));
    }

    #[test]
    fn an_analyzer_needs_evidence_and_a_user_does_not() {
        let mut draft = node_draft(None, vec!["Concept"]);
        draft.evidence = Vec::new();

        let analyzer_set = set(analyzer(), vec![GraphOperation::UpsertNode(draft.clone())]);
        assert!(
            analyzer_set
                .validate()
                .unwrap_err()
                .contains(&ChangeSetError::MissingEvidence { index: 0 })
        );

        let user_set = set(Owner::User, vec![GraphOperation::UpsertNode(draft)]);
        assert_eq!(user_set.validate(), Ok(()));
    }

    #[test]
    fn duplicate_identifiers_within_one_set_are_rejected() {
        let id = LocalNodeId::from_bytes([1; 16]);
        let change = set(
            analyzer(),
            vec![
                GraphOperation::UpsertNode(node_draft(Some(id), vec!["A"])),
                GraphOperation::UpsertNode(node_draft(Some(id), vec!["B"])),
            ],
        );
        assert!(
            change
                .validate()
                .unwrap_err()
                .contains(&ChangeSetError::DuplicateNodeId { id })
        );
    }

    #[test]
    fn drafts_without_identifiers_do_not_collide() {
        let change = set(
            analyzer(),
            vec![
                GraphOperation::UpsertNode(node_draft(None, vec!["A"])),
                GraphOperation::UpsertNode(node_draft(None, vec!["B"])),
            ],
        );
        assert_eq!(change.validate(), Ok(()));
    }

    #[test]
    fn duplicate_link_sources_and_aliases_are_rejected() {
        let source = CanonicalSourceLocator::new("./packages/child").unwrap();
        let alias = LinkAlias::new("child").unwrap();
        let change = set(
            analyzer(),
            vec![
                GraphOperation::UpsertLink(LinkDraft {
                    source: source.clone(),
                    alias: Some(alias.clone()),
                }),
                GraphOperation::UpsertLink(LinkDraft {
                    source: source.clone(),
                    alias: Some(alias.clone()),
                }),
            ],
        );
        let errors = change.validate().unwrap_err();
        assert!(errors.contains(&ChangeSetError::DuplicateLinkSource {
            source: source.clone()
        }));
        assert!(errors.contains(&ChangeSetError::DuplicateLinkAlias { alias }));
    }

    #[test]
    fn declaring_and_removing_one_link_in_the_same_set_is_rejected() {
        let source = CanonicalSourceLocator::new("./packages/child").unwrap();
        let change = set(
            analyzer(),
            vec![
                GraphOperation::UpsertLink(LinkDraft {
                    source: source.clone(),
                    alias: None,
                }),
                GraphOperation::RemoveLink(source.clone()),
            ],
        );
        assert!(
            change
                .validate()
                .unwrap_err()
                .contains(&ChangeSetError::ConflictingLinkOperations { source })
        );
    }

    #[test]
    fn a_set_may_only_remove_contributions_it_owns() {
        let other = Owner::Analyzer {
            name: text("other-analyzer"),
            version: text("1.0.0"),
        };
        let change = set(
            analyzer(),
            vec![GraphOperation::RemoveContribution(ContributionKey {
                owner: other,
                source_unit: unit(),
            })],
        );
        assert!(
            change
                .validate()
                .unwrap_err()
                .contains(&ChangeSetError::OwnershipViolation { index: 0 })
        );

        let own = set(
            analyzer(),
            vec![GraphOperation::RemoveContribution(ContributionKey {
                owner: analyzer(),
                source_unit: unit(),
            })],
        );
        assert_eq!(own.validate(), Ok(()));
    }

    #[test]
    fn a_placeholder_cannot_be_replaced_by_itself() {
        let id = LocalNodeId::from_bytes([4; 16]);
        let change = set(
            analyzer(),
            vec![GraphOperation::ResolvePlaceholder(PlaceholderResolution {
                placeholder: id,
                outcome: PlaceholderOutcome::Replaced { replacement: id },
                source_unit: unit(),
                evidence: vec![evidence()],
            })],
        );
        assert!(
            change
                .validate()
                .unwrap_err()
                .contains(&ChangeSetError::PlaceholderReplacedByItself { id })
        );
    }

    #[test]
    fn preserving_a_placeholder_identity_is_the_ordinary_case() {
        let change = set(
            analyzer(),
            vec![GraphOperation::ResolvePlaceholder(PlaceholderResolution {
                placeholder: LocalNodeId::from_bytes([4; 16]),
                outcome: PlaceholderOutcome::Preserved,
                source_unit: unit(),
                evidence: vec![evidence()],
            })],
        );
        assert_eq!(change.validate(), Ok(()));
    }

    #[test]
    fn push_appends_in_order() {
        let mut change = GraphChangeSet::new(Owner::User, text("snapshot-1"), 0);
        change.push(GraphOperation::UpsertNode(node_draft(None, vec!["A"])));
        change.push(GraphOperation::RemoveLink(
            CanonicalSourceLocator::new("./gone").unwrap(),
        ));
        assert_eq!(change.operations.len(), 2);
        assert!(matches!(
            change.operations[1],
            GraphOperation::RemoveLink(_)
        ));
    }
}
