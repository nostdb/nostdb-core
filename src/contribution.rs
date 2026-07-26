//! Ownership of graph records.
//!
//! A graph record may carry contributions from several producers at once. An
//! analyzer refresh replaces only the contributions owned by that analyzer for that
//! source unit; it preserves user contributions and contributions from other
//! analyzers. That is the rule in the root PRD section 11.3, and it is why
//! ownership is a first-class part of the model rather than a flag on a record.

use crate::evidence::{ContentDigest, Evidence};
use crate::id::SourceUnitId;
use crate::text::NonEmptyText;

/// Who produced a contribution.
#[derive(Clone, Debug, PartialEq)]
pub enum Owner {
    /// A deterministic analyzer, identified by name and version.
    ///
    /// The version is part of the identity, so upgrading an analyzer does not
    /// silently adopt facts the previous version produced.
    Analyzer {
        /// Analyzer name.
        name: NonEmptyText,
        /// Analyzer version.
        version: NonEmptyText,
    },
    /// AI analysis, identified by the digest of the analysis contract it ran under.
    AiAnalysis {
        /// Digest of the analysis contract.
        contract_digest: ContentDigest,
    },
    /// A user.
    User,
}

impl Owner {
    /// Reports whether this owner must supply evidence.
    ///
    /// An analyzer-created or AI-created record must have provenance, per the root
    /// PRD section 11.4. A user-declared record need not, because the user is the
    /// evidence.
    #[must_use]
    pub const fn requires_evidence(&self) -> bool {
        !matches!(self, Self::User)
    }

    /// The owner category, without its identifying detail.
    #[must_use]
    pub const fn kind(&self) -> OwnerKind {
        match self {
            Self::Analyzer { .. } => OwnerKind::Analyzer,
            Self::AiAnalysis { .. } => OwnerKind::AiAnalysis,
            Self::User => OwnerKind::User,
        }
    }
}

/// An owner category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OwnerKind {
    /// A deterministic analyzer.
    Analyzer,
    /// AI analysis.
    AiAnalysis,
    /// A user.
    User,
}

/// One producer's contribution to a graph record.
#[derive(Clone, Debug, PartialEq)]
pub struct Contribution {
    /// Who produced it.
    pub owner: Owner,
    /// The source unit it was derived from.
    pub source_unit: SourceUnitId,
    /// Provenance for the facts it asserts.
    pub evidence: Vec<Evidence>,
}

impl Contribution {
    /// The key that identifies this contribution for replacement or removal.
    #[must_use]
    pub fn key(&self) -> ContributionKey {
        ContributionKey {
            owner: self.owner.clone(),
            source_unit: self.source_unit,
        }
    }
}

/// Identifies a contribution without carrying its evidence.
///
/// A refresh or removal names the pair of owner and source unit, which is the
/// narrowest thing an analyzer is permitted to replace.
#[derive(Clone, Debug, PartialEq)]
pub struct ContributionKey {
    /// Who produced the contribution.
    pub owner: Owner,
    /// The source unit it was derived from.
    pub source_unit: SourceUnitId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer() -> Owner {
        Owner::Analyzer {
            name: NonEmptyText::new("rust-structural").unwrap(),
            version: NonEmptyText::new("0.1.0").unwrap(),
        }
    }

    #[test]
    fn only_a_user_may_omit_evidence() {
        assert!(analyzer().requires_evidence());
        assert!(
            Owner::AiAnalysis {
                contract_digest: ContentDigest::new("sha256:abcdef0123456789abcdef0123456789")
                    .unwrap(),
            }
            .requires_evidence()
        );
        assert!(!Owner::User.requires_evidence());
    }

    #[test]
    fn an_analyzer_version_is_part_of_its_identity() {
        let newer = Owner::Analyzer {
            name: NonEmptyText::new("rust-structural").unwrap(),
            version: NonEmptyText::new("0.2.0").unwrap(),
        };
        assert_ne!(analyzer(), newer);
        assert_eq!(analyzer().kind(), newer.kind());
    }

    #[test]
    fn a_contribution_key_drops_evidence_but_keeps_ownership() {
        let contribution = Contribution {
            owner: analyzer(),
            source_unit: SourceUnitId::from_bytes([7; 16]),
            evidence: Vec::new(),
        };
        let key = contribution.key();
        assert_eq!(key.owner, analyzer());
        assert_eq!(key.source_unit, SourceUnitId::from_bytes([7; 16]));
    }
}
