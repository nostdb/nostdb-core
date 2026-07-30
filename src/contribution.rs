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

/// Who produced a contribution: one name, and nothing beside it.
///
/// # Why one string rather than a structure
///
/// This was an enum carrying an analyzer's name **and version**, an AI contract digest, or nothing.
/// The version is what made it a structure, and carrying it produced the defect
/// [`crate::build::analyzer_owner`] documents: move the version and every record an earlier build wrote
/// answers to a name no change set names, so nothing can withdraw them and the graph holds two readings
/// of every file for ever.
///
/// `nostdb-spec` justified the version by saying an upgraded analyzer must not "silently adopt the
/// previous version's facts as the new version's own". Not adopting them was never the behavior anyone
/// wanted. What section 11.3 needs is that a refresh replaces its **own** prior contributions and leaves
/// other producers' alone, and that is what one name delivers.
///
/// # The kind is derived, not declared
///
/// [`RESERVED_USER`] is the user. A name beginning [`AI_PREFIX`] is AI analysis, and what follows is the
/// digest of the contract it ran under. Anything else is an analyzer. Both spellings are reserved,
/// because otherwise an analyzer called `user` would silently become the user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Owner(NonEmptyText);

/// The owner a user's own contributions carry.
pub const RESERVED_USER: &str = "user";

/// The prefix an AI contribution's owner carries, followed by its contract digest.
pub const AI_PREFIX: &str = "ai:";

impl Owner {
    /// An owner from a name, which is any non-empty text.
    ///
    /// No validation beyond non-emptiness, deliberately. A third-party analyzer names itself, and a
    /// closed list here would be the allowlist section 4 forbids wearing a different hat.
    #[must_use]
    pub const fn new(name: NonEmptyText) -> Self {
        Self(name)
    }

    /// The user.
    #[must_use]
    pub fn user() -> Self {
        Self(NonEmptyText::literal(RESERVED_USER))
    }

    /// AI analysis under one analysis contract.
    #[must_use]
    pub fn ai(contract_digest: &ContentDigest) -> Self {
        let spelled = format!("{AI_PREFIX}{}", contract_digest.as_str());
        Self(NonEmptyText::new(spelled).unwrap_or_else(|_| NonEmptyText::literal("ai:unknown")))
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The contract digest an AI owner names, when this is one.
    #[must_use]
    pub fn contract_digest(&self) -> Option<&str> {
        self.as_str().strip_prefix(AI_PREFIX)
    }

    /// Reports whether this owner must supply evidence.
    ///
    /// An analyzer-created or AI-created record must have provenance, per the root
    /// PRD section 11.4. A user-declared record need not, because the user is the
    /// evidence.
    #[must_use]
    pub fn requires_evidence(&self) -> bool {
        self.kind() != OwnerKind::User
    }

    /// The owner category, read from the name.
    #[must_use]
    pub fn kind(&self) -> OwnerKind {
        if self.as_str() == RESERVED_USER {
            OwnerKind::User
        } else if self.as_str().starts_with(AI_PREFIX) {
            OwnerKind::AiAnalysis
        } else {
            OwnerKind::Analyzer
        }
    }
}

impl std::fmt::Display for Owner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
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
        Owner::new(NonEmptyText::new("rust-structural").unwrap())
    }

    fn digest() -> ContentDigest {
        ContentDigest::new("sha256:abcdef0123456789abcdef0123456789").unwrap()
    }

    #[test]
    fn only_a_user_may_omit_evidence() {
        assert!(analyzer().requires_evidence());
        assert!(Owner::ai(&digest()).requires_evidence());
        assert!(!Owner::user().requires_evidence());
    }

    #[test]
    fn the_kind_is_read_from_the_name() {
        // No keyword declares it, so these three spellings are the whole of the rule. An analyzer is
        // whatever the other two are not, which is what lets a third-party analyzer name itself.
        assert_eq!(Owner::user().kind(), OwnerKind::User);
        assert_eq!(Owner::ai(&digest()).kind(), OwnerKind::AiAnalysis);
        assert_eq!(analyzer().kind(), OwnerKind::Analyzer);
    }

    #[test]
    fn an_ai_owner_carries_the_contract_it_ran_under() {
        // The digest is not decoration: it is how one AI contribution is told from another and withdrawn
        // on its own. Folding the owner into one string must not lose it.
        let owner = Owner::ai(&digest());
        assert_eq!(owner.contract_digest(), Some(digest().as_str()));
        assert_eq!(analyzer().contract_digest(), None);
    }

    #[test]
    fn a_version_is_no_longer_part_of_an_owners_identity() {
        // It used to be, and `nostdb-spec` justified it by saying an upgraded analyzer must not adopt the
        // previous version's facts. That is what left records nothing could withdraw when the version
        // moved. One name means a refresh replaces its own prior work, which is what section 11.3 needs.
        assert_eq!(
            Owner::new(NonEmptyText::literal("nostdb")),
            Owner::new(NonEmptyText::literal("nostdb"))
        );
        assert_ne!(analyzer(), Owner::new(NonEmptyText::literal("nostdb")));
    }

    #[test]
    fn a_reserved_name_is_not_available_to_an_analyzer() {
        // Stated as a test because the reservation is only a convention in the type: nothing stops
        // `Owner::new` from being handed `user`, and what it produces is the user rather than an analyzer
        // that happens to be called that. The spec says so; this is what makes it true here.
        assert_eq!(
            Owner::new(NonEmptyText::literal(RESERVED_USER)).kind(),
            OwnerKind::User
        );
        assert_eq!(
            Owner::new(NonEmptyText::literal("ai:anything")).kind(),
            OwnerKind::AiAnalysis
        );
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
