//! Synchronization between `.nostdb` and `.nost`.
//!
//! # Why a baseline rather than a timestamp
//!
//! Synchronization compares a baseline of generation and content digests, never
//! wall-clock time. Two machines can disagree about the time while both files are
//! legitimate, and a file copy can carry any modification time at all. A generation
//! advances only on a successful commit, and a digest changes only when bytes change,
//! so both are properties of the content rather than of the environment.
//!
//! # A conflict is not a retry
//!
//! When both representations changed from one baseline, this reports
//! [`SyncOutcome::Conflict`] and modifies neither. Both sides hold work derived from
//! the same starting point, so preferring either one would discard the other silently.
//! Resolving that is a human decision, which is why there is no "force" outcome here.

use crate::diagnostic::{Diagnostic, DiagnosticCode, Severity};
use crate::evidence::ContentDigest;
use crate::generation::Generation;
use crate::text::NonEmptyText;
use sha2::{Digest as _, Sha256};
use std::fmt;

/// Computes the content digest of arbitrary bytes.
///
/// The result is tagged `sha256:` followed by lower-case hexadecimal, which is the
/// form [`ContentDigest`] requires.
#[must_use]
pub fn digest_bytes(bytes: &[u8]) -> ContentDigest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut text = String::from("sha256:");
    for byte in hasher.finalize() {
        text.push_str(&format!("{byte:02x}"));
    }
    // The value is constructed to match the required shape, so this cannot fail; the
    // fallback keeps the function free of a panic path.
    ContentDigest::new(text)
        .unwrap_or_else(|_| ContentDigest::literal("sha256:00000000000000000000000000000000"))
}

/// Computes the content digest of text.
///
/// Text is digested as its UTF-8 bytes, so the same characters always produce the same
/// digest regardless of how they were read.
#[must_use]
pub fn digest_text(text: &str) -> ContentDigest {
    digest_bytes(text.as_bytes())
}

/// The state both representations were in when they last agreed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncBaseline {
    /// The generation the `.nost` file was produced from.
    pub database_generation: Generation,
    /// Digest of the database at that generation.
    pub database_digest: ContentDigest,
    /// Digest of the `.nost` text as produced.
    pub nost_content_digest: ContentDigest,
}

/// The state both representations are in now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncState {
    /// The database's current generation.
    pub database_generation: Generation,
    /// Digest of the database's current bytes.
    pub database_digest: ContentDigest,
    /// Digest of the `.nost` file's current text.
    pub nost_content_digest: ContentDigest,
}

/// What synchronization should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Neither side moved. Nothing to do.
    UpToDate,
    /// Only the `.nost` file moved, so it should be validated and adopted into the
    /// database as one atomic transaction.
    AdoptNost,
    /// Only the database moved, so the `.nost` file no longer describes it.
    ///
    /// The database stays authoritative and readable. Regeneration is explicit,
    /// because a stale file may hold edits its author has not applied.
    NostStale,
    /// Both sides moved from one baseline. Neither is modified.
    Conflict,
}

impl SyncOutcome {
    /// The stable diagnostic code for this outcome, when it has one.
    ///
    /// The two acting outcomes report nothing, because doing the work is not a finding.
    #[must_use]
    pub const fn code(&self) -> Option<DiagnosticCode> {
        match self {
            Self::UpToDate | Self::AdoptNost => None,
            Self::NostStale => Some(DiagnosticCode::NostSourceStale),
            Self::Conflict => Some(DiagnosticCode::SyncConflict),
        }
    }

    /// Reports whether this outcome permits modifying either representation.
    #[must_use]
    pub const fn may_modify(&self) -> bool {
        matches!(self, Self::AdoptNost)
    }

    /// Renders this outcome as a diagnostic, when it reports one.
    #[must_use]
    pub fn to_diagnostic(&self) -> Option<Diagnostic> {
        let code = self.code()?;
        let message = match self {
            Self::NostStale => {
                "the database advanced while the .nost file did not, so the file must be \
                 regenerated explicitly"
            }
            Self::Conflict => {
                "both the database and the .nost file changed from the same baseline, so \
                 neither was modified"
            }
            Self::UpToDate | Self::AdoptNost => return None,
        };
        Some(Diagnostic {
            code,
            severity: Severity::Error,
            message: NonEmptyText::literal(message),
            source: None,
            range: None,
            details: Vec::new(),
        })
    }
}

impl fmt::Display for SyncOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UpToDate => "up to date",
            Self::AdoptNost => "adopt the .nost file",
            Self::NostStale => "the .nost file is stale",
            Self::Conflict => "a synchronization conflict",
        })
    }
}

/// Which side of the pair moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// Whether the database moved since the baseline.
    pub database_changed: bool,
    /// Whether the `.nost` file moved since the baseline.
    pub nost_changed: bool,
}

/// Compares a baseline against the current state.
///
/// The database counts as changed when either its generation or its digest differs. The
/// generation alone is not enough, because a failed or externally rewritten file could
/// carry the same generation with different bytes; the digest alone is not enough
/// either, because it says nothing about ordering.
#[must_use]
pub fn diverged(baseline: &SyncBaseline, current: &SyncState) -> Divergence {
    Divergence {
        database_changed: current.database_generation != baseline.database_generation
            || current.database_digest != baseline.database_digest,
        nost_changed: current.nost_content_digest != baseline.nost_content_digest,
    }
}

/// Decides what synchronization should do.
#[must_use]
pub fn decide(baseline: &SyncBaseline, current: &SyncState) -> SyncOutcome {
    let divergence = diverged(baseline, current);
    match (divergence.database_changed, divergence.nost_changed) {
        (false, false) => SyncOutcome::UpToDate,
        (false, true) => SyncOutcome::AdoptNost,
        (true, false) => SyncOutcome::NostStale,
        (true, true) => SyncOutcome::Conflict,
    }
}

/// Builds the baseline recorded after the two representations are made to agree.
#[must_use]
pub fn baseline_from(
    database_generation: Generation,
    database_bytes: &[u8],
    nost_text: &str,
) -> SyncBaseline {
    SyncBaseline {
        database_generation,
        database_digest: digest_bytes(database_bytes),
        nost_content_digest: digest_text(nost_text),
    }
}

/// Builds the current state from what is on disk now.
#[must_use]
pub fn state_from(
    database_generation: Generation,
    database_bytes: &[u8],
    nost_text: &str,
) -> SyncState {
    SyncState {
        database_generation,
        database_digest: digest_bytes(database_bytes),
        nost_content_digest: digest_text(nost_text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> SyncBaseline {
        baseline_from(Generation::from_raw(5), b"database bytes", "@nost 1\n")
    }

    fn unchanged() -> SyncState {
        state_from(Generation::from_raw(5), b"database bytes", "@nost 1\n")
    }

    #[test]
    fn sha256_matches_its_published_vectors() {
        // Without a known answer, a wrong implementation would agree with itself.
        assert_eq!(
            digest_bytes(b"abc").as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest_bytes(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest_text("abc"), digest_bytes(b"abc"));
    }

    #[test]
    fn identical_content_digests_identically_and_a_single_bit_changes_it() {
        assert_eq!(digest_bytes(b"same"), digest_bytes(b"same"));
        assert_ne!(digest_bytes(b"same"), digest_bytes(b"sane"));
        assert_ne!(digest_text("a"), digest_text("a\n"));
    }

    #[test]
    fn neither_side_moved_is_a_no_op() {
        let outcome = decide(&baseline(), &unchanged());
        assert_eq!(outcome, SyncOutcome::UpToDate);
        assert_eq!(outcome.code(), None);
        assert!(!outcome.may_modify());
        assert!(outcome.to_diagnostic().is_none());
    }

    #[test]
    fn only_the_nost_file_moved_is_adopted() {
        let current = state_from(
            Generation::from_raw(5),
            b"database bytes",
            "@nost 1\nmodule m id \"m_1\" {}\n",
        );
        let outcome = decide(&baseline(), &current);
        assert_eq!(outcome, SyncOutcome::AdoptNost);
        assert_eq!(outcome.code(), None);
        assert!(outcome.may_modify());
    }

    #[test]
    fn only_the_database_moved_makes_the_file_stale() {
        let current = state_from(Generation::from_raw(6), b"new database bytes", "@nost 1\n");
        let outcome = decide(&baseline(), &current);
        assert_eq!(outcome, SyncOutcome::NostStale);
        assert_eq!(outcome.code(), Some(DiagnosticCode::NostSourceStale));
        assert!(!outcome.may_modify());
        let diagnostic = outcome.to_diagnostic().expect("a stale file reports");
        assert_eq!(diagnostic.severity, Severity::Error);
    }

    #[test]
    fn both_moving_is_a_conflict_that_permits_no_modification() {
        let current = state_from(
            Generation::from_raw(6),
            b"new database bytes",
            "@nost 1\nmodule m id \"m_1\" {}\n",
        );
        let outcome = decide(&baseline(), &current);
        assert_eq!(outcome, SyncOutcome::Conflict);
        assert_eq!(outcome.code(), Some(DiagnosticCode::SyncConflict));
        // The whole point: a conflict never authorizes a write.
        assert!(!outcome.may_modify());
    }

    #[test]
    fn a_rewritten_database_at_the_same_generation_still_counts_as_changed() {
        // A generation comparison alone would miss this, and calling it unchanged would
        // let an externally rewritten file be treated as the baseline.
        let current = state_from(Generation::from_raw(5), b"tampered bytes", "@nost 1\n");
        assert_eq!(decide(&baseline(), &current), SyncOutcome::NostStale);
        assert!(diverged(&baseline(), &current).database_changed);
    }

    #[test]
    fn a_generation_change_alone_counts_as_changed() {
        // Identical bytes at a different generation should not be called unchanged
        // either, because ordering is information a digest does not carry.
        let current = state_from(Generation::from_raw(9), b"database bytes", "@nost 1\n");
        assert!(diverged(&baseline(), &current).database_changed);
    }

    #[test]
    fn exactly_one_outcome_permits_modification() {
        let permitted: Vec<SyncOutcome> = [
            SyncOutcome::UpToDate,
            SyncOutcome::AdoptNost,
            SyncOutcome::NostStale,
            SyncOutcome::Conflict,
        ]
        .into_iter()
        .filter(SyncOutcome::may_modify)
        .collect();
        assert_eq!(permitted, vec![SyncOutcome::AdoptNost]);
    }

    #[test]
    fn every_reporting_outcome_carries_a_registered_code() {
        for outcome in [SyncOutcome::NostStale, SyncOutcome::Conflict] {
            let code = outcome.code().expect("reports a code");
            assert!(DiagnosticCode::ALL.contains(&code));
        }
    }
}
