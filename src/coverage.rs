//! Build coverage.
//!
//! Coverage is how a build reports what it did not do. A build that quietly skipped
//! half a repository and reported success would be worse than one that failed, so
//! skipped, deferred, and failed work is recorded explicitly.

use crate::id::SourceUnitId;
use crate::locator::CanonicalSourceLocator;
use crate::text::NonEmptyText;
use std::fmt;

/// Current `coverage_version`.
pub const COVERAGE_VERSION: u32 = 1;

/// How complete one phase of a build is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoverageState {
    /// Every eligible unit was processed.
    Complete,
    /// Some eligible units remain, because of a budget, a failure, or a deferral.
    Partial,
    /// The phase did not run.
    Skipped,
    /// The phase ran and failed as a whole.
    Failed,
}

impl fmt::Display for CoverageState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        })
    }
}

/// Why a source was not analyzed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// Excluded by ignore rules.
    Ignored,
    /// Identified as potentially sensitive, so it was withheld from analysis.
    Sensitive,
    /// Its kind could not be determined.
    Unclassified,
    /// The provider refused access.
    PermissionDenied,
    /// No analyzer declares support, and AI analysis did not run.
    Unsupported,
    /// Larger than the configured limit.
    TooLarge,
    /// Detected as binary content.
    Binary,
    /// Reached through a symlink cycle.
    SymlinkCycle,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ignored => "ignored",
            Self::Sensitive => "sensitive",
            Self::Unclassified => "unclassified",
            Self::PermissionDenied => "permission denied",
            Self::Unsupported => "unsupported",
            Self::TooLarge => "too large",
            Self::Binary => "binary",
            Self::SymlinkCycle => "symlink cycle",
        })
    }
}

/// A source unit that failed to analyze.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceUnitFailure {
    /// Which unit failed.
    pub source_unit: SourceUnitId,
    /// Why it failed.
    pub reason: NonEmptyText,
}

/// A source that was not analyzed.
#[derive(Clone, Debug, PartialEq)]
pub struct SkippedSource {
    /// The source it belongs to.
    pub source: CanonicalSourceLocator,
    /// The path within that source, when there is one.
    pub path: Option<NonEmptyText>,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// What a build covered.
#[derive(Clone, Debug, PartialEq)]
pub struct BuildCoverage {
    /// Version of this contract.
    pub coverage_version: u32,
    /// How complete deterministic structural extraction is.
    pub structural: CoverageState,
    /// How complete optional semantic enrichment is.
    pub semantic: CoverageState,
    /// Units served from a reusable analysis artifact.
    pub cached_units: u64,
    /// Units left for a later run.
    pub deferred_units: u64,
    /// Units that failed.
    pub failed_units: Vec<SourceUnitFailure>,
    /// Sources that were not analyzed.
    pub skipped_sources: Vec<SkippedSource>,
    /// References that did not resolve, and therefore produced Placeholders.
    pub unresolved_units: u64,
}

impl BuildCoverage {
    /// An empty coverage report at the current contract version.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            coverage_version: COVERAGE_VERSION,
            structural: CoverageState::Skipped,
            semantic: CoverageState::Skipped,
            cached_units: 0,
            deferred_units: 0,
            failed_units: Vec::new(),
            skipped_sources: Vec::new(),
            unresolved_units: 0,
        }
    }

    /// Reports whether the build left work undone.
    ///
    /// A caller uses this to decide whether to present a result as partial. It is
    /// deliberately broader than `structural == Partial`: deferred or failed units
    /// make a result partial even when both phases report themselves complete.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.structural != CoverageState::Complete
            || self.semantic == CoverageState::Partial
            || self.semantic == CoverageState::Failed
            || self.deferred_units > 0
            || !self.failed_units.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_report_is_partial_because_nothing_ran() {
        let coverage = BuildCoverage::empty();
        assert_eq!(coverage.coverage_version, COVERAGE_VERSION);
        assert!(coverage.is_partial());
    }

    #[test]
    fn a_complete_structural_build_without_enrichment_is_not_partial() {
        let coverage = BuildCoverage {
            structural: CoverageState::Complete,
            semantic: CoverageState::Skipped,
            ..BuildCoverage::empty()
        };
        assert!(!coverage.is_partial());
    }

    #[test]
    fn deferred_or_failed_units_make_a_complete_build_partial() {
        let deferred = BuildCoverage {
            structural: CoverageState::Complete,
            semantic: CoverageState::Complete,
            deferred_units: 1,
            ..BuildCoverage::empty()
        };
        assert!(deferred.is_partial());

        let failed = BuildCoverage {
            structural: CoverageState::Complete,
            semantic: CoverageState::Complete,
            failed_units: vec![SourceUnitFailure {
                source_unit: SourceUnitId::from_bytes([1; 16]),
                reason: NonEmptyText::new("analyzer crashed").unwrap(),
            }],
            ..BuildCoverage::empty()
        };
        assert!(failed.is_partial());
    }

    #[test]
    fn a_skipped_source_alone_does_not_make_a_build_partial() {
        // An ignored file is expected, not missing work.
        let coverage = BuildCoverage {
            structural: CoverageState::Complete,
            semantic: CoverageState::Complete,
            skipped_sources: vec![SkippedSource {
                source: CanonicalSourceLocator::new("./packages/child").unwrap(),
                path: Some(NonEmptyText::new("target/debug/build.log").unwrap()),
                reason: SkipReason::Ignored,
            }],
            ..BuildCoverage::empty()
        };
        assert!(!coverage.is_partial());
    }
}
