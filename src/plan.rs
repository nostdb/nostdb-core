//! What a build would do, decided before it does any of it.
//!
//! Root PRD section 17.6 states the rule this module exists to enforce: no AI action
//! begins before producing a plan. A plan is therefore not a progress report — it is
//! produced from a scan and a capability registry alone, spends nothing, and is what a
//! budget check runs against.
//!
//! # The estimate is wide on purpose
//!
//! Token counts here are a heuristic over byte counts, not a tokenizer's answer. A
//! narrow estimate that is wrong is worse than a wide estimate that is right: the budget
//! check uses [`TokenRange::high`], so understating the cost is what lets a run start a
//! call it cannot afford. The band is stated in [`estimate_input`] rather than tuned
//! quietly.
//!
//! # What is counted, and what is spent
//!
//! `semantic_candidates` counts the files AI *would* read. The token estimates describe what
//! *this* run would spend, which is zero when [`AiMode::Off`] is configured. Keeping them
//! separate is what lets a plan say "412 files could be enriched, and this run will spend
//! nothing" instead of implying one from the other.
//!
//! What AI would read depends on the mode, because the modes ask for different things.
//! [`AiMode::Auto`] asks for a second pass over what the analyzers could not cover;
//! [`AiMode::Full`] asks for AI *instead of* them, so every scanned file is read. A plan that
//! counted only the unsupported files in `Full` would under-report the whole run — and the
//! budget is checked against this plan, so under-reporting it is how a hard limit gets passed
//! without anything noticing.

use crate::analysis::{CapabilityRegistry, PrecisionClass};
use crate::coverage::SkipReason;
use crate::scan::Scan;
use crate::settings::{AiMode, AnalysisSettings, BudgetAction};
use std::collections::BTreeMap;
use std::fmt;

/// Version of the plan contract.
pub const PLAN_VERSION: u32 = 1;

/// Bytes per token at the verbose end of the band.
const BYTES_PER_TOKEN_LOW: u64 = 6;

/// Bytes per token at the dense end of the band.
const BYTES_PER_TOKEN_HIGH: u64 = 2;

/// Tokens one analysis packet costs beyond the source it carries.
///
/// The packet envelope — the contract, the schema excerpt, the instructions — is charged
/// per unit rather than per byte, because it does not shrink with a small file.
const PACKET_OVERHEAD_TOKENS: u64 = 200;

/// Tokens one enriched unit is expected to produce, at the low end.
const OUTPUT_TOKENS_LOW: u64 = 64;

/// Tokens one enriched unit is expected to produce, at the high end.
const OUTPUT_TOKENS_HIGH: u64 = 512;

/// An estimate with an explicit spread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenRange {
    /// The optimistic end.
    pub low: u64,
    /// The pessimistic end, which is the one a budget check uses.
    pub high: u64,
}

impl TokenRange {
    /// A range that spends nothing.
    pub const ZERO: Self = Self { low: 0, high: 0 };

    /// A range from its two ends, ordered so `low` never exceeds `high`.
    #[must_use]
    pub const fn new(low: u64, high: u64) -> Self {
        if low > high {
            Self {
                low: high,
                high: low,
            }
        } else {
            Self { low, high }
        }
    }

    /// Reports whether this range spends nothing at either end.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.high == 0
    }
}

impl fmt::Display for TokenRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low == self.high {
            write!(formatter, "{}", self.low)
        } else {
            write!(formatter, "{}–{}", self.low, self.high)
        }
    }
}

/// The ceilings an AI run may not cross.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AiBudget {
    /// Hard input-token ceiling, or unlimited.
    pub max_input_tokens: Option<u64>,
    /// Hard output-token ceiling, or unlimited.
    pub max_output_tokens: Option<u64>,
    /// Advisory cost ceiling, as a decimal string so a currency amount is never a float.
    pub max_cost_usd: Option<String>,
    /// What to do at a ceiling.
    pub on_exceeded: BudgetAction,
}

impl AiBudget {
    /// The budget the configured analysis settings describe.
    #[must_use]
    pub fn from_settings(analysis: &AnalysisSettings) -> Self {
        Self {
            max_input_tokens: analysis.max_input_tokens,
            max_output_tokens: analysis.max_output_tokens,
            max_cost_usd: analysis.max_cost_usd.clone(),
            on_exceeded: analysis.on_budget_exceeded,
        }
    }

    /// Reports whether an estimated run fits.
    ///
    /// Checked against [`TokenRange::high`], because section 17.6 requires that a call
    /// which *could* exceed a hard limit never starts. Comparing the optimistic end would
    /// make the limit advisory in exactly the cases where it matters.
    #[must_use]
    pub fn check(&self, input: TokenRange, output: TokenRange) -> BudgetCheck {
        if let Some(limit) = self.max_input_tokens
            && input.high > limit
        {
            return BudgetCheck::Exceeds {
                field: "max_input_tokens",
                estimated: input.high,
                limit,
            };
        }
        if let Some(limit) = self.max_output_tokens
            && output.high > limit
        {
            return BudgetCheck::Exceeds {
                field: "max_output_tokens",
                estimated: output.high,
                limit,
            };
        }
        BudgetCheck::Fits
    }

    /// Reports whether any hard ceiling is configured.
    ///
    /// With none, section 17.6 requires the Skill to show the estimate and ask once before
    /// enrichment rather than proceeding on a default.
    #[must_use]
    pub const fn has_hard_limit(&self) -> bool {
        self.max_input_tokens.is_some() || self.max_output_tokens.is_some()
    }
}

/// What a budget check decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetCheck {
    /// The estimated run fits every hard ceiling.
    Fits,
    /// A ceiling would be crossed.
    Exceeds {
        /// Which ceiling.
        field: &'static str,
        /// The pessimistic estimate that crossed it.
        estimated: u64,
        /// The ceiling.
        limit: u64,
    },
}

impl BudgetCheck {
    /// Reports whether the run may start.
    #[must_use]
    pub const fn fits(self) -> bool {
        matches!(self, Self::Fits)
    }
}

impl fmt::Display for BudgetCheck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fits => formatter.write_str("within budget"),
            Self::Exceeds {
                field,
                estimated,
                limit,
            } => write!(
                formatter,
                "{field} is {limit} and this run could reach {estimated}"
            ),
        }
    }
}

/// What a build would do.
///
/// The shape root PRD section 17.6 publishes, field for field. Anything this build also
/// knows lives in [`PlanReport`] beside it, so the published contract stays exactly what
/// the contract says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildPlan {
    /// Version of this contract.
    pub plan_version: u32,
    /// The immutable snapshot this plan describes.
    pub source_revision: String,
    /// Files the scanner reached and did not exclude.
    pub scanned_files: u64,
    /// Files a deterministic analyzer covers.
    pub structural_files: u64,
    /// Files no analyzer covers.
    pub unsupported_files: u64,
    /// Files eligible for AI enrichment.
    pub semantic_candidates: u64,
    /// Candidates a reusable artifact already answers.
    pub semantic_cache_hits: u64,
    /// What this run would send.
    pub estimated_input_tokens: TokenRange,
    /// What this run would receive.
    pub estimated_output_tokens: TokenRange,
    /// The ceilings it may not cross.
    pub budget: AiBudget,
}

impl BuildPlan {
    /// Reports whether this run would spend any AI tokens.
    #[must_use]
    pub const fn spends_tokens(&self) -> bool {
        !self.estimated_input_tokens.is_zero()
    }

    /// Reports whether the estimated run fits every hard ceiling.
    #[must_use]
    pub fn within_budget(&self) -> BudgetCheck {
        self.budget
            .check(self.estimated_input_tokens, self.estimated_output_tokens)
    }
}

/// What one language contributes to a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanguageSummary {
    /// The language.
    pub language: String,
    /// How many files carry it.
    pub files: u64,
    /// How many bytes they hold.
    pub bytes: u64,
    /// The best precision available for it.
    pub precision: PrecisionClass,
}

/// A plan and everything this build knows beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanReport {
    /// The published plan.
    pub plan: BuildPlan,
    /// What each language contributes, in name order.
    pub languages: Vec<LanguageSummary>,
    /// How many files each exclusion accounts for, in reason order.
    pub skipped: Vec<(SkipReason, u64)>,
    /// Whether AI enrichment is permitted at all.
    pub ai_mode: AiMode,
}

impl PlanReport {
    /// Files the scanner excluded, for every reason together.
    #[must_use]
    pub fn skipped_files(&self) -> u64 {
        self.skipped.iter().map(|(_, count)| count).sum()
    }
}

/// The immutable snapshot identity of a scanned tree.
///
/// A provider supplies this for a remote source: section 15 requires a branch or tag to be
/// resolved to one commit before analysis. A local working tree has no such identity, so it
/// is derived from what was scanned — every path with the digest of its contents, in the
/// scan's own sorted order.
///
/// Tagged `tree:` so it is never mistaken for a commit. Two trees with the same revision
/// hold the same analyzable bytes at the same paths, which is exactly what an incremental
/// rebuild needs to decide it can skip everything.
#[must_use]
pub fn source_revision(scan: &Scan) -> String {
    let mut material = Vec::new();
    for file in &scan.files {
        material.extend_from_slice(file.path.as_bytes());
        material.push(0);
        material.extend_from_slice(file.digest.as_str().as_bytes());
        material.push(b'\n');
    }
    format!("tree:{}", crate::sync::digest_bytes(&material).as_str())
}

/// Estimates the input tokens `bytes` of source costs across `units` packets.
///
/// The band is deliberately wide. Six bytes per token is verbose, well-spaced source; two
/// is dense or minified. A real tokenizer would narrow it, and pulling one in for an
/// estimate that only has to be a safe bound would be a dependency bought for nothing.
///
/// Packet overhead is charged per unit, because the contract and instructions wrapped
/// around a small file do not shrink with it.
#[must_use]
pub fn estimate_input(bytes: u64, units: u64) -> TokenRange {
    if units == 0 {
        return TokenRange::ZERO;
    }
    let overhead = units.saturating_mul(PACKET_OVERHEAD_TOKENS);
    TokenRange::new(
        (bytes / BYTES_PER_TOKEN_LOW).saturating_add(overhead),
        (bytes / BYTES_PER_TOKEN_HIGH).saturating_add(overhead),
    )
}

/// Estimates the output tokens `units` enriched units produce.
///
/// Charged per unit rather than as a fraction of the input. Enrichment produces a summary,
/// and a summary of a large file is not proportionally larger than a summary of a small
/// one.
#[must_use]
pub fn estimate_output(units: u64) -> TokenRange {
    TokenRange::new(
        units.saturating_mul(OUTPUT_TOKENS_LOW),
        units.saturating_mul(OUTPUT_TOKENS_HIGH),
    )
}

/// Whether AI would read a file at this precision, in this mode.
///
/// [`AiMode::Full`] is the whole tree, because in that mode **AI is the reader** rather than the second
/// pass: the caller asked for it instead of the analyzers, not on top of them. Every other mode reads what
/// an analyzer could not cover, which is what [`PrecisionClass::eligible_for_ai`] names.
///
/// [`AiMode::Off`] answers as [`AiMode::Auto`] does, and deliberately. The count is what AI *would* read,
/// and the estimate below is what this run spends — so a plan can say "412 files could be enriched, and this
/// run will spend nothing" rather than implying one from the other. Returning nothing here would collapse
/// that into a zero a reader cannot tell from "there is nothing to enrich".
///
/// This is the first thing in the crate that tells `Full` from `Auto`. Until now the only branch on
/// `ai_mode` anywhere was the `Off` test below, so a mode documented as "enrichment is required" estimated
/// exactly what the optional one did.
const fn reads(mode: AiMode, precision: PrecisionClass) -> bool {
    match mode {
        // Unsupported text is the fallback path, not a dead end. A heuristic analyzer's output is also
        // eligible, because it is the case enrichment exists to improve.
        AiMode::Off | AiMode::Auto => precision.eligible_for_ai(),
        AiMode::Full => true,
    }
}

/// Produces the plan for one scan.
///
/// Pure: it reads no file and spends nothing. Everything it reports comes from the scan
/// already in hand, the analyzers registered, and the configured budget.
#[must_use]
pub fn plan(scan: &Scan, registry: &CapabilityRegistry, analysis: &AnalysisSettings) -> PlanReport {
    let mut per_language: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for file in &scan.files {
        let entry = per_language.entry(file.language.as_str()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += file.bytes;
    }

    let mut languages = Vec::with_capacity(per_language.len());
    let mut structural_files = 0_u64;
    let mut unsupported_files = 0_u64;
    let mut candidate_files = 0_u64;
    let mut candidate_bytes = 0_u64;

    for (language, (files, bytes)) in per_language {
        let precision = registry.precision(language);
        if precision.is_deterministic() {
            structural_files += files;
        }
        if precision == PrecisionClass::Unsupported {
            unsupported_files += files;
        }
        if reads(analysis.ai_mode, precision) {
            candidate_files += files;
            candidate_bytes += bytes;
        }
        languages.push(LanguageSummary {
            language: language.to_owned(),
            files,
            bytes,
            precision,
        });
    }

    // Candidates are a fact about the source; the estimate is what this run would spend.
    // With AI off nothing is sent, and saying so beats implying it from a zero count.
    let (input, output) = if analysis.ai_mode == AiMode::Off {
        (TokenRange::ZERO, TokenRange::ZERO)
    } else {
        (
            estimate_input(candidate_bytes, candidate_files),
            estimate_output(candidate_files),
        )
    };

    let mut skipped: BTreeMap<SkipReason, u64> = BTreeMap::new();
    for entry in &scan.skipped {
        *skipped.entry(entry.reason).or_default() += 1;
    }

    PlanReport {
        plan: BuildPlan {
            plan_version: PLAN_VERSION,
            source_revision: source_revision(scan),
            scanned_files: scan.files.len() as u64,
            structural_files,
            unsupported_files,
            semantic_candidates: candidate_files,
            // No reusable artifact exists yet. Reporting a hit this build cannot have
            // would make the first real cache look like a regression.
            semantic_cache_hits: 0,
            estimated_input_tokens: input,
            estimated_output_tokens: output,
            budget: AiBudget::from_settings(analysis),
        },
        languages,
        skipped: skipped.into_iter().collect(),
        ai_mode: analysis.ai_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{AnalyzerCapability, FactKind};
    use crate::coverage::SkippedSource;
    use crate::locator::CanonicalSourceLocator;
    use crate::scan::ScannedFile;
    use crate::text::NonEmptyText;

    fn file(path: &str, language: &str, bytes: u64) -> ScannedFile {
        ScannedFile {
            path: path.to_owned(),
            language: language.to_owned(),
            bytes,
            digest: crate::sync::digest_bytes(path.as_bytes()),
        }
    }

    fn scanned(files: Vec<ScannedFile>) -> Scan {
        Scan {
            files,
            skipped: Vec::new(),
        }
    }

    fn registry_with(language: &str, precision: PrecisionClass) -> CapabilityRegistry {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(AnalyzerCapability {
                language: NonEmptyText::new(language).unwrap(),
                precision,
                facts: vec![FactKind::Function],
            })
            .expect("a valid capability");
        registry
    }

    fn settings() -> AnalysisSettings {
        AnalysisSettings {
            ai_mode: AiMode::Auto,
            max_input_tokens: None,
            max_output_tokens: None,
            max_cost_usd: None,
            on_budget_exceeded: BudgetAction::Ask,
        }
    }

    #[test]
    fn an_empty_scan_plans_nothing_and_spends_nothing() {
        let report = plan(
            &scanned(Vec::new()),
            &CapabilityRegistry::new(),
            &settings(),
        );
        assert_eq!(report.plan.scanned_files, 0);
        assert_eq!(report.plan.semantic_candidates, 0);
        assert_eq!(report.plan.estimated_input_tokens, TokenRange::ZERO);
        assert!(!report.plan.spends_tokens());
        assert!(report.plan.within_budget().fits());
    }

    #[test]
    fn a_language_with_no_analyzer_is_unsupported_and_eligible_for_ai() {
        // Unsupported is the fallback path, not a dead end. Section 17.3 requires the text
        // to stay eligible, so a plan must count it as a candidate rather than write it off.
        let scan = scanned(vec![file("a.py", "python", 6000)]);
        let report = plan(&scan, &CapabilityRegistry::new(), &settings());
        assert_eq!(report.plan.structural_files, 0);
        assert_eq!(report.plan.unsupported_files, 1);
        assert_eq!(report.plan.semantic_candidates, 1);
        assert!(report.plan.spends_tokens());
        assert_eq!(report.languages[0].precision, PrecisionClass::Unsupported);
    }

    #[test]
    fn a_deterministic_analyzer_covers_a_file_without_spending_a_token() {
        // The invariant in section 29.1: structural extraction of supported source costs
        // nothing externally.
        let scan = scanned(vec![file("a.rs", "rust", 6000)]);
        let registry = registry_with("rust", PrecisionClass::DeterministicSyntactic);
        let report = plan(&scan, &registry, &settings());
        assert_eq!(report.plan.structural_files, 1);
        assert_eq!(report.plan.unsupported_files, 0);
        assert_eq!(report.plan.semantic_candidates, 0);
        assert_eq!(report.plan.estimated_input_tokens, TokenRange::ZERO);
    }

    #[test]
    fn a_heuristic_analyzer_covers_a_file_and_still_leaves_it_worth_enriching() {
        let scan = scanned(vec![file("a.rb", "ruby", 6000)]);
        let registry = registry_with("ruby", PrecisionClass::Heuristic);
        let report = plan(&scan, &registry, &settings());
        assert_eq!(
            report.plan.structural_files, 0,
            "heuristic is not deterministic"
        );
        assert_eq!(
            report.plan.unsupported_files, 0,
            "an analyzer exists, so it is not unsupported"
        );
        assert_eq!(
            report.plan.semantic_candidates, 1,
            "enrichment exists to improve exactly this case"
        );
    }

    #[test]
    fn asking_for_ai_instead_of_the_analyzers_counts_every_file() {
        // `Full` asks for AI *instead of* the analyzers, not on top of them, so a file an analyzer covers is
        // still read. Counting only the unsupported ones would under-report the whole run — and the budget
        // is checked against this plan, which is how a hard limit gets passed without anything noticing.
        let scan = scanned(vec![
            file("a.rs", "rust", 4_000),
            file("b.py", "python", 6_000),
            file("notes.md", "markdown", 2_000),
        ]);
        let registry = crate::analyze::builtin_registry().expect("registry");

        let auto = plan(&scan, &registry, &settings());
        assert_eq!(
            auto.plan.semantic_candidates, 1,
            "by default AI reads what an analyzer could not: the Markdown, and neither of the other two"
        );

        let full = plan(
            &scan,
            &registry,
            &AnalysisSettings {
                ai_mode: AiMode::Full,
                ..settings()
            },
        );
        assert_eq!(
            full.plan.semantic_candidates, 3,
            "asked for AI instead of the analyzers, it reads the whole tree"
        );
        assert!(
            full.plan.estimated_input_tokens.low > auto.plan.estimated_input_tokens.low,
            "and the estimate covers what it reads: {:?} against {:?}",
            full.plan.estimated_input_tokens,
            auto.plan.estimated_input_tokens
        );
        // The source facts do not move with the mode. Which files an analyzer covers is a property of the
        // source and the registry, and only what AI reads is being asked differently.
        assert_eq!(full.plan.structural_files, auto.plan.structural_files);
        assert_eq!(full.plan.unsupported_files, auto.plan.unsupported_files);
    }

    #[test]
    fn turning_ai_off_spends_nothing_while_still_counting_what_could_be_enriched() {
        let scan = scanned(vec![file("a.py", "python", 60_000)]);
        let analysis = AnalysisSettings {
            ai_mode: AiMode::Off,
            ..settings()
        };
        let report = plan(&scan, &CapabilityRegistry::new(), &analysis);
        assert_eq!(
            report.plan.semantic_candidates, 1,
            "what could be enriched is a fact about the source"
        );
        assert_eq!(
            report.plan.estimated_input_tokens,
            TokenRange::ZERO,
            "what this run spends is a different question"
        );
    }

    #[test]
    fn the_estimate_is_a_band_and_the_budget_check_uses_its_top() {
        // Understating a cost is what lets a run start a call it cannot afford, so the
        // check compares the pessimistic end.
        let input = estimate_input(60_000, 10);
        assert!(input.low < input.high, "{input:?}");
        assert_eq!(input.low, 60_000 / 6 + 2000);
        assert_eq!(input.high, 60_000 / 2 + 2000);

        let budget = AiBudget {
            max_input_tokens: Some(input.high - 1),
            ..AiBudget::default()
        };
        assert!(!budget.check(input, TokenRange::ZERO).fits());

        let generous = AiBudget {
            max_input_tokens: Some(input.high),
            ..AiBudget::default()
        };
        assert!(
            generous.check(input, TokenRange::ZERO).fits(),
            "a limit exactly at the estimate is not exceeded"
        );
    }

    #[test]
    fn an_output_ceiling_is_checked_as_well_as_an_input_one() {
        let output = estimate_output(100);
        let budget = AiBudget {
            max_output_tokens: Some(output.high - 1),
            ..AiBudget::default()
        };
        let check = budget.check(TokenRange::ZERO, output);
        assert!(matches!(
            check,
            BudgetCheck::Exceeds {
                field: "max_output_tokens",
                ..
            }
        ));
        assert!(check.to_string().contains("max_output_tokens"), "{check}");
    }

    #[test]
    fn a_zero_ceiling_permits_no_work_at_all() {
        // The settings contract permits zero and says it means no AI work may start.
        let budget = AiBudget {
            max_input_tokens: Some(0),
            ..AiBudget::default()
        };
        assert!(budget.has_hard_limit());
        assert!(
            !budget
                .check(estimate_input(100, 1), TokenRange::ZERO)
                .fits()
        );
        assert!(budget.check(TokenRange::ZERO, TokenRange::ZERO).fits());
    }

    #[test]
    fn no_configured_ceiling_is_not_the_same_as_a_ceiling_of_zero() {
        // With no hard limit the contract requires asking once rather than proceeding, so
        // the two cases must stay distinguishable.
        let unlimited = AiBudget::default();
        assert!(!unlimited.has_hard_limit());
        assert!(
            unlimited
                .check(estimate_input(1_000_000, 100), TokenRange::ZERO)
                .fits()
        );
    }

    #[test]
    fn the_revision_follows_the_bytes_and_not_the_order_they_were_found_in() {
        let one = scanned(vec![file("a.rs", "rust", 10), file("b.rs", "rust", 20)]);
        let same = scanned(vec![file("a.rs", "rust", 10), file("b.rs", "rust", 20)]);
        assert_eq!(source_revision(&one), source_revision(&same));

        let changed = scanned(vec![file("a.rs", "rust", 10), file("c.rs", "rust", 20)]);
        assert_ne!(
            source_revision(&one),
            source_revision(&changed),
            "a different path is a different snapshot"
        );
        assert!(
            source_revision(&one).starts_with("tree:"),
            "a content-derived revision must never be mistaken for a commit"
        );
    }

    #[test]
    fn a_language_summary_reports_each_language_once_in_name_order() {
        let scan = scanned(vec![
            file("a.rs", "rust", 100),
            file("b.py", "python", 200),
            file("c.rs", "rust", 300),
        ]);
        let registry = registry_with("rust", PrecisionClass::DeterministicSyntactic);
        let report = plan(&scan, &registry, &settings());
        assert_eq!(report.languages.len(), 2);
        assert_eq!(report.languages[0].language, "python");
        assert_eq!(report.languages[1].language, "rust");
        assert_eq!(report.languages[1].files, 2);
        assert_eq!(report.languages[1].bytes, 400);
    }

    #[test]
    fn exclusions_are_carried_into_the_report_grouped_by_reason() {
        let locator = CanonicalSourceLocator::new(".").unwrap();
        let skip = |path: &str, reason| SkippedSource {
            source: locator.clone(),
            path: NonEmptyText::new(path).ok(),
            reason,
        };
        let scan = Scan {
            files: vec![file("a.rs", "rust", 100)],
            skipped: vec![
                skip("x.log", SkipReason::Ignored),
                skip("y.log", SkipReason::Ignored),
                skip(".env", SkipReason::Sensitive),
            ],
        };
        let report = plan(&scan, &CapabilityRegistry::new(), &settings());
        assert_eq!(
            report.skipped,
            vec![(SkipReason::Ignored, 2), (SkipReason::Sensitive, 1)]
        );
        assert_eq!(report.skipped_files(), 3);
    }

    #[test]
    fn a_cache_hit_is_never_claimed_before_a_cache_exists() {
        // Reporting a hit this build cannot have would make the first real cache look
        // like a regression.
        let scan = scanned(vec![file("a.py", "python", 6000)]);
        let report = plan(&scan, &CapabilityRegistry::new(), &settings());
        assert_eq!(report.plan.semantic_cache_hits, 0);
    }

    #[test]
    fn a_range_renders_one_number_when_both_ends_agree() {
        assert_eq!(TokenRange::new(5, 5).to_string(), "5");
        assert_eq!(TokenRange::new(5, 9).to_string(), "5–9");
        assert_eq!(
            TokenRange::new(9, 5),
            TokenRange::new(5, 9),
            "the ends are ordered rather than trusted"
        );
    }
}
