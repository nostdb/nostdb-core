//! The deterministic analysis boundary.
//!
//! # No closed language list
//!
//! Storage and queries are programming-language-neutral, and the root PRD section 17.3
//! forbids encoding a closed list of languages into `.nostdb`. A language is therefore a
//! string, and this registry is open: a language nobody registered is
//! [`PrecisionClass::Unsupported`], which is a value rather than an error.
//!
//! That distinction matters. Unsupported text stays eligible for AI analysis and still
//! produces a source record, so treating an unknown language as a failure would throw
//! away work the product promises to do.
//!
//! # Capability is not a promise of equal accuracy
//!
//! Each analyzer declares what it extracts and how precisely. A caller presenting a
//! heuristic or AI-derived fact as though it carried the same weight as a deterministic
//! one would be misrepresenting the graph, which is why precision travels with every
//! capability rather than being inferred from whether a result exists.

use crate::text::NonEmptyText;
use std::collections::BTreeMap;
use std::fmt;

/// How precisely an analyzer extracts facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrecisionClass {
    /// Resolves names and types, so a fact reflects the language's semantics.
    DeterministicSemantic,
    /// Reads syntax without resolving names, so a fact reflects the text's shape.
    DeterministicSyntactic,
    /// Pattern-based, so a fact may be wrong in ways the analyzer cannot detect.
    Heuristic,
    /// Produced by AI analysis rather than by a deterministic analyzer.
    AiFallback,
    /// No analyzer declares support.
    Unsupported,
}

impl PrecisionClass {
    /// Reports whether facts at this precision are reproducible from the source alone.
    #[must_use]
    pub const fn is_deterministic(self) -> bool {
        matches!(
            self,
            Self::DeterministicSemantic | Self::DeterministicSyntactic
        )
    }

    /// Reports whether reaching this precision spends external AI tokens.
    ///
    /// Structural extraction of supported source spends none, which the root PRD
    /// section 29.1 requires.
    #[must_use]
    pub const fn spends_ai_tokens(self) -> bool {
        matches!(self, Self::AiFallback)
    }

    /// Reports whether text at this precision remains eligible for AI analysis.
    ///
    /// Unsupported text is eligible: that is the fallback path, not a dead end.
    #[must_use]
    pub const fn eligible_for_ai(self) -> bool {
        matches!(self, Self::Unsupported | Self::Heuristic)
    }
}

impl fmt::Display for PrecisionClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DeterministicSemantic => "deterministic semantic",
            Self::DeterministicSyntactic => "deterministic syntactic",
            Self::Heuristic => "heuristic",
            Self::AiFallback => "AI fallback",
            Self::Unsupported => "unsupported",
        })
    }
}

/// A kind of fact an analyzer can extract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactKind {
    /// Packages.
    Package,
    /// Modules.
    Module,
    /// Files.
    File,
    /// Types.
    Type,
    /// Classes.
    Class,
    /// Functions.
    Function,
    /// Methods.
    Method,
    /// Fields.
    Field,
    /// Declarations.
    Declaration,
    /// Definitions.
    Definition,
    /// Imports and exports.
    ImportExport,
    /// Package dependencies.
    PackageDependency,
    /// Direct calls.
    Call,
    /// Inheritance.
    Inheritance,
    /// Interface implementation.
    InterfaceImplementation,
    /// Configuration-defined entry points.
    EntryPoint,
    /// Source ranges for extracted facts.
    SourceRange,
    /// Content hashes for analyzed units.
    ContentHash,
}

impl fmt::Display for FactKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// What one analyzer declares about one language.
///
/// Coverage and precision, and deliberately **not** attribution. There is no version here: which named
/// reader among this build's own deterministic analyzers produced a record is not something a query can act
/// on, and what a reader does act on is [`PrecisionClass`], `EvidenceMethod`, and `Confidence`. Versioning
/// what a build asserts about a file is one number — [`crate::build::GRAPH_SCHEMA_VERSION`] — rather than one
/// per analyzer.
///
/// This says nothing about `Owner::Analyzer`, whose version *is* part of a contribution's identity, is
/// declared in `nostdb-spec`, and is required grammar in `.nost`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyzerCapability {
    /// The language, as a free string. There is no closed list.
    pub language: NonEmptyText,
    /// How precisely this analyzer works.
    pub precision: PrecisionClass,
    /// What it extracts.
    pub facts: Vec<FactKind>,
}

impl AnalyzerCapability {
    /// Reports whether this analyzer declares a given fact kind.
    #[must_use]
    pub fn extracts(&self, fact: FactKind) -> bool {
        self.facts.contains(&fact)
    }
}

/// Why a capability could not be registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    /// A capability declared [`PrecisionClass::Unsupported`].
    ///
    /// Unsupported is the answer for a language nobody registered, so registering it
    /// would state a capability that is really its absence.
    UnsupportedDeclared {
        /// The language named.
        language: String,
    },
    /// A deterministic capability declared no facts.
    ///
    /// An analyzer that extracts nothing is not support; it would make a language look
    /// covered while producing no graph.
    NoFactsDeclared {
        /// The language named.
        language: String,
    },
    /// Another capability is already registered for this language.
    AlreadyRegistered {
        /// The language named.
        language: String,
    },
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDeclared { language } => write!(
                formatter,
                "{language}: unsupported is the absence of a capability, so it is not registered"
            ),
            Self::NoFactsDeclared { language } => {
                write!(
                    formatter,
                    "{language}: a capability must declare a fact kind"
                )
            }
            Self::AlreadyRegistered { language } => {
                write!(formatter, "{language}: a capability is already registered")
            }
        }
    }
}

impl std::error::Error for CapabilityError {}

/// The analyzers available to a build.
///
/// Lookup is by exact language string. Normalizing case or aliasing names is a caller
/// decision, because what counts as the same language differs by ecosystem.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    entries: BTreeMap<String, AnalyzerCapability>,
}

impl CapabilityRegistry {
    /// An empty registry, which reports every language as unsupported.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a capability.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::UnsupportedDeclared`] when the capability declares
    /// unsupported, [`CapabilityError::NoFactsDeclared`] when it declares no fact kind,
    /// and [`CapabilityError::AlreadyRegistered`] when the language already has one.
    pub fn register(&mut self, capability: AnalyzerCapability) -> Result<(), CapabilityError> {
        let language = capability.language.as_str().to_owned();
        if capability.precision == PrecisionClass::Unsupported {
            return Err(CapabilityError::UnsupportedDeclared { language });
        }
        if capability.facts.is_empty() {
            return Err(CapabilityError::NoFactsDeclared { language });
        }
        if self.entries.contains_key(&language) {
            return Err(CapabilityError::AlreadyRegistered { language });
        }
        self.entries.insert(language, capability);
        Ok(())
    }

    /// The capability for a language, when one is registered.
    #[must_use]
    pub fn capability(&self, language: &str) -> Option<&AnalyzerCapability> {
        self.entries.get(language)
    }

    /// The precision available for a language.
    ///
    /// An unregistered language is [`PrecisionClass::Unsupported`], which is an answer
    /// rather than a failure.
    #[must_use]
    pub fn precision(&self, language: &str) -> PrecisionClass {
        self.capability(language)
            .map_or(PrecisionClass::Unsupported, |found| found.precision)
    }

    /// Reports whether structural extraction for a language spends no AI tokens.
    #[must_use]
    pub fn structural_is_free(&self, language: &str) -> bool {
        self.precision(language).is_deterministic()
    }

    /// Every registered language, in sorted order.
    #[must_use]
    pub fn languages(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// Number of registered capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> NonEmptyText {
        NonEmptyText::new(value).unwrap()
    }

    fn capability(language: &str, precision: PrecisionClass) -> AnalyzerCapability {
        AnalyzerCapability {
            language: text(language),
            precision,
            facts: vec![FactKind::Function, FactKind::Call, FactKind::SourceRange],
        }
    }

    #[test]
    fn an_empty_registry_reports_every_language_as_unsupported() {
        let registry = CapabilityRegistry::new();
        assert!(registry.is_empty());
        for language in ["rust", "python", "a language nobody has written yet"] {
            assert_eq!(registry.precision(language), PrecisionClass::Unsupported);
            assert!(registry.capability(language).is_none());
        }
    }

    #[test]
    fn an_unregistered_language_is_a_value_not_an_error_and_stays_eligible_for_ai() {
        let registry = CapabilityRegistry::new();
        let precision = registry.precision("cobol");
        assert_eq!(precision, PrecisionClass::Unsupported);
        // The product promises AI fallback for unsupported text, so this must be true.
        assert!(precision.eligible_for_ai());
        assert!(!precision.is_deterministic());
    }

    #[test]
    fn registering_and_looking_up_a_capability() {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(capability("rust", PrecisionClass::DeterministicSemantic))
            .unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.precision("rust"),
            PrecisionClass::DeterministicSemantic
        );
        assert!(registry.structural_is_free("rust"));
        let found = registry.capability("rust").expect("registered");
        assert!(found.extracts(FactKind::Call));
        assert!(!found.extracts(FactKind::Inheritance));
        assert_eq!(registry.languages(), vec!["rust"]);
    }

    #[test]
    fn lookup_is_exact_so_normalization_stays_a_caller_decision() {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(capability("rust", PrecisionClass::DeterministicSemantic))
            .unwrap();
        assert_eq!(registry.precision("Rust"), PrecisionClass::Unsupported);
    }

    #[test]
    fn declaring_unsupported_is_refused_because_it_states_an_absence() {
        let mut registry = CapabilityRegistry::new();
        assert_eq!(
            registry.register(capability("rust", PrecisionClass::Unsupported)),
            Err(CapabilityError::UnsupportedDeclared {
                language: "rust".to_owned()
            })
        );
    }

    #[test]
    fn a_capability_extracting_nothing_is_refused() {
        let mut registry = CapabilityRegistry::new();
        let mut empty = capability("rust", PrecisionClass::DeterministicSyntactic);
        empty.facts.clear();
        assert_eq!(
            registry.register(empty),
            Err(CapabilityError::NoFactsDeclared {
                language: "rust".to_owned()
            })
        );
    }

    #[test]
    fn a_second_capability_for_one_language_is_refused() {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(capability("rust", PrecisionClass::DeterministicSemantic))
            .unwrap();
        assert_eq!(
            registry.register(capability("rust", PrecisionClass::Heuristic)),
            Err(CapabilityError::AlreadyRegistered {
                language: "rust".to_owned()
            })
        );
    }

    #[test]
    fn only_ai_fallback_spends_tokens_and_only_deterministic_classes_are_reproducible() {
        let spending: Vec<PrecisionClass> = [
            PrecisionClass::DeterministicSemantic,
            PrecisionClass::DeterministicSyntactic,
            PrecisionClass::Heuristic,
            PrecisionClass::AiFallback,
            PrecisionClass::Unsupported,
        ]
        .into_iter()
        .filter(|precision| precision.spends_ai_tokens())
        .collect();
        assert_eq!(spending, vec![PrecisionClass::AiFallback]);

        assert!(PrecisionClass::DeterministicSemantic.is_deterministic());
        assert!(PrecisionClass::DeterministicSyntactic.is_deterministic());
        assert!(!PrecisionClass::Heuristic.is_deterministic());
        assert!(!PrecisionClass::AiFallback.is_deterministic());
    }

    #[test]
    fn a_registry_holding_many_languages_imposes_no_allowlist() {
        let mut registry = CapabilityRegistry::new();
        for language in ["rust", "python", "go", "brand-new-language", "日本語"] {
            registry
                .register(capability(language, PrecisionClass::DeterministicSyntactic))
                .unwrap();
        }
        assert_eq!(registry.len(), 5);
        // Sorted, so reporting is deterministic.
        let languages = registry.languages();
        let mut sorted = languages.clone();
        sorted.sort_unstable();
        assert_eq!(languages, sorted);
    }
}
