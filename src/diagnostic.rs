//! Diagnostics.
//!
//! A diagnostic code is a stable identifier. It is part of the public contract, so
//! it is never renamed, and every code here is registered in `nostdb-spec`.
//!
//! The root workspace verifies that this enumeration and the `nostdb-spec` registry
//! contain exactly the same codes. The two live in separate repositories pinned
//! together, so a cross-repository check is the only thing that can keep them
//! aligned; matching them by inspection would drift on the first change.
//!
//! # Codes and errors are different things
//!
//! A diagnostic reports something about analyzed content: a `.nost` file sets a
//! property twice, a container is corrupt, a link cannot be reached. A caller
//! misusing this crate's API gets a typed error instead, with no diagnostic code,
//! because inventing an unregistered code would put this crate's vocabulary ahead
//! of the published contract.

use crate::evidence::SourceRange;
use crate::locator::CanonicalSourceLocator;
use crate::name::PropertyKey;
use crate::property::PropertyValue;
use crate::text::NonEmptyText;
use std::fmt;
use std::str::FromStr;

/// How serious a diagnostic is.
///
/// A warning never silently changes query semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// The operation cannot proceed.
    Error,
    /// The operation proceeds, and the result is reported as partial or qualified.
    Warning,
    /// Context that changes nothing.
    Information,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Information => "information",
        })
    }
}

/// A stable diagnostic code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticCode {
    /// Input does not match the `.nost` grammar.
    NostParseError,
    /// The `@nost` header names an unsupported language version.
    NostVersionUnsupported,
    /// Two link declarations claim the same alias.
    NostDuplicateLinkAlias,
    /// Two link declarations canonicalize to the same locator.
    NostDuplicateLinkSource,
    /// Two declarations in one scope share a name.
    NostDuplicateDeclarationName,
    /// Two declarations claim the same record identifier.
    NostDuplicateId,
    /// A stated record identifier is not a kind prefix followed by a canonical UUID.
    NostInvalidId,
    /// Two schema declarations share a name.
    NostDuplicateSchemaName,
    /// Two schemas named by one record declare a shared field key with different types.
    NostSchemaConflict,
    /// A record does not satisfy a schema it names.
    ///
    /// A warning, because schema validation is soft; an explicit Constraint is hard.
    NostSchemaViolation,
    /// A contribution or evidence block is missing, unknown, or malformed in some key.
    NostInvalidEvidence,
    /// A property block sets the same key twice.
    NostDuplicatePropertyKey,
    /// A settings link entry names a source no link declaration carries.
    ///
    /// A warning: the entry is ignored, and refusing to open the project over a stale
    /// operational entry would be worse than reporting it.
    OrphanLinkSettings,
    /// A settings document is malformed.
    SettingsInvalid,
    /// A settings document names a version this build cannot read or safely write.
    SettingsVersionUnsupported,
    /// A declared link could not be opened.
    ///
    /// A warning: the declaration stays, the reachable results are returned, and the
    /// result summary reports itself partial.
    LinkUnavailable,
    /// A change set breaks a rule decidable without a database.
    ChangeSetInvalid,
    /// The `change_set_version` is not one this build reads.
    ChangeSetVersionUnsupported,
    /// Recursive traversal reached a canonical source it had already opened.
    LinkCycle,
    /// Recursive traversal reached a configured depth or database limit.
    LinkLimitExceeded,
    /// An endpoint names a link alias or locator that is not declared.
    NostUnknownLinkAlias,
    /// An endpoint resolves to nothing, so a Placeholder is created.
    NostUnresolvedEndpoint,
    /// An integer literal does not fit in a signed 64-bit value.
    NostIntegerOutOfRange,
    /// A float is not finite, or a confidence score is outside `0.0..=1.0`.
    NostNonFiniteNumber,
    /// A datetime literal is not a valid RFC 3339 timestamp.
    NostInvalidDatetime,
    /// The query uses a construct outside the declared subset.
    CypherUnsupported,
    /// The query is inside the subset but meaningless.
    CypherSemanticError,
    /// A write named a record belonging to a linked source.
    ///
    /// This build cannot emit it, and that is worth stating rather than leaving a reader
    /// to wonder. No linked record is bindable yet, because link resolution and recursive
    /// federation are not implemented, so a write has no way to name one. The guarantee is
    /// structural rather than checked: every mutation resolves through the root graph, and
    /// a record of another source is not in it.
    ///
    /// The code is registered because the published query subset contract names it and the
    /// root product contract requires it. Federation is what makes it reachable.
    LinkedDatabaseReadOnly,
    /// The database advanced while the `.nost` file did not.
    NostSourceStale,
    /// Both representations changed from one baseline, so neither is modified.
    SyncConflict,
    /// The container declares an unsupported format version.
    NostdbFormatUnsupported,
    /// The container is structurally invalid.
    NostdbCorrupt,
    /// The container exceeds a bounded-parsing limit.
    NostdbLimitExceeded,
}

impl DiagnosticCode {
    /// Every code, in registry order.
    ///
    /// The root workspace compares this against the `nostdb-spec` registry.
    pub const ALL: [Self; 33] = [
        Self::NostParseError,
        Self::NostVersionUnsupported,
        Self::NostDuplicateLinkAlias,
        Self::NostDuplicateLinkSource,
        Self::NostDuplicateDeclarationName,
        Self::NostDuplicateId,
        Self::NostInvalidId,
        Self::NostDuplicateSchemaName,
        Self::NostSchemaConflict,
        Self::NostSchemaViolation,
        Self::NostInvalidEvidence,
        Self::NostDuplicatePropertyKey,
        Self::OrphanLinkSettings,
        Self::SettingsInvalid,
        Self::SettingsVersionUnsupported,
        Self::LinkUnavailable,
        Self::ChangeSetInvalid,
        Self::ChangeSetVersionUnsupported,
        Self::LinkCycle,
        Self::LinkLimitExceeded,
        Self::NostUnknownLinkAlias,
        Self::NostUnresolvedEndpoint,
        Self::NostIntegerOutOfRange,
        Self::NostNonFiniteNumber,
        Self::NostInvalidDatetime,
        Self::CypherUnsupported,
        Self::CypherSemanticError,
        Self::LinkedDatabaseReadOnly,
        Self::NostSourceStale,
        Self::SyncConflict,
        Self::NostdbFormatUnsupported,
        Self::NostdbCorrupt,
        Self::NostdbLimitExceeded,
    ];

    /// The stable wire form of this code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NostParseError => "NOST_PARSE_ERROR",
            Self::NostVersionUnsupported => "NOST_VERSION_UNSUPPORTED",
            Self::NostDuplicateLinkAlias => "NOST_DUPLICATE_LINK_ALIAS",
            Self::NostDuplicateLinkSource => "NOST_DUPLICATE_LINK_SOURCE",
            Self::NostDuplicateDeclarationName => "NOST_DUPLICATE_DECLARATION_NAME",
            Self::NostDuplicateId => "NOST_DUPLICATE_ID",
            Self::NostInvalidId => "NOST_INVALID_ID",
            Self::NostDuplicateSchemaName => "NOST_DUPLICATE_SCHEMA_NAME",
            Self::NostSchemaConflict => "NOST_SCHEMA_CONFLICT",
            Self::NostSchemaViolation => "NOST_SCHEMA_VIOLATION",
            Self::NostInvalidEvidence => "NOST_INVALID_EVIDENCE",
            Self::NostDuplicatePropertyKey => "NOST_DUPLICATE_PROPERTY_KEY",
            Self::OrphanLinkSettings => "ORPHAN_LINK_SETTINGS",
            Self::SettingsInvalid => "SETTINGS_INVALID",
            Self::SettingsVersionUnsupported => "SETTINGS_VERSION_UNSUPPORTED",
            Self::LinkUnavailable => "LINK_UNAVAILABLE",
            Self::ChangeSetInvalid => "CHANGE_SET_INVALID",
            Self::ChangeSetVersionUnsupported => "CHANGE_SET_VERSION_UNSUPPORTED",
            Self::LinkCycle => "LINK_CYCLE",
            Self::LinkLimitExceeded => "LINK_LIMIT_EXCEEDED",
            Self::NostUnknownLinkAlias => "NOST_UNKNOWN_LINK_ALIAS",
            Self::NostUnresolvedEndpoint => "NOST_UNRESOLVED_ENDPOINT",
            Self::NostIntegerOutOfRange => "NOST_INTEGER_OUT_OF_RANGE",
            Self::NostNonFiniteNumber => "NOST_NON_FINITE_NUMBER",
            Self::NostInvalidDatetime => "NOST_INVALID_DATETIME",
            Self::CypherUnsupported => "CYPHER_UNSUPPORTED",
            Self::CypherSemanticError => "CYPHER_SEMANTIC_ERROR",
            Self::LinkedDatabaseReadOnly => "LINKED_DATABASE_READ_ONLY",
            Self::NostSourceStale => "NOST_SOURCE_STALE",
            Self::SyncConflict => "SYNC_CONFLICT",
            Self::NostdbFormatUnsupported => "NOSTDB_FORMAT_UNSUPPORTED",
            Self::NostdbCorrupt => "NOSTDB_CORRUPT",
            Self::NostdbLimitExceeded => "NOSTDB_LIMIT_EXCEEDED",
        }
    }

    /// The severity the registry assigns to this code.
    ///
    /// Only an unresolved endpoint is a warning: it produces a Placeholder and lets
    /// the operation continue, rather than refusing the whole change.
    #[must_use]
    pub const fn default_severity(&self) -> Severity {
        match self {
            Self::NostUnresolvedEndpoint | Self::NostSchemaViolation | Self::OrphanLinkSettings => {
                Severity::Warning
            }
            _ => Severity::Error,
        }
    }
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DiagnosticCode {
    type Err = UnknownDiagnosticCode;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|code| code.as_str() == text)
            .ok_or_else(|| UnknownDiagnosticCode {
                found: text.to_owned(),
            })
    }
}

/// A diagnostic code string this build does not recognize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownDiagnosticCode {
    /// The unrecognized text.
    pub found: String,
}

impl fmt::Display for UnknownDiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown diagnostic code {:?}", self.found)
    }
}

impl std::error::Error for UnknownDiagnosticCode {}

/// One structured detail attached to a diagnostic.
///
/// Details reuse [`PropertyValue`] rather than an untyped JSON value, so a detail
/// is subject to the same no-null and finite-number rules as stored data and needs
/// no separate serialization contract.
#[derive(Clone, Debug, PartialEq)]
pub struct DiagnosticDetail {
    /// What the detail is called.
    pub key: PropertyKey,
    /// The detail itself.
    pub value: PropertyValue,
}

/// A diagnostic.
#[derive(Clone, Debug, PartialEq)]
pub struct Diagnostic {
    /// The stable code.
    pub code: DiagnosticCode,
    /// How serious this occurrence is.
    pub severity: Severity,
    /// A human-readable explanation.
    pub message: NonEmptyText,
    /// The source it concerns, when it concerns one.
    pub source: Option<CanonicalSourceLocator>,
    /// Where in that source, when that is known.
    pub range: Option<SourceRange>,
    /// Structured details.
    pub details: Vec<DiagnosticDetail>,
}

impl Diagnostic {
    /// Creates a diagnostic at the code's default severity, with no source, range,
    /// or details.
    #[must_use]
    pub fn new(code: DiagnosticCode, message: NonEmptyText) -> Self {
        Self {
            code,
            severity: code.default_severity(),
            message,
            source: None,
            range: None,
            details: Vec::new(),
        }
    }

    /// Attaches the source this diagnostic concerns.
    #[must_use]
    pub fn with_source(mut self, source: CanonicalSourceLocator) -> Self {
        self.source = Some(source);
        self
    }

    /// Attaches the range this diagnostic concerns.
    #[must_use]
    pub fn with_range(mut self, range: SourceRange) -> Self {
        self.range = Some(range);
        self
    }

    /// Attaches a structured detail.
    #[must_use]
    pub fn with_detail(mut self, key: PropertyKey, value: PropertyValue) -> Self {
        self.details.push(DiagnosticDetail { key, value });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_code_round_trips_through_its_wire_form() {
        for code in DiagnosticCode::ALL {
            assert_eq!(DiagnosticCode::from_str(code.as_str()), Ok(code));
        }
    }

    #[test]
    fn wire_forms_are_unique_and_upper_snake_case() {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for code in DiagnosticCode::ALL {
            let text = code.as_str();
            assert!(seen.insert(text), "duplicate wire form {text}");
            assert!(
                text.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "{text} must be upper snake case"
            );
        }
        assert_eq!(seen.len(), DiagnosticCode::ALL.len());
    }

    #[test]
    fn an_unknown_code_is_rejected_rather_than_guessed() {
        assert_eq!(
            DiagnosticCode::from_str("NOST_MADE_UP"),
            Err(UnknownDiagnosticCode {
                found: "NOST_MADE_UP".to_owned()
            })
        );
        assert!(DiagnosticCode::from_str("nost_parse_error").is_err());
    }

    #[test]
    fn an_unresolved_endpoint_is_a_warning_and_the_rest_are_errors() {
        assert_eq!(
            DiagnosticCode::NostUnresolvedEndpoint.default_severity(),
            Severity::Warning
        );
        assert_eq!(
            DiagnosticCode::NostSchemaViolation.default_severity(),
            Severity::Warning
        );
        for code in DiagnosticCode::ALL {
            if matches!(
                code,
                DiagnosticCode::NostUnresolvedEndpoint
                    | DiagnosticCode::NostSchemaViolation
                    | DiagnosticCode::OrphanLinkSettings
                    | DiagnosticCode::LinkUnavailable
                    | DiagnosticCode::LinkCycle
                    | DiagnosticCode::LinkLimitExceeded
            ) {
                continue;
            }
            assert_eq!(code.default_severity(), Severity::Error, "{code}");
        }
    }

    #[test]
    fn a_diagnostic_builds_up_source_range_and_details() {
        let diagnostic = Diagnostic::new(
            DiagnosticCode::NostDuplicatePropertyKey,
            NonEmptyText::new("the property key name is set more than once").unwrap(),
        )
        .with_source(CanonicalSourceLocator::new("./packages/child").unwrap())
        .with_detail(
            PropertyKey::new("key").unwrap(),
            PropertyValue::from("name"),
        );

        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.source.is_some());
        assert_eq!(diagnostic.details.len(), 1);
        assert_eq!(diagnostic.range, None);
    }
}
