//! Canonical source locators.
//!
//! A link is identified by its canonical source path or address. There is no
//! generated link identifier and no target database identifier, which is the rule
//! in the root PRD sections 7 and 18.1. Two locators that differ textually are two
//! logical sources even when their current bytes are identical.
//!
//! # Canonicalization
//!
//! Turning a user-supplied string into its canonical form is provider-specific: a
//! GitHub locator lower-cases owner and repository while preserving path and ref
//! case, and a local path resolves relative to the declaring file. Those rules
//! belong to the provider layer and arrive with it.
//!
//! This type therefore holds an already-canonical locator and guarantees only what
//! is provider-independent: it is non-empty, trimmed, and free of control
//! characters. Equality is exact string equality of the canonical form, which is
//! what cycle detection and duplicate-link detection compare.

use std::fmt;
use std::str::FromStr;

/// An already-canonical source locator that identifies a link target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalSourceLocator(String);

impl CanonicalSourceLocator {
    /// Wraps an already-canonical locator.
    ///
    /// # Errors
    ///
    /// Returns [`LocatorError::Empty`] when the value is empty or whitespace only,
    /// [`LocatorError::Untrimmed`] when it has leading or trailing whitespace, and
    /// [`LocatorError::ControlCharacter`] when it contains a control character. A
    /// locator with surrounding whitespace is rejected rather than trimmed, because
    /// silently rewriting a link identity would change which target it names.
    pub fn new(value: impl Into<String>) -> Result<Self, LocatorError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(LocatorError::Empty);
        }
        if value.trim() != value {
            return Err(LocatorError::Untrimmed);
        }
        if let Some(found) = value.chars().find(|c| c.is_control()) {
            return Err(LocatorError::ControlCharacter { found });
        }
        Ok(Self(value))
    }

    /// Borrows the locator.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwraps into the owned string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Reports whether this locator names a remote source rather than a path.
    ///
    /// A remote locator carries a `<scheme>://` prefix. A relative or absolute
    /// filesystem path does not.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        self.scheme().is_some()
    }

    /// The URI scheme, when the locator has one.
    ///
    /// Returns `None` for a filesystem path such as `./packages/child`.
    #[must_use]
    pub fn scheme(&self) -> Option<&str> {
        let (scheme, _) = self.0.split_once("://")?;
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
            || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        {
            return None;
        }
        Some(scheme)
    }
}

impl fmt::Display for CanonicalSourceLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CanonicalSourceLocator {
    type Err = LocatorError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

/// Why a locator was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatorError {
    /// The locator was empty or whitespace only.
    Empty,
    /// The locator had leading or trailing whitespace.
    Untrimmed,
    /// The locator contained a control character.
    ControlCharacter {
        /// The first control character found.
        found: char,
    },
}

impl fmt::Display for LocatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("a locator must not be empty"),
            Self::Untrimmed => {
                formatter.write_str("a locator must not have leading or trailing whitespace")
            }
            Self::ControlCharacter { found } => write!(
                formatter,
                "a locator must not contain the control character {found:?}"
            ),
        }
    }
}

impl std::error::Error for LocatorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_paths_and_remote_addresses() {
        for candidate in [
            "./packages/child",
            "../sibling",
            "/absolute/path/.nostdb/root.nostdb",
            "github://example/payments/.nostdb/root.nostdb?ref=v1.2.0",
        ] {
            assert!(
                CanonicalSourceLocator::new(candidate).is_ok(),
                "{candidate}"
            );
        }
    }

    #[test]
    fn rejects_empty_untrimmed_and_control_characters() {
        assert_eq!(CanonicalSourceLocator::new(""), Err(LocatorError::Empty));
        assert_eq!(CanonicalSourceLocator::new("  "), Err(LocatorError::Empty));
        assert_eq!(
            CanonicalSourceLocator::new(" ./a"),
            Err(LocatorError::Untrimmed)
        );
        assert_eq!(
            CanonicalSourceLocator::new("./a\n"),
            Err(LocatorError::Untrimmed)
        );
        assert_eq!(
            CanonicalSourceLocator::new("./a\u{7}b"),
            Err(LocatorError::ControlCharacter { found: '\u{7}' })
        );
    }

    #[test]
    fn distinguishes_remote_from_local() {
        let remote = CanonicalSourceLocator::new("github://example/payments/?ref=main").unwrap();
        assert!(remote.is_remote());
        assert_eq!(remote.scheme(), Some("github"));

        let local = CanonicalSourceLocator::new("./packages/child").unwrap();
        assert!(!local.is_remote());
        assert_eq!(local.scheme(), None);
    }

    #[test]
    fn a_windows_style_path_is_not_mistaken_for_a_scheme() {
        // A drive letter has no "://", so it stays a path.
        let path = CanonicalSourceLocator::new("C:/projects/app").unwrap();
        assert_eq!(path.scheme(), None);
        assert!(!path.is_remote());
    }

    #[test]
    fn two_textually_different_locators_are_two_sources() {
        let a = CanonicalSourceLocator::new("./packages/child").unwrap();
        let b = CanonicalSourceLocator::new("./packages/child/").unwrap();
        assert_ne!(a, b);
    }
}
