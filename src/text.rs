//! Constrained text used across the model.

use std::fmt;

/// Text that is non-empty, free of control characters, and free of leading or
/// trailing whitespace.
///
/// Producer names, version strings, and analyzer names use this so that an empty
/// or whitespace-only value cannot reach a stored record, where it would be
/// indistinguishable from a missing value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonEmptyText(String);

impl NonEmptyText {
    /// Creates constrained text.
    ///
    /// # Errors
    ///
    /// Returns [`TextError::Empty`] when the input is empty or entirely
    /// whitespace, [`TextError::Untrimmed`] when it has leading or trailing
    /// whitespace, and [`TextError::ControlCharacter`] when it contains a control
    /// character.
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TextError::Empty);
        }
        if value.trim() != value {
            return Err(TextError::Untrimmed);
        }
        if let Some(found) = value.chars().find(|c| c.is_control()) {
            return Err(TextError::ControlCharacter { found });
        }
        Ok(Self(value))
    }

    /// Wraps a compile-time literal that the author asserts is valid.
    ///
    /// This exists only so an infallible fallback can be written without `unwrap`,
    /// keeping the crate's no-panic guarantee. It is crate-internal and takes a
    /// `&'static str`, so a caller cannot smuggle runtime data past validation. The
    /// debug assertion catches a bad literal during development.
    pub(crate) fn literal(value: &'static str) -> Self {
        debug_assert!(
            Self::new(value).is_ok(),
            "NonEmptyText::literal was given an invalid literal"
        );
        Self(value.to_owned())
    }

    /// Borrows the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwraps into the owned string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for NonEmptyText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why constrained text was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextError {
    /// The value was empty or contained only whitespace.
    Empty,
    /// The value had leading or trailing whitespace.
    Untrimmed,
    /// The value contained a control character.
    ControlCharacter {
        /// The first control character found.
        found: char,
    },
}

impl fmt::Display for TextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("text must not be empty or whitespace only"),
            Self::Untrimmed => {
                formatter.write_str("text must not have leading or trailing whitespace")
            }
            Self::ControlCharacter { found } => {
                write!(
                    formatter,
                    "text must not contain the control character {found:?}"
                )
            }
        }
    }
}

impl std::error::Error for TextError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_text() {
        assert_eq!(NonEmptyText::new("analyzer").unwrap().as_str(), "analyzer");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_eq!(NonEmptyText::new(""), Err(TextError::Empty));
        assert_eq!(NonEmptyText::new("   "), Err(TextError::Empty));
    }

    #[test]
    fn rejects_untrimmed() {
        assert_eq!(NonEmptyText::new(" a"), Err(TextError::Untrimmed));
        assert_eq!(NonEmptyText::new("a "), Err(TextError::Untrimmed));
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(
            NonEmptyText::new("a\u{0}b"),
            Err(TextError::ControlCharacter { found: '\u{0}' })
        );
    }
}
