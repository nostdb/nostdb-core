//! Validated names.
//!
//! Labels, relation names, property keys, declaration names, and link aliases are
//! all identifiers under one rule, which is what the `.nost` language contract in
//! `nostdb-spec` specifies. This module is the single place that rule is
//! implemented, so the five uses cannot drift apart.
//!
//! # The rule
//!
//! An identifier starts with a Unicode scalar having `XID_Start`, or `_`, and
//! continues with scalars having `XID_Continue`, per UAX #31. Identifiers are
//! case-sensitive.
//!
//! A reserved word is never an identifier. Reserved words are matched exactly, and
//! they are all lower case, so `Node` is a valid name while `node` is not.
//!
//! # Why these are distinct types
//!
//! The validation is identical, but the types are not interchangeable. A function
//! taking a [`PropertyKey`] cannot be handed a [`Label`] by accident, which matters
//! because a graph record carries several name-shaped fields side by side.

use std::fmt;
use std::str::FromStr;

/// Words the `.nost` grammar reserves, which are therefore never identifiers.
///
/// Matching is exact and case-sensitive.
///
/// Language version 2 unreserved `id` and `source`, which became ordinary property and
/// evidence keys, and dropped `module` with the declaration it introduced. `id` in
/// particular must be a valid [`PropertyKey`] now, because it is how a record states its
/// identifier.
pub const RESERVED_WORDS: [&str; 8] = [
    "as", "bytes", "datetime", "edge", "false", "node", "schema", "true",
];

/// Why a name was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    /// The name was empty.
    Empty,
    /// The first character has neither `XID_Start` nor is it `_`.
    InvalidStart {
        /// The offending character.
        found: char,
    },
    /// A later character does not have `XID_Continue`.
    InvalidContinue {
        /// The offending character.
        found: char,
    },
    /// The name is a reserved word.
    Reserved,
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("a name must not be empty"),
            Self::InvalidStart { found } => write!(
                formatter,
                "a name must start with XID_Start or '_', found {found:?}"
            ),
            Self::InvalidContinue { found } => write!(
                formatter,
                "a name must continue with XID_Continue, found {found:?}"
            ),
            Self::Reserved => formatter.write_str("a reserved word is never a name"),
        }
    }
}

impl std::error::Error for NameError {}

fn validate(value: &str) -> Result<(), NameError> {
    let mut characters = value.chars();
    let first = characters.next().ok_or(NameError::Empty)?;
    if !(unicode_ident::is_xid_start(first) || first == '_') {
        return Err(NameError::InvalidStart { found: first });
    }
    for character in characters {
        if !unicode_ident::is_xid_continue(character) {
            return Err(NameError::InvalidContinue { found: character });
        }
    }
    if RESERVED_WORDS.contains(&value) {
        return Err(NameError::Reserved);
    }
    Ok(())
}

macro_rules! validated_name {
    ($name:ident, $what:literal) => {
        #[doc = concat!("A validated ", $what, ".")]
        ///
        /// See the module documentation for the identifier rule this enforces.
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validates and wraps a ", $what, ".")]
            ///
            /// # Errors
            ///
            /// Returns a [`NameError`] when the value is empty, starts with a
            /// character lacking `XID_Start`, continues with a character lacking
            /// `XID_Continue`, or is a reserved word.
            pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
                let value = value.into();
                validate(&value)?;
                Ok(Self(value))
            }

            /// Borrows the name.
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = NameError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::new(text)
            }
        }
    };
}

validated_name!(Label, "Node label");
validated_name!(RelationName, "Edge relation name");
validated_name!(PropertyKey, "property key");
validated_name!(DeclarationName, "declaration name");
validated_name!(LinkAlias, "link alias");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ascii_and_unicode_identifiers() {
        for candidate in [
            "Function",
            "login",
            "_private",
            "a1",
            "función",
            "модуль",
            "节点",
        ] {
            assert!(
                Label::new(candidate).is_ok(),
                "{candidate} should be a valid name"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(Label::new(""), Err(NameError::Empty));
    }

    #[test]
    fn rejects_a_digit_or_punctuation_start() {
        assert_eq!(
            Label::new("1abc"),
            Err(NameError::InvalidStart { found: '1' })
        );
        assert_eq!(
            Label::new("-abc"),
            Err(NameError::InvalidStart { found: '-' })
        );
        assert_eq!(
            Label::new(":abc"),
            Err(NameError::InvalidStart { found: ':' })
        );
    }

    #[test]
    fn rejects_punctuation_and_whitespace_inside() {
        assert_eq!(
            Label::new("a-b"),
            Err(NameError::InvalidContinue { found: '-' })
        );
        assert_eq!(
            Label::new("a b"),
            Err(NameError::InvalidContinue { found: ' ' })
        );
        assert_eq!(
            Label::new("a.b"),
            Err(NameError::InvalidContinue { found: '.' })
        );
    }

    #[test]
    fn rejects_every_reserved_word_in_every_name_position() {
        for reserved in RESERVED_WORDS {
            assert_eq!(Label::new(reserved), Err(NameError::Reserved), "{reserved}");
            assert_eq!(
                RelationName::new(reserved),
                Err(NameError::Reserved),
                "{reserved}"
            );
            assert_eq!(
                PropertyKey::new(reserved),
                Err(NameError::Reserved),
                "{reserved}"
            );
            assert_eq!(
                DeclarationName::new(reserved),
                Err(NameError::Reserved),
                "{reserved}"
            );
            assert_eq!(
                LinkAlias::new(reserved),
                Err(NameError::Reserved),
                "{reserved}"
            );
        }
    }

    #[test]
    fn reserved_word_matching_is_case_sensitive() {
        // The grammar reserves the lower-case spellings only, and names are
        // case-sensitive, so these differ from reserved words.
        assert!(Label::new("Node").is_ok());
        assert!(Label::new("NODE").is_ok());
        assert!(Label::new("nodes").is_ok());
        assert_eq!(Label::new("node"), Err(NameError::Reserved));
    }

    #[test]
    fn names_are_case_sensitive_and_distinct() {
        assert_ne!(Label::new("Login").unwrap(), Label::new("login").unwrap());
    }
}
