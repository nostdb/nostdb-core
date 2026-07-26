//! Declared links.
//!
//! A link is identified by its canonical locator. The alias is a convenience for
//! writing readable references, lives in the graph and never in settings, and is
//! optional. That is the rule in the root PRD sections 7 and 18.1.

use crate::locator::CanonicalSourceLocator;
use crate::name::LinkAlias;
use std::fmt;

/// A link declaration stored in a database.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Link {
    /// The canonical locator, which is this link's identity.
    pub source: CanonicalSourceLocator,
    /// The optional alias.
    pub alias: Option<LinkAlias>,
}

impl Link {
    /// A link with no alias.
    #[must_use]
    pub const fn new(source: CanonicalSourceLocator) -> Self {
        Self {
            source,
            alias: None,
        }
    }

    /// A link with an alias.
    #[must_use]
    pub const fn with_alias(source: CanonicalSourceLocator, alias: LinkAlias) -> Self {
        Self {
            source,
            alias: Some(alias),
        }
    }

    /// Reports whether this link points at a remote source.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        self.source.is_remote()
    }
}

impl fmt::Display for Link {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.alias {
            Some(alias) => write!(formatter, "{} as {alias}", self.source),
            None => write!(formatter, "{}", self.source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator(value: &str) -> CanonicalSourceLocator {
        CanonicalSourceLocator::new(value).unwrap()
    }

    #[test]
    fn identity_is_the_locator_not_the_alias() {
        let bare = Link::new(locator("./packages/child"));
        let aliased = Link::with_alias(
            locator("./packages/child"),
            LinkAlias::new("child").unwrap(),
        );
        // The same target declared twice, once with an alias, is the same locator.
        assert_eq!(bare.source, aliased.source);
        // The records still differ, because the alias is stored.
        assert_ne!(bare, aliased);
    }

    #[test]
    fn renders_both_declaration_forms() {
        assert_eq!(Link::new(locator("./a")).to_string(), "./a");
        assert_eq!(
            Link::with_alias(locator("./a"), LinkAlias::new("a").unwrap()).to_string(),
            "./a as a"
        );
    }

    #[test]
    fn remoteness_comes_from_the_locator() {
        assert!(Link::new(locator("github://example/app/?ref=main")).is_remote());
        assert!(!Link::new(locator("./packages/child")).is_remote());
    }
}
