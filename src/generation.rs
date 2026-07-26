//! Database generations.
//!
//! A generation is a monotonically increasing counter. Every successful commit
//! advances it, and synchronization compares generations and content digests rather
//! than wall-clock time, per the root PRD section 14. Two files at the same
//! generation with different digests have diverged; neither is newer.

use std::fmt;

/// A database generation.
///
/// The container contract does not constrain the stored value, so this type accepts
/// any `u64` a container can hold. What it does guarantee is that advancing is
/// checked: [`Generation::next`] cannot silently wrap back to a generation that has
/// already been committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    /// The generation of a newly created database.
    pub const INITIAL: Self = Self(1);

    /// Wraps a raw generation value.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// The raw generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next generation.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::Exhausted`] when the counter would wrap. Wrapping
    /// would produce a generation that has already been committed, which would make
    /// a diverged database look current.
    pub const fn next(self) -> Result<Self, GenerationError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(GenerationError::Exhausted),
        }
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Why a generation could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationError {
    /// The counter reached its maximum, so it cannot advance without wrapping.
    Exhausted,
}

impl fmt::Display for GenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => formatter.write_str("the database generation counter is exhausted"),
        }
    }
}

impl std::error::Error for GenerationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_database_starts_at_one() {
        assert_eq!(Generation::INITIAL.get(), 1);
    }

    #[test]
    fn generations_advance_and_order() {
        let first = Generation::INITIAL;
        let second = first.next().unwrap();
        let third = second.next().unwrap();
        assert_eq!(second.get(), 2);
        assert!(first < second);
        assert!(second < third);
    }

    #[test]
    fn advancing_never_wraps() {
        let last = Generation::from_raw(u64::MAX);
        assert_eq!(last.next(), Err(GenerationError::Exhausted));
    }
}
