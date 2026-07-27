//! Opaque record identifiers.
//!
//! An identifier is sixteen opaque bytes. Nothing in the model interprets their
//! content: a path, a name, and a package are mutable locators, never an identity.
//! That is the rule in the root PRD section 11.2, and it is why these types expose
//! bytes and text rather than any structured accessor.
//!
//! # Textual form
//!
//! The textual form is a two-character kind prefix followed by a UUID in canonical
//! lower-case text, which is how an identifier appears in a `.nost` `id` property:
//!
//! ```text
//! n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b
//! ```
//!
//! The prefix is part of the form so a Node identifier is not silently accepted
//! where an Edge identifier is required. Upper-case hexadecimal is rejected, so one
//! set of bytes has exactly one spelling and a canonical writer never has to choose.
//!
//! Parsing accepts any well-formed UUID, not only a version 7 one. A `.nost` file
//! may carry identifiers minted by an older or a different implementation, and the
//! version nibble is not something a reader may depend on.
//!
//! # Minting
//!
//! [`Minter`] assigns identifiers to records a transaction creates. It mints a UUID
//! version 7 by default and offers a sequential mode for tests.

use std::fmt;
use std::str::FromStr;

/// Characters in the canonical UUID text form, `8-4-4-4-12`.
const ENCODED_LENGTH: usize = 36;

/// Byte offsets within the canonical text form that hold a hyphen.
const HYPHENS: [usize; 4] = [8, 13, 18, 23];

fn encode(bytes: [u8; 16]) -> String {
    let mut text = String::with_capacity(ENCODED_LENGTH);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        text.push(char::from(nibble(byte >> 4)));
        text.push(char::from(nibble(byte & 0x0F)));
    }
    text
}

const fn nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

const fn hex_value(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        _ => None,
    }
}

fn decode(text: &str) -> Result<[u8; 16], IdError> {
    let characters = text.as_bytes();
    if text.chars().count() != ENCODED_LENGTH {
        return Err(IdError::WrongLength {
            expected: ENCODED_LENGTH,
            found: text.chars().count(),
        });
    }
    // The count above is in scalar values, so a multi-byte scalar would leave the
    // byte slice shorter. Rejecting that here keeps the indexing below in range.
    if characters.len() != ENCODED_LENGTH {
        return Err(IdError::InvalidCharacter {
            found: text.chars().find(|c| !c.is_ascii()).unwrap_or('?'),
        });
    }

    let mut bytes = [0_u8; 16];
    let mut written = 0_usize;
    let mut high: Option<u8> = None;
    for (position, &character) in characters.iter().enumerate() {
        if HYPHENS.contains(&position) {
            if character != b'-' {
                return Err(IdError::MisplacedHyphen { position });
            }
            continue;
        }
        if character == b'-' {
            return Err(IdError::MisplacedHyphen { position });
        }
        let value = hex_value(character).ok_or(IdError::InvalidCharacter {
            found: char::from(character),
        })?;
        match high.take() {
            None => high = Some(value),
            Some(first) => {
                bytes[written] = (first << 4) | value;
                written += 1;
            }
        }
    }
    debug_assert_eq!(written, 16, "the length check guarantees sixteen bytes");
    Ok(bytes)
}

/// Why an identifier could not be read from text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdError {
    /// The text did not start with the kind prefix this identifier requires.
    MissingPrefix {
        /// The prefix that was required.
        expected: &'static str,
    },
    /// The body was not 36 characters long.
    WrongLength {
        /// The required character count.
        expected: usize,
        /// The character count found.
        found: usize,
    },
    /// A hyphen was missing from, or present outside, the `8-4-4-4-12` positions.
    MisplacedHyphen {
        /// The offending position within the body.
        position: usize,
    },
    /// The body contained a character that is not a lower-case hexadecimal digit.
    InvalidCharacter {
        /// The offending character.
        found: char,
    },
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix { expected } => {
                write!(formatter, "identifier must start with {expected:?}")
            }
            Self::WrongLength { expected, found } => write!(
                formatter,
                "identifier body must be {expected} characters, found {found}"
            ),
            Self::MisplacedHyphen { position } => write!(
                formatter,
                "identifier body must be grouped 8-4-4-4-12, but position {position} breaks it"
            ),
            Self::InvalidCharacter { found } => write!(
                formatter,
                "identifier body contains {found:?}, which is not a lower-case hexadecimal digit"
            ),
        }
    }
}

impl std::error::Error for IdError {}

macro_rules! opaque_id {
    ($name:ident, $prefix:literal, $what:literal) => {
        #[doc = concat!("An opaque persistent identifier for ", $what, ".")]
        ///
        #[doc = concat!("The textual form is `", $prefix, "` followed by a UUID in")]
        /// canonical lower-case text.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            #[doc = concat!("The textual prefix marking ", $what, ".")]
            pub const PREFIX: &'static str = $prefix;

            /// Wraps sixteen opaque bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Borrows the opaque bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Copies out the opaque bytes.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(Self::PREFIX)?;
                formatter.write_str(&encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                let body = text
                    .strip_prefix(Self::PREFIX)
                    .ok_or(IdError::MissingPrefix {
                        expected: Self::PREFIX,
                    })?;
                decode(body).map(Self)
            }
        }
    };
}

opaque_id!(LocalNodeId, "n_", "a Node within one database");
opaque_id!(LocalEdgeId, "e_", "an Edge within one database");
opaque_id!(
    SourceUnitId,
    "u_",
    "a source unit that a contribution was derived from"
);

impl SourceUnitId {
    /// The source unit a change made outside any analyzed source belongs to.
    ///
    /// A query is not an analyzed source, so a record it creates derives from no source
    /// unit. Every such contribution shares this one, which is harmless: an analyzer
    /// refresh replaces only contributions its own owner holds, and this unit only ever
    /// carries user-owned contributions.
    ///
    /// These are the all-zero bytes, which is exactly the nil UUID. A minted identifier
    /// is a version 7 value and therefore always carries 7 in its version nibble, so no
    /// minted value can ever collide with this sentinel. That is a property worth
    /// keeping rather than an accident to tidy away.
    pub const QUERY: Self = Self::from_bytes([0; 16]);
}

/// How a [`Minter`] chooses each value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Strategy {
    /// A UUID version 7: a millisecond timestamp followed by random bits.
    UuidV7,
    /// A generation and a counter, so a test can assert an exact value.
    Sequential { generation: u64, sequence: u64 },
}

/// Assigns identifiers to records a transaction creates.
///
/// # Why a UUID version 7
///
/// An identifier only has to be unique within one database, because a record is
/// identified across databases by the pair of canonical source locator and local
/// identifier. A version 7 value satisfies that with room to spare, and being
/// time-ordered it also groups records written together, which helps a storage layout
/// that reads them together.
///
/// An earlier revision derived identifiers from the generation and a counter, with no
/// entropy source at all. That was reversed deliberately; the root
/// `IMPLEMENTATION_PROGRESS.md` records the reversal and what it costs.
///
/// The one thing given up is reproducible building: the same source rebuilt no longer
/// yields the same bytes. Synchronization is unaffected, because it compares one file
/// against its own recorded baseline rather than comparing two independent builds.
///
/// Nothing reads an identifier's content. This is how a value is chosen, not a
/// structure any part of the model interprets.
///
/// # Collisions with stated identifiers
///
/// A `.nost` file may state an identifier explicitly, so a minted value could in
/// principle collide with one. A caller therefore passes each candidate through its own
/// in-use check and mints again; both strategies produce a fresh value every call, so
/// that terminates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minter {
    strategy: Strategy,
    issued: u64,
}

impl Minter {
    /// A minter that issues a UUID version 7 for each record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            strategy: Strategy::UuidV7,
            issued: 0,
        }
    }

    /// A minter that derives each value from `generation` and a counter.
    ///
    /// This exists so a test can assert an exact identifier. A release path uses
    /// [`Minter::new`]; nothing outside a test should choose this, because two
    /// databases at the same generation would mint the same values.
    #[must_use]
    pub const fn sequential(generation: u64) -> Self {
        Self {
            strategy: Strategy::Sequential {
                generation,
                sequence: 0,
            },
            issued: 0,
        }
    }

    fn next_bytes(&mut self) -> [u8; 16] {
        self.issued = self.issued.wrapping_add(1);
        match &mut self.strategy {
            Strategy::UuidV7 => uuid::Uuid::now_v7().into_bytes(),
            Strategy::Sequential {
                generation,
                sequence,
            } => {
                let current = *sequence;
                *sequence = sequence.wrapping_add(1);
                let mut bytes = [0_u8; 16];
                bytes[..8].copy_from_slice(&generation.to_be_bytes());
                bytes[8..].copy_from_slice(&current.to_be_bytes());
                bytes
            }
        }
    }

    /// The next Node identifier.
    pub fn node(&mut self) -> LocalNodeId {
        LocalNodeId::from_bytes(self.next_bytes())
    }

    /// The next Edge identifier.
    pub fn edge(&mut self) -> LocalEdgeId {
        LocalEdgeId::from_bytes(self.next_bytes())
    }

    /// How many identifiers this minter has issued.
    #[must_use]
    pub const fn issued(&self) -> u64 {
        self.issued
    }
}

impl Default for Minter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: [u8; 16] = [
        0x01, 0x8F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6,
        0xF7,
    ];

    #[test]
    fn text_round_trips_for_every_kind() {
        let node = LocalNodeId::from_bytes(SAMPLE);
        assert_eq!(LocalNodeId::from_str(&node.to_string()), Ok(node));

        let edge = LocalEdgeId::from_bytes(SAMPLE);
        assert_eq!(LocalEdgeId::from_str(&edge.to_string()), Ok(edge));

        let unit = SourceUnitId::from_bytes(SAMPLE);
        assert_eq!(SourceUnitId::from_str(&unit.to_string()), Ok(unit));
    }

    #[test]
    fn the_text_form_is_a_prefix_and_a_canonical_uuid() {
        let rendered = LocalNodeId::from_bytes(SAMPLE).to_string();
        assert_eq!(rendered, "n_018f2a3b-4c5d-6e7f-8091-a2b3c4d5e6f7");
        assert!(rendered.starts_with("n_"));
        assert_eq!(rendered.len(), 2 + ENCODED_LENGTH);
    }

    #[test]
    fn a_kind_prefix_is_required_and_not_interchangeable() {
        let node = LocalNodeId::from_bytes(SAMPLE).to_string();
        assert_eq!(
            LocalEdgeId::from_str(&node),
            Err(IdError::MissingPrefix { expected: "e_" })
        );
        assert_eq!(
            LocalNodeId::from_str("018f2a3b-4c5d-6e7f-8091-a2b3c4d5e6f7"),
            Err(IdError::MissingPrefix { expected: "n_" })
        );
    }

    #[test]
    fn rejects_a_wrong_length_body() {
        assert_eq!(
            LocalNodeId::from_str("n_1"),
            Err(IdError::WrongLength {
                expected: 36,
                found: 1
            })
        );
        assert_eq!(
            LocalNodeId::from_str("n_018f2a3b-4c5d-6e7f-8091-a2b3c4d5e6f"),
            Err(IdError::WrongLength {
                expected: 36,
                found: 35
            })
        );
    }

    #[test]
    fn rejects_a_misgrouped_body() {
        // Right length, hyphens in the wrong places.
        assert_eq!(
            LocalNodeId::from_str("n_018f2a3b4-c5d-6e7f-8091-a2b3c4d5e6f7"),
            Err(IdError::MisplacedHyphen { position: 8 })
        );
        // Right length and hyphens in the four required places, plus a stray one inside
        // the last group.
        assert_eq!(
            LocalNodeId::from_str("n_018f2a3b-4c5d-6e7f-8091-a2b3c4d-e6f7"),
            Err(IdError::MisplacedHyphen { position: 31 })
        );
    }

    #[test]
    fn rejects_upper_case_and_non_hexadecimal_bodies() {
        assert_eq!(
            LocalNodeId::from_str("n_018F2A3B-4C5D-6E7F-8091-A2B3C4D5E6F7"),
            Err(IdError::InvalidCharacter { found: 'F' })
        );
        assert_eq!(
            LocalNodeId::from_str("n_018f2a3g-4c5d-6e7f-8091-a2b3c4d5e6f7"),
            Err(IdError::InvalidCharacter { found: 'g' })
        );
    }

    #[test]
    fn rejects_a_non_ascii_body_without_panicking() {
        // Thirty-six scalar values, but more than thirty-six bytes.
        let body: String = "가".repeat(36);
        assert_eq!(
            LocalNodeId::from_str(&format!("n_{body}")),
            Err(IdError::InvalidCharacter { found: '가' })
        );
    }

    #[test]
    fn every_byte_pattern_round_trips() {
        for byte in 0..=u8::MAX {
            let id = LocalNodeId::from_bytes([byte; 16]);
            assert_eq!(LocalNodeId::from_str(&id.to_string()), Ok(id));
        }
    }

    #[test]
    fn a_minted_identifier_is_a_version_7_uuid() {
        let mut minter = Minter::new();
        for _ in 0..64 {
            let bytes = minter.node().to_bytes();
            assert_eq!(bytes[6] >> 4, 0x7, "version nibble must be 7");
            assert_eq!(bytes[8] >> 6, 0b10, "variant bits must be 0b10");
        }
    }

    #[test]
    fn minted_identifiers_do_not_repeat() {
        let mut minter = Minter::new();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..1024 {
            assert!(seen.insert(minter.node()), "a minted identifier repeated");
        }
        assert_eq!(minter.issued(), 1024);
    }

    #[test]
    fn a_minted_identifier_never_collides_with_the_query_source_unit() {
        // The sentinel is the nil UUID, whose version nibble is 0, and a version 7
        // value always carries 7. The two cannot meet.
        assert_eq!(SourceUnitId::QUERY.to_bytes(), [0; 16]);
        assert_eq!(
            SourceUnitId::QUERY.to_string(),
            "u_00000000-0000-0000-0000-000000000000"
        );
        let mut minter = Minter::new();
        for _ in 0..64 {
            assert_ne!(minter.node().to_bytes(), SourceUnitId::QUERY.to_bytes());
        }
    }

    #[test]
    fn the_sequential_strategy_is_reproducible_and_the_default_is_not() {
        let mut left = Minter::sequential(5);
        let mut right = Minter::sequential(5);
        assert_eq!(left.node(), right.node());
        assert_eq!(left.edge(), right.edge());

        let mut first = Minter::new();
        let mut second = Minter::new();
        assert_ne!(first.node(), second.node());
    }

    #[test]
    fn a_sequential_identifier_carries_its_generation_and_counter() {
        let mut minter = Minter::sequential(5);
        let first = minter.node().to_bytes();
        let second = minter.node().to_bytes();
        assert_eq!(first[..8], 5_u64.to_be_bytes());
        assert_eq!(first[8..], 0_u64.to_be_bytes());
        assert_eq!(second[8..], 1_u64.to_be_bytes());
        assert_eq!(minter.issued(), 2);
    }

    #[test]
    fn a_parsed_identifier_need_not_be_version_7() {
        // A .nost file may carry an identifier an older implementation minted, so a
        // reader must not depend on the version nibble.
        let parsed = LocalNodeId::from_str("n_018f2a3b-4c5d-1e7f-0091-a2b3c4d5e6f7");
        assert!(parsed.is_ok(), "a version 1 UUID must still parse");
    }
}
