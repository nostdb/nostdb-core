//! Opaque record identifiers.
//!
//! An identifier is sixteen opaque bytes. Nothing in the model interprets their
//! content: a path, a name, and a package are mutable locators, never an identity.
//! That is the rule in the root PRD section 11.2, and it is why these types expose
//! bytes and text rather than any structured accessor.
//!
//! # Textual form
//!
//! The textual form is a two-character kind prefix followed by 26 Crockford base32
//! characters, which is how an identifier appears inside a `.nost` `id` clause.
//! Crockford base32 omits `I`, `L`, `O`, and `U`, so a transcribed identifier
//! cannot turn a letter into a digit. Decoding accepts either case and maps `I`
//! and `L` to `1` and `O` to `0`; encoding always emits upper case.
//!
//! # Minting
//!
//! [`Minter`] assigns identifiers to records a transaction creates. It derives them
//! from the generation being written and a counter within that transaction rather
//! than from randomness, which is a deliberate choice explained on the type.

use std::fmt;
use std::str::FromStr;

/// Crockford base32 alphabet.
const ALPHABET: [u8; 32] = *b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of base32 characters that encode sixteen bytes.
const ENCODED_LENGTH: usize = 26;

/// Highest value the leading character may carry, because sixteen bytes occupy
/// 128 bits and 26 base32 characters carry 130.
const MAX_LEADING_DIGIT: u8 = 7;

fn encode(bytes: [u8; 16]) -> String {
    let mut value = u128::from_be_bytes(bytes);
    let mut buffer = [0_u8; ENCODED_LENGTH];
    for slot in buffer.iter_mut().rev() {
        *slot = ALPHABET[(value & 0x1F) as usize];
        value >>= 5;
    }
    buffer.iter().map(|&byte| char::from(byte)).collect()
}

fn digit(character: char) -> Option<u8> {
    if !character.is_ascii() {
        return None;
    }
    let upper = character.to_ascii_uppercase();
    match upper {
        'O' => Some(0),
        'I' | 'L' => Some(1),
        'U' => None,
        _ => ALPHABET
            .iter()
            .position(|&byte| byte == upper as u8)
            .and_then(|position| u8::try_from(position).ok()),
    }
}

fn decode(text: &str) -> Result<[u8; 16], IdError> {
    let characters: Vec<char> = text.chars().collect();
    if characters.len() != ENCODED_LENGTH {
        return Err(IdError::WrongLength {
            expected: ENCODED_LENGTH,
            found: characters.len(),
        });
    }
    let mut value: u128 = 0;
    for (index, &character) in characters.iter().enumerate() {
        let digit = digit(character).ok_or(IdError::InvalidCharacter { found: character })?;
        if index == 0 && digit > MAX_LEADING_DIGIT {
            return Err(IdError::OutOfRange);
        }
        value = (value << 5) | u128::from(digit);
    }
    Ok(value.to_be_bytes())
}

/// Why an identifier could not be read from text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdError {
    /// The text did not start with the kind prefix this identifier requires.
    MissingPrefix {
        /// The prefix that was required.
        expected: &'static str,
    },
    /// The encoded body was not 26 characters long.
    WrongLength {
        /// The required character count.
        expected: usize,
        /// The character count found.
        found: usize,
    },
    /// The encoded body contained a character outside the Crockford alphabet.
    InvalidCharacter {
        /// The offending character.
        found: char,
    },
    /// The encoded body described a value wider than sixteen bytes.
    OutOfRange,
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
            Self::InvalidCharacter { found } => write!(
                formatter,
                "identifier body contains {found:?}, which is not Crockford base32"
            ),
            Self::OutOfRange => {
                formatter.write_str("identifier body describes more than sixteen bytes")
            }
        }
    }
}

impl std::error::Error for IdError {}

macro_rules! opaque_id {
    ($name:ident, $prefix:literal, $what:literal) => {
        #[doc = concat!("An opaque persistent identifier for ", $what, ".")]
        ///
        #[doc = concat!("The textual form is `", $prefix, "` followed by 26 Crockford")]
        /// base32 characters.
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
    StableModuleId,
    "m_",
    "an analyzed module, persisted across renames"
);
opaque_id!(
    SourceUnitId,
    "u_",
    "a source unit that a contribution was derived from"
);

impl SourceUnitId {
    /// The source unit a change made through the query language belongs to.
    ///
    /// A query is not an analyzed source, so a record it creates derives from no source
    /// unit. Every such contribution shares this one, which is harmless: an analyzer
    /// refresh replaces only contributions its own owner holds, and this unit only ever
    /// carries user-owned contributions.
    pub const QUERY: Self = Self::from_bytes([0; 16]);
}

/// Assigns identifiers to records a transaction creates.
///
/// # Why not randomness
///
/// An identifier is only required to be unique within one database, because a record is
/// identified across databases by the pair of canonical source locator and local
/// identifier. Deriving it from the generation being written and a counter within that
/// transaction satisfies that: a generation is committed at most once, so no two
/// transactions can mint the same value, and a deleted record's identifier is never
/// reissued.
///
/// Determinism also buys something an entropy source would take away. The same write
/// against the same database produces the same file, which is what lets synchronization
/// compare content digests rather than wall-clock time. A random identifier would make
/// two identical writes produce two different databases.
///
/// Nothing reads an identifier's content. This is how a value is chosen, not a structure
/// any part of the model interprets.
///
/// # Collisions with stated identifiers
///
/// A `.nost` file may state an identifier explicitly, so a minted value could in
/// principle collide with one. A caller therefore passes each candidate through its own
/// in-use check and calls [`Minter::node`] again; the counter never repeats, so that
/// terminates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minter {
    generation: u64,
    sequence: u64,
}

impl Minter {
    /// A minter for records committed at `generation`.
    ///
    /// Pass the generation the transaction will write, not the one it read.
    #[must_use]
    pub const fn new(generation: u64) -> Self {
        Self {
            generation,
            sequence: 0,
        }
    }

    fn next_bytes(&mut self) -> [u8; 16] {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&self.generation.to_be_bytes());
        bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        bytes
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
        self.sequence
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

        let module = StableModuleId::from_bytes(SAMPLE);
        assert_eq!(StableModuleId::from_str(&module.to_string()), Ok(module));

        let unit = SourceUnitId::from_bytes(SAMPLE);
        assert_eq!(SourceUnitId::from_str(&unit.to_string()), Ok(unit));
    }

    #[test]
    fn the_textual_form_has_the_documented_shape() {
        let rendered = LocalNodeId::from_bytes(SAMPLE).to_string();
        assert!(rendered.starts_with("n_"));
        assert_eq!(rendered.len(), 2 + ENCODED_LENGTH);
        assert!(rendered[2..].chars().all(|c| ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn all_zero_and_all_one_bytes_round_trip() {
        for bytes in [[0x00_u8; 16], [0xFF_u8; 16]] {
            let id = LocalNodeId::from_bytes(bytes);
            assert_eq!(LocalNodeId::from_str(&id.to_string()), Ok(id));
            assert_eq!(id.to_bytes(), bytes);
        }
    }

    #[test]
    fn a_kind_prefix_is_required_and_not_interchangeable() {
        let node = LocalNodeId::from_bytes(SAMPLE).to_string();
        assert_eq!(
            LocalEdgeId::from_str(&node),
            Err(IdError::MissingPrefix { expected: "e_" })
        );
        assert_eq!(
            LocalNodeId::from_str(&node[2..]),
            Err(IdError::MissingPrefix { expected: "n_" })
        );
    }

    #[test]
    fn decoding_is_case_insensitive_and_maps_confusable_letters() {
        let canonical = LocalNodeId::from_str("n_0000000000000000000000000K").unwrap();
        assert_eq!(
            LocalNodeId::from_str("n_0000000000000000000000000k"),
            Ok(canonical)
        );
        // O decodes as zero, and I and L decode as one.
        assert_eq!(
            LocalNodeId::from_str("n_OOOOOOOOOOOOOOOOOOOOOOOOOO"),
            Ok(LocalNodeId::from_bytes([0; 16]))
        );
        let ones = LocalNodeId::from_str("n_IIIIIIIIIIIIIIIIIIIIIIIIII").unwrap();
        assert_eq!(
            LocalNodeId::from_str("n_LLLLLLLLLLLLLLLLLLLLLLLLLL"),
            Ok(ones)
        );
    }

    #[test]
    fn rejects_a_wrong_length_body() {
        assert_eq!(
            LocalNodeId::from_str("n_0"),
            Err(IdError::WrongLength {
                expected: ENCODED_LENGTH,
                found: 1
            })
        );
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // U is excluded from Crockford base32 on purpose.
        assert_eq!(
            LocalNodeId::from_str("n_U000000000000000000000000"),
            Err(IdError::WrongLength {
                expected: ENCODED_LENGTH,
                found: 25
            })
        );
        assert_eq!(
            LocalNodeId::from_str("n_U0000000000000000000000000"),
            Err(IdError::InvalidCharacter { found: 'U' })
        );
        assert_eq!(
            LocalNodeId::from_str("n_$0000000000000000000000000"),
            Err(IdError::InvalidCharacter { found: '$' })
        );
    }

    #[test]
    fn rejects_a_body_wider_than_sixteen_bytes() {
        // The leading character carries only three significant bits, so any value
        // above seven would describe a 129-bit number.
        assert_eq!(
            LocalNodeId::from_str("n_80000000000000000000000000"),
            Err(IdError::OutOfRange)
        );
        assert_eq!(
            LocalNodeId::from_str("n_Z0000000000000000000000000"),
            Err(IdError::OutOfRange)
        );
        assert!(LocalNodeId::from_str("n_70000000000000000000000000").is_ok());
    }

    #[test]
    fn a_minter_never_repeats_within_a_generation() {
        let mut minter = Minter::new(7);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(minter.node().to_bytes()));
        }
        assert_eq!(minter.issued(), 1000);
    }

    #[test]
    fn two_generations_never_mint_the_same_identifier() {
        // This is what makes a deleted record's identifier safe from reissue: a generation
        // is committed at most once.
        let first: Vec<[u8; 16]> = {
            let mut minter = Minter::new(3);
            (0..8).map(|_| minter.node().to_bytes()).collect()
        };
        let second: Vec<[u8; 16]> = {
            let mut minter = Minter::new(4);
            (0..8).map(|_| minter.node().to_bytes()).collect()
        };
        for bytes in &first {
            assert!(!second.contains(bytes));
        }
    }

    #[test]
    fn minting_is_reproducible_so_two_identical_writes_produce_one_database() {
        let mut left = Minter::new(12);
        let mut right = Minter::new(12);
        assert_eq!(left.node(), right.node());
        assert_eq!(left.edge(), right.edge());
    }

    #[test]
    fn a_node_and_an_edge_identifier_never_share_a_body() {
        // One counter serves both kinds, so nothing depends on remembering that a node and
        // an edge are different types.
        let mut minter = Minter::new(1);
        let node = minter.node();
        let edge = minter.edge();
        assert_ne!(node.to_bytes(), edge.to_bytes());
    }

    #[test]
    fn the_query_source_unit_is_a_stable_well_known_value() {
        assert_eq!(SourceUnitId::QUERY.to_bytes(), [0; 16]);
        assert_eq!(
            SourceUnitId::from_str(&SourceUnitId::QUERY.to_string()),
            Ok(SourceUnitId::QUERY)
        );
    }

    #[test]
    fn non_ascii_is_rejected_rather_than_truncated() {
        assert_eq!(
            LocalNodeId::from_str("n_Ω000000000000000000000000"),
            Err(IdError::WrongLength {
                expected: ENCODED_LENGTH,
                found: 25
            })
        );
        assert_eq!(
            LocalNodeId::from_str("n_Ω0000000000000000000000000"),
            Err(IdError::InvalidCharacter { found: 'Ω' })
        );
    }
}
