//! The `.nostdb` container.
//!
//! This implements the container contract `nostdb-spec` publishes: the magic, the
//! 48-byte header, the 32-byte section table entry, CRC-32C checksums, and the
//! twelve ordered bounded-parsing checks.
//!
//! # Opaque payloads
//!
//! A section payload is opaque here. This module locates, bounds, and checksums a
//! section; it does not interpret one. How a Node or an Edge is laid out inside the
//! `nodes` section is a separate contract that arrives with the parser, which is
//! the first thing that needs to turn a record into bytes.
//!
//! # Untrusted input
//!
//! [`Container::parse`] treats its input as hostile. Every length is validated
//! before it drives an allocation, and the checks run in the contract's order so a
//! file breaking several rules reports the first one rather than whichever check
//! happened to run first.

use crate::crc::crc32c;
use crate::diagnostic::DiagnosticCode;
use crate::generation::Generation;
use std::collections::BTreeSet;
use std::fmt;

/// The container magic: `NOSTDB` followed by `0x1A` and `0x0A`.
///
/// The `0x1A` halts accidental text-mode display, and the trailing `0x0A` detects
/// CRLF translation during transfer.
pub const MAGIC: [u8; 8] = [0x4E, 0x4F, 0x53, 0x54, 0x44, 0x42, 0x1A, 0x0A];

/// Header length, unchanged across every format version this build has written.
pub const HEADER_LENGTH: u64 = 48;

/// Length of one section table entry.
pub const SECTION_ENTRY_LENGTH: u64 = 32;

/// Format versions this build reads and writes.
///
/// Version 1 is **not** among them, and that is deliberate. A contribution's owner was three tagged shapes in
/// version 1 and is one interned name in version 2, with no reader left for the earlier tags. Keeping version 1
/// here would mean an old database decoded until it reached an owner byte and then reported an unknown tag,
/// which is what a corrupt file reports. Refusing it at the header instead says what is true: a database to
/// rebuild, not a database to fear.
/// Version 3 keeps version 2 readable, which the previous bump could not offer. A property
/// value may now be an object, and the two sections that changed differ narrowly: a list
/// element is a value rather than a scalar, which is byte-identical wherever the element is
/// a scalar, and a schema field's declared type is a recursive shape rather than a scalar
/// and a flag. Only the second needs a reader that knows which version it is reading.
///
/// Refusing version 2 would have destroyed data to avoid that one branch: a container holds
/// user-owned contributions no analyzer can rebuild from source. That is the difference from
/// version 1, for which no reader existed at all.
pub const SUPPORTED_FORMAT_VERSIONS: [u32; 2] = [2, 3];

/// The version this build writes.
///
/// A version 2 container opens, and the next write promotes it, because a write emits this
/// version through the same atomic path every write uses.
pub const FORMAT_VERSION: u32 = 3;

/// Largest permitted section count.
///
/// The limit is checked before the table is sized, so a corrupt count cannot make a
/// reader allocate a large table before it has validated anything.
pub const MAX_SECTION_COUNT: u64 = 4096;

/// Byte offset of the header checksum field, which is also the number of bytes it
/// covers.
const HEADER_CRC_OFFSET: usize = 44;

/// What a section holds.
///
/// An unknown kind in the reserved range is preserved rather than dropped, so a file
/// written by a newer build survives a round trip through an older one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SectionKind {
    /// Deduplicated strings other sections refer to.
    StringTable,
    /// Node records.
    Nodes,
    /// Edge records.
    Edges,
    /// Property records.
    Properties,
    /// Schema definitions.
    Schemas,
    /// Constraint definitions.
    Constraints,
    /// Evidence records.
    Evidence,
    /// Contribution records.
    Contributions,
    /// Link declarations, which are semantic.
    Links,
    /// Last resolved link snapshots, which are operational.
    LinkSnapshots,
    /// Analyzer metadata.
    AnalyzerMetadata,
    /// Synchronization metadata.
    SyncMetadata,
    /// Index metadata.
    Indexes,
    /// Build coverage.
    BuildCoverage,
    /// A kind reserved for a future standard section, `15..=32767`.
    Reserved(u32),
    /// An experimental kind, `32768..`, which a release build never writes.
    Experimental(u32),
}

impl SectionKind {
    /// Reads a kind from its stored value.
    ///
    /// # Errors
    ///
    /// Returns a corruption error when the value is zero, which the contract marks
    /// invalid and never written.
    pub const fn from_raw(value: u32) -> Result<Self, ContainerError> {
        Ok(match value {
            0 => return Err(ContainerError::Corrupt(CorruptReason::InvalidSectionKind)),
            1 => Self::StringTable,
            2 => Self::Nodes,
            3 => Self::Edges,
            4 => Self::Properties,
            5 => Self::Schemas,
            6 => Self::Constraints,
            7 => Self::Evidence,
            8 => Self::Contributions,
            9 => Self::Links,
            10 => Self::LinkSnapshots,
            11 => Self::AnalyzerMetadata,
            12 => Self::SyncMetadata,
            13 => Self::Indexes,
            14 => Self::BuildCoverage,
            15..=32767 => Self::Reserved(value),
            _ => Self::Experimental(value),
        })
    }

    /// The stored value for this kind.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::StringTable => 1,
            Self::Nodes => 2,
            Self::Edges => 3,
            Self::Properties => 4,
            Self::Schemas => 5,
            Self::Constraints => 6,
            Self::Evidence => 7,
            Self::Contributions => 8,
            Self::Links => 9,
            Self::LinkSnapshots => 10,
            Self::AnalyzerMetadata => 11,
            Self::SyncMetadata => 12,
            Self::Indexes => 13,
            Self::BuildCoverage => 14,
            Self::Reserved(value) | Self::Experimental(value) => value,
        }
    }

    /// Reports whether this build understands the section's contents.
    ///
    /// A reader still bounds and checksums a section it cannot interpret.
    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Reserved(_) | Self::Experimental(_))
    }
}

/// One section of a container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// What the section holds.
    pub kind: SectionKind,
    /// The opaque payload.
    pub payload: Vec<u8>,
}

/// A bounded-parsing limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// Number of sections.
    SectionCount,
}

impl fmt::Display for Limit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionCount => formatter.write_str("section count"),
        }
    }
}

/// Why a container is structurally invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorruptReason {
    /// The file is shorter than a header.
    TooShort,
    /// The magic does not match, which also catches a text-mode transfer.
    BadMagic,
    /// The header length is not what this format version fixes it at.
    WrongHeaderLength,
    /// The header checksum does not match.
    HeaderChecksum,
    /// A reserved field is not zero, so its future meaning cannot be relied on.
    ReservedNotZero,
    /// An undefined flag bit is set.
    UndefinedFlag,
    /// The section table does not lie inside the file at or after the header.
    TableOutOfBounds,
    /// A section kind is zero, which is never valid.
    InvalidSectionKind,
    /// A section does not lie inside the file, or its extent would wrap.
    SectionOutOfBounds,
    /// Two regions overlap.
    SectionOverlap,
    /// A section kind appears more than once.
    DuplicateSectionKind,
    /// A section checksum does not match.
    SectionChecksum,
}

impl fmt::Display for CorruptReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooShort => "the file is shorter than a container header",
            Self::BadMagic => "the container magic does not match",
            Self::WrongHeaderLength => "the header length is wrong for this format version",
            Self::HeaderChecksum => "the header checksum does not match",
            Self::ReservedNotZero => "a reserved field is not zero",
            Self::UndefinedFlag => "an undefined flag bit is set",
            Self::TableOutOfBounds => "the section table does not lie inside the file",
            Self::InvalidSectionKind => "a section kind is zero",
            Self::SectionOutOfBounds => "a section does not lie inside the file",
            Self::SectionOverlap => "two regions overlap",
            Self::DuplicateSectionKind => "a section kind appears more than once",
            Self::SectionChecksum => "a section checksum does not match",
        })
    }
}

/// Why a container could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerError {
    /// The container is structurally invalid.
    Corrupt(CorruptReason),
    /// The container declares a format version this build does not support.
    UnsupportedVersion {
        /// The version found.
        found: u32,
    },
    /// The container exceeds a bounded-parsing limit.
    LimitExceeded {
        /// Which limit.
        limit: Limit,
        /// The value found.
        found: u64,
    },
}

impl ContainerError {
    /// The stable diagnostic code for this error.
    #[must_use]
    pub const fn code(&self) -> DiagnosticCode {
        match self {
            Self::Corrupt(_) => DiagnosticCode::NostdbCorrupt,
            Self::UnsupportedVersion { .. } => DiagnosticCode::NostdbFormatUnsupported,
            Self::LimitExceeded { .. } => DiagnosticCode::NostdbLimitExceeded,
        }
    }
}

impl fmt::Display for ContainerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(reason) => write!(formatter, "{reason}"),
            Self::UnsupportedVersion { found } => write!(
                formatter,
                "nostdb_format_version {found} is not supported by this build"
            ),
            Self::LimitExceeded { limit, found } => {
                write!(formatter, "the {limit} limit is exceeded: {found}")
            }
        }
    }
}

impl std::error::Error for ContainerError {}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let array: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let array: [u8; 8] = bytes.get(at..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

fn corrupt<T>(reason: CorruptReason) -> Result<T, ContainerError> {
    Err(ContainerError::Corrupt(reason))
}

/// A validated container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    generation: Generation,
    version: u32,
    sections: Vec<Section>,
}

impl Container {
    /// Validates and reads a container from bytes.
    ///
    /// Checks run in the order the contract states, so a file breaking several rules
    /// reports the first violation rather than an arbitrary one.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Corrupt`] for a structural violation,
    /// [`ContainerError::UnsupportedVersion`] when the format version is not
    /// supported, and [`ContainerError::LimitExceeded`] when a bounded-parsing limit
    /// is exceeded. Use [`ContainerError::code`] for the stable diagnostic code.
    pub fn parse(bytes: &[u8]) -> Result<Self, ContainerError> {
        let file_length = bytes.len() as u64;

        // 1. The file is at least a header long.
        if file_length < HEADER_LENGTH {
            return corrupt(CorruptReason::TooShort);
        }

        // 2. The magic matches, before any length is trusted.
        if bytes.get(..MAGIC.len()) != Some(&MAGIC[..]) {
            return corrupt(CorruptReason::BadMagic);
        }

        // 3. The format version is supported.
        let version = u32_at(bytes, 8).ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?;
        if !SUPPORTED_FORMAT_VERSIONS.contains(&version) {
            return Err(ContainerError::UnsupportedVersion { found: version });
        }

        // 4. This format version fixes the header length.
        let header_length =
            u64::from(u32_at(bytes, 12).ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?);
        if header_length != HEADER_LENGTH {
            return corrupt(CorruptReason::WrongHeaderLength);
        }

        // 5. The header checksum covers the header with the checksum field excluded.
        let covered = bytes
            .get(..HEADER_CRC_OFFSET)
            .ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?;
        let stored_crc = u32_at(bytes, HEADER_CRC_OFFSET)
            .ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?;
        if crc32c(covered) != stored_crc {
            return corrupt(CorruptReason::HeaderChecksum);
        }

        // 6. No undefined flag is set, and the reserved field is zero.
        let flags = u32_at(bytes, 36).ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?;
        if flags != 0 {
            return corrupt(CorruptReason::UndefinedFlag);
        }
        let reserved = u32_at(bytes, 40).ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?;
        if reserved != 0 {
            return corrupt(CorruptReason::ReservedNotZero);
        }

        let generation = Generation::from_raw(
            u64_at(bytes, 16).ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?,
        );

        // 7. The section count is bounded before the table is sized.
        let section_count =
            u64::from(u32_at(bytes, 32).ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?);
        if section_count > MAX_SECTION_COUNT {
            return Err(ContainerError::LimitExceeded {
                limit: Limit::SectionCount,
                found: section_count,
            });
        }

        // 8. The whole section table lies inside the file, at or after the header.
        let table_offset =
            u64_at(bytes, 24).ok_or(ContainerError::Corrupt(CorruptReason::TooShort))?;
        let table_length = section_count
            .checked_mul(SECTION_ENTRY_LENGTH)
            .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
        let table_end = table_offset
            .checked_add(table_length)
            .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
        if table_offset < HEADER_LENGTH || table_end > file_length {
            return corrupt(CorruptReason::TableOutOfBounds);
        }

        let mut regions: Vec<(u64, u64)> = vec![(0, HEADER_LENGTH)];
        if table_length > 0 {
            regions.push((table_offset, table_end));
        }

        let mut kinds: BTreeSet<u32> = BTreeSet::new();
        let mut planned: Vec<(SectionKind, u64, u64, u32)> = Vec::new();

        for index in 0..section_count {
            let entry_offset = table_offset
                .checked_add(
                    index
                        .checked_mul(SECTION_ENTRY_LENGTH)
                        .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?,
                )
                .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
            let base = usize::try_from(entry_offset)
                .map_err(|_| ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;

            let raw_kind = u32_at(bytes, base)
                .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
            let entry_reserved = u32_at(bytes, base + 4)
                .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
            let entry_reserved2 = u32_at(bytes, base + 28)
                .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
            if entry_reserved != 0 || entry_reserved2 != 0 {
                return corrupt(CorruptReason::ReservedNotZero);
            }
            let kind = SectionKind::from_raw(raw_kind)?;

            let offset = u64_at(bytes, base + 8)
                .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
            let length = u64_at(bytes, base + 16)
                .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;
            let stored = u32_at(bytes, base + 24)
                .ok_or(ContainerError::Corrupt(CorruptReason::TableOutOfBounds))?;

            // 9. The section lies inside the file without wrapping.
            let end = offset
                .checked_add(length)
                .ok_or(ContainerError::Corrupt(CorruptReason::SectionOutOfBounds))?;
            if offset < HEADER_LENGTH || end > file_length {
                return corrupt(CorruptReason::SectionOutOfBounds);
            }

            // 11. A section kind never repeats.
            if !kinds.insert(raw_kind) {
                return corrupt(CorruptReason::DuplicateSectionKind);
            }

            if length > 0 {
                regions.push((offset, end));
            }
            planned.push((kind, offset, length, stored));
        }

        // 10. Nothing overlaps the header, the table, or another section.
        for (index, &(a_start, a_end)) in regions.iter().enumerate() {
            for &(b_start, b_end) in regions.get(index + 1..).unwrap_or_default() {
                if a_start < b_end && b_start < a_end {
                    return corrupt(CorruptReason::SectionOverlap);
                }
            }
        }

        // 12. Every section checksum matches.
        let mut sections = Vec::with_capacity(planned.len());
        for (kind, offset, length, stored) in planned {
            let start = usize::try_from(offset)
                .map_err(|_| ContainerError::Corrupt(CorruptReason::SectionOutOfBounds))?;
            let end = usize::try_from(offset + length)
                .map_err(|_| ContainerError::Corrupt(CorruptReason::SectionOutOfBounds))?;
            let payload = bytes
                .get(start..end)
                .ok_or(ContainerError::Corrupt(CorruptReason::SectionOutOfBounds))?;
            if crc32c(payload) != stored {
                return corrupt(CorruptReason::SectionChecksum);
            }
            sections.push(Section {
                kind,
                payload: payload.to_vec(),
            });
        }

        Ok(Self {
            generation,
            version,
            sections,
        })
    }

    /// The generation this container records.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// The `nostdb_format_version` this container declared.
    ///
    /// Retained rather than discarded after validation because one section decodes
    /// differently per version: a schema field's declared type. Every other section is
    /// version-independent, which is why this is a decoder input rather than a migration
    /// step.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Every section, in the order the table listed them.
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// The payload of one section, when present.
    #[must_use]
    pub fn section(&self, kind: SectionKind) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|section| section.kind == kind)
            .map(|section| section.payload.as_slice())
    }
}

/// Builds a container.
#[derive(Clone, Debug)]
pub struct ContainerBuilder {
    generation: Generation,
    sections: Vec<Section>,
}

impl ContainerBuilder {
    /// Starts a container at the given generation.
    #[must_use]
    pub const fn new(generation: Generation) -> Self {
        Self {
            generation,
            sections: Vec::new(),
        }
    }

    /// Adds a section.
    ///
    /// # Errors
    ///
    /// Returns a corruption error when the kind is already present, because a kind
    /// must not repeat within one container.
    pub fn push_section(
        &mut self,
        kind: SectionKind,
        payload: impl Into<Vec<u8>>,
    ) -> Result<(), ContainerError> {
        if self.sections.iter().any(|section| section.kind == kind) {
            return corrupt(CorruptReason::DuplicateSectionKind);
        }
        self.sections.push(Section {
            kind,
            payload: payload.into(),
        });
        Ok(())
    }

    /// Serializes the container.
    ///
    /// Sections are laid out contiguously after the table, in the order they were
    /// added, so the same input always produces the same bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::LimitExceeded`] when there are more sections than
    /// the contract permits.
    pub fn build(&self) -> Result<Vec<u8>, ContainerError> {
        let section_count = self.sections.len() as u64;
        if section_count > MAX_SECTION_COUNT {
            return Err(ContainerError::LimitExceeded {
                limit: Limit::SectionCount,
                found: section_count,
            });
        }

        let table_offset = HEADER_LENGTH;
        let table_length = section_count * SECTION_ENTRY_LENGTH;
        let mut cursor = table_offset + table_length;

        let mut table = Vec::with_capacity(table_length as usize);
        let mut payloads = Vec::new();
        for section in &self.sections {
            let length = section.payload.len() as u64;
            table.extend_from_slice(&section.kind.raw().to_le_bytes());
            table.extend_from_slice(&0_u32.to_le_bytes());
            table.extend_from_slice(&cursor.to_le_bytes());
            table.extend_from_slice(&length.to_le_bytes());
            table.extend_from_slice(&crc32c(&section.payload).to_le_bytes());
            table.extend_from_slice(&0_u32.to_le_bytes());
            payloads.extend_from_slice(&section.payload);
            cursor += length;
        }

        let mut header = Vec::with_capacity(HEADER_LENGTH as usize);
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        header.extend_from_slice(&(HEADER_LENGTH as u32).to_le_bytes());
        header.extend_from_slice(&self.generation.get().to_le_bytes());
        header.extend_from_slice(&table_offset.to_le_bytes());
        header.extend_from_slice(&(section_count as u32).to_le_bytes());
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.extend_from_slice(&crc32c(&header).to_le_bytes());

        let mut bytes = header;
        bytes.extend_from_slice(&table);
        bytes.extend_from_slice(&payloads);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built(generation: u64, sections: &[(SectionKind, &[u8])]) -> Vec<u8> {
        let mut builder = ContainerBuilder::new(Generation::from_raw(generation));
        for &(kind, payload) in sections {
            builder.push_section(kind, payload).unwrap();
        }
        builder.build().unwrap()
    }

    #[test]
    fn an_empty_container_round_trips() {
        let bytes = built(1, &[]);
        assert_eq!(bytes.len(), HEADER_LENGTH as usize);
        let container = Container::parse(&bytes).unwrap();
        assert_eq!(container.generation(), Generation::INITIAL);
        assert!(container.sections().is_empty());
    }

    #[test]
    fn sections_round_trip_with_their_payloads_and_generation() {
        let bytes = built(
            42,
            &[
                (SectionKind::StringTable, b"strings"),
                (SectionKind::Nodes, b"node bytes"),
                (SectionKind::Links, b""),
            ],
        );
        let container = Container::parse(&bytes).unwrap();
        assert_eq!(container.generation().get(), 42);
        assert_eq!(container.sections().len(), 3);
        assert_eq!(
            container.section(SectionKind::StringTable),
            Some(&b"strings"[..])
        );
        assert_eq!(
            container.section(SectionKind::Nodes),
            Some(&b"node bytes"[..])
        );
        assert_eq!(container.section(SectionKind::Links), Some(&b""[..]));
        assert_eq!(container.section(SectionKind::Edges), None);
    }

    #[test]
    fn building_is_deterministic() {
        let first = built(
            7,
            &[(SectionKind::Nodes, b"a"), (SectionKind::Edges, b"bb")],
        );
        let second = built(
            7,
            &[(SectionKind::Nodes, b"a"), (SectionKind::Edges, b"bb")],
        );
        assert_eq!(first, second);
    }

    #[test]
    fn a_reserved_kind_survives_a_round_trip() {
        let kind = SectionKind::from_raw(9000).unwrap();
        assert_eq!(kind, SectionKind::Reserved(9000));
        assert!(!kind.is_known());
        let bytes = built(1, &[(kind, b"future")]);
        let container = Container::parse(&bytes).unwrap();
        assert_eq!(container.section(kind), Some(&b"future"[..]));
    }

    #[test]
    fn an_experimental_kind_is_distinguished_from_a_reserved_one() {
        assert_eq!(
            SectionKind::from_raw(40000).unwrap(),
            SectionKind::Experimental(40000)
        );
        assert_eq!(
            SectionKind::from_raw(32767).unwrap(),
            SectionKind::Reserved(32767)
        );
        assert_eq!(
            SectionKind::from_raw(0),
            Err(ContainerError::Corrupt(CorruptReason::InvalidSectionKind))
        );
    }

    #[test]
    fn every_known_kind_round_trips_through_its_raw_value() {
        for raw in 1_u32..=14 {
            let kind = SectionKind::from_raw(raw).unwrap();
            assert!(kind.is_known(), "{raw}");
            assert_eq!(kind.raw(), raw);
        }
    }

    #[test]
    fn a_duplicate_kind_is_refused_when_building() {
        let mut builder = ContainerBuilder::new(Generation::INITIAL);
        builder
            .push_section(SectionKind::Nodes, b"a".to_vec())
            .unwrap();
        assert_eq!(
            builder.push_section(SectionKind::Nodes, b"b".to_vec()),
            Err(ContainerError::Corrupt(CorruptReason::DuplicateSectionKind))
        );
    }

    #[test]
    fn a_short_file_is_corrupt() {
        assert_eq!(
            Container::parse(&[]),
            Err(ContainerError::Corrupt(CorruptReason::TooShort))
        );
        let bytes = built(1, &[]);
        assert_eq!(
            Container::parse(&bytes[..HEADER_LENGTH as usize - 1]),
            Err(ContainerError::Corrupt(CorruptReason::TooShort))
        );
    }

    #[test]
    fn bad_magic_is_detected_before_anything_else() {
        let mut bytes = built(1, &[]);
        bytes[7] = 0x0D; // the CRLF-translation case
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::BadMagic))
        );
    }

    #[test]
    fn an_unsupported_version_is_distinguished_from_corruption() {
        // Version 1 is the live case, not a hypothetical one: it is what every database written before an
        // owner became one interned name declares, and there is no reader left for the owner tags it holds.
        // Refusing it here rather than at the tag is what makes it a database to rebuild instead of one that
        // looks corrupt.
        let mut bytes = built(FORMAT_VERSION.into(), &[]);
        bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
        // Repair the checksum so only the version check can fire.
        let crc = crc32c(&bytes[..HEADER_CRC_OFFSET]);
        bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::UnsupportedVersion { found: 1 })
        );
        assert_eq!(
            Container::parse(&bytes).unwrap_err().code(),
            DiagnosticCode::NostdbFormatUnsupported
        );
    }

    #[test]
    fn a_wrong_header_length_is_corrupt() {
        let mut bytes = built(1, &[]);
        bytes[12..16].copy_from_slice(&40_u32.to_le_bytes());
        let crc = crc32c(&bytes[..HEADER_CRC_OFFSET]);
        bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::WrongHeaderLength))
        );
    }

    #[test]
    fn flipping_any_checksum_covered_header_byte_is_detected() {
        let original = built(1, &[]);
        assert!(Container::parse(&original).is_ok());
        for index in 0..HEADER_CRC_OFFSET {
            let mut mutated = original.clone();
            mutated[index] ^= 0x01;
            assert!(
                Container::parse(&mutated).is_err(),
                "flipping a bit at offset {index} went undetected"
            );
        }
    }

    #[test]
    fn a_set_flag_and_a_nonzero_reserved_field_are_refused() {
        for (offset, expected) in [
            (36_usize, CorruptReason::UndefinedFlag),
            (40, CorruptReason::ReservedNotZero),
        ] {
            let mut bytes = built(1, &[]);
            bytes[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
            let crc = crc32c(&bytes[..HEADER_CRC_OFFSET]);
            bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
            assert_eq!(
                Container::parse(&bytes),
                Err(ContainerError::Corrupt(expected))
            );
        }
    }

    #[test]
    fn too_many_sections_is_a_limit_not_corruption() {
        let mut bytes = built(1, &[]);
        let over = u32::try_from(MAX_SECTION_COUNT).unwrap() + 1;
        bytes[32..36].copy_from_slice(&over.to_le_bytes());
        let crc = crc32c(&bytes[..HEADER_CRC_OFFSET]);
        bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        let error = Container::parse(&bytes).unwrap_err();
        assert_eq!(
            error,
            ContainerError::LimitExceeded {
                limit: Limit::SectionCount,
                found: u64::from(over)
            }
        );
        assert_eq!(error.code(), DiagnosticCode::NostdbLimitExceeded);
    }

    #[test]
    fn the_limit_is_checked_before_the_table_is_sized() {
        // The file is only a header long, so a table bounds check would also fail.
        // The limit must be reported, because it is checked first.
        let mut bytes = built(1, &[]);
        bytes[32..36].copy_from_slice(&4097_u32.to_le_bytes());
        let crc = crc32c(&bytes[..HEADER_CRC_OFFSET]);
        bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            Container::parse(&bytes),
            Err(ContainerError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn a_table_outside_the_file_or_inside_the_header_is_refused() {
        for offset in [16_u64, 4096] {
            let mut bytes = built(1, &[(SectionKind::Nodes, b"abcd")]);
            bytes[24..32].copy_from_slice(&offset.to_le_bytes());
            let crc = crc32c(&bytes[..HEADER_CRC_OFFSET]);
            bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
            assert_eq!(
                Container::parse(&bytes),
                Err(ContainerError::Corrupt(CorruptReason::TableOutOfBounds)),
                "table offset {offset}"
            );
        }
    }

    #[test]
    fn a_section_outside_the_file_is_refused() {
        let mut bytes = built(1, &[(SectionKind::Nodes, b"abcd")]);
        // Section length field of the single entry lives at 48 + 16.
        bytes[64..72].copy_from_slice(&1000_u64.to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::SectionOutOfBounds))
        );
    }

    #[test]
    fn a_section_extent_that_would_wrap_is_refused() {
        let mut bytes = built(1, &[(SectionKind::Nodes, b"abcd")]);
        bytes[64..72].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::SectionOutOfBounds))
        );
    }

    #[test]
    fn a_section_overlapping_the_header_is_refused() {
        let mut bytes = built(1, &[(SectionKind::Nodes, b"abcd")]);
        // Section offset field lives at 48 + 8.
        bytes[56..64].copy_from_slice(&0_u64.to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::SectionOutOfBounds))
        );
    }

    #[test]
    fn overlapping_sections_are_refused() {
        let mut bytes = built(
            1,
            &[
                (SectionKind::Nodes, b"aaaaaaaa"),
                (SectionKind::Edges, b"bbbbbbbb"),
            ],
        );
        // Point the second entry's offset into the first payload.
        let second_entry = 48 + 32;
        let first_offset = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        bytes[second_entry + 8..second_entry + 16]
            .copy_from_slice(&(first_offset + 4).to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::SectionOverlap))
        );
    }

    #[test]
    fn a_duplicate_kind_in_the_table_is_refused() {
        let mut bytes = built(
            1,
            &[(SectionKind::Nodes, b"aaaa"), (SectionKind::Edges, b"bbbb")],
        );
        let second_entry = 48 + 32;
        bytes[second_entry..second_entry + 4]
            .copy_from_slice(&SectionKind::Nodes.raw().to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::DuplicateSectionKind))
        );
    }

    #[test]
    fn a_bad_section_checksum_is_refused() {
        let mut bytes = built(1, &[(SectionKind::Nodes, b"abcd")]);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::SectionChecksum))
        );
    }

    #[test]
    fn a_nonzero_entry_reserved_field_is_refused() {
        for offset in [48 + 4_usize, 48 + 28] {
            let mut bytes = built(1, &[(SectionKind::Nodes, b"abcd")]);
            bytes[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
            assert_eq!(
                Container::parse(&bytes),
                Err(ContainerError::Corrupt(CorruptReason::ReservedNotZero)),
                "entry reserved at {offset}"
            );
        }
    }

    #[test]
    fn a_zero_section_kind_is_refused() {
        let mut bytes = built(1, &[(SectionKind::Nodes, b"abcd")]);
        bytes[48..52].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            Container::parse(&bytes),
            Err(ContainerError::Corrupt(CorruptReason::InvalidSectionKind))
        );
    }
}
