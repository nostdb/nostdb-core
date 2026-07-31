//! Provenance for graph records.
//!
//! Every analyzer-created Node and Edge carries evidence tracing it back to
//! accessible source, which is the rule in the root PRD section 11.4. Evidence is
//! what makes a graph fact checkable rather than asserted.

use crate::locator::CanonicalSourceLocator;
use crate::text::NonEmptyText;
use std::fmt;

/// A position in a source file.
///
/// Lines and columns are 1-based, counted in Unicode scalar values, and the offset
/// is a 0-based byte offset. Carrying both means a diagnostic can be shown to a
/// person and sliced by a machine without recomputing one from the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourcePosition {
    /// 1-based line.
    pub line: u32,
    /// 1-based column, in Unicode scalar values.
    pub column: u32,
    /// 0-based byte offset from the start of the source.
    pub offset: u64,
}

/// A half-open range within one source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceRange {
    start: SourcePosition,
    end: SourcePosition,
}

impl SourceRange {
    /// A zero-length range at the start of a source.
    ///
    /// This exists so a caller that has provably valid positions can fall back
    /// without panicking, rather than calling `unwrap` on
    /// [`SourceRange::new`].
    pub const ORIGIN: Self = Self {
        start: SourcePosition {
            line: 1,
            column: 1,
            offset: 0,
        },
        end: SourcePosition {
            line: 1,
            column: 1,
            offset: 0,
        },
    };

    /// Creates a range.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::EndBeforeStart`] when the end offset precedes the
    /// start offset, and [`RangeError::ZeroLineOrColumn`] when a line or column is
    /// zero, because both are 1-based.
    pub fn new(start: SourcePosition, end: SourcePosition) -> Result<Self, RangeError> {
        for position in [start, end] {
            if position.line == 0 || position.column == 0 {
                return Err(RangeError::ZeroLineOrColumn);
            }
        }
        if end.offset < start.offset {
            return Err(RangeError::EndBeforeStart);
        }
        Ok(Self { start, end })
    }

    /// The start position.
    #[must_use]
    pub const fn start(&self) -> SourcePosition {
        self.start
    }

    /// The end position.
    #[must_use]
    pub const fn end(&self) -> SourcePosition {
        self.end
    }

    /// Length of the range in bytes.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.end.offset - self.start.offset
    }
}

/// Why a source range was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// The end offset preceded the start offset.
    EndBeforeStart,
    /// A line or column was zero, but both are 1-based.
    ZeroLineOrColumn,
}

impl fmt::Display for RangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndBeforeStart => {
                formatter.write_str("a source range must not end before it starts")
            }
            Self::ZeroLineOrColumn => {
                formatter.write_str("source lines and columns are 1-based, so zero is invalid")
            }
        }
    }
}

impl std::error::Error for RangeError {}

/// A confidence score between `0.0` and `1.0` inclusive.
///
/// The root PRD section 11.4 requires confidence scores to be finite and within
/// `0.0..=1.0`. This type holds one, so an out-of-range score is unrepresentable
/// rather than checked later.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Score(f32);

impl Score {
    /// Wraps a score.
    ///
    /// # Errors
    ///
    /// Returns [`ScoreError::NotFinite`] when the value is an infinity or a NaN,
    /// and [`ScoreError::OutOfRange`] when it falls outside `0.0..=1.0`.
    pub fn new(value: f32) -> Result<Self, ScoreError> {
        if !value.is_finite() {
            return Err(ScoreError::NotFinite);
        }
        if !(0.0..=1.0).contains(&value) {
            return Err(ScoreError::OutOfRange);
        }
        Ok(Self(if value == 0.0 { 0.0 } else { value }))
    }

    /// Wraps a compile-time constant that the author asserts is in range.
    ///
    /// This exists only so an infallible fallback can be written without `unwrap`, keeping the
    /// crate's no-panic guarantee — the same reason [`crate::text::NonEmptyText::literal`] exists,
    /// and it is crate-internal for the same reason: a caller cannot smuggle runtime data past
    /// validation. The debug assertion catches a bad constant during development.
    pub(crate) fn literal(value: f32) -> Self {
        debug_assert!(
            Self::new(value).is_ok(),
            "Score::literal was given a value outside 0.0..=1.0"
        );
        Self(value)
    }

    /// The wrapped score.
    #[must_use]
    pub const fn get(self) -> f32 {
        self.0
    }
}

impl fmt::Display for Score {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Why a confidence score was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScoreError {
    /// The value was an infinity or a NaN.
    NotFinite,
    /// The value fell outside `0.0..=1.0`.
    OutOfRange,
}

impl fmt::Display for ScoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinite => formatter.write_str("a confidence score must be finite"),
            Self::OutOfRange => {
                formatter.write_str("a confidence score must be within 0.0 through 1.0")
            }
        }
    }
}

impl std::error::Error for ScoreError {}

impl SourceRange {
    /// A range written `line:column:offset-line:column:offset`.
    ///
    /// The spelling `.nost` uses, held here so the language reader and the change-set reader share one rather
    /// than each carrying a copy. They did not: a change set dropped the range entirely, and a copy in the
    /// second reader would have been a second chance to spell it differently.
    ///
    /// # Errors
    ///
    /// Returns the text that could not be read, so a caller can name it in its own diagnostic.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let position = |part: &str| -> Option<SourcePosition> {
            let mut parts = part.split(':');
            let line = parts.next()?.parse().ok()?;
            let column = parts.next()?.parse().ok()?;
            let offset = parts.next()?.parse().ok()?;
            if parts.next().is_some() {
                return None;
            }
            Some(SourcePosition {
                line,
                column,
                offset,
            })
        };
        let (start, end) = text.split_once('-').ok_or_else(|| {
            format!("a range is written line:column:offset-line:column:offset, found {text}")
        })?;
        let start = position(start)
            .ok_or_else(|| format!("{start} is not a line:column:offset position"))?;
        let end =
            position(end).ok_or_else(|| format!("{end} is not a line:column:offset position"))?;
        Self::new(start, end).map_err(|error| format!("{text}: {error}"))
    }
}

impl Confidence {
    /// A confidence written `extracted`, `inferred(<score>)`, or `ambiguous(<score>)`.
    ///
    /// One spelling for both routes into a graph. A change set used to name a confidence and have it thrown
    /// away — every proposal was stored as [`Self::Extracted`], the value reserved for a fact read directly
    /// out of source — while the `.nost` reader honored the same three words. Two readers of one graph
    /// disagreed about what evidence meant.
    ///
    /// # Errors
    ///
    /// Returns the reason, so a caller can name the field it came from. A score outside `0.0..=1.0` is
    /// refused rather than clamped: a producer that computed 1.4 has a defect, and storing 1.0 would hide it.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let (word, score) = match text.split_once('(') {
            Some((word, rest)) => {
                let inner = rest
                    .strip_suffix(')')
                    .ok_or_else(|| format!("{text}: a score is closed with `)`"))?;
                let value: f32 = inner
                    .trim()
                    .parse()
                    .map_err(|_| format!("{inner} is not a score"))?;
                (
                    word.trim(),
                    Some(Score::new(value).map_err(|error| format!("{inner}: {error}"))?),
                )
            }
            None => (text.trim(), None),
        };
        Self::from_parts(word, score)
    }

    /// A confidence from the word and the score a reader already separated.
    ///
    /// The `.nost` parser hands those apart — a confidence is an enumerator with an optional score there —
    /// so this is where the rule lives that both readers need: which three words exist, and which of them
    /// carry a score.
    ///
    /// # Errors
    ///
    /// Returns the reason, so a caller can name the field or the source range it came from.
    pub fn from_parts(word: &str, score: Option<Score>) -> Result<Self, String> {
        match (word, score) {
            ("extracted", None) => Ok(Self::Extracted),
            ("extracted", Some(_)) => Err("`extracted` carries no score".to_owned()),
            ("inferred", Some(score)) => Ok(Self::Inferred { score }),
            ("ambiguous", Some(score)) => Ok(Self::Ambiguous { score }),
            ("inferred" | "ambiguous", None) => {
                Err(format!("`{word}` is written with a score, as {word}(0.8)"))
            }
            (other, _) => Err(format!("`{other}` is not a confidence")),
        }
    }
}

/// How confident a graph fact is.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Confidence {
    /// Read directly out of source. No score, because there is nothing to weigh.
    Extracted,
    /// Inferred, with a score.
    Inferred {
        /// How confident the inference is.
        score: Score,
    },
    /// Ambiguous between candidates, with a score.
    Ambiguous {
        /// How confident the chosen candidate is.
        score: Score,
    },
}

impl Confidence {
    /// The score, when this confidence carries one.
    ///
    /// [`Confidence::Extracted`] has no score.
    #[must_use]
    pub const fn score(&self) -> Option<Score> {
        match self {
            Self::Extracted => None,
            Self::Inferred { score } | Self::Ambiguous { score } => Some(*score),
        }
    }

    /// Reports whether this fact was read directly from source.
    ///
    /// A user interface must not present an inferred or ambiguous fact as though it
    /// carried the same weight as an extracted one.
    #[must_use]
    pub const fn is_deterministic(&self) -> bool {
        matches!(self, Self::Extracted)
    }
}

/// How a graph fact was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceMethod {
    /// Produced by a deterministic analyzer.
    Deterministic,
    /// Inferred by AI analysis.
    AiInferred,
    /// Declared by a user.
    UserDeclared,
}

/// A content digest, in `algorithm:hex` form.
///
/// The tagged form means a stored digest stays readable after a second algorithm
/// is introduced, instead of becoming an untagged hex string nobody can identify.
/// The permitted algorithm set is fixed when the container contract absorbs this
/// representation; until then any lower-case algorithm token is accepted.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Minimum number of hexadecimal digits, which is a 128-bit digest.
    pub const MIN_HEX_DIGITS: usize = 32;

    /// Validates and wraps a digest.
    ///
    /// # Errors
    ///
    /// Returns a [`DigestError`] when the value has no `algorithm:hex` separator,
    /// when the algorithm token is empty or not lower-case alphanumeric with
    /// hyphens, or when the hexadecimal part is not an even number of at least
    /// [`Self::MIN_HEX_DIGITS`] lower-case hexadecimal digits.
    pub fn new(value: impl Into<String>) -> Result<Self, DigestError> {
        let value = value.into();
        let (algorithm, hex) = value.split_once(':').ok_or(DigestError::MissingAlgorithm)?;
        if algorithm.is_empty()
            || !algorithm
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(DigestError::InvalidAlgorithm);
        }
        if hex.len() < Self::MIN_HEX_DIGITS || hex.len() % 2 != 0 {
            return Err(DigestError::InvalidHexLength { found: hex.len() });
        }
        if !hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        {
            return Err(DigestError::InvalidHexDigit);
        }
        Ok(Self(value))
    }

    /// Wraps a compile-time literal the author asserts is valid.
    ///
    /// This exists so an infallible fallback can be written without `unwrap`, keeping
    /// the crate's no-panic guarantee. It is crate-internal and takes a `&'static str`,
    /// so runtime data cannot bypass validation, and the debug assertion catches a bad
    /// literal during development.
    pub(crate) fn literal(value: &'static str) -> Self {
        debug_assert!(
            Self::new(value).is_ok(),
            "ContentDigest::literal was given an invalid literal"
        );
        Self(value.to_owned())
    }

    /// Borrows the whole `algorithm:hex` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The algorithm token.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        self.0
            .split_once(':')
            .map_or("", |(algorithm, _)| algorithm)
    }

    /// The hexadecimal digest.
    #[must_use]
    pub fn hex(&self) -> &str {
        self.0.split_once(':').map_or("", |(_, hex)| hex)
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why a content digest was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestError {
    /// The value had no `algorithm:hex` separator.
    MissingAlgorithm,
    /// The algorithm token was empty or contained an unexpected character.
    InvalidAlgorithm,
    /// The hexadecimal part was too short or had an odd length.
    InvalidHexLength {
        /// The number of characters found.
        found: usize,
    },
    /// The hexadecimal part contained a character that is not a lower-case
    /// hexadecimal digit.
    InvalidHexDigit,
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAlgorithm => {
                formatter.write_str("a digest must be written as algorithm:hex")
            }
            Self::InvalidAlgorithm => formatter
                .write_str("a digest algorithm must be lower-case alphanumeric with hyphens"),
            Self::InvalidHexLength { found } => write!(
                formatter,
                "a digest needs an even number of at least {} hexadecimal digits, found {found}",
                ContentDigest::MIN_HEX_DIGITS
            ),
            Self::InvalidHexDigit => {
                formatter.write_str("a digest must use lower-case hexadecimal digits")
            }
        }
    }
}

impl std::error::Error for DigestError {}

/// Provenance for one graph fact.
#[derive(Clone, Debug, PartialEq)]
pub struct Evidence {
    /// The source this fact came from.
    pub source: CanonicalSourceLocator,
    /// The immutable revision the source resolved to, when the provider has one.
    pub resolved_revision: Option<NonEmptyText>,
    /// The path within the source, when the fact came from a file.
    pub path: Option<NonEmptyText>,
    /// Digest of the content the fact was derived from.
    pub content_digest: ContentDigest,
    /// Where in the content the fact appears, when that is known.
    pub range: Option<SourceRange>,
    /// What produced the fact.
    pub producer: NonEmptyText,
    /// Version of what produced the fact.
    pub producer_version: NonEmptyText,
    /// How the fact was obtained.
    pub method: EvidenceMethod,
    /// How confident the fact is.
    pub confidence: Confidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(line: u32, column: u32, offset: u64) -> SourcePosition {
        SourcePosition {
            line,
            column,
            offset,
        }
    }

    #[test]
    fn a_range_must_not_end_before_it_starts() {
        assert_eq!(
            SourceRange::new(position(1, 5, 10), position(1, 2, 4)),
            Err(RangeError::EndBeforeStart)
        );
        let range = SourceRange::new(position(1, 1, 0), position(2, 3, 12)).unwrap();
        assert_eq!(range.byte_length(), 12);
    }

    #[test]
    fn lines_and_columns_are_one_based() {
        assert_eq!(
            SourceRange::new(position(0, 1, 0), position(1, 1, 0)),
            Err(RangeError::ZeroLineOrColumn)
        );
        assert_eq!(
            SourceRange::new(position(1, 0, 0), position(1, 1, 0)),
            Err(RangeError::ZeroLineOrColumn)
        );
    }

    #[test]
    fn an_empty_range_is_allowed() {
        let range = SourceRange::new(position(1, 1, 7), position(1, 1, 7)).unwrap();
        assert_eq!(range.byte_length(), 0);
    }

    #[test]
    fn a_score_outside_zero_through_one_cannot_be_constructed() {
        assert!(Score::new(0.0).is_ok());
        assert!(Score::new(1.0).is_ok());
        assert!(Score::new(0.5).is_ok());
        assert_eq!(Score::new(-0.1), Err(ScoreError::OutOfRange));
        assert_eq!(Score::new(1.1), Err(ScoreError::OutOfRange));
        assert_eq!(Score::new(f32::NAN), Err(ScoreError::NotFinite));
        assert_eq!(Score::new(f32::INFINITY), Err(ScoreError::NotFinite));
    }

    #[test]
    fn extracted_confidence_carries_no_score() {
        assert_eq!(Confidence::Extracted.score(), None);
        assert!(Confidence::Extracted.is_deterministic());

        let inferred = Confidence::Inferred {
            score: Score::new(0.8).unwrap(),
        };
        assert_eq!(inferred.score().map(Score::get), Some(0.8));
        assert!(!inferred.is_deterministic());

        let ambiguous = Confidence::Ambiguous {
            score: Score::new(0.4).unwrap(),
        };
        assert!(!ambiguous.is_deterministic());
    }

    #[test]
    fn accepts_a_tagged_digest_and_exposes_its_parts() {
        let digest = ContentDigest::new(
            "sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        )
        .unwrap();
        assert_eq!(digest.algorithm(), "sha256");
        assert_eq!(digest.hex().len(), 64);
    }

    #[test]
    fn rejects_untagged_short_odd_and_upper_case_digests() {
        assert_eq!(
            ContentDigest::new("abcdef0123456789abcdef0123456789"),
            Err(DigestError::MissingAlgorithm)
        );
        assert_eq!(
            ContentDigest::new(":abcdef0123456789abcdef0123456789"),
            Err(DigestError::InvalidAlgorithm)
        );
        assert_eq!(
            ContentDigest::new("SHA256:abcdef0123456789abcdef0123456789"),
            Err(DigestError::InvalidAlgorithm)
        );
        assert_eq!(
            ContentDigest::new("sha256:abcd"),
            Err(DigestError::InvalidHexLength { found: 4 })
        );
        assert_eq!(
            ContentDigest::new("sha256:abcdef0123456789abcdef0123456789a"),
            Err(DigestError::InvalidHexLength { found: 33 })
        );
        assert_eq!(
            ContentDigest::new("sha256:ABCDEF0123456789ABCDEF0123456789"),
            Err(DigestError::InvalidHexDigit)
        );
        assert_eq!(
            ContentDigest::new("sha256:ghijkl0123456789abcdef0123456789"),
            Err(DigestError::InvalidHexDigit)
        );
    }
}
