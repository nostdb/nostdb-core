//! Property values.
//!
//! # There is no null
//!
//! A stored property null is unrepresentable, which is the rule in the root PRD
//! section 11.1 and in the `.nost` language contract. [`PropertyValue`] therefore
//! has no null variant. In a query, `null` means missing or non-applicable, and
//! assigning `null` removes a property; a property that should not exist is simply
//! absent from a record.
//!
//! # A list holds scalars
//!
//! [`PropertyValue::List`] holds [`PropertyScalar`], not [`PropertyValue`], so
//! lists cannot nest. That is enforced by the types rather than checked.

use crate::text::NonEmptyText;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A finite double-precision number.
///
/// A non-finite value is unrepresentable: an infinity or a NaN cannot be
/// constructed. Rejecting them at the boundary matters because the container
/// stores fixed-width bytes, and a NaN has many bit patterns that would compare
/// unequal to themselves.
///
/// Negative zero is normalized to positive zero on construction, which keeps
/// equality and hashing consistent.
#[derive(Clone, Copy, Debug)]
pub struct FiniteF64(f64);

impl FiniteF64 {
    /// Wraps a finite number.
    ///
    /// # Errors
    ///
    /// Returns [`NumberError::NotFinite`] when the value is an infinity or a NaN.
    pub fn new(value: f64) -> Result<Self, NumberError> {
        if !value.is_finite() {
            return Err(NumberError::NotFinite);
        }
        // Normalize -0.0 so that equal values hash equally.
        Ok(Self(if value == 0.0 { 0.0 } else { value }))
    }

    /// The wrapped number, which is always finite.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl PartialEq for FiniteF64 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FiniteF64 {}

impl PartialOrd for FiniteF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FiniteF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Total order is well defined here: there is no NaN, and negative zero was
        // normalized away on construction.
        self.0.total_cmp(&other.0)
    }
}

impl Hash for FiniteF64 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl fmt::Display for FiniteF64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Why a number was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberError {
    /// The value was an infinity or a NaN.
    NotFinite,
}

impl fmt::Display for NumberError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinite => formatter.write_str("a number property must be finite"),
        }
    }
}

impl std::error::Error for NumberError {}

/// An RFC 3339 timestamp.
///
/// The `.nost` language contract requires a datetime literal to be a valid RFC
/// 3339 timestamp. This type holds one, so an invalid timestamp cannot reach a
/// record.
///
/// The stored form is the text as supplied. It is not normalized to UTC, because
/// the offset a source declared is itself information.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DateTime(String);

impl DateTime {
    /// Validates and wraps an RFC 3339 timestamp.
    ///
    /// Accepts a lower-case `t` date-time separator and a lower-case `z` offset, as
    /// RFC 3339 permits. A second value of 60 is accepted, because RFC 3339 allows
    /// a leap second.
    ///
    /// # Errors
    ///
    /// Returns a [`DateTimeError`] describing which part of the timestamp was
    /// malformed or out of range.
    pub fn new(value: impl Into<String>) -> Result<Self, DateTimeError> {
        let value = value.into();
        validate_rfc3339(&value)?;
        Ok(Self(value))
    }

    /// Borrows the timestamp text.
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

impl fmt::Display for DateTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why a timestamp was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateTimeError {
    /// The value was not ASCII, so it cannot be an RFC 3339 timestamp.
    NotAscii,
    /// The value did not match the RFC 3339 date-time shape.
    Malformed,
    /// A component fell outside its permitted range.
    OutOfRange {
        /// Which component was out of range.
        component: DateTimeComponent,
        /// The value found.
        value: u32,
    },
}

/// A component of an RFC 3339 timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateTimeComponent {
    /// The month, which must be 1 through 12.
    Month,
    /// The day, which must be valid for the month and year.
    Day,
    /// The hour, which must be 0 through 23.
    Hour,
    /// The minute, which must be 0 through 59.
    Minute,
    /// The second, which must be 0 through 60 to permit a leap second.
    Second,
    /// The offset hour, which must be 0 through 23.
    OffsetHour,
    /// The offset minute, which must be 0 through 59.
    OffsetMinute,
}

impl fmt::Display for DateTimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAscii => formatter.write_str("an RFC 3339 timestamp must be ASCII"),
            Self::Malformed => {
                formatter.write_str("the value does not match the RFC 3339 date-time shape")
            }
            Self::OutOfRange { component, value } => {
                write!(formatter, "{component:?} is out of range: {value}")
            }
        }
    }
}

impl std::error::Error for DateTimeError {}

fn two_digits(bytes: &[u8], at: usize) -> Option<u32> {
    let high = bytes.get(at)?;
    let low = bytes.get(at + 1)?;
    if !high.is_ascii_digit() || !low.is_ascii_digit() {
        return None;
    }
    Some(u32::from(high - b'0') * 10 + u32::from(low - b'0'))
}

fn four_digits(bytes: &[u8], at: usize) -> Option<u32> {
    let high = two_digits(bytes, at)?;
    let low = two_digits(bytes, at + 2)?;
    Some(high * 100 + low)
}

fn expect_byte(bytes: &[u8], at: usize, options: &[u8]) -> Option<()> {
    let found = bytes.get(at)?;
    if options.contains(found) {
        Some(())
    } else {
        None
    }
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn validate_rfc3339(value: &str) -> Result<(), DateTimeError> {
    if !value.is_ascii() {
        return Err(DateTimeError::NotAscii);
    }
    let bytes = value.as_bytes();

    let year = four_digits(bytes, 0).ok_or(DateTimeError::Malformed)?;
    expect_byte(bytes, 4, b"-").ok_or(DateTimeError::Malformed)?;
    let month = two_digits(bytes, 5).ok_or(DateTimeError::Malformed)?;
    expect_byte(bytes, 7, b"-").ok_or(DateTimeError::Malformed)?;
    let day = two_digits(bytes, 8).ok_or(DateTimeError::Malformed)?;
    expect_byte(bytes, 10, b"Tt").ok_or(DateTimeError::Malformed)?;
    let hour = two_digits(bytes, 11).ok_or(DateTimeError::Malformed)?;
    expect_byte(bytes, 13, b":").ok_or(DateTimeError::Malformed)?;
    let minute = two_digits(bytes, 14).ok_or(DateTimeError::Malformed)?;
    expect_byte(bytes, 16, b":").ok_or(DateTimeError::Malformed)?;
    let second = two_digits(bytes, 17).ok_or(DateTimeError::Malformed)?;

    let mut cursor = 19;
    if expect_byte(bytes, cursor, b".").is_some() {
        cursor += 1;
        let mut digits = 0;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
            digits += 1;
        }
        if digits == 0 {
            return Err(DateTimeError::Malformed);
        }
    }

    let (offset_hour, offset_minute) = match bytes.get(cursor) {
        Some(b'Z' | b'z') => {
            cursor += 1;
            (0, 0)
        }
        Some(b'+' | b'-') => {
            let hour = two_digits(bytes, cursor + 1).ok_or(DateTimeError::Malformed)?;
            expect_byte(bytes, cursor + 3, b":").ok_or(DateTimeError::Malformed)?;
            let minute = two_digits(bytes, cursor + 4).ok_or(DateTimeError::Malformed)?;
            cursor += 6;
            (hour, minute)
        }
        _ => return Err(DateTimeError::Malformed),
    };

    if cursor != bytes.len() {
        return Err(DateTimeError::Malformed);
    }

    let out_of_range = |component, value| Err(DateTimeError::OutOfRange { component, value });
    if !(1..=12).contains(&month) {
        return out_of_range(DateTimeComponent::Month, month);
    }
    if day < 1 || day > days_in_month(year, month) {
        return out_of_range(DateTimeComponent::Day, day);
    }
    if hour > 23 {
        return out_of_range(DateTimeComponent::Hour, hour);
    }
    if minute > 59 {
        return out_of_range(DateTimeComponent::Minute, minute);
    }
    if second > 60 {
        return out_of_range(DateTimeComponent::Second, second);
    }
    if offset_hour > 23 {
        return out_of_range(DateTimeComponent::OffsetHour, offset_hour);
    }
    if offset_minute > 59 {
        return out_of_range(DateTimeComponent::OffsetMinute, offset_minute);
    }
    Ok(())
}

/// A scalar property value.
///
/// A list holds scalars, so this type is what a list element may be.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PropertyScalar {
    /// A boolean.
    Boolean(bool),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A finite double-precision number.
    Float(FiniteF64),
    /// A UTF-8 string.
    String(String),
    /// An opaque byte string.
    Bytes(Vec<u8>),
    /// An RFC 3339 timestamp.
    DateTime(DateTime),
}

/// A property value.
///
/// There is deliberately no null variant. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PropertyValue {
    /// A boolean.
    Boolean(bool),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A finite double-precision number.
    Float(FiniteF64),
    /// A UTF-8 string.
    String(String),
    /// An opaque byte string.
    Bytes(Vec<u8>),
    /// An RFC 3339 timestamp.
    DateTime(DateTime),
    /// An ordered list of scalars, which does not nest.
    List(Vec<PropertyScalar>),
}

impl PropertyValue {
    /// Reports whether this value is a list.
    #[must_use]
    pub const fn is_list(&self) -> bool {
        matches!(self, Self::List(_))
    }

    /// The name of this value's type, for diagnostics.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Boolean(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Bytes(_) => "bytes",
            Self::DateTime(_) => "datetime",
            Self::List(_) => "list",
        }
    }
}

impl From<PropertyScalar> for PropertyValue {
    fn from(scalar: PropertyScalar) -> Self {
        match scalar {
            PropertyScalar::Boolean(value) => Self::Boolean(value),
            PropertyScalar::Integer(value) => Self::Integer(value),
            PropertyScalar::Float(value) => Self::Float(value),
            PropertyScalar::String(value) => Self::String(value),
            PropertyScalar::Bytes(value) => Self::Bytes(value),
            PropertyScalar::DateTime(value) => Self::DateTime(value),
        }
    }
}

impl From<bool> for PropertyValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<i64> for PropertyValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<String> for PropertyValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for PropertyValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<NonEmptyText> for PropertyValue {
    fn from(value: NonEmptyText) -> Self {
        Self::String(value.into_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_finite_float_cannot_be_constructed() {
        assert_eq!(FiniteF64::new(f64::NAN), Err(NumberError::NotFinite));
        assert_eq!(FiniteF64::new(f64::INFINITY), Err(NumberError::NotFinite));
        assert_eq!(
            FiniteF64::new(f64::NEG_INFINITY),
            Err(NumberError::NotFinite)
        );
        assert!(FiniteF64::new(0.0).is_ok());
        assert!(FiniteF64::new(f64::MAX).is_ok());
    }

    #[test]
    fn negative_zero_is_normalized_so_equality_and_hashing_agree() {
        use std::collections::HashSet;
        let positive = FiniteF64::new(0.0).unwrap();
        let negative = FiniteF64::new(-0.0).unwrap();
        assert_eq!(positive, negative);
        let mut set = HashSet::new();
        set.insert(positive);
        assert!(set.contains(&negative));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn accepts_valid_timestamps() {
        for candidate in [
            "2026-07-26T09:00:00Z",
            "2026-07-26t09:00:00z",
            "2026-07-26T09:00:00.123456Z",
            "2026-07-26T09:00:00+09:00",
            "2026-07-26T09:00:00-05:30",
            "2024-02-29T00:00:00Z",
            "2026-12-31T23:59:60Z",
        ] {
            assert!(DateTime::new(candidate).is_ok(), "{candidate}");
        }
    }

    #[test]
    fn rejects_malformed_timestamps() {
        for candidate in [
            "26/07/2026 09:00",
            "2026-07-26",
            "2026-07-26T09:00:00",
            "2026-07-26 09:00:00Z",
            "2026-07-26T09:00:00.Z",
            "2026-07-26T09:00:00+0900",
            "2026-07-26T09:00:00Zextra",
            "",
        ] {
            assert_eq!(
                DateTime::new(candidate),
                Err(DateTimeError::Malformed),
                "{candidate}"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_components_including_a_non_leap_february() {
        assert_eq!(
            DateTime::new("2026-13-01T00:00:00Z"),
            Err(DateTimeError::OutOfRange {
                component: DateTimeComponent::Month,
                value: 13
            })
        );
        assert_eq!(
            DateTime::new("2026-02-29T00:00:00Z"),
            Err(DateTimeError::OutOfRange {
                component: DateTimeComponent::Day,
                value: 29
            })
        );
        assert_eq!(
            DateTime::new("1900-02-29T00:00:00Z"),
            Err(DateTimeError::OutOfRange {
                component: DateTimeComponent::Day,
                value: 29
            })
        );
        assert!(DateTime::new("2000-02-29T00:00:00Z").is_ok());
        assert_eq!(
            DateTime::new("2026-07-26T24:00:00Z"),
            Err(DateTimeError::OutOfRange {
                component: DateTimeComponent::Hour,
                value: 24
            })
        );
        assert_eq!(
            DateTime::new("2026-07-26T09:00:61Z"),
            Err(DateTimeError::OutOfRange {
                component: DateTimeComponent::Second,
                value: 61
            })
        );
        assert_eq!(
            DateTime::new("2026-07-26T09:00:00+24:00"),
            Err(DateTimeError::OutOfRange {
                component: DateTimeComponent::OffsetHour,
                value: 24
            })
        );
    }

    #[test]
    fn rejects_non_ascii() {
        assert_eq!(
            DateTime::new("２026-07-26T09:00:00Z"),
            Err(DateTimeError::NotAscii)
        );
    }

    #[test]
    fn a_list_holds_scalars_and_therefore_cannot_nest() {
        let list = PropertyValue::List(vec![
            PropertyScalar::Integer(1),
            PropertyScalar::String("two".to_owned()),
            PropertyScalar::Float(FiniteF64::new(2.5).unwrap()),
        ]);
        assert!(list.is_list());
        assert_eq!(list.type_name(), "list");
    }

    #[test]
    fn a_scalar_converts_into_a_value() {
        assert_eq!(
            PropertyValue::from(PropertyScalar::Boolean(true)),
            PropertyValue::Boolean(true)
        );
        assert_eq!(PropertyValue::from(7_i64), PropertyValue::Integer(7));
        assert_eq!(
            PropertyValue::from("text"),
            PropertyValue::String("text".to_owned())
        );
    }
}
