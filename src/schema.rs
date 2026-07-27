//! Schemas: the typed shape a record carrying a given label is expected to have.
//!
//! A Schema declares field keys with types, marks each required or optional, and may
//! constrain the endpoints of an Edge. Its name is the label its records carry, so a
//! query matches on it with no additional syntax and a Node's at-least-one-label rule is
//! satisfied without a special case.
//!
//! # Validation is soft, and a Schema is open
//!
//! Root PRD section 11.6 permits soft Schema validation and reserves hard rejection for
//! explicit Constraints. [`Schema::violations`] therefore *reports* rather than refuses,
//! and a record carrying a property no Schema declares is not a violation at all: an
//! analyzer routinely attaches properties a hand-written Schema did not anticipate, and
//! treating those as violations would fill a build with warnings that say nothing.

use crate::name::{Label, PropertyKey};
use crate::property::PropertyValue;
use std::collections::BTreeMap;
use std::fmt;

/// A scalar a Schema field may declare.
///
/// There is exactly one spelling per model type, so a canonical writer never has to
/// choose between two names for one thing. `double` rather than `float`, because the
/// value is an IEEE 754 binary64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScalarType {
    /// `boolean`
    Boolean,
    /// `integer`
    Integer,
    /// `double`
    Double,
    /// `string`
    String,
    /// `bytes`
    Bytes,
    /// `datetime`
    DateTime,
}

impl ScalarType {
    /// Every scalar type, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Boolean,
        Self::Integer,
        Self::Double,
        Self::String,
        Self::Bytes,
        Self::DateTime,
    ];

    /// Reads a scalar type from its declared spelling.
    #[must_use]
    pub fn from_text(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// The declared spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Double => "double",
            Self::String => "string",
            Self::Bytes => "bytes",
            Self::DateTime => "datetime",
        }
    }

    /// The stored discriminant.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::Boolean => 1,
            Self::Integer => 2,
            Self::Double => 3,
            Self::String => 4,
            Self::Bytes => 5,
            Self::DateTime => 6,
        }
    }

    /// Reads a scalar type from its stored discriminant.
    #[must_use]
    pub const fn from_raw(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::Boolean,
            2 => Self::Integer,
            3 => Self::Double,
            4 => Self::String,
            5 => Self::Bytes,
            6 => Self::DateTime,
            _ => return None,
        })
    }
}

impl fmt::Display for ScalarType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A declared field type: a scalar, or an array of that scalar.
///
/// Arrays do not nest, because a stored list holds scalars only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldType {
    /// The scalar the field holds.
    pub scalar: ScalarType,
    /// Whether the field holds an array of that scalar rather than one value.
    pub array: bool,
}

impl FieldType {
    /// A field holding one scalar.
    #[must_use]
    pub const fn scalar(scalar: ScalarType) -> Self {
        Self {
            scalar,
            array: false,
        }
    }

    /// A field holding an array of one scalar.
    #[must_use]
    pub const fn array(scalar: ScalarType) -> Self {
        Self {
            scalar,
            array: true,
        }
    }

    /// Reports whether `value` satisfies this declared type.
    #[must_use]
    pub fn accepts(self, value: &PropertyValue) -> bool {
        if self.array {
            return match value {
                PropertyValue::List(items) => items
                    .iter()
                    .all(|item| self.scalar == scalar_of_scalar(item)),
                _ => false,
            };
        }
        scalar_of(value) == Some(self.scalar)
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.scalar.as_str())?;
        if self.array {
            formatter.write_str("[]")?;
        }
        Ok(())
    }
}

fn scalar_of(value: &PropertyValue) -> Option<ScalarType> {
    Some(match value {
        PropertyValue::Boolean(_) => ScalarType::Boolean,
        PropertyValue::Integer(_) => ScalarType::Integer,
        PropertyValue::Float(_) => ScalarType::Double,
        PropertyValue::String(_) => ScalarType::String,
        PropertyValue::Bytes(_) => ScalarType::Bytes,
        PropertyValue::DateTime(_) => ScalarType::DateTime,
        PropertyValue::List(_) => return None,
    })
}

fn scalar_of_scalar(value: &crate::property::PropertyScalar) -> ScalarType {
    use crate::property::PropertyScalar;
    match value {
        PropertyScalar::Boolean(_) => ScalarType::Boolean,
        PropertyScalar::Integer(_) => ScalarType::Integer,
        PropertyScalar::Float(_) => ScalarType::Double,
        PropertyScalar::String(_) => ScalarType::String,
        PropertyScalar::Bytes(_) => ScalarType::Bytes,
        PropertyScalar::DateTime(_) => ScalarType::DateTime,
    }
}

/// One field a Schema declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaField {
    /// The field key.
    pub key: PropertyKey,
    /// The declared type.
    pub field_type: FieldType,
    /// Whether a record must carry it.
    pub required: bool,
}

/// The Schemas an Edge's endpoints must carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointConstraint {
    /// The Schema the source record must carry.
    pub source: Label,
    /// The Schema the target record must carry.
    pub target: Label,
}

/// A Schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    /// The Schema name, which is also the label its records carry.
    pub name: Label,
    /// The endpoint constraint, when this Schema describes an Edge.
    ///
    /// Declaring one makes the Schema edge-only. A Schema without one may describe a
    /// Node or an Edge, and its use decides which.
    pub endpoints: Option<EndpointConstraint>,
    /// Fields, in a caller-defined order. A key must not repeat.
    pub fields: Vec<SchemaField>,
}

/// A way a record fails the Schemas it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaViolation {
    /// A required field is absent.
    MissingField {
        /// The absent key.
        key: PropertyKey,
        /// The type it was declared with.
        declared: FieldType,
    },
    /// A field holds a value of the wrong type.
    WrongType {
        /// The key.
        key: PropertyKey,
        /// The declared type.
        declared: FieldType,
    },
    /// Two Schemas this record names declare one key with different types.
    ConflictingField {
        /// The key both declare.
        key: PropertyKey,
        /// The type the first declares.
        first: FieldType,
        /// The type the second declares.
        second: FieldType,
    },
}

impl fmt::Display for SchemaViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { key, declared } => write!(
                formatter,
                "the required field {} of type {declared} is missing",
                key.as_str()
            ),
            Self::WrongType { key, declared } => write!(
                formatter,
                "the field {} is declared {declared} but holds a value of another type",
                key.as_str()
            ),
            Self::ConflictingField { key, first, second } => write!(
                formatter,
                "the field {} is declared as {first} and as {second} by two schemas this \
                 record names",
                key.as_str()
            ),
        }
    }
}

/// The fields a set of named Schemas jointly requires of one record.
///
/// Where two Schemas declare one key, the declared types must agree, and a key required
/// in either is required. Taking the stricter reading is the only rule that cannot
/// silently weaken a declaration its author wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveSchema {
    fields: BTreeMap<PropertyKey, (FieldType, bool)>,
    conflicts: Vec<SchemaViolation>,
}

impl EffectiveSchema {
    /// Combines every declared Schema among `named`.
    ///
    /// A name matching no Schema is skipped, because a record may carry a label no
    /// Schema declares. The language contract records that this makes a misspelled
    /// Schema name indistinguishable from an intentional bare label.
    #[must_use]
    pub fn combine<'a>(schemas: &'a [Schema], named: impl IntoIterator<Item = &'a Label>) -> Self {
        let mut combined = Self::default();
        for name in named {
            let Some(schema) = schemas.iter().find(|schema| schema.name == *name) else {
                continue;
            };
            for field in &schema.fields {
                match combined.fields.get_mut(&field.key) {
                    None => {
                        combined
                            .fields
                            .insert(field.key.clone(), (field.field_type, field.required));
                    }
                    Some((existing, required)) => {
                        if *existing != field.field_type {
                            combined.conflicts.push(SchemaViolation::ConflictingField {
                                key: field.key.clone(),
                                first: *existing,
                                second: field.field_type,
                            });
                        }
                        *required = *required || field.required;
                    }
                }
            }
        }
        combined
    }

    /// Reports whether any Schema was matched at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.conflicts.is_empty()
    }

    /// Reports every way `properties` fails this combined Schema.
    ///
    /// A property no Schema declares is not reported: a Schema is open.
    #[must_use]
    pub fn violations(&self, properties: &[(PropertyKey, PropertyValue)]) -> Vec<SchemaViolation> {
        let mut found = self.conflicts.clone();
        for (key, (declared, required)) in &self.fields {
            match properties.iter().find(|(name, _)| name == key) {
                None => {
                    if *required {
                        found.push(SchemaViolation::MissingField {
                            key: key.clone(),
                            declared: *declared,
                        });
                    }
                }
                Some((_, value)) => {
                    if !declared.accepts(value) {
                        found.push(SchemaViolation::WrongType {
                            key: key.clone(),
                            declared: *declared,
                        });
                    }
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::FiniteF64;

    fn key(text: &str) -> PropertyKey {
        PropertyKey::new(text).unwrap()
    }

    fn label(text: &str) -> Label {
        Label::new(text).unwrap()
    }

    fn schema(name: &str, fields: &[(&str, FieldType, bool)]) -> Schema {
        Schema {
            name: label(name),
            endpoints: None,
            fields: fields
                .iter()
                .map(|(text, field_type, required)| SchemaField {
                    key: key(text),
                    field_type: *field_type,
                    required: *required,
                })
                .collect(),
        }
    }

    #[test]
    fn a_scalar_type_round_trips_through_text_and_its_discriminant() {
        for kind in ScalarType::ALL {
            assert_eq!(ScalarType::from_text(kind.as_str()), Some(kind));
            assert_eq!(ScalarType::from_raw(kind.raw()), Some(kind));
        }
        assert_eq!(ScalarType::from_text("float"), None);
        assert_eq!(ScalarType::from_raw(0), None);
        assert_eq!(ScalarType::from_raw(7), None);
    }

    #[test]
    fn a_field_type_renders_the_way_the_contract_writes_it() {
        assert_eq!(FieldType::scalar(ScalarType::String).to_string(), "string");
        assert_eq!(FieldType::array(ScalarType::Double).to_string(), "double[]");
    }

    #[test]
    fn a_scalar_field_accepts_only_its_own_kind() {
        let declared = FieldType::scalar(ScalarType::Integer);
        assert!(declared.accepts(&PropertyValue::Integer(1)));
        assert!(!declared.accepts(&PropertyValue::String("1".to_owned())));
        assert!(!declared.accepts(&PropertyValue::List(Vec::new())));
    }

    #[test]
    fn an_array_field_checks_every_element_and_accepts_an_empty_list() {
        use crate::property::PropertyScalar;
        let declared = FieldType::array(ScalarType::String);
        assert!(declared.accepts(&PropertyValue::List(Vec::new())));
        assert!(
            declared.accepts(&PropertyValue::List(vec![PropertyScalar::String(
                "a".to_owned()
            )]))
        );
        assert!(!declared.accepts(&PropertyValue::List(vec![PropertyScalar::Integer(1)])));
        assert!(!declared.accepts(&PropertyValue::String("a".to_owned())));
    }

    #[test]
    fn a_double_field_accepts_a_float_and_not_an_integer() {
        // The two are distinct in the model, so a schema must not blur them.
        let declared = FieldType::scalar(ScalarType::Double);
        assert!(declared.accepts(&PropertyValue::Float(FiniteF64::new(1.5).unwrap())));
        assert!(!declared.accepts(&PropertyValue::Integer(1)));
    }

    #[test]
    fn a_missing_required_field_is_reported_and_an_optional_one_is_not() {
        let schemas = [schema(
            "S",
            &[
                ("required", FieldType::scalar(ScalarType::String), true),
                ("optional", FieldType::scalar(ScalarType::String), false),
            ],
        )];
        let effective = EffectiveSchema::combine(&schemas, [&label("S")]);
        let found = effective.violations(&[]);
        assert_eq!(
            found,
            vec![SchemaViolation::MissingField {
                key: key("required"),
                declared: FieldType::scalar(ScalarType::String),
            }]
        );
    }

    #[test]
    fn a_schema_is_open() {
        let schemas = [schema("S", &[])];
        let effective = EffectiveSchema::combine(&schemas, [&label("S")]);
        assert!(
            effective
                .violations(&[(key("undeclared"), PropertyValue::Integer(1))])
                .is_empty()
        );
    }

    #[test]
    fn an_undeclared_schema_name_matches_nothing() {
        let effective = EffectiveSchema::combine(&[], [&label("Absent")]);
        assert!(effective.is_empty());
        assert!(effective.violations(&[]).is_empty());
    }

    #[test]
    fn two_schemas_disagreeing_on_a_type_conflict_and_the_stricter_requirement_wins() {
        let schemas = [
            schema("A", &[("k", FieldType::scalar(ScalarType::String), true)]),
            schema("B", &[("k", FieldType::scalar(ScalarType::Integer), false)]),
        ];
        let effective = EffectiveSchema::combine(&schemas, [&label("A"), &label("B")]);
        let found = effective.violations(&[]);
        assert!(found.contains(&SchemaViolation::ConflictingField {
            key: key("k"),
            first: FieldType::scalar(ScalarType::String),
            second: FieldType::scalar(ScalarType::Integer),
        }));
        // Required in A and optional in B means required.
        assert!(found.iter().any(|violation| matches!(
            violation,
            SchemaViolation::MissingField { key: found, .. } if *found == key("k")
        )));
    }

    #[test]
    fn combining_is_order_independent_for_requiredness() {
        let strict = schema("A", &[("k", FieldType::scalar(ScalarType::String), true)]);
        let loose = schema("B", &[("k", FieldType::scalar(ScalarType::String), false)]);
        for order in [
            vec![strict.clone(), loose.clone()],
            vec![loose.clone(), strict.clone()],
        ] {
            let effective = EffectiveSchema::combine(&order, [&label("A"), &label("B")]);
            assert_eq!(
                effective.violations(&[]),
                vec![SchemaViolation::MissingField {
                    key: key("k"),
                    declared: FieldType::scalar(ScalarType::String),
                }]
            );
        }
    }
}
