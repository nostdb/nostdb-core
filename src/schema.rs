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
use crate::property::{MAX_NESTING_DEPTH, PropertyValue};
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

/// A declared field type: a scalar, an anonymous object, or a list of either.
///
/// An object type is the fields a nested value declares. It is anonymous because a
/// named shape is a Schema, and a Schema's name is a label a record carries — which a
/// nested value is not.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldType {
    /// One scalar.
    Scalar(ScalarType),
    /// An object declaring these fields.
    Object(Vec<SchemaField>),
    /// A list whose every element has the inner type.
    Array(Box<FieldType>),
}

impl FieldType {
    /// A field holding one scalar.
    #[must_use]
    pub const fn scalar(scalar: ScalarType) -> Self {
        Self::Scalar(scalar)
    }

    /// A field holding an array of one scalar.
    #[must_use]
    pub fn array(scalar: ScalarType) -> Self {
        Self::Array(Box::new(Self::Scalar(scalar)))
    }

    /// A field holding a list of `inner`.
    #[must_use]
    pub fn list_of(inner: Self) -> Self {
        Self::Array(Box::new(inner))
    }

    /// Reports whether `value` has the *shape* this type declares.
    ///
    /// An object type accepts any object, and the entries inside it are reported by
    /// [`EffectiveSchema::violations`] instead. The split follows the two rules the
    /// language contract already states: a Schema is **open**, so an entry nothing
    /// declares is not an error, and validation is **soft**, so a missing required entry
    /// is a warning about a value rather than a claim the value is the wrong type.
    /// Folding both into one boolean would report a nested typo as "this is not an
    /// object", which it is.
    #[must_use]
    pub fn accepts(&self, value: &PropertyValue) -> bool {
        match (self, value) {
            (Self::Scalar(scalar), _) => scalar_of(value) == Some(*scalar),
            (Self::Array(inner), PropertyValue::List(items)) => {
                items.iter().all(|item| inner.accepts(item))
            }
            (Self::Object(_), PropertyValue::Map(_)) => true,
            _ => false,
        }
    }

    /// The nesting depth of this type: 0 for a scalar, and one more than its inner type
    /// for a list or an object.
    ///
    /// Iterative for the reason [`PropertyValue::depth`] is.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut deepest = 0;
        let mut pending = vec![(self, 0_usize)];
        while let Some((declared, depth)) = pending.pop() {
            deepest = deepest.max(depth);
            match declared {
                Self::Array(inner) => {
                    deepest = deepest.max(depth + 1);
                    pending.push((inner.as_ref(), depth + 1));
                }
                Self::Object(fields) => {
                    deepest = deepest.max(depth + 1);
                    pending.extend(fields.iter().map(|field| (&field.field_type, depth + 1)));
                }
                Self::Scalar(_) => {}
            }
        }
        deepest
    }

    /// Reports whether this type nests deeper than [`MAX_NESTING_DEPTH`].
    #[must_use]
    pub fn exceeds_nesting_limit(&self) -> bool {
        self.depth() > MAX_NESTING_DEPTH
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scalar(scalar) => formatter.write_str(scalar.as_str()),
            Self::Array(inner) => write!(formatter, "{inner}[]"),
            Self::Object(fields) => {
                if fields.is_empty() {
                    return formatter.write_str("{}");
                }
                formatter.write_str("{ ")?;
                for (index, field) in fields.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    formatter.write_str(field.key.as_str())?;
                    if !field.required {
                        formatter.write_str("?")?;
                    }
                    write!(formatter, ": {}", field.field_type)?;
                }
                formatter.write_str(" }")
            }
        }
    }
}

/// Reports every violation *inside* an object or a list of them, naming each by path.
///
/// Called only when [`FieldType::accepts`] already agreed on the shape, so the two
/// arms below are the whole of it: an object type beside an object, and a list type
/// beside a list.
///
/// Recursion is bounded by [`MAX_NESTING_DEPTH`], which the `.nost` parser and the
/// container decoder both enforce before a value reaches here. A value that has not
/// passed one of those two doors is not one this function is safe to walk.
fn nested_violations(
    declared: &FieldType,
    value: &PropertyValue,
    path: &str,
    found: &mut Vec<SchemaViolation>,
) {
    match (declared, value) {
        (FieldType::Object(fields), PropertyValue::Map(entries)) => {
            for field in fields {
                let child = format!("{path}.{}", field.key.as_str());
                // The first entry with this key wins. A repeated key is
                // NOST_DUPLICATE_PROPERTY_KEY, reported where duplicates are found
                // rather than as a schema violation here.
                match entries.iter().find(|(name, _)| *name == field.key) {
                    None => {
                        if field.required {
                            found.push(SchemaViolation::Nested {
                                path: child,
                                inner: Box::new(SchemaViolation::MissingField {
                                    key: field.key.clone(),
                                    declared: field.field_type.clone(),
                                }),
                            });
                        }
                    }
                    Some((_, held)) => {
                        if field.field_type.accepts(held) {
                            nested_violations(&field.field_type, held, &child, found);
                        } else {
                            found.push(SchemaViolation::Nested {
                                path: child,
                                inner: Box::new(SchemaViolation::WrongType {
                                    key: field.key.clone(),
                                    declared: field.field_type.clone(),
                                }),
                            });
                        }
                    }
                }
            }
        }
        (FieldType::Array(inner), PropertyValue::List(items)) => {
            for (index, item) in items.iter().enumerate() {
                nested_violations(inner, item, &format!("{path}[{index}]"), found);
            }
        }
        _ => {}
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
        PropertyValue::List(_) | PropertyValue::Map(_) => return None,
    })
}

/// One field a Schema declares.
///
/// Ordered and hashable because [`FieldType::Object`] holds these, and `FieldType` is
/// compared and hashed wherever a declared type is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// A violation inside an object value.
    Nested {
        /// The path from the record to the offending entry, such as
        /// `dependencies[0].name`.
        ///
        /// A rendered string rather than a typed path, because the only consumer is a
        /// diagnostic message and a typed path would be a second spelling of one that
        /// already exists in the value being walked.
        path: String,
        /// The violation at that path.
        inner: Box<SchemaViolation>,
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
            Self::Nested { path, inner } => write!(formatter, "at {path}, {inner}"),
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
                        combined.fields.insert(
                            field.key.clone(),
                            (field.field_type.clone(), field.required),
                        );
                    }
                    Some((existing, required)) => {
                        if *existing != field.field_type {
                            combined.conflicts.push(SchemaViolation::ConflictingField {
                                key: field.key.clone(),
                                first: existing.clone(),
                                second: field.field_type.clone(),
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
                            declared: declared.clone(),
                        });
                    }
                }
                Some((_, value)) => {
                    if declared.accepts(value) {
                        nested_violations(declared, value, key.as_str(), &mut found);
                    } else {
                        found.push(SchemaViolation::WrongType {
                            key: key.clone(),
                            declared: declared.clone(),
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
                    field_type: field_type.clone(),
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
        let declared = FieldType::array(ScalarType::String);
        assert!(declared.accepts(&PropertyValue::List(Vec::new())));
        assert!(
            declared.accepts(&PropertyValue::List(vec![PropertyValue::String(
                "a".to_owned()
            )]))
        );
        assert!(!declared.accepts(&PropertyValue::List(vec![PropertyValue::Integer(1)])));
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
