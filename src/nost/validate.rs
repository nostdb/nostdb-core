//! Semantic validation for a parsed `.nost` file.
//!
//! These are the rules the grammar cannot express. Each produces the stable diagnostic
//! code the language contract assigns, with a source range, and every problem is
//! reported rather than only the first.
//!
//! Two of them are warnings rather than errors. An unresolved endpoint leaves the Engine
//! creating a Placeholder Node and continuing, and a schema violation is soft by
//! contract; an explicit Constraint is what rejects a transaction.

use super::{
    ContributionBlock, EdgeDeclaration, Endpoint, EvidenceBlock, EvidenceValue, FieldType,
    LANGUAGE_VERSION, NodeDeclaration, OwnerDeclaration, Property, RecordBody, ScalarType,
    SchemaDeclaration, SourceFile, Spanned, Value,
};
use crate::diagnostic::{Diagnostic, DiagnosticCode, Severity};
use crate::evidence::SourceRange;
use crate::id::{LocalEdgeId, LocalNodeId, SourceUnitId};
use crate::property::DateTime;
use crate::text::NonEmptyText;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

/// Language versions this build understands.
///
/// Version 1 is absent deliberately. It required a module declaration version 2 has no
/// production for, so accepting it would promise a parse this build cannot deliver.
pub const SUPPORTED_LANGUAGE_VERSIONS: [u32; 1] = [LANGUAGE_VERSION];

/// Property key whose value is a confidence score constrained to `0.0..=1.0`.
pub const CONFIDENCE_SCORE_KEY: &str = "confidence_score";

/// Reserved property key holding the opaque record identifier.
pub const ID_KEY: &str = "id";

/// Reserved property key holding labels beyond the record's schema names.
pub const LABELS_KEY: &str = "labels";

/// Evidence keys an implementation must accept, and whether each is required.
const EVIDENCE_KEYS: [(&str, bool); 9] = [
    ("source", true),
    ("digest", true),
    ("method", true),
    ("confidence", true),
    ("revision", false),
    ("path", false),
    ("range", false),
    ("producer", false),
    ("producer_version", false),
];

/// Values the `method` key accepts.
const METHODS: [&str; 3] = ["deterministic", "ai_inferred", "user_declared"];

fn diagnostic(code: DiagnosticCode, range: SourceRange, message: String) -> Diagnostic {
    Diagnostic {
        code,
        severity: code.default_severity(),
        message: NonEmptyText::new(message)
            .unwrap_or_else(|_| NonEmptyText::literal("a semantic rule was broken")),
        source: None,
        range: Some(range),
        details: Vec::new(),
    }
}

/// Reports every semantic rule the file breaks.
///
/// An empty result means the file satisfies every rule decidable without opening the
/// linked sources it declares.
#[must_use]
pub fn validate(file: &SourceFile) -> Vec<Diagnostic> {
    let mut found = Vec::new();

    if !SUPPORTED_LANGUAGE_VERSIONS.contains(&file.version.value) {
        found.push(diagnostic(
            DiagnosticCode::NostVersionUnsupported,
            file.version.range,
            format!(
                "language version {} is not supported; this build supports {:?}",
                file.version.value, SUPPORTED_LANGUAGE_VERSIONS
            ),
        ));
    }

    check_links(file, &mut found);
    check_schemas(file, &mut found);
    check_declarations(file, &mut found);
    check_endpoints(file, &mut found);
    check_contributions(file, &mut found);

    found
}

fn check_links(file: &SourceFile, found: &mut Vec<Diagnostic>) {
    let mut sources: BTreeSet<&str> = BTreeSet::new();
    let mut aliases: BTreeSet<&str> = BTreeSet::new();
    for link in &file.links {
        if !sources.insert(link.source.value.as_str()) {
            found.push(diagnostic(
                DiagnosticCode::NostDuplicateLinkSource,
                link.source.range,
                format!("the link {} is declared more than once", link.source.value),
            ));
        }
        if let Some(alias) = &link.alias
            && !aliases.insert(alias.value.as_str())
        {
            found.push(diagnostic(
                DiagnosticCode::NostDuplicateLinkAlias,
                alias.range,
                format!("the link alias {} is claimed more than once", alias.value),
            ));
        }
    }
}

fn check_schemas(file: &SourceFile, found: &mut Vec<Diagnostic>) {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for schema in &file.schemas {
        if !names.insert(schema.name.value.as_str()) {
            found.push(diagnostic(
                DiagnosticCode::NostDuplicateSchemaName,
                schema.name.range,
                format!(
                    "the schema name {} is declared more than once",
                    schema.name.value
                ),
            ));
        }
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        for field in &schema.fields {
            if !keys.insert(field.key.value.as_str()) {
                found.push(diagnostic(
                    DiagnosticCode::NostDuplicatePropertyKey,
                    field.key.range,
                    format!(
                        "the field key {} is declared more than once in schema {}",
                        field.key.value, schema.name.value
                    ),
                ));
            }
        }
    }
}

/// The field a record's schemas require, keyed by field key.
///
/// Where two schemas declare one key, the declared types must agree, and a key that is
/// required in either is required. Taking the stricter reading is the only rule that
/// cannot silently weaken a declaration its author wrote.
struct EffectiveSchema<'a> {
    fields: BTreeMap<&'a str, (FieldType, bool)>,
}

fn effective_schema<'a>(
    schemas: &BTreeMap<&'a str, &'a SchemaDeclaration>,
    named: &'a [Spanned<String>],
    found: &mut Vec<Diagnostic>,
) -> EffectiveSchema<'a> {
    let mut fields: BTreeMap<&'a str, (FieldType, bool)> = BTreeMap::new();
    for name in named {
        let Some(schema) = schemas.get(name.value.as_str()) else {
            // A record may name an undeclared schema; the name is then an unvalidated
            // label. The contract records that a misspelling is indistinguishable from
            // an intentional bare label while schemas stay optional.
            continue;
        };
        for field in &schema.fields {
            let key = field.key.value.as_str();
            let declared = field.field_type.value;
            match fields.get_mut(key) {
                None => {
                    fields.insert(key, (declared, !field.optional));
                }
                Some((existing, required)) => {
                    if *existing != declared {
                        found.push(diagnostic(
                            DiagnosticCode::NostSchemaConflict,
                            field.key.range,
                            format!(
                                "the field {key} is declared as {existing} and as {declared} by \
                                 two schemas this record names"
                            ),
                        ));
                    }
                    *required = *required || !field.optional;
                }
            }
        }
    }
    EffectiveSchema { fields }
}

fn value_matches(value: &Value, declared: FieldType) -> bool {
    if declared.array {
        return match value {
            Value::List(items) => items
                .iter()
                .all(|item| scalar_matches(&item.value, declared.scalar)),
            _ => false,
        };
    }
    scalar_matches(value, declared.scalar)
}

fn scalar_matches(value: &Value, scalar: ScalarType) -> bool {
    matches!(
        (value, scalar),
        (Value::Boolean(_), ScalarType::Boolean)
            | (Value::Integer(_), ScalarType::Integer)
            | (Value::Float(_), ScalarType::Double)
            | (Value::String(_), ScalarType::String)
            | (Value::Bytes { .. }, ScalarType::Bytes)
            | (Value::DateTime(_), ScalarType::DateTime)
    )
}

fn check_record(
    schemas: &BTreeMap<&str, &SchemaDeclaration>,
    named: &[Spanned<String>],
    record: &RecordBody,
    head: SourceRange,
    ids: &mut BTreeSet<String>,
    node_kind: bool,
    found: &mut Vec<Diagnostic>,
) {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for property in &record.properties {
        if !seen.insert(property.key.value.as_str()) {
            found.push(diagnostic(
                DiagnosticCode::NostDuplicatePropertyKey,
                property.key.range,
                format!(
                    "the property key {} is set more than once in this block",
                    property.key.value
                ),
            ));
        }
        check_value(&property.key.value, &property.value, found);
        check_reserved_key(property, ids, node_kind, found);
    }

    let effective = effective_schema(schemas, named, found);
    for (key, (declared, required)) in &effective.fields {
        match record
            .properties
            .iter()
            .find(|property| property.key.value == *key)
        {
            None => {
                if *required {
                    found.push(diagnostic(
                        DiagnosticCode::NostSchemaViolation,
                        head,
                        format!("the required field {key} of type {declared} is missing"),
                    ));
                }
            }
            Some(property) => {
                if !value_matches(&property.value.value, *declared) {
                    found.push(diagnostic(
                        DiagnosticCode::NostSchemaViolation,
                        property.value.range,
                        format!(
                            "the field {key} is declared {declared} but holds a {}",
                            property.value.value.kind_name()
                        ),
                    ));
                }
            }
        }
    }
}

fn check_reserved_key(
    property: &Property,
    ids: &mut BTreeSet<String>,
    node_kind: bool,
    found: &mut Vec<Diagnostic>,
) {
    match property.key.value.as_str() {
        ID_KEY => {
            let Value::String(text) = &property.value.value else {
                found.push(diagnostic(
                    DiagnosticCode::NostInvalidId,
                    property.value.range,
                    format!(
                        "the reserved key `id` holds a quoted identifier, found a {}",
                        property.value.value.kind_name()
                    ),
                ));
                return;
            };
            let parsed = if node_kind {
                LocalNodeId::from_str(text).map(|_| ())
            } else {
                LocalEdgeId::from_str(text).map(|_| ())
            };
            if let Err(error) = parsed {
                found.push(diagnostic(
                    DiagnosticCode::NostInvalidId,
                    property.value.range,
                    format!("{text} is not a valid record identifier: {error}"),
                ));
                return;
            }
            if !ids.insert(text.clone()) {
                found.push(diagnostic(
                    DiagnosticCode::NostDuplicateId,
                    property.value.range,
                    format!("the record identifier {text} is used more than once"),
                ));
            }
        }
        LABELS_KEY => {
            let valid = match &property.value.value {
                Value::List(items) => items
                    .iter()
                    .all(|item| matches!(item.value, Value::String(_))),
                _ => false,
            };
            if !valid {
                found.push(diagnostic(
                    DiagnosticCode::NostSchemaViolation,
                    property.value.range,
                    "the reserved key `labels` holds a list of strings".to_owned(),
                ));
            }
        }
        _ => {}
    }
}

fn check_declarations(file: &SourceFile, found: &mut Vec<Diagnostic>) {
    let schemas: BTreeMap<&str, &SchemaDeclaration> = file
        .schemas
        .iter()
        .map(|schema| (schema.name.value.as_str(), schema))
        .collect();

    let mut ids: BTreeSet<String> = BTreeSet::new();
    let mut names: BTreeSet<&str> = BTreeSet::new();

    for node in &file.nodes {
        if !names.insert(node.name.value.as_str()) {
            found.push(diagnostic(
                DiagnosticCode::NostDuplicateDeclarationName,
                node.name.range,
                format!(
                    "the name {} is declared more than once in this file",
                    node.name.value
                ),
            ));
        }
        check_record(
            &schemas,
            &node.schemas,
            &node.record,
            node.name.range,
            &mut ids,
            true,
            found,
        );
    }

    for edge in &file.edges {
        check_record(
            &schemas,
            std::slice::from_ref(&edge.relation),
            &edge.record,
            edge.relation.range,
            &mut ids,
            false,
            found,
        );
        check_edge_endpoint_constraint(&schemas, file, edge, found);
    }
}

/// Checks an edge against its schema's endpoint constraint, when it declares one.
fn check_edge_endpoint_constraint(
    schemas: &BTreeMap<&str, &SchemaDeclaration>,
    file: &SourceFile,
    edge: &EdgeDeclaration,
    found: &mut Vec<Diagnostic>,
) {
    let Some(schema) = schemas.get(edge.relation.value.as_str()) else {
        return;
    };
    let Some(constraint) = &schema.endpoints else {
        return;
    };
    for (endpoint, required, side) in [
        (&edge.source, &constraint.source, "source"),
        (&edge.target, &constraint.target, "target"),
    ] {
        // Only a local endpoint can be checked here: an aliased or locator endpoint
        // names a record in a linked source this file cannot see.
        let Endpoint::Local(name) = endpoint else {
            continue;
        };
        let Some(node) = file.nodes.iter().find(|node| node.name.value == name.value) else {
            continue;
        };
        if !node
            .schemas
            .iter()
            .any(|carried| carried.value == required.value)
        {
            found.push(diagnostic(
                DiagnosticCode::NostSchemaViolation,
                name.range,
                format!(
                    "schema {} requires its {side} to carry {}, but {} does not",
                    edge.relation.value, required.value, name.value
                ),
            ));
        }
    }
}

fn check_endpoints(file: &SourceFile, found: &mut Vec<Diagnostic>) {
    let aliases: BTreeSet<&str> = file
        .links
        .iter()
        .filter_map(|link| link.alias.as_ref().map(|alias| alias.value.as_str()))
        .collect();
    let locators: BTreeSet<&str> = file
        .links
        .iter()
        .map(|link| link.source.value.as_str())
        .collect();
    let declared: BTreeSet<&str> = file
        .nodes
        .iter()
        .map(|node: &NodeDeclaration| node.name.value.as_str())
        .collect();

    for edge in &file.edges {
        for endpoint in [&edge.source, &edge.target] {
            match endpoint {
                Endpoint::Local(name) => {
                    if !declared.contains(name.value.as_str()) {
                        found.push(diagnostic(
                            DiagnosticCode::NostUnresolvedEndpoint,
                            name.range,
                            format!(
                                "the endpoint {} resolves to no declaration, so a \
                                 Placeholder is created",
                                name.value
                            ),
                        ));
                    }
                }
                Endpoint::Aliased { alias, .. } => {
                    if !aliases.contains(alias.value.as_str()) {
                        found.push(diagnostic(
                            DiagnosticCode::NostUnknownLinkAlias,
                            alias.range,
                            format!("no link declares the alias {}", alias.value),
                        ));
                    }
                }
                Endpoint::Locator { locator, .. } => {
                    if !locators.contains(locator.value.as_str()) {
                        found.push(diagnostic(
                            DiagnosticCode::NostUnknownLinkAlias,
                            locator.range,
                            format!("no link declares the locator {}", locator.value),
                        ));
                    }
                }
            }
        }
    }
}

fn check_contributions(file: &SourceFile, found: &mut Vec<Diagnostic>) {
    for node in &file.nodes {
        for contribution in &node.record.contributions {
            check_contribution(contribution, found);
        }
    }
    for edge in &file.edges {
        for contribution in &edge.record.contributions {
            check_contribution(contribution, found);
        }
    }
}

fn check_contribution(contribution: &ContributionBlock, found: &mut Vec<Diagnostic>) {
    if let Some(unit) = &contribution.unit
        && let Err(error) = SourceUnitId::from_str(&unit.value)
    {
        found.push(diagnostic(
            DiagnosticCode::NostInvalidEvidence,
            unit.range,
            format!(
                "{} is not a valid source unit identifier: {error}",
                unit.value
            ),
        ));
    }

    // Only a user contribution may omit evidence, because the user is the evidence.
    if contribution.evidence.is_empty()
        && !matches!(contribution.owner, OwnerDeclaration::User { .. })
    {
        found.push(diagnostic(
            DiagnosticCode::NostInvalidEvidence,
            contribution.owner.range(),
            format!(
                "an `{}` contribution must carry evidence",
                contribution.owner.keyword()
            ),
        ));
    }

    let inherits_producer = matches!(contribution.owner, OwnerDeclaration::Analyzer { .. });
    for evidence in &contribution.evidence {
        check_evidence(evidence, inherits_producer, found);
    }
}

fn check_evidence(evidence: &EvidenceBlock, inherits_producer: bool, found: &mut Vec<Diagnostic>) {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for field in &evidence.fields {
        let key = field.key.value.as_str();
        if !EVIDENCE_KEYS.iter().any(|(known, _)| *known == key) {
            found.push(diagnostic(
                DiagnosticCode::NostInvalidEvidence,
                field.key.range,
                format!("`{key}` is not an evidence key"),
            ));
            continue;
        }
        if !seen.insert(key) {
            found.push(diagnostic(
                DiagnosticCode::NostDuplicatePropertyKey,
                field.key.range,
                format!("the evidence key {key} is set more than once in this block"),
            ));
        }
        check_evidence_value(key, &field.value, found);
    }

    for (key, required) in EVIDENCE_KEYS {
        if !required || seen.contains(key) {
            continue;
        }
        found.push(diagnostic(
            DiagnosticCode::NostInvalidEvidence,
            evidence.range,
            format!("an evidence block must state `{key}`"),
        ));
    }

    // A producer is inherited from an analyzer owner, and nowhere else.
    if !inherits_producer {
        for key in ["producer", "producer_version"] {
            if !seen.contains(key) {
                found.push(diagnostic(
                    DiagnosticCode::NostInvalidEvidence,
                    evidence.range,
                    format!(
                        "`{key}` is required here, because only an `analyzer` owner supplies \
                         one to inherit"
                    ),
                ));
            }
        }
    }
}

fn check_evidence_value(key: &str, value: &Spanned<EvidenceValue>, found: &mut Vec<Diagnostic>) {
    let text_keys = [
        "source",
        "digest",
        "revision",
        "path",
        "range",
        "producer",
        "producer_version",
    ];
    match &value.value {
        EvidenceValue::Text(_) => {
            if !text_keys.contains(&key) {
                found.push(diagnostic(
                    DiagnosticCode::NostInvalidEvidence,
                    value.range,
                    format!("`{key}` takes a bare word, not a quoted string"),
                ));
            }
        }
        EvidenceValue::Enumerator { name, score } => {
            if text_keys.contains(&key) {
                found.push(diagnostic(
                    DiagnosticCode::NostInvalidEvidence,
                    value.range,
                    format!("`{key}` takes a quoted string"),
                ));
                return;
            }
            match key {
                "method" => {
                    if !METHODS.contains(&name.as_str()) {
                        found.push(diagnostic(
                            DiagnosticCode::NostInvalidEvidence,
                            value.range,
                            format!("`{name}` is not a method; expected one of {METHODS:?}"),
                        ));
                    }
                    if score.is_some() {
                        found.push(diagnostic(
                            DiagnosticCode::NostInvalidEvidence,
                            value.range,
                            "a method carries no score".to_owned(),
                        ));
                    }
                }
                "confidence" => check_confidence(name, score.as_deref(), value.range, found),
                _ => {}
            }
        }
    }
}

fn check_confidence(
    name: &str,
    score: Option<&str>,
    range: SourceRange,
    found: &mut Vec<Diagnostic>,
) {
    match (name, score) {
        ("extracted", None) => {}
        ("extracted", Some(_)) => found.push(diagnostic(
            DiagnosticCode::NostInvalidEvidence,
            range,
            "`extracted` carries no score, because a fact read from source has nothing to \
             weigh"
                .to_owned(),
        )),
        ("inferred" | "ambiguous", None) => found.push(diagnostic(
            DiagnosticCode::NostInvalidEvidence,
            range,
            format!("`{name}` requires a score, written `{name}(0.5)`"),
        )),
        ("inferred" | "ambiguous", Some(score)) => match score.parse::<f64>() {
            Ok(number) if (0.0..=1.0).contains(&number) => {}
            _ => found.push(diagnostic(
                DiagnosticCode::NostInvalidEvidence,
                range,
                format!("a confidence score must be within 0.0 through 1.0, found {score}"),
            )),
        },
        (other, _) => found.push(diagnostic(
            DiagnosticCode::NostInvalidEvidence,
            range,
            format!("`{other}` is not a confidence; expected extracted, inferred, or ambiguous"),
        )),
    }
}

fn check_value(key: &str, value: &Spanned<Value>, found: &mut Vec<Diagnostic>) {
    match &value.value {
        Value::Integer(text) => {
            if text.parse::<i64>().is_err() {
                found.push(diagnostic(
                    DiagnosticCode::NostIntegerOutOfRange,
                    value.range,
                    format!("the integer {text} does not fit in a signed 64-bit value"),
                ));
            }
        }
        Value::Float(text) => match text.parse::<f64>() {
            Ok(number) if !number.is_finite() => found.push(diagnostic(
                DiagnosticCode::NostNonFiniteNumber,
                value.range,
                format!("the number {text} is not finite"),
            )),
            Ok(number) if key == CONFIDENCE_SCORE_KEY && !(0.0..=1.0).contains(&number) => {
                found.push(diagnostic(
                    DiagnosticCode::NostNonFiniteNumber,
                    value.range,
                    format!("a confidence score must be within 0.0 through 1.0, found {text}"),
                ));
            }
            Ok(_) => {}
            Err(_) => found.push(diagnostic(
                DiagnosticCode::NostNonFiniteNumber,
                value.range,
                format!("the number {text} cannot be read as a finite value"),
            )),
        },
        Value::DateTime(text) => {
            if let Err(error) = DateTime::new(text.clone()) {
                found.push(diagnostic(
                    DiagnosticCode::NostInvalidDatetime,
                    value.range,
                    format!("{text} is not a valid RFC 3339 timestamp: {error}"),
                ));
            }
        }
        Value::List(items) => {
            for item in items {
                check_value(key, item, found);
            }
        }
        Value::Boolean(_) | Value::String(_) | Value::Bytes { .. } => {}
    }
}

/// Reports whether any diagnostic in `found` is an error rather than a warning.
///
/// A file with warnings only is still usable, which is why this distinction exists.
#[must_use]
pub fn has_errors(found: &[Diagnostic]) -> bool {
    found
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::*;

    const NODE_ID: &str = "n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const OTHER_ID: &str = "n_0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";

    fn codes(source: &str) -> Vec<DiagnosticCode> {
        let file = parse(source).expect("the fixture must parse");
        validate(&file).into_iter().map(|d| d.code).collect()
    }

    #[test]
    fn a_valid_file_reports_nothing() {
        assert!(codes("@nost 2\nschema L {\n k: integer,\n}\nnode n: L {\n k: 1,\n}\n").is_empty());
    }

    #[test]
    fn reports_an_unsupported_language_version() {
        assert_eq!(
            codes("@nost 999\n"),
            vec![DiagnosticCode::NostVersionUnsupported]
        );
    }

    #[test]
    fn version_one_is_refused_rather_than_read() {
        assert_eq!(
            codes("@nost 1\n"),
            vec![DiagnosticCode::NostVersionUnsupported]
        );
    }

    #[test]
    fn reports_duplicate_links() {
        assert_eq!(
            codes("@nost 2\n@link \"./a\"\n@link \"./a\" as a\n"),
            vec![DiagnosticCode::NostDuplicateLinkSource]
        );
        assert_eq!(
            codes("@nost 2\n@link \"./a\" as s\n@link \"./b\" as s\n"),
            vec![DiagnosticCode::NostDuplicateLinkAlias]
        );
    }

    #[test]
    fn reports_a_duplicate_schema_name() {
        assert_eq!(
            codes("@nost 2\nschema S {}\nschema S {}\n"),
            vec![DiagnosticCode::NostDuplicateSchemaName]
        );
    }

    #[test]
    fn reports_duplicate_names_ids_and_keys() {
        assert_eq!(
            codes("@nost 2\nnode d: L {}\nnode d: L {}\n"),
            vec![DiagnosticCode::NostDuplicateDeclarationName]
        );
        assert_eq!(
            codes(&format!(
                "@nost 2\nnode a: L {{\n id: \"{NODE_ID}\",\n}}\nnode b: L {{\n id: \"{NODE_ID}\",\n}}\n"
            )),
            vec![DiagnosticCode::NostDuplicateId]
        );
        assert_eq!(
            codes("@nost 2\nnode a: L {\n k: 1,\n k: 2,\n}\n"),
            vec![DiagnosticCode::NostDuplicatePropertyKey]
        );
    }

    #[test]
    fn reports_a_malformed_record_identifier() {
        assert_eq!(
            codes("@nost 2\nnode a: L {\n id: \"n_1\",\n}\n"),
            vec![DiagnosticCode::NostInvalidId]
        );
        // A node identifier where an edge identifier belongs is refused by its prefix.
        assert_eq!(
            codes(&format!(
                "@nost 2\nedge a -> a :R {{\n id: \"{NODE_ID}\",\n}}\n"
            ))
            .into_iter()
            .filter(|code| *code == DiagnosticCode::NostInvalidId)
            .count(),
            1
        );
    }

    #[test]
    fn an_edge_identifier_is_accepted_on_an_edge() {
        let edge_id = format!("e_{}", &NODE_ID[2..]);
        let source =
            format!("@nost 2\nnode a: L {{}}\nedge a -> a :R {{\n id: \"{edge_id}\",\n}}\n");
        assert!(codes(&source).is_empty(), "{:?}", codes(&source));
    }

    #[test]
    fn two_records_may_state_different_identifiers() {
        let source = format!(
            "@nost 2\nnode a: L {{\n id: \"{NODE_ID}\",\n}}\nnode b: L {{\n id: \"{OTHER_ID}\",\n}}\n"
        );
        assert!(codes(&source).is_empty(), "{:?}", codes(&source));
    }

    #[test]
    fn reports_a_missing_required_field_and_a_wrong_type() {
        assert_eq!(
            codes("@nost 2\nschema S {\n name: string,\n}\nnode a: S {}\n"),
            vec![DiagnosticCode::NostSchemaViolation]
        );
        assert_eq!(
            codes("@nost 2\nschema S {\n name: string,\n}\nnode a: S {\n name: 42,\n}\n"),
            vec![DiagnosticCode::NostSchemaViolation]
        );
    }

    #[test]
    fn an_optional_field_may_be_omitted_and_a_schema_is_open() {
        assert!(
            codes("@nost 2\nschema S {\n name?: string,\n}\nnode a: S {\n extra: 1,\n}\n")
                .is_empty()
        );
    }

    #[test]
    fn an_array_field_checks_every_element() {
        assert!(
            codes("@nost 2\nschema S {\n t: string[],\n}\nnode a: S {\n t: [\"x\", \"y\"],\n}\n")
                .is_empty()
        );
        assert_eq!(
            codes("@nost 2\nschema S {\n t: string[],\n}\nnode a: S {\n t: [\"x\", 1],\n}\n"),
            vec![DiagnosticCode::NostSchemaViolation]
        );
        assert_eq!(
            codes("@nost 2\nschema S {\n t: string[],\n}\nnode a: S {\n t: \"x\",\n}\n"),
            vec![DiagnosticCode::NostSchemaViolation]
        );
    }

    #[test]
    fn two_schemas_disagreeing_on_a_field_type_conflict() {
        assert_eq!(
            codes(
                "@nost 2\nschema A {\n k: string,\n}\nschema B {\n k: integer,\n}\nnode n: A, B {\n k: \"x\",\n}\n"
            )
            .into_iter()
            .filter(|code| *code == DiagnosticCode::NostSchemaConflict)
            .count(),
            1
        );
    }

    #[test]
    fn the_stricter_requirement_wins_when_two_schemas_disagree() {
        // Required in one and optional in the other means required.
        assert_eq!(
            codes(
                "@nost 2\nschema A {\n k: string,\n}\nschema B {\n k?: string,\n}\nnode n: A, B {}\n"
            ),
            vec![DiagnosticCode::NostSchemaViolation]
        );
    }

    #[test]
    fn an_undeclared_schema_name_is_an_unvalidated_label() {
        assert!(codes("@nost 2\nnode n: NotDeclared {\n anything: 1,\n}\n").is_empty());
    }

    #[test]
    fn reports_an_endpoint_constraint_violation() {
        let source = "@nost 2\nschema A {}\nschema B {}\nschema R (A -> B) {}\n\
            node x: A {}\nnode y: A {}\nedge x -> y :R {}\n";
        assert_eq!(
            codes(source),
            vec![DiagnosticCode::NostSchemaViolation],
            "the target does not carry B"
        );
    }

    #[test]
    fn reports_an_unknown_alias_or_locator_and_an_unresolved_local_endpoint() {
        let base = "@nost 2\nnode a: L {}\n";
        assert_eq!(
            codes(&format!("{base}edge a -> absent::x :R {{}}\n")),
            vec![DiagnosticCode::NostUnknownLinkAlias]
        );
        assert_eq!(
            codes(&format!("{base}edge a -> \"./never\"::x :R {{}}\n")),
            vec![DiagnosticCode::NostUnknownLinkAlias]
        );
        assert_eq!(
            codes(&format!("{base}edge a -> gone :R {{}}\n")),
            vec![DiagnosticCode::NostUnresolvedEndpoint]
        );
    }

    #[test]
    fn an_unresolved_endpoint_and_a_schema_violation_are_only_warnings() {
        let file =
            parse("@nost 2\nschema S {\n k: string,\n}\nnode a: S {}\nedge a -> gone :R {}\n")
                .unwrap();
        let found = validate(&file);
        assert_eq!(found.len(), 2);
        for entry in &found {
            assert_eq!(entry.severity, Severity::Warning, "{entry:?}");
        }
        assert!(!has_errors(&found));
    }

    #[test]
    fn reports_value_rules_including_inside_a_list() {
        let head = "@nost 2\nnode a: L {\n";
        assert_eq!(
            codes(&format!("{head} k: 9223372036854775808,\n}}\n")),
            vec![DiagnosticCode::NostIntegerOutOfRange]
        );
        assert_eq!(
            codes(&format!("{head} k: datetime\"26/07/2026\",\n}}\n")),
            vec![DiagnosticCode::NostInvalidDatetime]
        );
        assert_eq!(
            codes(&format!("{head} confidence_score: 1.5,\n}}\n")),
            vec![DiagnosticCode::NostNonFiniteNumber]
        );
        assert_eq!(
            codes(&format!("{head} k: [1, 9223372036854775808],\n}}\n")),
            vec![DiagnosticCode::NostIntegerOutOfRange]
        );
    }

    #[test]
    fn an_ordinary_float_outside_zero_to_one_is_accepted() {
        // The range rule applies to a confidence score, not to every number.
        assert!(codes("@nost 2\nnode a: L {\n ratio: 7.5,\n}\n").is_empty());
    }

    #[test]
    fn the_labels_key_must_hold_a_list_of_strings() {
        assert!(codes("@nost 2\nnode a: L {\n labels: [\"X\", \"Y\"],\n}\n").is_empty());
        assert_eq!(
            codes("@nost 2\nnode a: L {\n labels: \"X\",\n}\n"),
            vec![DiagnosticCode::NostSchemaViolation]
        );
        assert_eq!(
            codes("@nost 2\nnode a: L {\n labels: [1],\n}\n"),
            vec![DiagnosticCode::NostSchemaViolation]
        );
    }

    fn evidence(body: &str) -> Vec<DiagnosticCode> {
        codes(&format!(
            "@nost 2\nnode a: L {{\n @by analyzer \"r\" \"1\" {{\n  @evidence {{\n{body}  }}\n }}\n}}\n"
        ))
    }

    #[test]
    fn a_complete_evidence_block_reports_nothing() {
        assert!(
            evidence(
                "   source: \"./\",\n   digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   \
                 method: deterministic,\n   confidence: extracted,\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn reports_a_missing_required_evidence_key() {
        let found = evidence("   source: \"./\",\n   method: deterministic,\n");
        assert!(found.contains(&DiagnosticCode::NostInvalidEvidence));
        // digest and confidence are both missing.
        assert_eq!(
            found
                .iter()
                .filter(|code| **code == DiagnosticCode::NostInvalidEvidence)
                .count(),
            2
        );
    }

    #[test]
    fn reports_an_unknown_evidence_key() {
        let found = evidence(
            "   source: \"./\",\n   digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   \
             method: deterministic,\n   confidence: extracted,\n   nonsense: \"x\",\n",
        );
        assert_eq!(found, vec![DiagnosticCode::NostInvalidEvidence]);
    }

    #[test]
    fn reports_a_confidence_that_breaks_its_own_rules() {
        let base = "   source: \"./\",\n   digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   \
                    method: deterministic,\n";
        assert_eq!(
            evidence(&format!("{base}   confidence: extracted(0.5),\n")),
            vec![DiagnosticCode::NostInvalidEvidence]
        );
        assert_eq!(
            evidence(&format!("{base}   confidence: inferred,\n")),
            vec![DiagnosticCode::NostInvalidEvidence]
        );
        assert_eq!(
            evidence(&format!("{base}   confidence: inferred(1.5),\n")),
            vec![DiagnosticCode::NostInvalidEvidence]
        );
        assert_eq!(
            evidence(&format!("{base}   confidence: certain,\n")),
            vec![DiagnosticCode::NostInvalidEvidence]
        );
        assert!(evidence(&format!("{base}   confidence: ambiguous(0.4),\n")).is_empty());
    }

    #[test]
    fn reports_a_method_that_is_not_one_of_the_three() {
        let found = evidence(
            "   source: \"./\",\n   digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   \
             method: guessed,\n   confidence: extracted,\n",
        );
        assert_eq!(found, vec![DiagnosticCode::NostInvalidEvidence]);
    }

    #[test]
    fn only_a_user_contribution_may_omit_evidence() {
        assert!(codes("@nost 2\nnode a: L {\n @by user {}\n}\n").is_empty());
        assert_eq!(
            codes("@nost 2\nnode a: L {\n @by analyzer \"r\" \"1\" {}\n}\n"),
            vec![DiagnosticCode::NostInvalidEvidence]
        );
        assert_eq!(
            codes("@nost 2\nnode a: L {\n @by ai \"sha256:x\" {}\n}\n"),
            vec![DiagnosticCode::NostInvalidEvidence]
        );
    }

    #[test]
    fn a_producer_is_required_when_there_is_no_analyzer_to_inherit_from() {
        let found = codes(
            "@nost 2\nnode a: L {\n @by ai \"sha256:x\" {\n  @evidence {\n   source: \"./\",\n   \
             digest: \"sha256:abcdef0123456789abcdef0123456789\",\n   method: ai_inferred,\n   \
             confidence: inferred(0.5),\n  }\n }\n}\n",
        );
        assert_eq!(
            found
                .iter()
                .filter(|code| **code == DiagnosticCode::NostInvalidEvidence)
                .count(),
            2,
            "producer and producer_version are both required"
        );
    }

    #[test]
    fn a_malformed_source_unit_is_reported() {
        assert_eq!(
            codes("@nost 2\nnode a: L {\n @by user unit \"u_1\" {}\n}\n"),
            vec![DiagnosticCode::NostInvalidEvidence]
        );
    }

    #[test]
    fn every_diagnostic_carries_a_range() {
        let file = parse("@nost 999\n@link \"./a\"\n@link \"./a\"\n").unwrap();
        let found = validate(&file);
        assert!(found.len() >= 2);
        for entry in found {
            assert!(entry.range.is_some());
        }
    }
}
