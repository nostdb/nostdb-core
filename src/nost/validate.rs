//! Semantic validation for a parsed `.nost` file.
//!
//! These are the rules the grammar cannot express. Each produces the stable diagnostic
//! code the language contract assigns, with a source range, and every problem is
//! reported rather than only the first.
//!
//! An unresolved endpoint is a warning, not an error: the Engine creates a Placeholder
//! Node and continues, which is why the file stays usable.

use super::{Endpoint, Property, SourceFile, Spanned, Value};
use crate::diagnostic::{Diagnostic, DiagnosticCode, Severity};
use crate::evidence::SourceRange;
use crate::property::DateTime;
use crate::text::NonEmptyText;
use std::collections::BTreeSet;

/// Language versions this build understands.
pub const SUPPORTED_LANGUAGE_VERSIONS: [u32; 1] = [1];

/// Property key whose value is a confidence score constrained to `0.0..=1.0`.
///
/// The language contract states the range rule but does not yet name the key that
/// carries a confidence. This build uses `confidence_score`, and the choice is recorded
/// in the root progress file as something the contract should absorb.
pub const CONFIDENCE_SCORE_KEY: &str = "confidence_score";

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
    check_identifiers(file, &mut found);
    check_endpoints(file, &mut found);
    check_values(file, &mut found);

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

fn record_id(seen: &mut BTreeSet<String>, id: &Spanned<String>, found: &mut Vec<Diagnostic>) {
    if !seen.insert(id.value.clone()) {
        found.push(diagnostic(
            DiagnosticCode::NostDuplicateId,
            id.range,
            format!("the record identifier {} is used more than once", id.value),
        ));
    }
}

fn check_identifiers(file: &SourceFile, found: &mut Vec<Diagnostic>) {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let mut module_names: BTreeSet<&str> = BTreeSet::new();

    for module in &file.modules {
        if !module_names.insert(module.name.value.as_str()) {
            found.push(diagnostic(
                DiagnosticCode::NostDuplicateDeclarationName,
                module.name.range,
                format!(
                    "the module name {} is declared more than once",
                    module.name.value
                ),
            ));
        }
        record_id(&mut ids, &module.id, found);

        let mut local_names: BTreeSet<&str> = BTreeSet::new();
        for node in &module.nodes {
            if !local_names.insert(node.name.value.as_str()) {
                found.push(diagnostic(
                    DiagnosticCode::NostDuplicateDeclarationName,
                    node.name.range,
                    format!(
                        "the name {} is declared more than once in this module",
                        node.name.value
                    ),
                ));
            }
            record_id(&mut ids, &node.id, found);
            check_duplicate_keys(&node.properties, found);
        }
        for edge in &module.edges {
            if !local_names.insert(edge.name.value.as_str()) {
                found.push(diagnostic(
                    DiagnosticCode::NostDuplicateDeclarationName,
                    edge.name.range,
                    format!(
                        "the name {} is declared more than once in this module",
                        edge.name.value
                    ),
                ));
            }
            record_id(&mut ids, &edge.id, found);
            check_duplicate_keys(&edge.properties, found);
        }
    }
}

fn check_duplicate_keys(properties: &[Property], found: &mut Vec<Diagnostic>) {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for property in properties {
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
        .modules
        .iter()
        .flat_map(|module| module.nodes.iter().map(|node| node.name.value.as_str()))
        .collect();

    for module in &file.modules {
        for edge in &module.edges {
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
}

fn check_values(file: &SourceFile, found: &mut Vec<Diagnostic>) {
    for module in &file.modules {
        for node in &module.nodes {
            for property in &node.properties {
                check_property(property, found);
            }
        }
        for edge in &module.edges {
            for property in &edge.properties {
                check_property(property, found);
            }
        }
    }
}

fn check_property(property: &Property, found: &mut Vec<Diagnostic>) {
    check_value(&property.key.value, &property.value, found);
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

    fn codes(source: &str) -> Vec<DiagnosticCode> {
        let file = parse(source).expect("the fixture must parse");
        validate(&file).into_iter().map(|d| d.code).collect()
    }

    #[test]
    fn a_valid_file_reports_nothing() {
        assert!(
            codes("@nost 1\nmodule m id \"m_1\" {\n node n id \"n_1\" :L {\n k: 1\n }\n}\n")
                .is_empty()
        );
    }

    #[test]
    fn reports_an_unsupported_language_version() {
        assert_eq!(
            codes("@nost 999\n"),
            vec![DiagnosticCode::NostVersionUnsupported]
        );
    }

    #[test]
    fn reports_duplicate_links() {
        assert_eq!(
            codes("@nost 1\n@link \"./a\"\n@link \"./a\" as a\n"),
            vec![DiagnosticCode::NostDuplicateLinkSource]
        );
        assert_eq!(
            codes("@nost 1\n@link \"./a\" as s\n@link \"./b\" as s\n"),
            vec![DiagnosticCode::NostDuplicateLinkAlias]
        );
    }

    #[test]
    fn reports_duplicate_names_ids_and_keys() {
        assert_eq!(
            codes(
                "@nost 1\nmodule m id \"m_1\" {\n node d id \"n_1\" :L {}\n node d id \"n_2\" :L {}\n}\n"
            ),
            vec![DiagnosticCode::NostDuplicateDeclarationName]
        );
        assert_eq!(
            codes(
                "@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L {}\n node b id \"n_1\" :L {}\n}\n"
            ),
            vec![DiagnosticCode::NostDuplicateId]
        );
        assert_eq!(
            codes("@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L {\n k: 1\n k: 2\n }\n}\n"),
            vec![DiagnosticCode::NostDuplicatePropertyKey]
        );
    }

    #[test]
    fn reports_an_unknown_alias_or_locator_and_an_unresolved_local_endpoint() {
        let base = "@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L {}\n";
        assert_eq!(
            codes(&format!(
                "{base} edge e id \"e_1\" :R (a -> absent::x) {{}}\n}}\n"
            )),
            vec![DiagnosticCode::NostUnknownLinkAlias]
        );
        assert_eq!(
            codes(&format!(
                "{base} edge e id \"e_1\" :R (a -> \"./never\"::x) {{}}\n}}\n"
            )),
            vec![DiagnosticCode::NostUnknownLinkAlias]
        );
        assert_eq!(
            codes(&format!(
                "{base} edge e id \"e_1\" :R (a -> gone) {{}}\n}}\n"
            )),
            vec![DiagnosticCode::NostUnresolvedEndpoint]
        );
    }

    #[test]
    fn an_unresolved_endpoint_is_only_a_warning() {
        let file = parse(
            "@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L {}\n edge e id \"e_1\" :R (a -> gone) {}\n}\n",
        )
        .unwrap();
        let found = validate(&file);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Warning);
        assert!(!has_errors(&found));
    }

    #[test]
    fn reports_value_rules_including_inside_a_list() {
        let node = "@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L {\n";
        assert_eq!(
            codes(&format!("{node} k: 9223372036854775808\n }}\n}}\n")),
            vec![DiagnosticCode::NostIntegerOutOfRange]
        );
        assert_eq!(
            codes(&format!("{node} k: datetime\"26/07/2026\"\n }}\n}}\n")),
            vec![DiagnosticCode::NostInvalidDatetime]
        );
        assert_eq!(
            codes(&format!("{node} confidence_score: 1.5\n }}\n}}\n")),
            vec![DiagnosticCode::NostNonFiniteNumber]
        );
        // A list element is checked too.
        assert_eq!(
            codes(&format!("{node} k: [1, 9223372036854775808]\n }}\n}}\n")),
            vec![DiagnosticCode::NostIntegerOutOfRange]
        );
    }

    #[test]
    fn an_ordinary_float_outside_zero_to_one_is_accepted() {
        // The range rule applies to a confidence score, not to every number.
        assert!(
            codes("@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L {\n ratio: 7.5\n }\n}\n")
                .is_empty()
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
