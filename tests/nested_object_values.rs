//! End to end for `nost_language_version` 4: an object field type, an object value, and
//! the optional separator, through the public API only.
//!
//! The shape under test is the one that motivated the version — a project with a list of
//! dependencies — written the way somebody writes it, with newlines instead of commas.
//! Each stage is asserted separately, because a single "it round-trips" assertion would
//! pass while validation said nothing and the container stored a different graph.

use nostdb_core::container::{
    Container, ContainerBuilder, FORMAT_VERSION, SUPPORTED_FORMAT_VERSIONS,
};
use nostdb_core::encoding::{decode_graph, encode_graph};
use nostdb_core::generation::Generation;
use nostdb_core::nost::{format, parse, to_graph, validate};
use nostdb_core::schema::{FieldType, ScalarType};
use nostdb_core::{MAX_NESTING_DEPTH, PropertyValue};

/// The declaration the language exists to accept, with no comma anywhere.
const DOCUMENT: &str = "\
@nost 4

schema Project {
  name: string
  description?: string
  dependencies?: {
    name: string
    version?: string
  }[]
}

node app: Project {
  name: \"app\"
  dependencies: [{ name: \"serde\", version: \"1\" }, { name: \"tokio\" }]
}
";

fn container_of(graph: &nostdb_core::encoding::Graph) -> Container {
    let mut builder = ContainerBuilder::new(Generation::INITIAL);
    for section in encode_graph(graph) {
        builder.push_section(section.kind, section.payload).unwrap();
    }
    Container::parse(&builder.build().unwrap()).unwrap()
}

#[test]
fn the_declaration_parses_validates_and_stores_without_a_single_comma_between_entries() {
    let file = parse(DOCUMENT).expect("the document parses");
    assert!(
        validate(&file).is_empty(),
        "the document must raise no diagnostic: {:?}",
        validate(&file)
    );

    // The declared type is an array of an object, not a scalar and a flag.
    let declared = &file.schemas[0].fields[2];
    assert_eq!(declared.key.value, "dependencies");
    assert!(declared.optional);

    let graph = to_graph(&file).expect("the document converts");
    let schema = &graph.schemas[0];
    let field = schema
        .fields
        .iter()
        .find(|field| field.key.as_str() == "dependencies")
        .expect("the field survives conversion");
    let FieldType::Array(inner) = &field.field_type else {
        panic!("expected an array type, found {}", field.field_type);
    };
    let FieldType::Object(nested) = inner.as_ref() else {
        panic!("expected an array of objects, found {inner}");
    };
    assert_eq!(nested.len(), 2);
    assert_eq!(nested[0].key.as_str(), "name");
    assert!(nested[0].required);
    assert_eq!(nested[0].field_type, FieldType::Scalar(ScalarType::String));
    assert_eq!(nested[1].key.as_str(), "version");
    assert!(!nested[1].required, "an optional nested key stays optional");

    // The value is a list of objects, and the second omits the optional key.
    let stored = graph.nodes[0]
        .properties
        .iter()
        .find(|(key, _)| key.as_str() == "dependencies")
        .map(|(_, value)| value)
        .expect("the property survives conversion");
    let PropertyValue::List(items) = stored else {
        panic!("expected a list, found {}", stored.type_name());
    };
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(PropertyValue::is_map));
    let PropertyValue::Map(second) = &items[1] else {
        unreachable!("just asserted every element is an object");
    };
    assert_eq!(second.len(), 1, "the omitted optional key is simply absent");
}

#[test]
fn the_stored_graph_survives_a_container_round_trip() {
    let file = parse(DOCUMENT).expect("the document parses");
    let original = to_graph(&file).expect("the document converts");
    let decoded = decode_graph(&container_of(&original)).expect("the container decodes");
    assert_eq!(
        decoded, original,
        "an object value and an object field type must both survive the container"
    );
}

#[test]
fn a_written_container_declares_the_current_format_version_and_still_reads_its_predecessor() {
    let file = parse(DOCUMENT).expect("the document parses");
    let container = container_of(&to_graph(&file).expect("converts"));
    assert_eq!(container.version(), FORMAT_VERSION);
    assert_eq!(FORMAT_VERSION, 3);
    assert!(
        SUPPORTED_FORMAT_VERSIONS.contains(&2),
        "version 2 stays readable, because a container holds contributions no analyzer \
         can rebuild"
    );
}

#[test]
fn the_canonical_form_expands_an_object_and_keeps_a_scalar_list_inline() {
    let file = parse(DOCUMENT).expect("the document parses");
    let written = format(&file);

    // Canonical rule 6 asks for one field per line at every depth, so an object *type*
    // expands too. Collapsing it onto one line would rewrite a schema its author wrote
    // across several, which a canonical form has no reason to do.
    assert!(
        written.contains("  dependencies?: {\n    name: string,\n    version?: string\n  }[],\n"),
        "an object type must keep its shape:\n{written}"
    );

    // Canonical rule 8: the object list expands one entry per line.
    assert!(
        written.contains("  dependencies: [\n    {\n      name: \"serde\",\n"),
        "an object value must expand:\n{written}"
    );
    // Rule 7: no trailing comma, at any depth.
    assert!(
        !written.contains(",\n    }"),
        "no trailing comma:\n{written}"
    );
    // Keys sort inside the object; element order is data and is preserved.
    let serde_at = written.find("serde").expect("serde is written");
    let tokio_at = written.find("tokio").expect("tokio is written");
    assert!(serde_at < tokio_at, "element order is data:\n{written}");

    // A second pass is byte-identical, which is the whole point of a canonical form.
    let again = format(&parse(&written).expect("the canonical form parses"));
    assert_eq!(written, again, "formatting must be idempotent");

    // And the reformatted document still says the same thing. Compared field by field
    // rather than graph to graph: neither document states an `id`, so each conversion
    // mints a fresh one and two whole graphs would differ on identity alone.
    let reparsed = parse(&written).expect("parses");
    assert!(validate(&reparsed).is_empty());
    let before = to_graph(&file).expect("converts");
    let after = to_graph(&reparsed).expect("converts");
    assert_eq!(after.schemas, before.schemas, "the schema must survive");
    assert_eq!(
        after.nodes[0].properties, before.nodes[0].properties,
        "every property, including the nested object, must survive"
    );
    assert_eq!(after.nodes[0].labels, before.nodes[0].labels);
}

#[test]
fn a_scalar_list_stays_on_one_line() {
    let source = "@nost 4\n\nnode n: L {\n  tags: [\"b\", \"a\"]\n}\n";
    let file = parse(source).expect("parses");
    let written = format(&file);
    assert!(
        written.contains("  tags: [\"b\", \"a\"]\n"),
        "a list of scalars is compact data and stays inline:\n{written}"
    );
}

#[test]
fn a_nested_object_reports_the_key_that_violates_its_schema_by_path() {
    let source = "\
@nost 4

schema Project {
  dependencies?: {
    name: string
    version?: string
  }[]
}

node app: Project {
  dependencies: [{ version: 1 }]
}
";
    let file = parse(source).expect("parses");
    let found = validate(&file);

    let messages: Vec<&str> = found.iter().map(|d| d.message.as_str()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("dependencies[0].name") && m.contains("missing")),
        "a missing required nested key must be named by path: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("dependencies[0].version") && m.contains("string")),
        "a nested key of the wrong type must be named by path: {messages:?}"
    );

    // Soft by contract: a schema violation is a warning, so the document still converts.
    assert!(
        found
            .iter()
            .all(|d| d.severity == nostdb_core::diagnostic::Severity::Warning),
        "schema validation is soft"
    );
    to_graph(&file).expect("a violating document still converts");
}

#[test]
fn nesting_is_bounded_at_the_depth_the_contract_requires_every_reader_to_accept() {
    let at_limit = format!(
        "@nost 4\n\nschema S {{\n  a: {}string{}\n}}\n",
        "{ a: ".repeat(MAX_NESTING_DEPTH),
        " }".repeat(MAX_NESTING_DEPTH)
    );
    assert!(
        parse(&at_limit).is_ok(),
        "{MAX_NESTING_DEPTH} levels is the minimum every implementation must accept"
    );

    let past_limit = format!(
        "@nost 4\n\nschema S {{\n  a: {}string{}\n}}\n",
        "{ a: ".repeat(MAX_NESTING_DEPTH + 1),
        " }".repeat(MAX_NESTING_DEPTH + 1)
    );
    let error = parse(&past_limit).expect_err("one level past the limit is refused");
    assert!(
        error.message.contains("nests") && error.message.contains("maximum"),
        "the refusal must say what the limit is: {error}"
    );

    // The same bound applies to a value, not only to a type.
    let deep_value = format!(
        "@nost 4\n\nnode n: L {{\n  a: {}1{}\n}}\n",
        "[".repeat(MAX_NESTING_DEPTH + 1),
        "]".repeat(MAX_NESTING_DEPTH + 1)
    );
    assert!(
        parse(&deep_value).is_err(),
        "a value nesting past the limit is refused too"
    );
}

#[test]
fn an_object_literal_takes_no_contribution_block() {
    // Ownership attaches to a record, and an object is one property's value.
    let source = "@nost 4\n\nnode n: L {\n  detail: { name: \"a\", @by \"user\" {} }\n}\n";
    let error = parse(source).expect_err("a contribution inside an object is refused");
    assert!(error.range.start().line >= 1, "the refusal carries a range");
}
