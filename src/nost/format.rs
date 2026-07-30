//! The canonical formatter.
//!
//! Canonical output exists so a second format pass is byte-identical and a Git diff
//! shows graph change rather than layout churn.
//!
//! # Ordering
//!
//! Links sort by locator, then schemas and nodes by name, then edges by source endpoint,
//! target endpoint, relation, and identifier. Field keys, property keys, and label values
//! sort by Unicode scalar value, not locale collation, so canonical output does not
//! depend on the environment.
//!
//! An edge has no declaration name to sort by, so its key is what identifies it: the two
//! endpoints and the relation. Two edges may still agree on all three, which the language
//! contract permits, so the identifier breaks the tie and keeps the order total.
//!
//! # Blank lines
//!
//! One blank line separates the version header, the link group, and each schema, node, and
//! edge declaration. Link declarations are not separated from each other, because they are
//! single-line directives forming one group. The contract's wording is ambiguous on that
//! point, and the reading used here is recorded in the root progress file.
//!
//! # Separators
//!
//! Fields and properties are separated by commas. A trailing comma is accepted on input
//! and never written, so one set of records has one canonical spelling.

use super::{
    Comment, Comments, ContributionBlock, EdgeDeclaration, Endpoint, EvidenceBlock, EvidenceValue,
    NodeDeclaration, OwnerDeclaration, Property, RecordBody, SchemaDeclaration, SourceFile,
    Spanned, Value,
};

const INDENT: &str = "  ";

/// The reserved key holding a record identifier, which sorts ahead of everything else.
const ID_KEY: &str = "id";

struct Writer {
    out: String,
}

impl Writer {
    fn line(&mut self, depth: usize, text: &str) {
        for _ in 0..depth {
            self.out.push_str(INDENT);
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn blank(&mut self) {
        self.out.push('\n');
    }

    fn leading(&mut self, depth: usize, comments: &Comments) {
        for comment in &comments.leading {
            self.line(depth, &render_comment(comment));
        }
    }

    fn block_comments(&mut self, depth: usize, comments: &[Comment]) {
        for comment in comments {
            self.line(depth, &render_comment(comment));
        }
    }
}

fn render_comment(comment: &Comment) -> String {
    if comment.block {
        format!("/*{}*/", comment.text)
    } else {
        format!(
            "//{}{}",
            if comment.text.is_empty() { "" } else { " " },
            comment.text
        )
    }
}

fn with_trailing(mut text: String, comments: &Comments) -> String {
    if let Some(trailing) = &comments.trailing {
        text.push(' ');
        text.push_str(&render_comment(trailing));
    }
    text
}

fn escape_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => {
                out.push_str(&format!("\\u{{{:X}}}", u32::from(other)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn render_number(text: &str, float: bool) -> String {
    // A number is normalized when it can be read, and left as written when it cannot,
    // because an out-of-range literal is a semantic diagnostic the caller still needs to
    // see quoted exactly.
    if float {
        match text.parse::<f64>() {
            Ok(number) if number.is_finite() => format!("{number:?}"),
            _ => text.to_owned(),
        }
    } else {
        text.parse::<i64>()
            .map_or_else(|_| text.to_owned(), |number| number.to_string())
    }
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Boolean(true) => "true".to_owned(),
        Value::Boolean(false) => "false".to_owned(),
        Value::Integer(text) => render_number(text, false),
        Value::Float(text) => render_number(text, true),
        Value::String(text) => escape_string(text),
        Value::Bytes { digits, .. } => format!("bytes\"{}\"", digits.to_lowercase()),
        Value::DateTime(text) => format!("datetime\"{text}\""),
        Value::List(items) => {
            let rendered: Vec<String> =
                items.iter().map(|item| render_value(&item.value)).collect();
            format!("[{}]", rendered.join(", "))
        }
    }
}

fn render_endpoint(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Local(name) => name.value.clone(),
        Endpoint::Aliased { alias, name } => format!("{}::{}", alias.value, name.value),
        Endpoint::Locator { locator, name } => {
            format!("{}::{}", escape_string(&locator.value), name.value)
        }
    }
}

/// The identifier a record states, used only to break an ordering tie.
fn stated_id(record: &RecordBody) -> &str {
    record
        .properties
        .iter()
        .find(|property| property.key.value == ID_KEY)
        .and_then(|property| match &property.value.value {
            Value::String(text) => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("")
}

fn sorted_properties(properties: &[Property]) -> Vec<&Property> {
    let mut sorted: Vec<&Property> = properties.iter().collect();
    sorted.sort_by(|left, right| left.key.value.cmp(&right.key.value));
    sorted
}

/// Writes a comma-separated block, or `{}` when there is nothing to put in it.
///
/// `body` renders the entries; it returns whether it wrote anything, which decides
/// between the empty and the open form.
fn write_block(
    writer: &mut Writer,
    depth: usize,
    head: &str,
    comments: &Comments,
    empty: bool,
    body: impl FnOnce(&mut Writer),
) {
    if empty {
        writer.line(depth, &with_trailing(format!("{head} {{}}"), comments));
        return;
    }
    writer.line(depth, &with_trailing(format!("{head} {{"), comments));
    body(writer);
    writer.line(depth, "}");
}

fn write_record_body(writer: &mut Writer, depth: usize, head: &str, record: &RecordBody) {
    let empty = record.properties.is_empty()
        && record.contributions.is_empty()
        && record.block_comments.is_empty();
    write_block(writer, depth, head, &record.comments, empty, |writer| {
        let properties = sorted_properties(&record.properties);
        let last = properties.len().saturating_sub(1);
        for (index, property) in properties.iter().enumerate() {
            writer.leading(depth + 1, &property.comments);
            let separator = if index == last { "" } else { "," };
            let text = format!(
                "{}: {}{separator}",
                property.key.value,
                render_value(&property.value.value)
            );
            writer.line(depth + 1, &with_trailing(text, &property.comments));
        }

        for contribution in sorted_contributions(&record.contributions) {
            writer.blank();
            write_contribution(writer, depth + 1, contribution);
        }

        if !record.block_comments.is_empty() {
            if !record.contributions.is_empty() {
                writer.blank();
            }
            writer.block_comments(depth + 1, &record.block_comments);
        }
    });
}

/// An owner, which is one string.
fn render_owner(owner: &OwnerDeclaration) -> String {
    escape_string(&owner.name.value)
}

/// Contribution blocks in the order a canonical writer emits them.
fn sorted_contributions(contributions: &[ContributionBlock]) -> Vec<&ContributionBlock> {
    let mut sorted: Vec<&ContributionBlock> = contributions.iter().collect();
    sorted.sort_by(|left, right| {
        owner_key(&left.owner)
            .cmp(&owner_key(&right.owner))
            .then_with(|| {
                let left_unit = left.unit.as_ref().map(|u| u.value.as_str()).unwrap_or("");
                let right_unit = right.unit.as_ref().map(|u| u.value.as_str()).unwrap_or("");
                left_unit.cmp(right_unit)
            })
    });
    sorted
}

/// A total order over contribution blocks, matching what `convert`'s own key emits.
fn owner_key(owner: &OwnerDeclaration) -> (u8, String) {
    let rank = match owner.kind() {
        crate::contribution::OwnerKind::Analyzer => 0,
        crate::contribution::OwnerKind::AiAnalysis => 1,
        crate::contribution::OwnerKind::User => 2,
    };
    (rank, owner.name.value.clone())
}

fn write_contribution(writer: &mut Writer, depth: usize, contribution: &ContributionBlock) {
    writer.leading(depth, &contribution.comments);
    let mut head = format!("@by {}", render_owner(&contribution.owner));
    if let Some(unit) = &contribution.unit {
        head.push_str(&format!(" unit {}", escape_string(&unit.value)));
    }

    let empty = contribution.evidence.is_empty() && contribution.block_comments.is_empty();
    write_block(
        writer,
        depth,
        &head,
        &contribution.comments,
        empty,
        |writer| {
            for (index, evidence) in contribution.evidence.iter().enumerate() {
                if index > 0 {
                    writer.blank();
                }
                write_evidence(writer, depth + 1, evidence);
            }
            if !contribution.block_comments.is_empty() {
                if !contribution.evidence.is_empty() {
                    writer.blank();
                }
                writer.block_comments(depth + 1, &contribution.block_comments);
            }
        },
    );
}

fn render_evidence_value(value: &EvidenceValue) -> String {
    match value {
        EvidenceValue::Text(text) => escape_string(text),
        EvidenceValue::Enumerator { name, score } => match score {
            Some(score) => format!("{name}({})", render_number(score, true)),
            None => name.clone(),
        },
    }
}

fn write_evidence(writer: &mut Writer, depth: usize, evidence: &EvidenceBlock) {
    writer.leading(depth, &evidence.comments);
    let empty = evidence.fields.is_empty() && evidence.block_comments.is_empty();
    write_block(
        writer,
        depth,
        "@evidence",
        &evidence.comments,
        empty,
        |writer| {
            let mut fields: Vec<_> = evidence.fields.iter().collect();
            fields.sort_by(|left, right| left.key.value.cmp(&right.key.value));
            let last = fields.len().saturating_sub(1);
            for (index, field) in fields.iter().enumerate() {
                writer.leading(depth + 1, &field.comments);
                let separator = if index == last { "" } else { "," };
                let text = format!(
                    "{}: {}{separator}",
                    field.key.value,
                    render_evidence_value(&field.value.value)
                );
                writer.line(depth + 1, &with_trailing(text, &field.comments));
            }
            writer.block_comments(depth + 1, &evidence.block_comments);
        },
    );
}

fn write_schema(writer: &mut Writer, schema: &SchemaDeclaration) {
    writer.leading(0, &schema.comments);
    let mut head = format!("schema {}", schema.name.value);
    if let Some(constraint) = &schema.endpoints {
        head.push_str(&format!(
            " ({} -> {})",
            constraint.source.value, constraint.target.value
        ));
    }

    let empty = schema.fields.is_empty() && schema.block_comments.is_empty();
    write_block(writer, 0, &head, &schema.comments, empty, |writer| {
        let mut fields: Vec<_> = schema.fields.iter().collect();
        fields.sort_by(|left, right| left.key.value.cmp(&right.key.value));
        let last = fields.len().saturating_sub(1);
        for (index, field) in fields.iter().enumerate() {
            writer.leading(1, &field.comments);
            let separator = if index == last { "" } else { "," };
            let text = format!(
                "{}{}: {}{separator}",
                field.key.value,
                if field.optional { "?" } else { "" },
                field.field_type.value
            );
            writer.line(1, &with_trailing(text, &field.comments));
        }
        writer.block_comments(1, &schema.block_comments);
    });
}

fn sorted_schema_names(schemas: &[Spanned<String>]) -> Vec<&str> {
    let mut sorted: Vec<&str> = schemas.iter().map(|name| name.value.as_str()).collect();
    sorted.sort_unstable();
    sorted
}

fn write_node(writer: &mut Writer, node: &NodeDeclaration) {
    writer.leading(0, &node.record.comments);
    let head = format!(
        "node {}: {}",
        node.name.value,
        sorted_schema_names(&node.schemas).join(", ")
    );
    write_record_body(writer, 0, &head, &node.record);
}

fn write_edge(writer: &mut Writer, edge: &EdgeDeclaration) {
    writer.leading(0, &edge.record.comments);
    let head = format!(
        "edge {} -> {} :{}",
        render_endpoint(&edge.source),
        render_endpoint(&edge.target),
        edge.relation.value
    );
    write_record_body(writer, 0, &head, &edge.record);
}

/// Renders a parsed file in canonical form.
///
/// Formatting the result reproduces it byte for byte.
#[must_use]
pub fn format(file: &SourceFile) -> String {
    let mut writer = Writer { out: String::new() };

    writer.leading(0, &file.version_comments);
    writer.line(
        0,
        &with_trailing(
            format!("@nost {}", file.version.value),
            &file.version_comments,
        ),
    );

    if !file.links.is_empty() {
        writer.blank();
        let mut links: Vec<_> = file.links.iter().collect();
        links.sort_by(|left, right| left.source.value.cmp(&right.source.value));
        for link in links {
            writer.leading(0, &link.comments);
            let mut text = format!("@link {}", escape_string(&link.source.value));
            if let Some(alias) = &link.alias {
                text.push_str(&format!(" as {}", alias.value));
            }
            writer.line(0, &with_trailing(text, &link.comments));
        }
    }

    let mut schemas: Vec<&SchemaDeclaration> = file.schemas.iter().collect();
    schemas.sort_by(|left, right| left.name.value.cmp(&right.name.value));
    for schema in schemas {
        writer.blank();
        write_schema(&mut writer, schema);
    }

    let mut nodes: Vec<&NodeDeclaration> = file.nodes.iter().collect();
    nodes.sort_by(|left, right| left.name.value.cmp(&right.name.value));
    for node in nodes {
        writer.blank();
        write_node(&mut writer, node);
    }

    let mut edges: Vec<&EdgeDeclaration> = file.edges.iter().collect();
    edges.sort_by(|left, right| {
        render_endpoint(&left.source)
            .cmp(&render_endpoint(&right.source))
            .then_with(|| render_endpoint(&left.target).cmp(&render_endpoint(&right.target)))
            .then_with(|| left.relation.value.cmp(&right.relation.value))
            .then_with(|| stated_id(&left.record).cmp(stated_id(&right.record)))
    });
    for edge in edges {
        writer.blank();
        write_edge(&mut writer, edge);
    }

    if !file.trailing_comments.is_empty() {
        writer.blank();
        writer.block_comments(0, &file.trailing_comments);
    }

    writer.out
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::*;

    fn round_trip(source: &str) -> String {
        format(&parse(source).expect("must parse"))
    }

    #[test]
    fn formatting_is_idempotent() {
        for source in [
            "@nost 3\n",
            "@nost 3\n@link \"./b\"\n@link \"./a\" as a\n",
            "@nost 3\nschema L {\n b?: integer,\n a: string,\n}\nnode z: B, A {\n k: 1,\n}\nnode a: L {}\nedge a -> z :R {\n q: [1, 2],\n}\n",
            "// lead\n@nost 3 // trail\n\n// about\nnode n: L {\n // key\n k: \"v\", // after\n}\n",
            "@nost 3\nnode n: L {\n k: 1,\n\n @by \"r\" unit \"u_1\" {\n  @evidence {\n   source: \"./\",\n   confidence: inferred(0.5),\n  }\n }\n\n @by \"user\" {}\n}\n",
        ] {
            let once = round_trip(source);
            let twice = round_trip(&once);
            assert_eq!(once, twice, "not idempotent for:\n{source}\ngave:\n{once}");
        }
    }

    #[test]
    fn output_is_sorted_deterministically() {
        let formatted = round_trip(
            "@nost 3\n@link \"./z\"\n@link \"./a\"\nnode z: L {}\nnode a: L {}\nschema L {}\n",
        );
        assert!(formatted.find("\"./a\"").unwrap() < formatted.find("\"./z\"").unwrap());
        assert!(formatted.find("node a").unwrap() < formatted.find("node z").unwrap());
        // Schemas come before nodes regardless of where they were written.
        assert!(formatted.find("schema L").unwrap() < formatted.find("node a").unwrap());
    }

    #[test]
    fn schema_names_and_keys_are_sorted_and_nodes_precede_edges() {
        let formatted =
            round_trip("@nost 3\nedge a -> a :R {}\nnode a: Zed, Alpha {\n zz: 1,\n aa: 2,\n}\n");
        assert!(formatted.contains("node a: Alpha, Zed"), "{formatted}");
        assert!(formatted.find("aa: 2").unwrap() < formatted.find("zz: 1").unwrap());
        assert!(formatted.find("node a").unwrap() < formatted.find("edge a").unwrap());
    }

    #[test]
    fn edges_sort_by_endpoints_then_relation_then_identifier() {
        let formatted =
            round_trip("@nost 3\nedge b -> a :R {}\nedge a -> b :Z {}\nedge a -> b :A {}\n");
        let first = formatted.find("edge a -> b :A").unwrap();
        let second = formatted.find("edge a -> b :Z").unwrap();
        let third = formatted.find("edge b -> a :R").unwrap();
        assert!(first < second && second < third, "{formatted}");
    }

    #[test]
    fn properties_are_comma_separated_with_no_trailing_comma() {
        let formatted = round_trip("@nost 3\nnode n: L {\n a: 1,\n b: 2,\n}\n");
        assert!(formatted.contains("a: 1,\n"), "{formatted}");
        assert!(formatted.contains("b: 2\n"), "{formatted}");
        assert!(!formatted.contains("b: 2,"), "{formatted}");
    }

    #[test]
    fn an_optional_field_keeps_its_question_mark() {
        let formatted = round_trip("@nost 3\nschema S {\n a?: string[],\n b: integer,\n}\n");
        assert!(formatted.contains("a?: string[],"), "{formatted}");
        assert!(formatted.contains("b: integer\n"), "{formatted}");
    }

    #[test]
    fn an_endpoint_constraint_is_reproduced() {
        let formatted = round_trip("@nost 3\nschema R (A -> B) {\n s?: datetime,\n}\n");
        assert!(formatted.contains("schema R (A -> B) {"), "{formatted}");
    }

    #[test]
    fn an_empty_block_is_written_as_braces() {
        let formatted = round_trip("@nost 3\nnode a: L {\n}\nschema L {\n}\n");
        assert!(formatted.contains("node a: L {}"), "{formatted}");
        assert!(formatted.contains("schema L {}"), "{formatted}");
    }

    #[test]
    fn contributions_sort_analyzer_then_ai_then_user() {
        let formatted = round_trip(
            "@nost 3\nnode n: L {\n @by \"user\" {}\n @by \"ai:sha256:a\" {}\n @by \"z\" {}\n @by \"a\" {}\n}\n",
        );
        let analyzer_a = formatted.find("@by \"a\"").unwrap();
        let analyzer_z = formatted.find("@by \"z\"").unwrap();
        let ai = formatted.find("@by \"ai:sha256:a\"").unwrap();
        let user = formatted.find("@by \"user\"").unwrap();
        assert!(analyzer_a < analyzer_z, "{formatted}");
        assert!(analyzer_z < ai, "{formatted}");
        assert!(ai < user, "{formatted}");
    }

    #[test]
    fn every_comment_survives_a_round_trip() {
        let source = "// one\n@nost 3 // two\n\n// three\n@link \"./a\"\n\n\
            // four\nnode n: L { // five\n k: 1, // six\n // seven\n}\n\n// eight\n";
        let parsed = parse(source).unwrap();
        let before = parsed.all_comments().len();
        assert_eq!(before, 8, "the fixture should carry eight comments");

        let formatted = format(&parsed);
        let reparsed = parse(&formatted).expect("formatted output must parse");
        assert_eq!(reparsed.all_comments().len(), before, "{formatted}");
        assert_eq!(format(&reparsed), formatted);
    }

    #[test]
    fn a_comment_inside_a_contribution_survives() {
        let source = "@nost 3\nnode n: L {\n @by \"user\" { // owner\n  // inside\n }\n}\n";
        let parsed = parse(source).unwrap();
        assert_eq!(parsed.all_comments().len(), 2);
        let formatted = format(&parsed);
        let reparsed = parse(&formatted).expect("formatted output must parse");
        assert_eq!(reparsed.all_comments().len(), 2, "{formatted}");
        assert_eq!(format(&reparsed), formatted);
    }

    #[test]
    fn a_number_is_normalized_when_it_can_be_read() {
        let formatted = round_trip("@nost 3\nnode a: L {\n i: 007,\n f: 2E+1,\n}\n");
        assert!(formatted.contains("i: 7"), "{formatted}");
        assert!(formatted.contains("f: 20.0"), "{formatted}");
    }

    #[test]
    fn an_unreadable_number_is_left_exactly_as_written() {
        // An out-of-range integer is a semantic diagnostic, so the formatter must not
        // silently alter the text a diagnostic will quote.
        let formatted = round_trip("@nost 3\nnode a: L {\n i: 9223372036854775808,\n}\n");
        assert!(formatted.contains("i: 9223372036854775808"), "{formatted}");
    }

    #[test]
    fn bytes_digits_are_lower_cased_and_strings_are_re_escaped() {
        let formatted =
            round_trip("@nost 3\nnode a: L {\n b: bytes\"DEADbeef\",\n s: \"tab\\there\",\n}\n");
        assert!(formatted.contains("bytes\"deadbeef\""), "{formatted}");
        assert!(formatted.contains("\"tab\\there\""), "{formatted}");
    }

    #[test]
    fn the_file_ends_with_exactly_one_newline() {
        for source in ["@nost 3\n", "@nost 3\nnode a: L {}\n"] {
            let formatted = round_trip(source);
            assert!(formatted.ends_with('\n'));
            assert!(!formatted.ends_with("\n\n"), "{formatted:?}");
        }
    }
}
