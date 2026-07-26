//! The canonical formatter.
//!
//! Canonical output exists so a second format pass is byte-identical and a Git diff
//! shows graph change rather than layout churn.
//!
//! # Ordering
//!
//! Links sort by locator, modules by name, and within a module nodes come before edges,
//! each sorted by name. Labels and property keys sort by Unicode scalar value, not
//! locale collation, so canonical output does not depend on the environment.
//!
//! # Blank lines
//!
//! One blank line separates the version header, the link group, and each module; and
//! one separates sibling declarations inside a module body. Link declarations are not
//! separated from each other, because they are single-line directives forming one
//! group. The contract's wording is ambiguous on that point, and the reading used here
//! is recorded in the root progress file.

use super::{
    Comment, Comments, EdgeDeclaration, Endpoint, ModuleDeclaration, NodeDeclaration, Property,
    SourceFile, Spanned, Value,
};

const INDENT: &str = "  ";

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

fn render_value(value: &Value) -> String {
    match value {
        Value::Boolean(true) => "true".to_owned(),
        Value::Boolean(false) => "false".to_owned(),
        // A number is normalized when it can be read, and left as written when it
        // cannot, because an out-of-range literal is a semantic diagnostic the caller
        // still needs to see quoted exactly.
        Value::Integer(text) => text
            .parse::<i64>()
            .map_or_else(|_| text.clone(), |number| number.to_string()),
        Value::Float(text) => match text.parse::<f64>() {
            Ok(number) if number.is_finite() => format!("{number:?}"),
            _ => text.clone(),
        },
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

fn sorted_labels(labels: &[Spanned<String>]) -> Vec<&str> {
    let mut sorted: Vec<&str> = labels.iter().map(|label| label.value.as_str()).collect();
    sorted.sort_unstable();
    sorted
}

fn sorted_properties(properties: &[Property]) -> Vec<&Property> {
    let mut sorted: Vec<&Property> = properties.iter().collect();
    sorted.sort_by(|left, right| left.key.value.cmp(&right.key.value));
    sorted
}

fn write_property_block(
    writer: &mut Writer,
    depth: usize,
    head: String,
    comments: &Comments,
    properties: &[Property],
    block_comments: &[Comment],
) {
    if properties.is_empty() && block_comments.is_empty() {
        writer.line(depth, &with_trailing(format!("{head} {{}}"), comments));
        return;
    }
    writer.line(depth, &with_trailing(format!("{head} {{"), comments));
    for property in sorted_properties(properties) {
        writer.leading(depth + 1, &property.comments);
        let text = format!(
            "{}: {}",
            property.key.value,
            render_value(&property.value.value)
        );
        writer.line(depth + 1, &with_trailing(text, &property.comments));
    }
    writer.block_comments(depth + 1, block_comments);
    writer.line(depth, "}");
}

fn write_node(writer: &mut Writer, depth: usize, node: &NodeDeclaration) {
    writer.leading(depth, &node.comments);
    let labels = sorted_labels(&node.labels)
        .into_iter()
        .map(|label| format!(":{label}"))
        .collect::<Vec<_>>()
        .join(" ");
    let head = format!(
        "node {} id {} {labels}",
        node.name.value,
        escape_string(&node.id.value)
    );
    write_property_block(
        writer,
        depth,
        head,
        &node.comments,
        &node.properties,
        &node.block_comments,
    );
}

fn write_edge(writer: &mut Writer, depth: usize, edge: &EdgeDeclaration) {
    writer.leading(depth, &edge.comments);
    let head = format!(
        "edge {} id {} :{} ({} -> {})",
        edge.name.value,
        escape_string(&edge.id.value),
        edge.relation.value,
        render_endpoint(&edge.source),
        render_endpoint(&edge.target)
    );
    write_property_block(
        writer,
        depth,
        head,
        &edge.comments,
        &edge.properties,
        &edge.block_comments,
    );
}

fn write_module(writer: &mut Writer, module: &ModuleDeclaration) {
    writer.leading(0, &module.comments);
    let mut head = format!(
        "module {} id {}",
        module.name.value,
        escape_string(&module.id.value)
    );
    if let Some(source) = &module.source {
        head.push_str(&format!(" source {}", escape_string(&source.value)));
    }

    let mut nodes: Vec<&NodeDeclaration> = module.nodes.iter().collect();
    nodes.sort_by(|left, right| left.name.value.cmp(&right.name.value));
    let mut edges: Vec<&EdgeDeclaration> = module.edges.iter().collect();
    edges.sort_by(|left, right| left.name.value.cmp(&right.name.value));

    if nodes.is_empty() && edges.is_empty() && module.block_comments.is_empty() {
        writer.line(0, &with_trailing(format!("{head} {{}}"), &module.comments));
        return;
    }

    writer.line(0, &with_trailing(format!("{head} {{"), &module.comments));
    let mut first = true;
    for node in nodes {
        if !first {
            writer.blank();
        }
        first = false;
        write_node(writer, 1, node);
    }
    for edge in edges {
        if !first {
            writer.blank();
        }
        first = false;
        write_edge(writer, 1, edge);
    }
    if !module.block_comments.is_empty() {
        if !first {
            writer.blank();
        }
        writer.block_comments(1, &module.block_comments);
    }
    writer.line(0, "}");
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

    let mut modules: Vec<&ModuleDeclaration> = file.modules.iter().collect();
    modules.sort_by(|left, right| left.name.value.cmp(&right.name.value));
    for module in modules {
        writer.blank();
        write_module(&mut writer, module);
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
            "@nost 1\n",
            "@nost 1\n@link \"./b\"\n@link \"./a\" as a\n",
            "@nost 1\nmodule m id \"m_1\" source \"src/a.rs\" {\n node z id \"n_2\" :B :A { k: 1 }\n node a id \"n_1\" :L {}\n edge e id \"e_1\" :R (a -> z) { q: [1, 2] }\n}\n",
            "// lead\n@nost 1 // trail\n\nmodule m id \"m_1\" {\n // about\n node n id \"n_1\" :L {\n  // key\n  k: \"v\" // after\n }\n}\n",
        ] {
            let once = round_trip(source);
            let twice = round_trip(&once);
            assert_eq!(once, twice, "not idempotent for:\n{source}");
        }
    }

    #[test]
    fn output_is_sorted_deterministically() {
        let formatted = round_trip(
            "@nost 1\n@link \"./z\"\n@link \"./a\"\nmodule z id \"m_2\" {}\nmodule a id \"m_1\" {}\n",
        );
        let a_link = formatted.find("\"./a\"").unwrap();
        let z_link = formatted.find("\"./z\"").unwrap();
        assert!(a_link < z_link);
        let a_module = formatted.find("module a").unwrap();
        let z_module = formatted.find("module z").unwrap();
        assert!(a_module < z_module);
    }

    #[test]
    fn labels_and_keys_are_sorted_and_nodes_precede_edges() {
        let formatted = round_trip(
            "@nost 1\nmodule m id \"m_1\" {\n edge e id \"e_1\" :R (a -> a) {}\n node a id \"n_1\" :Zed :Alpha { zz: 1 aa: 2 }\n}\n",
        );
        assert!(formatted.contains(":Alpha :Zed"));
        assert!(formatted.find("aa: 2").unwrap() < formatted.find("zz: 1").unwrap());
        assert!(formatted.find("node a").unwrap() < formatted.find("edge e").unwrap());
    }

    #[test]
    fn an_empty_block_is_written_as_braces() {
        let formatted =
            round_trip("@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L {\n }\n}\n");
        assert!(formatted.contains("node a id \"n_1\" :L {}"), "{formatted}");
    }

    #[test]
    fn every_comment_survives_a_round_trip() {
        let source = "// one\n@nost 1 // two\n\n// three\n@link \"./a\"\n\n\
            module m id \"m_1\" { // four\n // five\n node n id \"n_1\" :L {\n  k: 1 // six\n  // seven\n }\n // eight\n}\n";
        let parsed = parse(source).unwrap();
        let before = parsed.all_comments().len();
        assert_eq!(before, 8, "the fixture should carry eight comments");

        let formatted = format(&parsed);
        let reparsed = parse(&formatted).expect("formatted output must parse");
        assert_eq!(reparsed.all_comments().len(), before, "{formatted}");
        assert_eq!(format(&reparsed), formatted);
    }

    #[test]
    fn a_number_is_normalized_when_it_can_be_read() {
        let formatted = round_trip(
            "@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L { i: 007 f: 2E+1 }\n}\n",
        );
        assert!(formatted.contains("i: 7"), "{formatted}");
        assert!(formatted.contains("f: 20.0"), "{formatted}");
    }

    #[test]
    fn an_unreadable_number_is_left_exactly_as_written() {
        // An out-of-range integer is a semantic diagnostic, so the formatter must not
        // silently alter the text a diagnostic will quote.
        let formatted = round_trip(
            "@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L { i: 9223372036854775808 }\n}\n",
        );
        assert!(formatted.contains("i: 9223372036854775808"), "{formatted}");
    }

    #[test]
    fn bytes_digits_are_lower_cased_and_strings_are_re_escaped() {
        let formatted = round_trip(
            "@nost 1\nmodule m id \"m_1\" {\n node a id \"n_1\" :L { b: bytes\"DEADbeef\" s: \"tab\\there\" }\n}\n",
        );
        assert!(formatted.contains("bytes\"deadbeef\""), "{formatted}");
        assert!(formatted.contains("\"tab\\there\""), "{formatted}");
    }

    #[test]
    fn the_file_ends_with_exactly_one_newline() {
        for source in ["@nost 1\n", "@nost 1\nmodule m id \"m_1\" {}\n"] {
            let formatted = round_trip(source);
            assert!(formatted.ends_with('\n'));
            assert!(!formatted.ends_with("\n\n"), "{formatted:?}");
        }
    }
}
