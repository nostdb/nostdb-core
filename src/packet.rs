//! The analysis packet a Skill sends instead of a repository.
//!
//! Root PRD section 17.5 opens with the prohibition the rest of this module exists to make
//! structural: a Skill MUST NOT send an entire repository to AI by default.
//!
//! # Compact by construction, not by discipline
//!
//! A packet is built from **one source unit** and the units an edge reaches from it. Its
//! size is bounded by that unit's own contents and a fixed neighbour budget, so it does not
//! grow when the repository does.
//!
//! That is deliberately a property of the shape rather than a rule somebody follows. A
//! packet builder that took a graph and a filter would be one wrong filter away from sending
//! everything, and the failure would be invisible: a larger prompt looks like a more
//! thorough one right up until the bill arrives.
//!
//! # Anchored on the unit a contribution names
//!
//! `source_unit` is the same identity a [`crate::contribution::Contribution`] carries. That
//! is what lets an enrichment's result be replaced exactly the way an analyzer's is — a
//! packet derived from one unit produces contributions for that unit, and a later run
//! withdraws precisely those.
//!
//! # What a packet does not carry
//!
//! Not source it has no reason to include: an excerpt is selected and bounded, and a whole
//! file never travels. Not a credential, which cannot be in the graph because a file that
//! looked like one was never scanned. And not the deterministic edges already established —
//! those are summarized so a model can *see* them, precisely so it is not asked to
//! rediscover them and cannot present a rediscovery as a new fact.

use crate::contribution::Owner;
use crate::encoding::Graph;
use crate::evidence::SourceRange;
use crate::graph::{Node, NodeReference};
use crate::id::{LocalNodeId, SourceUnitId};
use crate::property::PropertyValue;
use std::collections::{BTreeMap, BTreeSet};

/// Version of the packet contract.
pub const PACKET_VERSION: u32 = 1;

/// How many neighbouring units a packet may summarize.
///
/// Fixed rather than configurable. The point of a bound is that it holds; a setting for it
/// would be a setting somebody raises the first time a packet looks thin, which is exactly
/// when the repository is large enough for the bound to matter.
pub const MAX_NEIGHBOURING_UNITS: usize = 8;

/// How many evidence excerpts a packet may carry.
pub const MAX_EVIDENCE_SPANS: usize = 16;

/// The longest excerpt, in bytes.
///
/// An excerpt is meant to show a model the shape of something, not to ship a file. Anything
/// longer than this is a file arriving one span at a time.
pub const MAX_EXCERPT_BYTES: usize = 2000;

/// One record the packet describes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolSummary {
    /// The record.
    pub id: LocalNodeId,
    /// Its labels.
    pub labels: Vec<String>,
    /// Its name, when it has one.
    pub name: Option<String>,
    /// Where it is, when that is recorded.
    pub path: Option<String>,
}

/// One relation the packet describes.
///
/// Summarized so a model can see what is already established. Section 17.5 forbids AI from
/// re-emitting a deterministic import, call, inheritance, or package edge as an independent
/// fact, and showing them is how that prohibition becomes possible to obey rather than only
/// possible to violate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeSummary {
    /// Where it starts.
    pub from: LocalNodeId,
    /// Where it ends.
    pub to: LocalNodeId,
    /// What it is.
    pub relation: String,
}

/// A name that resolved to nothing.
///
/// The first thing section 17.5 prioritizes for enrichment, and the reason: a deterministic
/// analyzer already found everything it can, so what it could not resolve is exactly where a
/// model has something to add.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceSummary {
    /// The record that refers.
    pub from: LocalNodeId,
    /// The name it refers to.
    pub name: String,
}

/// A bounded excerpt of source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceExcerpt {
    /// Which file.
    pub path: String,
    /// Where in it.
    pub range: SourceRange,
    /// The text, truncated to [`MAX_EXCERPT_BYTES`].
    pub text: String,
    /// Whether the text was cut.
    ///
    /// Stated rather than inferred from the length. A model shown a truncated excerpt that
    /// does not say so may reason about what the code does *after* the cut, and be confident
    /// about something it never saw.
    pub truncated: bool,
}

/// A unit reachable from the anchored one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceUnitSummary {
    /// The unit.
    pub source_unit: SourceUnitId,
    /// Its path, when one is recorded.
    pub path: Option<String>,
    /// How many records it holds.
    pub records: u64,
}

/// A compact, versioned description of one source unit and its surroundings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisPacket {
    /// Version of this contract.
    pub packet_version: u32,
    /// The unit this packet is derived from, and that its results belong to.
    pub source_unit: SourceUnitId,
    /// The records that unit holds.
    pub symbols: Vec<SymbolSummary>,
    /// Relations among them, and to their neighbours.
    pub structural_edges: Vec<EdgeSummary>,
    /// Names that resolved to nothing.
    pub unresolved_references: Vec<ReferenceSummary>,
    /// Bounded excerpts a caller selected.
    pub selected_evidence_spans: Vec<SourceExcerpt>,
    /// Units an edge reaches from this one.
    pub neighboring_units: Vec<SourceUnitSummary>,
}

impl AnalysisPacket {
    /// How many records this packet describes, across every part of it.
    ///
    /// The number a budget estimate is built from. Reported rather than recomputed by a
    /// caller, so the thing being budgeted and the thing being sent cannot diverge.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.symbols.len()
            + self.structural_edges.len()
            + self.unresolved_references.len()
            + self.selected_evidence_spans.len()
            + self.neighboring_units.len()
    }

    /// The bytes this packet would carry, excluding envelope overhead.
    #[must_use]
    pub fn content_bytes(&self) -> usize {
        self.selected_evidence_spans
            .iter()
            .map(|span| span.text.len())
            .sum::<usize>()
            + self
                .symbols
                .iter()
                .map(|symbol| symbol.name.as_ref().map_or(0, String::len))
                .sum::<usize>()
    }

    /// Reports whether this packet would tell a model anything.
    ///
    /// A unit with no records and nothing unresolved is one an analyzer already covered
    /// completely. Sending it would spend tokens to be told what is already known.
    #[must_use]
    pub fn is_worth_sending(&self) -> bool {
        !self.unresolved_references.is_empty() || !self.symbols.is_empty()
    }
}

/// Builds a packet for one source unit.
///
/// `excerpts` are supplied by the caller rather than read here: the Engine does not hold
/// source, and a packet builder that read files would be one that could read a file the
/// scanner had deliberately withheld.
#[must_use]
pub fn build(
    graph: &Graph,
    source_unit: SourceUnitId,
    excerpts: &[SourceExcerpt],
) -> AnalysisPacket {
    let owned: BTreeSet<LocalNodeId> = graph
        .nodes
        .iter()
        .filter(|node| holds(node, source_unit))
        .map(|node| node.id)
        .collect();

    let symbols: Vec<SymbolSummary> = graph
        .nodes
        .iter()
        .filter(|node| owned.contains(&node.id))
        .map(|node| SymbolSummary {
            id: node.id,
            labels: node
                .labels
                .iter()
                .map(|label| label.as_str().to_owned())
                .collect(),
            name: text(node, "name"),
            path: text(node, "path"),
        })
        .collect();

    // Edges with at least one endpoint in this unit. An edge wholly outside it is somebody
    // else's fact and belongs in somebody else's packet.
    let mut structural_edges = Vec::new();
    let mut neighbours: BTreeMap<SourceUnitId, (Option<String>, u64)> = BTreeMap::new();
    for edge in &graph.edges {
        let (NodeReference::Local(from), NodeReference::Local(to)) = (&edge.source, &edge.target)
        else {
            continue;
        };
        let (inside_from, inside_to) = (owned.contains(from), owned.contains(to));
        if !inside_from && !inside_to {
            continue;
        }
        structural_edges.push(EdgeSummary {
            from: *from,
            to: *to,
            relation: edge.relation.as_str().to_owned(),
        });

        let outside = if inside_from { to } else { from };
        if let Some(node) = graph.nodes.iter().find(|node| node.id == *outside)
            && let Some(unit) = unit_of(node)
            && unit != source_unit
        {
            let entry = neighbours.entry(unit).or_insert((text(node, "path"), 0));
            entry.1 += 1;
        }
    }

    // Bounded here rather than trusted to be small. A unit at the centre of a repository has
    // hundreds of neighbours, and the packet that describes it must not.
    let neighboring_units: Vec<SourceUnitSummary> = neighbours
        .into_iter()
        .take(MAX_NEIGHBOURING_UNITS)
        .map(|(source_unit, (path, records))| SourceUnitSummary {
            source_unit,
            path,
            records,
        })
        .collect();

    AnalysisPacket {
        packet_version: PACKET_VERSION,
        source_unit,
        symbols,
        structural_edges,
        // Nothing here yet produces an unresolved-reference record in the graph; the builder
        // reads them rather than inventing them, so this fills in when one does.
        unresolved_references: Vec::new(),
        selected_evidence_spans: excerpts
            .iter()
            .take(MAX_EVIDENCE_SPANS)
            .map(truncated)
            .collect(),
        neighboring_units,
    }
}

/// Cuts an excerpt to the permitted length, saying so when it cut.
fn truncated(excerpt: &SourceExcerpt) -> SourceExcerpt {
    if excerpt.text.len() <= MAX_EXCERPT_BYTES {
        return excerpt.clone();
    }
    // Cut on a character boundary, since a packet is text and half a scalar is not.
    let mut end = MAX_EXCERPT_BYTES;
    while end > 0 && !excerpt.text.is_char_boundary(end) {
        end -= 1;
    }
    SourceExcerpt {
        text: excerpt.text[..end].to_owned(),
        truncated: true,
        ..excerpt.clone()
    }
}

/// Reports whether a record carries an analyzer contribution for one unit.
fn holds(node: &Node, source_unit: SourceUnitId) -> bool {
    node.contributions.iter().any(|contribution| {
        contribution.source_unit == source_unit
            && matches!(contribution.owner, Owner::Analyzer { .. })
    })
}

/// The unit an analyzer derived a record from, when one did.
fn unit_of(node: &Node) -> Option<SourceUnitId> {
    node.contributions
        .iter()
        .find(|contribution| matches!(contribution.owner, Owner::Analyzer { .. }))
        .map(|contribution| contribution.source_unit)
}

fn text(node: &Node, key: &str) -> Option<String> {
    node.properties
        .iter()
        .find_map(|(held, value)| match value {
            PropertyValue::String(found) if held.as_str() == key => Some(found.clone()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::SourcePosition;
    use crate::scan::ScanOptions;
    use std::fs;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("nostdb-core-packet-{label}"));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).expect("temporary directory");
            Self(base)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A built graph, so the packet is tested against what a build actually produces rather
    /// than against a graph shaped to suit it.
    fn built(dir: &TempDir, files: &[(&str, &str)]) -> crate::project::Project {
        let project = crate::project::Project::initialize(&dir.0).expect("initialize");
        for (path, source) in files {
            let full = dir.0.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).expect("parent");
            }
            fs::write(full, source).expect("write");
        }
        let registry = crate::analyze::builtin_registry().expect("registry");
        project
            .build(&registry, &ScanOptions::default(), false)
            .expect("build");
        project
    }

    fn unit_for(graph: &Graph, path: &str) -> SourceUnitId {
        let node = graph
            .nodes
            .iter()
            .find(|node| text(node, "path").as_deref() == Some(path))
            .unwrap_or_else(|| panic!("no record for {path}"));
        unit_of(node).expect("an analyzer contribution")
    }

    fn excerpt(text: &str) -> SourceExcerpt {
        SourceExcerpt {
            path: "src/a.rs".to_owned(),
            range: SourceRange::new(
                SourcePosition {
                    line: 1,
                    column: 1,
                    offset: 0,
                },
                SourcePosition {
                    line: 2,
                    column: 1,
                    offset: 10,
                },
            )
            .expect("a range"),
            text: text.to_owned(),
            truncated: false,
        }
    }

    #[test]
    fn a_packet_describes_the_unit_it_is_anchored_on_and_not_the_repository() {
        // The prohibition section 17.5 opens with, made a property of the shape: the packet
        // holds one unit's records however many units the project has.
        let dir = TempDir::new("anchored");
        let project = built(
            &dir,
            &[
                ("src/a.rs", "fn a_one() {}\nfn a_two() {}\n"),
                ("src/b.rs", "fn b_one() {}\n"),
                ("src/c.rs", "fn c_one() {}\n"),
            ],
        );
        let graph = project.read_graph().expect("graph");
        let unit = unit_for(&graph, "src/a.rs");
        let packet = build(&graph, unit, &[]);

        assert_eq!(packet.packet_version, PACKET_VERSION);
        assert_eq!(packet.source_unit, unit);
        let names: Vec<&str> = packet
            .symbols
            .iter()
            .filter_map(|symbol| symbol.name.as_deref())
            .collect();
        assert!(names.contains(&"a_one"), "{names:?}");
        assert!(names.contains(&"a_two"), "{names:?}");
        assert!(
            !names.contains(&"b_one"),
            "another unit's records are not here: {names:?}"
        );
        assert!(!names.contains(&"c_one"), "{names:?}");
    }

    #[test]
    fn the_anchor_is_the_identity_a_contribution_names() {
        // What lets an enrichment's result be replaced exactly the way an analyzer's is.
        let dir = TempDir::new("anchor-identity");
        let project = built(&dir, &[("src/a.rs", "fn a_one() {}\n")]);
        let graph = project.read_graph().expect("graph");
        let unit = unit_for(&graph, "src/a.rs");
        let packet = build(&graph, unit, &[]);

        for symbol in &packet.symbols {
            let node = graph
                .nodes
                .iter()
                .find(|node| node.id == symbol.id)
                .expect("the record");
            assert!(
                holds(node, packet.source_unit),
                "every symbol belongs to the unit the packet is anchored on"
            );
        }
    }

    #[test]
    fn a_cross_unit_edge_is_included_and_its_far_side_becomes_a_neighbour() {
        // A model asked about one file needs to know what it reaches. It does not need the
        // file it reaches.
        let dir = TempDir::new("neighbours");
        let project = built(
            &dir,
            &[
                ("src/a.rs", "fn caller() { callee(); }\n"),
                ("src/b.rs", "fn callee() {}\n"),
            ],
        );
        let graph = project.read_graph().expect("graph");
        let unit = unit_for(&graph, "src/a.rs");
        let packet = build(&graph, unit, &[]);

        assert!(
            packet
                .structural_edges
                .iter()
                .any(|edge| edge.relation == "CALLS"),
            "{:?}",
            packet.structural_edges
        );
        assert_eq!(packet.neighboring_units.len(), 1);
        assert_ne!(packet.neighboring_units[0].source_unit, unit);
    }

    #[test]
    fn an_edge_wholly_outside_the_unit_is_somebody_elses_fact() {
        let dir = TempDir::new("outside");
        let project = built(
            &dir,
            &[
                ("src/a.rs", "fn alone() {}\n"),
                ("src/b.rs", "fn caller() { callee(); }\nfn callee() {}\n"),
            ],
        );
        let graph = project.read_graph().expect("graph");
        let unit = unit_for(&graph, "src/a.rs");
        let packet = build(&graph, unit, &[]);

        let owned: BTreeSet<LocalNodeId> = packet.symbols.iter().map(|s| s.id).collect();
        for edge in &packet.structural_edges {
            assert!(
                owned.contains(&edge.from) || owned.contains(&edge.to),
                "an edge with neither endpoint here does not belong in this packet"
            );
        }
    }

    #[test]
    fn the_neighbour_list_is_bounded_however_central_the_unit_is() {
        // A unit at the centre of a repository has hundreds of neighbours. The packet that
        // describes it must not.
        let dir = TempDir::new("bounded");
        let mut files: Vec<(String, String)> = vec![(
            "src/hub.rs".to_owned(),
            (0..MAX_NEIGHBOURING_UNITS + 6)
                .map(|n| format!("fn call_{n}() {{ leaf_{n}(); }}\n"))
                .collect::<String>(),
        )];
        for n in 0..MAX_NEIGHBOURING_UNITS + 6 {
            files.push((format!("src/leaf_{n}.rs"), format!("fn leaf_{n}() {{}}\n")));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect();
        let project = built(&dir, &borrowed);
        let graph = project.read_graph().expect("graph");
        let unit = unit_for(&graph, "src/hub.rs");
        let packet = build(&graph, unit, &[]);

        assert_eq!(packet.neighboring_units.len(), MAX_NEIGHBOURING_UNITS);
    }

    #[test]
    fn an_excerpt_is_cut_and_says_that_it_was() {
        // A model shown a truncated excerpt that does not say so may reason about what the
        // code does after the cut, and be confident about something it never saw.
        let long = "x".repeat(MAX_EXCERPT_BYTES * 2);
        let packet = build(&Graph::default(), SourceUnitId::QUERY, &[excerpt(&long)]);
        let span = &packet.selected_evidence_spans[0];
        assert_eq!(span.text.len(), MAX_EXCERPT_BYTES);
        assert!(span.truncated);

        let short = build(
            &Graph::default(),
            SourceUnitId::QUERY,
            &[excerpt("fn a() {}")],
        );
        assert!(!short.selected_evidence_spans[0].truncated);
    }

    #[test]
    fn an_excerpt_is_cut_on_a_character_boundary() {
        // A packet is text, and half a scalar is not.
        let long = "é".repeat(MAX_EXCERPT_BYTES);
        let packet = build(&Graph::default(), SourceUnitId::QUERY, &[excerpt(&long)]);
        let span = &packet.selected_evidence_spans[0];
        assert!(span.text.len() <= MAX_EXCERPT_BYTES);
        assert!(
            span.text.chars().all(|c| c == 'é'),
            "the cut split a scalar"
        );
    }

    #[test]
    fn the_number_of_excerpts_is_bounded_too() {
        let many: Vec<SourceExcerpt> = (0..MAX_EVIDENCE_SPANS + 10)
            .map(|n| excerpt(&format!("fn f{n}() {{}}")))
            .collect();
        let packet = build(&Graph::default(), SourceUnitId::QUERY, &many);
        assert_eq!(packet.selected_evidence_spans.len(), MAX_EVIDENCE_SPANS);
    }

    #[test]
    fn a_unit_an_analyzer_covered_completely_is_not_worth_sending() {
        // Spending tokens to be told what is already known.
        let empty = build(&Graph::default(), SourceUnitId::QUERY, &[]);
        assert!(!empty.is_worth_sending());
        assert_eq!(empty.record_count(), 0);
    }

    #[test]
    fn the_size_a_budget_uses_is_the_size_of_what_would_be_sent() {
        // Reported by the packet rather than recomputed by a caller, so the thing being
        // budgeted and the thing being sent cannot diverge.
        let packet = build(
            &Graph::default(),
            SourceUnitId::QUERY,
            &[excerpt("fn a() {}"), excerpt("fn b() {}")],
        );
        assert_eq!(packet.record_count(), 2);
        assert_eq!(packet.content_bytes(), "fn a() {}".len() * 2);
    }

    #[test]
    fn a_withheld_file_cannot_reach_a_packet_because_it_never_reached_the_graph() {
        // The scanner refuses a file that looks like a credential, so there is no record for
        // one to summarize. The packet inherits that rather than re-checking it, and this
        // asserts the inheritance holds.
        let dir = TempDir::new("withheld");
        fs::write(dir.0.join(".env"), "TOKEN=ghp_notarealvalue\n").expect("write");
        let project = built(&dir, &[("src/a.rs", "fn a_one() {}\n")]);
        let graph = project.read_graph().expect("graph");
        let unit = unit_for(&graph, "src/a.rs");
        let packet = build(&graph, unit, &[]);

        let rendered = format!("{packet:?}");
        assert!(
            !rendered.contains("ghp_notarealvalue"),
            "a secret reached a packet"
        );
        assert!(
            !rendered.contains(".env"),
            "a withheld file was named in a packet"
        );
    }
}
