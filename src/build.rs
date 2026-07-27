//! Turning what an analyzer found into a change set.
//!
//! This is the step between "the analyzer read the file" and "the database holds the
//! facts". It reads source, produces a [`GraphChangeSet`], and writes nothing; the caller
//! applies and commits it, so a build that turns out to be invalid costs the previous
//! generation nothing.
//!
//! # A path locates a record, it does not identify one
//!
//! Root PRD section 11 forbids using a file path as identity. So a rebuild does not match
//! records by path — it looks up the `File` node whose `path` property matches, takes the
//! **source unit** recorded on its contribution, and reuses the identifiers already stored
//! under that unit. The path is how the persisted identity is *found*; the identity itself
//! stays opaque, and every edge pointing at a record survives a rebuild that did not change
//! its name.
//!
//! Within a source unit, a record is keyed by its qualified name — `Parser::advance` rather
//! than "the third item in the file". Moving a function down a file keeps its identifier;
//! renaming it mints a new one and retires the old, which is the correct reading, because a
//! renamed function is not the same function to anything that referred to it by name.
//!
//! # Unresolved references are counted, not invented
//!
//! A call whose name matches nothing in the build gets no edge and no Placeholder. The
//! contract's rule is that a missing symbol must never produce a null endpoint, and not
//! creating the edge satisfies it.
//!
//! Creating a Placeholder instead would be worse than useless here. At
//! [`crate::analysis::PrecisionClass::DeterministicSyntactic`] the analyzer cannot tell a
//! genuinely missing symbol from one that lives in a dependency it was never given, and a
//! real codebase calls into its dependencies constantly — `nostdb-core` alone has some nine
//! thousand call sites. Manufacturing a node for each would assert something false: that
//! this project declares them. They are counted in
//! [`crate::coverage::BuildCoverage::unresolved_units`], which is the honest record.

use crate::analysis::CapabilityRegistry;
use crate::analyze::{self, FileAnalysis, Item, ItemKind};
use crate::change::{EdgeDraft, GraphChangeSet, GraphOperation, NodeDraft};
use crate::contribution::{ContributionKey, Owner};
use crate::coverage::{BuildCoverage, CoverageState, SkipReason, SkippedSource};
use crate::encoding::Graph;
use crate::evidence::{Confidence, Evidence, EvidenceMethod};
use crate::graph::NodeReference;
use crate::id::{LocalNodeId, Minter, SourceUnitId};
use crate::locator::CanonicalSourceLocator;
use crate::name::{Label, PropertyKey, RelationName};
use crate::property::PropertyValue;
use crate::scan::Scan;
use crate::text::NonEmptyText;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The label every analyzed file carries.
pub const FILE_LABEL: &str = "File";

/// Relation from a container to what it declares.
pub const CONTAINS: &str = "CONTAINS";

/// Relation from a function to a name it calls.
pub const CALLS: &str = "CALLS";

/// Relation from an implementation to the trait it implements.
pub const IMPLEMENTS: &str = "IMPLEMENTS";

/// Relation from an implementation to the type it is for.
pub const FOR_TYPE: &str = "FOR_TYPE";

/// The label a kind of item carries.
#[must_use]
pub fn label_for(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Module => "Module",
        ItemKind::Struct => "Struct",
        ItemKind::Enum => "Enum",
        ItemKind::Union => "Union",
        ItemKind::Trait => "Trait",
        ItemKind::TypeAlias => "TypeAlias",
        ItemKind::Function => "Function",
        ItemKind::Method => "Method",
        ItemKind::Field => "Field",
        ItemKind::Constant => "Constant",
        ItemKind::Implementation => "Impl",
    }
}

/// What to build, and how.
#[derive(Clone, Copy)]
pub struct BuildRequest<'a> {
    /// Where the scanned paths are relative to.
    pub root: &'a Path,
    /// What to analyze.
    pub scan: &'a Scan,
    /// The graph as it stands, which is where persisted identity is found.
    pub graph: &'a Graph,
    /// Which languages have an analyzer.
    pub registry: &'a CapabilityRegistry,
    /// The immutable snapshot the facts are derived from.
    pub revision: &'a str,
    /// The generation this is computed against.
    pub base_generation: u64,
    /// Whether to re-read every file rather than reusing what is already recorded.
    pub rebuild: bool,
}

/// What building produced, before anything was applied.
#[derive(Clone, Debug)]
pub struct BuildDraft {
    /// The change set to apply.
    pub change_set: GraphChangeSet,
    /// What the build covered.
    pub coverage: BuildCoverage,
    /// Files that were read and analyzed.
    pub analyzed_files: u64,
    /// References that matched a record in this build.
    pub resolved_references: u64,
    /// Files whose recorded facts were reused rather than re-read.
    pub reused_files: u64,
}

/// What one file contributes to settling an item's identity.
struct FileContext<'a> {
    unit: SourceUnitId,
    path: &'a str,
    known: &'a BTreeMap<(String, i64), LocalNodeId>,
}

/// One record this build will assert, before it becomes a draft.
struct Planned {
    id: LocalNodeId,
    kind: ItemKind,
    qualified: String,
    /// Which occurrence of this qualified name within the file, from zero.
    ordinal: i64,
    name: String,
    unit: SourceUnitId,
    path: String,
    line: u32,
    end_line: u32,
    children: Vec<usize>,
    references: Vec<crate::analyze::Reference>,
    implements: Option<String>,
    target: Option<String>,
}

/// Builds a change set from a scan.
///
/// Files whose language no analyzer reads are recorded as skipped rather than failed,
/// because unsupported text stays eligible for AI analysis.
///
/// Never fails. A file that cannot be read becomes a [`SkipReason::PermissionDenied`]
/// record, because one unreadable file must not cost a build every other file.
#[must_use]
pub fn draft(request: &BuildRequest<'_>, minter: &mut Minter) -> BuildDraft {
    let (root, scan, graph, registry) =
        (request.root, request.scan, request.graph, request.registry);
    let locator = CanonicalSourceLocator::root();
    let mut coverage = BuildCoverage::empty();
    let mut planned: Vec<Planned> = Vec::new();
    let mut units: Vec<(String, SourceUnitId, Option<LocalNodeId>, FileAnalysis)> = Vec::new();
    let mut reused: Vec<SourceUnitId> = Vec::new();
    let mut reused_files = 0_u64;

    // Pass one: read and analyze, and settle each file's persisted identity.
    for file in &scan.files {
        if !registry.precision(&file.language).is_deterministic() {
            coverage.skipped_sources.push(SkippedSource {
                source: locator.clone(),
                path: NonEmptyText::new(&file.path).ok(),
                reason: SkipReason::Unsupported,
            });
            continue;
        }
        let held = existing_unit(graph, &file.path);
        // A file whose bytes are the digest already recorded is a file whose facts are
        // already in the database. Section 17.8 makes reuse the default; `--rebuild` is
        // what asks for the work to be redone.
        if !request.rebuild
            && let Some((unit, Some(node))) = held
            && stored_digest(graph, node) == Some(file.digest.as_str())
        {
            reused.push(unit);
            reused_files += 1;
            continue;
        }
        let Ok(source) = std::fs::read_to_string(root.join(&file.path)) else {
            coverage.skipped_sources.push(SkippedSource {
                source: locator.clone(),
                path: NonEmptyText::new(&file.path).ok(),
                reason: SkipReason::PermissionDenied,
            });
            continue;
        };
        let Some(analysis) = analyze::analyze(&file.language, &source) else {
            // The registry said an analyzer exists and none does. That is a defect in this
            // build rather than in the source, and recording it beats pretending coverage.
            coverage.skipped_sources.push(SkippedSource {
                source: locator.clone(),
                path: NonEmptyText::new(&file.path).ok(),
                reason: SkipReason::Unsupported,
            });
            continue;
        };
        let (unit, existing) = held.unwrap_or_else(|| {
            // A file nothing has analyzed before. Its unit is minted once and then
            // persists on the File node's contribution.
            (minter.source_unit(), None)
        });
        units.push((file.path.clone(), unit, existing, analysis));
    }

    // A file the source no longer holds must take its records with it. Nothing else would
    // ever remove them: they belong to a unit no scan will name again.
    let present: BTreeSet<SourceUnitId> = units
        .iter()
        .map(|(_, unit, _, _)| *unit)
        .chain(reused.iter().copied())
        .collect();
    let departed: Vec<SourceUnitId> = analyzed_units(graph)
        .into_iter()
        .filter(|unit| !present.contains(unit))
        .collect();

    // Reuse is only sound while the names the unchanged files could refer to have not
    // moved. When a rebuilt file adds or removes a declared name, an edge from a file this
    // build never read may have become right or wrong, and the only honest answer at
    // syntactic precision is to read them all. That is the "affected context-resolution
    // units" half of section 17.8, taken conservatively rather than approximately.
    //
    // Taken all the way: if *anything* was re-read, everything is. A finer rule was tried —
    // reuse per file, with references resolved against reused records as well as fresh ones
    // — and it lost edges. Building this crate and then editing one comment produced 1275
    // `CALLS` edges where a full build of the same source produces 1308, and a forced
    // rebuild immediately after created exactly the 33 that were missing.
    //
    // The cause is a difference between resolving against one index and resolving against
    // two, and it is not yet understood. Until it is, the finer rule is not worth having: a
    // graph that depends on how it was built is worse than one that took longer to build.
    // What survives is the case that matters most and is provably safe — a tree where
    // nothing changed is not read at all.
    let names_moved = !departed.is_empty() || !units.is_empty();
    if names_moved && !reused.is_empty() {
        return draft(
            &BuildRequest {
                rebuild: true,
                ..*request
            },
            minter,
        );
    }

    let mut change_set = GraphChangeSet::new(
        analyzer_owner(),
        NonEmptyText::new(request.revision)
            .unwrap_or_else(|_| NonEmptyText::literal("tree:unknown")),
        request.base_generation,
    );

    // Every unit being rebuilt withdraws its previous claim first, so a record the source
    // no longer declares disappears rather than lingering. A departed file withdraws its
    // claim and restates nothing, which is what removes it.
    for unit in units
        .iter()
        .map(|(_, unit, _, _)| *unit)
        .chain(departed.iter().copied())
    {
        change_set.push(GraphOperation::RemoveContribution(ContributionKey {
            owner: analyzer_owner(),
            source_unit: unit,
        }));
    }

    // Pass two: settle every identifier before any edge needs one.
    let mut file_nodes: Vec<(usize, LocalNodeId)> = Vec::new();
    for (index, (path, unit, existing, analysis)) in units.iter().enumerate() {
        let known = existing_names(graph, *unit);
        let context = FileContext {
            unit: *unit,
            path,
            known: &known,
        };
        let mut seen: BTreeMap<String, i64> = BTreeMap::new();
        let file_id = existing.unwrap_or_else(|| minter.node());
        file_nodes.push((index, file_id));
        for item in &analysis.items {
            plan_item(item, "", &context, &mut seen, minter, &mut planned);
        }
    }

    // Pass three: the drafts themselves, now that every identifier is known.
    for (index, (path, unit, _, analysis)) in units.iter().enumerate() {
        let file_id = file_nodes[index].1;
        change_set.push(GraphOperation::UpsertNode(NodeDraft {
            id: Some(file_id),
            labels: vec![label(FILE_LABEL)],
            properties: vec![
                text_property("path", path),
                text_property("language", &analysis.language),
                text_property("digest", analysis.digest.as_str()),
            ],
            source_unit: *unit,
            evidence: vec![file_evidence(&locator, path, analysis)],
        }));
    }

    // A name is resolvable when exactly one record in the build carries it. Two records
    // with one name is not an error and not a guess: the reference stays unresolved.
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (at, record) in planned.iter().enumerate() {
        // An implementation is named for the type it is for, so indexing it would make
        // every `impl Cursor` collide with `struct Cursor` and leave both unresolvable. It
        // is also not something a reference can name: nothing calls an impl block.
        if record.kind == ItemKind::Implementation {
            continue;
        }
        by_name.entry(record.name.as_str()).or_default().push(at);
        if record.qualified != record.name {
            by_name
                .entry(record.qualified.as_str())
                .or_default()
                .push(at);
        }
    }
    // A reused file's records are not in `planned`, but a re-analyzed file can call them.
    // Resolving against `planned` alone would drop every cross-file edge out of an
    // incremental build and put it back on the next full one, which is a graph that
    // depends on how it was built rather than on what the source says.
    let mut reused_by_name: BTreeMap<String, Vec<LocalNodeId>> = BTreeMap::new();
    if !reused.is_empty() {
        let owner = analyzer_owner();
        let held: BTreeSet<SourceUnitId> = reused.iter().copied().collect();
        for node in &graph.nodes {
            if node.labels.iter().any(|held| held.as_str() == FILE_LABEL)
                || node.labels.iter().any(|held| held.as_str() == "Impl")
                || !node
                    .contributions
                    .iter()
                    .any(|c| c.owner == owner && held.contains(&c.source_unit))
            {
                continue;
            }
            // Indexed under both names, but only once each: for a top-level item the two
            // are the same string, and pushing twice would make one record look like two
            // candidates and resolve to nothing.
            let name = property(node, "name").map(str::to_owned);
            let qualified = property(node, "qualified_name").map(str::to_owned);
            for key in [name.clone(), qualified].into_iter().flatten() {
                let entry = reused_by_name.entry(key).or_default();
                if !entry.contains(&node.id) {
                    entry.push(node.id);
                }
            }
        }
    }

    let resolve = |name: &str| -> Option<LocalNodeId> {
        let fresh = by_name.get(name).map(Vec::as_slice).unwrap_or_default();
        let held = reused_by_name
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or_default();
        match (fresh, held) {
            ([only], []) => Some(planned[*only].id),
            ([], [only]) => Some(*only),
            // Ambiguous across the two halves for the same reason it is ambiguous within
            // one: picking either would be a guess.
            _ => None,
        }
    };

    for record in &planned {
        let analysis = units
            .iter()
            .find(|(path, _, _, _)| *path == record.path)
            .map(|(_, _, _, analysis)| analysis);
        let evidence = match analysis {
            Some(analysis) => vec![item_evidence(&locator, record, analysis)],
            None => Vec::new(),
        };
        change_set.push(GraphOperation::UpsertNode(NodeDraft {
            id: Some(record.id),
            labels: vec![label(label_for(record.kind))],
            properties: vec![
                text_property("name", &record.name),
                text_property("qualified_name", &record.qualified),
                text_property("path", &record.path),
                integer_property("ordinal", record.ordinal),
                integer_property("line", i64::from(record.line)),
                integer_property("end_line", i64::from(record.end_line)),
            ],
            source_unit: record.unit,
            evidence,
        }));
    }

    let known_edges = existing_edges(graph);
    let mut edges = Edges::default();

    // Containment: from the file to each top-level record, and from each record to its
    // children. Emitted after every node, so no edge can name an endpoint not yet drafted.
    for (index, (path, unit, _, _)) in units.iter().enumerate() {
        let file_id = file_nodes[index].1;
        for record in planned
            .iter()
            .filter(|record| &record.path == path && !record.qualified.contains("::"))
        {
            edges.add(file_id, record.id, CONTAINS, *unit);
        }
    }
    for record in &planned {
        for child in &record.children {
            let child = &planned[*child];
            edges.add(record.id, child.id, CONTAINS, record.unit);
        }
    }

    let mut resolved = 0_u64;
    let mut unresolved = 0_u64;
    for record in &planned {
        for reference in &record.references {
            match resolve(&reference.name) {
                Some(target) => {
                    resolved += 1;
                    edges.add(record.id, target, CALLS, record.unit);
                }
                // Counted, not invented. See the module documentation.
                None => unresolved += 1,
            }
        }
        if let Some(name) = &record.implements {
            match resolve(name) {
                Some(target) => {
                    resolved += 1;
                    edges.add(record.id, target, IMPLEMENTS, record.unit);
                }
                None => unresolved += 1,
            }
        }
        if let Some(name) = &record.target
            && record.kind == ItemKind::Implementation
        {
            match resolve(name) {
                Some(target) if target != record.id => {
                    resolved += 1;
                    edges.add(record.id, target, FOR_TYPE, record.unit);
                }
                _ => unresolved += 1,
            }
        }
    }

    edges.drain_into(&mut change_set, &locator, &known_edges);

    coverage.unresolved_units = unresolved;
    coverage.structural = if coverage.skipped_sources.is_empty() {
        CoverageState::Complete
    } else {
        CoverageState::Partial
    };
    // Nothing here spends an AI token, so the semantic phase did not run.
    coverage.semantic = CoverageState::Skipped;

    BuildDraft {
        change_set,
        coverage,
        analyzed_files: units.len() as u64,
        resolved_references: resolved,
        reused_files,
    }
}

/// The owner every record this module produces belongs to.
#[must_use]
pub fn analyzer_owner() -> Owner {
    Owner::Analyzer {
        name: NonEmptyText::new(crate::analyze::rust::LANGUAGE)
            .unwrap_or_else(|_| NonEmptyText::literal("rust")),
        version: NonEmptyText::new(crate::analyze::rust::VERSION)
            .unwrap_or_else(|_| NonEmptyText::literal("1")),
    }
}

/// The source unit and node identifier already persisted for a path, when there is one.
fn existing_unit(graph: &Graph, path: &str) -> Option<(SourceUnitId, Option<LocalNodeId>)> {
    let owner = analyzer_owner();
    let node = graph.nodes.iter().find(|node| {
        node.labels.iter().any(|label| label.as_str() == FILE_LABEL)
            && property(node, "path") == Some(path)
            && node.contributions.iter().any(|held| held.owner == owner)
    })?;
    let unit = node
        .contributions
        .iter()
        .find(|held| held.owner == owner)?
        .source_unit;
    Some((unit, Some(node.id)))
}

/// Every identifier this analyzer already holds in one source unit.
///
/// Keyed by qualified name *and* occurrence, because a qualified name is not unique within
/// a file. Rust allows several inherent `impl` blocks for one type, and two trait impls for
/// one type each declare a method of the same name — `execute.rs` in this crate has three
/// `impl Scoped` blocks. Keying by name alone made all three claim one persisted
/// identifier, and the change set was refused for duplicate identifiers on the second
/// build. The occurrence is stored on the record rather than inferred from position in the
/// node list, so identity does not depend on the order storage happens to return.
fn existing_names(graph: &Graph, unit: SourceUnitId) -> BTreeMap<(String, i64), LocalNodeId> {
    let owner = analyzer_owner();
    graph
        .nodes
        .iter()
        .filter(|node| {
            node.contributions
                .iter()
                .any(|held| held.owner == owner && held.source_unit == unit)
        })
        .filter_map(|node| {
            let qualified = property(node, "qualified_name")?.to_owned();
            let ordinal = integer(node, "ordinal").unwrap_or(0);
            Some(((qualified, ordinal), node.id))
        })
        .collect()
}

/// Every edge identifier this analyzer already holds, keyed by what the edge connects.
fn existing_edges(
    graph: &Graph,
) -> BTreeMap<(LocalNodeId, LocalNodeId, String), crate::id::LocalEdgeId> {
    let owner = analyzer_owner();
    graph
        .edges
        .iter()
        .filter(|edge| edge.contributions.iter().any(|held| held.owner == owner))
        .filter_map(|edge| {
            let (NodeReference::Local(from), NodeReference::Local(to)) =
                (&edge.source, &edge.target)
            else {
                return None;
            };
            Some(((*from, *to, edge.relation.as_str().to_owned()), edge.id))
        })
        .collect()
}

/// The digest recorded on a file record, when it carries one.
fn stored_digest(graph: &Graph, node: LocalNodeId) -> Option<&str> {
    property(graph.nodes.iter().find(|held| held.id == node)?, "digest")
}

/// Every source unit this analyzer holds a contribution for.
fn analyzed_units(graph: &Graph) -> BTreeSet<SourceUnitId> {
    let owner = analyzer_owner();
    graph
        .nodes
        .iter()
        .flat_map(|node| node.contributions.iter())
        .filter(|held| held.owner == owner)
        .map(|held| held.source_unit)
        .collect()
}

/// One property's integer value, when the node carries it as one.
fn integer(node: &crate::graph::Node, key: &str) -> Option<i64> {
    node.properties
        .iter()
        .find_map(|(held, value)| match value {
            PropertyValue::Integer(number) if held.as_str() == key => Some(*number),
            _ => None,
        })
}

/// One property's text value, when the node carries it as text.
fn property<'a>(node: &'a crate::graph::Node, key: &str) -> Option<&'a str> {
    node.properties
        .iter()
        .find_map(|(held, value)| match value {
            PropertyValue::String(text) if held.as_str() == key => Some(text.as_str()),
            _ => None,
        })
}

/// Settles one item's identity and records it, then recurses into its children.
fn plan_item(
    item: &Item,
    prefix: &str,
    file: &FileContext<'_>,
    seen: &mut BTreeMap<String, i64>,
    minter: &mut Minter,
    planned: &mut Vec<Planned>,
) -> usize {
    let qualified = if prefix.is_empty() {
        item.name.clone()
    } else {
        format!("{prefix}::{}", item.name)
    };
    let ordinal = {
        let counter = seen.entry(qualified.clone()).or_insert(0);
        let ordinal = *counter;
        *counter += 1;
        ordinal
    };
    // The qualified name and occurrence are what carry identity forward. Moving a function
    // down a file keeps its identifier; renaming it mints a new one, which is correct — a
    // renamed function is not the same function to anything that referred to it by name.
    let id = file
        .known
        .get(&(qualified.clone(), ordinal))
        .copied()
        .unwrap_or_else(|| minter.node());

    let at = planned.len();
    planned.push(Planned {
        id,
        kind: item.kind,
        qualified: qualified.clone(),
        ordinal,
        name: item.name.clone(),
        unit: file.unit,
        path: file.path.to_owned(),
        line: item.range.start().line,
        end_line: item.range.end().line,
        children: Vec::new(),
        references: item.references.clone(),
        implements: item.implements.clone(),
        target: item.target.clone(),
    });

    let mut children = Vec::with_capacity(item.children.len());
    for child in &item.children {
        children.push(plan_item(child, &qualified, file, seen, minter, planned));
    }
    planned[at].children = children;
    at
}

/// Collects the edges a build asserts, one per distinct relation.
///
/// A relation is a fact, not an occurrence. `main` calling `helper` twice is one edge
/// carrying a count of two, and emitting two would be both wrong and impossible: two
/// drafts of the same relation resolve to the same persisted identifier, and a change set
/// with a repeated identifier is refused. Found by rebuilding this crate.
#[derive(Default)]
struct Edges {
    order: Vec<(LocalNodeId, LocalNodeId, String, SourceUnitId)>,
    counts: BTreeMap<(LocalNodeId, LocalNodeId, String), i64>,
}

impl Edges {
    fn add(&mut self, from: LocalNodeId, to: LocalNodeId, relation: &str, unit: SourceUnitId) {
        let key = (from, to, relation.to_owned());
        let seen = self.counts.entry(key.clone()).or_insert(0);
        if *seen == 0 {
            self.order.push((from, to, relation.to_owned(), unit));
        }
        *seen += 1;
    }

    fn drain_into(
        self,
        change_set: &mut GraphChangeSet,
        locator: &CanonicalSourceLocator,
        known: &BTreeMap<(LocalNodeId, LocalNodeId, String), crate::id::LocalEdgeId>,
    ) {
        for (from, to, relation, unit) in self.order {
            let count = self
                .counts
                .get(&(from, to, relation.clone()))
                .copied()
                .unwrap_or(1);
            push_edge(change_set, from, to, &relation, unit, count, locator, known);
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "every one names a distinct part of the edge, and grouping them into a struct \
              used at a single call site would hide rather than clarify"
)]
fn push_edge(
    change_set: &mut GraphChangeSet,
    from: LocalNodeId,
    to: LocalNodeId,
    relation: &str,
    unit: SourceUnitId,
    count: i64,
    locator: &CanonicalSourceLocator,
    known: &BTreeMap<(LocalNodeId, LocalNodeId, String), crate::id::LocalEdgeId>,
) {
    let Ok(relation) = RelationName::new(relation) else {
        return;
    };
    // An edge is identified by what it connects and what it is. A rebuild that finds the
    // same relation between the same two records reuses its identifier rather than minting
    // one, so an unchanged tree does not churn five thousand edges every build.
    let id = known
        .get(&(from, to, relation.as_str().to_owned()))
        .copied();
    change_set.push(GraphOperation::UpsertEdge(EdgeDraft {
        id,
        source: NodeReference::Local(from),
        target: NodeReference::Local(to),
        relation,
        properties: vec![integer_property("count", count)],
        source_unit: unit,
        // The evidence for an edge is the same file the endpoints came from, so it carries
        // no range: the relation is not at one position in the text.
        evidence: vec![Evidence {
            source: locator.clone(),
            resolved_revision: None,
            path: None,
            content_digest: crate::sync::digest_bytes(&[]),
            range: None,
            producer: NonEmptyText::new(crate::analyze::rust::LANGUAGE)
                .unwrap_or_else(|_| NonEmptyText::literal("rust")),
            producer_version: NonEmptyText::new(crate::analyze::rust::VERSION)
                .unwrap_or_else(|_| NonEmptyText::literal("1")),
            method: EvidenceMethod::Deterministic,
            confidence: Confidence::Extracted,
        }],
    }));
}

fn file_evidence(
    locator: &CanonicalSourceLocator,
    path: &str,
    analysis: &FileAnalysis,
) -> Evidence {
    Evidence {
        source: locator.clone(),
        resolved_revision: None,
        path: NonEmptyText::new(path).ok(),
        content_digest: analysis.digest.clone(),
        range: None,
        producer: NonEmptyText::new(analysis.language.as_str())
            .unwrap_or_else(|_| NonEmptyText::literal("rust")),
        producer_version: NonEmptyText::new(crate::analyze::rust::VERSION)
            .unwrap_or_else(|_| NonEmptyText::literal("1")),
        method: EvidenceMethod::Deterministic,
        confidence: Confidence::Extracted,
    }
}

fn item_evidence(
    locator: &CanonicalSourceLocator,
    record: &Planned,
    analysis: &FileAnalysis,
) -> Evidence {
    Evidence {
        range: crate::evidence::SourceRange::new(
            crate::evidence::SourcePosition {
                line: record.line.max(1),
                column: 1,
                offset: 0,
            },
            crate::evidence::SourcePosition {
                line: record.end_line.max(record.line).max(1),
                column: 1,
                offset: 0,
            },
        )
        .ok(),
        ..file_evidence(locator, &record.path, analysis)
    }
}

fn label(text: &str) -> Label {
    Label::new(text).unwrap_or_else(|_| Label::literal("Unknown"))
}

fn text_property(key: &str, value: &str) -> (PropertyKey, PropertyValue) {
    (
        PropertyKey::new(key).unwrap_or_else(|_| PropertyKey::literal("unknown")),
        PropertyValue::String(value.to_owned()),
    )
}

fn integer_property(key: &str, value: i64) -> (PropertyKey, PropertyValue) {
    (
        PropertyKey::new(key).unwrap_or_else(|_| PropertyKey::literal("unknown")),
        PropertyValue::Integer(value),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::builtin_registry;
    use crate::evidence::ContentDigest;
    use crate::scan::ScannedFile;
    use std::fs;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("nostdb-core-build-{label}"));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).expect("temporary directory");
            Self(base)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, contents: &str) -> ScannedFile {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parent");
            }
            fs::write(&path, contents).expect("write");
            ScannedFile {
                path: relative.to_owned(),
                language: "rust".to_owned(),
                bytes: contents.len() as u64,
                digest: crate::sync::digest_bytes(contents.as_bytes()),
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn build(
        dir: &TempDir,
        files: Vec<ScannedFile>,
        graph: &mut Graph,
        generation: u64,
    ) -> BuildDraft {
        build_with(dir, files, graph, generation, false)
    }

    static REGISTRY: std::sync::OnceLock<CapabilityRegistry> = std::sync::OnceLock::new();

    fn request<'a>(
        dir: &'a TempDir,
        scan: &'a Scan,
        graph: &'a Graph,
        generation: u64,
        rebuild: bool,
    ) -> BuildRequest<'a> {
        BuildRequest {
            root: dir.path(),
            scan,
            graph,
            registry: REGISTRY.get_or_init(|| builtin_registry().expect("the registry")),
            revision: "tree:sha256:test",
            base_generation: generation,
            rebuild,
        }
    }

    fn build_with(
        dir: &TempDir,
        files: Vec<ScannedFile>,
        graph: &mut Graph,
        generation: u64,
        rebuild: bool,
    ) -> BuildDraft {
        let scan = Scan {
            files,
            skipped: Vec::new(),
        };
        let mut minter = Minter::new();
        let draft = super::draft(
            &request(dir, &scan, graph, generation, rebuild),
            &mut minter,
        );
        // A build that reused everything proposes nothing, which is the point of reuse
        // rather than a failure to apply.
        if !draft.change_set.operations.is_empty() {
            crate::apply::apply(graph, &draft.change_set, generation, &mut minter)
                .expect("the draft applies");
        }
        draft
    }

    fn names(graph: &Graph, label: &str) -> Vec<String> {
        let mut found: Vec<String> = graph
            .nodes
            .iter()
            .filter(|node| node.labels.iter().any(|held| held.as_str() == label))
            .filter_map(|node| property(node, "name").map(str::to_owned))
            .collect();
        found.sort();
        found
    }

    fn relations(graph: &Graph, relation: &str) -> Vec<(String, String)> {
        let name_of = |reference: &NodeReference| match reference {
            NodeReference::Local(id) => graph
                .nodes
                .iter()
                .find(|node| node.id == *id)
                .and_then(|node| property(node, "name"))
                .unwrap_or("?")
                .to_owned(),
            NodeReference::External(_) => "external".to_owned(),
        };
        let mut found: Vec<(String, String)> = graph
            .edges
            .iter()
            .filter(|edge| edge.relation.as_str() == relation)
            .map(|edge| (name_of(&edge.source), name_of(&edge.target)))
            .collect();
        found.sort();
        found
    }

    #[test]
    fn a_build_records_a_file_and_the_items_it_declares() {
        let dir = TempDir::new("basic");
        let file = dir.write("src/main.rs", "fn main() {}\nstruct Config { port: u32 }\n");
        let mut graph = Graph::default();
        let draft = build(&dir, vec![file], &mut graph, 1);

        assert_eq!(draft.analyzed_files, 1);
        let file_node = graph
            .nodes
            .iter()
            .find(|node| node.labels.iter().any(|held| held.as_str() == FILE_LABEL))
            .expect("a file record");
        assert_eq!(property(file_node, "path"), Some("src/main.rs"));
        assert_eq!(property(file_node, "language"), Some("rust"));
        assert_eq!(names(&graph, "Function"), ["main"]);
        assert_eq!(names(&graph, "Struct"), ["Config"]);
        assert_eq!(names(&graph, "Field"), ["port"]);
        assert!(
            relations(&graph, CONTAINS).contains(&("Config".to_owned(), "port".to_owned())),
            "{:?}",
            relations(&graph, CONTAINS)
        );
    }

    #[test]
    fn a_call_that_matches_one_record_becomes_an_edge() {
        let dir = TempDir::new("calls");
        let file = dir.write("src/main.rs", "fn main() { helper(); }\nfn helper() {}\n");
        let mut graph = Graph::default();
        let draft = build(&dir, vec![file], &mut graph, 1);

        assert_eq!(
            relations(&graph, CALLS),
            [("main".to_owned(), "helper".to_owned())]
        );
        assert!(draft.resolved_references >= 1);
    }

    #[test]
    fn a_call_resolves_across_files() {
        let dir = TempDir::new("cross-file");
        let one = dir.write("src/a.rs", "fn caller() { callee(); }\n");
        let two = dir.write("src/b.rs", "fn callee() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![one, two], &mut graph, 1);

        assert_eq!(
            relations(&graph, CALLS),
            [("caller".to_owned(), "callee".to_owned())]
        );
    }

    #[test]
    fn a_call_matching_nothing_is_counted_rather_than_given_a_placeholder() {
        // A missing symbol must never produce a null endpoint, and not creating the edge
        // satisfies that. Manufacturing a node would assert that this project declares
        // `println` — which at syntactic precision the analyzer cannot know either way.
        let dir = TempDir::new("unresolved");
        let file = dir.write("src/main.rs", "fn main() { nowhere(); elsewhere(); }\n");
        let mut graph = Graph::default();
        let draft = build(&dir, vec![file], &mut graph, 1);

        assert!(relations(&graph, CALLS).is_empty());
        assert_eq!(draft.coverage.unresolved_units, 2);
        assert_eq!(
            graph.nodes.len(),
            2,
            "the file and `main`, and nothing invented: {:?}",
            names(&graph, "Function")
        );
    }

    #[test]
    fn a_name_two_records_share_stays_unresolved_rather_than_being_guessed() {
        let dir = TempDir::new("ambiguous");
        let one = dir.write("src/a.rs", "fn shared() {}\nfn caller() { shared(); }\n");
        let two = dir.write("src/b.rs", "fn shared() {}\n");
        let mut graph = Graph::default();
        let draft = build(&dir, vec![one, two], &mut graph, 1);

        assert!(
            relations(&graph, CALLS).is_empty(),
            "picking one of two would be a guess: {:?}",
            relations(&graph, CALLS)
        );
        assert!(draft.coverage.unresolved_units >= 1);
    }

    #[test]
    fn an_implementation_points_at_its_trait_and_its_type() {
        let dir = TempDir::new("impl");
        let file = dir.write(
            "src/lib.rs",
            "trait Read { fn read(&self); }\nstruct Cursor;\nimpl Read for Cursor { fn read(&self) {} }\n",
        );
        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);

        assert_eq!(
            relations(&graph, IMPLEMENTS),
            [("Cursor".to_owned(), "Read".to_owned())],
            "the impl node is named for the type it is for"
        );
        assert_eq!(
            relations(&graph, FOR_TYPE),
            [("Cursor".to_owned(), "Cursor".to_owned())]
        );
    }

    fn ids(graph: &Graph) -> Vec<LocalNodeId> {
        let mut ids: Vec<LocalNodeId> = graph.nodes.iter().map(|node| node.id).collect();
        ids.sort();
        ids
    }

    #[test]
    fn a_rebuild_with_no_change_reuses_everything_and_proposes_nothing() {
        let dir = TempDir::new("rebuild-stable");
        let file = dir.write("src/main.rs", "fn main() { helper(); }\nfn helper() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file.clone()], &mut graph, 1);
        let before = ids(&graph);

        let draft = build(&dir, vec![file], &mut graph, 2);
        assert_eq!(draft.reused_files, 1);
        assert_eq!(draft.analyzed_files, 0, "nothing was re-read");
        assert!(
            draft.change_set.operations.is_empty(),
            "a build with nothing to do proposes nothing rather than restating everything"
        );
        assert_eq!(ids(&graph), before);
    }

    #[test]
    fn asking_for_a_rebuild_re_reads_a_file_reuse_would_have_skipped() {
        // Section 17.8: `--rebuild` explicitly bypasses reusable analysis artifacts.
        let dir = TempDir::new("rebuild-forced");
        let file = dir.write("src/main.rs", "fn main() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file.clone()], &mut graph, 1);
        let before = ids(&graph);

        let draft = build_with(&dir, vec![file], &mut graph, 2, true);
        assert_eq!(draft.reused_files, 0);
        assert_eq!(draft.analyzed_files, 1);
        assert_eq!(
            ids(&graph),
            before,
            "redoing the work must still reach the same identifiers"
        );
    }

    #[test]
    fn one_changed_file_makes_the_whole_build_read_again() {
        // Reuse is all or nothing. A finer rule lost edges — see the comment beside the
        // decision in `draft` — and a graph that depends on how it was built is worse than
        // one that took longer to build.
        let dir = TempDir::new("rebuild-partial");
        let one = dir.write("src/a.rs", "fn a_one() {}\nfn a_two() {}\n");
        let two = dir.write("src/b.rs", "fn b_one() { a_two(); }\n");
        let mut graph = Graph::default();
        build(&dir, vec![one, two.clone()], &mut graph, 1);
        let before = relations(&graph, CALLS);
        assert_eq!(before, [("b_one".to_owned(), "a_two".to_owned())]);

        let edited = dir.write("src/a.rs", "fn a_one() { let x = 1; }\nfn a_two() {}\n");
        let draft = build(&dir, vec![edited, two], &mut graph, 2);
        assert_eq!(draft.analyzed_files, 2, "one changed, so both are read");
        assert_eq!(draft.reused_files, 0);
        assert_eq!(
            relations(&graph, CALLS),
            before,
            "the cross-file edge survives, which is what the finer rule could not promise"
        );
    }

    #[test]
    fn a_file_the_source_no_longer_holds_takes_its_records_with_it() {
        // Nothing else would ever remove them: they belong to a unit no scan will name
        // again.
        let dir = TempDir::new("rebuild-departed");
        let one = dir.write("src/a.rs", "fn kept() {}\n");
        let two = dir.write("src/gone.rs", "fn departed() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![one.clone(), two], &mut graph, 1);
        assert_eq!(names(&graph, "Function"), ["departed", "kept"]);

        std::fs::remove_file(dir.path().join("src/gone.rs")).expect("remove");
        build(&dir, vec![one], &mut graph, 2);
        assert_eq!(names(&graph, "Function"), ["kept"]);
        assert!(
            !graph
                .nodes
                .iter()
                .any(|node| property(node, "path") == Some("src/gone.rs")),
            "the file record goes too"
        );
    }

    #[test]
    fn moving_an_item_down_a_file_keeps_its_identifier() {
        let dir = TempDir::new("rebuild-moved");
        let file = dir.write("src/main.rs", "fn first() {}\nfn second() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);
        let id = graph
            .nodes
            .iter()
            .find(|node| property(node, "name") == Some("second"))
            .expect("the record")
            .id;

        let moved = dir.write(
            "src/main.rs",
            "// a comment added at the top\n\nfn second() {}\nfn first() {}\n",
        );
        build(&dir, vec![moved], &mut graph, 2);
        let after = graph
            .nodes
            .iter()
            .find(|node| property(node, "name") == Some("second"))
            .expect("the record");
        assert_eq!(after.id, id, "position is not identity");
        assert_eq!(
            property(after, "line"),
            None,
            "line is an integer property, not text"
        );
    }

    #[test]
    fn a_record_the_source_no_longer_declares_disappears() {
        let dir = TempDir::new("rebuild-removed");
        let file = dir.write("src/main.rs", "fn kept() {}\nfn removed() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);
        assert_eq!(names(&graph, "Function"), ["kept", "removed"]);

        let edited = dir.write("src/main.rs", "fn kept() {}\n");
        build(&dir, vec![edited], &mut graph, 2);
        assert_eq!(names(&graph, "Function"), ["kept"]);
    }

    #[test]
    fn renaming_an_item_retires_the_old_record_and_mints_a_new_one() {
        // Correct rather than convenient: a renamed function is not the same function to
        // anything that referred to it by name.
        let dir = TempDir::new("rebuild-renamed");
        let file = dir.write("src/main.rs", "fn before() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);
        let old = graph
            .nodes
            .iter()
            .find(|node| property(node, "name") == Some("before"))
            .expect("the record")
            .id;

        let edited = dir.write("src/main.rs", "fn after() {}\n");
        build(&dir, vec![edited], &mut graph, 2);
        assert_eq!(names(&graph, "Function"), ["after"]);
        assert!(
            graph.nodes.iter().all(|node| node.id != old),
            "the old record is retired rather than renamed in place"
        );
    }

    #[test]
    fn several_records_sharing_a_qualified_name_keep_distinct_identifiers() {
        // Found by building this crate. Rust allows several inherent `impl` blocks for one
        // type, and `execute.rs` has three for `Scoped`. Keying identity by name alone made
        // all three claim one persisted identifier, and the second build was refused for
        // duplicate identifiers.
        let dir = TempDir::new("shared-name");
        let file = dir.write(
            "src/lib.rs",
            "struct S;\nimpl S { fn a(&self) {} }\nimpl S { fn b(&self) {} }\nimpl S { fn c(&self) {} }\n",
        );
        let mut graph = Graph::default();
        build(&dir, vec![file.clone()], &mut graph, 1);

        let impls: Vec<LocalNodeId> = graph
            .nodes
            .iter()
            .filter(|node| node.labels.iter().any(|held| held.as_str() == "Impl"))
            .map(|node| node.id)
            .collect();
        assert_eq!(impls.len(), 3);

        // The rebuild is the half that used to fail. Forced, because reuse would
        // otherwise skip the file and never exercise the identity lookup.
        build_with(&dir, vec![file], &mut graph, 2, true);
        let mut after: Vec<LocalNodeId> = graph
            .nodes
            .iter()
            .filter(|node| node.labels.iter().any(|held| held.as_str() == "Impl"))
            .map(|node| node.id)
            .collect();
        after.sort();
        let mut before = impls;
        before.sort();
        assert_eq!(before, after, "each occurrence keeps its own identifier");
    }

    #[test]
    fn a_file_no_analyzer_reads_is_skipped_rather_than_failed() {
        let dir = TempDir::new("unsupported");
        let mut file = dir.write("app.py", "def main(): pass\n");
        file.language = "python".to_owned();
        let mut graph = Graph::default();
        let scan = Scan {
            files: vec![file],
            skipped: Vec::new(),
        };
        let mut minter = Minter::new();
        let draft = super::draft(&request(&dir, &scan, &graph, 1, false), &mut minter);
        assert_eq!(draft.analyzed_files, 0);
        assert_eq!(draft.coverage.skipped_sources.len(), 1);
        assert_eq!(
            draft.coverage.skipped_sources[0].reason,
            SkipReason::Unsupported
        );
        assert_eq!(draft.coverage.structural, CoverageState::Partial);
        let _ = &mut graph;
    }

    #[test]
    fn a_build_spends_no_ai_tokens_and_says_the_semantic_phase_did_not_run() {
        let dir = TempDir::new("coverage");
        let file = dir.write("src/main.rs", "fn main() {}\n");
        let mut graph = Graph::default();
        let draft = build(&dir, vec![file], &mut graph, 1);
        assert_eq!(draft.coverage.semantic, CoverageState::Skipped);
        assert_eq!(draft.coverage.structural, CoverageState::Complete);
    }

    #[test]
    fn every_record_carries_evidence_naming_the_file_it_came_from() {
        // An analyzer-created record must have provenance. A record asserting a fact with
        // nothing behind it is indistinguishable from one somebody made up.
        let dir = TempDir::new("evidence");
        let file = dir.write("src/main.rs", "fn main() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);

        for node in &graph.nodes {
            let contribution = node
                .contributions
                .iter()
                .find(|held| held.owner == analyzer_owner())
                .expect("an analyzer contribution");
            assert!(
                !contribution.evidence.is_empty(),
                "{:?} has no evidence",
                property(node, "name")
            );
            assert_eq!(
                contribution.evidence[0].method,
                EvidenceMethod::Deterministic
            );
        }
    }

    #[test]
    fn the_digest_on_a_file_record_is_the_one_the_scan_saw() {
        let dir = TempDir::new("digest");
        let source = "fn main() {}\n";
        let file = dir.write("src/main.rs", source);
        let expected: ContentDigest = file.digest.clone();
        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);

        let node = graph
            .nodes
            .iter()
            .find(|node| node.labels.iter().any(|held| held.as_str() == FILE_LABEL))
            .expect("the file record");
        assert_eq!(property(node, "digest"), Some(expected.as_str()));
    }

    #[test]
    fn an_unchanged_rebuild_reports_updates_rather_than_churn() {
        // A rebuild withdraws its claim and restates it, so every record is deleted and
        // recreated inside one change set. Reporting that as thousands of deletions and
        // creations would make an unchanged tree look like it rewrote the whole database.
        let dir = TempDir::new("rebuild-counts");
        let file = dir.write(
            "src/main.rs",
            "fn main() { helper(); }\nfn helper() {}\nstruct S { a: u32 }\n",
        );
        let mut graph = Graph::default();
        build(&dir, vec![file.clone()], &mut graph, 1);
        let nodes = graph.nodes.len();
        let edges = graph.edges.len();

        let scan = Scan {
            files: vec![file],
            skipped: Vec::new(),
        };
        let mut minter = Minter::new();
        // Forced: reuse would propose nothing, and what this test is about is what the
        // counts say when the work is actually redone.
        let draft = super::draft(&request(&dir, &scan, &graph, 2, true), &mut minter);
        let summary = crate::apply::apply(&mut graph, &draft.change_set, 2, &mut minter)
            .expect("the draft applies");

        assert_eq!(summary.nodes_created, 0, "{summary:?}");
        assert_eq!(summary.nodes_deleted, 0, "{summary:?}");
        assert_eq!(summary.nodes_updated as usize, nodes);
        assert_eq!(summary.edges_created, 0, "{summary:?}");
        assert_eq!(summary.edges_deleted, 0, "{summary:?}");
        assert_eq!(summary.edges_updated as usize, edges);
    }

    #[test]
    fn an_edge_keeps_its_identifier_across_a_rebuild() {
        let dir = TempDir::new("rebuild-edges");
        let file = dir.write("src/main.rs", "fn main() { helper(); }\nfn helper() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file.clone()], &mut graph, 1);
        let mut before: Vec<crate::id::LocalEdgeId> =
            graph.edges.iter().map(|edge| edge.id).collect();
        before.sort();

        build_with(&dir, vec![file], &mut graph, 2, true);
        let mut after: Vec<crate::id::LocalEdgeId> =
            graph.edges.iter().map(|edge| edge.id).collect();
        after.sort();
        assert_eq!(before, after, "an unchanged relation is the same edge");
    }

    #[test]
    fn calling_the_same_function_twice_is_one_edge_carrying_a_count() {
        // A relation is a fact, not an occurrence. Emitting two would also be impossible:
        // both drafts resolve to one persisted identifier, and a change set with a repeated
        // identifier is refused. Found by rebuilding this crate.
        let dir = TempDir::new("repeat-call");
        let file = dir.write(
            "src/main.rs",
            "fn main() { helper(); helper(); helper(); }\nfn helper() {}\n",
        );
        let mut graph = Graph::default();
        build(&dir, vec![file.clone()], &mut graph, 1);

        let calls: Vec<&crate::graph::Edge> = graph
            .edges
            .iter()
            .filter(|edge| edge.relation.as_str() == CALLS)
            .collect();
        assert_eq!(calls.len(), 1, "one relation, however many call sites");
        assert_eq!(
            calls[0]
                .properties
                .iter()
                .find(|(key, _)| key.as_str() == "count")
                .map(|(_, value)| value.clone()),
            Some(PropertyValue::Integer(3)),
            "how many times is a property of the relation, not more relations"
        );

        // The rebuild is what used to be refused. Forced, so reuse does not skip it.
        build_with(&dir, vec![file], &mut graph, 2, true);
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| edge.relation.as_str() == CALLS)
                .count(),
            1
        );
    }

    #[test]
    fn a_cross_file_call_survives_every_rebuild() {
        // The property the whole reuse question is about. It holds now because a build
        // that reads anything reads everything; the finer rule that would have made this
        // interesting is the one that lost edges.
        let dir = TempDir::new("incremental-cross-file");
        let caller = dir.write("src/a.rs", "fn caller() { callee(); }\n");
        let callee = dir.write("src/b.rs", "fn callee() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![caller, callee.clone()], &mut graph, 1);
        let before = relations(&graph, CALLS);
        assert_eq!(before, [("caller".to_owned(), "callee".to_owned())]);

        let edited = dir.write("src/a.rs", "fn caller() { let x = 1; callee(); }\n");
        build(&dir, vec![edited, callee], &mut graph, 2);
        assert_eq!(
            relations(&graph, CALLS),
            before,
            "the edge survives an edit to the file it points out of"
        );
    }

    /// A graph reduced to what it says, with identifiers removed.
    ///
    /// Two independent builds mint different identifiers, so comparing them directly would
    /// only ever prove they are not the same object. What has to match is what they
    /// *assert*: which records exist, what each one says about itself, and which relations
    /// connect which of them.
    fn described(graph: &Graph) -> (Vec<String>, Vec<String>) {
        let describe_node = |node: &crate::graph::Node| {
            let mut labels: Vec<&str> =
                node.labels.iter().map(crate::name::Label::as_str).collect();
            labels.sort_unstable();
            let mut properties: Vec<String> = node
                .properties
                .iter()
                .map(|(key, value)| format!("{}={value:?}", key.as_str()))
                .collect();
            properties.sort();
            format!("[{}] {}", labels.join(","), properties.join(" "))
        };
        let node_of = |reference: &NodeReference| match reference {
            NodeReference::Local(id) => graph
                .nodes
                .iter()
                .find(|node| node.id == *id)
                .map_or_else(|| "?".to_owned(), &describe_node),
            NodeReference::External(scoped) => format!("external:{scoped}"),
        };

        let mut nodes: Vec<String> = graph.nodes.iter().map(&describe_node).collect();
        nodes.sort();
        let mut edges: Vec<String> = graph
            .edges
            .iter()
            .map(|edge| {
                let mut properties: Vec<String> = edge
                    .properties
                    .iter()
                    .map(|(key, value)| format!("{}={value:?}", key.as_str()))
                    .collect();
                properties.sort();
                format!(
                    "{} -[{} {}]-> {}",
                    node_of(&edge.source),
                    edge.relation.as_str(),
                    properties.join(" "),
                    node_of(&edge.target)
                )
            })
            .collect();
        edges.sort();
        (nodes, edges)
    }

    /// A tree with cross-file calls, a trait, an impl, and a repeated call.
    fn fixture(dir: &TempDir, body: &str) -> Vec<ScannedFile> {
        vec![
            dir.write(
                "src/a.rs",
                &format!("fn caller() {{ {body} callee(); callee(); }}\nfn only_here() {{}}\n"),
            ),
            dir.write(
                "src/b.rs",
                "pub fn callee() {}\nstruct Cursor;\ntrait Read {{ fn read(&self); }}\n",
            ),
            dir.write(
                "src/c.rs",
                "mod inner { pub fn nested() { super::super::callee(); } }\n",
            ),
        ]
    }

    #[test]
    fn an_incremental_build_and_a_fresh_one_produce_the_same_graph() {
        // The property the reuse work is answerable for, and the one a comment-only edit
        // reporting deletions with no creations put in doubt. Identifiers are dropped
        // before comparing: two independent builds mint different ones, and what has to
        // match is what the graphs assert rather than which objects they are.
        let incremental = TempDir::new("same-graph-incremental");
        let mut built = Graph::default();
        build(&incremental, fixture(&incremental, ""), &mut built, 1);
        let edited = fixture(&incremental, "let x = 1;");
        let draft = build(&incremental, edited, &mut built, 2);
        assert_eq!(
            draft.analyzed_files, 3,
            "one file changed, so all three are read"
        );

        let fresh_dir = TempDir::new("same-graph-fresh");
        let mut fresh = Graph::default();
        build(&fresh_dir, fixture(&fresh_dir, "let x = 1;"), &mut fresh, 1);

        let (built_nodes, built_edges) = described(&built);
        let (fresh_nodes, fresh_edges) = described(&fresh);
        assert_eq!(built_nodes, fresh_nodes, "the records must agree");
        assert_eq!(built_edges, fresh_edges, "the relations must agree");
    }

    #[test]
    fn a_forced_rebuild_and_an_incremental_one_produce_the_same_graph() {
        // The same property from the other side: reuse must not be the reason a graph
        // differs, so redoing the work over the same source must reach the same place.
        let dir = TempDir::new("same-graph-forced");
        let mut incremental = Graph::default();
        build(&dir, fixture(&dir, ""), &mut incremental, 1);
        build(&dir, fixture(&dir, "let x = 1;"), &mut incremental, 2);

        let forced_dir = TempDir::new("same-graph-forced-full");
        let mut forced = Graph::default();
        build(&forced_dir, fixture(&forced_dir, ""), &mut forced, 1);
        build_with(
            &forced_dir,
            fixture(&forced_dir, "let x = 1;"),
            &mut forced,
            2,
            true,
        );

        assert_eq!(described(&incremental), described(&forced));
    }
}
