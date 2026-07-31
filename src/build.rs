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

use crate::analysis::{CapabilityRegistry, PrecisionClass};
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

/// The label a framework's entry point carries.
///
/// `Endpoint` rather than `EntryPoint`, which is the fact kind's name. An HTTP route is one kind of
/// configuration-defined entry point and a scheduled job is another, and giving them one label with a
/// `kind` property would make every query about routes filter on a property to avoid matching jobs. The
/// fact kind stays the general one; the label names the specific thing.
pub const ENDPOINT_LABEL: &str = "Endpoint";

/// Relation from a framework's entry point to the declaration that serves it.
pub const HANDLED_BY: &str = "HANDLED_BY";

/// The label a framework analyzer's user-interface component carries.
///
/// A record of its own rather than a second label on the declaration, for the reason `Endpoint` is one: a
/// framework analyzer declares its own version and capability, and root `docs/PRD.md` section 11.3 lets it
/// withdraw only its own contributions. A label added to a record the language analyzer owns could not be
/// withdrawn when the framework analyzer's version moved.
pub const COMPONENT_LABEL: &str = "Component";

/// Relation from a component to the declaration that defines it.
///
/// Not `HANDLED_BY`, which says something different: an entry point is *served by* a handler it names, and a
/// component *is* its declaration seen through a framework's eyes. One relation for both would make
/// "what serves this route" and "where is this component written" the same question.
pub const DECLARED_BY: &str = "DECLARED_BY";

/// The label every directory in the source tree carries.
pub const DIRECTORY_LABEL: &str = "Directory";

/// The label a file carries when analyzed source imports it and no analyzer read it.
///
/// An image, a font, a media file — anything a component imports by path and the scanner skipped. It is
/// in the graph because **analyzed source references it**, not because the scan found it: root
/// `docs/PRD.md` section 17.2 requires the scanner to skip a binary file unless an analyzer supports one,
/// and this record does not change that. The bytes are never read, never sniffed, and never analyzed.
///
/// What is asserted is exactly what is known: something at this path was imported, it was skipped, and
/// this is why. Duration, codec, and resolution are not here, because reading them would mean opening the
/// file — which is the thing section 17.2 forbids and nothing about an import requires.
pub const ASSET_LABEL: &str = "Asset";

/// The path recorded for the project root, which has no name of its own.
pub const ROOT_PATH: &str = ".";

/// Relation from a container to what it declares.
pub const CONTAINS: &str = "CONTAINS";

/// Relation from a function to a name it calls.
pub const CALLS: &str = "CALLS";

/// Relation from an implementation to the trait it implements.
pub const IMPLEMENTS: &str = "IMPLEMENTS";

/// Relation from an implementation to the type it is for.
pub const FOR_TYPE: &str = "FOR_TYPE";

/// Relation from a file to a file it imports from.
///
/// File to file, rather than to the imported declaration, because that is what the import proves. An
/// import names a path; whether the declaration at the end of it is the one a reader means is a
/// question about resolution, and at [`PrecisionClass::DeterministicSyntactic`] this build does not
/// answer it. What it can state exactly is which file in this project the path names.
pub const IMPORTS: &str = "IMPORTS";

/// Version of what this module asserts about a file.
///
/// Part of every parse cache key, so changing a label, a property, or a relation makes
/// every stored artifact miss instead of being read back into a shape that no longer
/// matches. Bump it whenever what a build asserts about a file changes.
///
/// **It is now the only such number, which widens what "changes" means.** No analyzer declares a version, so
/// a change to one language's reader is no longer invalidated by that reader's own constant — this is what has
/// to move for it, even when every label and property stays identical. A parser that starts recording a
/// declaration it used to skip changes what a build asserts, and a warm cache will serve the old answer until
/// this moves.
///
/// Coarser than a version per analyzer, deliberately: one hand-maintained number is one thing to forget
/// rather than two. The trade is recorded in Stage 22.
///
/// 10 because the Kotlin analyzer keeps the annotations on a primary-constructor property, which it used to
/// drop. A database built before it holds no record of `@NotBlank` on a `data class` field and the bytes did
/// not change, so reuse would keep that absence for ever.
///
/// It is also recorded on every file node, and reuse requires the stored value to match. Without
/// that, a database written by an earlier shape keeps it forever: reuse compares digests, an
/// unchanged tree is never read, and so nothing would ever rewrite records that predate a new
/// property. A version bump is the migration — the next build redraws what it holds.
///
/// 9 because a file node now carries the package it declares, and because a qualified import is resolved
/// against what a file declares rather than against what it is named. A database built before this holds
/// `IMPORTS` edges the current rule would not draw — and is missing ones it would — and reuse would keep
/// them, because the bytes did not change.
pub const GRAPH_SCHEMA_VERSION: u32 = 10;

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
    /// Where a parse may be read from and stored.
    pub cache: &'a crate::cache::ParseCache,
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
    /// How many files hold a record, whether or not an analyzer read them.
    ///
    /// Separate from `analyzed_files` because the two answer different questions. A project with
    /// no analyzer for its language records every file and analyzes none, and reporting one number
    /// for both would either claim coverage the build lacks or hide the graph it committed.
    pub recorded_files: u64,
    /// References that matched a record in this build.
    pub resolved_references: u64,
    /// Files whose recorded facts were reused rather than re-read.
    pub reused_files: u64,
    /// Files whose parse came from the cache rather than from the source.
    pub cached_parses: u64,
    /// Framework entry points recorded.
    pub endpoints: u64,
    /// Framework user-interface components recorded.
    pub components: u64,
    /// The frameworks whose analyzers recognised something, in name order.
    pub frameworks: Vec<String>,
    /// Annotation names no framework analyzer interpreted, in name order.
    ///
    /// The capability diagnostic section 17.3 requires, and the evidence a caller needs to decide what
    /// is worth enriching. Reported by annotation name rather than by framework: naming a framework this
    /// build cannot read would need a list of frameworks it knows of and cannot read, which is a closed
    /// allowlist by another route.
    pub uninterpreted_annotations: Vec<String>,
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

/// One file's place in a build: its persisted identity, and whatever was learned about it.
struct Unit {
    /// The path relative to the scan root.
    path: String,
    /// The source unit its contributions belong to.
    unit: SourceUnitId,
    /// The file node an earlier build minted for it, when there is one.
    existing: Option<LocalNodeId>,
    /// The facts found in it, which for a recorded file is none.
    analysis: FileAnalysis,
    /// Whether an analyzer read the file, rather than the scan merely recording it.
    ///
    /// Stored rather than derived from the language's precision, because a file whose language
    /// *is* covered still arrives here unanalyzed when its bytes could not be read. Deriving it
    /// would count that file as analyzed and report coverage the build does not have.
    analyzed: bool,
}

impl Unit {
    /// A file an analyzer read.
    fn analyzed(
        path: String,
        unit: SourceUnitId,
        existing: Option<LocalNodeId>,
        analysis: FileAnalysis,
    ) -> Self {
        Self {
            path,
            unit,
            existing,
            analysis,
            analyzed: true,
        }
    }

    /// A file the scan named and nothing analyzed.
    ///
    /// Its bytes are not read. The path, the language, and the digest are all the scan's, so the
    /// record costs nothing beyond the node itself — which is the point: a language with no
    /// analyzer is a gap in depth rather than a reason for a repository to be absent from its own
    /// graph.
    fn recorded(
        file: &crate::scan::ScannedFile,
        held: Option<(SourceUnitId, Option<LocalNodeId>)>,
        minter: &mut Minter,
    ) -> Self {
        let (unit, existing) = held.unwrap_or_else(|| (minter.source_unit(), None));
        Self {
            path: file.path.clone(),
            unit,
            existing,
            analysis: FileAnalysis {
                language: file.language.clone(),
                digest: file.digest.clone(),
                // Nothing read this file, so it declares nothing — including no package.
                package: None,
                items: Vec::new(),
                imports: Vec::new(),
            },
            analyzed: false,
        }
    }
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
    let mut units: Vec<Unit> = Vec::new();
    let mut cached_parses = 0_u64;

    // Reuse is decided before anything is read, and it is all or nothing.
    //
    // A finer rule was tried — reuse per file, with references resolved against reused
    // records as well as fresh ones — and it lost edges. Building this crate and then
    // editing one comment produced 1275 `CALLS` edges where a full build of the same source
    // produces 1308, and a forced rebuild immediately after created exactly the 33 that
    // were missing. The cause is a difference between resolving against one index and
    // resolving against two, and it is not yet understood.
    //
    // Until it is, the finer rule is not worth having: a graph that depends on how it was
    // built is worse than one that took longer to build. What survives is the case that
    // matters most and is provably safe — a tree where nothing changed is not read at all.
    // The parse cache below recovers most of the rest, without touching resolution.
    if !request.rebuild
        && let Some(unchanged) = every_file_unchanged(scan, graph)
    {
        // Complete, not skipped. Everything is covered — it was covered by an earlier
        // build and nothing has changed since. Reporting `skipped` would say the opposite
        // of what happened.
        coverage.structural = CoverageState::Complete;
        return BuildDraft {
            change_set: GraphChangeSet::new(
                analyzer_owner(),
                NonEmptyText::new(request.revision)
                    .unwrap_or_else(|_| NonEmptyText::literal("tree:unknown")),
                request.base_generation,
            ),
            coverage,
            endpoints: 0,
            components: 0,
            frameworks: Vec::new(),
            uninterpreted_annotations: Vec::new(),
            analyzed_files: 0,
            recorded_files: 0,
            resolved_references: 0,
            reused_files: unchanged,
            cached_parses: 0,
        };
    }

    // Pass one: read and analyze, and settle each file's persisted identity.
    //
    // A file the scan kept always leaves a record. Section 17.3 requires it — an unsupported
    // language "at minimum produces a source/module record with an explicit capability
    // diagnostic" — and coverage below says what could not be done with it. What an analyzer
    // adds is facts *inside* that record, so its absence costs depth and not existence.
    for file in &scan.files {
        let held = existing_unit(graph, &file.path);
        if !registry.precision(&file.language).is_deterministic() {
            // The capability diagnostic. Recording the file is not claiming to have read it,
            // so this entry stays and `structural` stays short of `Complete`.
            //
            // A file whose language could not be named is reported as unclassified rather than
            // unsupported. Section 17.2 requires both in coverage and they are different facts:
            // one says no analyzer covers this language, the other says there was no language to
            // look up. Collapsing them would lose the distinction the section asks for.
            coverage.skipped_sources.push(SkippedSource {
                source: locator.clone(),
                path: NonEmptyText::new(&file.path).ok(),
                reason: match file.language == crate::scan::UNKNOWN_LANGUAGE {
                    true => SkipReason::Unclassified,
                    false => SkipReason::Unsupported,
                },
            });
            units.push(Unit::recorded(file, held, minter));
            continue;
        }
        // The parse cache is orthogonal to reuse, and deliberately so. A cached parse
        // still enters `units`, so the name index this build resolves against is complete;
        // what is saved is the reading and the parsing, not the resolving. That is the
        // half of incremental work that was provably safe to keep.
        let parse_key = parse_cache_key(file);
        if let Some(analysis) = request.cache.get(&parse_key) {
            cached_parses += 1;
            let (unit, existing) = held.unwrap_or_else(|| (minter.source_unit(), None));
            units.push(Unit::analyzed(file.path.clone(), unit, existing, analysis));
            continue;
        }
        let Ok(source) = std::fs::read_to_string(root.join(&file.path)) else {
            coverage.skipped_sources.push(SkippedSource {
                source: locator.clone(),
                path: NonEmptyText::new(&file.path).ok(),
                reason: SkipReason::PermissionDenied,
            });
            units.push(Unit::recorded(file, held, minter));
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
            units.push(Unit::recorded(file, held, minter));
            continue;
        };
        let (unit, existing) = held.unwrap_or_else(|| {
            // A file nothing has analyzed before. Its unit is minted once and then
            // persists on the File node's contribution.
            (minter.source_unit(), None)
        });
        // Stored before the build commits anything. A parse depends on the bytes and the
        // analyzer, not on whether the transaction that follows succeeds, so an abandoned
        // build still leaves work its successor can use.
        let _ = request.cache.put(&parse_key, &analysis);
        units.push(Unit::analyzed(file.path.clone(), unit, existing, analysis));
    }

    // A file the source no longer holds must take its records with it. Nothing else would
    // ever remove them: they belong to a unit no scan will name again.
    // Settled before the departed set, because the tree is a unit this build still holds. Left out
    // of `present` it would look like a deleted file, its directories would be withdrawn, and every
    // build would report the whole tree as changed.
    let tree_unit = existing_tree_unit(graph).unwrap_or_else(|| minter.source_unit());
    let mut present: BTreeSet<SourceUnitId> = units.iter().map(|held| held.unit).collect();
    present.insert(tree_unit);
    let departed: Vec<SourceUnitId> = analyzed_units(graph)
        .into_iter()
        .filter(|unit| !present.contains(unit))
        .collect();

    // Reuse is only sound while the names the unchanged files could refer to have not
    // moved. When a rebuilt file adds or removes a declared name, an edge from a file this
    // build never read may have become right or wrong, and the only honest answer at
    // syntactic precision is to read them all. That is the "affected context-resolution
    // units" half of section 17.8, taken conservatively rather than approximately.
    let mut change_set = GraphChangeSet::new(
        analyzer_owner(),
        NonEmptyText::new(request.revision)
            .unwrap_or_else(|_| NonEmptyText::literal("tree:unknown")),
        request.base_generation,
    );

    // Every unit being rebuilt withdraws its previous claim first, so a record the source
    // no longer declares disappears rather than lingering. A departed file withdraws its
    // claim and restates nothing, which is what removes it.
    // The tree's unit withdraws with the rest. It is redrawn in full below, and without the
    // withdrawal a directory whose last file was deleted would keep being claimed: it is upserted
    // when it exists and nothing would ever remove it when it stops existing.
    //
    // Only when there is a tree to speak about, though. A project holding nothing this build
    // records has no directories to withdraw and none to draw, and a change set carrying a lone
    // withdrawal would commit a generation on every build over a project that never changes.
    let redraw_tree = !units.is_empty() || existing_tree_unit(graph).is_some();
    for unit in units
        .iter()
        .map(|held| held.unit)
        .chain(redraw_tree.then_some(tree_unit))
        .chain(departed.iter().copied())
    {
        change_set.push(GraphOperation::RemoveContribution(ContributionKey {
            owner: analyzer_owner(),
            source_unit: unit,
        }));
    }

    // Pass two: settle every identifier before any edge needs one.
    let mut file_nodes: Vec<(usize, LocalNodeId)> = Vec::new();
    for (index, held) in units.iter().enumerate() {
        let known = existing_names(graph, held.unit);
        let context = FileContext {
            unit: held.unit,
            path: &held.path,
            known: &known,
        };
        let mut seen: BTreeMap<String, i64> = BTreeMap::new();
        let file_id = held.existing.unwrap_or_else(|| minter.node());
        file_nodes.push((index, file_id));
        for item in &held.analysis.items {
            plan_item(item, "", &context, &mut seen, minter, &mut planned);
        }
    }

    // Pass three: the drafts themselves, now that every identifier is known.
    for (index, held) in units.iter().enumerate() {
        let file_id = file_nodes[index].1;
        let mut properties = vec![
            text_property("path", &held.path),
            text_property("language", &held.analysis.language),
            text_property("digest", held.analysis.digest.as_str()),
            // What a reader may conclude from this record, per section 17.3's requirement
            // that results not imply equal confidence for every language. `unsupported`
            // says the file is here and nothing read it, which is a different claim from
            // an analyzer having found no items in it.
            text_property("precision", &precision_of(registry, held).to_string()),
            integer_property("schema_version", i64::from(GRAPH_SCHEMA_VERSION)),
        ];
        // Written only when the file declared one, because absent and empty are different answers: a Rust
        // file has no package to name, and a Kotlin file in the default package wrote none. An empty string
        // would make the two indistinguishable and would claim a package named "".
        if let Some(package) = &held.analysis.package {
            properties.push(text_property("package", package));
        }
        change_set.push(GraphOperation::UpsertNode(NodeDraft {
            id: Some(file_id),
            labels: vec![label(FILE_LABEL)],
            properties,
            source_unit: held.unit,
            evidence: vec![file_evidence(&locator, held)],
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
    let resolve = |name: &str| -> Option<LocalNodeId> {
        match by_name.get(name)?.as_slice() {
            [only] => Some(planned[*only].id),
            _ => None,
        }
    };

    for record in &planned {
        let analysis = units
            .iter()
            .find(|held| held.path == record.path)
            .map(|held| &held.analysis);
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

    // Framework entry points, and the declarations that serve them.
    //
    // Drafted after every item node exists, so `HANDLED_BY` can name the method it points at. A route
    // whose handler is not among the planned records gets the edge omitted rather than a placeholder:
    // the endpoint is still a fact about the project, and inventing a handler would assert a method the
    // source does not declare.
    let mut uninterpreted: BTreeSet<String> = BTreeSet::new();
    let mut framework_names: BTreeSet<String> = BTreeSet::new();
    let mut endpoints_found = 0_u64;
    let mut components_found = 0_u64;
    for (index, held) in units.iter().enumerate() {
        if !held.analyzed {
            continue;
        }
        let framework = crate::analyze::framework::analyze(&held.analysis);
        uninterpreted.extend(framework.uninterpreted.iter().cloned());
        framework_names.extend(framework.frameworks.iter().cloned());
        let file_id = file_nodes[index].1;
        for endpoint in &framework.endpoints {
            endpoints_found += 1;
            let id = minter.node();
            change_set.push(GraphOperation::UpsertNode(NodeDraft {
                id: Some(id),
                labels: vec![label(ENDPOINT_LABEL)],
                properties: vec![
                    text_property("method", &endpoint.method),
                    text_property("path", &endpoint.path),
                    text_property("handler", &endpoint.handler),
                    text_property(
                        "framework",
                        &framework
                            .frameworks
                            .iter()
                            .next()
                            .cloned()
                            .unwrap_or_default(),
                    ),
                    // A framework analyzer reads what a language analyzer wrote down, so its precision
                    // is its own and is recorded on the record. Section 17.3 requires that nothing imply
                    // an AI-inferred route has the confidence of a read one.
                    text_property(
                        "precision",
                        &crate::analyze::framework::spring::PRECISION.to_string(),
                    ),
                    integer_property("schema_version", i64::from(GRAPH_SCHEMA_VERSION)),
                ],
                source_unit: held.unit,
                evidence: vec![framework_evidence(&locator, held, endpoint)],
            }));
            // The handler, by name, among the records planned for this same file. Matched within the
            // file rather than across the build: two files may each declare a `callback`, and a route in
            // one of them is served by its own.
            if let Some(record) = planned
                .iter()
                .find(|record| record.path == held.path && record.name == endpoint.handler)
            {
                edges.add(id, record.id, HANDLED_BY, held.unit);
            }
            edges.add(file_id, id, CONTAINS, held.unit);
        }

        // Components, which are the same shape of fact about a different kind of thing.
        for component in &framework.components {
            components_found += 1;
            let id = minter.node();
            change_set.push(GraphOperation::UpsertNode(NodeDraft {
                id: Some(id),
                labels: vec![label(COMPONENT_LABEL)],
                properties: vec![
                    text_property("name", &component.name),
                    text_property(
                        "framework",
                        &framework
                            .frameworks
                            .iter()
                            .next()
                            .cloned()
                            .unwrap_or_default(),
                    ),
                    // The analyzer's class, and then how *this* component was recognised. One analyzer may
                    // know some exactly and others by convention, and a reader judging a count needs the
                    // second number rather than the first.
                    text_property(
                        "precision",
                        &crate::analyze::framework::react::PRECISION.to_string(),
                    ),
                    text_property("recognised_by", &component.recognised_by.to_string()),
                    integer_property("schema_version", i64::from(GRAPH_SCHEMA_VERSION)),
                ],
                source_unit: held.unit,
                evidence: vec![component_evidence(&locator, held, component)],
            }));
            if let Some(record) = planned
                .iter()
                .find(|record| record.path == held.path && record.name == component.name)
            {
                edges.add(id, record.id, DECLARED_BY, held.unit);
            }
            edges.add(file_id, id, CONTAINS, held.unit);
        }
    }

    // The tree the files sit in.
    //
    // Without it a graph is a bag of files. That is enough to satisfy section 17.3's minimum, and
    // it is not enough to be worth querying: a project with no analyzer for its language would hold
    // records nothing connects, and "which files are under docs/" would be a string comparison
    // rather than a traversal.
    //
    // Paths are the only input, so this is deterministic, language-neutral, and spends nothing.
    let mut directories: BTreeMap<String, LocalNodeId> = BTreeMap::new();
    let mut ancestors: BTreeSet<String> = BTreeSet::new();
    for held in &units {
        let mut at = parent_of(&held.path);
        loop {
            let next = parent_of(&at);
            ancestors.insert(at.clone());
            if at == ROOT_PATH {
                break;
            }
            at = next;
        }
    }
    for path in &ancestors {
        let id = existing_directory(graph, path).unwrap_or_else(|| minter.node());
        directories.insert(path.clone(), id);
        change_set.push(GraphOperation::UpsertNode(NodeDraft {
            id: Some(id),
            labels: vec![label(DIRECTORY_LABEL)],
            properties: vec![
                text_property("path", path),
                integer_property("schema_version", i64::from(GRAPH_SCHEMA_VERSION)),
            ],
            source_unit: tree_unit,
            evidence: vec![directory_evidence(&locator, path)],
        }));
    }
    // A directory to its parent directory, and to every file directly in it. Both endpoints are
    // drafted above, so no edge can name one that does not exist.
    for (path, id) in &directories {
        if path == ROOT_PATH {
            continue;
        }
        if let Some(parent) = directories.get(&parent_of(path)) {
            edges.add(*parent, *id, CONTAINS, tree_unit);
        }
    }
    for (index, held) in units.iter().enumerate() {
        if let Some(parent) = directories.get(&parent_of(&held.path)) {
            edges.add(*parent, file_nodes[index].1, CONTAINS, tree_unit);
        }
    }

    // Imports, which two analyzers have declared `FactKind::ImportExport` for since they were written
    // and neither produced. `analysis.imports` was read only by the parse cache and by Spring's
    // recognition check, so no import has ever reached the graph.
    //
    // Resolved by one of two rules, chosen by whether the importing file declared a package:
    //
    // - **by declared name**, where it did. `com.demo.app.Payload` is answered by the file declaring
    //   `Payload` in package `com.demo.app`, whatever that file is called. This is the only sound rule for
    //   Kotlin, which does not require a declaration to sit in a file of its own name;
    // - **by path correspondence**, where it did not. `a::b` names `…/a/b.<ext>`, so the import is matched
    //   against the paths this build actually scanned.
    //
    // Either way it is exact, never a guess: the module documentation above explains why an unresolved
    // *call* must not become a Placeholder, and an import is the stronger case, because most imports in any
    // real file name a dependency. This file's own reported repository imports
    // `org.springframework.boot.runApplication`, and nothing in the project declares it.
    //
    // Matching by last segment would be cheaper and wrong under either rule: `import java.util.List` in a
    // project that declares exactly one `List` would resolve to it, and the graph would assert that a file
    // imports a class it does not import. Resolving a *package-qualified* name is what rules that out
    // exactly, rather than relying on a path suffix being hard to produce by accident.
    //
    // Counted with every other reference, because an import is one: a name in one file that either
    // matches a record in this build or names something outside it.
    let mut resolved = 0_u64;
    let mut unresolved = 0_u64;
    let by_file_path: BTreeMap<&str, LocalNodeId> = units
        .iter()
        .enumerate()
        .map(|(index, held)| (held.path.as_str(), file_nodes[index].1))
        .collect();
    // What the scan saw and did not read, which is where an asset comes from.
    //
    // `Binary` and `TooLarge` only. An `Ignored` file was excluded on purpose and a `Sensitive` one was
    // withheld, so importing either must not put it in the graph by another route — the exclusion is the
    // decision, and an import does not overrule it. A `PermissionDenied` file was never established to
    // exist at all.
    let assets_available: BTreeMap<&str, SkipReason> = scan
        .skipped
        .iter()
        .filter(|held| matches!(held.reason, SkipReason::Binary | SkipReason::TooLarge))
        .filter_map(|held| held.path.as_ref().map(|path| (path.as_str(), held.reason)))
        .collect();
    let mut assets: BTreeMap<String, LocalNodeId> = BTreeMap::new();

    // Every declaration this build makes available under a package, mapped to the file declaring it.
    //
    // This is what a dotted import is matched against, and it exists because a file name cannot answer one.
    // Kotlin does not require `class Payload` to be declared in `Payload.kt`, so a path match either misses
    // the declaration or attaches the import to whatever file happens to carry the name — and the second is
    // the graph asserting an import of something a file does not declare, which is the error the
    // last-segment rule was rejected for.
    //
    // Top-level declarations only. An import naming a nested type is answered by walking back to the outer
    // one, which is in here.
    //
    // `None` marks a name two files declare, for the reason [`only_match`] gives: neither is the answer. Two
    // declarations of one name in the *same* file — overloads — are not a collision and stay resolvable.
    let mut by_declared_name: BTreeMap<String, Option<LocalNodeId>> = BTreeMap::new();
    for (index, held) in units.iter().enumerate() {
        let Some(package) = &held.analysis.package else {
            continue;
        };
        let file_id = file_nodes[index].1;
        for item in &held.analysis.items {
            by_declared_name
                .entry(format!("{package}.{}", item.name))
                .and_modify(|found| {
                    if *found != Some(file_id) {
                        *found = None;
                    }
                })
                .or_insert(Some(file_id));
        }
    }

    for (index, held) in units.iter().enumerate() {
        let from = file_nodes[index].1;
        let directory = parent_of(&held.path);
        for import in &held.analysis.imports {
            // A file that declared a package writes its imports as qualified names of declarations, so they
            // are resolved as that and not as paths. There is deliberately no path fallback here: path
            // correspondence is the guess being removed, and an unresolved import is the honest answer,
            // because most imports in any real file name a dependency this build never scanned.
            let found = match &held.analysis.package {
                Some(_) => imported_declaration(&import.path, &by_declared_name),
                None => imported_file(&import.path, &directory, &by_file_path),
            };
            if let Some(target) = found {
                if target != from {
                    resolved += 1;
                    edges.add(from, target, IMPORTS, held.unit);
                    continue;
                }
                unresolved += 1;
                continue;
            }
            // Nothing analyzed answers to it. Something the scan skipped may, and that is an asset: a
            // file this project imports and no analyzer read.
            match imported_asset(&import.path, &directory, &assets_available) {
                Some(path) => {
                    resolved += 1;
                    let id = *assets.entry(path.clone()).or_insert_with(|| {
                        existing_asset(graph, &path).unwrap_or_else(|| minter.node())
                    });
                    edges.add(from, id, IMPORTS, held.unit);
                }
                // A dependency, an ambiguous path, or a path naming nothing at all. Counted like every
                // other reference that names nothing in this build.
                None => unresolved += 1,
            }
        }
    }

    // Drafted after the loop so one asset imported by three components is one record. Owned by the tree
    // unit for the reason a directory is: it is something the scan observed, no analyzer read it, and
    // owning it through one importing file would delete it when that file stopped importing it while
    // another still did.
    for (path, id) in &assets {
        let reason = assets_available
            .get(path.as_str())
            .map_or_else(String::new, ToString::to_string);
        change_set.push(GraphOperation::UpsertNode(NodeDraft {
            id: Some(*id),
            labels: vec![label(ASSET_LABEL)],
            properties: vec![
                text_property("path", path),
                text_property("skipped", &reason),
                integer_property("schema_version", i64::from(GRAPH_SCHEMA_VERSION)),
            ],
            source_unit: tree_unit,
            evidence: vec![directory_evidence(&locator, path)],
        }));
    }

    // Containment: from the file to each top-level record, and from each record to its
    // children. Emitted after every node, so no edge can name an endpoint not yet drafted.
    for (index, held) in units.iter().enumerate() {
        let file_id = file_nodes[index].1;
        for record in planned
            .iter()
            .filter(|record| record.path == held.path && !record.qualified.contains("::"))
        {
            edges.add(file_id, record.id, CONTAINS, held.unit);
        }
    }
    for record in &planned {
        for child in &record.children {
            let child = &planned[*child];
            edges.add(record.id, child.id, CONTAINS, record.unit);
        }
    }

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
        // A method carries a target when the language states one in the declaration itself, which Go does
        // with a receiver: `func (s *Service) Do()` says both that `Do` exists and what it is on. Rust
        // states it on the `impl` block instead, so both kinds reach this edge.
        //
        // Nothing else sets `target` on a method, so this is additive: Kotlin, Java, TypeScript, and
        // Python put a method inside its type's body, where containment already says whose it is.
        if let Some(name) = &record.target
            && matches!(record.kind, ItemKind::Implementation | ItemKind::Method)
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
        // Recorded is not analyzed. A build that recorded 41 Kotlin files and read none of
        // them reports zero here, because this is what `plan` predicts as `structural_files`
        // and the two are checked against each other.
        endpoints: endpoints_found,
        components: components_found,
        frameworks: framework_names.into_iter().collect(),
        uninterpreted_annotations: uninterpreted.into_iter().collect(),
        analyzed_files: units.iter().filter(|held| held.analyzed).count() as u64,
        recorded_files: units.len() as u64,
        resolved_references: resolved,
        reused_files: 0,
        cached_parses,
    }
}

/// How many files are already recorded exactly as they are on disk, when every one is.
///
/// Returns `None` the moment anything differs — a changed file, a new file, a file the
/// database holds that the scan no longer names — because reuse is all or nothing and
/// there is nothing to gain from counting further.
fn every_file_unchanged(scan: &Scan, graph: &Graph) -> Option<u64> {
    let mut present: BTreeSet<SourceUnitId> = BTreeSet::new();
    let mut count = 0_u64;
    // Every file the scan kept, not only the analyzable ones. A recorded file holds a digest,
    // so skipping it here would let an edit to a Kotlin file leave its record stale while the
    // build reported that nothing had changed.
    for file in &scan.files {
        let (unit, Some(node)) = existing_unit(graph, &file.path)? else {
            return None;
        };
        if stored_digest(graph, node) != Some(file.digest.as_str()) {
            return None;
        }
        // Written by an earlier record shape. The bytes are unchanged, so nothing else here would
        // ever notice, and the records would keep a shape this build no longer produces.
        if stored_schema_version(graph, node) != Some(i64::from(GRAPH_SCHEMA_VERSION)) {
            return None;
        }
        present.insert(unit);
        count += 1;
    }
    // A unit the database holds and the scan no longer names is a deleted file, which is a
    // change even though no file this scan saw differs. The tree's own unit is exempt: it holds
    // directories rather than files, so no scan names it and it is never deleted.
    let tree = existing_tree_unit(graph);
    if analyzed_units(graph)
        .iter()
        .any(|unit| !present.contains(unit) && Some(*unit) != tree)
    {
        return None;
    }
    (count > 0).then_some(count)
}

/// A schema for every label this module writes.
///
/// # Why the Engine declares these at all
///
/// `nost_language_version` section 5.3.3 permits a record to name a schema nothing declares, and calls
/// the consequence "accepted rather than solved": a misspelled schema name is indistinguishable from an
/// intentional bare label. A materialized `.nost` was therefore valid and said nothing about the shape of
/// anything in it.
///
/// The Engine knows that shape exactly — it wrote the records. Declaring it makes the export
/// self-describing and turns a hand-edited misspelling into a `NOST_SCHEMA_VIOLATION` warning, which is
/// the same gap `CYPHER_UNKNOWN_LABEL` closes on the query side.
///
/// # These are unowned, and that has a cost
///
/// A schema declaration carries no `@by` in version 2 and [`Schema`] carries no owner, so these are
/// indistinguishable from a schema somebody wrote by hand. **A hand-written schema of the same name is
/// replaced on the next build.** That was chosen deliberately over a language version bump, and the
/// build warns when the schema it replaces differed from what it declares — which is not ownership, but
/// it does mean nothing is lost silently.
///
/// They are also not change-set operations, because there is no operation for a schema: a change set
/// carries contributions and validates their owner, and a thing with no owner does not fit it.
///
/// # Node schemas only
///
/// No edge schema is declared. An endpoint constraint names one source schema and one target schema, and
/// `CONTAINS` legitimately runs `Directory -> File`, `Directory -> Directory`, `File -> Struct`,
/// `File -> Endpoint`, and `Struct -> Method`. One constraint cannot describe that, and declaring any one
/// of them would raise a violation on every edge of the other shapes.
#[must_use]
pub fn schemas() -> Vec<crate::schema::Schema> {
    use crate::schema::{FieldType, ScalarType, Schema, SchemaField};

    let field = |key: &str, scalar: ScalarType, required: bool| SchemaField {
        key: PropertyKey::new(key).unwrap_or_else(|_| PropertyKey::literal("unknown")),
        field_type: FieldType::scalar(scalar),
        required,
    };
    let text = |key: &str| field(key, ScalarType::String, true);
    let number = |key: &str| field(key, ScalarType::Integer, true);
    let optional_text = |key: &str| field(key, ScalarType::String, false);
    let schema = |name: &str, fields: Vec<SchemaField>| Schema {
        name: Label::new(name).unwrap_or_else(|_| Label::literal("Unknown")),
        endpoints: None,
        fields,
    };

    // Every item label shares one shape, because `plan_item` writes one set of properties for all of
    // them. Listed from `label_for` rather than repeated, so a new `ItemKind` cannot gain a label with no
    // schema — the test below requires every label this module can write to appear here.
    let item = |name: &str| {
        schema(
            name,
            vec![
                text("name"),
                text("qualified_name"),
                text("path"),
                number("ordinal"),
                number("line"),
                number("end_line"),
            ],
        )
    };

    let mut declared = vec![
        schema(
            FILE_LABEL,
            vec![
                text("path"),
                text("language"),
                text("digest"),
                text("precision"),
                number("schema_version"),
                // Optional, because most languages declare no package and a file that declares none carries
                // no such property. Required would make every Rust and TypeScript file a warning.
                optional_text("package"),
            ],
        ),
        schema(
            DIRECTORY_LABEL,
            vec![text("path"), number("schema_version")],
        ),
        schema(
            ASSET_LABEL,
            // `skipped` is why no analyzer read it, carried so a reader can tell an image from a file
            // too large to open. Without it every asset would look alike and the graph would answer
            // "why is there nothing inside this" with silence.
            vec![text("path"), text("skipped"), number("schema_version")],
        ),
        schema(
            COMPONENT_LABEL,
            vec![
                text("name"),
                text("framework"),
                text("precision"),
                text("recognised_by"),
                number("schema_version"),
            ],
        ),
        schema(
            ENDPOINT_LABEL,
            vec![
                text("method"),
                text("path"),
                text("handler"),
                text("framework"),
                text("precision"),
                number("schema_version"),
            ],
        ),
    ];
    declared.extend(
        EVERY_ITEM_KIND
            .into_iter()
            .map(|kind| item(label_for(kind))),
    );
    declared
}

/// Every kind an item can be, so nothing that gains a label can miss a schema.
const EVERY_ITEM_KIND: [ItemKind; 11] = [
    ItemKind::Module,
    ItemKind::Struct,
    ItemKind::Enum,
    ItemKind::Union,
    ItemKind::Trait,
    ItemKind::TypeAlias,
    ItemKind::Function,
    ItemKind::Method,
    ItemKind::Field,
    ItemKind::Constant,
    ItemKind::Implementation,
];

/// The key a file's parse is stored under.
#[must_use]
pub fn parse_cache_key(file: &crate::scan::ScannedFile) -> crate::cache::StructuralParseCacheKey {
    crate::cache::StructuralParseCacheKey {
        content_digest: file.digest.clone(),
        language: file.language.clone(),
        // The language alone. No analyzer declares a version to put here, so what keeps a stored parse
        // from being read back into a shape that no longer matches is `graph_schema_version` below — the
        // one number that has to move when what a build asserts about a file changes.
        //
        // Still named per language rather than fixed, because two analyzers must not share one identity:
        // a Kotlin parse stored under Rust's would be handed to whichever reader asked for it.
        //
        // The trade this makes is recorded in Stage 22. A change to one language's reader that leaves the
        // record shape alone is no longer invalidated by that reader's own version, so `GRAPH_SCHEMA_VERSION`
        // is what has to move for it — one hand-maintained number where there were two.
        analyzer_digest: file.language.clone(),
        analyzer_config_digest: "default".to_owned(),
        graph_schema_version: GRAPH_SCHEMA_VERSION,
    }
}

/// The version a structural record's evidence names as its producer's.
///
/// [`GRAPH_SCHEMA_VERSION`], because that is the number tracking what a build asserts about a file. It
/// replaced a per-analyzer version that this read from the declared capability, and section 11.4 still
/// requires `producer_version` to carry something — attribution stopped being versioned, provenance did not
/// stop being required.
///
/// One number rather than one per language, which is the trade recorded in Stage 22: a change to a single
/// language's reader is no longer invalidated by that reader's own version, so this is what has to move.
fn producer_version_of_a_build() -> String {
    GRAPH_SCHEMA_VERSION.to_string()
}

/// The owner every record this module produces belongs to.
///
/// `nostdb`, and one string. It was `Analyzer { name: "rust", version: "1" }` — named for the only analyzer
/// that existed when it was written, which was wrong from the second analyzer onward, and carrying a version
/// that made renaming it unsafe.
///
/// What made it unsafe is gone. `docs/PRD.md` section 11.3 lets a change set remove only contributions owned
/// by its own owner, so a rename used to leave every record an earlier build wrote answering to a name nothing
/// could withdraw. There is no such record to strand: `nostdb_format_version` moved, so a database written
/// under the previous owner reports an unsupported version and is rebuilt rather than read.
#[must_use]
pub fn analyzer_owner() -> Owner {
    Owner::new(NonEmptyText::new(OWNER_NAME).unwrap_or_else(|_| NonEmptyText::literal("nostdb")))
}

/// The owner [`analyzer_owner`] names.
///
/// Every deterministic analyzer this build ships contributes under it. Which of them read a given file is in
/// the record's evidence, where section 11.4 puts provenance, rather than in the owner — Stage 22 established
/// that attribution is not identity, and this is the last place that had confused the two.
pub const OWNER_NAME: &str = "nostdb";

/// The file in this build that an import path names, when exactly one does.
///
/// Reached by a file that declared **no package**. One that did names declarations rather than locations,
/// and [`imported_declaration`] answers it — Java and Kotlin no longer arrive here, because a Kotlin file
/// name is not required to agree with anything declared in it and matching a path was therefore a guess.
///
/// Two shapes of import reach here, and conflating them was a real defect:
///
/// - **a dotted or `::` module name**, which Rust writes and which Python's dotted form matches, because
///   there a package *is* a directory. `a::b` is `.../a/b.rs`, so the separator is normalized and the result
///   matched as a suffix of a scanned path;
/// - **a filesystem path**, which TypeScript, JavaScript, Go, and C write. `./assets/logo.png` is already a
///   path, relative to the importing file's own directory. Normalizing its dots would turn it into
///   `//assets/logo/png`, which names nothing — and the extension is part of it, not a separator.
///
/// Told apart by the leading `.` or an embedded `/`, which a dotted module name never has.
///
/// Resolution is exact, never a guess. A relative path is joined to the importing directory and matched
/// whole; a module name is matched as an anchored suffix. Either way a candidate that two files answer to
/// resolves to neither, which is the rule the name index uses and for the same reason.
///
/// What is deliberately not done is module resolution. `./x` is matched against `x`, `x.ts`, and
/// `x/index.ts` by comparing stems, because those are the same file under three spellings — but a path
/// rewritten by a `tsconfig` alias, a package `exports` map, or a bundler is not resolved. Guessing at one
/// would put a file in the graph that nobody imported.
fn imported_file(
    path: &str,
    from_directory: &str,
    files: &BTreeMap<&str, LocalNodeId>,
) -> Option<LocalNodeId> {
    if path.starts_with('.') {
        let joined = join_relative(from_directory, path);
        return only_match(files, |file_path| corresponds_exactly(file_path, &joined));
    }

    // A path with a separator is already one, so it is matched as written rather than normalized. A bare
    // name — `react` — is a package and matches nothing, which is correct.
    let normalized = if path.contains('/') {
        path.to_owned()
    } else {
        path.replace("::", "/").replace('.', "/")
    };
    let without_last = parent_of(&normalized);
    let mut candidates: Vec<&str> = Vec::new();
    for candidate in [normalized.as_str(), without_last.as_str()] {
        if candidate.is_empty() || candidate == ROOT_PATH {
            continue;
        }
        candidates.push(candidate);
        // `crate::x` and `self::x` are `x` relative to the root, so the first segment names no
        // directory. Stripped rather than special-cased per language: a real directory called `crate`
        // still matches through the unstripped candidate above.
        if let Some(rest) = candidate
            .strip_prefix("crate/")
            .or_else(|| candidate.strip_prefix("self/"))
        {
            candidates.push(rest);
        }
    }

    // Longest first, so `a/b/C` is preferred over `a/b` when both name a file.
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));
    candidates.dedup();

    for candidate in candidates {
        if let Some(found) = only_match(files, |file_path| corresponds(file_path, candidate)) {
            return Some(found);
        }
    }
    None
}

/// The file declaring what a qualified import names, when exactly one does.
///
/// Written by a language that declares packages, where an import is a **declaration's** name rather than a
/// location. `com.demo.app.Payload` is answered by the file declaring `Payload` in package `com.demo.app`,
/// whatever that file is called.
///
/// Trailing segments are dropped one at a time, because an import may name something inside a declaration
/// rather than the declaration: `a.b.Outer.Inner` is a nested type and `a.b.C.CONSTANT` is a static member,
/// and the index holds `a.b.Outer` and `a.b.C`. The walk stops at two segments, since one segment cannot be
/// a package and a name together.
///
/// Returns `None` for a name two files declare, and stops rather than shortening: the specific name was
/// found and was ambiguous, and answering with a shorter one would be a guess.
fn imported_declaration(
    path: &str,
    declared: &BTreeMap<String, Option<LocalNodeId>>,
) -> Option<LocalNodeId> {
    // A star import names a package, not a declaration, so nothing in this index answers it. Rejected
    // outright rather than walked back: `a.b.*` shortened to `a.b` would resolve to a declaration called `b`
    // in package `a`, which is a different thing that happens to share a name.
    if path.ends_with('*') {
        return None;
    }
    let mut candidate = path;
    loop {
        if let Some(found) = declared.get(candidate) {
            return *found;
        }
        let (before, _) = candidate.rsplit_once('.')?;
        if !before.contains('.') {
            return None;
        }
        candidate = before;
    }
}

/// The skipped path an import names, when exactly one does.
///
/// Only a **relative** path can name an asset, and that is not a shortcut. A bare specifier like
/// `react` or a dotted `a.b.C` names a module by a resolution rule this build does not implement, so
/// matching one against a skipped file would be a guess. `./assets/logo.png` names a location, and the
/// scan already recorded whether something is there.
///
/// Matched with the extension included and no `index` fallback, because an asset is imported by its whole
/// name: `./logo` is not `./logo.png` to any toolchain without a loader configured, and inventing that
/// rule would attach a component to a file it does not import.
fn imported_asset(
    path: &str,
    from_directory: &str,
    available: &BTreeMap<&str, SkipReason>,
) -> Option<String> {
    if !path.starts_with('.') {
        return None;
    }
    let joined = join_relative(from_directory, path);
    available.contains_key(joined.as_str()).then_some(joined)
}

/// The one file matching a test, or `None` when none or more than one does.
fn only_match(
    files: &BTreeMap<&str, LocalNodeId>,
    matches: impl Fn(&str) -> bool,
) -> Option<LocalNodeId> {
    let mut found = files.iter().filter(|(path, _)| matches(path));
    match (found.next(), found.next()) {
        (Some((_, id)), None) => Some(*id),
        // Two files answer to one import path. Neither is the answer.
        _ => None,
    }
}

/// Joins a relative import path to the directory of the file that wrote it, resolving `.` and `..`.
///
/// A `..` that climbs past the root is dropped rather than kept as a segment, because a path outside the
/// scanned tree names no file in this build and a literal `..` component would never match one.
fn join_relative(from_directory: &str, path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    if from_directory != ROOT_PATH {
        segments.extend(from_directory.split('/').filter(|part| !part.is_empty()));
    }
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// Reports whether a scanned file path is the one a joined relative path names.
///
/// Three spellings of one file are accepted, and no more: the path as written with its extension, the
/// path without one, and the path as a directory holding an `index`. Those are the forms every JavaScript
/// toolchain agrees on; anything beyond them is configuration this build does not read.
fn corresponds_exactly(file_path: &str, joined: &str) -> bool {
    if file_path == joined {
        return true;
    }
    let stem = file_path
        .rsplit_once('.')
        .map_or(file_path, |(stem, _)| stem);
    stem == joined
        || stem
            .strip_suffix("/index")
            .is_some_and(|before| before == joined)
}

/// Reports whether a scanned file path is the one a normalized import candidate names.
///
/// The extension is dropped from the file path, because an import never writes one, and a trailing
/// `/mod` is dropped as well: a directory module lives in `x/mod.rs` and is imported as `x`.
///
/// The match is anchored on a separator so `a/b/Cat` is not found by an import of `a/b/at`. A bare
/// suffix test would make every import that happened to end a real path resolve to it.
fn corresponds(file_path: &str, candidate: &str) -> bool {
    let without_extension = file_path
        .rsplit_once('.')
        .map_or(file_path, |(stem, _)| stem);
    let stem = without_extension
        .strip_suffix("/mod")
        .unwrap_or(without_extension);
    stem == candidate
        || stem
            .strip_suffix(candidate)
            .is_some_and(|before| before.ends_with('/'))
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

/// The directory a path sits in, as [`ROOT_PATH`] when it sits at the top.
///
/// Scan paths always use `/`, on every platform, so this is not a platform-dependent split.
fn parent_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent.to_owned(),
        _ => ROOT_PATH.to_owned(),
    }
}

/// The source unit the directory tree already belongs to, when a build drew it before.
///
/// The tree gets one unit of its own rather than borrowing a file's. A directory outlives any
/// single file in it, so owning it through one file would delete `docs/` when `docs/api.md` was
/// removed and leave every other document in it parentless.
fn existing_tree_unit(graph: &Graph) -> Option<SourceUnitId> {
    let owner = analyzer_owner();
    graph
        .nodes
        .iter()
        .filter(|node| {
            node.labels
                .iter()
                .any(|label| label.as_str() == DIRECTORY_LABEL)
        })
        .flat_map(|node| node.contributions.iter())
        .find(|held| held.owner == owner)
        .map(|held| held.source_unit)
}

/// The node an earlier build minted for a directory, so its identifier survives a rebuild.
fn existing_directory(graph: &Graph, path: &str) -> Option<LocalNodeId> {
    graph
        .nodes
        .iter()
        .find(|node| {
            node.labels
                .iter()
                .any(|label| label.as_str() == DIRECTORY_LABEL)
                && property(node, "path") == Some(path)
        })
        .map(|node| node.id)
}

/// The node an earlier build minted for an asset, so its identifier survives a rebuild.
fn existing_asset(graph: &Graph, path: &str) -> Option<LocalNodeId> {
    graph
        .nodes
        .iter()
        .find(|node| {
            node.labels
                .iter()
                .any(|label| label.as_str() == ASSET_LABEL)
                && property(node, "path") == Some(path)
        })
        .map(|node| node.id)
}

/// Evidence for a directory's record.
///
/// The producer is the scan: a directory is something the tree walk observed, and no analyzer is
/// involved in it at all. A directory has no contents of its own, so what is digested is its path:
/// that is the fact being recorded, and a digest of nothing would leave the evidence unable to say
/// what it was evidence of.
fn directory_evidence(locator: &CanonicalSourceLocator, path: &str) -> Evidence {
    Evidence {
        source: locator.clone(),
        resolved_revision: None,
        path: NonEmptyText::new(path).ok(),
        content_digest: crate::sync::digest_bytes(path.as_bytes()),
        range: None,
        producer: NonEmptyText::new(SCAN_PRODUCER)
            .unwrap_or_else(|_| NonEmptyText::literal("scan")),
        producer_version: NonEmptyText::new(SCAN_VERSION)
            .unwrap_or_else(|_| NonEmptyText::literal("1")),
        method: EvidenceMethod::Deterministic,
        confidence: Confidence::Extracted,
    }
}

/// The record shape a stored file node was written by, when it records one.
///
/// `None` for a node written before the version was recorded, which is the answer that makes such
/// a database rebuild rather than keep a shape nothing would otherwise refresh.
fn stored_schema_version(graph: &Graph, node: LocalNodeId) -> Option<i64> {
    integer(
        graph.nodes.iter().find(|held| held.id == node)?,
        "schema_version",
    )
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
            // The scan, not an analyzer. This is a link the settings declare, and naming the Rust
            // analyzer as its producer said a language analyzer had found something it never read.
            producer: NonEmptyText::new(SCAN_PRODUCER)
                .unwrap_or_else(|_| NonEmptyText::literal("scan")),
            producer_version: NonEmptyText::new(SCAN_VERSION)
                .unwrap_or_else(|_| NonEmptyText::literal("1")),
            method: EvidenceMethod::Deterministic,
            confidence: Confidence::Extracted,
        }],
    }));
}

/// What may be concluded from a file's record.
///
/// A recorded file reports `Unsupported` whatever its language, because the question this answers
/// is what was learned about *this file* and not what the build can do in general. A covered
/// language whose bytes could not be read would otherwise advertise semantic precision over a
/// record holding nothing.
fn precision_of(registry: &CapabilityRegistry, held: &Unit) -> PrecisionClass {
    match held.analyzed {
        true => registry.precision(&held.analysis.language),
        false => PrecisionClass::Unsupported,
    }
}

/// The producer recorded for a file the scan named and nothing analyzed.
const SCAN_PRODUCER: &str = "scan";

/// Its version, which moves when what a scan records about a file changes.
const SCAN_VERSION: &str = "1";

/// Evidence for a file's own record.
///
/// `Deterministic` and `Extracted` hold for a recorded file as much as for an analyzed one, and
/// that is not a loophole: the path and the digest were read off the filesystem rather than
/// inferred, so the claim being made — this file exists and these are its bytes — is exact. What
/// changes is the producer, because a scan found it and no analyzer did, and the `precision`
/// property on the record says nothing was read out of it.
fn file_evidence(locator: &CanonicalSourceLocator, held: &Unit) -> Evidence {
    match held.analyzed {
        true => analyzed_evidence(locator, &held.path, &held.analysis),
        false => Evidence {
            producer: NonEmptyText::new(SCAN_PRODUCER)
                .unwrap_or_else(|_| NonEmptyText::literal("scan")),
            producer_version: NonEmptyText::new(SCAN_VERSION)
                .unwrap_or_else(|_| NonEmptyText::literal("1")),
            ..analyzed_evidence(locator, &held.path, &held.analysis)
        },
    }
}

/// Evidence for a framework's entry point.
///
/// The producer is the framework analyzer, not the language analyzer that read the file. A route is a
/// fact about Spring, and crediting the Kotlin analyzer with finding it would name a producer that read
/// an annotation and drew no conclusion from it.
///
/// The range is the handler's, because that is where the route is written. `Deterministic` and
/// `Extracted` hold: the method and the path were read off an annotation rather than inferred, and a path
/// this analyzer could not evaluate is recorded as written rather than resolved.
/// Evidence for a component's record.
///
/// The producer is the React analyzer and the confidence is **not** `Extracted` when the component was
/// recognised by a convention. `Inferred` with a score is what section 11.4 gives a fact that is
/// pattern-based, and reporting a capitalised function as extracted would say the source declared something
/// it only implied.
fn component_evidence(
    locator: &CanonicalSourceLocator,
    held: &Unit,
    component: &crate::analyze::framework::Component,
) -> Evidence {
    use crate::analyze::framework::Recognition;
    Evidence {
        source: locator.clone(),
        resolved_revision: None,
        path: NonEmptyText::new(held.path.as_str()).ok(),
        content_digest: held.analysis.digest.clone(),
        range: Some(component.range),
        producer: NonEmptyText::new(crate::analyze::framework::react::FRAMEWORK)
            .unwrap_or_else(|_| NonEmptyText::literal("framework")),
        producer_version: NonEmptyText::new(crate::analyze::framework::react::VERSION)
            .unwrap_or_else(|_| NonEmptyText::literal("1")),
        method: EvidenceMethod::Deterministic,
        confidence: match component.recognised_by {
            Recognition::Declared => Confidence::Extracted,
            // A convention every React project follows, and which a helper called `Wrapper` also satisfies.
            Recognition::Convention => Confidence::Inferred {
                score: crate::evidence::Score::literal(CONVENTION_CONFIDENCE),
            },
        },
    }
}

/// The score a component recognised by convention carries.
///
/// A number rather than a shrug, because `Inferred` requires one and a reader comparing two facts needs it to
/// mean something. The capitalisation convention is the one JSX itself enforces — `<Card />` is a component
/// and `<div />` is a tag — so it holds for nearly every component and fails only for a capitalised helper.
const CONVENTION_CONFIDENCE: f32 = 0.8;

fn framework_evidence(
    locator: &CanonicalSourceLocator,
    held: &Unit,
    endpoint: &crate::analyze::framework::Endpoint,
) -> Evidence {
    Evidence {
        source: locator.clone(),
        resolved_revision: None,
        path: NonEmptyText::new(held.path.as_str()).ok(),
        content_digest: held.analysis.digest.clone(),
        range: Some(endpoint.range),
        producer: NonEmptyText::new(crate::analyze::framework::spring::FRAMEWORK)
            .unwrap_or_else(|_| NonEmptyText::literal("framework")),
        producer_version: NonEmptyText::new(crate::analyze::framework::spring::VERSION)
            .unwrap_or_else(|_| NonEmptyText::literal("1")),
        method: EvidenceMethod::Deterministic,
        confidence: Confidence::Extracted,
    }
}

/// Evidence naming the analyzer that read a file.
///
/// Every record an analyzer produced carries this, including the items inside a file, because an
/// item cannot exist without an analyzer having found it.
fn analyzed_evidence(
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
            .unwrap_or_else(|_| NonEmptyText::literal("unknown")),
        producer_version: NonEmptyText::new(producer_version_of_a_build().as_str())
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
        ..analyzed_evidence(locator, &record.path, analysis)
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
    /// Every label this module can write has a schema, and every schema names a label it writes.
    ///
    /// Both directions. A label with no schema is what prompted this — a materialized `.nost` naming
    /// `File` and `Endpoint` and declaring neither — and a schema naming a label nothing writes is a
    /// declaration a reader would look for records under and find none of.
    ///
    /// The item labels come from `label_for` rather than a second list, so adding an `ItemKind` fails here
    /// instead of quietly gaining a label with no schema.
    #[test]
    fn every_label_this_build_writes_has_a_schema_and_the_reverse() {
        let declared: BTreeSet<String> = super::schemas()
            .into_iter()
            .map(|schema| schema.name.as_str().to_owned())
            .collect();
        let mut written: BTreeSet<String> = [
            FILE_LABEL,
            DIRECTORY_LABEL,
            ENDPOINT_LABEL,
            ASSET_LABEL,
            COMPONENT_LABEL,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        written.extend(
            super::EVERY_ITEM_KIND
                .into_iter()
                .map(|kind| label_for(kind).to_owned()),
        );
        assert_eq!(declared, written);

        // And `EVERY_ITEM_KIND` really is every kind, which nothing else here would notice.
        assert_eq!(
            super::EVERY_ITEM_KIND.len(),
            11,
            "an ItemKind was added without a schema: {:?}",
            super::EVERY_ITEM_KIND
        );
    }

    #[test]
    fn the_analyzer_owner_is_frozen_at_what_existing_databases_hold() {
        // Removing analyzer versions must not move this. `analyzer_owner` read `rust::VERSION` for its
        // version half, and that constant is gone — so the literal is pinned here instead of being trusted
        // to stay right by inspection.
        //
        // Moving either half leaves every record an earlier build wrote owned by a name nothing can
        // withdraw: `existing_unit` stops finding them, fresh units are minted beside them, and the graph
        // holds both readings of every file for ever. That is a defect no later change can repair, because
        // the unreachable records are already in somebody's database.
        assert_eq!(analyzer_owner().as_str(), "nostdb");
        assert_eq!(
            analyzer_owner().kind(),
            crate::contribution::OwnerKind::Analyzer,
            "the kind is read from the name, so a rename must not make this the user or an AI owner"
        );
    }

    #[test]
    fn a_declared_capability_carries_coverage_and_not_attribution() {
        // The registry answers "what is covered, and how precisely". It does not answer "which reader",
        // because no query acts on that — and a version field invited a second migration axis beside
        // `GRAPH_SCHEMA_VERSION` for no reader's benefit.
        let registry = crate::analyze::builtin_registry().expect("the builtin registry");
        let declared = registry.capability("kotlin").expect("kotlin is covered");
        assert_eq!(declared.language.as_str(), "kotlin");
        assert!(declared.precision.is_deterministic());
        assert!(declared.extracts(crate::analysis::FactKind::ImportExport));
    }

    #[test]
    fn a_declared_schema_matches_the_properties_the_record_actually_carries() {
        // The point of declaring a schema is that it describes what is there. A schema requiring a field
        // the writer never sets would make every record of that label raise NOST_SCHEMA_VIOLATION.
        let dir = TempDir::new("schema-shape");
        let file = dir.write("src/lib.rs", "fn only() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);

        for schema in super::schemas() {
            let name = schema.name.as_str();
            for node in graph
                .nodes
                .iter()
                .filter(|node| node.labels.iter().any(|held| held.as_str() == name))
            {
                let carried: BTreeSet<&str> = node
                    .properties
                    .iter()
                    .map(|(key, _)| key.as_str())
                    .collect();
                for field in schema.fields.iter().filter(|field| field.required) {
                    assert!(
                        carried.contains(field.key.as_str()),
                        "{name} requires `{}` and a record carries {carried:?}",
                        field.key.as_str()
                    );
                }
            }
        }
    }

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
            // Off by default here: a test that means to exercise parsing should not have
            // its second call quietly served from a cache the first one filled.
            cache: CACHE.get_or_init(crate::cache::ParseCache::disabled),
        }
    }

    static CACHE: std::sync::OnceLock<crate::cache::ParseCache> = std::sync::OnceLock::new();

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
                // A file or a directory is named by its path and carries no `name`, so both are
                // read here. Without the fallback every containment edge from a file rendered as
                // `?` and an assertion about one could not say which file it meant.
                .and_then(|node| property(node, "name").or_else(|| property(node, "path")))
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
    fn an_import_naming_a_file_in_this_build_becomes_an_edge() {
        // `FactKind::ImportExport` has been declared by both analyzers since they were written and
        // produced by neither: `analysis.imports` reached the parse cache and Spring's recognition
        // check, and never the graph. The reported repository has 772 `CONTAINS`, 307 `CALLS`, 9
        // `HANDLED_BY`, and no import edge at all, while its Kotlin sources do import each other.
        let dir = TempDir::new("imports");
        let mut service = dir.write(
            "src/main/kotlin/com/demo/app/Service.kt",
            "package com.demo.app\n\nimport com.demo.app.data.Payload\n\nclass Service\n",
        );
        service.language = "kotlin".to_owned();
        let mut payload = dir.write(
            "src/main/kotlin/com/demo/app/data/Payload.kt",
            "package com.demo.app.data\n\nclass Payload\n",
        );
        payload.language = "kotlin".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![service, payload], &mut graph, 1);

        assert_eq!(
            relations(&graph, IMPORTS),
            [(
                "src/main/kotlin/com/demo/app/Service.kt".to_owned(),
                "src/main/kotlin/com/demo/app/data/Payload.kt".to_owned()
            )],
            "an import names a path, and that path is a file in this build"
        );
    }

    #[test]
    fn an_import_naming_a_dependency_is_never_matched_by_name() {
        // The reason resolution is by path and not by name. This project declares exactly one `List`,
        // so a last-segment match would resolve `java.util.List` to it and the graph would assert that
        // a file imports a class it does not import. A suffix of a real path cannot be produced by an
        // import that names something outside the project.
        let dir = TempDir::new("dependency");
        let mut using = dir.write(
            "src/main/kotlin/com/demo/Using.kt",
            "package com.demo\n\nimport java.util.List\nimport org.springframework.boot.runApplication\n\nclass Using\n",
        );
        using.language = "kotlin".to_owned();
        let mut ours = dir.write(
            "src/main/kotlin/com/demo/List.kt",
            "package com.demo\n\nclass List\n",
        );
        ours.language = "kotlin".to_owned();

        let mut graph = Graph::default();
        let draft = build(&dir, vec![using, ours], &mut graph, 1);

        assert!(
            relations(&graph, IMPORTS).is_empty(),
            "a dependency must not be resolved to a same-named local declaration: {:?}",
            relations(&graph, IMPORTS)
        );
        assert!(
            draft.coverage.unresolved_units >= 2,
            "both dependency imports are counted, not invented"
        );
    }

    #[test]
    fn a_kotlin_declaration_in_a_differently_named_file_resolves() {
        // Kotlin does not require `class Payload` to be declared in `Payload.kt`. Resolving by path
        // correspondence missed every declaration whose file was named for something else, silently: the
        // import was counted unresolved and no edge was drawn.
        let dir = TempDir::new("declared");
        let mut service = dir.write(
            "src/main/kotlin/com/demo/app/Service.kt",
            "package com.demo.app\n\nimport com.demo.app.data.Payload\n\nclass Service\n",
        );
        service.language = "kotlin".to_owned();
        let mut models = dir.write(
            "src/main/kotlin/com/demo/app/data/Models.kt",
            "package com.demo.app.data\n\nclass Payload\n\nclass Envelope\n",
        );
        models.language = "kotlin".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![service, models], &mut graph, 1);

        assert_eq!(
            relations(&graph, IMPORTS),
            [(
                "src/main/kotlin/com/demo/app/Service.kt".to_owned(),
                "src/main/kotlin/com/demo/app/data/Models.kt".to_owned()
            )],
            "an import names a declaration, and the file declaring it is the answer whatever it is called"
        );
    }

    #[test]
    fn a_file_named_for_an_import_it_does_not_declare_gets_no_edge() {
        // The wrong edge path correspondence drew. `Payload.kt` is exactly where the old rule looked, and
        // what it declares is `Other` — so the graph asserted that a file imports a class the target does
        // not declare, which is the error the last-segment rule was rejected for.
        let dir = TempDir::new("misnamed");
        let mut service = dir.write(
            "src/main/kotlin/com/demo/app/Service.kt",
            "package com.demo.app\n\nimport com.demo.app.data.Payload\n\nclass Service\n",
        );
        service.language = "kotlin".to_owned();
        let mut named = dir.write(
            "src/main/kotlin/com/demo/app/data/Payload.kt",
            "package com.demo.app.data\n\nclass Other\n",
        );
        named.language = "kotlin".to_owned();

        let mut graph = Graph::default();
        let draft = build(&dir, vec![service, named], &mut graph, 1);

        assert!(
            relations(&graph, IMPORTS).is_empty(),
            "a file named for a declaration it does not make is not the answer: {:?}",
            relations(&graph, IMPORTS)
        );
        assert!(
            draft.coverage.unresolved_units >= 1,
            "the import is counted rather than attached to the file that shares its name"
        );
    }

    #[test]
    fn a_java_import_resolves_by_declaration_rather_than_by_file_name() {
        // Java constrains a public top-level class to a file of its own name, so path correspondence
        // agreed with the language here and resolving by declaration must keep agreeing. It also reaches
        // what a path never could: `Helper` is a second top-level class in a file named for the first.
        let dir = TempDir::new("java-declared");
        let mut app = dir.write(
            "src/main/java/com/demo/App.java",
            "package com.demo;\n\nimport com.demo.data.Payload;\nimport com.demo.data.Helper;\n\nclass App { }\n",
        );
        app.language = "java".to_owned();
        let mut payload = dir.write(
            "src/main/java/com/demo/data/Payload.java",
            "package com.demo.data;\n\npublic class Payload { }\n\nclass Helper { }\n",
        );
        payload.language = "java".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![app, payload], &mut graph, 1);

        assert_eq!(
            relations(&graph, IMPORTS),
            [(
                "src/main/java/com/demo/App.java".to_owned(),
                "src/main/java/com/demo/data/Payload.java".to_owned()
            )],
            "both imports name declarations in one file, and one file is one edge"
        );
    }

    #[test]
    fn a_star_import_names_a_package_and_draws_no_edge() {
        // `a.b.*` names a package rather than a declaration. Shortening it to `a.b` would resolve to a
        // declaration called `b` in package `a` — a different thing that happens to share a name — and the
        // old path rule matched it against a file called `b.kt` for the same reason.
        let dir = TempDir::new("star");
        let mut using = dir.write(
            "src/main/kotlin/com/demo/Using.kt",
            "package com.demo\n\nimport com.demo.data.*\n\nclass Using\n",
        );
        using.language = "kotlin".to_owned();
        let mut data = dir.write(
            "src/main/kotlin/com/demo/data.kt",
            "package com.demo\n\nclass data\n",
        );
        data.language = "kotlin".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![using, data], &mut graph, 1);

        assert!(
            relations(&graph, IMPORTS).is_empty(),
            "a star import resolves to no single file: {:?}",
            relations(&graph, IMPORTS)
        );
    }

    #[test]
    fn a_use_naming_a_symbol_resolves_to_the_file_the_module_path_names() {
        // Kotlin's import ends in the declaration and its file is named for it; Rust's ends in a symbol
        // inside a module file. Dropping the last segment is what makes one rule serve both, and
        // `crate` names the root rather than a directory under it.
        let dir = TempDir::new("use");
        let main = dir.write("src/main.rs", "use crate::helper::Thing;\nfn main() {}\n");
        let helper = dir.write("src/helper.rs", "pub struct Thing;\n");

        let mut graph = Graph::default();
        build(&dir, vec![main, helper], &mut graph, 1);

        assert_eq!(
            relations(&graph, IMPORTS),
            [("src/main.rs".to_owned(), "src/helper.rs".to_owned())]
        );
    }

    #[test]
    fn an_import_two_files_answer_to_resolves_to_neither() {
        // The rule the name index already uses, for the reason it uses it: two answers is not an answer.
        let dir = TempDir::new("ambiguous");
        let mut using = dir.write(
            "src/main/kotlin/Using.kt",
            "import data.Payload\n\nclass Using\n",
        );
        using.language = "kotlin".to_owned();
        let mut first = dir.write("src/a/data/Payload.kt", "class Payload\n");
        first.language = "kotlin".to_owned();
        let mut second = dir.write("src/b/data/Payload.kt", "class Payload\n");
        second.language = "kotlin".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![using, first, second], &mut graph, 1);

        assert!(
            relations(&graph, IMPORTS).is_empty(),
            "{:?}",
            relations(&graph, IMPORTS)
        );
    }

    #[test]
    fn correspondence_is_anchored_on_a_separator() {
        // A bare suffix test would make every import that happened to end a real path resolve to it,
        // so `a/b/at` must not be found by a file called `a/b/Cat`.
        let files: BTreeMap<&str, LocalNodeId> = BTreeMap::new();
        assert!(corresponds("src/a/b/Cat.rs", "a/b/Cat"));
        assert!(corresponds("src/a/b/Cat.rs", "Cat"));
        assert!(!corresponds("src/a/b/Cat.rs", "at"));
        assert!(!corresponds("src/a/b/Cat.rs", "b/at"));
        // A directory module is imported by the directory's name, not by `mod`.
        assert!(corresponds("src/analyze/mod.rs", "analyze"));
        assert!(!corresponds("src/analyze/mod.rs", "analyze/mod"));
        assert_eq!(imported_file("anything", ROOT_PATH, &files), None);
    }

    #[test]
    fn a_relative_path_is_joined_to_the_directory_that_wrote_it() {
        // TypeScript imports a path, not a name, and the dots in it are not separators. Normalizing them
        // the way a dotted module name is normalized turned `./assets/logo.png` into `//assets/logo/png`,
        // which names nothing — so an asset import resolved to no file and every one of them was counted
        // unresolved.
        assert_eq!(
            join_relative("src/components", "./assets/logo.png"),
            "src/components/assets/logo.png"
        );
        assert_eq!(
            join_relative("src/components", "../shared/util"),
            "src/shared/util"
        );
        assert_eq!(join_relative(ROOT_PATH, "./a/b"), "a/b");
        // Climbing past the root drops rather than keeping a `..` that could never match a scanned path.
        assert_eq!(join_relative("src", "../../outside"), "outside");
    }

    #[test]
    fn three_spellings_of_one_file_correspond_and_nothing_else_does() {
        // The forms every JavaScript toolchain agrees on: as written, without the extension, and as a
        // directory holding an index. A `tsconfig` alias is not among them and is not guessed at.
        assert!(corresponds_exactly(
            "src/assets/logo.png",
            "src/assets/logo.png"
        ));
        assert!(corresponds_exactly("src/Button.tsx", "src/Button"));
        assert!(corresponds_exactly("src/Button/index.ts", "src/Button"));
        assert!(!corresponds_exactly("src/Button.tsx", "src/Butto"));
        assert!(!corresponds_exactly("src/other/Button.tsx", "src/Button"));
    }

    #[test]
    fn a_typescript_import_of_a_sibling_module_becomes_an_edge() {
        let dir = TempDir::new("ts-imports");
        let mut card = dir.write(
            "src/components/Card.tsx",
            "import { helper } from \"../shared/helper\";\nexport class Card { }\n",
        );
        card.language = "typescript".to_owned();
        let mut helper = dir.write(
            "src/shared/helper.ts",
            "export function helper() { return 1; }\n",
        );
        helper.language = "typescript".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![card, helper], &mut graph, 1);

        assert_eq!(
            relations(&graph, IMPORTS),
            [(
                "src/components/Card.tsx".to_owned(),
                "src/shared/helper.ts".to_owned()
            )]
        );
    }

    /// A scan whose skipped list is stated, so an asset test does not depend on what `looks_binary`
    /// decides about bytes written into a temporary directory.
    fn build_with_skipped(
        dir: &TempDir,
        files: Vec<ScannedFile>,
        skipped: Vec<(&str, SkipReason)>,
        graph: &mut Graph,
    ) -> BuildDraft {
        let scan = Scan {
            files,
            skipped: skipped
                .into_iter()
                .map(|(path, reason)| SkippedSource {
                    source: CanonicalSourceLocator::root(),
                    path: NonEmptyText::new(path).ok(),
                    reason,
                })
                .collect(),
        };
        let mut minter = Minter::new();
        let draft = super::draft(&request(dir, &scan, graph, 1, false), &mut minter);
        if !draft.change_set.operations.is_empty() {
            crate::apply::apply(graph, &draft.change_set, 1, &mut minter)
                .expect("the draft applies");
        }
        draft
    }

    #[test]
    fn a_react_component_is_a_record_of_its_own_joined_to_its_declaration() {
        // A record rather than a second label on the declaration, for the reason `Endpoint` is one: the
        // framework analyzer declares its own version, and section 11.3 lets it withdraw only its own
        // contributions. A label on a record the language analyzer owns could not be withdrawn.
        let dir = TempDir::new("react-components");
        let mut card = dir.write(
            "src/Card.tsx",
            "import React from \"react\";\nexport function Card() { return null; }\nexport function helper() { return 1; }\n",
        );
        card.language = "typescript".to_owned();

        let mut graph = Graph::default();
        let draft = build(&dir, vec![card], &mut graph, 1);

        assert_eq!(draft.components, 1, "the helper is not one");
        let component = graph
            .nodes
            .iter()
            .find(|node| {
                node.labels
                    .iter()
                    .any(|held| held.as_str() == COMPONENT_LABEL)
            })
            .expect("a component record");
        assert_eq!(property(component, "name"), Some("Card"));
        assert_eq!(property(component, "framework"), Some("react"));
        // The analyzer's class, and how this one was recognised. A reader judging the count needs the second.
        assert_eq!(property(component, "precision"), Some("heuristic"));
        assert_eq!(property(component, "recognised_by"), Some("convention"));
        assert_eq!(
            relations(&graph, DECLARED_BY),
            [("Card".to_owned(), "Card".to_owned())]
        );
    }

    #[test]
    fn a_component_recognised_by_convention_is_evidenced_as_inferred() {
        // `Extracted` would say the source declared what it only implied. A class extending `Component`
        // states it, and that one is extracted.
        let dir = TempDir::new("react-confidence");
        let mut file = dir.write(
            "src/Both.tsx",
            "import React from \"react\";\nexport function Loose() {}\nexport class Strict extends React.Component {}\n",
        );
        file.language = "typescript".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);

        let mut seen: Vec<(String, bool)> = graph
            .nodes
            .iter()
            .filter(|node| {
                node.labels
                    .iter()
                    .any(|held| held.as_str() == COMPONENT_LABEL)
            })
            .map(|node| {
                let extracted = node.contributions.iter().any(|held| {
                    held.evidence
                        .iter()
                        .any(|found| found.confidence == crate::evidence::Confidence::Extracted)
                });
                (
                    property(node, "name").unwrap_or_default().to_owned(),
                    extracted,
                )
            })
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            [("Loose".to_owned(), false), ("Strict".to_owned(), true),]
        );
    }

    #[test]
    fn a_go_receiver_joins_the_method_to_the_type_it_is_on() {
        // Go states the owner in the declaration rather than by containment, so the edge has to come from
        // the method's target. Nothing else sets one on a method, so this reaches `FOR_TYPE` the same way
        // a Rust `impl` block does.
        let dir = TempDir::new("go-receiver");
        let mut file = dir.write(
            "service.go",
            "package main\n\ntype Service struct {\n\tName string\n}\n\nfunc (s *Service) Do() error {\n\treturn nil\n}\n",
        );
        file.language = "go".to_owned();

        let mut graph = Graph::default();
        build(&dir, vec![file], &mut graph, 1);

        assert_eq!(
            relations(&graph, FOR_TYPE),
            [("Do".to_owned(), "Service".to_owned())]
        );
    }

    #[test]
    fn a_component_importing_a_skipped_file_is_joined_to_it_as_an_asset() {
        // The requirement, and the shape of it: a schema, a path, and an edge from what references it.
        // The binary is never read — it is in the graph because analyzed source names it, which is why
        // section 17.2's rule that the scanner skips a binary file is untouched.
        let dir = TempDir::new("asset");
        let mut card = dir.write(
            "src/Card.tsx",
            "import logo from \"./assets/logo.png\";\nexport class Card { }\n",
        );
        card.language = "typescript".to_owned();

        let mut graph = Graph::default();
        build_with_skipped(
            &dir,
            vec![card],
            vec![("src/assets/logo.png", SkipReason::Binary)],
            &mut graph,
        );

        assert_eq!(
            relations(&graph, IMPORTS),
            [("src/Card.tsx".to_owned(), "src/assets/logo.png".to_owned())]
        );
        let asset = graph
            .nodes
            .iter()
            .find(|node| node.labels.iter().any(|held| held.as_str() == ASSET_LABEL))
            .expect("an asset record");
        assert_eq!(property(asset, "path"), Some("src/assets/logo.png"));
        assert_eq!(
            property(asset, "skipped"),
            Some("binary"),
            "why no analyzer read it is part of the record"
        );
    }

    #[test]
    fn one_asset_imported_by_two_components_is_one_record() {
        let dir = TempDir::new("shared-asset");
        let mut first = dir.write(
            "src/A.tsx",
            "import l from \"./img/l.png\";\nexport class A { }\n",
        );
        first.language = "typescript".to_owned();
        let mut second = dir.write(
            "src/B.tsx",
            "import l from \"./img/l.png\";\nexport class B { }\n",
        );
        second.language = "typescript".to_owned();

        let mut graph = Graph::default();
        build_with_skipped(
            &dir,
            vec![first, second],
            vec![("src/img/l.png", SkipReason::Binary)],
            &mut graph,
        );

        let assets = graph
            .nodes
            .iter()
            .filter(|node| node.labels.iter().any(|held| held.as_str() == ASSET_LABEL))
            .count();
        assert_eq!(assets, 1, "one path is one record, however many import it");
        assert_eq!(relations(&graph, IMPORTS).len(), 2);
    }

    #[test]
    fn an_excluded_file_does_not_become_an_asset_by_being_imported() {
        // An `Ignored` file was excluded on purpose and a `Sensitive` one was withheld before it was read.
        // An import must not overrule either: the exclusion is the decision, and a route into the graph
        // that bypasses it would make `.gitignore` and the sensitive list advisory.
        let dir = TempDir::new("excluded");
        let mut app = dir.write(
            "src/App.tsx",
            "import a from \"./secret.pem\";\nimport b from \"./build/out.bin\";\nexport class App { }\n",
        );
        app.language = "typescript".to_owned();

        let mut graph = Graph::default();
        let draft = build_with_skipped(
            &dir,
            vec![app],
            vec![
                ("src/secret.pem", SkipReason::Sensitive),
                ("src/build/out.bin", SkipReason::Ignored),
            ],
            &mut graph,
        );

        assert!(
            !graph
                .nodes
                .iter()
                .any(|node| node.labels.iter().any(|held| held.as_str() == ASSET_LABEL)),
            "neither exclusion may be reached through an import"
        );
        assert!(draft.coverage.unresolved_units >= 2);
    }

    #[test]
    fn a_file_too_large_to_read_is_an_asset_and_says_so() {
        let dir = TempDir::new("too-large");
        let mut player = dir.write(
            "src/Player.tsx",
            "import clip from \"./media/clip.mp4\";\nexport class Player { }\n",
        );
        player.language = "typescript".to_owned();

        let mut graph = Graph::default();
        build_with_skipped(
            &dir,
            vec![player],
            vec![("src/media/clip.mp4", SkipReason::TooLarge)],
            &mut graph,
        );

        let asset = graph
            .nodes
            .iter()
            .find(|node| node.labels.iter().any(|held| held.as_str() == ASSET_LABEL))
            .expect("an asset record");
        assert_eq!(property(asset, "skipped"), Some("too large"));
    }

    #[test]
    fn a_bare_specifier_never_names_an_asset() {
        // Only a relative path names a location. `react` and `a.b.C` name a module by a resolution rule
        // this build does not implement, so matching either against a skipped file would be a guess.
        let available: BTreeMap<&str, SkipReason> = [("assets/logo.png", SkipReason::Binary)]
            .into_iter()
            .collect();
        assert_eq!(
            imported_asset("./assets/logo.png", ROOT_PATH, &available).as_deref(),
            Some("assets/logo.png")
        );
        assert_eq!(
            imported_asset("assets/logo.png", ROOT_PATH, &available),
            None
        );
        assert_eq!(imported_asset("react", ROOT_PATH, &available), None);
        // No `index` fallback and no extension guessing: `./logo` is not `./logo.png` to any toolchain
        // without a loader configured, and inventing that rule would attach a component to a file it does
        // not import.
        assert_eq!(imported_asset("./assets/logo", ROOT_PATH, &available), None);
    }

    #[test]
    fn a_package_import_names_no_file_and_is_counted() {
        let dir = TempDir::new("ts-package");
        let mut app = dir.write(
            "src/App.tsx",
            "import React from \"react\";\nexport class App { }\n",
        );
        app.language = "typescript".to_owned();

        let mut graph = Graph::default();
        let draft = build(&dir, vec![app], &mut graph, 1);

        assert!(
            relations(&graph, IMPORTS).is_empty(),
            "a package is not a file here"
        );
        assert!(draft.coverage.unresolved_units >= 1);
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
        // Directories are excluded rather than counted. The claim being made is that nothing was
        // invented for `nowhere` or `elsewhere`, and a directory is observed rather than invented —
        // counting them would make this assertion move whenever the tree's depth did.
        let read_out_of_source = graph
            .nodes
            .iter()
            .filter(|node| {
                !node
                    .labels
                    .iter()
                    .any(|label| label.as_str() == DIRECTORY_LABEL)
            })
            .count();
        assert_eq!(
            read_out_of_source,
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
    fn a_file_no_analyzer_reads_is_recorded_rather_than_dropped() {
        // Section 17.3: an unsupported language "at minimum produces a source/module record with
        // an explicit capability diagnostic". It used to produce the diagnostic and no record.
        //
        // This test is the reason that survived a whole Stage. It asserted the three lines below
        // and nothing about the graph, so it passed both before and after — a precise pin on the
        // half of the behaviour that was already right.
        //
        // Markdown, deliberately. This used to be a `.py` file, and the language gained an analyzer —
        // which made the test assert the opposite of what it was written to assert while still passing
        // the two lines below it. A prose format is the durable choice: it is named so the report can say
        // what it is, and no structural analyzer is ever coming for it.
        let dir = TempDir::new("unsupported");
        let mut file = dir.write("notes.md", "# Notes\n\nSome prose.\n");
        file.language = "markdown".to_owned();
        let mut graph = Graph::default();
        let draft = build_with(&dir, vec![file], &mut graph, 1, false);

        assert_eq!(draft.analyzed_files, 0, "nothing read it");
        assert_eq!(draft.coverage.skipped_sources.len(), 1);
        assert_eq!(
            draft.coverage.skipped_sources[0].reason,
            SkipReason::Unsupported
        );
        // Recording a file is not claiming to have analyzed it.
        assert_eq!(draft.coverage.structural, CoverageState::Partial);

        assert_eq!(draft.recorded_files, 1);
        let recorded: Vec<&crate::graph::Node> = graph
            .nodes
            .iter()
            .filter(|node| node.labels.iter().any(|held| held.as_str() == FILE_LABEL))
            .collect();
        assert_eq!(recorded.len(), 1, "the file is in its own graph");
        assert_eq!(property(recorded[0], "path"), Some("notes.md"));
        assert_eq!(
            property(recorded[0], "language"),
            Some("markdown"),
            "the language is named even though nothing analyzes it"
        );
        assert_eq!(
            property(recorded[0], "precision"),
            Some("unsupported"),
            "and the record says outright that nothing was read out of it"
        );
    }

    #[test]
    fn a_database_written_by_an_earlier_record_shape_is_redrawn_rather_than_reused() {
        // Reuse compares digests, so an unchanged tree is never read and nothing would ever rewrite
        // records that predate a new property. The version on each record is what makes a bump the
        // migration: without it, a database built before `precision` existed would never gain it.
        let dir = TempDir::new("shape-change");
        let file = dir.write("src/lib.rs", "fn only() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![file.clone()], &mut graph, 1);

        // What a database written by the previous shape looks like: same bytes, no version.
        for node in &mut graph.nodes {
            node.properties
                .retain(|(key, _)| key.as_str() != "schema_version");
        }

        let draft = build(&dir, vec![file], &mut graph, 2);
        assert_eq!(
            draft.reused_files, 0,
            "the bytes are unchanged, and the shape is not"
        );
        assert_eq!(draft.analyzed_files, 1, "so the file is read again");
        assert!(
            graph.nodes.iter().any(|node| {
                node.labels.iter().any(|held| held.as_str() == FILE_LABEL)
                    && integer(node, "schema_version") == Some(i64::from(GRAPH_SCHEMA_VERSION))
            }),
            "and its record now says which shape wrote it"
        );
    }

    #[test]
    fn a_directory_that_loses_its_last_file_goes_with_it() {
        // A directory is not owned by any one file in it — it has its own source unit for exactly
        // this reason. What must still happen is that an empty one stops being claimed, because a
        // directory the tree no longer has is not a fact about the tree.
        let dir = TempDir::new("emptied");
        let kept = dir.write("src/kept.rs", "fn kept() {}\n");
        let going = dir.write("old/going.rs", "fn going() {}\n");
        let mut graph = Graph::default();
        build(&dir, vec![kept.clone(), going], &mut graph, 1);
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| property(node, "path") == Some("old")),
            "it was there to begin with"
        );

        build(&dir, vec![kept], &mut graph, 2);
        let remaining: Vec<&str> = graph
            .nodes
            .iter()
            .filter(|node| {
                node.labels
                    .iter()
                    .any(|held| held.as_str() == DIRECTORY_LABEL)
            })
            .filter_map(|node| property(node, "path"))
            .collect();
        assert_eq!(remaining, [".", "src"], "and `old` left with its last file");
    }

    #[test]
    fn a_project_holding_only_documents_builds_a_graph() {
        // The direction this Stage answers: analysis must not depend on the language, and a
        // repository of documents with no code at all has to be analyzable. Whatever else is
        // true of such a project, its own files are facts about it.
        let dir = TempDir::new("documents-only");
        let files = ["README.md", "docs/design.md", "docs/api.md"]
            .into_iter()
            .map(|path| {
                let mut file = dir.write(path, "# Title\n\nProse.\n");
                file.language = "markdown".to_owned();
                file
            })
            .collect();
        let mut graph = Graph::default();
        let draft = build_with(&dir, files, &mut graph, 1, false);

        assert_eq!(draft.analyzed_files, 0);
        assert_eq!(draft.recorded_files, 3);
        assert!(
            !draft.change_set.operations.is_empty(),
            "an empty change set is refused, and would commit no generation at all"
        );
        let paths = |label: &str| {
            let mut found: Vec<&str> = graph
                .nodes
                .iter()
                .filter(|node| node.labels.iter().any(|held| held.as_str() == label))
                .filter_map(|node| property(node, "path"))
                .collect();
            found.sort_unstable();
            found
        };
        assert_eq!(
            paths(FILE_LABEL),
            ["README.md", "docs/api.md", "docs/design.md"]
        );
        // And the tree they sit in, so the graph is something to walk rather than a list.
        assert_eq!(paths(DIRECTORY_LABEL), [".", "docs"]);
        let contains = relations(&graph, CONTAINS);
        assert!(
            contains.contains(&(".".to_owned(), "docs".to_owned())),
            "a directory reaches its subdirectory: {contains:?}"
        );
        assert!(
            contains.contains(&("docs".to_owned(), "docs/api.md".to_owned())),
            "and the files directly in it: {contains:?}"
        );
        assert!(
            contains.contains(&(".".to_owned(), "README.md".to_owned())),
            "including at the top: {contains:?}"
        );
    }

    #[test]
    fn editing_a_recorded_file_is_noticed_even_though_nothing_analyzes_it() {
        // Reuse compares digests. It used to consider only the analyzable files, so an edit to a
        // file nothing analyzes left its record holding a digest the file no longer had while the
        // build reported that every file was unchanged.
        let dir = TempDir::new("recorded-edit");
        let mut file = dir.write("notes.md", "# One\n");
        file.language = "markdown".to_owned();
        let mut graph = Graph::default();
        build_with(&dir, vec![file], &mut graph, 1, false);

        let mut edited = dir.write("notes.md", "# One\n\n# Two\n");
        edited.language = "markdown".to_owned();
        let digest = edited.digest.as_str().to_owned();
        let draft = build_with(&dir, vec![edited], &mut graph, 2, false);

        assert_eq!(
            draft.reused_files, 0,
            "the file changed, so nothing is reused"
        );
        assert_eq!(draft.recorded_files, 1);
        let stored = graph
            .nodes
            .iter()
            .find_map(|node| property(node, "digest"))
            .expect("the record is still there");
        assert_eq!(stored, digest, "and its record holds the new bytes");
    }

    #[test]
    fn a_recorded_file_is_reused_when_it_has_not_changed() {
        let dir = TempDir::new("recorded-reuse");
        let mut file = dir.write("notes.md", "# One\n");
        file.language = "markdown".to_owned();
        let mut graph = Graph::default();
        build_with(&dir, vec![file.clone()], &mut graph, 1, false);

        let draft = build_with(&dir, vec![file], &mut graph, 2, false);
        assert_eq!(draft.reused_files, 1);
        assert!(
            draft.change_set.operations.is_empty(),
            "an unchanged tree is not read at all"
        );
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
