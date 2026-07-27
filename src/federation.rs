//! Resolving declared links into a reachable set of graphs.
//!
//! A link is identified by its canonical locator, never by a generated identifier and
//! never by the target's internal identity. Resolution walks the declarations
//! recursively, opens what it can reach, and reports what it cannot.
//!
//! # Nothing here fails because a link does
//!
//! Root PRD section 18.6 requires an inaccessible source to keep its declaration and the
//! query to return everything reachable. Resolution therefore produces warnings and
//! statuses rather than errors: the only way to get an `Err` out of it is for the *root*
//! to be unreadable, which is a different problem.
//!
//! # Linking unions; it does not merge
//!
//! Two sources may carry records with the same label, the same properties, and even the
//! same local identifier — a database copied and then linked from its original has all
//! three. They stay distinct, because a record is identified by the pair of canonical
//! locator and local identifier. Resolution keeps each source's graph separate for
//! exactly that reason, rather than concatenating them into one.

use crate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::encoding::{Graph, read_graph};
use crate::link::Link;
use crate::locator::CanonicalSourceLocator;
use crate::nost;
use crate::settings::FederationSettings;
use crate::storage::Database;
use crate::text::NonEmptyText;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// The state directory a configured project keeps.
const STATE_DIRECTORY: &str = ".nostdb";

/// The default database inside a project directory.
const DEFAULT_DATABASE: &str = "root.nostdb";

/// The settings file whose presence marks a configured project.
const SETTINGS_FILE: &str = "settings.json";

/// Why a declared link is not contributing records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unreachable {
    /// The locator names a scheme this build has no provider for.
    NoProvider {
        /// The scheme, such as `github`.
        scheme: String,
    },
    /// The locator resolves to nothing on disk.
    NotFound,
    /// The target exists but could not be read or decoded.
    Unreadable {
        /// What went wrong.
        reason: String,
    },
    /// The target was already opened in this traversal.
    Cycle,
    /// A configured traversal limit was reached before this link.
    LimitExceeded {
        /// Which limit.
        limit: &'static str,
    },
}

impl Unreachable {
    /// The diagnostic code this state reports.
    #[must_use]
    pub const fn code(&self) -> DiagnosticCode {
        match self {
            Self::Cycle => DiagnosticCode::LinkCycle,
            Self::LimitExceeded { .. } => DiagnosticCode::LinkLimitExceeded,
            Self::NoProvider { .. } | Self::NotFound | Self::Unreadable { .. } => {
                DiagnosticCode::LinkUnavailable
            }
        }
    }
}

impl fmt::Display for Unreachable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProvider { scheme } => write!(
                formatter,
                "no provider for the `{scheme}` scheme is built into this binary"
            ),
            Self::NotFound => formatter.write_str("the target does not exist"),
            Self::Unreadable { reason } => formatter.write_str(reason),
            Self::Cycle => {
                formatter.write_str("already opened in this traversal, so the cycle is cut")
            }
            Self::LimitExceeded { limit } => write!(formatter, "the {limit} limit was reached"),
        }
    }
}

/// What became of one declared link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkStatus {
    /// The locator, which is the link's identity.
    pub locator: CanonicalSourceLocator,
    /// The alias, when the declaration carried one.
    pub alias: Option<String>,
    /// Which source declared it. `None` means the root.
    pub declared_by: Option<CanonicalSourceLocator>,
    /// How deep the declaring source sits. The root is zero.
    pub depth: u32,
    /// Why it is not contributing, when it is not.
    pub unreachable: Option<Unreachable>,
}

impl LinkStatus {
    /// Reports whether this link contributed records.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.unreachable.is_none()
    }
}

/// One graph in the reachable set.
#[derive(Clone, Debug, PartialEq)]
pub struct FederatedSource {
    /// The canonical locator. `None` for the root.
    pub locator: Option<CanonicalSourceLocator>,
    /// The file the graph was read from.
    pub path: PathBuf,
    /// How many links were followed to reach it. The root is zero.
    pub depth: u32,
    /// The records it holds.
    pub graph: Graph,
}

/// The root and everything reachable from it.
#[derive(Clone, Debug, PartialEq)]
pub struct Federation {
    /// The root first, then each opened link in the order it was reached.
    pub sources: Vec<FederatedSource>,
    /// One entry per declared link, reachable or not.
    pub statuses: Vec<LinkStatus>,
}

impl Federation {
    /// How many linked databases were opened, excluding the root.
    #[must_use]
    pub fn linked_databases_opened(&self) -> u64 {
        self.sources.len().saturating_sub(1) as u64
    }

    /// Reports whether some declared source was not fully traversed.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.statuses.iter().any(|status| !status.is_available())
    }

    /// The root graph.
    ///
    /// # Panics
    ///
    /// Never: resolution always places the root first.
    #[must_use]
    pub fn root(&self) -> &Graph {
        &self
            .sources
            .first()
            .expect("resolution always places the root first")
            .graph
    }

    /// One warning per unreachable link, in declaration order.
    #[must_use]
    pub fn warnings(&self) -> Vec<Diagnostic> {
        self.statuses
            .iter()
            .filter_map(|status| {
                let unreachable = status.unreachable.as_ref()?;
                let code = unreachable.code();
                Some(Diagnostic {
                    code,
                    severity: code.default_severity(),
                    message: NonEmptyText::new(format!("{}: {unreachable}", status.locator))
                        .unwrap_or_else(|_| NonEmptyText::literal("a link is unreachable")),
                    source: Some(status.locator.clone()),
                    range: None,
                    details: Vec::new(),
                })
            })
            .collect()
    }
}

/// Where a locator resolves to on disk, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// A `.nostdb` container.
    Database(PathBuf),
    /// A `.nost` document.
    Document(PathBuf),
}

/// Resolves a local locator against the directory that declared it.
///
/// Root PRD section 18.2 lists four accepted forms, and they are tried in that order. A
/// relative path resolves from the file that declared the link, which is why `base` is a
/// parameter rather than the working directory: a link declared two hops away must not
/// silently re-anchor to wherever the command was run.
fn resolve_target(base: &Path, locator: &CanonicalSourceLocator) -> Option<Target> {
    let candidate = base.join(locator.as_str());

    if candidate.is_file() {
        return match candidate.extension().and_then(std::ffi::OsStr::to_str) {
            Some("nost") => Some(Target::Document(candidate)),
            _ => Some(Target::Database(candidate)),
        };
    }

    if candidate.is_dir() {
        // A configured project: its settings name the database.
        let settings = candidate.join(STATE_DIRECTORY).join(SETTINGS_FILE);
        if settings.is_file() {
            let named = std::fs::read_to_string(&settings)
                .ok()
                .and_then(|text| crate::settings::SettingsDocument::parse(&text).ok())
                .map_or_else(
                    || DEFAULT_DATABASE.to_owned(),
                    |document| {
                        crate::settings::SettingsDocument::resolve(None, Some(&document))
                            .database
                            .path
                    },
                );
            let database = candidate.join(STATE_DIRECTORY).join(named);
            if database.is_file() {
                return Some(Target::Database(database));
            }
        }
        // A directory holding a database without settings.
        let database = candidate.join(STATE_DIRECTORY).join(DEFAULT_DATABASE);
        if database.is_file() {
            return Some(Target::Database(database));
        }
    }

    None
}

fn open_target(target: &Target) -> Result<Graph, Unreachable> {
    match target {
        Target::Database(path) => {
            let database = Database::open(path).map_err(|error| Unreachable::Unreadable {
                reason: error.to_string(),
            })?;
            read_graph(&database).map_err(|error| Unreachable::Unreadable {
                reason: error.to_string(),
            })
        }
        Target::Document(path) => {
            let text = std::fs::read_to_string(path).map_err(|error| Unreachable::Unreadable {
                reason: error.to_string(),
            })?;
            let file = nost::parse(&text).map_err(|error| Unreachable::Unreadable {
                reason: error.to_string(),
            })?;
            nost::to_graph(&file).map_err(|error| Unreachable::Unreadable {
                reason: error.to_string(),
            })
        }
    }
}

/// Resolves every link reachable from `root`.
///
/// `root_path` is the file the root graph came from; relative locators in the root
/// resolve from its directory. `limits` come from the effective settings.
///
/// This never fails. An unreachable link becomes a status and a warning, because the
/// product contract requires a query over a broken link to return what it can reach.
#[must_use]
pub fn resolve(root: Graph, root_path: &Path, limits: &FederationSettings) -> Federation {
    let root_directory = root_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let mut sources = vec![FederatedSource {
        locator: None,
        path: root_path.to_path_buf(),
        depth: 0,
        graph: root,
    }];
    let mut statuses: Vec<LinkStatus> = Vec::new();
    let mut opened: BTreeSet<String> = BTreeSet::new();

    // The traversal is breadth-first over (source index, declaring directory), so depth
    // is the number of links followed and the cheapest sources are reached first.
    let mut frontier: Vec<(usize, PathBuf)> = vec![(0, root_directory)];
    let mut depth = 0_u32;

    while !frontier.is_empty() {
        if depth >= u32::try_from(limits.max_link_depth).unwrap_or(u32::MAX) {
            // Record every link the next level would have followed, so the caller learns
            // what was cut rather than only that something was.
            for (index, _) in &frontier {
                let declared_by = sources[*index].locator.clone();
                for link in collect_links(&sources[*index].graph) {
                    statuses.push(LinkStatus {
                        locator: link.source.clone(),
                        alias: link.alias.as_ref().map(ToString::to_string),
                        declared_by: declared_by.clone(),
                        depth,
                        unreachable: Some(Unreachable::LimitExceeded {
                            limit: "max_link_depth",
                        }),
                    });
                }
            }
            break;
        }

        let mut next: Vec<(usize, PathBuf)> = Vec::new();
        for (index, base) in std::mem::take(&mut frontier) {
            let declared_by = sources[index].locator.clone();
            for link in collect_links(&sources[index].graph) {
                let status = follow(
                    &link,
                    &base,
                    declared_by.clone(),
                    depth,
                    limits,
                    &mut opened,
                    &mut sources,
                    &mut next,
                );
                statuses.push(status);
            }
        }
        frontier = next;
        depth += 1;
    }

    Federation { sources, statuses }
}

fn collect_links(graph: &Graph) -> Vec<Link> {
    graph.links.clone()
}

#[allow(clippy::too_many_arguments)]
fn follow(
    link: &Link,
    base: &Path,
    declared_by: Option<CanonicalSourceLocator>,
    depth: u32,
    limits: &FederationSettings,
    opened: &mut BTreeSet<String>,
    sources: &mut Vec<FederatedSource>,
    next: &mut Vec<(usize, PathBuf)>,
) -> LinkStatus {
    let mut status = LinkStatus {
        locator: link.source.clone(),
        alias: link.alias.as_ref().map(ToString::to_string),
        declared_by,
        depth,
        unreachable: None,
    };

    // A cycle is detected by canonical locator, which is also how the same reachable
    // source reached twice is opened only once.
    if opened.contains(link.source.as_str()) {
        status.unreachable = Some(Unreachable::Cycle);
        return status;
    }

    // The limit counts *linked* databases, so the root is excluded. That matches
    // `linked_databases_opened` in the result envelope, which is the number a caller sees
    // beside it; a limit counting one thing and a report counting another would be a trap.
    let linked_so_far = (sources.len() - 1) as u64;
    if linked_so_far >= limits.max_link_databases {
        status.unreachable = Some(Unreachable::LimitExceeded {
            limit: "max_link_databases",
        });
        return status;
    }

    if let Some(scheme) = link.source.scheme() {
        // The MVP remote provider is a separate out-of-process executable, and this
        // binary does not carry one. Saying so is better than reporting "not found",
        // which would send a reader looking for a missing file.
        status.unreachable = Some(Unreachable::NoProvider {
            scheme: scheme.to_owned(),
        });
        return status;
    }

    let Some(target) = resolve_target(base, &link.source) else {
        status.unreachable = Some(Unreachable::NotFound);
        return status;
    };

    match open_target(&target) {
        Err(reason) => status.unreachable = Some(reason),
        Ok(graph) => {
            opened.insert(link.source.as_str().to_owned());
            let path = match &target {
                Target::Database(path) | Target::Document(path) => path.clone(),
            };
            let directory = path
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            sources.push(FederatedSource {
                locator: Some(link.source.clone()),
                path,
                depth: depth + 1,
                graph,
            });
            next.push((sources.len() - 1, directory));
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::commit_graph;
    use crate::graph::Node;
    use crate::id::LocalNodeId;
    use crate::name::{Label, LinkAlias};
    use std::fs;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("nostdb-core-federation-{label}"));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).expect("temporary directory");
            Self(base)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits() -> FederationSettings {
        FederationSettings {
            max_link_depth: 16,
            max_link_databases: 256,
            link_open_timeout_ms: 10_000,
        }
    }

    fn locator(value: &str) -> CanonicalSourceLocator {
        CanonicalSourceLocator::new(value).unwrap()
    }

    /// A graph holding one node with the given label, and the given links.
    fn graph(marker: u8, label: &str, links: Vec<Link>) -> Graph {
        Graph {
            nodes: vec![Node {
                id: LocalNodeId::from_bytes([marker; 16]),
                labels: vec![Label::new(label).unwrap()],
                properties: Vec::new(),
                contributions: Vec::new(),
            }],
            edges: Vec::new(),
            links,
            schemas: Vec::new(),
        }
    }

    /// Writes a graph as a `.nostdb` file and returns its path.
    fn write_database(directory: &Path, name: &str, value: &Graph) -> PathBuf {
        fs::create_dir_all(directory).unwrap();
        let path = directory.join(name);
        let mut database = Database::create(&path).unwrap();
        commit_graph(&mut database, value).unwrap();
        path
    }

    #[test]
    fn a_root_with_no_links_resolves_to_itself() {
        let dir = TempDir::new("alone");
        let path = write_database(dir.path(), "root.nostdb", &graph(1, "Root", Vec::new()));
        let resolved = resolve(graph(1, "Root", Vec::new()), &path, &limits());

        assert_eq!(resolved.sources.len(), 1);
        assert_eq!(resolved.linked_databases_opened(), 0);
        assert!(!resolved.is_partial());
        assert!(resolved.statuses.is_empty());
        assert!(resolved.warnings().is_empty());
    }

    #[test]
    fn a_link_is_followed_recursively_and_depth_counts_the_hops() {
        // root -> child -> grandchild
        let dir = TempDir::new("recursive");
        write_database(
            dir.path(),
            "grandchild.nostdb",
            &graph(3, "Grandchild", Vec::new()),
        );
        write_database(
            dir.path(),
            "child.nostdb",
            &graph(2, "Child", vec![Link::new(locator("./grandchild.nostdb"))]),
        );
        let root = graph(1, "Root", vec![Link::new(locator("./child.nostdb"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(
            resolved.linked_databases_opened(),
            2,
            "{:?}",
            resolved.statuses
        );
        assert!(!resolved.is_partial());
        assert_eq!(resolved.sources[0].depth, 0);
        assert_eq!(resolved.sources[1].depth, 1);
        assert_eq!(resolved.sources[2].depth, 2);
        assert_eq!(
            resolved.sources[2].graph.nodes[0].labels[0].as_str(),
            "Grandchild"
        );
    }

    #[test]
    fn a_relative_locator_resolves_from_the_file_that_declared_it() {
        // The grandchild is named relative to the child's directory, not the root's, so
        // a traversal anchored on the working directory would miss it.
        let dir = TempDir::new("relative");
        let nested = dir.path().join("packages");
        write_database(
            &nested,
            "grandchild.nostdb",
            &graph(3, "Grandchild", Vec::new()),
        );
        write_database(
            &nested,
            "child.nostdb",
            &graph(2, "Child", vec![Link::new(locator("./grandchild.nostdb"))]),
        );
        let root = graph(
            1,
            "Root",
            vec![Link::new(locator("./packages/child.nostdb"))],
        );
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(
            resolved.linked_databases_opened(),
            2,
            "{:?}",
            resolved.statuses
        );
    }

    #[test]
    fn a_cycle_is_cut_by_canonical_locator_rather_than_looping() {
        let dir = TempDir::new("cycle");
        write_database(
            dir.path(),
            "child.nostdb",
            &graph(2, "Child", vec![Link::new(locator("./child.nostdb"))]),
        );
        let root = graph(1, "Root", vec![Link::new(locator("./child.nostdb"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(resolved.linked_databases_opened(), 1);
        assert!(resolved.is_partial());
        let cut = resolved
            .statuses
            .iter()
            .find(|status| status.unreachable == Some(Unreachable::Cycle))
            .expect("the self link is cut");
        assert_eq!(cut.locator.as_str(), "./child.nostdb");
        assert_eq!(
            resolved.warnings()[0].code,
            DiagnosticCode::LinkCycle,
            "{:?}",
            resolved.warnings()
        );
    }

    #[test]
    fn one_reachable_locator_is_opened_once_however_many_declare_it() {
        let dir = TempDir::new("shared");
        write_database(dir.path(), "shared.nostdb", &graph(4, "Shared", Vec::new()));
        write_database(
            dir.path(),
            "left.nostdb",
            &graph(2, "Left", vec![Link::new(locator("./shared.nostdb"))]),
        );
        write_database(
            dir.path(),
            "right.nostdb",
            &graph(3, "Right", vec![Link::new(locator("./shared.nostdb"))]),
        );
        let root = graph(
            1,
            "Root",
            vec![
                Link::new(locator("./left.nostdb")),
                Link::new(locator("./right.nostdb")),
            ],
        );
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        // left, right, and shared once.
        assert_eq!(
            resolved.linked_databases_opened(),
            3,
            "{:?}",
            resolved.statuses
        );
        let shared: Vec<_> = resolved
            .statuses
            .iter()
            .filter(|status| status.locator.as_str() == "./shared.nostdb")
            .collect();
        assert_eq!(shared.len(), 2, "both declarations are reported");
        assert_eq!(
            shared.iter().filter(|status| status.is_available()).count(),
            1,
            "and only one of them opened it"
        );
    }

    #[test]
    fn a_missing_target_stays_declared_and_yields_a_warning() {
        let dir = TempDir::new("missing");
        let root = graph(1, "Root", vec![Link::new(locator("./absent.nostdb"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(resolved.linked_databases_opened(), 0);
        assert!(resolved.is_partial());
        assert_eq!(resolved.statuses.len(), 1, "the declaration survives");
        assert_eq!(
            resolved.statuses[0].unreachable,
            Some(Unreachable::NotFound)
        );

        let warnings = resolved.warnings();
        assert_eq!(warnings[0].code, DiagnosticCode::LinkUnavailable);
        assert_eq!(
            warnings[0]
                .source
                .as_ref()
                .map(CanonicalSourceLocator::as_str),
            Some("./absent.nostdb")
        );
    }

    #[test]
    fn a_remote_locator_says_there_is_no_provider_rather_than_no_file() {
        // Reporting "not found" would send a reader looking for a missing file.
        let dir = TempDir::new("remote");
        let root = graph(
            1,
            "Root",
            vec![Link::new(locator(
                "github://example/shared/root.nostdb?ref=main",
            ))],
        );
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(
            resolved.statuses[0].unreachable,
            Some(Unreachable::NoProvider {
                scheme: "github".to_owned()
            })
        );
        assert!(resolved.warnings()[0].message.as_str().contains("github"));
    }

    #[test]
    fn a_corrupt_target_is_unavailable_rather_than_fatal() {
        let dir = TempDir::new("corrupt");
        let broken = dir.path().join("broken.nostdb");
        fs::write(&broken, b"not a container").unwrap();
        let root = graph(1, "Root", vec![Link::new(locator("./broken.nostdb"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert!(matches!(
            resolved.statuses[0].unreachable,
            Some(Unreachable::Unreadable { .. })
        ));
        // The root's own records are still there, which is the point.
        assert_eq!(resolved.root().nodes.len(), 1);
    }

    #[test]
    fn a_nost_document_is_a_valid_target() {
        let dir = TempDir::new("document");
        fs::write(
            dir.path().join("child.nost"),
            "@nost 2\nnode child: Child {}\n",
        )
        .unwrap();
        let root = graph(1, "Root", vec![Link::new(locator("./child.nost"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(
            resolved.linked_databases_opened(),
            1,
            "{:?}",
            resolved.statuses
        );
        assert_eq!(
            resolved.sources[1].graph.nodes[0].labels[0].as_str(),
            "Child"
        );
    }

    #[test]
    fn a_project_directory_resolves_through_its_settings() {
        let dir = TempDir::new("project-directory");
        let child = dir.path().join("packages").join("child");
        let state = child.join(STATE_DIRECTORY);
        write_database(&state, "root.nostdb", &graph(2, "Child", Vec::new()));
        fs::write(state.join(SETTINGS_FILE), "{\"settings_version\": 1}\n").unwrap();

        let root = graph(1, "Root", vec![Link::new(locator("./packages/child"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(
            resolved.linked_databases_opened(),
            1,
            "{:?}",
            resolved.statuses
        );
        assert_eq!(
            resolved.sources[1].graph.nodes[0].labels[0].as_str(),
            "Child"
        );
    }

    #[test]
    fn a_directory_holding_a_database_resolves_without_settings() {
        let dir = TempDir::new("bare-directory");
        let child = dir.path().join("child");
        write_database(
            &child.join(STATE_DIRECTORY),
            "root.nostdb",
            &graph(2, "Child", Vec::new()),
        );

        let root = graph(1, "Root", vec![Link::new(locator("./child"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(
            resolved.linked_databases_opened(),
            1,
            "{:?}",
            resolved.statuses
        );
    }

    #[test]
    fn the_depth_limit_stops_traversal_and_says_what_it_cut() {
        let dir = TempDir::new("depth-limit");
        write_database(
            dir.path(),
            "grandchild.nostdb",
            &graph(3, "Grandchild", Vec::new()),
        );
        write_database(
            dir.path(),
            "child.nostdb",
            &graph(2, "Child", vec![Link::new(locator("./grandchild.nostdb"))]),
        );
        let root = graph(1, "Root", vec![Link::new(locator("./child.nostdb"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let shallow = FederationSettings {
            max_link_depth: 1,
            ..limits()
        };
        let resolved = resolve(root, &path, &shallow);
        assert_eq!(resolved.linked_databases_opened(), 1, "only the child");
        assert!(resolved.is_partial());
        let cut = resolved
            .statuses
            .iter()
            .find(|status| {
                status.unreachable
                    == Some(Unreachable::LimitExceeded {
                        limit: "max_link_depth",
                    })
            })
            .expect("the grandchild is named as cut");
        assert_eq!(cut.locator.as_str(), "./grandchild.nostdb");
        assert_eq!(resolved.warnings().len(), 1);
        assert_eq!(
            resolved.warnings()[0].code,
            DiagnosticCode::LinkLimitExceeded
        );
    }

    #[test]
    fn the_database_limit_stops_opening_further_sources() {
        let dir = TempDir::new("database-limit");
        write_database(dir.path(), "one.nostdb", &graph(2, "One", Vec::new()));
        write_database(dir.path(), "two.nostdb", &graph(3, "Two", Vec::new()));
        let root = graph(
            1,
            "Root",
            vec![
                Link::new(locator("./one.nostdb")),
                Link::new(locator("./two.nostdb")),
            ],
        );
        let path = write_database(dir.path(), "root.nostdb", &root);

        // The limit counts linked databases and excludes the root, so a limit of 1
        // admits exactly one link and refuses the second.
        let capped = FederationSettings {
            max_link_databases: 1,
            ..limits()
        };
        let resolved = resolve(root, &path, &capped);
        assert_eq!(resolved.linked_databases_opened(), 1);
        assert_eq!(
            resolved
                .statuses
                .iter()
                .filter(|status| status.unreachable
                    == Some(Unreachable::LimitExceeded {
                        limit: "max_link_databases"
                    }))
                .count(),
            1,
            "{:?}",
            resolved.statuses
        );
        assert!(resolved.is_partial());
    }

    #[test]
    fn an_alias_and_the_declaring_source_are_recorded() {
        let dir = TempDir::new("provenance");
        write_database(dir.path(), "child.nostdb", &graph(2, "Child", Vec::new()));
        let root = graph(
            1,
            "Root",
            vec![Link::with_alias(
                locator("./child.nostdb"),
                LinkAlias::new("child").unwrap(),
            )],
        );
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(resolved.statuses[0].alias.as_deref(), Some("child"));
        assert_eq!(
            resolved.statuses[0].declared_by, None,
            "declared by the root"
        );
        assert_eq!(resolved.statuses[0].depth, 0);
    }

    #[test]
    fn a_link_declared_by_a_linked_source_records_who_declared_it() {
        let dir = TempDir::new("declared-by");
        write_database(
            dir.path(),
            "grandchild.nostdb",
            &graph(3, "Grandchild", Vec::new()),
        );
        write_database(
            dir.path(),
            "child.nostdb",
            &graph(2, "Child", vec![Link::new(locator("./grandchild.nostdb"))]),
        );
        let root = graph(1, "Root", vec![Link::new(locator("./child.nostdb"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        let nested = resolved
            .statuses
            .iter()
            .find(|status| status.locator.as_str() == "./grandchild.nostdb")
            .expect("the nested declaration is recorded");
        assert_eq!(
            nested
                .declared_by
                .as_ref()
                .map(CanonicalSourceLocator::as_str),
            Some("./child.nostdb")
        );
        assert_eq!(nested.depth, 1);
    }

    #[test]
    fn two_sources_carrying_the_same_identifier_stay_distinct() {
        // A database copied and then linked from its original has identical identifiers.
        // Keeping the graphs separate is what makes them different records rather than
        // one record seen twice.
        let dir = TempDir::new("copied");
        write_database(dir.path(), "copy.nostdb", &graph(1, "Copy", Vec::new()));
        let root = graph(1, "Root", vec![Link::new(locator("./copy.nostdb"))]);
        let path = write_database(dir.path(), "root.nostdb", &root);

        let resolved = resolve(root, &path, &limits());
        assert_eq!(resolved.sources.len(), 2);
        assert_eq!(
            resolved.sources[0].graph.nodes[0].id, resolved.sources[1].graph.nodes[0].id,
            "the identifiers really do collide"
        );
        assert_ne!(
            resolved.sources[0].locator, resolved.sources[1].locator,
            "and the locators are what tell them apart"
        );
    }
}
