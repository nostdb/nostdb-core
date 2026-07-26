//! A graph round-trips through a real `.nostdb` file on disk.
//!
//! The unit tests cover encoding against an in-memory container. This exercises the
//! whole path a caller uses: create a database, commit a graph, close it, reopen it,
//! and read the graph back.

use nostdb_core::container::SectionKind;
use nostdb_core::contribution::{Contribution, Owner};
use nostdb_core::encoding::{Graph, commit_graph, read_graph};
use nostdb_core::graph::{Edge, Node, NodeReference};
use nostdb_core::id::{LocalEdgeId, LocalNodeId, SourceUnitId};
use nostdb_core::link::Link;
use nostdb_core::locator::CanonicalSourceLocator;
use nostdb_core::name::{Label, LinkAlias, PropertyKey, RelationName};
use nostdb_core::property::PropertyValue;
use nostdb_core::storage::Database;
use std::fs;
use std::path::PathBuf;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut base = std::env::temp_dir();
        base.push(format!("nostdb-core-graph-{label}"));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("temporary directory");
        Self(base)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn user_contribution() -> Contribution {
    Contribution {
        owner: Owner::User,
        source_unit: SourceUnitId::from_bytes([1; 16]),
        evidence: Vec::new(),
    }
}

fn sample_graph() -> Graph {
    let login = LocalNodeId::from_bytes([0x11; 16]);
    let database = LocalNodeId::from_bytes([0x22; 16]);
    Graph {
        nodes: vec![
            Node {
                id: login,
                labels: vec![Label::new("Function").unwrap()],
                properties: vec![(
                    PropertyKey::new("name").unwrap(),
                    PropertyValue::from("login"),
                )],
                contributions: vec![user_contribution()],
            },
            Node {
                id: database,
                labels: vec![Label::new("Database").unwrap()],
                properties: vec![(
                    PropertyKey::new("name").unwrap(),
                    PropertyValue::from("primary"),
                )],
                contributions: vec![user_contribution()],
            },
        ],
        edges: vec![Edge {
            id: LocalEdgeId::from_bytes([0x33; 16]),
            source: NodeReference::Local(login),
            target: NodeReference::Local(database),
            relation: RelationName::new("CALLS").unwrap(),
            properties: Vec::new(),
            contributions: vec![user_contribution()],
        }],
        links: vec![
            Link::new(CanonicalSourceLocator::new("./packages/child").unwrap()),
            Link::with_alias(
                CanonicalSourceLocator::new("./packages/shared").unwrap(),
                LinkAlias::new("shared").unwrap(),
            ),
        ],
    }
}

#[test]
fn a_graph_survives_a_commit_and_a_reopen() {
    let dir = TempDir::new("roundtrip");
    let path = dir.join("root.nostdb");

    let expected = sample_graph();
    let mut database = Database::create(&path).unwrap();
    assert!(read_graph(&database).unwrap().is_empty());

    let generation = commit_graph(&mut database, &expected).unwrap();
    assert_eq!(generation.get(), 2);

    // Reopen from disk rather than reusing the handle, so this proves the bytes carry
    // the graph rather than the in-memory value doing so.
    let reopened = Database::open(&path).unwrap();
    assert_eq!(reopened.generation().get(), 2);
    assert_eq!(read_graph(&reopened).unwrap(), expected);
}

#[test]
fn committing_a_second_graph_replaces_the_first() {
    let dir = TempDir::new("replace");
    let path = dir.join("root.nostdb");
    let mut database = Database::create(&path).unwrap();

    commit_graph(&mut database, &sample_graph()).unwrap();

    let mut trimmed = sample_graph();
    trimmed.edges.clear();
    trimmed.links.clear();
    let generation = commit_graph(&mut database, &trimmed).unwrap();
    assert_eq!(generation.get(), 3);

    let reopened = Database::open(&path).unwrap();
    let read = read_graph(&reopened).unwrap();
    assert_eq!(read, trimmed);
    assert!(read.edges.is_empty());
    assert!(read.links.is_empty());
    // A section that holds nothing is not written at all.
    assert_eq!(reopened.container().section(SectionKind::Edges), None);
    assert_eq!(reopened.container().section(SectionKind::Links), None);
}

#[test]
fn an_empty_graph_commits_and_reads_back_empty() {
    let dir = TempDir::new("empty");
    let path = dir.join("root.nostdb");
    let mut database = Database::create(&path).unwrap();
    commit_graph(&mut database, &Graph::default()).unwrap();

    let reopened = Database::open(&path).unwrap();
    assert!(read_graph(&reopened).unwrap().is_empty());
}

#[test]
fn a_committed_graph_is_byte_identical_across_commits_of_the_same_content() {
    let dir = TempDir::new("deterministic");
    let first_path = dir.join("first.nostdb");
    let second_path = dir.join("second.nostdb");

    let graph = sample_graph();
    let mut first = Database::create(&first_path).unwrap();
    commit_graph(&mut first, &graph).unwrap();
    let mut second = Database::create(&second_path).unwrap();
    commit_graph(&mut second, &graph).unwrap();

    // Same content at the same generation must produce the same bytes, which is what
    // lets synchronization compare digests rather than timestamps.
    assert_eq!(
        fs::read(&first_path).unwrap(),
        fs::read(&second_path).unwrap()
    );
}

#[test]
fn corrupting_a_committed_graph_is_reported_rather_than_returning_a_partial_graph() {
    let dir = TempDir::new("corrupt");
    let path = dir.join("root.nostdb");
    let mut database = Database::create(&path).unwrap();
    commit_graph(&mut database, &sample_graph()).unwrap();

    // Flip a byte in the tail, which lands in a section payload.
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&path, &bytes).unwrap();

    // The container checksum catches it before any payload is interpreted.
    assert!(Database::open(&path).is_err());
}
