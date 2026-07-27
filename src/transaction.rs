//! Explicit transactions over an open database.
//!
//! # What a transaction is for
//!
//! A query that writes needs somewhere for its changes to live until they are complete. A
//! transaction is that place: it reads the graph once, runs statements against its own
//! copy, and writes the whole graph back in one commit. A failure at any point leaves the
//! file untouched, which is the root product invariant that a failed mutation preserves the
//! last valid generation.
//!
//! Read-your-writes falls out of the same design. A statement sees what earlier statements
//! in its transaction did, because they modified the copy it is reading.
//!
//! # Why a stale base generation is a conflict rather than a rebase
//!
//! A transaction answers its reads from the generation it began at. If the database has
//! advanced since, those answers may no longer hold, so writes derived from them may no
//! longer mean what the caller intended. Committing anyway would silently rebase a decision
//! onto data it was never shown, so [`Transaction::commit`] reports
//! [`TransactionError::Conflict`] and modifies nothing.
//!
//! The check reads the generation from the file rather than from memory, because the point
//! is to notice a change another process made.
//!
//! # A conflict is a typed error, not a diagnostic code
//!
//! It describes what the caller did, not something found in analyzed content. The root
//! product contract keeps those two vocabularies apart, and the query subset contract says
//! so explicitly for this case.

use crate::cypher::{Query, QueryError};
use crate::encoding::{DecodeError, Graph, commit_graph, read_graph};
use crate::execute::{DatabaseContext, Parameters, QueryResult, execute};
use crate::generation::Generation;
use crate::locator::CanonicalSourceLocator;
use crate::mutate::WriteSummary;
use crate::storage::{Database, StorageError};
use std::fmt;

/// Why a transaction could not begin, run, or commit.
#[derive(Clone, Debug, PartialEq)]
pub enum TransactionError {
    /// The database's contents could not be decoded.
    Decode(DecodeError),
    /// A storage step failed.
    Storage(StorageError),
    /// The query was refused.
    Query(QueryError),
    /// The database advanced while this transaction was open.
    ///
    /// Nothing was modified. The caller re-reads and decides again, rather than having a
    /// decision rebased onto data it never saw.
    Conflict {
        /// The generation the transaction began at.
        base: u64,
        /// The generation the file holds now.
        found: u64,
    },
}

impl fmt::Display for TransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "{error}"),
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::Query(error) => write!(formatter, "{error}"),
            Self::Conflict { base, found } => write!(
                formatter,
                "the database advanced from generation {base} to {found} while this \
                 transaction was open, so nothing was modified"
            ),
        }
    }
}

impl std::error::Error for TransactionError {}

impl From<DecodeError> for TransactionError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<StorageError> for TransactionError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<QueryError> for TransactionError {
    fn from(error: QueryError) -> Self {
        Self::Query(error)
    }
}

/// An open transaction against one database.
///
/// Dropping a transaction without committing discards it. Nothing here commits implicitly:
/// a caller that wanted to keep a change and forgot to say so is better served by losing
/// the change than by a database that changed without being told to.
#[derive(Debug)]
pub struct Transaction<'a> {
    database: &'a mut Database,
    base: Generation,
    graph: Graph,
    context: DatabaseContext,
    writes: WriteSummary,
}

impl<'a> Transaction<'a> {
    /// Reads the database and opens a transaction over it.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::Decode`] when the container's payloads do not describe a
    /// valid graph.
    pub fn begin(database: &'a mut Database) -> Result<Self, TransactionError> {
        let graph = read_graph(database)?;
        let base = database.generation();
        let source = CanonicalSourceLocator::new(database.path().display().to_string()).ok();
        Ok(Self {
            database,
            base,
            graph,
            context: DatabaseContext {
                generation: Some(base),
                source,
            },
            writes: WriteSummary::default(),
        })
    }

    /// The generation this transaction began at.
    #[must_use]
    pub const fn base_generation(&self) -> Generation {
        self.base
    }

    /// The graph as this transaction currently sees it, including its own uncommitted
    /// writes.
    #[must_use]
    pub const fn graph(&self) -> &Graph {
        &self.graph
    }

    /// Everything this transaction has changed so far.
    #[must_use]
    pub const fn writes(&self) -> WriteSummary {
        self.writes
    }

    /// Runs one query.
    ///
    /// # Errors
    ///
    /// Returns whatever [`execute`] reports. A refused query may have applied part of its
    /// work to this transaction's copy; the caller decides, and
    /// [`Transaction::rollback`] discards it.
    pub fn run(
        &mut self,
        query: &Query,
        parameters: &Parameters,
    ) -> Result<QueryResult, QueryError> {
        let result = execute(query, &mut self.graph, parameters, &self.context)?;
        self.accumulate(result.writes);
        Ok(result)
    }

    fn accumulate(&mut self, writes: WriteSummary) {
        self.writes.nodes_created += writes.nodes_created;
        self.writes.nodes_deleted += writes.nodes_deleted;
        self.writes.edges_created += writes.edges_created;
        self.writes.edges_deleted += writes.edges_deleted;
        self.writes.properties_set += writes.properties_set;
        self.writes.properties_removed += writes.properties_removed;
        self.writes.labels_added += writes.labels_added;
        self.writes.labels_removed += writes.labels_removed;
    }

    /// Commits, returning the generation the database now holds.
    ///
    /// A transaction that changed nothing commits without advancing the generation.
    /// Synchronization compares generations, so letting a read advance one would make a
    /// query look like a change.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::Conflict`] when the database advanced since this
    /// transaction began, in which case nothing is modified, and
    /// [`TransactionError::Storage`] when a filesystem step fails.
    pub fn commit(self) -> Result<Generation, TransactionError> {
        if self.writes.is_empty() {
            return Ok(self.base);
        }

        // Read the generation from the file, not from memory: the change this is looking
        // for is one another process made.
        let current = Database::open(self.database.path())?.generation();
        if current != self.base {
            return Err(TransactionError::Conflict {
                base: self.base.get(),
                found: current.get(),
            });
        }

        Ok(commit_graph(self.database, &self.graph)?)
    }

    /// Discards everything this transaction did.
    ///
    /// The database is byte-identical to what it was when the transaction began, because
    /// nothing was written to it.
    pub fn rollback(self) {
        drop(self);
    }
}

/// Runs one query against a database, committing it when it wrote.
///
/// This is the autocommit path a single statement takes. A read commits nothing, so the
/// generation it reports is the one it read.
///
/// # Errors
///
/// Returns whatever [`Transaction::begin`], [`Transaction::run`], and
/// [`Transaction::commit`] report.
pub fn run_once(
    database: &mut Database,
    query: &Query,
    parameters: &Parameters,
) -> Result<(QueryResult, Generation), TransactionError> {
    let mut transaction = Transaction::begin(database)?;
    let result = transaction.run(query, parameters)?;
    let generation = transaction.commit()?;
    Ok((result, generation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cypher::parse;
    use crate::diagnostic::DiagnosticCode;
    use std::fs;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("nostdb-core-transaction-{label}"));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).expect("temporary directory");
            Self(base)
        }

        fn database(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn no_parameters() -> Parameters {
        Parameters::new()
    }

    fn run(database: &mut Database, source: &str) -> QueryResult {
        let query = parse(source).unwrap_or_else(|error| panic!("{source}: {error}"));
        let (result, _) = run_once(database, &query, &no_parameters())
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        result
    }

    #[test]
    fn a_write_commits_and_survives_a_reopen() {
        let dir = TempDir::new("commit");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        assert_eq!(database.generation().get(), 1);

        let result = run(
            &mut database,
            "CREATE (n:Function {name: \"login\"}) RETURN n.name",
        );
        assert_eq!(result.writes.nodes_created, 1);
        assert_eq!(result.rows.len(), 1);

        let reopened = Database::open(&path).unwrap();
        assert_eq!(reopened.generation().get(), 2);
        assert_eq!(read_graph(&reopened).unwrap().nodes.len(), 1);
    }

    #[test]
    fn a_read_only_transaction_does_not_advance_the_generation() {
        // Synchronization compares generations, so a query that changed nothing must not
        // look like a change.
        let dir = TempDir::new("read");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        run(&mut database, "CREATE (n:Function {name: \"login\"})");
        let after_write = Database::open(&path).unwrap().generation();

        let bytes_before = fs::read(&path).unwrap();
        run(&mut database, "MATCH (n:Function) RETURN n.name");
        assert_eq!(Database::open(&path).unwrap().generation(), after_write);
        assert_eq!(fs::read(&path).unwrap(), bytes_before);
    }

    #[test]
    fn statements_in_one_transaction_see_each_others_writes() {
        let dir = TempDir::new("readyourwrites");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();

        let mut transaction = Transaction::begin(&mut database).unwrap();
        transaction
            .run(
                &parse("CREATE (n:Service {name: \"alpha\"})").unwrap(),
                &no_parameters(),
            )
            .unwrap();
        let found = transaction
            .run(
                &parse("MATCH (n:Service) RETURN n.name").unwrap(),
                &no_parameters(),
            )
            .unwrap();
        assert_eq!(found.row_count(), 1);
        assert_eq!(transaction.writes().nodes_created, 1);

        let generation = transaction.commit().unwrap();
        assert_eq!(generation.get(), 2);
    }

    #[test]
    fn a_rollback_leaves_the_file_byte_identical() {
        let dir = TempDir::new("rollback");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        run(&mut database, "CREATE (n:Function {name: \"login\"})");
        let before = fs::read(&path).unwrap();

        let mut transaction = Transaction::begin(&mut database).unwrap();
        transaction
            .run(
                &parse("MATCH (n:Function) DETACH DELETE n").unwrap(),
                &no_parameters(),
            )
            .unwrap();
        assert!(transaction.graph().nodes.is_empty());
        transaction.rollback();

        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            read_graph(&Database::open(&path).unwrap())
                .unwrap()
                .nodes
                .len(),
            1
        );
    }

    #[test]
    fn a_stale_base_generation_is_a_conflict_and_modifies_nothing() {
        let dir = TempDir::new("conflict");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();

        let mut first = Transaction::begin(&mut database).unwrap();
        first
            .run(
                &parse("CREATE (n:Service {name: \"alpha\"})").unwrap(),
                &no_parameters(),
            )
            .unwrap();

        // Another process commits while the first transaction is open.
        {
            let mut other = Database::open(&path).unwrap();
            let mut writing = Transaction::begin(&mut other).unwrap();
            writing
                .run(
                    &parse("CREATE (n:Service {name: \"beta\"})").unwrap(),
                    &no_parameters(),
                )
                .unwrap();
            writing.commit().unwrap();
        }
        let bytes_before = fs::read(&path).unwrap();

        let error = first.commit().unwrap_err();
        assert_eq!(
            error,
            TransactionError::Conflict { base: 1, found: 2 },
            "{error}"
        );
        // The other transaction's work is intact, and the conflicted one wrote nothing.
        assert_eq!(fs::read(&path).unwrap(), bytes_before);
        let graph = read_graph(&Database::open(&path).unwrap()).unwrap();
        assert_eq!(graph.nodes.len(), 1);
    }

    #[test]
    fn a_refused_statement_leaves_the_database_at_its_last_valid_generation() {
        let dir = TempDir::new("refused");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        run(&mut database, "CREATE (n:Function {name: \"login\"})");
        let before = fs::read(&path).unwrap();

        // Deleting a node that still has a relationship is refused; the point is that the
        // file does not change.
        run(
            &mut database,
            "MATCH (n:Function) CREATE (n)-[:CALLS]->(m:Function {name: \"helper\"})",
        );
        let after_relationship = fs::read(&path).unwrap();
        assert_ne!(after_relationship, before);

        let query = parse("MATCH (n:Function {name: \"login\"}) DELETE n").unwrap();
        let error = run_once(&mut database, &query, &no_parameters()).unwrap_err();
        match error {
            TransactionError::Query(inner) => {
                assert_eq!(inner.code, DiagnosticCode::CypherSemanticError);
            }
            other => panic!("expected a query refusal, found {other}"),
        }
        assert_eq!(fs::read(&path).unwrap(), after_relationship);
    }

    #[test]
    fn a_transaction_reports_the_generation_it_began_at() {
        let dir = TempDir::new("base");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        let transaction = Transaction::begin(&mut database).unwrap();
        assert_eq!(transaction.base_generation(), Generation::INITIAL);
        transaction.rollback();
    }

    #[test]
    fn identifiers_a_write_mints_differ_across_two_identical_databases() {
        // This asserts the opposite of what an earlier revision asserted. Minting used to
        // derive an identifier from the generation and a counter, so the same write
        // against two identical databases produced byte-identical files. A minted
        // identifier is now a UUID version 7, so it does not.
        //
        // Synchronization is unaffected: it compares one file against its own recorded
        // baseline, never two independently produced databases. What is given up is
        // reproducible building, which the root product contract never asked for. The
        // reversal is recorded in the root IMPLEMENTATION_PROGRESS.md.
        let dir = TempDir::new("distinct-minting");
        let mut left = Database::create(dir.database("left.nostdb")).unwrap();
        let mut right = Database::create(dir.database("right.nostdb")).unwrap();
        for database in [&mut left, &mut right] {
            run(
                database,
                "CREATE (a:Service {name: \"alpha\"})-[:CALLS]->(b:Database {name: \"primary\"})",
            );
        }
        assert_ne!(
            fs::read(dir.database("left.nostdb")).unwrap(),
            fs::read(dir.database("right.nostdb")).unwrap()
        );
    }

    #[test]
    fn committing_identical_content_still_produces_identical_bytes() {
        // The property synchronization actually depends on, which minting does not touch:
        // two databases holding the same records, identifiers included, serialize the
        // same way. Only the choice of a new identifier is unpredictable.
        let dir = TempDir::new("identical-content");
        let mut left = Database::create(dir.database("left.nostdb")).unwrap();
        let mut right = Database::create(dir.database("right.nostdb")).unwrap();
        run(&mut left, "CREATE (a:Service {name: \"alpha\"})");

        let graph = read_graph(&left).unwrap();
        commit_graph(&mut right, &graph).unwrap();

        assert_eq!(
            fs::read(dir.database("left.nostdb")).unwrap(),
            fs::read(dir.database("right.nostdb")).unwrap()
        );
    }

    #[test]
    fn the_source_procedure_names_the_database_the_query_opened() {
        let dir = TempDir::new("source");
        let path = dir.database("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        run(&mut database, "CREATE (n:Function {name: \"login\"})");

        let result = run(
            &mut database,
            "MATCH (n:Function) RETURN nostdb.source(n) AS source",
        );
        assert_eq!(result.row_count(), 1);
        assert_eq!(
            result.rows[0][0].to_string(),
            path.display().to_string(),
            "the locator is the path the database was opened from"
        );
    }
}
