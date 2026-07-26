//! Database files on disk.
//!
//! # How a commit becomes atomic
//!
//! A commit never writes over a live database. It stages the whole next container
//! beside it, flushes that file, records the intent in the journal, flushes the
//! journal, and only then renames the staged file into place. A rename is atomic, so
//! a reader observes either the previous generation or the next one, never a mixture.
//!
//! If the process dies at any point before the rename, the database file is
//! untouched and the last valid generation stays readable. [`recover`] then discards
//! the abandoned staged file.
//!
//! # Durability limits worth stating plainly
//!
//! The staged file and the journal are flushed with `sync_all` before the rename. The
//! containing directory is also flushed, best effort: not every platform and
//! filesystem supports flushing a directory handle, and treating that as a failure
//! would make commits fail on systems where the rename is durable anyway. On a system
//! that ignores directory flushes, a power loss immediately after a rename can lose
//! the rename itself. The journal is what lets the next open finish that promotion.

use crate::container::{Container, ContainerBuilder, ContainerError, Section};
use crate::generation::{Generation, GenerationError};
use crate::journal::{self, JournalError, JournalRecord};
use std::fmt;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Extension appended to stage the next container.
pub const STAGED_SUFFIX: &str = ".staged";

/// Extension appended for the transaction journal.
pub const JOURNAL_SUFFIX: &str = ".journal";

/// Why a storage operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// The filesystem refused an operation.
    ///
    /// The path and the operating system's message are both retained, because a
    /// storage failure that does not say which file it concerns is hard to act on.
    Io {
        /// The path concerned.
        path: String,
        /// What the operating system reported.
        message: String,
    },
    /// The container is invalid.
    Container(ContainerError),
    /// The generation counter cannot advance.
    Generation(GenerationError),
    /// The journal cannot represent a path.
    Journal(JournalError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(formatter, "{path}: {message}"),
            Self::Container(error) => write!(formatter, "{error}"),
            Self::Generation(error) => write!(formatter, "{error}"),
            Self::Journal(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<ContainerError> for StorageError {
    fn from(error: ContainerError) -> Self {
        Self::Container(error)
    }
}

impl From<GenerationError> for StorageError {
    fn from(error: GenerationError) -> Self {
        Self::Generation(error)
    }
}

impl From<JournalError> for StorageError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

fn io_error(path: &Path, error: &std::io::Error) -> StorageError {
    StorageError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

fn as_utf8(path: &Path) -> Result<&str, StorageError> {
    path.to_str()
        .ok_or(StorageError::Journal(JournalError::NonUtf8Path))
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn write_durably(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let mut file = File::create(path).map_err(|error| io_error(path, &error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(path, &error))?;
    file.sync_all().map_err(|error| io_error(path, &error))?;
    Ok(())
}

/// Flushes a directory, best effort. See the module documentation.
fn sync_directory(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(handle) = File::open(parent)
    {
        let _ = handle.sync_all();
    }
}

fn read_if_present(path: &Path) -> Result<Option<Vec<u8>>, StorageError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(path, &error)),
    }
}

fn remove_if_present(path: &Path) -> Result<(), StorageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, &error)),
    }
}

/// An opened database file.
#[derive(Clone, Debug)]
pub struct Database {
    path: PathBuf,
    container: Container,
}

impl Database {
    /// Creates a database holding no sections at the initial generation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Io`] when the file cannot be written, or
    /// [`StorageError::Container`] when the container cannot be built.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let bytes = ContainerBuilder::new(Generation::INITIAL).build()?;
        write_durably(&path, &bytes)?;
        sync_directory(&path);
        let container = Container::parse(&bytes)?;
        Ok(Self { path, container })
    }

    /// Opens a database file.
    ///
    /// No daemon is required, which is the root PRD invariant in section 7.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Io`] when the file cannot be read, or
    /// [`StorageError::Container`] when it is corrupt or its format version is
    /// unsupported. Use [`ContainerError::code`] for the stable diagnostic code.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let bytes = fs::read(&path).map_err(|error| io_error(&path, &error))?;
        let container = Container::parse(&bytes)?;
        Ok(Self { path, container })
    }

    /// The path this database was opened from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current generation.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.container.generation()
    }

    /// The current container.
    #[must_use]
    pub const fn container(&self) -> &Container {
        &self.container
    }

    /// Replaces every section, advancing the generation by one.
    ///
    /// The whole next container is staged and flushed before anything is renamed, so a
    /// failure at any earlier point leaves the previous generation readable.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Generation`] when the counter cannot advance,
    /// [`StorageError::Container`] when the next container cannot be built, and
    /// [`StorageError::Io`] when a filesystem step fails.
    pub fn commit(&mut self, sections: Vec<Section>) -> Result<Generation, StorageError> {
        let next = self.generation().next()?;

        let mut builder = ContainerBuilder::new(next);
        for section in sections {
            builder.push_section(section.kind, section.payload)?;
        }
        let bytes = builder.build()?;
        let container = Container::parse(&bytes)?;

        let staged = sibling(&self.path, STAGED_SUFFIX);
        let journal_path = sibling(&self.path, JOURNAL_SUFFIX);

        write_durably(&staged, &bytes)?;

        let transaction = journal::encode_transaction(
            next,
            &[JournalRecord::Promote {
                staged: as_utf8(&staged)?.to_owned(),
                destination: as_utf8(&self.path)?.to_owned(),
            }],
        );
        write_durably(&journal_path, &transaction)?;

        fs::rename(&staged, &self.path).map_err(|error| io_error(&staged, &error))?;
        sync_directory(&self.path);

        // The promotion is done, so the intent record is no longer needed. Leaving it
        // would make the next open replay a promotion whose staged file is gone.
        remove_if_present(&journal_path)?;

        self.container = container;
        Ok(next)
    }
}

/// What recovery did.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RecoveryReport {
    /// Promotions completed because the journal recorded them as committed.
    pub promotions_completed: usize,
    /// Staged files discarded because their transaction never committed.
    pub staged_discarded: usize,
    /// Whether the journal had a torn tail.
    pub journal_truncated: bool,
}

/// Finishes or rolls back an interrupted transaction for a database path.
///
/// Call this before opening a database that may have been interrupted. A committed
/// promotion whose staged file still exists is completed; an uncommitted staged file
/// is discarded. Replaying twice has the same effect as replaying once.
///
/// # Errors
///
/// Returns [`StorageError::Io`] when a filesystem step fails.
pub fn recover(path: impl AsRef<Path>) -> Result<RecoveryReport, StorageError> {
    let path = path.as_ref();
    let journal_path = sibling(path, JOURNAL_SUFFIX);
    let staged_path = sibling(path, STAGED_SUFFIX);

    let Some(journal_bytes) = read_if_present(&journal_path)? else {
        // No journal means no interrupted transaction. A staged file left behind
        // without a journal was abandoned before its intent was durable.
        let discarded = usize::from(read_if_present(&staged_path)?.is_some());
        remove_if_present(&staged_path)?;
        return Ok(RecoveryReport {
            promotions_completed: 0,
            staged_discarded: discarded,
            journal_truncated: false,
        });
    };

    let recovery = journal::replay(&journal_bytes);
    let mut report = RecoveryReport {
        journal_truncated: recovery.truncated,
        ..RecoveryReport::default()
    };

    for record in &recovery.committed {
        match record {
            JournalRecord::Promote {
                staged,
                destination,
            } => {
                let staged = Path::new(staged);
                if staged.exists() {
                    fs::rename(staged, Path::new(destination))
                        .map_err(|error| io_error(staged, &error))?;
                    sync_directory(Path::new(destination));
                    report.promotions_completed += 1;
                }
            }
            JournalRecord::Remove { path } => remove_if_present(Path::new(path))?,
            JournalRecord::Begin { .. } | JournalRecord::Commit => {}
        }
    }

    for staged in &recovery.abandoned_staged {
        let staged = Path::new(staged);
        if staged.exists() {
            remove_if_present(staged)?;
            report.staged_discarded += 1;
        }
    }

    // A staged file the journal never mentioned is also abandoned.
    if staged_path.exists() {
        remove_if_present(&staged_path)?;
        report.staged_discarded += 1;
    }

    remove_if_present(&journal_path)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::SectionKind;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            // A per-label directory keeps concurrent tests from colliding without
            // needing a random number source.
            base.push(format!("nostdb-core-storage-{label}"));
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

    fn section(kind: SectionKind, payload: &[u8]) -> Section {
        Section {
            kind,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn a_created_database_opens_at_the_initial_generation_without_a_daemon() {
        let dir = TempDir::new("create");
        let path = dir.join("root.nostdb");
        let created = Database::create(&path).unwrap();
        assert_eq!(created.generation(), Generation::INITIAL);

        let opened = Database::open(&path).unwrap();
        assert_eq!(opened.generation(), Generation::INITIAL);
        assert!(opened.container().sections().is_empty());
    }

    #[test]
    fn a_commit_advances_the_generation_and_is_visible_after_reopening() {
        let dir = TempDir::new("commit");
        let path = dir.join("root.nostdb");
        let mut database = Database::create(&path).unwrap();

        let next = database
            .commit(vec![section(SectionKind::Nodes, b"node bytes")])
            .unwrap();
        assert_eq!(next.get(), 2);
        assert_eq!(database.generation(), next);

        let reopened = Database::open(&path).unwrap();
        assert_eq!(reopened.generation().get(), 2);
        assert_eq!(
            reopened.container().section(SectionKind::Nodes),
            Some(&b"node bytes"[..])
        );
    }

    #[test]
    fn successive_commits_keep_advancing() {
        let dir = TempDir::new("successive");
        let path = dir.join("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        for expected in 2..=5_u64 {
            let generation = database
                .commit(vec![section(SectionKind::Nodes, &[expected as u8])])
                .unwrap();
            assert_eq!(generation.get(), expected);
        }
        assert_eq!(Database::open(&path).unwrap().generation().get(), 5);
    }

    #[test]
    fn a_commit_leaves_no_staged_file_or_journal_behind() {
        let dir = TempDir::new("clean");
        let path = dir.join("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        database
            .commit(vec![section(SectionKind::Nodes, b"x")])
            .unwrap();
        assert!(!sibling(&path, STAGED_SUFFIX).exists());
        assert!(!sibling(&path, JOURNAL_SUFFIX).exists());
    }

    #[test]
    fn an_interrupted_commit_preserves_the_last_valid_generation() {
        let dir = TempDir::new("interrupted");
        let path = dir.join("root.nostdb");
        let mut database = Database::create(&path).unwrap();
        database
            .commit(vec![section(SectionKind::Nodes, b"first")])
            .unwrap();

        // Simulate a crash after staging and journalling, before the rename: the
        // journal records the intent, but its Commit record never landed.
        let staged = sibling(&path, STAGED_SUFFIX);
        let journal_path = sibling(&path, JOURNAL_SUFFIX);
        let next_bytes = {
            let mut builder = ContainerBuilder::new(Generation::from_raw(3));
            builder
                .push_section(SectionKind::Nodes, b"second".to_vec())
                .unwrap();
            builder.build().unwrap()
        };
        fs::write(&staged, &next_bytes).unwrap();
        let mut partial = JournalRecord::Begin {
            generation: Generation::from_raw(3),
        }
        .encode();
        partial.extend_from_slice(
            &JournalRecord::Promote {
                staged: staged.to_str().unwrap().to_owned(),
                destination: path.to_str().unwrap().to_owned(),
            }
            .encode(),
        );
        fs::write(&journal_path, &partial).unwrap();

        let report = recover(&path).unwrap();
        assert_eq!(report.promotions_completed, 0);
        assert_eq!(report.staged_discarded, 1);
        assert!(!staged.exists());
        assert!(!journal_path.exists());

        // The database still holds the last committed generation.
        let reopened = Database::open(&path).unwrap();
        assert_eq!(reopened.generation().get(), 2);
        assert_eq!(
            reopened.container().section(SectionKind::Nodes),
            Some(&b"first"[..])
        );
    }

    #[test]
    fn a_committed_but_unpromoted_transaction_is_completed_by_recovery() {
        let dir = TempDir::new("finish");
        let path = dir.join("root.nostdb");
        Database::create(&path).unwrap();

        // Simulate a crash between the journal Commit and the rename.
        let staged = sibling(&path, STAGED_SUFFIX);
        let journal_path = sibling(&path, JOURNAL_SUFFIX);
        let next_bytes = {
            let mut builder = ContainerBuilder::new(Generation::from_raw(2));
            builder
                .push_section(SectionKind::Nodes, b"promoted".to_vec())
                .unwrap();
            builder.build().unwrap()
        };
        fs::write(&staged, &next_bytes).unwrap();
        fs::write(
            &journal_path,
            journal::encode_transaction(
                Generation::from_raw(2),
                &[JournalRecord::Promote {
                    staged: staged.to_str().unwrap().to_owned(),
                    destination: path.to_str().unwrap().to_owned(),
                }],
            ),
        )
        .unwrap();

        let report = recover(&path).unwrap();
        assert_eq!(report.promotions_completed, 1);
        assert!(!staged.exists());

        let reopened = Database::open(&path).unwrap();
        assert_eq!(reopened.generation().get(), 2);
        assert_eq!(
            reopened.container().section(SectionKind::Nodes),
            Some(&b"promoted"[..])
        );
    }

    #[test]
    fn recovery_is_idempotent() {
        let dir = TempDir::new("idempotent");
        let path = dir.join("root.nostdb");
        Database::create(&path).unwrap();
        let first = recover(&path).unwrap();
        let second = recover(&path).unwrap();
        assert_eq!(first, RecoveryReport::default());
        assert_eq!(second, RecoveryReport::default());
        assert_eq!(Database::open(&path).unwrap().generation().get(), 1);
    }

    #[test]
    fn a_staged_file_without_a_journal_is_discarded() {
        let dir = TempDir::new("orphan");
        let path = dir.join("root.nostdb");
        Database::create(&path).unwrap();
        fs::write(sibling(&path, STAGED_SUFFIX), b"garbage").unwrap();

        let report = recover(&path).unwrap();
        assert_eq!(report.staged_discarded, 1);
        assert!(!sibling(&path, STAGED_SUFFIX).exists());
        assert_eq!(Database::open(&path).unwrap().generation().get(), 1);
    }

    #[test]
    fn opening_a_corrupt_file_reports_the_container_code() {
        let dir = TempDir::new("corrupt");
        let path = dir.join("root.nostdb");
        Database::create(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();

        let error = Database::open(&path).unwrap_err();
        match error {
            StorageError::Container(inner) => {
                assert_eq!(
                    inner.code(),
                    crate::diagnostic::DiagnosticCode::NostdbCorrupt
                );
            }
            other => panic!("expected a container error, found {other:?}"),
        }
    }

    #[test]
    fn opening_a_missing_file_reports_the_path() {
        let dir = TempDir::new("missing");
        let path = dir.join("absent.nostdb");
        match Database::open(&path).unwrap_err() {
            StorageError::Io {
                path: reported,
                message,
            } => {
                assert!(reported.contains("absent.nostdb"), "{reported}");
                assert!(!message.is_empty());
            }
            other => panic!("expected an I/O error, found {other:?}"),
        }
    }
}
