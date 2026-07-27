//! Finding and opening a configured project.
//!
//! A configured project is a directory holding `.nostdb/settings.json`. The active
//! project is the nearest ancestor of the working directory that has one, which is the
//! rule in root PRD section 10.1.
//!
//! # Why this is in the Engine
//!
//! The command surface and the daemon both have to answer "which project is this?" and
//! they must answer it identically. The root contract's rule is that shared behavior
//! calls a public Core API rather than being implemented twice.
//!
//! # Opening does not create
//!
//! [`Project::open`] reads. Nothing here creates a directory or a file except
//! [`Project::initialize`], which is what `nostdb init` calls. A read-only command that
//! quietly wrote settings would violate the rule in the settings contract that a
//! read-only open never fills in a missing entry.

use crate::encoding::{DecodeError, Graph};
use crate::evidence::ContentDigest;
use crate::generation::Generation;
use crate::settings::{Settings, SettingsDocument, SettingsError};
use crate::storage::{Database, StorageError};
use crate::sync::{SyncBaseline, SyncState};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The directory a configured project keeps its state in.
pub const STATE_DIRECTORY: &str = ".nostdb";

/// The settings file whose presence marks a configured project.
pub const SETTINGS_FILE: &str = "settings.json";

/// The canonical human-readable file, when materialization is enabled.
pub const NOST_FILE: &str = "root.nost";

/// The synchronization baseline, recorded beside the database rather than inside it.
///
/// # Why a sidecar rather than the container's reserved section
///
/// The container reserves a `sync_metadata` section and it stays unwritten, deliberately.
/// A baseline records the digest of the whole database file. Writing it into that file
/// would change the digest it had just recorded, and advance the generation it had just
/// named, so the baseline would be wrong the instant it was stored.
///
/// Breaking that circle from inside would mean digesting everything *except* one section
/// and writing the baseline in the same commit that produces the generation it names.
/// Both are possible and neither is explicable. A sidecar has no circle to break.
pub const BASELINE_FILE: &str = "sync.json";

/// The baseline document's own version.
const BASELINE_VERSION: u64 = 1;

/// Why a project could not be found, opened, or created.
#[derive(Debug)]
pub enum ProjectError {
    /// No ancestor of the starting directory is a configured project.
    NotFound {
        /// Where the search started.
        from: PathBuf,
    },
    /// The directory is already a configured project.
    AlreadyConfigured {
        /// The project root.
        root: PathBuf,
    },
    /// The settings document was refused.
    Settings {
        /// Which file.
        path: PathBuf,
        /// Why.
        error: SettingsError,
    },
    /// A filesystem step failed.
    Io {
        /// What was being read or written.
        path: PathBuf,
        /// Why.
        error: io::Error,
    },
    /// The database could not be created or opened.
    Storage(StorageError),
    /// The `.nost` document was refused.
    Nost {
        /// Which file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// The recorded baseline is not one this build understands.
    Baseline {
        /// Which file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// The database opened, but its payloads do not describe a valid graph.
    ///
    /// Distinct from [`ProjectError::Storage`] because the container was readable: the
    /// bytes passed their checksums and only their interpretation failed, which is a
    /// different thing for a caller to be told.
    Decode(DecodeError),
}

impl fmt::Display for ProjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { from } => write!(
                formatter,
                "no configured project found at {} or in any parent directory; run `nostdb init`",
                from.display()
            ),
            Self::AlreadyConfigured { root } => write!(
                formatter,
                "{} is already a configured project",
                root.display()
            ),
            Self::Settings { path, error } => {
                write!(formatter, "{}: {error}", path.display())
            }
            Self::Io { path, error } => write!(formatter, "{}: {error}", path.display()),
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::Nost { path, reason } => write!(formatter, "{}: {reason}", path.display()),
            Self::Baseline { path, reason } => {
                write!(formatter, "{}: the baseline {reason}", path.display())
            }
            Self::Decode(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ProjectError {}

impl From<StorageError> for ProjectError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Replaces a file by renaming a sibling temporary over it.
///
/// A half-written baseline would be worse than none: it parses far enough to look like a
/// record of an agreement that never happened.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), ProjectError> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".staged");
    let staged = path.with_file_name(name);
    std::fs::write(&staged, bytes).map_err(|error| ProjectError::Io {
        path: staged.clone(),
        error,
    })?;
    std::fs::rename(&staged, path).map_err(|error| {
        let _ = std::fs::remove_file(&staged);
        ProjectError::Io {
            path: path.to_path_buf(),
            error,
        }
    })
}

fn read_document(path: &Path) -> Result<SettingsDocument, ProjectError> {
    let text = std::fs::read_to_string(path).map_err(|error| ProjectError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    SettingsDocument::parse(&text).map_err(|error| ProjectError::Settings {
        path: path.to_path_buf(),
        error,
    })
}

/// What synchronization did, or declined to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncAction {
    /// Both representations already agreed.
    UpToDate,
    /// The `.nost` file was adopted and the database advanced.
    Adopted {
        /// The generation the database now holds.
        generation: Generation,
    },
    /// The `.nost` file did not exist and was written from the database.
    Materialized,
    /// The database advanced and the `.nost` file did not, so the file is stale.
    NostStale,
    /// Both changed from one baseline. Neither was modified.
    Conflict,
    /// Nothing is recorded about what the two last agreed on.
    ///
    /// Synchronization cannot tell which side moved, so it declines rather than guessing.
    /// `export --nost` establishes a baseline; `convert` adopts a document wholesale.
    NoBaseline,
    /// Materialization is off and no `.nost` file exists, so there is nothing to compare.
    NotMaterialized,
}

impl SyncAction {
    /// Reports whether the two representations now agree.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        matches!(
            self,
            Self::UpToDate | Self::Adopted { .. } | Self::Materialized | Self::NotMaterialized
        )
    }
}

/// What synchronization did, and what it wants to say about it.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncReport {
    /// What happened.
    pub action: SyncAction,
    /// What to report, which is empty for an outcome that acted.
    pub diagnostics: Vec<crate::diagnostic::Diagnostic>,
}

impl SyncReport {
    fn nothing_to_do() -> Self {
        Self {
            action: SyncAction::NotMaterialized,
            diagnostics: Vec::new(),
        }
    }
}

/// A configured project: its root, and the settings in effect for it.
#[derive(Clone, Debug)]
pub struct Project {
    root: PathBuf,
    settings: Settings,
}

impl Project {
    /// The state directory for a project root.
    #[must_use]
    pub fn state_directory(root: &Path) -> PathBuf {
        root.join(STATE_DIRECTORY)
    }

    /// The settings file for a project root.
    #[must_use]
    pub fn settings_path(root: &Path) -> PathBuf {
        Self::state_directory(root).join(SETTINGS_FILE)
    }

    /// Reports whether `root` is a configured project.
    #[must_use]
    pub fn is_configured(root: &Path) -> bool {
        Self::settings_path(root).is_file()
    }

    /// Finds the nearest ancestor of `start` that is a configured project.
    ///
    /// `start` itself is considered first.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::NotFound`] when no ancestor is configured, and whatever
    /// [`Project::open`] reports for the one that is.
    pub fn discover(start: &Path, global: Option<&Path>) -> Result<Self, ProjectError> {
        let mut candidate: Option<&Path> = Some(start);
        while let Some(directory) = candidate {
            if Self::is_configured(directory) {
                return Self::open(directory, global);
            }
            candidate = directory.parent();
        }
        Err(ProjectError::NotFound {
            from: start.to_path_buf(),
        })
    }

    /// Opens the project rooted at `root`, merging the global settings when supplied.
    ///
    /// `global` names the user-global settings file, usually `~/.nostdb/settings.json`.
    /// A missing global file is not an error: it simply contributes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::NotFound`] when `root` is not configured,
    /// [`ProjectError::Settings`] when either document is refused, and
    /// [`ProjectError::Io`] when one cannot be read.
    pub fn open(root: &Path, global: Option<&Path>) -> Result<Self, ProjectError> {
        let settings_path = Self::settings_path(root);
        if !settings_path.is_file() {
            return Err(ProjectError::NotFound {
                from: root.to_path_buf(),
            });
        }
        let project_document = read_document(&settings_path)?;
        let global_document = match global {
            Some(path) if path.is_file() => Some(read_document(path)?),
            _ => None,
        };
        Ok(Self {
            root: root.to_path_buf(),
            settings: SettingsDocument::resolve(global_document.as_ref(), Some(&project_document)),
        })
    }

    /// Creates a configured project at `root`.
    ///
    /// Writes `.nostdb/settings.json` holding nothing but the contract version, and an
    /// empty database at the configured path. Every other setting is a default, so an
    /// unedited file states no value it does not need to.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::AlreadyConfigured`] rather than overwriting an existing
    /// settings file, [`ProjectError::Io`] when a directory or file cannot be written,
    /// and [`ProjectError::Storage`] when the database cannot be created.
    pub fn initialize(root: &Path) -> Result<Self, ProjectError> {
        if Self::is_configured(root) {
            return Err(ProjectError::AlreadyConfigured {
                root: root.to_path_buf(),
            });
        }

        let state = Self::state_directory(root);
        std::fs::create_dir_all(&state).map_err(|error| ProjectError::Io {
            path: state.clone(),
            error,
        })?;

        let settings = Settings::default();
        let database_path = state.join(&settings.database.path);
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| ProjectError::Io {
                path: parent.to_path_buf(),
                error,
            })?;
        }
        Database::create(&database_path)?;

        // The database is created before the settings file, so a crash between the two
        // leaves an unconfigured directory rather than a project pointing at nothing.
        let settings_path = Self::settings_path(root);
        std::fs::write(&settings_path, "{\n  \"settings_version\": 1\n}\n").map_err(|error| {
            ProjectError::Io {
                path: settings_path.clone(),
                error,
            }
        })?;

        Ok(Self {
            root: root.to_path_buf(),
            settings,
        })
    }

    /// The project root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The effective settings.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The database file this project's settings name.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        Self::state_directory(&self.root).join(&self.settings.database.path)
    }

    /// The canonical human-readable file, whether or not materialization is enabled.
    #[must_use]
    pub fn nost_path(&self) -> PathBuf {
        Self::state_directory(&self.root).join(NOST_FILE)
    }

    /// Opens the project's database.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Database::open`] reports.
    pub fn open_database(&self) -> Result<Database, ProjectError> {
        Ok(Database::open(self.database_path())?)
    }

    /// Reads the project's graph.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Storage`] when the database cannot be opened and
    /// [`ProjectError::Decode`] when its payloads do not describe a valid graph.
    pub fn read_graph(&self) -> Result<Graph, ProjectError> {
        let database = self.open_database()?;
        crate::encoding::read_graph(&database).map_err(ProjectError::Decode)
    }

    /// Where the synchronization baseline is recorded.
    #[must_use]
    pub fn baseline_path(&self) -> PathBuf {
        Self::state_directory(&self.root).join(BASELINE_FILE)
    }

    /// Reads the recorded baseline, or `None` when the two have never been made to agree.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when the file exists and cannot be read, and
    /// [`ProjectError::Baseline`] when it is not a baseline this build understands. A
    /// malformed baseline is refused rather than ignored: treating it as absent would
    /// silently discard the record of what the two sides last agreed on.
    pub fn read_baseline(&self) -> Result<Option<SyncBaseline>, ProjectError> {
        let path = self.baseline_path();
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path).map_err(|error| ProjectError::Io {
            path: path.clone(),
            error,
        })?;
        let malformed = |reason: &str| ProjectError::Baseline {
            path: path.clone(),
            reason: reason.to_owned(),
        };
        let document: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| malformed("not valid JSON"))?;
        if document
            .get("baseline_version")
            .and_then(serde_json::Value::as_u64)
            != Some(BASELINE_VERSION)
        {
            return Err(malformed(
                "names a baseline version this build does not write",
            ));
        }
        let field = |name: &str| -> Result<String, ProjectError> {
            document
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| malformed(&format!("is missing `{name}`")))
        };
        let generation = document
            .get("database_generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| malformed("is missing `database_generation`"))?;
        Ok(Some(SyncBaseline {
            database_generation: Generation::from_raw(generation),
            database_digest: ContentDigest::new(field("database_digest")?)
                .map_err(|_| malformed("`database_digest` is not a tagged digest"))?,
            nost_content_digest: ContentDigest::new(field("nost_content_digest")?)
                .map_err(|_| malformed("`nost_content_digest` is not a tagged digest"))?,
        }))
    }

    /// Records a baseline, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when the file cannot be written.
    pub fn write_baseline(&self, baseline: &SyncBaseline) -> Result<(), ProjectError> {
        let document = serde_json::json!({
            "baseline_version": BASELINE_VERSION,
            "database_generation": baseline.database_generation.get(),
            "database_digest": baseline.database_digest.as_str(),
            "nost_content_digest": baseline.nost_content_digest.as_str(),
        });
        let text =
            serde_json::to_string_pretty(&document).unwrap_or_else(|_| document.to_string()) + "\n";
        write_atomically(&self.baseline_path(), text.as_bytes())
    }

    /// The state both representations are in now.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when either file cannot be read.
    pub fn sync_state(&self) -> Result<SyncState, ProjectError> {
        let database_path = self.database_path();
        let bytes = std::fs::read(&database_path).map_err(|error| ProjectError::Io {
            path: database_path,
            error,
        })?;
        let nost = self.read_nost()?.unwrap_or_default();
        Ok(crate::sync::state_from(
            self.open_database()?.generation(),
            &bytes,
            &nost,
        ))
    }

    /// The `.nost` file's text, when it exists.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when it exists and cannot be read.
    pub fn read_nost(&self) -> Result<Option<String>, ProjectError> {
        let path = self.nost_path();
        if !path.is_file() {
            return Ok(None);
        }
        std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|error| ProjectError::Io { path, error })
    }

    /// Resolves every link reachable from this project's database.
    ///
    /// Never fails because a link does: an unreachable target becomes a status and a
    /// warning, which is what the product contract requires of a broken link.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Project::read_graph`] reports for the *root*. A root that
    /// cannot be read is a different problem from a link that cannot be reached.
    pub fn resolve_links(&self) -> Result<crate::federation::Federation, ProjectError> {
        let graph = self.read_graph()?;
        Ok(crate::federation::resolve(
            graph,
            &self.database_path(),
            &self.settings.federation,
        ))
    }

    /// Brings the two representations into agreement, or reports why it cannot.
    ///
    /// The decision is the state machine in [`crate::sync`]; this supplies it with what is
    /// on disk and carries out the one outcome that permits a change.
    ///
    /// # Errors
    ///
    /// Returns a [`ProjectError`] when a file cannot be read or written, or when the
    /// `.nost` file is refused. Reaching a `Conflict` or `NostStale` outcome is not an
    /// error here: both are reported in the returned [`SyncReport`], because the caller
    /// decides what a refusal to act means for its exit status.
    pub fn synchronize(&self) -> Result<SyncReport, ProjectError> {
        let materialize = self.settings.database.nost;
        let Some(nost) = self.read_nost()? else {
            if !materialize {
                return Ok(SyncReport::nothing_to_do());
            }
            // The contract requires the Engine to materialize a missing file when the
            // setting is on. There is nothing to compare, so nothing can conflict.
            let text = self.materialize()?;
            let baseline = self.baseline_for(&text)?;
            self.write_baseline(&baseline)?;
            return Ok(SyncReport {
                action: SyncAction::Materialized,
                diagnostics: Vec::new(),
            });
        };

        let Some(baseline) = self.read_baseline()? else {
            return Ok(SyncReport {
                action: SyncAction::NoBaseline,
                diagnostics: Vec::new(),
            });
        };

        let current = self.sync_state()?;
        let outcome = crate::sync::decide(&baseline, &current);
        let diagnostics = outcome.to_diagnostic().into_iter().collect();

        match outcome {
            crate::sync::SyncOutcome::UpToDate => Ok(SyncReport {
                action: SyncAction::UpToDate,
                diagnostics,
            }),
            crate::sync::SyncOutcome::NostStale => Ok(SyncReport {
                action: SyncAction::NostStale,
                diagnostics,
            }),
            crate::sync::SyncOutcome::Conflict => Ok(SyncReport {
                action: SyncAction::Conflict,
                diagnostics,
            }),
            crate::sync::SyncOutcome::AdoptNost => {
                let generation = self.adopt(&nost)?;
                // The baseline is recorded from what is on disk *after* the commit, so
                // the next comparison starts from the state that actually exists.
                let baseline = self.baseline_for(&nost)?;
                self.write_baseline(&baseline)?;
                Ok(SyncReport {
                    action: SyncAction::Adopted { generation },
                    diagnostics,
                })
            }
        }
    }

    /// Writes the canonical `.nost` from the database and records the agreement.
    ///
    /// # Errors
    ///
    /// Returns a [`ProjectError`] when the graph cannot be read or the file written.
    pub fn export_nost(&self) -> Result<String, ProjectError> {
        let text = self.materialize()?;
        let baseline = self.baseline_for(&text)?;
        self.write_baseline(&baseline)?;
        Ok(text)
    }

    /// Writes the canonical `.nost` without touching the baseline.
    fn materialize(&self) -> Result<String, ProjectError> {
        let graph = self.read_graph()?;
        let text = crate::nost::format(&crate::nost::from_graph(&graph));
        write_atomically(&self.nost_path(), text.as_bytes())?;
        Ok(text)
    }

    /// Validates a `.nost` document and commits it over this project's database.
    fn adopt(&self, text: &str) -> Result<Generation, ProjectError> {
        let file = crate::nost::parse(text).map_err(|error| ProjectError::Nost {
            path: self.nost_path(),
            reason: error.to_string(),
        })?;
        // Validation runs before anything is written, so a refused document leaves the
        // database exactly as it was.
        let found = crate::nost::validate(&file);
        if crate::nost::validate::has_errors(&found) {
            let first = found
                .iter()
                .find(|diagnostic| diagnostic.severity == crate::diagnostic::Severity::Error);
            return Err(ProjectError::Nost {
                path: self.nost_path(),
                reason: first.map_or_else(
                    || "the document is invalid".to_owned(),
                    |diagnostic| format!("{}: {}", diagnostic.code.as_str(), diagnostic.message),
                ),
            });
        }
        let graph = crate::nost::to_graph(&file).map_err(|error| ProjectError::Nost {
            path: self.nost_path(),
            reason: error.to_string(),
        })?;
        let mut database = self.open_database()?;
        Ok(crate::encoding::commit_graph(&mut database, &graph)?)
    }

    /// The baseline describing the database as it is now, paired with `nost`.
    fn baseline_for(&self, nost: &str) -> Result<SyncBaseline, ProjectError> {
        let path = self.database_path();
        let bytes = std::fs::read(&path).map_err(|error| ProjectError::Io {
            path: path.clone(),
            error,
        })?;
        let generation = Database::open(&path)?.generation();
        Ok(crate::sync::baseline_from(generation, &bytes, nost))
    }

    /// Reports every settings link entry that mirrors no link the graph declares.
    #[must_use]
    pub fn orphan_link_settings(&self, graph: &Graph) -> Vec<crate::diagnostic::Diagnostic> {
        let declared: Vec<&str> = graph
            .links
            .iter()
            .map(|link| link.source.as_str())
            .collect();
        self.settings.orphan_link_settings(declared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("nostdb-core-project-{label}"));
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

    #[test]
    fn initializing_creates_the_state_directory_the_settings_and_the_database() {
        let dir = TempDir::new("initialize");
        let project = Project::initialize(dir.path()).unwrap();

        assert!(Project::settings_path(dir.path()).is_file());
        assert!(project.database_path().is_file());
        assert_eq!(project.settings(), &Settings::default());

        // An unedited settings file states the version and nothing else.
        let text = fs::read_to_string(Project::settings_path(dir.path())).unwrap();
        let document: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            document.as_object().map(serde_json::Map::len),
            Some(1),
            "{text}"
        );
    }

    #[test]
    fn initializing_twice_is_refused_rather_than_overwriting() {
        let dir = TempDir::new("twice");
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            "{\"settings_version\": 1, \"database\": {\"nost\": true}}",
        )
        .unwrap();

        let error = Project::initialize(dir.path()).unwrap_err();
        assert!(matches!(error, ProjectError::AlreadyConfigured { .. }));

        // The edit survived, which is the point of refusing.
        let reopened = Project::open(dir.path(), None).unwrap();
        assert!(reopened.settings().database.nost);
    }

    #[test]
    fn discovery_finds_the_nearest_configured_ancestor() {
        let dir = TempDir::new("discover");
        Project::initialize(dir.path()).unwrap();
        let nested = dir.path().join("packages").join("child");
        fs::create_dir_all(&nested).unwrap();

        let found = Project::discover(&nested, None).unwrap();
        assert_eq!(found.root(), dir.path());

        // A nested project wins over its parent, because it is nearer.
        Project::initialize(&nested).unwrap();
        let inner = Project::discover(&nested, None).unwrap();
        assert_eq!(inner.root(), nested);
    }

    #[test]
    fn discovery_reports_where_it_started_when_nothing_is_configured() {
        let dir = TempDir::new("undiscovered");
        let nested = dir.path().join("deep");
        fs::create_dir_all(&nested).unwrap();
        match Project::discover(&nested, None) {
            Err(ProjectError::NotFound { from }) => assert_eq!(from, nested),
            other => panic!("expected NotFound, found {other:?}"),
        }
    }

    #[test]
    fn opening_merges_the_global_document() {
        let dir = TempDir::new("merge");
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            "{\"settings_version\": 1, \"database\": {\"nost\": true}}",
        )
        .unwrap();

        let global = dir.path().join("global.json");
        fs::write(
            &global,
            "{\"settings_version\": 1, \"federation\": {\"max_link_depth\": 4}}",
        )
        .unwrap();

        let project = Project::open(dir.path(), Some(&global)).unwrap();
        assert!(project.settings().database.nost, "from the project");
        assert_eq!(
            project.settings().federation.max_link_depth,
            4,
            "from the global"
        );
    }

    #[test]
    fn a_missing_global_document_contributes_nothing_rather_than_failing() {
        let dir = TempDir::new("no-global");
        Project::initialize(dir.path()).unwrap();
        let absent = dir.path().join("does-not-exist.json");
        let project = Project::open(dir.path(), Some(&absent)).unwrap();
        assert_eq!(project.settings(), &Settings::default());
    }

    #[test]
    fn a_refused_settings_document_names_the_file() {
        let dir = TempDir::new("bad-settings");
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            "{\"settings_version\": 0}",
        )
        .unwrap();

        let error = Project::open(dir.path(), None).unwrap_err();
        match &error {
            ProjectError::Settings { path, .. } => {
                assert_eq!(path, &Project::settings_path(dir.path()));
            }
            other => panic!("expected a settings error, found {other:?}"),
        }
        assert!(error.to_string().contains("settings.json"), "{error}");
    }

    #[test]
    fn the_database_path_follows_the_setting() {
        let dir = TempDir::new("database-path");
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            "{\"settings_version\": 1, \"database\": {\"path\": \"graphs/other.nostdb\"}}",
        )
        .unwrap();

        let project = Project::open(dir.path(), None).unwrap();
        assert!(project.database_path().ends_with("graphs/other.nostdb"));
        assert!(project.nost_path().ends_with(".nostdb/root.nost"));
    }

    #[test]
    fn an_orphan_settings_entry_is_reported_against_the_graph() {
        let dir = TempDir::new("orphan");
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            "{\"settings_version\": 1, \"links\": [{\"source\": \"./gone\"}]}",
        )
        .unwrap();

        let project = Project::open(dir.path(), None).unwrap();
        let graph = project.read_graph().unwrap();
        let found = project.orphan_link_settings(&graph);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].code,
            crate::diagnostic::DiagnosticCode::OrphanLinkSettings
        );
    }

    // -- synchronization -------------------------------------------------------------

    /// A configured project whose database holds one node and whose `.nost` is on.
    fn materialized(label: &str) -> (TempDir, Project) {
        let dir = TempDir::new(label);
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            "{\"settings_version\": 1, \"database\": {\"nost\": true}}",
        )
        .unwrap();
        let project = Project::open(dir.path(), None).unwrap();

        let mut database = project.open_database().unwrap();
        let graph = crate::nost::to_graph(
            &crate::nost::parse("@nost 2\nnode seed: Function {\n  name: \"seed\",\n}\n").unwrap(),
        )
        .unwrap();
        crate::encoding::commit_graph(&mut database, &graph).unwrap();
        (dir, project)
    }

    #[test]
    fn a_missing_nost_file_is_materialized_when_the_setting_is_on() {
        let (_dir, project) = materialized("materialize");
        assert!(!project.nost_path().is_file());

        let report = project.synchronize().unwrap();
        assert_eq!(report.action, SyncAction::Materialized);
        assert!(project.nost_path().is_file());
        assert!(
            project.baseline_path().is_file(),
            "and a baseline is recorded"
        );

        // A second run has nothing to do.
        assert_eq!(project.synchronize().unwrap().action, SyncAction::UpToDate);
    }

    #[test]
    fn a_missing_nost_file_is_left_alone_when_the_setting_is_off() {
        let dir = TempDir::new("not-materialized");
        let project = Project::initialize(dir.path()).unwrap();
        let report = project.synchronize().unwrap();
        assert_eq!(report.action, SyncAction::NotMaterialized);
        assert!(!project.nost_path().is_file());
    }

    #[test]
    fn without_a_baseline_synchronization_declines_rather_than_guessing() {
        // Nothing records what the two last agreed on, so neither side can be called the
        // one that moved. Guessing would overwrite whichever the guess went against.
        let (_dir, project) = materialized("no-baseline");
        project.export_nost().unwrap();
        fs::remove_file(project.baseline_path()).unwrap();

        let report = project.synchronize().unwrap();
        assert_eq!(report.action, SyncAction::NoBaseline);
    }

    #[test]
    fn a_changed_nost_file_is_adopted_and_the_database_advances() {
        let (_dir, project) = materialized("adopt");
        project.export_nost().unwrap();
        let before = project.open_database().unwrap().generation().get();

        let edited = format!(
            "{}\nnode added: Function {{\n  name: \"added\",\n}}\n",
            project.read_nost().unwrap().unwrap()
        );
        fs::write(project.nost_path(), &edited).unwrap();

        let report = project.synchronize().unwrap();
        match report.action {
            SyncAction::Adopted { generation } => assert!(generation.get() > before),
            other => panic!("expected an adoption, found {other:?}"),
        }
        assert_eq!(project.read_graph().unwrap().nodes.len(), 2);
        // And the two now agree, so a second run does nothing.
        assert_eq!(project.synchronize().unwrap().action, SyncAction::UpToDate);
    }

    #[test]
    fn a_changed_database_leaves_the_nost_file_stale_rather_than_regenerating_it() {
        // A stale file may hold edits its author has not applied, so regeneration is
        // explicit.
        let (_dir, project) = materialized("stale");
        project.export_nost().unwrap();
        let before = project.read_nost().unwrap().unwrap();

        let mut database = project.open_database().unwrap();
        let mut graph = project.read_graph().unwrap();
        graph.nodes.clear();
        crate::encoding::commit_graph(&mut database, &graph).unwrap();

        let report = project.synchronize().unwrap();
        assert_eq!(report.action, SyncAction::NostStale);
        assert_eq!(
            report.diagnostics[0].code,
            crate::diagnostic::DiagnosticCode::NostSourceStale
        );
        assert_eq!(
            project.read_nost().unwrap().unwrap(),
            before,
            "the file is untouched"
        );
    }

    #[test]
    fn both_sides_changing_is_a_conflict_that_modifies_neither() {
        let (_dir, project) = materialized("conflict");
        project.export_nost().unwrap();
        let nost_before = project.read_nost().unwrap().unwrap();

        // Move the database.
        let mut database = project.open_database().unwrap();
        let mut graph = project.read_graph().unwrap();
        graph.nodes.clear();
        crate::encoding::commit_graph(&mut database, &graph).unwrap();
        let database_before = fs::read(project.database_path()).unwrap();

        // And move the file.
        let edited = format!("{nost_before}\nnode added: Function {{}}\n");
        fs::write(project.nost_path(), &edited).unwrap();

        let report = project.synchronize().unwrap();
        assert_eq!(report.action, SyncAction::Conflict);
        assert_eq!(
            report.diagnostics[0].code,
            crate::diagnostic::DiagnosticCode::SyncConflict
        );
        assert_eq!(project.read_nost().unwrap().unwrap(), edited);
        assert_eq!(fs::read(project.database_path()).unwrap(), database_before);
        assert!(!report.action.is_settled());
    }

    #[test]
    fn a_refused_nost_file_leaves_the_database_exactly_as_it_was() {
        let (_dir, project) = materialized("refused");
        project.export_nost().unwrap();
        let before = fs::read(project.database_path()).unwrap();

        fs::write(
            project.nost_path(),
            "@nost 2\nnode a: L {\n  id: \"n_1\",\n}\n",
        )
        .unwrap();
        let error = project.synchronize().unwrap_err();
        assert!(matches!(error, ProjectError::Nost { .. }), "{error:?}");
        assert!(error.to_string().contains("NOST_INVALID_ID"), "{error}");
        assert_eq!(fs::read(project.database_path()).unwrap(), before);
    }

    #[test]
    fn a_malformed_baseline_is_refused_rather_than_treated_as_absent() {
        // Treating it as absent would silently discard the record of what the two last
        // agreed on, and the next run would then decline instead of acting.
        let (_dir, project) = materialized("bad-baseline");
        project.export_nost().unwrap();
        fs::write(project.baseline_path(), "{\"baseline_version\": 99}").unwrap();

        let error = project.read_baseline().unwrap_err();
        assert!(matches!(error, ProjectError::Baseline { .. }), "{error:?}");
    }

    #[test]
    fn a_baseline_round_trips_through_its_file() {
        let (_dir, project) = materialized("baseline-round-trip");
        let text = project.export_nost().unwrap();
        let written = project.read_baseline().unwrap().expect("a baseline exists");

        let expected = crate::sync::baseline_from(
            project.open_database().unwrap().generation(),
            &fs::read(project.database_path()).unwrap(),
            &text,
        );
        assert_eq!(written, expected);
    }

    #[test]
    fn the_container_never_carries_the_baseline() {
        // Writing it inside would change the digest it had just recorded. The section
        // stays reserved, and this asserts it stays unwritten.
        let (_dir, project) = materialized("sidecar");
        project.export_nost().unwrap();
        let database = project.open_database().unwrap();
        assert_eq!(
            database
                .container()
                .section(crate::container::SectionKind::SyncMetadata),
            None
        );
    }
}
