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
//!
//! Recovery is the one exception, and it is not a counterexample. [`Project::open`]
//! finishes a committed multi-file transaction before reading anything, because a crash
//! partway through four renames can leave the database, the settings mirror, the `.nost`,
//! and the baseline disagreeing. Finishing it is not inventing a decision: the decision
//! was made durable before the first rename, and replay only carries out what the journal
//! already records. Nothing happens in the ordinary case, where there is no journal.

use crate::encoding::{DecodeError, Graph};
use crate::evidence::ContentDigest;
use crate::generation::Generation;
use crate::journal;
use crate::link::Link;
use crate::locator::CanonicalSourceLocator;
use crate::name::LinkAlias;
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

/// The multi-file journal, inside the state directory.
const JOURNAL_FILE: &str = "journal";

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
    /// A build produced a change set the graph would not accept.
    Build {
        /// Why.
        reason: String,
    },
    /// A link declaration was refused.
    Link {
        /// The locator the command named.
        source: String,
        /// Why it was refused.
        reason: String,
    },
    /// The materialized `.nost` holds changes the database has not adopted.
    NostUnsynchronized {
        /// The file that would have been overwritten.
        path: PathBuf,
        /// What the synchronization state machine decided.
        reason: String,
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
            Self::Build { reason } => write!(formatter, "the build was refused: {reason}"),
            Self::Link { source, reason } => {
                write!(formatter, "link `{source}` was refused: {reason}")
            }
            Self::NostUnsynchronized { path, reason } => write!(
                formatter,
                "{} holds changes the database has not adopted ({reason}); \
                 run `nostdb sync` before changing a link",
                path.display()
            ),
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
    /// The user's own `~/.nostdb`, when one was supplied to [`Project::open`].
    user_directory: Option<PathBuf>,
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
        Self::recover(root)?;

        let project_document = read_document(&settings_path)?;
        let global_document = match global {
            Some(path) if path.is_file() => Some(read_document(path)?),
            _ => None,
        };
        Ok(Self {
            root: root.to_path_buf(),
            settings: SettingsDocument::resolve(global_document.as_ref(), Some(&project_document)),
            // The global settings file lives in the user's `.nostdb`, which is also where
            // their cache tier is. Deriving it from the path already supplied beats asking
            // a caller for the same directory twice.
            user_directory: global.and_then(|path| path.parent()).map(Path::to_path_buf),
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
            // A project being created has read no global settings, so it knows of no user
            // directory. Reopening it is what supplies one.
            user_directory: None,
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
        write_atomically(&self.baseline_path(), baseline_json(baseline).as_bytes())
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

    /// Walks this project's tree and reports what a build may analyze.
    ///
    /// The scan starts at the project root, not at the state directory, so the source a
    /// person arranged is what gets read. `.nostdb` is pruned, which keeps the database's
    /// own bytes from being fed back into it.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when the root cannot be listed. Nothing below the root
    /// produces an error: every failure becomes a recorded skip, because one unreadable
    /// subtree must not cost a build every other subtree.
    pub fn scan(
        &self,
        options: &crate::scan::ScanOptions,
    ) -> Result<crate::scan::Scan, ProjectError> {
        // The root is its own source. A federated build gives each linked source its own
        // locator, which is what keeps a coverage record meaningful once there are several.
        let locator = CanonicalSourceLocator::new(".")
            .unwrap_or_else(|_| unreachable!("`.` is a valid relative locator"));
        crate::scan::scan(&self.root, &locator, options).map_err(|error| match error {
            crate::scan::ScanError::Unreadable { path, error } => ProjectError::Io { path, error },
        })
    }

    /// Plans a build over this project without doing any of it.
    ///
    /// Root PRD section 17.6 requires a plan before any AI action begins. This produces
    /// one and spends nothing: it reads source to digest it, and stops there.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Project::scan`] reports.
    pub fn plan(
        &self,
        registry: &crate::analysis::CapabilityRegistry,
        options: &crate::scan::ScanOptions,
    ) -> Result<crate::plan::PlanReport, ProjectError> {
        let scan = self.scan(options)?;
        Ok(crate::plan::plan(&scan, registry, &self.settings.analysis))
    }

    /// Analyzes this project's source and commits what it found.
    ///
    /// The structural generation is committed before any optional enrichment, which root
    /// PRD section 17.1 requires: AI failure must not be able to erase structural facts,
    /// and the only way to guarantee that is for the structural database to exist first.
    ///
    /// Reuse is the default. A file whose bytes match the digest already recorded is not
    /// re-read, which is what section 17.8 asks for; `rebuild` asks for the work to be
    /// redone anyway.
    ///
    /// A failure leaves the previous generation exactly as it was. Nothing is written until
    /// the change set has been built, validated, and applied to a copy of the graph.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when the tree cannot be scanned, [`ProjectError::Decode`]
    /// when the database does not hold a readable graph, and [`ProjectError::Storage`] when
    /// the commit fails. A change set that cannot be applied is reported as
    /// [`ProjectError::Build`].
    pub fn build(
        &self,
        registry: &crate::analysis::CapabilityRegistry,
        options: &crate::scan::ScanOptions,
        rebuild: bool,
    ) -> Result<BuildReport, ProjectError> {
        let scan = self.scan(options)?;
        // Created up front so the first build of a project leaves entries behind rather
        // than only the second.
        self.prepare_cache()?;
        let plan = crate::plan::plan(&scan, registry, &self.settings.analysis);
        let revision = plan.plan.source_revision.clone();

        let mut database = self.open_database()?;
        let generation = database.generation();
        let mut graph = crate::encoding::read_graph(&database).map_err(ProjectError::Decode)?;
        let mut minter = crate::id::Minter::new();

        let draft = crate::build::draft(
            &crate::build::BuildRequest {
                root: &self.root,
                scan: &scan,
                graph: &graph,
                registry,
                revision: &revision,
                base_generation: generation.get(),
                rebuild,
                cache: &crate::cache::ParseCache::new(self.cache_layout()),
            },
            &mut minter,
        );
        // An empty set is refused by contract, and a project with no analyzable source is
        // not an error. Saying so beats reporting a failure the user cannot act on.
        if draft.change_set.operations.is_empty() {
            return Ok(BuildReport {
                generation,
                revision,
                summary: crate::apply::ApplySummary::default(),
                coverage: draft.coverage,
                analyzed_files: draft.analyzed_files,
                reused_files: draft.reused_files,
                cached_parses: draft.cached_parses,
                resolved_references: draft.resolved_references,
                plan,
            });
        }

        let summary =
            crate::apply::apply(&mut graph, &draft.change_set, generation.get(), &mut minter)
                .map_err(|error| ProjectError::Build {
                    reason: error.to_string(),
                })?;

        let generation = crate::encoding::commit_graph(&mut database, &graph)?;
        Ok(BuildReport {
            generation,
            revision,
            summary,
            coverage: draft.coverage,
            analyzed_files: draft.analyzed_files,
            reused_files: draft.reused_files,
            cached_parses: draft.cached_parses,
            resolved_references: draft.resolved_references,
            plan,
        })
    }

    /// The caches this project may read, in the order the contract fixes.
    ///
    /// The project tier is always present, because it is where this project's own artifacts
    /// belong. The user tier is present when the settings ask for it and a user directory
    /// is known — `cache.user` is how a project declines to read a tier shared with every
    /// other project the same operating-system user builds.
    #[must_use]
    pub fn cache_layout(&self) -> crate::cache::CacheLayout {
        let layout =
            crate::cache::CacheLayout::none().with_project(&Self::state_directory(&self.root));
        match self.user_directory.as_deref() {
            Some(path) if self.settings.cache.user => layout.with_user(path),
            _ => layout,
        }
    }

    /// Creates the project cache directory and keeps it out of version control.
    ///
    /// `.nostdb` as a whole is not excluded — the database inside it is meant to be shared
    /// — so the cache needs its own exclusion, and section 17.7 requires that neither cache
    /// is committed by default. Writing the file is what makes that true rather than
    /// advisory.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when the directory or the file cannot be written.
    pub fn prepare_cache(&self) -> Result<PathBuf, ProjectError> {
        let directory =
            Self::state_directory(&self.root).join(crate::cache::PROJECT_CACHE_DIRECTORY);
        std::fs::create_dir_all(&directory).map_err(|error| ProjectError::Io {
            path: directory.clone(),
            error,
        })?;
        let ignore = directory.join(crate::cache::CACHE_IGNORE_FILE);
        if !ignore.exists() {
            std::fs::write(&ignore, crate::cache::CACHE_IGNORE_CONTENTS).map_err(|error| {
                ProjectError::Io {
                    path: ignore.clone(),
                    error,
                }
            })?;
        }
        Ok(directory)
    }

    /// Where the multi-file journal lives.
    #[must_use]
    pub fn journal_path(&self) -> PathBuf {
        Self::state_directory(&self.root).join(JOURNAL_FILE)
    }

    /// Finishes or discards a multi-file transaction left by a crash.
    ///
    /// Called by [`Project::open`], so a caller does not have to remember to. Does nothing
    /// when there is no journal, which is every ordinary open.
    ///
    /// A journal with no commit record is discarded along with its staging files: the
    /// intent was never made durable, so the last valid generation is the one on disk.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Io`] when the journal cannot be read or a recorded rename
    /// cannot be carried out.
    pub fn recover(root: &Path) -> Result<(), ProjectError> {
        let path = Self::state_directory(root).join(JOURNAL_FILE);
        journal::recover_at(&path)
            .map(|_| ())
            .map_err(|error| ProjectError::Io { path, error })
    }

    /// Declares a link and mirrors it into the settings.
    ///
    /// The declaration is semantic and goes into the database; the settings entry carries
    /// only the operational detail a graph file must not hold. The alias goes into the
    /// database alone, because an alias in settings would make one link mean two things on
    /// two checkouts.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Link`] when the locator or alias is malformed, when the
    /// source is already declared, or when the alias is already in use;
    /// [`ProjectError::NostUnsynchronized`] when the materialized `.nost` holds unadopted
    /// changes; and the usual I/O and storage failures otherwise. Every refusal happens
    /// before anything is written.
    pub fn add_link(&self, source: &str, alias: Option<&str>) -> Result<LinkChange, ProjectError> {
        let refuse = |reason: String| ProjectError::Link {
            source: source.to_owned(),
            reason,
        };
        let locator =
            CanonicalSourceLocator::new(source).map_err(|error| refuse(error.to_string()))?;
        let alias = match alias {
            Some(text) => Some(LinkAlias::new(text).map_err(|error| refuse(error.to_string()))?),
            None => None,
        };

        let mut graph = self.read_graph()?;
        if graph.links.iter().any(|link| link.source == locator) {
            return Err(refuse("it is already declared".to_owned()));
        }
        if let Some(alias) = &alias
            && let Some(existing) = graph
                .links
                .iter()
                .find(|link| link.alias.as_ref() == Some(alias))
        {
            return Err(refuse(format!(
                "the alias `{alias}` already names `{}`",
                existing.source
            )));
        }

        let link = Link {
            source: locator,
            alias,
        };
        graph.links.push(link.clone());
        let outcome = self.commit_link_change(&graph)?;
        Ok(LinkChange {
            link,
            generation: outcome.0,
            settings_updated: outcome.1,
            nost_updated: outcome.2,
        })
    }

    /// Removes a declared link and its settings mirror.
    ///
    /// Removing a link removes a declaration, never data. Nothing reached through the link
    /// was ever part of this database, so there is nothing here to delete.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Link`] when the locator is malformed or names no declared
    /// link, [`ProjectError::NostUnsynchronized`] when the materialized `.nost` holds
    /// unadopted changes, and the usual I/O and storage failures otherwise.
    pub fn remove_link(&self, source: &str) -> Result<LinkChange, ProjectError> {
        let refuse = |reason: String| ProjectError::Link {
            source: source.to_owned(),
            reason,
        };
        let locator =
            CanonicalSourceLocator::new(source).map_err(|error| refuse(error.to_string()))?;

        let mut graph = self.read_graph()?;
        let Some(at) = graph.links.iter().position(|link| link.source == locator) else {
            return Err(refuse("no such link is declared".to_owned()));
        };
        let link = graph.links.remove(at);
        let outcome = self.commit_link_change(&graph)?;
        Ok(LinkChange {
            link,
            generation: outcome.0,
            settings_updated: outcome.1,
            nost_updated: outcome.2,
        })
    }

    /// Commits a graph whose links changed, together with every file that follows from it.
    ///
    /// Four files can move at once: the database, the settings mirror, the materialized
    /// `.nost`, and the baseline recording that the two agree. A rename is atomic on its
    /// own but four renames are not, so the whole set goes through the journal and a crash
    /// between any two of them is finished by the next open.
    ///
    /// Returns the new generation and whether the settings and `.nost` moved.
    fn commit_link_change(&self, graph: &Graph) -> Result<(Generation, bool, bool), ProjectError> {
        let database_path = self.database_path();
        let generation = Database::open(&database_path)?
            .generation()
            .next()
            .map_err(|error| ProjectError::Storage(StorageError::from(error)))?;

        // Everything that can be refused is refused before the first byte is staged.
        let nost = self.nost_to_write(graph)?;
        let settings = self.mirror_to_write(graph)?;

        let mut builder = crate::container::ContainerBuilder::new(generation);
        for section in crate::encoding::encode_graph(graph) {
            builder
                .push_section(section.kind, section.payload)
                .map_err(StorageError::from)?;
        }
        let bytes = builder.build().map_err(StorageError::from)?;

        let mut transaction = journal::FileTransaction::begin(self.journal_path(), generation);
        let staged = (|| -> io::Result<()> {
            transaction.stage(&database_path, &bytes)?;
            if let Some(settings) = &settings {
                transaction.stage(&Self::settings_path(&self.root), settings.as_bytes())?;
            }
            if let Some(nost) = &nost {
                transaction.stage(&self.nost_path(), nost.as_bytes())?;
                let baseline = crate::sync::baseline_from(generation, &bytes, nost);
                transaction.stage(&self.baseline_path(), baseline_json(&baseline).as_bytes())?;
            }
            Ok(())
        })();
        if let Err(error) = staged {
            // Nothing was promoted and no journal was written, so discarding the staging
            // files leaves the project exactly as it was.
            transaction.abandon();
            return Err(ProjectError::Io {
                path: Self::state_directory(&self.root),
                error,
            });
        }
        transaction.commit().map_err(|error| ProjectError::Io {
            path: self.journal_path(),
            error,
        })?;
        Ok((generation, settings.is_some(), nost.is_some()))
    }

    /// The `.nost` text to write beside a changed graph, or `None` when none is materialized.
    ///
    /// Refuses when the file on disk holds changes the database has not adopted.
    /// Regenerating it would overwrite what somebody wrote, which is the one thing an
    /// edit to an unrelated part of the project must never do.
    fn nost_to_write(&self, graph: &Graph) -> Result<Option<String>, ProjectError> {
        if !self.settings.database.nost {
            return Ok(None);
        }
        if self.read_nost()?.is_some() {
            // A file with no baseline is not known to be safe. It may be the Engine's own
            // output from before baselines were recorded, or it may be hand-written.
            let Some(baseline) = self.read_baseline()? else {
                return Err(ProjectError::NostUnsynchronized {
                    path: self.nost_path(),
                    reason: "no baseline records what the two last agreed on".to_owned(),
                });
            };
            let outcome = crate::sync::decide(&baseline, &self.sync_state()?);
            if matches!(
                outcome,
                crate::sync::SyncOutcome::AdoptNost | crate::sync::SyncOutcome::Conflict
            ) {
                return Err(ProjectError::NostUnsynchronized {
                    path: self.nost_path(),
                    reason: outcome.to_diagnostic().map_or_else(
                        || "the file changed since the baseline".to_owned(),
                        |diagnostic| diagnostic.code.as_str().to_owned(),
                    ),
                });
            }
        }
        Ok(Some(crate::nost::format(&crate::nost::from_graph(graph))))
    }

    /// The settings text to write beside a changed graph, or `None` when it already agrees.
    ///
    /// Every unknown field is preserved: this rewrites the document the user has, rather
    /// than rendering a fresh one from the fields this build happens to know.
    fn mirror_to_write(&self, graph: &Graph) -> Result<Option<String>, ProjectError> {
        let path = Self::settings_path(&self.root);
        let text = std::fs::read_to_string(&path).map_err(|error| ProjectError::Io {
            path: path.clone(),
            error,
        })?;
        let document = SettingsDocument::parse(&text).map_err(|error| ProjectError::Settings {
            path: path.clone(),
            error,
        })?;
        let mut value = document.to_json().clone();
        let object = value
            .as_object_mut()
            .ok_or_else(|| ProjectError::Settings {
                path: path.clone(),
                error: SettingsError::Invalid {
                    field: "<root>".to_owned(),
                    reason: "the document is not an object".to_owned(),
                },
            })?;

        let existing: Vec<serde_json::Value> = object
            .get("links")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let declared: Vec<&str> = graph
            .links
            .iter()
            .map(|link| link.source.as_str())
            .collect();

        // Kept in the graph's declaration order, with each surviving entry's operational
        // fields exactly as the user left them.
        let mut mirrored: Vec<serde_json::Value> = Vec::with_capacity(declared.len());
        for source in &declared {
            let entry = existing
                .iter()
                .find(|entry| {
                    entry.get("source").and_then(serde_json::Value::as_str) == Some(*source)
                })
                .cloned()
                .unwrap_or_else(|| serde_json::json!({ "source": source }));
            mirrored.push(entry);
        }

        if existing == mirrored && (!mirrored.is_empty() || object.contains_key("links")) {
            return Ok(None);
        }
        if mirrored.is_empty() && !object.contains_key("links") {
            return Ok(None);
        }
        object.insert("links".to_owned(), serde_json::Value::Array(mirrored));
        Ok(Some(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()) + "\n",
        ))
    }
}

/// What a build did.
#[derive(Clone, Debug)]
pub struct BuildReport {
    /// The generation the database now holds.
    pub generation: Generation,
    /// The immutable snapshot the facts were derived from.
    pub revision: String,
    /// What applying the change set did.
    pub summary: crate::apply::ApplySummary,
    /// What the build covered.
    pub coverage: crate::coverage::BuildCoverage,
    /// How many files were read and analyzed.
    pub analyzed_files: u64,
    /// How many files were reused rather than re-read.
    pub reused_files: u64,
    /// How many parses came from the cache rather than from the source.
    pub cached_parses: u64,
    /// How many references matched a record in the build.
    pub resolved_references: u64,
    /// The plan the build ran against.
    pub plan: crate::plan::PlanReport,
}

/// A committed link change.
#[derive(Clone, Debug)]
pub struct LinkChange {
    /// The link that was added or removed.
    pub link: Link,
    /// The generation the database now holds.
    pub generation: Generation,
    /// Whether the settings mirror was rewritten.
    pub settings_updated: bool,
    /// Whether the materialized `.nost` was rewritten.
    pub nost_updated: bool,
}

/// Renders a baseline as the document `sync.json` holds.
fn baseline_json(baseline: &SyncBaseline) -> String {
    let document = serde_json::json!({
        "baseline_version": BASELINE_VERSION,
        "database_generation": baseline.database_generation.get(),
        "database_digest": baseline.database_digest.as_str(),
        "nost_content_digest": baseline.nost_content_digest.as_str(),
    });
    serde_json::to_string_pretty(&document).unwrap_or_else(|_| document.to_string()) + "\n"
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

    /// A project with `nost` materialized and a baseline already recorded.
    fn materialized_project(dir: &TempDir) -> Project {
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            r#"{"settings_version": 1, "database": {"nost": true}}"#,
        )
        .unwrap();
        let project = Project::open(dir.path(), None).unwrap();
        project.export_nost().unwrap();
        project
    }

    fn links_in_settings(project: &Project) -> Vec<String> {
        let text = fs::read_to_string(Project::settings_path(project.root())).unwrap();
        let document: serde_json::Value = serde_json::from_str(&text).unwrap();
        document["links"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| entry["source"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn adding_a_link_declares_it_in_the_database_and_mirrors_it_into_the_settings() {
        let dir = TempDir::new("link-add");
        let project = Project::initialize(dir.path()).unwrap();

        let change = project.add_link("./packages/child", Some("child")).unwrap();
        assert_eq!(change.link.source.as_str(), "./packages/child");
        assert_eq!(change.link.alias.as_ref().unwrap().as_str(), "child");
        assert!(change.settings_updated);
        assert!(!change.nost_updated, "nothing is materialized here");

        let graph = project.read_graph().unwrap();
        assert_eq!(graph.links.len(), 1);
        assert_eq!(
            graph.links[0].alias.as_ref().map(|alias| alias.as_str()),
            Some("child")
        );
        assert_eq!(links_in_settings(&project), vec!["./packages/child"]);
    }

    #[test]
    fn the_alias_stays_out_of_the_settings() {
        // The settings contract forbids it: an alias in a machine-local operational file
        // would make one link mean two different things on two checkouts.
        let dir = TempDir::new("link-alias-not-mirrored");
        let project = Project::initialize(dir.path()).unwrap();
        project.add_link("./child", Some("child")).unwrap();

        let text = fs::read_to_string(Project::settings_path(dir.path())).unwrap();
        let document: serde_json::Value = serde_json::from_str(&text).unwrap();
        let entry = document["links"][0].as_object().unwrap();
        assert_eq!(entry["source"], "./child");
        assert_eq!(
            entry.keys().collect::<Vec<_>>(),
            vec!["source"],
            "the mirror carries the identity and nothing the contract forbids"
        );
        assert!(
            SettingsDocument::parse(&text).is_ok(),
            "an entry carrying an alias is rejected outright, so a mirror this build \
             writes must be one it accepts"
        );
    }

    #[test]
    fn a_duplicate_source_or_alias_is_refused_and_changes_nothing() {
        let dir = TempDir::new("link-duplicate");
        let project = Project::initialize(dir.path()).unwrap();
        project.add_link("./child", Some("child")).unwrap();
        let generation = project.open_database().unwrap().generation();

        assert!(matches!(
            project.add_link("./child", None),
            Err(ProjectError::Link { .. })
        ));
        assert!(matches!(
            project.add_link("./other", Some("child")),
            Err(ProjectError::Link { .. })
        ));
        assert!(matches!(
            project.remove_link("./nothing"),
            Err(ProjectError::Link { .. })
        ));

        assert_eq!(
            project.open_database().unwrap().generation(),
            generation,
            "a refused link leaves the last valid generation in place"
        );
        assert_eq!(project.read_graph().unwrap().links.len(), 1);
        assert_eq!(links_in_settings(&project), vec!["./child"]);
    }

    #[test]
    fn removing_a_link_removes_the_declaration_and_its_mirror() {
        let dir = TempDir::new("link-remove");
        let project = Project::initialize(dir.path()).unwrap();
        project.add_link("./first", None).unwrap();
        project.add_link("./second", Some("second")).unwrap();

        let change = project.remove_link("./first").unwrap();
        assert_eq!(change.link.source.as_str(), "./first");
        assert_eq!(
            project.read_graph().unwrap().links,
            vec![Link::with_alias(
                CanonicalSourceLocator::new("./second").unwrap(),
                LinkAlias::new("second").unwrap()
            )]
        );
        assert_eq!(links_in_settings(&project), vec!["./second"]);
    }

    #[test]
    fn the_mirror_keeps_operational_fields_and_unknown_fields_the_user_wrote() {
        let dir = TempDir::new("link-preserve");
        Project::initialize(dir.path()).unwrap();
        fs::write(
            Project::settings_path(dir.path()),
            r#"{
  "settings_version": 1,
  "links": [{"source": "./keep", "timeout_ms": 42000, "credential_ref": "ci"}],
  "experimental_field_a_newer_build_wrote": {"nested": true}
}"#,
        )
        .unwrap();
        // Reopened so the link the settings already mirror is also declared.
        let project = Project::open(dir.path(), None).unwrap();
        project.add_link("./keep", None).unwrap();
        project.add_link("./added", None).unwrap();

        let text = fs::read_to_string(Project::settings_path(dir.path())).unwrap();
        let document: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(document["links"][0]["timeout_ms"], 42000);
        assert_eq!(document["links"][0]["credential_ref"], "ci");
        assert_eq!(document["links"][1]["source"], "./added");
        assert_eq!(
            document["experimental_field_a_newer_build_wrote"]["nested"], true,
            "an unknown field must survive a write, or downgrading is lossy"
        );
    }

    #[test]
    fn a_materialized_project_rewrites_the_nost_and_the_baseline_together() {
        let dir = TempDir::new("link-materialized");
        let project = materialized_project(&dir);

        let change = project.add_link("./child", Some("child")).unwrap();
        assert!(change.nost_updated);
        let nost = project.read_nost().unwrap().unwrap();
        assert!(nost.contains("@link \"./child\" as child"), "{nost}");

        assert_eq!(
            project.synchronize().unwrap().action,
            SyncAction::UpToDate,
            "the baseline must describe the files the change left behind"
        );
    }

    #[test]
    fn a_nost_holding_unadopted_edits_is_never_overwritten() {
        let dir = TempDir::new("link-unsynchronized");
        let project = materialized_project(&dir);
        let edited = format!(
            "{}\n// a line somebody wrote by hand\n",
            project.read_nost().unwrap().unwrap()
        );
        fs::write(project.nost_path(), &edited).unwrap();
        let generation = project.open_database().unwrap().generation();

        assert!(matches!(
            project.add_link("./child", None),
            Err(ProjectError::NostUnsynchronized { .. })
        ));
        assert_eq!(
            project.read_nost().unwrap().unwrap(),
            edited,
            "the hand-written line survives the refusal"
        );
        assert_eq!(project.open_database().unwrap().generation(), generation);
        assert!(project.read_graph().unwrap().links.is_empty());
    }

    #[test]
    fn a_crash_after_the_journal_commits_is_finished_by_the_next_open() {
        let dir = TempDir::new("link-recovery");
        let project = materialized_project(&dir);
        project.add_link("./child", None).unwrap();

        // Reconstruct the state a crash between two renames leaves: the journal is
        // durable, one destination is stale, and its staging file is still present.
        let nost = project.nost_path();
        let finished = fs::read_to_string(&nost).unwrap();
        fs::write(&nost, "// the state before the change\n").unwrap();
        let staged = {
            let mut name = nost.file_name().unwrap().to_os_string();
            name.push(".staged");
            nost.with_file_name(name)
        };
        fs::write(&staged, &finished).unwrap();
        fs::write(
            Project::state_directory(dir.path()).join(JOURNAL_FILE),
            journal::encode_transaction(
                project.open_database().unwrap().generation(),
                &[journal::JournalRecord::Promote {
                    staged: staged.to_string_lossy().into_owned(),
                    destination: nost.to_string_lossy().into_owned(),
                }],
            ),
        )
        .unwrap();

        let project = Project::open(dir.path(), None).unwrap();
        assert_eq!(
            project.read_nost().unwrap().unwrap(),
            finished,
            "a committed rename is carried out rather than lost"
        );
        assert!(!staged.exists(), "the staging file is consumed");
        assert!(
            !Project::state_directory(dir.path())
                .join(JOURNAL_FILE)
                .exists(),
            "a finished journal is removed"
        );
    }

    #[test]
    fn a_journal_with_no_commit_record_is_discarded() {
        let dir = TempDir::new("link-uncommitted");
        let project = Project::initialize(dir.path()).unwrap();
        let settings = Project::settings_path(dir.path());
        let before = fs::read_to_string(&settings).unwrap();

        let mut name = settings.file_name().unwrap().to_os_string();
        name.push(".staged");
        let staged = settings.with_file_name(name);
        fs::write(&staged, "{\"settings_version\": 1, \"links\": []}").unwrap();
        let mut bytes = journal::JournalRecord::Begin {
            generation: Generation::from_raw(9),
        }
        .encode();
        bytes.extend(
            journal::JournalRecord::Promote {
                staged: staged.to_string_lossy().into_owned(),
                destination: settings.to_string_lossy().into_owned(),
            }
            .encode(),
        );
        fs::write(project.journal_path(), bytes).unwrap();

        Project::open(dir.path(), None).unwrap();
        assert_eq!(
            fs::read_to_string(&settings).unwrap(),
            before,
            "an intent that was never committed is not carried out"
        );
        assert!(!staged.exists(), "its staging file is discarded");
    }

    #[test]
    fn building_a_project_commits_a_generation_holding_what_the_analyzer_found() {
        let dir = TempDir::new("build");
        let project = Project::initialize(dir.path()).unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(
            dir.path().join("src/main.rs"),
            "fn main() { helper(); }\nfn helper() {}\n",
        )
        .unwrap();

        let registry = crate::analyze::builtin_registry().unwrap();
        let before = project.open_database().unwrap().generation();
        let report = project
            .build(&registry, &crate::scan::ScanOptions::default(), false)
            .unwrap();

        assert!(report.generation > before);
        assert_eq!(report.analyzed_files, 1);
        assert!(report.summary.nodes_created >= 3, "{:?}", report.summary);
        assert_eq!(report.resolved_references, 1);
        assert!(report.revision.starts_with("tree:"));

        let graph = project.read_graph().unwrap();
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.labels.iter().any(|label| label.as_str() == "Function")),
            "the committed generation holds the facts"
        );
    }

    #[test]
    fn a_project_with_no_analyzable_source_is_not_a_failure() {
        let dir = TempDir::new("build-empty");
        let project = Project::initialize(dir.path()).unwrap();
        fs::write(dir.path().join("notes.txt"), "nothing to analyze\n").unwrap();

        let registry = crate::analyze::builtin_registry().unwrap();
        let before = project.open_database().unwrap().generation();
        let report = project
            .build(&registry, &crate::scan::ScanOptions::default(), false)
            .unwrap();

        assert_eq!(report.analyzed_files, 0);
        assert!(report.summary.is_empty());
        assert_eq!(
            report.generation, before,
            "nothing was found, so nothing is committed"
        );
    }

    #[test]
    fn rebuilding_after_an_edit_replaces_only_what_changed() {
        let dir = TempDir::new("build-rebuild");
        let project = Project::initialize(dir.path()).unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), "fn kept() {}\n").unwrap();
        fs::write(dir.path().join("src/b.rs"), "fn removed() {}\n").unwrap();

        let registry = crate::analyze::builtin_registry().unwrap();
        let options = crate::scan::ScanOptions::default();
        project.build(&registry, &options, false).unwrap();

        let kept = project
            .read_graph()
            .unwrap()
            .nodes
            .iter()
            .find(|node| {
                node.properties.iter().any(|(key, value)| {
                    key.as_str() == "name"
                        && *value == crate::property::PropertyValue::String("kept".to_owned())
                })
            })
            .expect("the record")
            .id;

        fs::write(dir.path().join("src/b.rs"), "fn replaced() {}\n").unwrap();
        project.build(&registry, &options, false).unwrap();

        let graph = project.read_graph().unwrap();
        let names: Vec<String> = graph
            .nodes
            .iter()
            .filter_map(|node| {
                node.properties.iter().find_map(|(key, value)| match value {
                    crate::property::PropertyValue::String(text) if key.as_str() == "name" => {
                        Some(text.clone())
                    }
                    _ => None,
                })
            })
            .collect();
        assert!(names.contains(&"kept".to_owned()), "{names:?}");
        assert!(names.contains(&"replaced".to_owned()), "{names:?}");
        assert!(!names.contains(&"removed".to_owned()), "{names:?}");
        assert!(
            graph.nodes.iter().any(|node| node.id == kept),
            "the untouched file's records keep their identifiers"
        );
    }

    #[test]
    fn a_build_never_analyzes_the_state_directory() {
        // Feeding the database's own bytes back into itself would be a loop that grows
        // every generation.
        let dir = TempDir::new("build-state");
        let project = Project::initialize(dir.path()).unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

        let registry = crate::analyze::builtin_registry().unwrap();
        let report = project
            .build(&registry, &crate::scan::ScanOptions::default(), false)
            .unwrap();
        assert_eq!(report.analyzed_files, 1);
        assert!(
            report
                .plan
                .skipped
                .iter()
                .any(|(reason, _)| *reason == crate::coverage::SkipReason::Ignored)
        );
    }

    #[test]
    fn a_second_build_with_nothing_changed_commits_no_generation() {
        // A build that reuses everything has nothing to say. Committing a generation
        // anyway would make every run look like a change to whatever watches the file.
        let dir = TempDir::new("build-reuse");
        let project = Project::initialize(dir.path()).unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

        let registry = crate::analyze::builtin_registry().unwrap();
        let options = crate::scan::ScanOptions::default();
        let first = project.build(&registry, &options, false).unwrap();
        assert_eq!(first.analyzed_files, 1);

        let second = project.build(&registry, &options, false).unwrap();
        assert_eq!(second.reused_files, 1);
        assert_eq!(second.analyzed_files, 0);
        assert_eq!(
            second.coverage.structural,
            crate::coverage::CoverageState::Complete,
            "everything is covered; it was covered earlier and nothing changed"
        );
        assert_eq!(
            second.generation, first.generation,
            "nothing changed, so nothing is committed"
        );
    }

    #[test]
    fn a_cache_is_kept_out_of_version_control_by_the_engine_rather_than_by_advice() {
        // `.nostdb` as a whole is not excluded — the database inside it is meant to be
        // shared — so the cache needs its own exclusion.
        let dir = TempDir::new("cache-ignore");
        let project = Project::initialize(dir.path()).unwrap();
        let directory = project.prepare_cache().unwrap();

        let ignore = directory.join(crate::cache::CACHE_IGNORE_FILE);
        assert!(ignore.is_file());
        assert!(fs::read_to_string(&ignore).unwrap().contains('*'));

        // A second call must not overwrite a file somebody edited.
        fs::write(&ignore, "*\n!keep-this\n").unwrap();
        project.prepare_cache().unwrap();
        assert!(fs::read_to_string(&ignore).unwrap().contains("keep-this"));
    }

    #[test]
    fn the_project_cache_is_read_before_the_users_and_the_users_can_be_left_out() {
        let dir = TempDir::new("cache-layout");
        let project = Project::initialize(dir.path()).unwrap();
        let home = dir.path().join("home").join(".nostdb");

        let global = home.join("settings.json");
        fs::create_dir_all(&home).unwrap();
        fs::write(&global, "{\"settings_version\": 1}").unwrap();

        let with_user = Project::open(dir.path(), Some(&global)).unwrap();
        let layout = with_user.cache_layout();
        let tiers = layout.tiers();
        assert_eq!(tiers.len(), 2);
        assert_eq!(tiers[0].0, crate::cache::CacheTier::Project);
        assert!(tiers[0].1.starts_with(dir.path()));

        // A project that declines the shared tier reads only its own.
        fs::write(
            Project::settings_path(dir.path()),
            "{\"settings_version\": 1, \"cache\": {\"user\": false}}",
        )
        .unwrap();
        let declined = Project::open(dir.path(), Some(&global)).unwrap();
        let layout = declined.cache_layout();
        assert_eq!(layout.tiers().len(), 1);
        assert!(!layout.uses_user_tier());
        let _ = project;
    }

    #[test]
    fn the_cache_directory_is_never_analyzed() {
        // It sits inside `.nostdb`, which the scanner prunes. Feeding cached artifacts back
        // into the analysis that produced them would be a loop.
        let dir = TempDir::new("cache-not-scanned");
        let project = Project::initialize(dir.path()).unwrap();
        let directory = project.prepare_cache().unwrap();
        fs::write(directory.join("looks-like-source.rs"), "fn cached() {}\n").unwrap();
        fs::write(dir.path().join("real.rs"), "fn real() {}\n").unwrap();

        let scan = project.scan(&crate::scan::ScanOptions::default()).unwrap();
        let paths: Vec<&str> = scan.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, ["real.rs"]);
    }

    #[test]
    fn a_rebuild_after_an_edit_parses_only_the_file_that_changed() {
        // The half of incremental work that was provably safe to keep. Every file still
        // enters the build, so the name index is complete and resolution is unaffected;
        // what the cache saves is the reading and the parsing.
        let dir = TempDir::new("build-parse-cache");
        let project = Project::initialize(dir.path()).unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), "fn a() { b(); }\n").unwrap();
        fs::write(dir.path().join("src/b.rs"), "fn b() {}\n").unwrap();

        let registry = crate::analyze::builtin_registry().unwrap();
        let options = crate::scan::ScanOptions::default();
        let first = project.build(&registry, &options, false).unwrap();
        assert_eq!(first.analyzed_files, 2);
        assert_eq!(first.cached_parses, 0, "nothing was stored yet");

        fs::write(dir.path().join("src/a.rs"), "fn a() { let x = 1; b(); }\n").unwrap();
        let second = project.build(&registry, &options, false).unwrap();
        assert_eq!(second.analyzed_files, 2, "both files still enter the build");
        assert_eq!(
            second.cached_parses, 1,
            "only the unchanged one came from cache"
        );

        // The cross-file edge is the thing per-file reuse could not promise.
        let graph = project.read_graph().unwrap();
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| edge.relation.as_str() == crate::build::CALLS)
                .count(),
            1
        );
    }

    #[test]
    fn a_forced_rebuild_still_uses_the_parse_cache() {
        // `--rebuild` bypasses reusing *recorded facts*. A parse of bytes that have not
        // changed is not a fact about the database, so there is nothing there to distrust.
        let dir = TempDir::new("build-forced-cache");
        let project = Project::initialize(dir.path()).unwrap();
        fs::write(dir.path().join("only.rs"), "fn only() {}\n").unwrap();

        let registry = crate::analyze::builtin_registry().unwrap();
        let options = crate::scan::ScanOptions::default();
        project.build(&registry, &options, false).unwrap();
        let forced = project.build(&registry, &options, true).unwrap();
        assert_eq!(forced.analyzed_files, 1);
        assert_eq!(forced.cached_parses, 1);
    }
}
