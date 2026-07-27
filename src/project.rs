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
use crate::settings::{Settings, SettingsDocument, SettingsError};
use crate::storage::{Database, StorageError};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The directory a configured project keeps its state in.
pub const STATE_DIRECTORY: &str = ".nostdb";

/// The settings file whose presence marks a configured project.
pub const SETTINGS_FILE: &str = "settings.json";

/// The canonical human-readable file, when materialization is enabled.
pub const NOST_FILE: &str = "root.nost";

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
}
