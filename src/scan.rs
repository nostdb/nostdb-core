//! Enumerating and filtering the source a build will analyze.
//!
//! This is the second box in the pipeline in root PRD section 17.1, between resolving an
//! immutable snapshot and producing a `BuildPlan`. It answers one question — which files
//! are eligible, and for every file that is not, why — and it answers it without reading a
//! single byte more than it must.
//!
//! # Nothing is dropped silently
//!
//! Section 17.2 requires ignored, sensitive, unclassified, permission-denied, and
//! unsupported files to be recorded in build coverage. This goes further and records every
//! exclusion it makes, including size, binary content, and a symlink it did not follow. A
//! scanner that quietly omits a file reports a build that covered everything when it did
//! not, and the person reading that report has no way to tell.
//!
//! # A language is a string
//!
//! Classification here does not decide whether a file can be analyzed; it only names the
//! language. Whether an analyzer exists is [`crate::analysis::CapabilityRegistry`]'s
//! answer, and an unregistered language is [`crate::analysis::PrecisionClass::Unsupported`]
//! rather than an error, because unsupported text stays eligible for AI analysis. A file
//! whose language cannot be named at all is the only one that is `Unclassified`.

use crate::coverage::{SkipReason, SkippedSource};
use crate::evidence::ContentDigest;
use crate::ignore::{IgnoreFile, IgnoreStack};
use crate::locator::CanonicalSourceLocator;
use crate::text::NonEmptyText;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The ignore file Git reads.
pub const GIT_IGNORE_FILE: &str = ".gitignore";

/// The ignore file this product reads in addition.
pub const NOSTDB_IGNORE_FILE: &str = ".nostdbignore";

/// Default ceiling on a file this scanner will offer for analysis, in bytes.
///
/// A source file is not megabytes. Something that size is generated, vendored, or data,
/// and reading it costs more than the facts it yields.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// How much of a file is examined to decide whether it is binary.
const BINARY_SNIFF_BYTES: usize = 8192;

/// Directories pruned before any ignore rule is consulted.
///
/// Every one is a dependency, build, cache, or generated-output directory that section
/// 17.2 requires pruning. They are pruned rather than ignored because descending into
/// `node_modules` to discover it was excluded is the single largest cost a scanner can
/// pay, and none of them holds a fact about the project that is not derivable elsewhere.
pub const PRUNED_DIRECTORIES: [&str; 24] = [
    ".bundle",
    ".cache",
    ".git",
    ".gradle",
    ".hg",
    ".idea",
    ".mypy_cache",
    ".next",
    ".nostdb",
    ".nuxt",
    ".parcel-cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".terraform",
    ".tox",
    ".venv",
    "__pycache__",
    "bower_components",
    "node_modules",
    "target",
    "venv",
    "vendor",
    "zig-cache",
];

/// Whole file names treated as potentially sensitive.
const SENSITIVE_NAMES: [&str; 10] = [
    ".env",
    ".envrc",
    ".htpasswd",
    ".netrc",
    ".npmrc",
    ".pgpass",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_rsa",
];

/// Extensions treated as potentially sensitive.
const SENSITIVE_EXTENSIONS: [&str; 8] =
    ["asc", "gpg", "jks", "key", "keystore", "p12", "pem", "pfx"];

/// Extensions this build can name a language for.
///
/// Naming a language is not claiming to analyze it. The list exists so a report can say
/// "42 Python files, unsupported" rather than "42 unclassified files", which is the
/// difference between a gap somebody can act on and a number nobody can read.
const LANGUAGES: [(&str, &str); 42] = [
    ("bash", "shell"),
    ("c", "c"),
    ("cc", "cpp"),
    ("cjs", "javascript"),
    ("cpp", "cpp"),
    ("cs", "csharp"),
    ("css", "css"),
    ("cxx", "cpp"),
    ("go", "go"),
    ("h", "c"),
    ("hpp", "cpp"),
    ("hs", "haskell"),
    ("html", "html"),
    ("java", "java"),
    ("jl", "julia"),
    ("js", "javascript"),
    ("json", "json"),
    ("jsx", "javascript"),
    ("kt", "kotlin"),
    ("kts", "kotlin"),
    ("lua", "lua"),
    ("md", "markdown"),
    ("mjs", "javascript"),
    ("ml", "ocaml"),
    ("nost", "nost"),
    ("php", "php"),
    ("pl", "perl"),
    ("py", "python"),
    ("pyi", "python"),
    ("rb", "ruby"),
    ("rs", "rust"),
    ("scala", "scala"),
    ("sh", "shell"),
    ("sql", "sql"),
    ("swift", "swift"),
    ("toml", "toml"),
    ("ts", "typescript"),
    ("tsx", "typescript"),
    ("yaml", "yaml"),
    ("yml", "yaml"),
    ("zig", "zig"),
    ("zsh", "shell"),
];

/// Extensionless file names this build can still name a language for.
const NAMED_FILES: [(&str, &str); 6] = [
    ("CMakeLists.txt", "cmake"),
    ("Dockerfile", "dockerfile"),
    ("Gemfile", "ruby"),
    ("Makefile", "make"),
    ("Rakefile", "ruby"),
    ("justfile", "just"),
];

/// What a scan is allowed to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanOptions {
    /// Files larger than this are recorded as [`SkipReason::TooLarge`].
    pub max_file_bytes: u64,
    /// Whether to follow symbolic links. Off by default.
    pub follow_symlinks: bool,
    /// Whether `.gitignore` is honored.
    pub use_git_ignore: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            // Off by default, which section 17.2 requires. Following turns a tree into a
            // graph, and a link out of the project can pull in anything the user can read.
            follow_symlinks: false,
            use_git_ignore: true,
        }
    }
}

/// One file a build may analyze.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedFile {
    /// The path relative to the scan root, with `/` separators on every platform.
    pub path: String,
    /// The language this build names for it.
    pub language: String,
    /// Its size in bytes.
    pub bytes: u64,
    /// The digest of its contents, which is half of the structural parse cache key.
    pub digest: ContentDigest,
}

/// What one scan found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Scan {
    /// Files eligible for analysis, in path order.
    pub files: Vec<ScannedFile>,
    /// Everything excluded, and why, in path order.
    pub skipped: Vec<SkippedSource>,
}

impl Scan {
    /// How many paths the scan reached, whether or not they survived filtering.
    #[must_use]
    pub fn visited(&self) -> u64 {
        (self.files.len() + self.skipped.len()) as u64
    }

    /// How many were excluded for one reason.
    #[must_use]
    pub fn skipped_for(&self, reason: SkipReason) -> u64 {
        self.skipped
            .iter()
            .filter(|skipped| skipped.reason == reason)
            .count() as u64
    }

    /// The languages found, in name order.
    #[must_use]
    pub fn languages(&self) -> BTreeSet<&str> {
        self.files
            .iter()
            .map(|file| file.language.as_str())
            .collect()
    }
}

/// Why a scan could not start.
///
/// A failure *inside* the walk is not one of these: an unreadable directory becomes a
/// [`SkipReason::PermissionDenied`] record, because one unreadable subtree must not cost a
/// build every other subtree.
#[derive(Debug)]
pub enum ScanError {
    /// The root is not a directory that can be read.
    Unreadable {
        /// Which path.
        path: PathBuf,
        /// Why.
        error: io::Error,
    },
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, error } => {
                write!(formatter, "cannot scan {}: {error}", path.display())
            }
        }
    }
}

impl std::error::Error for ScanError {}

/// The language this build names for a path, or `None` when it can name none.
#[must_use]
pub fn language_of(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if let Some((_, language)) = NAMED_FILES.iter().find(|(known, _)| *known == name) {
        return Some(language);
    }
    // `rsplit_once` rather than `split_once`, so `.tar.gz` is a `gz` and `.env` — which
    // has no extension at all, only a leading dot — is not read as an `env` file.
    let (stem, extension) = name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    let extension = extension.to_ascii_lowercase();
    LANGUAGES
        .iter()
        .find(|(known, _)| *known == extension)
        .map(|(_, language)| *language)
}

/// Reports whether a path names something that commonly holds a secret.
///
/// Deliberately generous. A false positive costs one file's worth of analysis; a false
/// negative puts a private key in an AI packet, and section 17.2 requires these to be
/// identified *before* any dispatch rather than filtered at the boundary.
#[must_use]
pub fn is_sensitive(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lowered = name.to_ascii_lowercase();
    if SENSITIVE_NAMES.contains(&lowered.as_str()) {
        return true;
    }
    // `.env.local`, `.env.production`, and the rest of that family.
    if lowered.starts_with(".env.") || lowered.starts_with("credentials.") {
        return true;
    }
    lowered
        .rsplit_once('.')
        .is_some_and(|(_, extension)| SENSITIVE_EXTENSIONS.contains(&extension))
}

/// Reports whether `bytes` look like binary content.
///
/// A NUL byte in the first few kilobytes. It is the same test Git uses, it is what
/// distinguishes an executable from source in practice, and it costs one pass over a
/// buffer that has to be read anyway.
#[must_use]
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(BINARY_SNIFF_BYTES).any(|byte| *byte == 0)
}

/// Walks `root` and reports what a build may analyze.
///
/// `locator` names the source these paths belong to, so a coverage record stays meaningful
/// once several sources are federated.
///
/// # Errors
///
/// Returns [`ScanError::Unreadable`] when the root itself cannot be listed. Nothing below
/// the root produces an error: every failure becomes a recorded skip.
pub fn scan(
    root: &Path,
    locator: &CanonicalSourceLocator,
    options: &ScanOptions,
) -> Result<Scan, ScanError> {
    let mut walk = Walk {
        locator: locator.clone(),
        options: options.clone(),
        git: IgnoreStack::new(),
        nostdb: IgnoreStack::new(),
        visited: BTreeSet::new(),
        scan: Scan::default(),
    };
    fs::read_dir(root).map_err(|error| ScanError::Unreadable {
        path: root.to_path_buf(),
        error,
    })?;
    walk.directory(root, "");
    walk.scan.files.sort_by(|a, b| a.path.cmp(&b.path));
    walk.scan.skipped.sort_by(|a, b| {
        a.path
            .as_ref()
            .map(NonEmptyText::as_str)
            .cmp(&b.path.as_ref().map(NonEmptyText::as_str))
    });
    Ok(walk.scan)
}

/// One walk's state.
struct Walk {
    locator: CanonicalSourceLocator,
    options: ScanOptions,
    git: IgnoreStack,
    nostdb: IgnoreStack,
    /// Canonical directory paths already entered, which is how a symlink cycle is caught.
    visited: BTreeSet<PathBuf>,
    scan: Scan,
}

impl Walk {
    /// Records one exclusion.
    fn skip(&mut self, relative: &str, reason: SkipReason) {
        self.scan.skipped.push(SkippedSource {
            source: self.locator.clone(),
            path: NonEmptyText::new(relative).ok(),
            reason,
        });
    }

    /// Reports whether the ignore rules exclude `relative`.
    ///
    /// `.gitignore` is consulted first and its exclusion is final. A `.nostdbignore`
    /// negation therefore cannot re-include what Git excluded, which section 17.2 requires
    /// unless the user turns Git handling off — the one case where `use_git_ignore` is
    /// false and this consults only the second set.
    fn excluded(&self, relative: &str, is_dir: bool) -> bool {
        if self.options.use_git_ignore && self.git.excludes(relative, is_dir) {
            return true;
        }
        self.nostdb.excludes(relative, is_dir)
    }

    /// Reads the ignore files in `directory` and pushes them onto both stacks.
    ///
    /// Returns the depths to unwind to on the way back out.
    fn enter(&mut self, directory: &Path, relative: &str) -> (usize, usize) {
        let depths = (self.git.len(), self.nostdb.len());
        if self.options.use_git_ignore
            && let Ok(text) = fs::read_to_string(directory.join(GIT_IGNORE_FILE))
        {
            self.git.push(IgnoreFile::parse(&text, relative));
        }
        if let Ok(text) = fs::read_to_string(directory.join(NOSTDB_IGNORE_FILE)) {
            self.nostdb.push(IgnoreFile::parse(&text, relative));
        }
        depths
    }

    /// Walks one directory, refusing to enter one already on the path.
    ///
    /// The visited set is only maintained when links are followed. Without them a
    /// directory tree cannot contain a cycle, and canonicalizing every directory to prove
    /// that would be a syscall per directory paid for nothing.
    fn directory(&mut self, directory: &Path, relative: &str) {
        if !self.options.follow_symlinks {
            self.walk(directory, relative);
            return;
        }
        let Ok(canonical) = fs::canonicalize(directory) else {
            self.skip(relative, SkipReason::PermissionDenied);
            return;
        };
        if !self.visited.insert(canonical.clone()) {
            self.skip(relative, SkipReason::SymlinkCycle);
            return;
        }
        self.walk(directory, relative);
        self.visited.remove(&canonical);
    }

    /// Lists one directory and handles each entry.
    fn walk(&mut self, directory: &Path, relative: &str) {
        let Ok(entries) = fs::read_dir(directory) else {
            // Not fatal. One unreadable subtree must not cost the build every other one.
            self.skip(relative, SkipReason::PermissionDenied);
            return;
        };
        let (git_depth, nostdb_depth) = self.enter(directory, relative);

        // Sorted, so a scan of one tree produces the same order on every run and on every
        // platform. A build plan whose numbers move because a directory listing changed
        // order would be unreadable as a diff.
        let mut children: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect();
        children.sort();

        for child in children {
            let Some(name) = child.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let below = if relative.is_empty() {
                name.to_owned()
            } else {
                format!("{relative}/{name}")
            };
            self.entry(&child, &below, name);
        }

        self.git.truncate(git_depth);
        self.nostdb.truncate(nostdb_depth);
    }

    /// Handles one directory entry.
    fn entry(&mut self, path: &Path, relative: &str, name: &str) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            self.skip(relative, SkipReason::PermissionDenied);
            return;
        };

        if metadata.file_type().is_symlink() {
            if !self.options.follow_symlinks {
                self.skip(relative, SkipReason::Symlink);
                return;
            }
            let Ok(target) = fs::metadata(path) else {
                self.skip(relative, SkipReason::PermissionDenied);
                return;
            };
            if target.is_dir() {
                self.symlinked_directory(path, relative, name);
                return;
            }
            self.file(path, relative, target.len());
            return;
        }

        if metadata.is_dir() {
            if PRUNED_DIRECTORIES.contains(&name) {
                self.skip(relative, SkipReason::Ignored);
                return;
            }
            if self.excluded(relative, true) {
                // Recorded once, for the directory. Nothing under an excluded directory is
                // visited, so nothing under it can be re-included — which is the Git rule.
                self.skip(relative, SkipReason::Ignored);
                return;
            }
            self.directory(path, relative);
            return;
        }

        if metadata.is_file() {
            // A submodule's `.git` is a file holding a gitlink, not a directory, so the
            // prune list above never sees it. It is Git internals either way.
            if name == ".git" {
                self.skip(relative, SkipReason::Ignored);
                return;
            }
            self.file(path, relative, metadata.len());
        }
    }

    /// Enters a directory reached through a symlink.
    ///
    /// Cycle detection is [`Walk::directory`]'s, so a link to an ancestor is caught on the
    /// first hop rather than after going round once.
    fn symlinked_directory(&mut self, path: &Path, relative: &str, name: &str) {
        if PRUNED_DIRECTORIES.contains(&name) || self.excluded(relative, true) {
            self.skip(relative, SkipReason::Ignored);
            return;
        }
        self.directory(path, relative);
    }

    /// Classifies and, when eligible, records one file.
    fn file(&mut self, path: &Path, relative: &str, bytes: u64) {
        if self.excluded(relative, false) {
            self.skip(relative, SkipReason::Ignored);
            return;
        }
        // Before reading. A private key is withheld from analysis, and the point of
        // deciding here is that nothing downstream has to remember to.
        if is_sensitive(relative) {
            self.skip(relative, SkipReason::Sensitive);
            return;
        }
        // Before reading, from the metadata already in hand, so an enormous file costs
        // nothing to reject.
        if bytes > self.options.max_file_bytes {
            self.skip(relative, SkipReason::TooLarge);
            return;
        }
        let Some(language) = language_of(relative) else {
            self.skip(relative, SkipReason::Unclassified);
            return;
        };
        let Ok(contents) = fs::read(path) else {
            self.skip(relative, SkipReason::PermissionDenied);
            return;
        };
        if looks_binary(&contents) {
            self.skip(relative, SkipReason::Binary);
            return;
        }
        self.scan.files.push(ScannedFile {
            path: relative.to_owned(),
            language: language.to_owned(),
            bytes,
            digest: crate::sync::digest_bytes(&contents),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("nostdb-core-scan-{label}"));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).expect("temporary directory");
            Self(base)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, contents: impl AsRef<[u8]>) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parent directory");
            }
            fs::write(path, contents).expect("write");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn locator() -> CanonicalSourceLocator {
        CanonicalSourceLocator::new(".").expect("a valid locator")
    }

    fn run(dir: &TempDir, options: &ScanOptions) -> Scan {
        scan(dir.path(), &locator(), options).expect("the root is readable")
    }

    fn paths(scan: &Scan) -> Vec<&str> {
        scan.files.iter().map(|file| file.path.as_str()).collect()
    }

    fn reason(scan: &Scan, path: &str) -> Option<SkipReason> {
        scan.skipped
            .iter()
            .find(|skipped| skipped.path.as_ref().is_some_and(|p| p.as_str() == path))
            .map(|skipped| skipped.reason)
    }

    #[test]
    fn a_scan_finds_source_and_names_its_language() {
        let dir = TempDir::new("basic");
        dir.write("src/main.rs", "fn main() {}\n");
        dir.write("src/app.ts", "export const a = 1;\n");
        dir.write("README.md", "# hello\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["README.md", "src/app.ts", "src/main.rs"]);
        assert_eq!(
            found.languages().into_iter().collect::<Vec<_>>(),
            ["markdown", "rust", "typescript"]
        );
        assert_eq!(found.files[2].bytes, 13);
    }

    #[test]
    fn the_order_is_the_same_on_every_run() {
        // A plan whose numbers move because a directory listing changed order would be
        // unreadable as a diff, so the walk sorts rather than trusting the filesystem.
        let dir = TempDir::new("order");
        for name in ["z.rs", "a.rs", "m.rs", "b/c.rs", "b/a.rs"] {
            dir.write(name, "fn main() {}\n");
        }
        let first = run(&dir, &ScanOptions::default());
        let second = run(&dir, &ScanOptions::default());
        assert_eq!(first, second);
        assert_eq!(paths(&first), ["a.rs", "b/a.rs", "b/c.rs", "m.rs", "z.rs"]);
    }

    #[test]
    fn a_gitignore_excludes_and_the_exclusion_is_recorded() {
        let dir = TempDir::new("gitignore");
        dir.write(".gitignore", "*.log\ngenerated/\n");
        dir.write("keep.rs", "fn main() {}\n");
        dir.write("debug.log", "noise\n");
        dir.write("generated/out.rs", "fn main() {}\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["keep.rs"]);
        assert_eq!(reason(&found, "debug.log"), Some(SkipReason::Ignored));
        assert_eq!(reason(&found, "generated"), Some(SkipReason::Ignored));
        assert!(
            reason(&found, "generated/out.rs").is_none(),
            "an excluded directory is recorded once, not once per file inside it"
        );
    }

    #[test]
    fn a_nostdbignore_excludes_in_addition_to_gitignore() {
        let dir = TempDir::new("nostdbignore");
        dir.write(".gitignore", "*.log\n");
        dir.write(".nostdbignore", "fixtures/\n");
        dir.write("keep.rs", "fn main() {}\n");
        dir.write("debug.log", "noise\n");
        dir.write("fixtures/big.rs", "fn main() {}\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["keep.rs"]);
        assert_eq!(reason(&found, "fixtures"), Some(SkipReason::Ignored));
    }

    #[test]
    fn a_nostdbignore_cannot_re_include_what_gitignore_excluded() {
        // Section 17.2 states this outright. A file Git excludes is one the user believes
        // is not in the repository, and a second ignore file must not overrule that.
        let dir = TempDir::new("no-re-include");
        dir.write(".gitignore", "secret.rs\n");
        dir.write(".nostdbignore", "!secret.rs\n");
        dir.write("secret.rs", "fn main() {}\n");

        let found = run(&dir, &ScanOptions::default());
        assert!(paths(&found).is_empty(), "{:?}", found.files);
        assert_eq!(reason(&found, "secret.rs"), Some(SkipReason::Ignored));
    }

    #[test]
    fn turning_git_handling_off_is_what_lets_a_nostdbignore_decide_alone() {
        // The exception the contract names. With Git handling off there is no Git
        // exclusion to overrule, so the second file is the only one speaking.
        let dir = TempDir::new("git-off");
        dir.write(".gitignore", "secret.rs\n");
        dir.write(".nostdbignore", "!secret.rs\n");
        dir.write("secret.rs", "fn main() {}\n");

        let options = ScanOptions {
            use_git_ignore: false,
            ..ScanOptions::default()
        };
        let found = run(&dir, &options);
        assert_eq!(paths(&found), ["secret.rs"]);
    }

    #[test]
    fn known_dependency_and_build_directories_are_pruned() {
        let dir = TempDir::new("pruned");
        dir.write("src/main.rs", "fn main() {}\n");
        dir.write("node_modules/left-pad/index.js", "module.exports = 1;\n");
        dir.write("target/debug/build.rs", "fn main() {}\n");
        dir.write(".git/config", "[core]\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["src/main.rs"]);
        for pruned in [".git", "node_modules", "target"] {
            assert_eq!(
                reason(&found, pruned),
                Some(SkipReason::Ignored),
                "{pruned}"
            );
        }
    }

    #[test]
    fn a_submodule_gitlink_is_pruned_even_though_it_is_a_file() {
        // Found by scanning this workspace, which is a superproject. A submodule's `.git`
        // is a file holding a pointer, so the directory prune list never sees it and it
        // was landing in the report as unclassified.
        let dir = TempDir::new("gitlink");
        dir.write("child/.git", "gitdir: ../.git/modules/child\n");
        dir.write("child/src/main.rs", "fn main() {}\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["child/src/main.rs"]);
        assert_eq!(reason(&found, "child/.git"), Some(SkipReason::Ignored));
    }

    #[test]
    fn the_state_directory_is_never_analyzed() {
        // Analyzing `.nostdb` would feed the database's own bytes back into itself.
        let dir = TempDir::new("state-directory");
        dir.write(".nostdb/settings.json", "{\"settings_version\": 1}\n");
        dir.write("src/main.rs", "fn main() {}\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["src/main.rs"]);
        assert_eq!(reason(&found, ".nostdb"), Some(SkipReason::Ignored));
    }

    #[test]
    fn a_potentially_sensitive_file_is_withheld_before_it_is_read() {
        let dir = TempDir::new("sensitive");
        dir.write("src/main.rs", "fn main() {}\n");
        for name in [
            ".env",
            ".env.production",
            "deploy.pem",
            "server.key",
            "id_rsa",
            ".netrc",
        ] {
            dir.write(name, "nothing real\n");
        }

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["src/main.rs"]);
        assert_eq!(found.skipped_for(SkipReason::Sensitive), 6);
    }

    #[test]
    fn a_file_over_the_limit_is_recorded_rather_than_read() {
        let dir = TempDir::new("too-large");
        dir.write("small.rs", "fn main() {}\n");
        dir.write("large.rs", "x".repeat(4096));

        let options = ScanOptions {
            max_file_bytes: 1024,
            ..ScanOptions::default()
        };
        let found = run(&dir, &options);
        assert_eq!(paths(&found), ["small.rs"]);
        assert_eq!(reason(&found, "large.rs"), Some(SkipReason::TooLarge));
    }

    #[test]
    fn binary_content_is_detected_by_its_bytes_not_its_name() {
        let dir = TempDir::new("binary");
        dir.write("real.rs", "fn main() {}\n");
        dir.write("fake.rs", [0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01]);

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["real.rs"]);
        assert_eq!(reason(&found, "fake.rs"), Some(SkipReason::Binary));
    }

    #[test]
    fn a_file_whose_language_cannot_be_named_is_unclassified_rather_than_dropped() {
        let dir = TempDir::new("unclassified");
        dir.write("src/main.rs", "fn main() {}\n");
        dir.write("notes", "plain text\n");
        dir.write("data.frobnicate", "who knows\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["src/main.rs"]);
        assert_eq!(reason(&found, "notes"), Some(SkipReason::Unclassified));
        assert_eq!(
            reason(&found, "data.frobnicate"),
            Some(SkipReason::Unclassified)
        );
        assert_eq!(found.visited(), 3, "every path reached is accounted for");
    }

    #[test]
    fn an_extensionless_file_with_a_known_name_still_gets_a_language() {
        let dir = TempDir::new("named");
        dir.write("Makefile", "all:\n");
        dir.write("Dockerfile", "FROM scratch\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(paths(&found), ["Dockerfile", "Makefile"]);
        assert_eq!(
            found.languages().into_iter().collect::<Vec<_>>(),
            ["dockerfile", "make"]
        );
    }

    #[test]
    fn a_language_is_named_without_claiming_it_can_be_analyzed() {
        // The registry decides support. Naming the language is what turns "42 unclassified
        // files" into "42 Python files, unsupported", which is a gap somebody can act on.
        assert_eq!(language_of("a/b/main.rs"), Some("rust"));
        assert_eq!(language_of("script.PY"), Some("python"));
        assert_eq!(language_of("archive.tar.gz"), None);
        assert_eq!(language_of(".env"), None, "a dotfile has no extension");
        assert_eq!(language_of("Makefile"), Some("make"));
    }

    #[test]
    fn every_path_reached_is_either_a_file_or_a_recorded_skip() {
        // The whole point of the coverage record: a scanner that quietly omits something
        // reports a build that covered everything when it did not.
        let dir = TempDir::new("accounted");
        dir.write(".gitignore", "*.log\n");
        dir.write("src/main.rs", "fn main() {}\n");
        dir.write("app.log", "noise\n");
        dir.write("notes", "text\n");
        dir.write(".env", "SECRET=1\n");
        dir.write("node_modules/x/index.js", "1\n");

        let found = run(&dir, &ScanOptions::default());
        assert_eq!(found.files.len(), 1);
        // `.gitignore`, `app.log`, `notes`, `.env`, `node_modules`.
        assert_eq!(found.skipped.len(), 5, "{:?}", found.skipped);
        assert_eq!(found.visited(), 6);
    }

    #[test]
    fn a_symlink_is_not_followed_by_default_and_the_choice_is_recorded() {
        #[cfg(unix)]
        {
            let dir = TempDir::new("symlink-default");
            dir.write("real/main.rs", "fn main() {}\n");
            std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("linked"))
                .expect("symlink");

            let found = run(&dir, &ScanOptions::default());
            assert_eq!(paths(&found), ["real/main.rs"]);
            assert_eq!(
                reason(&found, "linked"),
                Some(SkipReason::Symlink),
                "a link that was not followed is a fact the report must carry"
            );
        }
    }

    #[test]
    fn following_symlinks_reaches_the_target_and_stops_at_a_cycle() {
        #[cfg(unix)]
        {
            let dir = TempDir::new("symlink-cycle");
            dir.write("real/main.rs", "fn main() {}\n");
            // A link inside `real` pointing back at `real`: following it without a visited
            // set walks forever.
            std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("real/loop"))
                .expect("symlink");

            let options = ScanOptions {
                follow_symlinks: true,
                ..ScanOptions::default()
            };
            let found = run(&dir, &options);
            assert_eq!(paths(&found), ["real/main.rs"]);
            assert_eq!(
                reason(&found, "real/loop"),
                Some(SkipReason::SymlinkCycle),
                "{:?}",
                found.skipped
            );
        }
    }

    #[test]
    fn an_unreadable_root_is_the_only_thing_that_fails_the_scan() {
        let dir = TempDir::new("unreadable-root");
        let absent = dir.path().join("not-here");
        assert!(matches!(
            scan(&absent, &locator(), &ScanOptions::default()),
            Err(ScanError::Unreadable { .. })
        ));
    }

    #[test]
    fn a_deeper_ignore_file_applies_only_to_its_own_subtree() {
        let dir = TempDir::new("nested-ignore");
        dir.write(".gitignore", "*.log\n");
        dir.write("keep/.gitignore", "!kept.log\n");
        dir.write("keep/kept.log", "wanted\n");
        dir.write("drop/dropped.log", "unwanted\n");
        dir.write("src/main.rs", "fn main() {}\n");

        let found = run(&dir, &ScanOptions::default());
        assert!(
            paths(&found).contains(&"src/main.rs"),
            "{:?}",
            paths(&found)
        );
        assert_eq!(
            reason(&found, "drop/dropped.log"),
            Some(SkipReason::Ignored)
        );
        assert_eq!(
            reason(&found, "keep/kept.log"),
            Some(SkipReason::Unclassified),
            "the deeper negation re-included it, so it is judged on its language instead"
        );
    }
}
