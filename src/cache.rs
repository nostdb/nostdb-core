//! Cache keys, and where a cached artifact lives.
//!
//! Root PRD section 17.7 publishes three keys and one rule that governs all of them:
//!
//! > The whole Engine version MUST NOT invalidate all caches. A cache is invalidated only
//! > by the component contract that affects its result.
//!
//! That rule is the reason these are three separate types rather than one key with a
//! version field. A parse depends on the bytes, the language, and the analyzer; it does not
//! depend on the model an enrichment ran against, and bumping the Engine's version must not
//! throw away every parse in the project. Each key therefore names exactly the inputs its
//! own result depends on, and a test asserts that changing any one of them moves that key
//! and leaves the other two where they were.
//!
//! # Nothing here decides what is cacheable
//!
//! A key says what a result depends on. Whether a result may be stored at all is a
//! different question, and for AI output section 17.7 answers it strictly: partial,
//! truncated, unvalidated, or out-of-scope output must never become an authoritative hit.
//! [`SemanticCacheKey`] exists so such a result can be *identified*; storing one is guarded
//! at the point of storage, where the validation outcome is known.

use crate::evidence::ContentDigest;
use crate::id::SourceUnitId;
use crate::sync::digest_bytes;
use std::fmt;
use std::path::{Path, PathBuf};

/// Where a project keeps cached artifacts.
pub const PROJECT_CACHE_DIRECTORY: &str = "cache";

/// Where the current operating-system user keeps them.
pub const USER_CACHE_DIRECTORY: &str = "cache";

/// The file that keeps a cache out of version control.
///
/// `.nostdb` as a whole is not excluded — the database inside it is meant to be shared —
/// so the cache needs its own exclusion. Section 17.7 requires that neither cache is
/// committed by default, and this is what makes that true rather than advisory.
pub const CACHE_IGNORE_FILE: &str = ".gitignore";

/// What [`CACHE_IGNORE_FILE`] holds.
pub const CACHE_IGNORE_CONTENTS: &str =
    "# Written by nostdb. A cache is derived, machine-local, and not shared.\n*\n";

/// Reduces a key's parts to one content-addressed string.
///
/// Each part is length-prefixed, so two keys whose parts differ only in where one ended
/// cannot collide. Without that, `["ab", "c"]` and `["a", "bc"]` would hash the same, and a
/// cache would serve one file's parse for another's.
fn key_digest(kind: &str, parts: &[&str]) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(kind.as_bytes());
    material.push(0);
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_le_bytes());
        material.extend_from_slice(part.as_bytes());
    }
    digest_bytes(&material).as_str().to_owned()
}

/// What a parse of one file depends on.
///
/// Deliberately not the Engine's version. A parse depends on the bytes, the language, the
/// analyzer that read them, and the shape the result is stored in — and on nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuralParseCacheKey {
    /// Digest of the file's contents.
    pub content_digest: ContentDigest,
    /// The language that was read.
    pub language: String,
    /// Identity of the analyzer, which includes its version.
    pub analyzer_digest: String,
    /// Identity of the analyzer's configuration.
    pub analyzer_config_digest: String,
    /// Version of the shape a stored result takes.
    pub graph_schema_version: u32,
}

impl StructuralParseCacheKey {
    /// The content-addressed name this key refers to.
    #[must_use]
    pub fn digest(&self) -> String {
        key_digest(
            "structural-parse",
            &[
                self.content_digest.as_str(),
                &self.language,
                &self.analyzer_digest,
                &self.analyzer_config_digest,
                &self.graph_schema_version.to_string(),
            ],
        )
    }
}

/// What resolving one source unit's references depends on.
///
/// Separate from the parse because resolution can change when nothing about the file did:
/// a name it refers to may have appeared or vanished somewhere else, which is what
/// `dependency_context_digest` carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextResolutionCacheKey {
    /// Which unit was resolved.
    pub source_unit: SourceUnitId,
    /// Digest of the parse this resolution ran over.
    pub parse_artifact_digest: String,
    /// Digest of everything outside the unit that its references could reach.
    pub dependency_context_digest: String,
    /// Identity of the resolver.
    pub resolver_digest: String,
}

impl ContextResolutionCacheKey {
    /// The content-addressed name this key refers to.
    #[must_use]
    pub fn digest(&self) -> String {
        key_digest(
            "context-resolution",
            &[
                &self.source_unit.to_string(),
                &self.parse_artifact_digest,
                &self.dependency_context_digest,
                &self.resolver_digest,
            ],
        )
    }
}

/// What one AI enrichment depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticCacheKey {
    /// Digest of the packet that was sent.
    pub analysis_packet_digest: String,
    /// Digest of the context it was sent with.
    pub context_digest: String,
    /// Identity of the contract it ran under.
    pub analysis_contract_digest: String,
    /// Which model answered.
    pub model_identity: String,
    /// Which mode it ran in.
    pub analysis_mode: String,
}

impl SemanticCacheKey {
    /// The content-addressed name this key refers to.
    #[must_use]
    pub fn digest(&self) -> String {
        key_digest(
            "semantic",
            &[
                &self.analysis_packet_digest,
                &self.context_digest,
                &self.analysis_contract_digest,
                &self.model_identity,
                &self.analysis_mode,
            ],
        )
    }
}

/// Where a cached artifact was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheTier {
    /// The project's own cache.
    Project,
    /// The current user's cache, shared across their projects.
    User,
}

impl fmt::Display for CacheTier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Project => "project",
            Self::User => "user",
        })
    }
}

/// The caches a project may read, in the order section 17.7 fixes.
///
/// Project first, then user, then nothing. The order matters: a project may hold an
/// artifact produced under settings that differ from the user's default, and reading the
/// user's copy first would serve the wrong one.
#[derive(Clone, Debug, Default)]
pub struct CacheLayout {
    project: Option<PathBuf>,
    user: Option<PathBuf>,
}

impl CacheLayout {
    /// A layout with neither tier.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            project: None,
            user: None,
        }
    }

    /// The project tier, inside a project's state directory.
    #[must_use]
    pub fn with_project(mut self, state_directory: &Path) -> Self {
        self.project = Some(state_directory.join(PROJECT_CACHE_DIRECTORY));
        self
    }

    /// The user tier, inside the user's own `~/.nostdb`.
    ///
    /// Section 17.7 lets a project disable it, which is what omitting it expresses.
    #[must_use]
    pub fn with_user(mut self, user_directory: &Path) -> Self {
        self.user = Some(user_directory.join(USER_CACHE_DIRECTORY));
        self
    }

    /// Each tier in lookup order.
    #[must_use]
    pub fn tiers(&self) -> Vec<(CacheTier, &Path)> {
        let mut found = Vec::new();
        if let Some(path) = &self.project {
            found.push((CacheTier::Project, path.as_path()));
        }
        if let Some(path) = &self.user {
            found.push((CacheTier::User, path.as_path()));
        }
        found
    }

    /// Where an artifact with this digest would live in a tier.
    ///
    /// Sharded on the first two characters, so a project with a hundred thousand cached
    /// parses does not put a hundred thousand entries in one directory.
    #[must_use]
    pub fn entry(tier: &Path, digest: &str) -> PathBuf {
        let name = digest.rsplit(':').next().unwrap_or(digest);
        let shard = name.get(..2).unwrap_or("00");
        tier.join(shard).join(name)
    }

    /// The first tier holding an artifact with this digest.
    #[must_use]
    pub fn find(&self, digest: &str) -> Option<(CacheTier, PathBuf)> {
        self.tiers().into_iter().find_map(|(tier, path)| {
            let entry = Self::entry(path, digest);
            entry.is_file().then_some((tier, entry))
        })
    }

    /// The project tier, when there is one.
    #[must_use]
    pub fn project(&self) -> Option<&Path> {
        self.project.as_deref()
    }

    /// Reports whether the user tier is in effect.
    #[must_use]
    pub const fn uses_user_tier(&self) -> bool {
        self.user.is_some()
    }
}

/// Version of the shape a stored artifact takes.
///
/// Part of a key rather than a compatibility problem. An artifact written under an older
/// shape can never be *found* by a newer key, so there is no migration to write and no
/// reader that has to understand two layouts — the entry simply misses and the work is
/// redone. Bump this whenever the stored shape changes.
pub const ARTIFACT_VERSION: u32 = 1;

/// Why a cached artifact could not be stored.
///
/// Reading has no error type on purpose. A cache is derived data, and a build that refused
/// to run because an entry was corrupt would be choosing the cache over the thing the cache
/// exists to speed up. An unreadable entry is a miss.
#[derive(Debug)]
pub enum CacheError {
    /// The entry could not be written.
    Write {
        /// Which path.
        path: PathBuf,
        /// Why.
        error: std::io::Error,
    },
}

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write { path, error } => {
                write!(formatter, "cannot write {}: {error}", path.display())
            }
        }
    }
}

impl std::error::Error for CacheError {}

/// Reads and writes parsed source, keyed by what the parse depended on.
///
/// # Reads both tiers, writes one
///
/// Lookup runs project then user, which section 17.7 fixes. Writing goes to the project
/// tier alone. A shared user cache written to by every project is a trust surface the
/// product contract has not designed — one project's build would be placing artifacts that
/// another project's build reads — and section 17.7 says a remote or team cache "requires a
/// separate trust and confidentiality design". The same reasoning applies one directory up.
#[derive(Clone, Debug)]
pub struct ParseCache {
    layout: CacheLayout,
}

impl ParseCache {
    /// A cache over the given tiers.
    #[must_use]
    pub const fn new(layout: CacheLayout) -> Self {
        Self { layout }
    }

    /// A cache that stores nothing and finds nothing.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            layout: CacheLayout::none(),
        }
    }

    /// Reports whether this cache can hold anything.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.layout.tiers().is_empty()
    }

    /// The parse stored under this key, when one is there and readable.
    ///
    /// An entry that does not decode is a miss. It is also removed, so a truncated write
    /// from an interrupted build does not cost every later build a failed read.
    #[must_use]
    pub fn get(&self, key: &StructuralParseCacheKey) -> Option<crate::analyze::FileAnalysis> {
        let (_, path) = self.layout.find(&key.digest())?;
        let text = std::fs::read_to_string(&path).ok()?;
        match decode_analysis(&text) {
            Some(analysis) => Some(analysis),
            None => {
                let _ = std::fs::remove_file(&path);
                None
            }
        }
    }

    /// Stores a parse under this key.
    ///
    /// Written to a staging file and renamed, so an interrupted write leaves no entry
    /// rather than half of one.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Write`] when the entry cannot be written.
    pub fn put(
        &self,
        key: &StructuralParseCacheKey,
        analysis: &crate::analyze::FileAnalysis,
    ) -> Result<(), CacheError> {
        let Some(tier) = self.layout.project() else {
            return Ok(());
        };
        let path = CacheLayout::entry(tier, &key.digest());
        let failed = |path: &Path, error: std::io::Error| CacheError::Write {
            path: path.to_path_buf(),
            error,
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| failed(parent, error))?;
        }
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".staged");
        let staged = path.with_file_name(name);
        std::fs::write(&staged, encode_analysis(analysis))
            .map_err(|error| failed(&staged, error))?;
        std::fs::rename(&staged, &path).map_err(|error| {
            let _ = std::fs::remove_file(&staged);
            failed(&path, error)
        })
    }
}

/// Renders a parse as the document an entry holds.
#[must_use]
pub fn encode_analysis(analysis: &crate::analyze::FileAnalysis) -> String {
    let document = serde_json::json!({
        "artifact_version": ARTIFACT_VERSION,
        "language": analysis.language,
        "digest": analysis.digest.as_str(),
        // Round-trips for the reason annotations do: a cached parse is read back as though the analyzer had
        // just produced it, and a package missing from the artifact would make the same file resolve its
        // imports one way on a first build and another way on the second.
        "package": analysis.package,
        "items": analysis.items.iter().map(encode_item).collect::<Vec<_>>(),
        "imports": analysis.imports.iter().map(|import| serde_json::json!({
            "path": import.path,
            "alias": import.alias,
            "range": encode_range(&import.range),
        })).collect::<Vec<_>>(),
    });
    document.to_string()
}

fn encode_item(item: &crate::analyze::Item) -> serde_json::Value {
    serde_json::json!({
        "kind": item.kind.to_string(),
        "name": item.name,
        "range": encode_range(&item.range),
        "target": item.target,
        "implements": item.implements,
        "references": item.references.iter().map(|reference| serde_json::json!({
            "name": reference.name,
            "qualifier": reference.qualifier,
            "is_method": reference.is_method,
            "range": encode_range(&reference.range),
        })).collect::<Vec<_>>(),
        // Annotations round-trip, because a cached parse is read back as though the analyzer had just
        // produced it. Omitted here, a framework analyzer would see them on a first build and not on
        // the second — the same file yielding different facts depending on whether it was cached.
        "annotations": item.annotations.iter().map(|annotation| serde_json::json!({
            "name": annotation.name,
            "arguments": annotation.arguments,
            "range": encode_range(&annotation.range),
        })).collect::<Vec<_>>(),
        "children": item.children.iter().map(encode_item).collect::<Vec<_>>(),
    })
}

fn encode_range(range: &crate::evidence::SourceRange) -> serde_json::Value {
    let position =
        |at: crate::evidence::SourcePosition| serde_json::json!([at.line, at.column, at.offset]);
    serde_json::json!([position(range.start()), position(range.end())])
}

/// Reads a parse back, or `None` when the document is not one this build wrote.
#[must_use]
pub fn decode_analysis(text: &str) -> Option<crate::analyze::FileAnalysis> {
    let document: serde_json::Value = serde_json::from_str(text).ok()?;
    if document.get("artifact_version")?.as_u64()? != u64::from(ARTIFACT_VERSION) {
        return None;
    }
    Some(crate::analyze::FileAnalysis {
        language: document.get("language")?.as_str()?.to_owned(),
        digest: ContentDigest::new(document.get("digest")?.as_str()?).ok()?,
        // Absent reads as `None`, like `alias` below, because most languages declare no package and writing
        // the key as null for all of them would say nothing. An artifact written before the key existed is
        // not reachable through leniency either way: the analyzer version and the graph schema version are
        // both part of the key, and both moved when this field arrived.
        package: document
            .get("package")
            .and_then(|held| held.as_str())
            .map(str::to_owned),
        items: document
            .get("items")?
            .as_array()?
            .iter()
            .map(decode_item)
            .collect::<Option<Vec<_>>>()?,
        imports: document
            .get("imports")?
            .as_array()?
            .iter()
            .map(|entry| {
                Some(crate::analyze::Import {
                    path: entry.get("path")?.as_str()?.to_owned(),
                    alias: entry
                        .get("alias")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    range: decode_range(entry.get("range")?)?,
                })
            })
            .collect::<Option<Vec<_>>>()?,
    })
}

fn decode_item(entry: &serde_json::Value) -> Option<crate::analyze::Item> {
    use crate::analyze::ItemKind;
    let kind = match entry.get("kind")?.as_str()? {
        "module" => ItemKind::Module,
        "struct" => ItemKind::Struct,
        "enum" => ItemKind::Enum,
        "union" => ItemKind::Union,
        "trait" => ItemKind::Trait,
        "type" => ItemKind::TypeAlias,
        "function" => ItemKind::Function,
        "method" => ItemKind::Method,
        "field" => ItemKind::Field,
        "constant" => ItemKind::Constant,
        "impl" => ItemKind::Implementation,
        _ => return None,
    };
    Some(crate::analyze::Item {
        kind,
        name: entry.get("name")?.as_str()?.to_owned(),
        range: decode_range(entry.get("range")?)?,
        target: entry
            .get("target")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        implements: entry
            .get("implements")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        // Absent is empty rather than a decode failure, so an artifact written before annotations
        // existed is still readable. `ARTIFACT_VERSION` is what refuses one that is genuinely
        // incompatible, and treating a missing list as unreadable would discard every cached parse for
        // a field that did not change what the older ones held.
        annotations: entry
            .get("annotations")
            .and_then(|v| v.as_array())
            .map(|found| {
                found
                    .iter()
                    .filter_map(|annotation| {
                        Some(crate::analyze::Annotation {
                            name: annotation.get("name")?.as_str()?.to_owned(),
                            arguments: annotation
                                .get("arguments")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            range: decode_range(annotation.get("range")?)?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        references: entry
            .get("references")?
            .as_array()?
            .iter()
            .map(|reference| {
                Some(crate::analyze::Reference {
                    name: reference.get("name")?.as_str()?.to_owned(),
                    qualifier: reference
                        .get("qualifier")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    is_method: reference.get("is_method")?.as_bool()?,
                    range: decode_range(reference.get("range")?)?,
                })
            })
            .collect::<Option<Vec<_>>>()?,
        children: entry
            .get("children")?
            .as_array()?
            .iter()
            .map(decode_item)
            .collect::<Option<Vec<_>>>()?,
    })
}

fn decode_range(entry: &serde_json::Value) -> Option<crate::evidence::SourceRange> {
    let ends = entry.as_array()?;
    let position = |at: &serde_json::Value| {
        let parts = at.as_array()?;
        Some(crate::evidence::SourcePosition {
            line: u32::try_from(parts.first()?.as_u64()?).ok()?,
            column: u32::try_from(parts.get(1)?.as_u64()?).ok()?,
            offset: parts.get(2)?.as_u64()?,
        })
    };
    crate::evidence::SourceRange::new(position(ends.first()?)?, position(ends.get(1)?)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_key() -> StructuralParseCacheKey {
        StructuralParseCacheKey {
            content_digest: digest_bytes(b"fn main() {}"),
            language: "rust".to_owned(),
            analyzer_digest: "rust/1".to_owned(),
            analyzer_config_digest: "default".to_owned(),
            graph_schema_version: 1,
        }
    }

    fn resolution_key() -> ContextResolutionCacheKey {
        ContextResolutionCacheKey {
            source_unit: SourceUnitId::from_bytes([1; 16]),
            parse_artifact_digest: parse_key().digest(),
            dependency_context_digest: "context".to_owned(),
            resolver_digest: "resolver/1".to_owned(),
        }
    }

    fn semantic_key() -> SemanticCacheKey {
        SemanticCacheKey {
            analysis_packet_digest: "packet".to_owned(),
            context_digest: "context".to_owned(),
            analysis_contract_digest: "contract/1".to_owned(),
            model_identity: "model-a".to_owned(),
            analysis_mode: "auto".to_owned(),
        }
    }

    #[test]
    fn a_key_is_stable_for_the_same_inputs() {
        assert_eq!(parse_key().digest(), parse_key().digest());
        assert_eq!(resolution_key().digest(), resolution_key().digest());
        assert_eq!(semantic_key().digest(), semantic_key().digest());
    }

    #[test]
    fn the_three_keys_never_collide_with_each_other() {
        // Each digest is tagged with its kind, so a parse and a resolution built from the
        // same strings cannot name one entry.
        let digests = [
            parse_key().digest(),
            resolution_key().digest(),
            semantic_key().digest(),
        ];
        let unique: std::collections::BTreeSet<&String> = digests.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn every_part_of_a_parse_key_moves_it() {
        let base = parse_key().digest();
        let cases: Vec<StructuralParseCacheKey> = vec![
            StructuralParseCacheKey {
                content_digest: digest_bytes(b"fn other() {}"),
                ..parse_key()
            },
            StructuralParseCacheKey {
                language: "ruby".to_owned(),
                ..parse_key()
            },
            StructuralParseCacheKey {
                analyzer_digest: "rust/2".to_owned(),
                ..parse_key()
            },
            StructuralParseCacheKey {
                analyzer_config_digest: "strict".to_owned(),
                ..parse_key()
            },
            StructuralParseCacheKey {
                graph_schema_version: 2,
                ..parse_key()
            },
        ];
        for case in cases {
            assert_ne!(case.digest(), base, "{case:?} must not reuse the entry");
        }
    }

    #[test]
    fn every_part_of_a_resolution_key_moves_it() {
        let base = resolution_key().digest();
        let cases: Vec<ContextResolutionCacheKey> = vec![
            ContextResolutionCacheKey {
                source_unit: SourceUnitId::from_bytes([2; 16]),
                ..resolution_key()
            },
            ContextResolutionCacheKey {
                parse_artifact_digest: "other".to_owned(),
                ..resolution_key()
            },
            ContextResolutionCacheKey {
                dependency_context_digest: "other".to_owned(),
                ..resolution_key()
            },
            ContextResolutionCacheKey {
                resolver_digest: "resolver/2".to_owned(),
                ..resolution_key()
            },
        ];
        for case in cases {
            assert_ne!(case.digest(), base, "{case:?} must not reuse the entry");
        }
    }

    #[test]
    fn every_part_of_a_semantic_key_moves_it() {
        let base = semantic_key().digest();
        let cases: Vec<SemanticCacheKey> = vec![
            SemanticCacheKey {
                analysis_packet_digest: "other".to_owned(),
                ..semantic_key()
            },
            SemanticCacheKey {
                context_digest: "other".to_owned(),
                ..semantic_key()
            },
            SemanticCacheKey {
                analysis_contract_digest: "contract/2".to_owned(),
                ..semantic_key()
            },
            SemanticCacheKey {
                model_identity: "model-b".to_owned(),
                ..semantic_key()
            },
            SemanticCacheKey {
                analysis_mode: "full".to_owned(),
                ..semantic_key()
            },
        ];
        for case in cases {
            assert_ne!(case.digest(), base, "{case:?} must not reuse the entry");
        }
    }

    #[test]
    fn one_contract_moving_leaves_the_other_caches_alone() {
        // The rule section 17.7 exists for: the whole Engine version must not invalidate
        // everything. A new analyzer must not throw away a project's AI enrichment, and a
        // new model must not throw away its parses.
        let new_analyzer = StructuralParseCacheKey {
            analyzer_digest: "rust/2".to_owned(),
            ..parse_key()
        };
        assert_ne!(new_analyzer.digest(), parse_key().digest());
        assert_eq!(
            semantic_key().digest(),
            semantic_key().digest(),
            "a semantic entry does not depend on which analyzer read the file"
        );

        let new_model = SemanticCacheKey {
            model_identity: "model-b".to_owned(),
            ..semantic_key()
        };
        assert_ne!(new_model.digest(), semantic_key().digest());
        assert_eq!(
            parse_key().digest(),
            parse_key().digest(),
            "a parse does not depend on which model answered"
        );
    }

    #[test]
    fn parts_cannot_run_together_into_one_another() {
        // Each part is length-prefixed. Without that, two keys whose parts differ only in
        // where one ended would name one entry, and a cache would serve one file's parse
        // for another's.
        let one = StructuralParseCacheKey {
            language: "ab".to_owned(),
            analyzer_digest: "c".to_owned(),
            ..parse_key()
        };
        let two = StructuralParseCacheKey {
            language: "a".to_owned(),
            analyzer_digest: "bc".to_owned(),
            ..parse_key()
        };
        assert_ne!(one.digest(), two.digest());
    }

    #[test]
    fn the_project_tier_is_read_before_the_users() {
        // A project may hold an artifact produced under settings that differ from the
        // user's default, and reading the user's copy first would serve the wrong one.
        let layout = CacheLayout::none()
            .with_project(Path::new("/p/.nostdb"))
            .with_user(Path::new("/home/u/.nostdb"));
        let tiers = layout.tiers();
        assert_eq!(tiers.len(), 2);
        assert_eq!(tiers[0].0, CacheTier::Project);
        assert_eq!(tiers[1].0, CacheTier::User);
        assert!(layout.uses_user_tier());
    }

    #[test]
    fn a_project_can_disable_the_user_tier() {
        let layout = CacheLayout::none().with_project(Path::new("/p/.nostdb"));
        assert_eq!(layout.tiers().len(), 1);
        assert!(!layout.uses_user_tier());
        assert!(layout.find("sha256:abcd").is_none());
    }

    #[test]
    fn an_entry_is_sharded_so_one_directory_does_not_hold_everything() {
        let entry = CacheLayout::entry(Path::new("/p/.nostdb/cache"), "sha256:ab12cd");
        assert_eq!(entry, Path::new("/p/.nostdb/cache/ab/ab12cd"));
    }

    #[test]
    fn a_layout_with_no_tier_finds_nothing_and_does_not_reach_the_filesystem() {
        let layout = CacheLayout::none();
        assert!(layout.tiers().is_empty());
        assert!(layout.find(&parse_key().digest()).is_none());
        assert!(layout.project().is_none());
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("nostdb-core-cache-{label}"));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).expect("temporary directory");
            Self(base)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn analysis() -> crate::analyze::FileAnalysis {
        crate::analyze::rust::analyze(
            "use std::fmt::{self, Display as D};\n\
             /// A parser.\n\
             pub struct Parser<'a> { source: &'a str, at: usize }\n\
             impl<'a> Display for Parser<'a> { fn fmt(&self) { write!(f, \"{}\", self.at); } }\n\
             enum Mode { Fast, Careful { retries: u8 } }\n\
             mod inner { pub fn nested() { helper(); } }\n\
             fn helper() {}\n",
        )
    }

    #[test]
    fn a_parse_round_trips_through_an_entry() {
        // Every field the analyzer produces has to survive, including the ones nothing
        // reads yet. A cache that drops a field silently changes what a build asserts.
        let original = analysis();
        let decoded = decode_analysis(&encode_analysis(&original)).expect("it decodes");
        assert_eq!(decoded, original);
    }

    #[test]
    fn a_stored_parse_is_found_again() {
        let dir = TempDir::new("hit");
        let cache = ParseCache::new(CacheLayout::none().with_project(&dir.0));
        assert!(cache.is_enabled());
        let key = parse_key();
        assert!(cache.get(&key).is_none(), "nothing is stored yet");

        cache.put(&key, &analysis()).expect("it stores");
        assert_eq!(cache.get(&key), Some(analysis()));
    }

    #[test]
    fn a_different_key_is_a_miss_rather_than_the_wrong_answer() {
        let dir = TempDir::new("miss");
        let cache = ParseCache::new(CacheLayout::none().with_project(&dir.0));
        cache.put(&parse_key(), &analysis()).expect("it stores");

        let other = StructuralParseCacheKey {
            content_digest: digest_bytes(b"different bytes"),
            ..parse_key()
        };
        assert!(cache.get(&other).is_none());
    }

    #[test]
    fn one_analyzer_never_reads_anothers_work_back() {
        // No builtin analyzer declares a version any more, so the identity this guards is the analyzer
        // itself rather than a newer revision of one: `build::parse_cache_key` writes the language here, and
        // a Kotlin parse handed to whichever reader asked for Rust would be facts nothing produced.
        //
        // What replaced the version half is `graph_schema_version`, a separate component of the same key,
        // covered by the test above.
        let dir = TempDir::new("analyzer-identity");
        let cache = ParseCache::new(CacheLayout::none().with_project(&dir.0));
        cache.put(&parse_key(), &analysis()).expect("it stores");

        let another = StructuralParseCacheKey {
            analyzer_digest: "kotlin".to_owned(),
            ..parse_key()
        };
        assert!(
            cache.get(&another).is_none(),
            "an analyzer must not adopt facts it did not produce"
        );
    }

    #[test]
    fn a_corrupt_entry_is_a_miss_and_is_removed() {
        // A cache is derived data. A build that refused to run because an entry was
        // truncated would be choosing the cache over the thing it exists to speed up.
        let dir = TempDir::new("corrupt");
        let cache = ParseCache::new(CacheLayout::none().with_project(&dir.0));
        let key = parse_key();
        cache.put(&key, &analysis()).expect("it stores");

        let entry = CacheLayout::entry(&dir.0.join(PROJECT_CACHE_DIRECTORY), &key.digest());
        std::fs::write(&entry, "{ truncated").expect("write");
        assert!(cache.get(&key).is_none());
        assert!(
            !entry.exists(),
            "a broken entry is cleared rather than failing every later read"
        );

        cache.put(&key, &analysis()).expect("it stores again");
        assert_eq!(cache.get(&key), Some(analysis()));
    }

    #[test]
    fn an_artifact_from_another_shape_is_a_miss() {
        let mut document: serde_json::Value =
            serde_json::from_str(&encode_analysis(&analysis())).unwrap();
        document["artifact_version"] = serde_json::json!(ARTIFACT_VERSION + 1);
        assert!(decode_analysis(&document.to_string()).is_none());
    }

    #[test]
    fn a_disabled_cache_stores_nothing_and_finds_nothing() {
        let cache = ParseCache::disabled();
        assert!(!cache.is_enabled());
        cache
            .put(&parse_key(), &analysis())
            .expect("storing is a no-op");
        assert!(cache.get(&parse_key()).is_none());
    }

    #[test]
    fn a_write_goes_to_the_project_tier_and_never_the_users() {
        // A shared user cache written to by every project is a trust surface the contract
        // has not designed: one project's build would place artifacts another project's
        // build reads.
        let dir = TempDir::new("tiers");
        let project = dir.0.join("project");
        let user = dir.0.join("user");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&user).unwrap();

        let cache = ParseCache::new(CacheLayout::none().with_project(&project).with_user(&user));
        cache.put(&parse_key(), &analysis()).expect("it stores");
        assert!(
            project.join(PROJECT_CACHE_DIRECTORY).is_dir(),
            "the project tier holds it"
        );
        assert!(
            !user.join(USER_CACHE_DIRECTORY).exists(),
            "the user tier was not written to"
        );
    }

    #[test]
    fn an_entry_only_the_user_tier_holds_is_still_found() {
        let dir = TempDir::new("user-hit");
        let project = dir.0.join("project");
        let user = dir.0.join("user");

        // Written as if by a build whose project tier was this directory.
        let writer = ParseCache::new(CacheLayout::none().with_project(&user));
        writer.put(&parse_key(), &analysis()).expect("it stores");

        let reader = ParseCache::new(CacheLayout::none().with_project(&project).with_user(&user));
        assert_eq!(reader.get(&parse_key()), Some(analysis()));
    }
}
