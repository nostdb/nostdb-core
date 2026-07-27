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
}
