//! Project and global settings.
//!
//! Settings hold operational configuration: where the database lives, whether the
//! human-readable representation is materialized, what an analysis run may spend, how a
//! declared link is reached, and which plugin serves an action. The contract is
//! `settings_version` in `nostdb-spec`.
//!
//! # Why this is in the Engine
//!
//! Both the command surface and the daemon read settings, and they must agree. The root
//! contract's rule is that shared behavior calls a public Core API rather than being
//! implemented twice, so it is implemented here once.
//!
//! # Settings are not the graph
//!
//! A link is declared semantically in `.nostdb`. Settings mirror the same link only to
//! carry what a graph file must not hold: a credential reference, a timeout, a refresh
//! policy. An alias is part of the semantic declaration, so an aliased entry is refused
//! rather than ignored, and no secret is present at all.
//!
//! # Two documents, then defaults
//!
//! Parsing keeps every field optional, because the merge is by *defined field*: a value
//! present in the project document replaces the global value for that field alone. A
//! parsed document that had already applied defaults could not express the difference
//! between "absent" and "set to the default", and the merge needs it.

use crate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::text::NonEmptyText;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;

/// The settings versions this build reads.
pub const SUPPORTED_VERSIONS: [u64; 1] = [1];

/// Default database file name, relative to the `.nostdb` directory.
pub const DEFAULT_DATABASE_PATH: &str = "root.nostdb";

/// Default maximum link traversal depth.
pub const DEFAULT_MAX_LINK_DEPTH: u64 = 16;

/// Default maximum number of linked databases opened for one query.
pub const DEFAULT_MAX_LINK_DATABASES: u64 = 256;

/// Default timeout, in milliseconds, for opening one linked source.
pub const DEFAULT_LINK_OPEN_TIMEOUT_MS: u64 = 10_000;

/// Why a settings document was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsError {
    /// The text is not JSON at all.
    NotJson {
        /// What the JSON reader said.
        reason: String,
    },
    /// A field is missing, has the wrong type, or holds a value with no valid reading.
    Invalid {
        /// The field, in dotted form, so a message can name it.
        field: String,
        /// Why it was refused.
        reason: String,
    },
    /// The document names a version this build cannot read.
    UnsupportedVersion {
        /// The version found.
        found: u64,
    },
}

impl SettingsError {
    /// The stable diagnostic code for this refusal.
    #[must_use]
    pub const fn code(&self) -> DiagnosticCode {
        match self {
            Self::NotJson { .. } | Self::Invalid { .. } => DiagnosticCode::SettingsInvalid,
            Self::UnsupportedVersion { .. } => DiagnosticCode::SettingsVersionUnsupported,
        }
    }

    /// Renders this refusal as a diagnostic.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic {
        let code = self.code();
        Diagnostic {
            code,
            severity: code.default_severity(),
            message: NonEmptyText::new(self.to_string())
                .unwrap_or_else(|_| NonEmptyText::literal("a settings document was refused")),
            source: None,
            range: None,
            details: Vec::new(),
        }
    }
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson { reason } => write!(formatter, "settings are not valid JSON: {reason}"),
            Self::Invalid { field, reason } => write!(formatter, "{field}: {reason}"),
            Self::UnsupportedVersion { found } => write!(
                formatter,
                "settings_version {found} is not supported; this build supports \
                 {SUPPORTED_VERSIONS:?}"
            ),
        }
    }
}

impl std::error::Error for SettingsError {}

fn invalid(field: &str, reason: impl Into<String>) -> SettingsError {
    SettingsError::Invalid {
        field: field.to_owned(),
        reason: reason.into(),
    }
}

/// How much AI enrichment an analysis run may perform.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AiMode {
    /// No AI work at all.
    Off,
    /// Enrichment within the configured budget.
    #[default]
    Auto,
    /// Enrichment is required rather than optional.
    Full,
}

/// What to do when an analysis budget is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BudgetAction {
    /// Ask the user.
    #[default]
    Ask,
    /// Stop the run.
    Stop,
    /// Finish without further AI work.
    ContinueWithoutAi,
}

/// When a linked source's snapshot advances.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RefreshPolicy {
    /// Only when explicitly refreshed.
    ///
    /// The only policy version 1 accepts. An automatic one would let a query advance a
    /// remote ref, which the root product contract forbids.
    #[default]
    Manual,
}

macro_rules! enumerated {
    ($name:ident, $field:literal, $($text:literal => $variant:ident),+ $(,)?) => {
        impl $name {
            /// The spelling used in a settings document.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }

            fn read(value: &Value, field: &str) -> Result<Self, SettingsError> {
                let text = value
                    .as_str()
                    .ok_or_else(|| invalid(field, "expected a string"))?;
                match text {
                    $($text => Ok(Self::$variant),)+
                    other => Err(invalid(
                        field,
                        format!(
                            "{other:?} is not one of {:?}",
                            [$($text),+]
                        ),
                    )),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let _ = $field;
                formatter.write_str(self.as_str())
            }
        }
    };
}

enumerated!(AiMode, "analysis.ai_mode", "off" => Off, "auto" => Auto, "full" => Full);
enumerated!(
    BudgetAction,
    "analysis.on_budget_exceeded",
    "ask" => Ask,
    "stop" => Stop,
    "continue_without_ai" => ContinueWithoutAi,
);
enumerated!(RefreshPolicy, "links[].refresh", "manual" => Manual);

/// One settings entry mirroring a declared link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSettings {
    /// The canonical locator, which is the link's identity.
    pub source: String,
    /// A name in `credentials.json`. Never a secret.
    pub credential_ref: Option<String>,
    /// When a remote snapshot advances.
    pub refresh: RefreshPolicy,
    /// How long opening this source may take.
    pub timeout_ms: u64,
    /// The immutable commit this link last resolved to.
    ///
    /// Snapshot metadata, not identity. The `source` remains what the link *is*; this
    /// records what it last pointed at, and only an explicit refresh advances it.
    pub resolved_commit: Option<String>,
    /// The content digest of what that commit yielded.
    pub resolved_digest: Option<String>,
}

/// Where the database is and whether `.nost` is materialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseSettings {
    /// The database file, relative to the `.nostdb` directory.
    pub path: String,
    /// Whether the canonical `.nost` is materialized.
    pub nost: bool,
}

/// What an analysis run may spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisSettings {
    /// How much AI enrichment is permitted.
    pub ai_mode: AiMode,
    /// Hard input-token ceiling, or unlimited.
    pub max_input_tokens: Option<u64>,
    /// Hard output-token ceiling, or unlimited.
    pub max_output_tokens: Option<u64>,
    /// Advisory cost ceiling, as a decimal string so it is never a binary float.
    pub max_cost_usd: Option<String>,
    /// What to do at a ceiling.
    pub on_budget_exceeded: BudgetAction,
}

/// Which cache tiers a project reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheSettings {
    /// Whether the user-global tier is read.
    ///
    /// The project tier has no field. A project that could not cache its own derived work
    /// would have nothing to turn off — that tier lives inside the project and is discarded
    /// with it. The user tier is shared across every project the same operating-system user
    /// builds, which is the thing a project might have reason not to read from.
    pub user: bool,
}

/// Safety limits on recursive federation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationSettings {
    /// Maximum link traversal depth.
    pub max_link_depth: u64,
    /// Maximum number of linked databases opened for one query.
    pub max_link_databases: u64,
    /// Timeout for opening one linked source.
    pub link_open_timeout_ms: u64,
}

/// Effective settings, after the merge and after defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The contract version.
    pub version: u64,
    /// Database location and materialization.
    pub database: DatabaseSettings,
    /// Analysis budget.
    pub analysis: AnalysisSettings,
    /// Operational mirrors of the declared links.
    pub links: Vec<LinkSettings>,
    /// Federation limits.
    pub federation: FederationSettings,
    /// Which cache tiers are read.
    pub cache: CacheSettings,
    /// Action name to plugin name.
    pub plugins: BTreeMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: SUPPORTED_VERSIONS[0],
            database: DatabaseSettings {
                path: DEFAULT_DATABASE_PATH.to_owned(),
                nost: false,
            },
            analysis: AnalysisSettings {
                ai_mode: AiMode::default(),
                max_input_tokens: None,
                max_output_tokens: None,
                max_cost_usd: None,
                on_budget_exceeded: BudgetAction::default(),
            },
            links: Vec::new(),
            cache: CacheSettings { user: true },
            federation: FederationSettings {
                max_link_depth: DEFAULT_MAX_LINK_DEPTH,
                max_link_databases: DEFAULT_MAX_LINK_DATABASES,
                link_open_timeout_ms: DEFAULT_LINK_OPEN_TIMEOUT_MS,
            },
            plugins: BTreeMap::new(),
        }
    }
}

impl Settings {
    /// Renders the effective settings as a whole JSON document.
    ///
    /// Every section is written, defaults included, because this is the effective view
    /// rather than a document to write back. See [`SettingsDocument::to_json`] for the
    /// form that preserves what a file actually held.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut root = Map::new();
        root.insert("settings_version".to_owned(), Value::from(self.version));
        root.insert(
            "database".to_owned(),
            serde_json::json!({
                "path": self.database.path,
                "nost": self.database.nost,
            }),
        );
        root.insert(
            "analysis".to_owned(),
            serde_json::json!({
                "ai_mode": self.analysis.ai_mode.as_str(),
                "max_input_tokens": self.analysis.max_input_tokens,
                "max_output_tokens": self.analysis.max_output_tokens,
                "max_cost_usd": self.analysis.max_cost_usd,
                "on_budget_exceeded": self.analysis.on_budget_exceeded.as_str(),
            }),
        );
        root.insert(
            "links".to_owned(),
            Value::Array(
                self.links
                    .iter()
                    .map(|link| {
                        serde_json::json!({
                            "source": link.source,
                            "credential_ref": link.credential_ref,
                            "refresh": link.refresh.as_str(),
                            "timeout_ms": link.timeout_ms,
                            "resolved_commit": link.resolved_commit,
                            "resolved_digest": link.resolved_digest,
                        })
                    })
                    .collect(),
            ),
        );
        root.insert(
            "federation".to_owned(),
            serde_json::json!({
                "max_link_depth": self.federation.max_link_depth,
                "max_link_databases": self.federation.max_link_databases,
                "link_open_timeout_ms": self.federation.link_open_timeout_ms,
            }),
        );
        root.insert(
            "cache".to_owned(),
            serde_json::json!({ "user": self.cache.user }),
        );
        root.insert(
            "plugins".to_owned(),
            Value::Object(
                self.plugins
                    .iter()
                    .map(|(action, plugin)| (action.clone(), Value::from(plugin.clone())))
                    .collect(),
            ),
        );
        Value::Object(root)
    }

    /// Reports every settings link entry that mirrors no declared link.
    ///
    /// An orphan is ignored rather than refused: a link removed from the graph leaves its
    /// operational entry behind, and refusing to open the project over that would be
    /// worse than saying so.
    #[must_use]
    pub fn orphan_link_settings<'a>(
        &'a self,
        declared: impl IntoIterator<Item = &'a str>,
    ) -> Vec<Diagnostic> {
        let declared: Vec<&str> = declared.into_iter().collect();
        self.links
            .iter()
            .filter(|link| !declared.contains(&link.source.as_str()))
            .map(|link| Diagnostic {
                code: DiagnosticCode::OrphanLinkSettings,
                severity: DiagnosticCode::OrphanLinkSettings.default_severity(),
                message: NonEmptyText::new(format!(
                    "the settings entry for {} matches no declared link, so it is ignored",
                    link.source
                ))
                .unwrap_or_else(|_| NonEmptyText::literal("an orphan settings link entry")),
                // The locator is reported inside the message rather than in the
                // `source` field, because that field holds a validated locator and a
                // settings entry may name one this build cannot canonicalize. Refusing
                // an orphan over its spelling would defeat the point of ignoring it.
                source: None,
                range: None,
                details: Vec::new(),
            })
            .collect()
    }
}

/// One settings file, parsed and validated, with every field still optional.
///
/// Keeping the fields optional is what makes the by-defined-field merge expressible: a
/// document that had already applied defaults could not say whether a value was written
/// or assumed.
#[derive(Clone, Debug, PartialEq)]
pub struct SettingsDocument {
    version: u64,
    database_path: Option<String>,
    database_nost: Option<bool>,
    ai_mode: Option<AiMode>,
    max_input_tokens: Option<Option<u64>>,
    max_output_tokens: Option<Option<u64>>,
    max_cost_usd: Option<Option<String>>,
    on_budget_exceeded: Option<BudgetAction>,
    links: Option<Vec<LinkSettings>>,
    max_link_depth: Option<u64>,
    max_link_databases: Option<u64>,
    link_open_timeout_ms: Option<u64>,
    cache_user: Option<bool>,
    plugins: Option<BTreeMap<String, String>>,
    original: Value,
}

/// Reads an optional member, applying `read` when it is present and not null.
fn optional<T>(
    parent: &Map<String, Value>,
    key: &str,
    field: &str,
    read: impl FnOnce(&Value, &str) -> Result<T, SettingsError>,
) -> Result<Option<T>, SettingsError> {
    match parent.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => read(value, field).map(Some),
    }
}

fn read_bool(value: &Value, field: &str) -> Result<bool, SettingsError> {
    value
        .as_bool()
        .ok_or_else(|| invalid(field, "expected a boolean"))
}

fn read_string(value: &Value, field: &str) -> Result<String, SettingsError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid(field, "expected a string"))
}

/// Reads a non-negative integer, refusing a float or a negative value.
fn read_count(value: &Value, field: &str) -> Result<u64, SettingsError> {
    match value.as_u64() {
        Some(number) => Ok(number),
        None if value.is_i64() || value.is_f64() => {
            Err(invalid(field, "expected a non-negative whole number"))
        }
        None => Err(invalid(field, "expected a non-negative whole number")),
    }
}

fn read_positive(value: &Value, field: &str) -> Result<u64, SettingsError> {
    let number = read_count(value, field)?;
    if number == 0 {
        return Err(invalid(field, "expected a positive whole number"));
    }
    Ok(number)
}

fn read_object<'a>(
    parent: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<&'a Map<String, Value>>, SettingsError> {
    match parent.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(_) => Err(invalid(field, "expected an object")),
    }
}

/// Reports whether a database path stays inside the `.nostdb` directory.
///
/// Settings are read from a repository someone else may have written, and this is the
/// one field there that could otherwise name any file on the machine.
fn check_database_path(path: &str) -> Result<(), SettingsError> {
    const FIELD: &str = "database.path";
    if path.is_empty() {
        return Err(invalid(FIELD, "must not be empty"));
    }
    if path.ends_with('/') || path.ends_with('\\') {
        return Err(invalid(FIELD, "must name a file, not a directory"));
    }
    // Windows separators are checked too, because a settings file is portable and a
    // backslash would otherwise slip a parent segment past a Unix-only check.
    let normalized = path.replace('\\', "/");
    if normalized.starts_with('/') || normalized.chars().nth(1) == Some(':') {
        return Err(invalid(FIELD, "must be relative"));
    }
    if normalized.split('/').any(|segment| segment == "..") {
        return Err(invalid(
            FIELD,
            "must not escape the .nostdb directory with a parent segment",
        ));
    }
    Ok(())
}

/// Reports whether a plugin value names a plugin rather than something to execute.
fn check_plugin_name(action: &str, name: &str) -> Result<(), SettingsError> {
    let field = format!("plugins.{action}");
    if name.is_empty() {
        return Err(SettingsError::Invalid {
            field,
            reason: "must not be empty".to_owned(),
        });
    }
    if name.contains('/') || name.contains('\\') || name.contains(' ') {
        return Err(SettingsError::Invalid {
            field,
            reason: "must be a plugin name, not a path or a command line".to_owned(),
        });
    }
    Ok(())
}

impl SettingsDocument {
    /// Parses and validates one settings file.
    ///
    /// # Errors
    ///
    /// Returns [`SettingsError::NotJson`] when the text is not JSON,
    /// [`SettingsError::UnsupportedVersion`] when the version is outside
    /// [`SUPPORTED_VERSIONS`], and [`SettingsError::Invalid`] naming the field for every
    /// other refusal the contract lists.
    pub fn parse(text: &str) -> Result<Self, SettingsError> {
        let original: Value =
            serde_json::from_str(text).map_err(|error| SettingsError::NotJson {
                reason: error.to_string(),
            })?;
        let root = original
            .as_object()
            .ok_or_else(|| invalid("settings", "a settings document is a JSON object"))?;

        let version = match root.get("settings_version") {
            None => return Err(invalid("settings_version", "is required")),
            Some(value) => {
                let number = value.as_u64().ok_or_else(|| {
                    invalid("settings_version", "expected a positive whole number")
                })?;
                if number == 0 {
                    return Err(invalid(
                        "settings_version",
                        "expected a positive whole number",
                    ));
                }
                number
            }
        };
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(SettingsError::UnsupportedVersion { found: version });
        }

        let mut document = Self {
            version,
            database_path: None,
            database_nost: None,
            ai_mode: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_cost_usd: None,
            on_budget_exceeded: None,
            links: None,
            max_link_depth: None,
            max_link_databases: None,
            link_open_timeout_ms: None,
            cache_user: None,
            plugins: None,
            original: original.clone(),
        };

        if let Some(database) = read_object(root, "database", "database")? {
            document.database_path = optional(database, "path", "database.path", read_string)?;
            if let Some(path) = &document.database_path {
                check_database_path(path)?;
            }
            document.database_nost = optional(database, "nost", "database.nost", read_bool)?;
        }

        if let Some(analysis) = read_object(root, "analysis", "analysis")? {
            document.ai_mode = optional(analysis, "ai_mode", "analysis.ai_mode", AiMode::read)?;
            document.on_budget_exceeded = optional(
                analysis,
                "on_budget_exceeded",
                "analysis.on_budget_exceeded",
                BudgetAction::read,
            )?;
            // A budget distinguishes "absent" from "explicitly null", because null is a
            // defined value meaning unlimited and must override a global limit.
            for (key, field, slot) in [
                (
                    "max_input_tokens",
                    "analysis.max_input_tokens",
                    &mut document.max_input_tokens,
                ),
                (
                    "max_output_tokens",
                    "analysis.max_output_tokens",
                    &mut document.max_output_tokens,
                ),
            ] {
                *slot = match analysis.get(key) {
                    None => None,
                    Some(Value::Null) => Some(None),
                    Some(value) => Some(Some(read_count(value, field)?)),
                };
            }
            document.max_cost_usd = match analysis.get("max_cost_usd") {
                None => None,
                Some(Value::Null) => Some(None),
                Some(value) => Some(Some(read_string(value, "analysis.max_cost_usd").map_err(
                    |_| {
                        invalid(
                            "analysis.max_cost_usd",
                            "expected a decimal string, so a currency amount is never a \
                             binary float",
                        )
                    },
                )?)),
            };
        }

        if let Some(federation) = read_object(root, "federation", "federation")? {
            document.max_link_depth = optional(
                federation,
                "max_link_depth",
                "federation.max_link_depth",
                read_positive,
            )?;
            document.max_link_databases = optional(
                federation,
                "max_link_databases",
                "federation.max_link_databases",
                read_positive,
            )?;
            document.link_open_timeout_ms = optional(
                federation,
                "link_open_timeout_ms",
                "federation.link_open_timeout_ms",
                read_positive,
            )?;
        }

        if let Some(cache) = read_object(root, "cache", "cache")? {
            document.cache_user = optional(cache, "user", "cache.user", read_bool)?;
        }

        document.links = match root.get("links") {
            None | Some(Value::Null) => None,
            Some(Value::Array(entries)) => Some(read_links(entries)?),
            Some(_) => return Err(invalid("links", "expected an array")),
        };

        if let Some(plugins) = read_object(root, "plugins", "plugins")? {
            let mut mapped = BTreeMap::new();
            for (action, value) in plugins {
                let name = read_string(value, &format!("plugins.{action}"))?;
                check_plugin_name(action, &name)?;
                mapped.insert(action.clone(), name);
            }
            document.plugins = Some(mapped);
        }

        Ok(document)
    }

    /// The document as it was written, with every unknown field intact.
    ///
    /// Preservation is what keeps a downgrade from being lossy: the moment a writer drops
    /// what it does not recognize, a machine running an older build destroys
    /// configuration for one running a newer build.
    #[must_use]
    pub const fn to_json(&self) -> &Value {
        &self.original
    }

    /// The contract version this document declares.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Combines a global and a project document, then applies defaults.
    ///
    /// The merge is by **defined field**, never a recursive JSON merge. A field present
    /// in the project document replaces the global value for that field alone.
    ///
    /// `links` is one field. A project that defines it replaces the global list entirely,
    /// including with an empty list, because merging two lists would require deciding
    /// what happens when both scopes name one source with different timeouts.
    #[must_use]
    pub fn resolve(global: Option<&Self>, project: Option<&Self>) -> Settings {
        let mut settings = Settings::default();
        if let Some(version) = project.or(global).map(Self::version) {
            settings.version = version;
        }

        let pick = |take: &dyn Fn(&Self) -> bool| -> Option<&Self> {
            project
                .filter(|document| take(document))
                .or_else(|| global.filter(|document| take(document)))
        };

        if let Some(source) = pick(&|d| d.database_path.is_some())
            && let Some(path) = &source.database_path
        {
            settings.database.path.clone_from(path);
        }
        if let Some(source) = pick(&|d| d.database_nost.is_some())
            && let Some(nost) = source.database_nost
        {
            settings.database.nost = nost;
        }
        if let Some(source) = pick(&|d| d.ai_mode.is_some())
            && let Some(mode) = source.ai_mode
        {
            settings.analysis.ai_mode = mode;
        }
        if let Some(source) = pick(&|d| d.on_budget_exceeded.is_some())
            && let Some(action) = source.on_budget_exceeded
        {
            settings.analysis.on_budget_exceeded = action;
        }
        if let Some(source) = pick(&|d| d.max_input_tokens.is_some())
            && let Some(limit) = source.max_input_tokens
        {
            settings.analysis.max_input_tokens = limit;
        }
        if let Some(source) = pick(&|d| d.max_output_tokens.is_some())
            && let Some(limit) = source.max_output_tokens
        {
            settings.analysis.max_output_tokens = limit;
        }
        if let Some(source) = pick(&|d| d.max_cost_usd.is_some())
            && let Some(limit) = &source.max_cost_usd
        {
            settings.analysis.max_cost_usd.clone_from(limit);
        }
        if let Some(source) = pick(&|d| d.cache_user.is_some())
            && let Some(user) = source.cache_user
        {
            settings.cache.user = user;
        }
        if let Some(source) = pick(&|d| d.links.is_some())
            && let Some(links) = &source.links
        {
            settings.links.clone_from(links);
        }
        if let Some(source) = pick(&|d| d.max_link_depth.is_some())
            && let Some(value) = source.max_link_depth
        {
            settings.federation.max_link_depth = value;
        }
        if let Some(source) = pick(&|d| d.max_link_databases.is_some())
            && let Some(value) = source.max_link_databases
        {
            settings.federation.max_link_databases = value;
        }
        if let Some(source) = pick(&|d| d.link_open_timeout_ms.is_some())
            && let Some(value) = source.link_open_timeout_ms
        {
            settings.federation.link_open_timeout_ms = value;
        }
        if let Some(source) = pick(&|d| d.plugins.is_some())
            && let Some(plugins) = &source.plugins
        {
            settings.plugins.clone_from(plugins);
        }

        settings
    }
}

fn read_links(entries: &[Value]) -> Result<Vec<LinkSettings>, SettingsError> {
    let mut links: Vec<LinkSettings> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let field = |name: &str| format!("links[{index}].{name}");
        let object = entry
            .as_object()
            .ok_or_else(|| invalid(&format!("links[{index}]"), "expected an object"))?;

        // An alias is part of the semantic declaration in the graph. Refusing rather than
        // ignoring one keeps two files from disagreeing about what a link is called.
        if object.contains_key("alias") {
            return Err(invalid(
                &field("alias"),
                "an alias is declared in the graph, never in settings",
            ));
        }

        let source = object
            .get("source")
            .ok_or_else(|| invalid(&field("source"), "is required"))?;
        let source = read_string(source, &field("source"))?;
        if source.is_empty() {
            return Err(invalid(&field("source"), "must not be empty"));
        }
        if links.iter().any(|existing| existing.source == source) {
            return Err(invalid(
                &field("source"),
                format!("{source} is already declared by an earlier entry"),
            ));
        }

        links.push(LinkSettings {
            source,
            credential_ref: optional(
                object,
                "credential_ref",
                &field("credential_ref"),
                read_string,
            )?,
            refresh: optional(object, "refresh", &field("refresh"), RefreshPolicy::read)?
                .unwrap_or_default(),
            timeout_ms: optional(object, "timeout_ms", &field("timeout_ms"), read_count)?
                .unwrap_or(DEFAULT_LINK_OPEN_TIMEOUT_MS),
            resolved_commit: optional(
                object,
                "resolved_commit",
                &field("resolved_commit"),
                read_string,
            )?,
            resolved_digest: optional(
                object,
                "resolved_digest",
                &field("resolved_digest"),
                read_string,
            )?,
        });
    }
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<SettingsDocument, SettingsError> {
        SettingsDocument::parse(text)
    }

    fn resolve(global: &str, project: &str) -> Settings {
        SettingsDocument::resolve(
            Some(&parse(global).expect("global must parse")),
            Some(&parse(project).expect("project must parse")),
        )
    }

    #[test]
    fn the_version_is_the_only_required_member() {
        let document = parse(r#"{"settings_version": 1}"#).unwrap();
        assert_eq!(document.version(), 1);
        assert_eq!(
            SettingsDocument::resolve(None, Some(&document)),
            Settings::default()
        );
    }

    #[test]
    fn a_missing_or_unusable_version_is_refused() {
        assert_eq!(parse("{}"), Err(invalid("settings_version", "is required")));
        assert!(matches!(
            parse(r#"{"settings_version": 0}"#),
            Err(SettingsError::Invalid { .. })
        ));
        assert!(matches!(
            parse(r#"{"settings_version": "1"}"#),
            Err(SettingsError::Invalid { .. })
        ));
        assert_eq!(
            parse(r#"{"settings_version": 99}"#),
            Err(SettingsError::UnsupportedVersion { found: 99 })
        );
        assert!(matches!(
            parse("[1, 2]"),
            Err(SettingsError::Invalid { .. })
        ));
        assert!(matches!(
            parse("not json"),
            Err(SettingsError::NotJson { .. })
        ));
    }

    #[test]
    fn a_database_path_must_stay_inside_the_project() {
        for path in [
            "/etc/passwd",
            "../../root.nostdb",
            "graphs/../../root.nostdb",
            "C:/root.nostdb",
            "..\\\\..\\\\root.nostdb",
            "graphs/",
            "",
        ] {
            let text = format!(r#"{{"settings_version": 1, "database": {{"path": "{path}"}}}}"#);
            assert!(
                matches!(parse(&text), Err(SettingsError::Invalid { .. })),
                "{path} must be refused"
            );
        }
        assert!(
            parse(r#"{"settings_version": 1, "database": {"path": "graphs/root.nostdb"}}"#).is_ok()
        );
    }

    #[test]
    fn a_link_entry_may_not_carry_an_alias() {
        let error = parse(r#"{"settings_version": 1, "links": [{"source": "./a", "alias": "a"}]}"#)
            .unwrap_err();
        assert!(
            error.to_string().contains("declared in the graph"),
            "{error}"
        );
    }

    #[test]
    fn a_link_entry_needs_a_unique_source() {
        assert!(matches!(
            parse(r#"{"settings_version": 1, "links": [{"timeout_ms": 1}]}"#),
            Err(SettingsError::Invalid { .. })
        ));
        assert!(matches!(
            parse(r#"{"settings_version": 1, "links": [{"source": "./a"}, {"source": "./a"}]}"#),
            Err(SettingsError::Invalid { .. })
        ));
    }

    #[test]
    fn only_manual_refresh_is_accepted() {
        assert!(
            parse(r#"{"settings_version": 1, "links": [{"source": "./a", "refresh": "manual"}]}"#)
                .is_ok()
        );
        assert!(matches!(
            parse(
                r#"{"settings_version": 1, "links": [{"source": "./a", "refresh": "automatic"}]}"#
            ),
            Err(SettingsError::Invalid { .. })
        ));
    }

    #[test]
    fn a_budget_is_non_negative_and_zero_is_a_budget() {
        assert!(parse(r#"{"settings_version": 1, "analysis": {"max_input_tokens": 0}}"#).is_ok());
        assert!(matches!(
            parse(r#"{"settings_version": 1, "analysis": {"max_input_tokens": -1}}"#),
            Err(SettingsError::Invalid { .. })
        ));
    }

    #[test]
    fn a_cost_is_a_decimal_string_rather_than_a_float() {
        assert!(parse(r#"{"settings_version": 1, "analysis": {"max_cost_usd": "5.00"}}"#).is_ok());
        let error =
            parse(r#"{"settings_version": 1, "analysis": {"max_cost_usd": 5.0}}"#).unwrap_err();
        assert!(error.to_string().contains("binary float"), "{error}");
    }

    #[test]
    fn an_unknown_enumerator_or_wrong_type_is_refused() {
        assert!(matches!(
            parse(r#"{"settings_version": 1, "analysis": {"ai_mode": "maximum"}}"#),
            Err(SettingsError::Invalid { .. })
        ));
        assert!(matches!(
            parse(r#"{"settings_version": 1, "database": {"nost": "true"}}"#),
            Err(SettingsError::Invalid { .. })
        ));
    }

    #[test]
    fn a_federation_limit_must_be_positive() {
        assert!(matches!(
            parse(r#"{"settings_version": 1, "federation": {"max_link_depth": 0}}"#),
            Err(SettingsError::Invalid { .. })
        ));
    }

    #[test]
    fn a_plugin_value_names_a_plugin_rather_than_a_command() {
        assert!(
            parse(r#"{"settings_version": 1, "plugins": {"view": "org.nostdb.view"}}"#).is_ok()
        );
        for name in ["./bin/viewer", "bin\\\\viewer", "viewer --flag"] {
            let text = format!(r#"{{"settings_version": 1, "plugins": {{"view": "{name}"}}}}"#);
            assert!(
                matches!(parse(&text), Err(SettingsError::Invalid { .. })),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn the_merge_replaces_one_defined_field_and_keeps_the_rest() {
        let settings = resolve(
            r#"{"settings_version": 1, "database": {"path": "global.nostdb", "nost": true}}"#,
            r#"{"settings_version": 1, "database": {"path": "project.nostdb"}}"#,
        );
        assert_eq!(settings.database.path, "project.nostdb");
        assert!(
            settings.database.nost,
            "an undefined field keeps the global value"
        );
    }

    #[test]
    fn links_replace_rather_than_append_even_when_empty() {
        let settings = resolve(
            r#"{"settings_version": 1, "links": [{"source": "./global"}]}"#,
            r#"{"settings_version": 1, "links": [{"source": "./project"}]}"#,
        );
        assert_eq!(settings.links.len(), 1);
        assert_eq!(settings.links[0].source, "./project");

        let emptied = resolve(
            r#"{"settings_version": 1, "links": [{"source": "./global"}]}"#,
            r#"{"settings_version": 1, "links": []}"#,
        );
        assert!(
            emptied.links.is_empty(),
            "an empty list is defined, so it replaces"
        );
    }

    #[test]
    fn an_explicit_null_budget_overrides_a_global_limit() {
        // null is a defined value meaning unlimited, which is why parsing keeps "absent"
        // and "explicitly null" apart.
        let settings = resolve(
            r#"{"settings_version": 1, "analysis": {"max_input_tokens": 100}}"#,
            r#"{"settings_version": 1, "analysis": {"max_input_tokens": null}}"#,
        );
        assert_eq!(settings.analysis.max_input_tokens, None);

        let inherited = resolve(
            r#"{"settings_version": 1, "analysis": {"max_input_tokens": 100}}"#,
            r#"{"settings_version": 1, "analysis": {}}"#,
        );
        assert_eq!(inherited.analysis.max_input_tokens, Some(100));
    }

    #[test]
    fn defaults_apply_when_neither_scope_defines_a_field() {
        let settings = SettingsDocument::resolve(None, None);
        assert_eq!(settings, Settings::default());
        assert_eq!(settings.database.path, DEFAULT_DATABASE_PATH);
        assert_eq!(settings.federation.max_link_depth, DEFAULT_MAX_LINK_DEPTH);
        assert_eq!(settings.analysis.ai_mode, AiMode::Auto);
    }

    #[test]
    fn an_unknown_field_survives_parsing() {
        let text = r#"{"settings_version": 1, "future_section": {"whatever": [1, 2, 3]}}"#;
        let document = parse(text).unwrap();
        assert_eq!(
            document.to_json()["future_section"]["whatever"],
            serde_json::json!([1, 2, 3])
        );
    }

    #[test]
    fn an_orphan_entry_is_a_warning_naming_its_source() {
        let settings = SettingsDocument::resolve(
            None,
            Some(
                &parse(r#"{"settings_version": 1, "links": [{"source": "./gone"}, {"source": "./kept"}]}"#)
                    .unwrap(),
            ),
        );
        let found = settings.orphan_link_settings(["./kept"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, DiagnosticCode::OrphanLinkSettings);
        assert_eq!(found[0].severity, crate::diagnostic::Severity::Warning);
        assert!(
            found[0].message.as_str().contains("./gone"),
            "the message names the orphan: {}",
            found[0].message
        );

        // A declared link with no entry is not a diagnostic: the declaration is
        // authoritative and the entry only supplies defaults.
        assert!(
            settings
                .orphan_link_settings(["./gone", "./kept", "./undeclared-in-settings"])
                .is_empty()
        );
    }

    #[test]
    fn the_effective_view_renders_every_section() {
        let rendered = Settings::default().to_json();
        for section in [
            "settings_version",
            "database",
            "analysis",
            "links",
            "federation",
            "plugins",
        ] {
            assert!(rendered.get(section).is_some(), "{section} is missing");
        }
        assert_eq!(rendered["analysis"]["max_input_tokens"], Value::Null);
        assert_eq!(rendered["links"], serde_json::json!([]));
    }

    #[test]
    fn the_user_cache_tier_is_read_unless_a_project_declines_it() {
        assert!(Settings::default().cache.user);
        // The effective document states the default; a parsed document preserves only
        // what was written, which is a different question and a different method.
        let effective = resolve(r#"{"settings_version": 1}"#, r#"{"settings_version": 1}"#);
        assert_eq!(effective.to_json()["cache"]["user"], true);
        assert!(
            parse(r#"{"settings_version": 1}"#)
                .unwrap()
                .to_json()
                .get("cache")
                .is_none()
        );

        let declined = resolve(
            r#"{"settings_version": 1}"#,
            r#"{"settings_version": 1, "cache": {"user": false}}"#,
        );
        assert!(!declined.cache.user);

        // By defined field, like every other section: a project saying `false` overrides a
        // global saying `true`, and a project saying nothing keeps the global.
        let inherited = resolve(
            r#"{"settings_version": 1, "cache": {"user": false}}"#,
            r#"{"settings_version": 1}"#,
        );
        assert!(!inherited.cache.user);
    }

    #[test]
    fn a_cache_field_of_the_wrong_type_is_refused_rather_than_guessed() {
        // Guessing that the string "no" means false is how a typo becomes a silent
        // behavior change.
        assert!(matches!(
            parse(r#"{"settings_version": 1, "cache": {"user": "no"}}"#),
            Err(SettingsError::Invalid { .. })
        ));
        assert!(matches!(
            parse(r#"{"settings_version": 1, "cache": true}"#),
            Err(SettingsError::Invalid { .. })
        ));
    }
}
