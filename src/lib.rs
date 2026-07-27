#![forbid(unsafe_code)]

//! The NostDB Engine.
//!
//! `nostdb-core` is the only component permitted to write `.nostdb`. Every other
//! component, including the CLI, the daemon, providers, Skills, and plugins, calls
//! the public API here rather than reimplementing a parser, storage engine,
//! synchronizer, query engine, or database writer.
//!
//! # What this crate contains today
//!
//! The graph model and the typed change contract, the `.nostdb` container and its
//! transaction foundation, the `.nost` lexer, comment-preserving parser and canonical
//! formatter, section payload encodings, the synchronization state machine, the
//! deterministic analysis boundary, and the openCypher query subset: parsing,
//! execution, writing, and explicit transactions. The module documentation states
//! what is deferred where it matters.
//!
//! # Contract source
//!
//! The `.nost` language and `.nostdb` container contracts live in `nostdb-spec`,
//! not here. Where a rule in this crate comes from one of those documents, the
//! rustdoc names the document and section so the two cannot drift silently.
//!
//! # How invariants are enforced
//!
//! The model uses two mechanisms, chosen deliberately:
//!
//! - A **value invariant** is enforced by its type, so an invalid value cannot be
//!   constructed at all. [`property::FiniteF64`] cannot hold an infinity,
//!   [`evidence::Score`] cannot hold a value outside `0.0..=1.0`, [`name::Label`]
//!   cannot hold a reserved word, and [`graph::Edge`] cannot hold a missing
//!   endpoint because its endpoints are not optional.
//! - A **collection invariant**, such as a property block setting one key twice,
//!   is reported by a validation call. Those are the conditions the Engine has to
//!   surface as diagnostics against real source anyway, so making them
//!   construction failures would throw away the position information a caller
//!   needs.
//!
//! # Library conduct
//!
//! This crate returns typed errors, never converts an ordinary error into a
//! process exit code, and never writes to stdout or stderr. It does not panic for
//! ordinary failures.

pub mod analysis;
pub mod analyze;
pub mod change;
pub mod container;
pub mod contribution;
pub mod coverage;
pub mod crc;
pub mod cypher;
pub mod diagnostic;
pub mod encoding;
pub mod evidence;
pub mod execute;
pub mod federation;
pub mod generation;
pub mod graph;
pub mod id;
pub mod ignore;
pub mod journal;
pub mod link;
pub mod locator;
pub mod mutate;
pub mod name;
pub mod nost;
pub mod plan;
pub mod procedure;
pub mod project;
pub mod property;
pub mod result;
pub mod scan;
pub mod schema;
pub mod settings;
pub mod storage;
pub mod sync;
pub mod text;
pub mod transaction;

pub use analysis::{AnalyzerCapability, CapabilityRegistry, FactKind, PrecisionClass};
pub use change::{ChangeSetError, GraphChangeSet, GraphOperation};
pub use container::{Container, ContainerBuilder, ContainerError, Section, SectionKind};
pub use contribution::{Contribution, ContributionKey, Owner};
pub use cypher::{Query, QueryError, parse};
pub use diagnostic::{Diagnostic, DiagnosticCode, Severity};
pub use encoding::{Graph, commit_graph, decode_graph, encode_graph, read_graph};
pub use evidence::{Confidence, Evidence, EvidenceMethod, Score, SourceRange};
pub use execute::{DatabaseContext, Parameters, QueryResult, QueryValue, execute};
pub use federation::{FederatedSource, Federation, LinkStatus, Unreachable};
pub use generation::Generation;
pub use graph::{Edge, Node, NodeReference, ScopedNodeId};
pub use id::{LocalEdgeId, LocalNodeId, Minter, SourceUnitId};
pub use link::Link;
pub use locator::CanonicalSourceLocator;
pub use mutate::WriteSummary;
pub use name::{DeclarationName, Label, LinkAlias, PropertyKey, RelationName};
pub use procedure::{FUNCTIONS, PROCEDURES};
pub use project::{Project, ProjectError};
pub use property::{PropertyScalar, PropertyValue};
pub use result::{RESULT_VERSION, ResultEnvelope};
pub use schema::{
    EffectiveSchema, EndpointConstraint, FieldType, ScalarType, Schema, SchemaField,
    SchemaViolation,
};
pub use settings::{
    AiMode, AnalysisSettings, BudgetAction, DatabaseSettings, FederationSettings, LinkSettings,
    RefreshPolicy, Settings, SettingsDocument, SettingsError,
};
pub use storage::{Database, StorageError};
pub use sync::{SyncBaseline, SyncOutcome, SyncState};
pub use transaction::{Transaction, TransactionError, run_once};
