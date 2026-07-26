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
//! This is the graph model and the typed change contract: the data types, their
//! validated construction, and their explicit error types. Storage, the `.nost`
//! parser, synchronization, analyzers, and query execution arrive in later Stages.
//! The module documentation states what is deferred where it matters.
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

pub mod change;
pub mod container;
pub mod contribution;
pub mod coverage;
pub mod crc;
pub mod diagnostic;
pub mod encoding;
pub mod evidence;
pub mod generation;
pub mod graph;
pub mod id;
pub mod journal;
pub mod link;
pub mod locator;
pub mod name;
pub mod nost;
pub mod property;
pub mod storage;
pub mod text;

pub use change::{ChangeSetError, GraphChangeSet, GraphOperation};
pub use container::{Container, ContainerBuilder, ContainerError, Section, SectionKind};
pub use contribution::{Contribution, ContributionKey, Owner};
pub use diagnostic::{Diagnostic, DiagnosticCode, Severity};
pub use encoding::{Graph, decode_graph, encode_graph};
pub use evidence::{Confidence, Evidence, EvidenceMethod, Score, SourceRange};
pub use generation::Generation;
pub use graph::{Edge, Node, NodeReference, ScopedNodeId};
pub use id::{LocalEdgeId, LocalNodeId, SourceUnitId, StableModuleId};
pub use link::Link;
pub use locator::CanonicalSourceLocator;
pub use name::{DeclarationName, Label, LinkAlias, PropertyKey, RelationName};
pub use property::{PropertyScalar, PropertyValue};
pub use storage::{Database, StorageError};
