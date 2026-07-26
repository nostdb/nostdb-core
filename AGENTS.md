# nostdb-core Agent Instructions

## Inheritance

This repository is a child of the NostDB root superproject. The root `AGENTS.md`
at <https://github.com/nostdb/nostdb> is the governing contract.

This file only narrows the root rules for the Engine boundary. It must not weaken
any root product, safety, or ownership boundary. If this file and the root
contract appear to conflict, the root contract wins, the current valid behavior
stays unchanged, and the exact conflict is recorded in the root
`IMPLEMENTATION_PROGRESS.md`.

## Language policy

Write everything in this repository in English only.

This covers documentation, source code, identifiers, comments, rustdoc, test
names, commit messages, branch names, pull request titles and bodies, issue text,
diagnostics, error messages, log records, configuration, fixtures, and example
`.nost` content.

This rule holds regardless of the language a request is written in.

## Ownership boundary

`nostdb-core` is the Engine and the only component that writes `.nostdb`.

Permitted:

- the graph model, including Nodes, Edges, properties, Schemas, Constraints,
  contributions, and evidence;
- the `.nost` parser, comment-preserving CST, and canonical formatter;
- the opaque `.nostdb` storage format, transactions, journal, and recovery;
- synchronization between `.nostdb` and `.nost`;
- deterministic structural analyzers and their declared capabilities;
- the public `SourceProvider` and `GraphStoreProvider` interfaces;
- link resolution, recursive federation, and cycle detection;
- the openCypher-compatible query subset, planning, and execution.

Prohibited:

- a CLI, REPL, or command surface, which belong to `nostdb-cli`;
- a daemon, named-database catalog, session layer, or IPC transport, which belong
  to `nostdb-server`;
- any HTTP, TCP, or network listener;
- a bundled GitHub provider implementation, which is a separate out-of-process
  executable;
- a plugin manager, which exists once in `nostdb-cli`;
- a second copy of the `.nost` grammar or conformance fixtures, which belong to
  `nostdb-spec`;
- a copy of the root PRD;
- code copied in from any legacy implementation.

## Invariants this repository must never break

These are the Engine's share of the product invariants. Breaking one is a defect
even when every test passes.

- `.nostdb` is opaque, and only this Engine writes it.
- A readable `.nostdb` opens without a running daemon.
- The `.nost` language, `.nostdb` format, settings, provider protocol, plugin
  protocol, and server protocol versions evolve independently.
- A failed build, sync, link refresh, or mutation preserves the last valid
  database generation.
- An Edge always has two non-null endpoints, validated before commit.
- A file path is a mutable source location, never the permanent identity of an
  Entity or Schema. Identity uses persisted Stable Module IDs and opaque record
  IDs.
- A missing referenced symbol produces a Warning plus a typed Placeholder Node or
  unresolved Schema reference, never a null endpoint.
- Resolving a Placeholder preserves its local ID whenever possible, and otherwise
  records an explicit identity replacement event.
- Synchronization uses database generations and content digests, never
  newest-timestamp-wins. When both representations changed from one baseline,
  report `SYNC_CONFLICT` and modify neither.
- Schema validation may be soft and record warnings. Explicit Constraints are
  always hard and reject the transaction.
- Analyzer-owned and user-owned contributions stay separate. An analyzer refresh
  replaces only its own contributions for its own source unit.
- Storage and queries are programming-language-neutral. Never encode a closed
  source-language allowlist into `.nostdb`.
- Structural analysis of supported source consumes zero external AI tokens, and a
  usable structural generation commits before any optional enrichment.
- Unsupported Cypher returns a source-ranged diagnostic and never executes with
  silently changed semantics.
- Result order is undefined without `ORDER BY`.
- A query sees only its root database and recursively declared links. Writes
  affect only the root database; a linked write returns
  `LINKED_DATABASE_READ_ONLY`.
- Link identity is the canonical source path or address, not a generated link ID
  or a target database ID.
- An unavailable link stays declared and yields reachable partial results plus a
  structured warning.
- Secrets never reach `.nostdb`, `.nost`, settings, caches, diagnostics, or log
  records.

## Rust standards

Rust stable and Edition 2024. Public APIs require explicit error types and
rustdoc. Use `#![forbid(unsafe_code)]` where practical; required `unsafe` code
needs a separate ADR with documented safety invariants and a Miri or equivalent
verification plan before implementation.

This is a library. It uses `tracing`, never writes directly to stdout, never
panics for ordinary errors, and never converts an ordinary error into a process
exit code.

Every change must pass:

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Do not add a dependency without documenting its purpose, maintenance status, and
license.

## Repository verification

Run before every commit:

```bash
./scripts/verify-repository.sh
```

The verifier is non-mutating. Extend it as the Engine lands rather than replacing
it with a manual checklist.

## Testing expectations

Treat every `.nost` file, `.nostdb` file, source tree, and query string as
untrusted input. Bound recursion, allocation, file size, query work, and link
traversal.

Each boundary carries its own coverage:

- parser: valid and invalid syntax, comments, recovery with source ranges, and
  golden fixtures from `nostdb-spec`;
- links: recursion, missing sources, duplicate aliases, cycles, namespaces, and
  disconnected components;
- sync: create, update, delete, stale sources, conflicts, crash rollback, and
  concurrent external edits;
- storage: reopen, checksums, migration, corruption, and transaction rollback;
- analysis: provenance, cache invalidation, ownership, unsupported languages,
  partial AI output, and hard budgets;
- query: parse, semantic analysis, execution, transactions, and mapped
  openCypher conformance fixtures.

A storage or sync change without a rollback test is incomplete.

## Safety and external actions

- Never execute analyzed source code.
- Do not create remote repositories, add remotes, push to a new remote, publish
  packages, create releases, or modify registries without explicit user
  authorization.
- Never place credentials, passwords, tokens, private keys, or PEM content in
  files, fixtures, diagnostics, or command output.
- Do not use destructive Git commands or broad deletion.
- Preserve existing user changes and never revert them without authorization.

## Stage workflow

Implementation sequencing is tracked in the root `IMPLEMENTATION_PROGRESS.md`,
not in this repository. Do not begin a later Stage during a setup-only request,
and do not mark a Stage `DONE` until every Acceptance Criterion passes.
