# nostdb-core

`nostdb-core` is the NostDB Engine. It owns the graph model, the `.nost` parser,
deterministic structural analyzers, the `.nostdb` storage format, transactions,
synchronization, the public provider interfaces, and the query engine.

NostDB is a clean-slate, local-first Property Graph Database for software
environments.

## Boundary

This repository is the only component permitted to write `.nostdb`.

It owns:

- the graph model: Nodes, Edges, properties, Schemas, Constraints, contributions,
  and evidence;
- the `.nost` parser, comment-preserving CST, and canonical formatter;
- the opaque `.nostdb` storage format, transactions, journal, and recovery;
- synchronization between `.nostdb` and `.nost`;
- deterministic structural analyzers and their declared capabilities;
- the public `SourceProvider` and `GraphStoreProvider` interfaces;
- link resolution, recursive federation, and cycle detection;
- the openCypher-compatible query subset and its execution.

It does not own:

- a CLI or REPL, which belong to `nostdb-cli`;
- a daemon, catalog, or IPC layer, which belong to `nostdb-server`;
- any HTTP or network listener;
- the GitHub provider implementation, which is a separate out-of-process
  executable;
- the plugin manager, which exists once in `nostdb-cli`;
- the `.nost` grammar and conformance fixtures, which belong to `nostdb-spec`.

Every other component calls the public API here rather than reimplementing a
parser, storage engine, synchronizer, query engine, or `.nostdb` writer.

## Current status

Implemented:

- the graph model and the typed change contract: identifiers, canonical source
  locators, validated names, property values, graph records, ownership and evidence,
  diagnostics, `GraphChangeSet`, and build coverage;
- the `.nostdb` container: CRC-32C, the header and section table, and the twelve
  ordered bounded-parsing checks, reading and writing;
- the transaction foundation: a monotonic generation, a checksummed journal with
  idempotent replay, and atomic commit through staged write and promotion;
- the `.nost` language: a lexer, a comment-preserving tree, a recursive-descent
  parser, semantic validation, and the canonical formatter whose second pass is
  byte-identical;
- section payload encodings, so a graph round-trips through a `.nostdb` file;
- the synchronization state machine, comparing a baseline of generation and content
  digests rather than wall-clock time;
- the deterministic analysis boundary: analyzer capability, precision class, and fact
  kinds, with no closed language allowlist;
- the openCypher subset parser for reading, refusing every construct outside the
  published subset with a source range and no query plan;
- query execution over a graph: pattern matching with bounded variable-length traversal,
  predicates, projection, DISTINCT, ORDER BY, SKIP, LIMIT, UNWIND, and UNION.

Decoding rebuilds every value through the same typed constructors the model uses, so a
corrupt or hostile file cannot produce a model that breaks an invariant; it produces an
error instead. Every count is checked against the remaining bytes before anything is
allocated.

Aggregation, write clauses, transactions, and procedures are still to come.

## Conformance against the specification

The container fixtures live in
[nostdb-spec](https://github.com/nostdb/nostdb-spec) and are never copied here.
`tests/container_conformance.rs` and `tests/nost_conformance.rs` read them from the
path the superproject supplies in `NOSTDB_SPEC_FIXTURES`, so conformance is proven
against the exact pinned commit.

The `.nost` suite deliberately does not compare error positions. The fixtures record
them, and the language contract marks them informative: they pin the reference
encoding, which is a PEG reporting the furthest position it backtracked from, while
this parser is recursive descent and reports the offending token. Rejection with a
usable range is what conformance requires.

A standalone clone has no sibling checkout, so that test reports itself skipped and
passes. Because a skipped test proves nothing, the root workspace verifier runs it
with the path set and fails unless it confirms the fixtures ran.

## How invariants are enforced

The model uses two mechanisms deliberately:

- A **value invariant** is enforced by its type, so an invalid value cannot exist.
  A float property cannot be infinite, a confidence score cannot fall outside
  `0.0..=1.0`, a label cannot be a reserved word, and an `Edge` cannot have a
  missing endpoint because its endpoints are not optional. There is no null
  property variant at all.
- A **collection invariant**, such as a property block setting one key twice, is
  reported by a validation call. The Engine has to surface those as diagnostics
  against real source positions, so refusing construction would discard the context
  a caller needs.

Diagnostic codes are stable identifiers registered in
[nostdb-spec](https://github.com/nostdb/nostdb-spec). The root workspace verifies
that this crate's vocabulary and that registry match exactly, because the two are
separate repositories pinned together.

## Product contract

The normative product contract is the PRD in the root NostDB superproject at
<https://github.com/nostdb/nostdb>. Executable format, grammar, and protocol
contracts live in <https://github.com/nostdb/nostdb-spec>.

This repository keeps no copy of the PRD. A divergent child copy would create two
competing contracts.

## Verify

```bash
./scripts/verify-repository.sh
```

The verifier runs the repository checks, `cargo fmt --check`, `cargo check`,
`cargo clippy -- -D warnings`, `cargo test`, and the ownership-boundary checks that
keep a command surface or a network listener out of the Engine. Continuous
integration runs the same script, so a local pass and a CI pass check identical
invariants.

## License

SSPL-1.0. See [LICENSE](LICENSE).

`nostdb-core` is **source-available**, not open source. `nostdb-cli` and
`nostdb-server` carry the same license. `nostdb-spec` and the Agent Skills are
Apache-2.0 so that any implementation can verify itself against the published
contracts.
