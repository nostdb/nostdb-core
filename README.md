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

This repository is initialized as root Stage 1 scaffolding. No model, storage,
parser, analyzer, or query code is present yet. Stage 3 begins the model and
typed change contracts, and later Stages add storage, analysis, and query.

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

Continuous integration runs the same verifier on every push and pull request, so
a local pass and a CI pass check identical invariants.

## License

SSPL-1.0. See [LICENSE](LICENSE).

`nostdb-core` is **source-available**, not open source. `nostdb-cli` and
`nostdb-server` carry the same license. `nostdb-spec` and the Agent Skills are
Apache-2.0 so that any implementation can verify itself against the published
contracts.
