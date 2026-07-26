#!/usr/bin/env bash

# Non-mutating verification for nostdb-core.
#
# Stage 1 checks repository scaffolding only. Later Stages extend this script
# with the Rust command set once Engine code lands:
#
#   cargo fmt --check
#   cargo check
#   cargo clippy --all-targets --all-features -- -D warnings
#   cargo test --all-targets --all-features

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

cd "$repository_root"

required_files="
AGENTS.md
CLAUDE.md
README.md
LICENSE
.gitignore
.editorconfig
.github/workflows/verify.yml
Cargo.toml
Cargo.lock
rust-toolchain.toml
src/lib.rs
tests/container_conformance.rs
tests/nost_conformance.rs
"

for required_file in $required_files; do
  if [ ! -e "$required_file" ]; then
    echo "missing required file: $required_file" >&2
    exit 1
  fi
done

# LICENSE is verbatim upstream text and is intentionally not whitespace-scanned.
# Rust sources are covered by `cargo fmt`.
checked_text_files="
AGENTS.md
README.md
.gitignore
.editorconfig
.github/workflows/verify.yml
Cargo.toml
rust-toolchain.toml
scripts/verify-repository.sh
"

for checked_file in $checked_text_files; do
  if grep -nE '[[:blank:]]+$' "$checked_file"; then
    echo "trailing whitespace found in: $checked_file" >&2
    exit 1
  fi
done

if [ ! -L CLAUDE.md ] || [ "$(readlink CLAUDE.md)" != "AGENTS.md" ]; then
  echo "CLAUDE.md must be a symlink to AGENTS.md" >&2
  exit 1
fi

if ! grep -q '^ *Server Side Public License$' LICENSE; then
  echo "LICENSE must be the Server Side Public License, Version 1" >&2
  exit 1
fi

if ! grep -q '^ *VERSION 1, OCTOBER 16, 2018$' LICENSE; then
  echo "LICENSE must be the Server Side Public License, Version 1" >&2
  exit 1
fi

# Section 13 is the clause that distinguishes the SSPL from the GPL family.
# Requiring it also detects a truncated license file.
if ! grep -q 'Offering the Program as a Service' LICENSE; then
  echo "LICENSE is missing Server Side Public License section 13" >&2
  exit 1
fi

git diff --check

# The Rust command set from the root contract.
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to verify the Engine" >&2
  exit 1
fi

cargo fmt --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features

# The Engine must not grow a command surface, a listener, or a second contract
# copy. These are the ownership boundaries in AGENTS.md, and nothing else checks
# them.
if grep -rnE '^[[:space:]]*fn main\(' src >/dev/null 2>&1; then
  echo "nostdb-core must not contain a binary entry point; a CLI belongs to nostdb-cli" >&2
  exit 1
fi

if grep -rnE '\b(TcpListener|TcpStream|UnixListener|HttpServer)\b' src >/dev/null 2>&1; then
  echo "nostdb-core must not contain a network or IPC listener" >&2
  exit 1
fi

if [ -e src/bin ]; then
  echo "nostdb-core must not declare binary targets" >&2
  exit 1
fi

echo "nostdb-core verification passed"
