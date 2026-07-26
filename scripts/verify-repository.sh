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
"

for required_file in $required_files; do
  if [ ! -e "$required_file" ]; then
    echo "missing required file: $required_file" >&2
    exit 1
  fi
done

# LICENSE is verbatim upstream text and is intentionally not whitespace-scanned.
checked_text_files="
AGENTS.md
README.md
.gitignore
.editorconfig
.github/workflows/verify.yml
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

echo "nostdb-core verification passed"
