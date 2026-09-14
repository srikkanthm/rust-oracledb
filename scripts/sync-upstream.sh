#!/usr/bin/env bash
#
# Sync this fork with upstream oracle/rust-oracledb (merge-based).
#
# Merging (rather than rebasing) keeps every commit reachable, so the exact
# `rev` pinned by SQLHighland's [patch.crates-io] stays fetchable.
#
# Usage: scripts/sync-upstream.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! git remote get-url upstream >/dev/null 2>&1; then
  git remote add upstream https://github.com/oracle/rust-oracledb.git
fi

git fetch upstream

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is dirty; commit or stash first." >&2
  exit 1
fi

git checkout main

behind=$(git rev-list --count main..upstream/main)
if [ "$behind" -eq 0 ]; then
  echo "Already up to date with upstream/main ($(git rev-parse --short upstream/main))."
  exit 0
fi

echo "Merging ${behind} upstream commit(s)..."
if ! git merge --no-edit upstream/main; then
  echo >&2
  echo "Merge conflicts. Resolve them, then:" >&2
  echo "  git add -A && git commit --no-edit" >&2
  echo "Conflict-prone files: src/client/mod.rs, src/messages/auth.rs," >&2
  echo "  src/transport.rs, src/messages/connect.rs," >&2
  echo "  src/client/capabilities.rs, Cargo.toml, README.md" >&2
  exit 1
fi

echo "Running checks..."
cargo fmt --check
cargo clippy --all-targets -- -D warnings
# The integration tests need RSO_TEST_ADMIN_PASSWORD etc.; unit tests do not.
cargo test --lib

echo
echo "Synced to $(git rev-parse HEAD)"
echo "Next:"
echo "  git push origin main"
echo "  re-pin SQLHighland Cargo.toml [patch.crates-io] rev to this SHA"
echo "  (bump the 'oracledb' requirement if upstream changed the crate version)"
