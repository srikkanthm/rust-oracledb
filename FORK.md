# SQLHighland fork of `oracledb` (rust-oracledb)

This repository is a fork of
[`oracle/rust-oracledb`](https://github.com/oracle/rust-oracledb) maintained for
[SQLHighland](https://github.com/srikkanthm/sqlhighland). It is consumed there
as a pinned git patch:

```toml
[patch.crates-io]
oracledb = { git = "https://github.com/srikkanthm/rust-oracledb", rev = "<sha>" }
```

## Base and remotes

- `upstream` → `https://github.com/oracle/rust-oracledb` (`main`)
- `origin` → `https://github.com/srikkanthm/rust-oracledb` (`main`)
- Fork base: upstream `466c453` (the `26.0.0-beta.4` era).

## Fork-only changes

All fork work is additive; new modules keep the conflict surface small.

- **Query cancellation** (`src/connection/*`, `src/transport.rs`,
  `src/error.rs`, `src/packet.rs`, `README.md`): plain-TCP out-of-band break
  (Unix), a `CancelHandle` API, `ErrorKind::Cancelled`.
- **Native Network Encryption / ANO** (`src/advanced_nego.rs`,
  `src/encryption.rs`, hooks in `src/client/mod.rs`, `src/transport.rs`,
  `src/messages/connect.rs`, `src/constants.rs`, `src/response/mod.rs`,
  `src/lib.rs`): AES-CBC packet crypto, Diffie-Hellman, SHA-2 checksums.
- **Oracle 10G (O3LOGON) password verifiers** (`src/messages/auth.rs`,
  `src/encryption.rs`): DES-derived verifier, AES-128 session keys, PBKDF2
  combo key.
- Dev probes: `examples/ano_probe.rs`, `examples/ano_cancel.rs`.
- The ANO debug trace is **opt-in** via `SQLHIGHLAND_ANO_TRACE`.

## Syncing with upstream

We **merge** `upstream/main` into `main` — never rebase/force-push. Merging
keeps every historical commit reachable, so the `rev` pinned by SQLHighland
(and by SQLHighland's `Cargo.lock`) keeps resolving.

```sh
scripts/sync-upstream.sh
```

The script fetches upstream, merges it into `main`, runs
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
`cargo test --lib`, then prints the new commit SHA. Then:

1. `git push origin main`
2. Re-pin SQLHighland's `[patch.crates-io] rev` to the new SHA.
3. If upstream bumped the crate `version`, update SQLHighland's `oracledb`
   dependency requirement to match.
4. Bump SQLHighland's own version and tag a release.

Conflict-prone files (because the fork edits them): `src/client/mod.rs`,
`src/messages/auth.rs`, `src/transport.rs`, `src/messages/connect.rs`,
`src/client/capabilities.rs`, `Cargo.toml`, `README.md`.

`Cargo.lock` is intentionally gitignored, so it never conflicts here.

## Bookkeeping

Tag a synced/released state as `sh-<sqlhighland-version>` (e.g. `sh-0.2.13`)
so a known-good driver revision is easy to find. Old commits remain reachable
because we only ever merge.
