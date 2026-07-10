# CLAUDE.md

Guidance for working in this repository (Primal Blossom Server — a Nostr/Blossom media server).

## Building

The crate uses `sqlx::query!` macros, which verify SQL against a **live database at compile time**.
There is no `.sqlx` offline cache checked in, so a reachable `DATABASE_URL` is required to build.

### Prerequisites

- Build inside the Nix dev shell (provides the Rust nightly toolchain and native deps):
  ```bash
  nix develop
  ```
- A Postgres instance containing the blossom schema (tables `media_storage`, `filterlist`,
  `media_storage_priority`, `media_metadata_stripping`, `media_uploads_media_block_csam`, ...).

  The sibling `primal-server` project provides one. Enter its dev shell to start Postgres, which
  listens on a local port; its cache database holds the blossom tables:
  ```bash
  nix develop <path to the primal-server checkout>
  ```

### Release build

```bash
nix develop --command sh -c \
  'DATABASE_URL="postgresql://USER@HOST:PORT/DATABASE" cargo build --release --bin primal_blossom_server'
```

Output: `target/release/primal_blossom_server`.

Notes:
- Use `--bin primal_blossom_server` to build only the real binary. `src/bin/scratch.rs` is an
  untracked scratch file that does not compile (it calls `main_1` with a 2-arg fn where 3 are
  expected) and is unrelated to normal builds.
- If sqlx complains `set DATABASE_URL to use query macros online`, the database is unreachable —
  start the `primal-server` Postgres (above) or point `DATABASE_URL` at another DB with the schema.
- Alternatively, run `cargo sqlx prepare` against a live DB to generate a `.sqlx` offline cache so
  future builds don't need a database.

## Running

The server is started with the `serve` subcommand and a config file:

```bash
nix develop --command sh -c \
  'DATABASE_URL="postgresql://USER@HOST:PORT/DATABASE" \
   ./target/release/primal_blossom_server --config-file primal-blossom-server-config.json serve'
```

See `primal-blossom-server-config.json.sample` for config fields and `run.sh` for the
watch-and-restart wrapper used in development.
