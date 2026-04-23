# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build / run / test

```bash
# Build (cold builds are slow due to SeaORM macros; incremental is fast)
cargo build
cargo build --release

# Generate Ed25519 keypair into keys/ (required before first run)
cargo run --bin keygen

# Run locally — needs reachable Postgres + keys/*.pem, reads .env
RUST_LOG=auth_rs=debug cargo run

# Dev stack (Postgres on host port 15432, auth on 8001). Auto-generates keys.
./run.sh
./stop.sh
```

### Tests

Integration tests in `tests/http_api.rs` exercise the full axum router against a **real Postgres**. The dev stack's Postgres on `localhost:15432` is the default target; override with `TEST_DATABASE_URL`.

```bash
# All tests — requires Postgres reachable at TEST_DATABASE_URL
# (defaults to postgres://auth:change_me@localhost:15432/auth)
cargo test

# Single test
cargo test --test http_api full_auth_flow -- --nocapture

# Against an alternate DB
TEST_DATABASE_URL=postgres://user:pw@host:5432/db cargo test
```

`tests/common/mod.rs::setup()` runs migrations on each call and gives every test a UUID-suffixed email so tests can share a DB without colliding.

**Whenever you add or change a feature, you MUST add or update a test for it and run `cargo test` before reporting the work as complete.** The HTTP contract is only enforced by these end-to-end tests.

## Architecture

Startup flow (`main.rs`): `Config::from_env` → connect Postgres → `Migrator::up` (embedded SQL migrations run unconditionally on every boot) → `bootstrap` (seeds `DEFAULT_USER_GROUPS`) → build `AppState` → mount `http::router` → `axum::serve` with graceful shutdown on SIGINT/SIGTERM.

Module map:

- `state::AppState` — `db` + `Security` + `Arc<Config>`, cloned per-request by axum
- `security` — bcrypt password hashing, EdDSA sign/verify, JWKS export, refresh-token SHA-256 hashing. Stateless; built once at startup
- `entities/` — SeaORM models for `user`, `user_group`, `user_group_user`, `refresh_token`
- `migrations/` — embedded `m20260418_000001_init.sql` run via `sea-orm-migration`
- `http/mod.rs::router` — composes three layers of routes:
  - `public` (register/login/refresh/logout/jwks) — no auth
  - `private` (`/me` + `admin`) — wrapped by `middleware::require_bearer`
  - `admin` (`/groups/*`) — additionally wrapped by `middleware::require_admin`
  - All `/auth/*` routes are nested under `cfg.api_prefix` (configurable). `/health`, `/docs`, `/api-docs/openapi.json` are NOT prefixed.
- `http/openapi.rs` — utoipa `ApiDoc` aggregating handler `#[utoipa::path]` annotations + `bearer_auth` security scheme; served via `utoipa-swagger-ui` at `/docs`. **New handlers must be added to `ApiDoc::paths` and their DTOs to `components(schemas(...))`** or they vanish from Swagger.
- `error::AppError` — single error type implementing `IntoResponse`; handlers return `Result<_, AppError>` and the impl decides the status code + JSON body shape (`{"detail": "..."}`)

CORS: when `BACKEND_CORS_ORIGINS` is non-empty, credentialed CORS is enabled with explicit method/header lists (tower-http panics if `credentials=true` is combined with `Any`).

Admin authorization is group-based: users registering with emails in `SUPERUSER_EMAILS` are automatically added to the `ADMIN` group (constant `auth_rs::ADMIN_GROUP`); `require_admin` checks group membership on the JWT subject.

### Reverse proxy

**This docker-compose.yaml does NOT include a reverse proxy.** Deploy one (Caddy, Nginx, etc.) in a separate LXC container or VM to route external traffic to `auth:8001`.

**Dev stack (docker-compose.dev.yaml):** Uses `ports: "8001:8001"` to expose directly—no proxy needed.

## Conventions worth knowing

- Two binaries share the crate: `auth_rs` (server, `src/main.rs`) and `keygen` (Ed25519 PEM generator, `src/bin/keygen.rs`). `lib.rs` re-exports modules so both binaries and `tests/` can import them via `use auth_rs::...`.
- Logging: `tracing` with the JSON formatter; level via `RUST_LOG` env (default `auth_rs=info,tower_http=info`).
- Migrations are idempotent and always run on startup — there is no separate `migrate` subcommand.
- Refresh tokens are stored hashed (SHA-256 hex); only the hash is in `refresh_token` table, the raw token is returned once at login/refresh.

## Development workflow

**All code changes MUST be made via sub-agents. Do not edit files directly.**

Three-agent model for all server work:

**Agent roles:**
- **Server Developer (Sonnet)**: Code implementation + tests
- **Code Reviewer (Opus)**: Test validation + approval
- **Documentation Updater (Sonnet)**: Updates CLAUDE.md, .env.example based on code changes

**Requirements:**
- All changes require corresponding test in `tests/`
- `cargo test` must pass 100% before submission
- Reviewers approve only if all tests pass

---

## Style note

This document prioritizes brevity. Keep explanations concise—one sentence per idea, bullet lists over paragraphs. Readers should get context in one pass.
