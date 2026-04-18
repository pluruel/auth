# auth_rs

Auth service in Rust: register / login / refresh / logout / me, EdDSA JWTs, group-based authorization, OpenAPI 3.1 + Swagger UI.

Stack:

- **axum** 0.7 on tokio — HTTP
- **SeaORM** 1.1 (sqlx-postgres) — ORM
- **sea-orm-migration** — embedded SQL migrations
- **jsonwebtoken** — EdDSA JWT
- **bcrypt** — password hashing
- **ed25519-dalek** + **pkcs8** — key loading / keygen binary
- **tower-http** — CORS / timeout / tracing middleware
- **tracing** + **tracing-subscriber** — structured (JSON) logging
- **utoipa** + **utoipa-swagger-ui** (`vendored`) — OpenAPI 3.1 spec + Swagger UI

---

## Endpoints

| Method | Path                              | Notes                              |
|--------|-----------------------------------|------------------------------------|
| POST   | `/auth/register`                  | JSON body                          |
| POST   | `/auth/login`                     | `application/x-www-form-urlencoded`|
| POST   | `/auth/refresh`                   | JSON body                          |
| POST   | `/auth/logout`                    | JSON body (optional)               |
| GET    | `/auth/me`                        | Bearer access token                |
| GET    | `/auth/.well-known/jwks.json`     | public keys                        |
| GET    | `/health`                         | liveness                           |
| GET    | `/docs`                           | Swagger UI                         |
| GET    | `/api-docs/openapi.json`          | OpenAPI 3.1 spec                   |

Prefix is configurable via `API_PREFIX` (applies to `/auth/*` only, not `/docs` or `/health`).

---

## Environment variables

### Required

| Name                | Example             |
|---------------------|---------------------|
| `POSTGRES_SERVER`   | `auth_db_postgres`  |
| `POSTGRES_USER`     | `auth`              |
| `POSTGRES_PASSWORD` | `change_me`         |
| `POSTGRES_DB`       | `auth` (default)    |
| `POSTGRES_PORT`     | `5432` (default)    |

### JWT

| Name                           | Default                       |
|--------------------------------|-------------------------------|
| `JWT_ISSUER`                   | `auth-svc`                    |
| `JWT_AUDIENCE`                 | `auth-svc`                    |
| `JWT_KEY_ID`                   | `auth-svc-key-1`              |
| `JWT_PRIVATE_KEY_PATH`         | `/app/keys/jwt_private.pem`   |
| `JWT_PUBLIC_KEY_PATH`          | `/app/keys/jwt_public.pem`    |
| `ACCESS_TOKEN_EXPIRE_MINUTES`  | `15`                          |
| `REFRESH_TOKEN_EXPIRE_DAYS`    | `14`                          |

### Misc

| Name                        | Default                                       |
|-----------------------------|-----------------------------------------------|
| `BACKEND_CORS_ORIGINS`      | `[]` (JSON array or comma-separated)          |
| `DEFAULT_USER_GROUPS`       | `{}` (JSON object)                            |
| `FIRST_SUPERUSER_EMAIL`     | unset — optional                              |
| `FIRST_SUPERUSER_PASSWORD`  | unset — optional                              |
| `ADMIN_EMAILS`              | unset — comma-separated or JSON array         |
| `PROJECT_NAME`              | `auth-svc`                                    |
| `API_PREFIX`                | `/auth`                                       |
| `ADDR`                      | `0.0.0.0:8001`                                |
| `RUST_LOG`                  | `auth_rs=info,tower_http=info`                |

---

## First-time setup

```bash
# 1. Config
cp .env.example .env
$EDITOR .env

# 2. Keys — the 'keygen' binary is built alongside the server.
cargo run --bin keygen

# 3. Bring up the dev stack
./run.sh                       # docker compose -f docker-compose.dev.yaml up --build -d

# 4. Smoke test
curl http://localhost:8001/health
curl http://localhost:8001/auth/.well-known/jwks.json

# 5. Open Swagger UI
open http://localhost:8001/docs          # or whatever opens URLs on your OS
```

Migrations run automatically on startup (`Migrator::up(&db, None)`).

---

## Local dev without Docker

```bash
# Needs a reachable Postgres and PEM keys on disk.
cp .env.example .env
cargo run --bin keygen
# edit .env to point POSTGRES_SERVER / etc. at localhost
RUST_LOG=auth_rs=debug cargo run
```

---

## Layout

```
auth_rs/
├── Cargo.toml
├── Dockerfile                 # multi-stage, distroless cc-nonroot
├── docker-compose.yaml        # prod: postgres + auth + nginx
├── docker-compose.dev.yaml    # dev: postgres + auth (expose 8001/5433)
├── nginx.conf
├── .env.example
├── run.sh / stop.sh
├── keys/                      # jwt_{private,public}.pem (gitignored)
└── src/
    ├── main.rs                # entrypoint: config → migrate → bootstrap → axum
    ├── lib.rs                 # re-exports modules for main & tests
    ├── bin/
    │   └── keygen.rs          # Ed25519 keypair generator
    ├── config.rs              # env → Config
    ├── error.rs               # AppError + IntoResponse
    ├── state.rs               # AppState (db + security + config)
    ├── security.rs            # bcrypt, EdDSA JWT, JWKS, refresh helpers
    ├── entities/              # SeaORM entities
    │   ├── user.rs
    │   ├── user_group.rs
    │   ├── user_group_user.rs
    │   └── refresh_token.rs
    ├── http/
    │   ├── mod.rs             # router + CORS/timeout layers + /docs mount
    │   ├── dto.rs             # request/response types (+ ToSchema derives)
    │   ├── handlers.rs        # register/login/refresh/logout/me/jwks (+ #[utoipa::path])
    │   ├── middleware.rs      # Bearer auth extractor
    │   └── openapi.rs         # ApiDoc + bearer_auth security scheme
    └── migrations/
        ├── mod.rs             # Migrator
        ├── m20260418_000001_init.rs
        └── m20260418_000001_init.sql
```

---

## Useful reading

- [axum docs](https://docs.rs/axum) + [examples](https://github.com/tokio-rs/axum/tree/main/examples)
- [SeaORM cookbook](https://www.sea-ql.org/SeaORM/)
- [rauthy](https://github.com/sebadob/rauthy) — production Rust OIDC server
  (axum + sqlx), great reference for auth-domain Rust patterns.
- [jsonwebtoken examples](https://github.com/Keats/jsonwebtoken/tree/master/examples)
