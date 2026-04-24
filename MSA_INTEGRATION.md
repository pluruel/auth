# MSA Integration Spec

Contract for integrating `auth-svc` as the central authentication service in an MSA. Read this before writing any user/auth-related code in a downstream service.

> **For AI agents**: this document is structured for AI consumption — imperative, normative, and self-contained. Add it to your working context (e.g. paste it into `CLAUDE.md`, reference it in the system prompt, or attach it when prompting) before generating integration code for a consumer service. Human-oriented prose, onboarding narrative, and checklists are deliberately omitted.

---

## MUST — Violating these breaks security or MSA boundaries

### DB boundaries

- Downstream services MUST NOT access `auth-svc`'s Postgres directly. Obtain user data only via JWT claims or the `/auth/me` / `/auth/groups` APIs.
- When referencing a user from a downstream table, store the JWT `sub` (UUID) as a **plain column with no foreign key**. A foreign key into `auth-svc`'s DB physically couples services and breaks MSA.
  ```sql
  CREATE TABLE document (
      id       uuid PRIMARY KEY,
      owner_id uuid NOT NULL,  -- auth-svc.user.id. No FK.
      ...
  );
  ```
- Do NOT replicate user email / name into downstream DBs. Use the JWT `email` claim or call `/auth/me` on demand. Replication causes sync bugs.

### Token verification

- Downstream services MUST verify every incoming JWT locally on every request: signature, `iss`, `aud`, `exp`, `typ`.
- `iss` must match the `JWT_ISSUER` configured in `auth-svc` (default `"auth-svc"`) exactly.
- `aud` is an **array**. The downstream checks whether **its own service name is contained in the array** — not exact equality.
- `typ` MUST be `"access"`. This prevents refresh tokens from being used as access tokens.
- Algorithm is fixed to **EdDSA (Ed25519)**. Do NOT accept `alg: "none"` or any other algorithm.
- `kid` is not emitted. If your JWT library enforces `kid` matching, disable it or configure it to operate against a single-key JWKS.

### auth-svc configuration

- The `JWT_AUDIENCE` env on `auth-svc` MUST list **every downstream service name** that will consume tokens. That way a single token is valid across all of them.
  ```
  JWT_AUDIENCE=["gpt-storage","billing","notifications"]
  ```
- The `ADMIN` group name is **hardcoded** (`auth_rs::ADMIN_GROUP`; the `require_admin` middleware checks the literal string). Renaming requires a code change. Do NOT arbitrarily change the `ADMIN` key/value in `DEFAULT_USER_GROUPS`.
- Do NOT put a wildcard (`*`) in `BACKEND_CORS_ORIGINS`. Credentialed CORS requires an explicit origin list; a wildcard causes `tower-http` to panic.

### Token transport

- The client must send the access token to a service via exactly one of:
  - `Authorization: Bearer <access_token>` header (preferred).
  - `Cookie: Authorization=Bearer <access_token>` (note: the **`Bearer `** scheme is required inside the cookie too).
- `/auth/login` uses **`application/x-www-form-urlencoded`**. Sending JSON returns `422`. Field names are `username` (which carries the email) and `password`.
- Do NOT store refresh tokens in `localStorage`. Persist them only in an httpOnly + Secure + SameSite cookie or in a server-side session.

---

## SHOULD — Recommended

- Cache the JWKS (`GET /auth/.well-known/jwks.json`) locally in each downstream service. The response carries `Cache-Control: public, max-age=300`, so a 5-minute refresh interval is a reasonable default.
- Keep access-token TTL short (15 minutes by default). Refresh-token TTL defaults to 14 days. Logout propagates only after the access TTL expires, so do not extend the access TTL.
- Terminate TLS at a reverse proxy (Caddy, Nginx, etc.). `auth-svc` listens on plain HTTP at `0.0.0.0:8001` — do not try to attach TLS to the service directly.
- Decide access policy for `/docs` (Swagger UI) in production. Block it at the reverse proxy if it should be internal-only.
- Bootstrap initial administrators by adding their emails to `SUPERUSER_EMAILS` so they are auto-added to the `ADMIN` group on registration. This is safer than calling `POST /auth/groups/{admin_id}/members` manually.

---

## API reference

All `/auth/*` paths are mounted under `API_PREFIX` (default `/auth`). `/health`, `/docs`, and `/api-docs/openapi.json` are not prefixed. See Swagger (`/docs`) for the full spec.

### Public (no authentication)

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/auth/register` | JSON `{email, password, full_name?}` | `201 UserRead` |
| POST | `/auth/login` | **form-urlencoded** `username=&password=` | `200 TokenPair` |
| POST | `/auth/refresh` | JSON `{refresh_token}` | `200 AccessTokenResp` (only access is reissued; refresh is unchanged) |
| POST | `/auth/logout` | JSON `{refresh_token}` (optional) | `204`, idempotent |
| GET  | `/auth/.well-known/jwks.json` | — | JWKS (Ed25519) |
| GET  | `/health` | — | `{"status":"ok"}` |

### Bearer required

| Method | Path | Authorization | Response |
|---|---|---|---|
| GET | `/auth/me` | logged in | `UserRead` |

### Bearer + ADMIN group

| Method | Path |
|---|---|
| GET    | `/auth/groups` |
| POST   | `/auth/groups` |
| GET    | `/auth/groups/{group_id}` |
| PATCH  | `/auth/groups/{group_id}` |
| DELETE | `/auth/groups/{group_id}` |
| POST   | `/auth/groups/{group_id}/members` |
| DELETE | `/auth/groups/{group_id}/members/{user_id}` |

### Error format

All errors use `{"detail": "..."}`. Status codes:
- `401` missing, malformed, or expired token
- `403` insufficient privileges or inactive user
- `404` not found
- `409` duplicate email or group name
- `422` missing/invalid fields

---

## JWT claim layout

```json
{
  "iss": "auth-svc",
  "aud": ["your-service", "other-service"],
  "sub": "aae2b11e-0d9b-422c-99d9-5ed62a11ea44",
  "email": "alice@example.com",
  "groups": ["ADMIN", "READ_ONLY"],
  "iat": 1735000000,
  "nbf": 1735000000,
  "exp": 1735000900,
  "typ": "access"
}
```

Header is `{"alg":"EdDSA","typ":"JWT"}` — no `kid`.

---

## Downstream middleware implementation guide

Required behavior:
1. At boot, fetch JWKS → cache in memory. Periodic refresh (5 min), plus a single forced refresh on verification failure.
2. On each request, extract the token from either the `Authorization` header or the `Authorization` cookie, stripping the `Bearer ` scheme.
3. Perform every check listed in the MUST section above.
4. Attach the verified claims to the request context (e.g. `req.user = {id, email, groups}`) for handlers to consume.
5. Implement group-based authorization by checking membership in the `groups` array.

### Node.js + jose reference

```js
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(
  new URL("http://localhost:8001/auth/.well-known/jwks.json"),
);

export async function requireAuth(req, res, next) {
  const h = req.headers.authorization ?? "";
  if (!h.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ detail: "Not authenticated" });
  }
  try {
    const { payload } = await jwtVerify(h.slice(7).trim(), JWKS, {
      issuer: "auth-svc",
      audience: "your-service",
    });
    if (payload.typ !== "access") throw new Error("wrong typ");
    req.user = { id: payload.sub, email: payload.email, groups: payload.groups };
    next();
  } catch {
    res.status(401).json({ detail: "Could not validate credentials" });
  }
}

export const requireGroup = (name) => (req, res, next) =>
  req.user?.groups?.includes(name)
    ? next()
    : res.status(403).json({ detail: `Requires group: ${name}` });
```

JWT libraries by language: Python `PyJWT[crypto]` / `authlib`, Go `github.com/lestrrat-go/jwx/v2/jwt`, Rust `jsonwebtoken`. Beware older versions that lack EdDSA support.

---

## Common mistakes (stated directly, not softened)

- Sending JSON to `/auth/login` → `422`. Use form-urlencoded.
- Putting a bare token in a cookie without the `Bearer ` scheme → `401`.
- Downstream querying `auth-svc`'s DB directly → breaks MSA boundaries.
- Expecting exact `aud` equality → fails. Check array containment.
- Requiring `kid` → fails. No `kid` is emitted.
- Renaming the ADMIN group → the middleware checks the literal, so the code must be updated too.
- Persisting refresh tokens in `localStorage` → leaks via XSS.

---

## Code pointers

- Routes: [src/http/mod.rs:23-79](src/http/mod.rs#L23-L79)
- Auth middleware: [src/http/middleware.rs](src/http/middleware.rs)
- Handlers: [src/http/handlers.rs](src/http/handlers.rs)
- DTOs: [src/http/dto.rs](src/http/dto.rs)
- JWT signing / verification / JWKS: [src/security.rs](src/security.rs)
- Migration (schema): [src/migrations/m20260418_000001_init.sql](src/migrations/m20260418_000001_init.sql)
- Env vars: [src/config.rs](src/config.rs), [.env.example](.env.example)
- Single source of truth for the HTTP contract (tests): [tests/http_api.rs](tests/http_api.rs)
