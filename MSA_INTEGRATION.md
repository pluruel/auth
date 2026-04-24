# MSA Integration Spec

`auth-svc`를 MSA 중앙 인증 서비스로 통합할 때의 규약. 다운스트림 서비스에 유저/인증 관련 코드를 넣기 전에 이 문서를 먼저 읽을 것.

---

## MUST — 위반 시 보안/경계가 깨짐

### DB 경계

- auth-svc의 Postgres에 다운스트림이 **직접 접근하지 마라**. 유저 정보는 JWT 클레임 또는 `/auth/me`, `/auth/groups` API로만 얻는다.
- 다운스트림 테이블에서 유저를 참조할 때는 **JWT `sub`(UUID)을 FK 없는 단순 컬럼**으로 저장한다. auth-svc DB에 FK를 거는 순간 MSA가 아니다.
  ```sql
  CREATE TABLE document (
      id       uuid PRIMARY KEY,
      owner_id uuid NOT NULL,  -- auth-svc.user.id. FK 금지.
      ...
  );
  ```
- 유저 이메일/이름을 다운스트림 DB에 **복제하지 마라**. 필요하면 JWT 클레임(`email`) 또는 `/auth/me`를 쓴다. 동기화 버그의 원인이 된다.

### 토큰 검증

- 다운스트림은 **모든 요청마다 로컬에서 JWT를 검증한다**. 서명·`iss`·`aud`·`exp`·`typ`을 전부 검사한다.
- `iss`는 auth-svc 배포의 `JWT_ISSUER`(기본 `"auth-svc"`)와 정확히 일치해야 한다.
- `aud`는 **배열**이고, 다운스트림은 **배열에 자기 서비스 이름이 포함**되는지 본다. 완전 일치가 아니다.
- `typ`은 반드시 `"access"` — refresh 토큰이 access인 척 쓰이는 것을 막는다.
- 알고리즘은 **EdDSA (Ed25519)** 고정. `alg: "none"` 이나 다른 알고리즘을 허용하지 마라.
- `kid`는 발행되지 않는다. 라이브러리가 kid 매칭을 강제하면 끄거나, 단일 키 JWKS로 동작하도록 구성한다.

### auth-svc 설정

- auth-svc의 `JWT_AUDIENCE` env에 **모든 다운스트림 서비스 이름을 나열한다.** 그래야 토큰 한 장이 여러 서비스에서 통한다.
  ```
  JWT_AUDIENCE=["gpt-storage","billing","notifications"]
  ```
- `ADMIN` 그룹명은 **하드코딩되어 있다** (`auth_rs::ADMIN_GROUP`, `require_admin` 미들웨어가 리터럴 검사). 다른 이름으로 바꾸려면 코드 수정 필요. `DEFAULT_USER_GROUPS`의 `ADMIN` 키/값을 임의로 바꾸지 마라.
- `BACKEND_CORS_ORIGINS`에 와일드카드(`*`)를 넣지 마라 — credentialed CORS는 명시적 오리진 목록이 필요하고, 넣으면 tower-http가 panic한다.

### 토큰 전송

- 클라이언트 → 서비스 토큰 전달은 다음 중 하나만:
  - `Authorization: Bearer <access_token>` 헤더 (기본)
  - `Cookie: Authorization=Bearer <access_token>` (쿠키에도 **스킴 `Bearer `** 필수)
- `/auth/login`은 **`application/x-www-form-urlencoded`** 다. JSON으로 보내면 `422`. 필드명은 `username`(이메일을 담음) / `password`.
- **refresh 토큰은 localStorage에 저장하지 마라.** httpOnly + Secure + SameSite 쿠키 또는 서버사이드 세션에만 저장.

---

## SHOULD — 권장

- JWKS(`GET /auth/.well-known/jwks.json`)는 **다운스트림에서 로컬 캐싱**한다. 응답에 `Cache-Control: public, max-age=300`이 붙어 있으니 5분 주기 갱신을 기본으로.
- access TTL은 짧게 (기본 15분). refresh TTL은 기본 14일. 로그아웃은 access TTL만큼 지연되므로 access를 길게 잡지 마라.
- 리버스 프록시(Caddy/Nginx 등)가 TLS를 종단한다. auth-svc는 평문 HTTP로 `0.0.0.0:8001`에 listen — TLS를 직접 붙이려 하지 마라.
- 운영 환경에서 `/docs` (Swagger UI) 공개 여부는 정책적으로 결정한다. 내부 전용이면 리버스 프록시에서 차단.
- 초기 관리자는 `SUPERUSER_EMAILS`에 이메일을 넣어 자동 ADMIN 그룹 부여. 수동으로 `POST /auth/groups/{admin_id}/members`를 호출하는 것보다 안전.

---

## API 레퍼런스

모든 `/auth/*`는 `API_PREFIX`(기본 `/auth`) 아래. `/health`, `/docs`, `/api-docs/openapi.json`은 prefix 무시. 스펙 전체는 Swagger(`/docs`) 참조.

### 공개 (인증 불필요)

| Method | Path | Body | 응답 |
|---|---|---|---|
| POST | `/auth/register` | JSON `{email, password, full_name?}` | `201 UserRead` |
| POST | `/auth/login` | **form-urlencoded** `username=&password=` | `200 TokenPair` |
| POST | `/auth/refresh` | JSON `{refresh_token}` | `200 AccessTokenResp` (access만 재발급, refresh는 그대로) |
| POST | `/auth/logout` | JSON `{refresh_token}` (선택) | `204` idempotent |
| GET  | `/auth/.well-known/jwks.json` | — | JWKS (Ed25519) |
| GET  | `/health` | — | `{"status":"ok"}` |

### Bearer 필요

| Method | Path | 권한 | 응답 |
|---|---|---|---|
| GET | `/auth/me` | 로그인 | `UserRead` |

### Bearer + ADMIN 그룹

| Method | Path |
|---|---|
| GET    | `/auth/groups` |
| POST   | `/auth/groups` |
| GET    | `/auth/groups/{group_id}` |
| PATCH  | `/auth/groups/{group_id}` |
| DELETE | `/auth/groups/{group_id}` |
| POST   | `/auth/groups/{group_id}/members` |
| DELETE | `/auth/groups/{group_id}/members/{user_id}` |

### 에러 포맷

전부 `{"detail": "..."}`. 상태 코드:
- `401` 토큰 없음/잘못됨/만료
- `403` 권한 부족 / 비활성 유저
- `404` not found
- `409` 이메일·그룹명 중복
- `422` 필드 누락

---

## JWT 클레임 구조

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

헤더는 `{"alg":"EdDSA","typ":"JWT"}` — `kid` 없음.

---

## 다운스트림 미들웨어 구현 지침

필수 동작:
1. 부팅 시 JWKS fetch → 메모리 캐시. 주기적 리프레시(5분) 또는 검증 실패 시 한 번 강제 리프레시.
2. 요청마다 `Authorization` 헤더 또는 `Authorization` 쿠키에서 `Bearer ` 제거 후 토큰 추출.
3. 위 MUST 섹션의 검증을 전부 수행.
4. 검증된 클레임을 요청 컨텍스트에 넣어서(`req.user = {id, email, groups}`) 핸들러가 쓰도록 한다.
5. 그룹 기반 인가는 `groups` 배열 포함 여부 체크.

### Node.js + jose 레퍼런스

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

언어별 JWT 라이브러리: Python `PyJWT[crypto]` / `authlib`, Go `github.com/lestrrat-go/jwx/v2/jwt`, Rust `jsonwebtoken`. EdDSA 미지원 구버전 주의.

---

## 흔한 실수 (돌려 말하지 않고 직접)

- `/auth/login`에 JSON → `422`. form-urlencoded로 보낼 것.
- 쿠키에 토큰만 넣고 `Bearer ` 생략 → `401`.
- 다운스트림이 auth-svc DB를 직접 조회 → MSA 경계 파괴.
- `aud` 완전 일치를 기대 → 실패. 배열 포함 여부로 검사.
- `kid` 강제 → 실패. kid를 발행하지 않는다.
- ADMIN 그룹명을 변경 → 미들웨어가 리터럴을 검사하므로 코드까지 고쳐야 함.
- refresh를 localStorage에 저장 → XSS 유출.

---

## 코드 포인터

- 라우트: [src/http/mod.rs:23-79](src/http/mod.rs#L23-L79)
- 인증 미들웨어: [src/http/middleware.rs](src/http/middleware.rs)
- 핸들러: [src/http/handlers.rs](src/http/handlers.rs)
- DTO: [src/http/dto.rs](src/http/dto.rs)
- JWT 서명/검증/JWKS: [src/security.rs](src/security.rs)
- 마이그레이션(스키마): [src/migrations/m20260418_000001_init.sql](src/migrations/m20260418_000001_init.sql)
- 환경변수: [src/config.rs](src/config.rs), [.env.example](.env.example)
- HTTP 계약의 단일 출처(테스트): [tests/http_api.rs](tests/http_api.rs)
