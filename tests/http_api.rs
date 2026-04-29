// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
//
// End-to-end HTTP tests. These exercise the full axum router against a real
// Postgres (the docker-compose dev stack on :5433 by default).
//
// Override the target DB with TEST_DATABASE_URL.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::Utc;
use common::*;
use ed25519_dalek::SigningKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use serde_json::json;
use uuid::Uuid;

// -----------------------------------------------------------------------
// Happy path
// -----------------------------------------------------------------------

#[tokio::test]
async fn health_endpoint() {
    let (app, _) = setup().await;
    let resp = send(&app, json_req("GET", "/health", json!(null))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn jwks_endpoint_structure() {
    let (app, _) = setup().await;
    let resp = send(
        &app,
        json_req("GET", "/auth/.well-known/jwks.json", json!(null)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["alg"], "EdDSA");
}

#[tokio::test]
async fn full_auth_flow() {
    let (app, email) = setup().await;

    // 1. register
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": "pw12345", "full_name": "Test User"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = read_json(resp).await;
    assert_eq!(body["email"], email);
    assert_eq!(body["full_name"], "Test User");
    assert_eq!(body["is_active"], true);
    assert_eq!(body["groups"].as_array().unwrap().len(), 0);

    // 2. login
    let resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", "pw12345")],
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let access = body["access_token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(body["token_type"], "bearer");
    assert_eq!(body["expires_in"], 15 * 60);
    assert!(!access.is_empty());
    assert!(!refresh.is_empty());

    // 3. /me with bearer
    let resp = send(&app, bearer_req("GET", "/auth/me", &access)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["email"], email);

    // 4. refresh — rotation: get back a new token pair
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let new_access = body["access_token"].as_str().unwrap();
    assert!(!new_access.is_empty());
    let new_refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert!(!new_refresh.is_empty());
    assert_ne!(new_refresh, refresh, "rotated refresh token must differ from original");

    // 5. logout using the NEW refresh token (original was already revoked by rotation)
    let resp = send(
        &app,
        json_req("POST", "/auth/logout", json!({"refresh_token": new_refresh})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 6. refresh with the new (now-revoked-by-logout) token must fail
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": new_refresh})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// -----------------------------------------------------------------------
// Failure modes
// -----------------------------------------------------------------------

#[tokio::test]
async fn register_rejects_duplicate_email() {
    let (app, email) = setup().await;
    let body = json!({"email": email, "password": "pw12345"});

    let r1 = send(&app, json_req("POST", "/auth/register", body.clone())).await;
    assert_eq!(r1.status(), StatusCode::CREATED);

    let r2 = send(&app, json_req("POST", "/auth/register", body)).await;
    assert_eq!(r2.status(), StatusCode::CONFLICT);
    let b = read_json(r2).await;
    assert_eq!(b["detail"], "Email already registered");
}

#[tokio::test]
async fn login_rejects_wrong_password() {
    let (app, email) = setup().await;
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": "pw12345"}),
        ),
    )
    .await;

    let resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", "wrong")],
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(read_json(resp).await["detail"], "Incorrect email or password");
}

#[tokio::test]
async fn login_rejects_unknown_email() {
    let (app, email) = setup().await;
    let resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", "whatever")],
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_requires_bearer() {
    let (app, _) = setup().await;
    // No Authorization header.
    let resp = send(
        &app,
        axum::http::Request::builder()
            .method("GET")
            .uri("/auth/me")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer")
    );
}

#[tokio::test]
async fn me_rejects_garbage_token() {
    let (app, _) = setup().await;
    let resp = send(&app, bearer_req("GET", "/auth/me", "not-a-jwt")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rejects_unknown_token() {
    let (app, _) = setup().await;
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/refresh",
            json!({"refresh_token": "made-up-token-that-does-not-exist"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_with_unknown_token_still_204() {
    let (app, _) = setup().await;
    // Logout is idempotent: unknown tokens are treated as already-logged-out.
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/logout",
            json!({"refresh_token": "nope"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn register_superuser_email_gets_admin_group() {
    use uuid::Uuid;
    let superuser_email = format!("admin_{}@example.com", Uuid::new_v4().simple());
    let (app, _) = common::setup_with_superuser_emails(vec![superuser_email.clone()]).await;

    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": superuser_email, "password": "pw12345", "full_name": "Admin"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = read_json(resp).await;
    assert_eq!(body["email"], superuser_email);
    let groups = body["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0], "ADMIN");
}

// -----------------------------------------------------------------------
// Category 1: JWT tampering & confusion
// -----------------------------------------------------------------------

/// Register a user and log in, returning (router, access_token, user_uuid, priv_pem).
async fn setup_registered_user_with_keys() -> (axum::Router, String, String, String) {
    let (app, email, priv_pem) = setup_with_keys().await;
    let password = "pw_adversarial_test";

    // register
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": password}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let reg_body = read_json(resp).await;
    let user_id = reg_body["id"].as_str().unwrap().to_string();

    // login
    let resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", password)],
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let login_body = read_json(resp).await;
    let access = login_body["access_token"].as_str().unwrap().to_string();

    (app, access, user_id, priv_pem)
}

/// Build a valid access claims body for the given user uuid/email.
fn valid_claims(sub: &str, email: &str) -> serde_json::Value {
    let now = Utc::now().timestamp();
    json!({
        "iss": "auth-svc",
        "aud": ["integration-test"],
        "sub": sub,
        "email": email,
        "groups": [],
        "typ": "access",
        "iat": now,
        "nbf": now,
        "exp": now + 900_i64
    })
}

#[tokio::test]
async fn jwt_alg_none_rejected() {
    let (app, _access, user_id, _priv_pem) = setup_registered_user_with_keys().await;

    // Hand-craft a JWT with alg:none. jsonwebtoken refuses to emit this, so we
    // build the three segments manually.
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"alg":"none","typ":"JWT"}"#);
    let now = Utc::now().timestamp();
    let payload_json = json!({
        "iss": "auth-svc",
        "aud": ["integration-test"],
        "sub": user_id,
        "email": "algnone@test.com",
        "groups": [],
        "typ": "access",
        "iat": now,
        "exp": now + 900_i64
    });
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.to_string());
    let token = format!("{header}.{payload}.");

    let resp = send(&app, bearer_req("GET", "/auth/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_foreign_key_rejected() {
    let (app, _access, user_id, _priv_pem) = setup_registered_user_with_keys().await;

    // Generate a completely separate Ed25519 keypair (not the server's).
    let foreign_signing = SigningKey::generate(&mut OsRng);
    let foreign_verifying = foreign_signing.verifying_key();
    let foreign_priv_pem = foreign_signing
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string();
    let _foreign_pub_pem = foreign_verifying
        .to_public_key_pem(LineEnding::LF)
        .expect("spki pem");

    let email = format!("foreign_{}@test.com", Uuid::new_v4().simple());
    let claims = valid_claims(&user_id, &email);
    let token = sign_eddsa(&foreign_priv_pem, &claims);

    let resp = send(&app, bearer_req("GET", "/auth/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_payload_tampered_rejected() {
    let (app, access, _user_id, _priv_pem) = setup_registered_user_with_keys().await;

    // Verify the real token works first.
    let check = send(&app, bearer_req("GET", "/auth/me", &access)).await;
    assert_eq!(check.status(), StatusCode::OK);

    // Flip one character in the payload (middle) segment.
    let parts: Vec<&str> = access.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 segments");
    let mut payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode payload");
    // Flip the last byte.
    let idx = payload_bytes.len() - 1;
    payload_bytes[idx] ^= 0xFF;
    let tampered_payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
    let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let resp = send(&app, bearer_req("GET", "/auth/me", &tampered)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_wrong_iss_rejected() {
    let (app, _access, user_id, priv_pem) = setup_registered_user_with_keys().await;
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": "evil",
        "aud": ["integration-test"],
        "sub": user_id,
        "email": "wrongiss@test.com",
        "groups": [],
        "typ": "access",
        "iat": now,
        "nbf": now,
        "exp": now + 900_i64
    });
    let token = sign_eddsa(&priv_pem, &claims);
    let resp = send(&app, bearer_req("GET", "/auth/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_wrong_aud_rejected() {
    let (app, _access, user_id, priv_pem) = setup_registered_user_with_keys().await;
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": "auth-svc",
        "aud": ["nope"],
        "sub": user_id,
        "email": "wrongaud@test.com",
        "groups": [],
        "typ": "access",
        "iat": now,
        "nbf": now,
        "exp": now + 900_i64
    });
    let token = sign_eddsa(&priv_pem, &claims);
    let resp = send(&app, bearer_req("GET", "/auth/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_refresh_typ_as_access_rejected() {
    let (app, _access, user_id, priv_pem) = setup_registered_user_with_keys().await;
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": "auth-svc",
        "aud": ["integration-test"],
        "sub": user_id,
        "email": "refreshtyp@test.com",
        "groups": [],
        "typ": "refresh",
        "iat": now,
        "nbf": now,
        "exp": now + 900_i64
    });
    let token = sign_eddsa(&priv_pem, &claims);
    let resp = send(&app, bearer_req("GET", "/auth/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_expired_rejected() {
    let (app, _access, user_id, priv_pem) = setup_registered_user_with_keys().await;
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": "auth-svc",
        "aud": ["integration-test"],
        "sub": user_id,
        "email": "expired@test.com",
        "groups": [],
        "typ": "access",
        "iat": now - 7200_i64,
        "nbf": now - 7200_i64,
        "exp": now - 3600_i64   // 1 hour in the past (well beyond default 60s leeway)
    });
    let token = sign_eddsa(&priv_pem, &claims);
    let resp = send(&app, bearer_req("GET", "/auth/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_sub_not_uuid_rejected() {
    let (app, _access, _user_id, priv_pem) = setup_registered_user_with_keys().await;
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": "auth-svc",
        "aud": ["integration-test"],
        "sub": "not-a-uuid",
        "email": "badsub@test.com",
        "groups": [],
        "typ": "access",
        "iat": now,
        "nbf": now,
        "exp": now + 900_i64
    });
    let token = sign_eddsa(&priv_pem, &claims);
    let resp = send(&app, bearer_req("GET", "/auth/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// -----------------------------------------------------------------------
// Category 2: Authorization header variants
// -----------------------------------------------------------------------

#[tokio::test]
async fn auth_header_empty_token_after_space_rejected() {
    let (app, _) = setup().await;
    // "Bearer " with nothing after the space
    let req = Request::builder()
        .method("GET")
        .uri("/auth/me")
        .header("authorization", "Bearer ")
        .body(Body::empty())
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_header_bearer_no_space_rejected() {
    let (app, _) = setup().await;
    // "Bearer" with no space and no token
    let req = Request::builder()
        .method("GET")
        .uri("/auth/me")
        .header("authorization", "Bearer")
        .body(Body::empty())
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_header_basic_scheme_rejected() {
    let (app, _) = setup().await;
    let req = Request::builder()
        .method("GET")
        .uri("/auth/me")
        .header("authorization", "Basic abc123")
        .body(Body::empty())
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_header_lowercase_bearer_accepted() {
    // The server's extract_bearer is case-insensitive on the scheme,
    // so "bearer <token>" must be accepted (200), not rejected.
    let (app, email) = setup().await;
    let password = "pw_lowercase_bearer";
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": password}),
        ),
    )
    .await;
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", password)],
        ),
    )
    .await;
    let login_body = read_json(login_resp).await;
    let access = login_body["access_token"].as_str().unwrap().to_string();

    // Use lowercase "bearer" scheme.
    let req = Request::builder()
        .method("GET")
        .uri("/auth/me")
        .header("authorization", format!("bearer {access}"))
        .body(Body::empty())
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// -----------------------------------------------------------------------
// Category 3: Admin route access control
// -----------------------------------------------------------------------

/// All the admin route requests we want to probe (no auth header).
fn admin_requests_no_auth() -> Vec<Request<Body>> {
    let fake_uuid = Uuid::new_v4().to_string();
    let fake_uuid2 = Uuid::new_v4().to_string();
    vec![
        Request::builder()
            .method("GET")
            .uri("/auth/groups")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/auth/groups")
            .header("content-type", "application/json")
            .body(Body::from(json!({"name":"test"}).to_string()))
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri(format!("/auth/groups/{fake_uuid}"))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("PATCH")
            .uri(format!("/auth/groups/{fake_uuid}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"name":"x"}).to_string()))
            .unwrap(),
        Request::builder()
            .method("DELETE")
            .uri(format!("/auth/groups/{fake_uuid}"))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri(format!("/auth/groups/{fake_uuid}/members"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"user_id": fake_uuid2}).to_string()))
            .unwrap(),
        Request::builder()
            .method("DELETE")
            .uri(format!("/auth/groups/{fake_uuid}/members/{fake_uuid2}"))
            .body(Body::empty())
            .unwrap(),
    ]
}

/// Same requests but with an Authorization header.
fn admin_requests_with_bearer(token: &str) -> Vec<Request<Body>> {
    let fake_uuid = Uuid::new_v4().to_string();
    let fake_uuid2 = Uuid::new_v4().to_string();
    vec![
        Request::builder()
            .method("GET")
            .uri("/auth/groups")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/auth/groups")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(json!({"name":"test"}).to_string()))
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri(format!("/auth/groups/{fake_uuid}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("PATCH")
            .uri(format!("/auth/groups/{fake_uuid}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(json!({"name":"x"}).to_string()))
            .unwrap(),
        Request::builder()
            .method("DELETE")
            .uri(format!("/auth/groups/{fake_uuid}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri(format!("/auth/groups/{fake_uuid}/members"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(json!({"user_id": fake_uuid2}).to_string()))
            .unwrap(),
        Request::builder()
            .method("DELETE")
            .uri(format!("/auth/groups/{fake_uuid}/members/{fake_uuid2}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    ]
}

#[tokio::test]
async fn admin_routes_require_bearer() {
    let (app, _) = setup().await;
    for req in admin_requests_no_auth() {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let resp = send(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Expected 401 for {method} {uri} with no auth"
        );
    }
}

#[tokio::test]
async fn admin_route_forbidden_for_regular_user() {
    let (app, email) = setup().await;
    let password = "pw_regular_user";
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": password}),
        ),
    )
    .await;
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", password)],
        ),
    )
    .await;
    let login_body = read_json(login_resp).await;
    let access = login_body["access_token"].as_str().unwrap().to_string();

    for req in admin_requests_with_bearer(&access) {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let resp = send(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Expected 403 for {method} {uri} with non-admin bearer"
        );
    }
}

#[tokio::test]
async fn admin_can_list_and_create_groups() {
    let superuser_email = format!("admin_{}@example.com", Uuid::new_v4().simple());
    let (app, _) =
        common::setup_with_superuser_emails(vec![superuser_email.clone()]).await;

    let password = "pw_admin_groups";
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": superuser_email, "password": password}),
        ),
    )
    .await;
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &superuser_email), ("password", password)],
        ),
    )
    .await;
    let login_body = read_json(login_resp).await;
    let access = login_body["access_token"].as_str().unwrap().to_string();

    // List groups — should succeed (200).
    let list_resp = send(&app, bearer_req("GET", "/auth/groups", &access)).await;
    assert_eq!(list_resp.status(), StatusCode::OK);

    // Create a uniquely-named group to avoid collisions across test runs.
    let group_name = format!("QA_{}", Uuid::new_v4().simple());
    let create_resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/auth/groups")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::from(json!({"name": group_name}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    // List again — the new group must appear.
    let list_resp2 = send(&app, bearer_req("GET", "/auth/groups", &access)).await;
    assert_eq!(list_resp2.status(), StatusCode::OK);
    let list_body = read_json(list_resp2).await;
    let names: Vec<String> = list_body
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["name"].as_str().map(String::from))
        .collect();
    assert!(
        names.iter().any(|n| n == &group_name),
        "new group must appear in group list: {names:?}"
    );
}

#[tokio::test]
async fn admin_invalid_uuid_in_path_returns_400() {
    // Admin passes middleware, axum path extraction for non-UUID → 400.
    let superuser_email = format!("admin_{}@example.com", Uuid::new_v4().simple());
    let (app, _) =
        common::setup_with_superuser_emails(vec![superuser_email.clone()]).await;

    let password = "pw_admin_bad_uuid";
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": superuser_email, "password": password}),
        ),
    )
    .await;
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &superuser_email), ("password", password)],
        ),
    )
    .await;
    let login_body = read_json(login_resp).await;
    let access = login_body["access_token"].as_str().unwrap().to_string();

    let resp = send(
        &app,
        Request::builder()
            .method("GET")
            .uri("/auth/groups/not-a-uuid")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// -----------------------------------------------------------------------
// Category 4: Input validation & normalization
// -----------------------------------------------------------------------

#[tokio::test]
async fn register_rejects_empty_email() {
    let (app, _) = setup().await;
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": "", "password": "pw12345"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = read_json(resp).await;
    assert_eq!(body["detail"], "email and password required");
}

#[tokio::test]
async fn register_rejects_whitespace_only_email() {
    let (app, _) = setup().await;
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": "   ", "password": "pw12345"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = read_json(resp).await;
    assert_eq!(body["detail"], "email and password required");
}

#[tokio::test]
async fn register_rejects_empty_password() {
    let (app, email) = setup().await;
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": ""}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = read_json(resp).await;
    assert_eq!(body["detail"], "email and password required");
}

#[tokio::test]
async fn email_case_normalization_roundtrip() {
    let unique = Uuid::new_v4().simple().to_string();
    let upper_email = format!("USER_{unique}@Example.COM");
    let lower_email = format!("user_{unique}@example.com");

    let (app, _) = setup().await;

    // Register with mixed-case email.
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": upper_email, "password": "pw_case_norm"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Login with lowercase version.
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &lower_email), ("password", "pw_case_norm")],
        ),
    )
    .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_body = read_json(login_resp).await;
    let access = login_body["access_token"].as_str().unwrap().to_string();

    // /me must return the lowercased email.
    let me_resp = send(&app, bearer_req("GET", "/auth/me", &access)).await;
    assert_eq!(me_resp.status(), StatusCode::OK);
    let me_body = read_json(me_resp).await;
    assert_eq!(me_body["email"], lower_email);
}

#[tokio::test]
async fn admin_group_create_whitespace_name_rejected() {
    let superuser_email = format!("admin_{}@example.com", Uuid::new_v4().simple());
    let (app, _) =
        common::setup_with_superuser_emails(vec![superuser_email.clone()]).await;

    let password = "pw_ws_group";
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": superuser_email, "password": password}),
        ),
    )
    .await;
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &superuser_email), ("password", password)],
        ),
    )
    .await;
    let login_body = read_json(login_resp).await;
    let access = login_body["access_token"].as_str().unwrap().to_string();

    let resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/auth/groups")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::from(json!({"name": "   "}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = read_json(resp).await;
    assert_eq!(body["detail"], "name required");
}

#[tokio::test]
async fn refresh_with_empty_token_rejected() {
    let (app, _) = setup().await;
    let resp = send(
        &app,
        json_req(
            "POST",
            "/auth/refresh",
            json!({"refresh_token": ""}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = read_json(resp).await;
    assert_eq!(body["detail"], "refresh_token required");
}

/// Each call to /auth/refresh rotates the token: the old token is revoked and
/// a brand-new refresh token is returned. Re-presenting the original token must
/// be rejected.
#[tokio::test]
async fn refresh_rotates_and_old_token_rejected() {
    let (app, email) = setup().await;

    // register + login
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": "pw_rotate_test"}),
        ),
    )
    .await;
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", "pw_rotate_test")],
        ),
    )
    .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_body = read_json(login_resp).await;
    let r1 = login_body["refresh_token"].as_str().unwrap().to_string();

    // first refresh — captures r2
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": r1})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let r2 = body["refresh_token"].as_str().unwrap().to_string();
    assert!(!r2.is_empty());
    assert_ne!(r2, r1, "rotated token must differ from original");

    // re-present r1 — must be rejected (token was already rotated/revoked)
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": r1})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Reuse detection: presenting an already-revoked refresh token causes all of
/// that user's active refresh tokens to be revoked as a theft signal.
#[tokio::test]
async fn refresh_reuse_revokes_all_sibling_tokens() {
    let (app, email) = setup().await;

    // register + login
    send(
        &app,
        json_req(
            "POST",
            "/auth/register",
            json!({"email": email, "password": "pw_reuse_test"}),
        ),
    )
    .await;
    let login_resp = send(
        &app,
        form_req(
            "POST",
            "/auth/login",
            &[("username", &email), ("password", "pw_reuse_test")],
        ),
    )
    .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_body = read_json(login_resp).await;
    let r1 = login_body["refresh_token"].as_str().unwrap().to_string();

    // normal rotation: r1 -> r2
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": r1})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let r2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(r2, r1);

    // replay r1 (already revoked) — triggers reuse detection, revokes all tokens
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": r1})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // r2 must also be revoked now (reuse detection wiped all siblings)
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": r2})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
