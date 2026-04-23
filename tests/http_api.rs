// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
//
// End-to-end HTTP tests. These exercise the full axum router against a real
// Postgres (the docker-compose dev stack on :5433 by default).
//
// Override the target DB with TEST_DATABASE_URL.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

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

    // 4. refresh
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let new_access = body["access_token"].as_str().unwrap();
    assert!(!new_access.is_empty());

    // 5. logout
    let resp = send(
        &app,
        json_req("POST", "/auth/logout", json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 6. refresh must now fail
    let resp = send(
        &app,
        json_req("POST", "/auth/refresh", json!({"refresh_token": refresh})),
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
