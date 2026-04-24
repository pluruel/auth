// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
//
// Shared harness for integration tests.
//
// Needs a reachable Postgres instance. Defaults to the docker-compose.dev.yaml
// Postgres at `localhost:5433`, override with `TEST_DATABASE_URL`.

use std::collections::HashMap;
use std::sync::Arc;

use auth_rs::{
    config::Config, http, migrations::Migrator, security::Security, state::AppState,
};
use axum::body::Body;
use axum::http::{Request, Response};
use axum::Router;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

/// Build a fresh router + unique email so tests are independent even when
/// they hit a shared dev Postgres. Returns a short handle to both.
pub async fn setup() -> (Router, String) {
    setup_with_superuser_emails(vec![]).await
}

/// Like setup(), but with specified superuser emails.
pub async fn setup_with_superuser_emails(superuser_emails: Vec<String>) -> (Router, String) {
    let db = connect_test_db().await;
    Migrator::up(&db, None).await.expect("migrate");

    let (priv_pem, pub_pem) = gen_keypair();
    let security = Security::from_pems(
        &priv_pem,
        &pub_pem,
        "auth-svc".into(),
        vec!["integration-test".to_string()],
        15,
        14,
    )
    .expect("security");

    let config = Config {
        project_name: "auth-svc".into(),
        api_prefix: "/auth".into(),
        addr: "0.0.0.0:0".into(),
        access_token_expire_minutes: 15,
        refresh_token_expire_days: 14,
        jwt_private_key_path: String::new(),
        jwt_public_key_path: String::new(),
        jwt_issuer: "auth-svc".into(),
        jwt_audiences: vec!["integration-test".to_string()],
        backend_cors_origins: vec![],
        database_url: String::new(),
        default_user_groups: HashMap::new(),
        superuser_emails,
    };

    let state = AppState {
        db,
        security,
        config: Arc::new(config),
    };
    let app = http::router(state);
    let email = format!("t_{}@example.com", Uuid::new_v4().simple());
    (app, email)
}

async fn connect_test_db() -> DatabaseConnection {
    let url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://auth:change_me@localhost:15432/auth".to_string());
    let mut opt = ConnectOptions::new(url);
    opt.max_connections(5).sqlx_logging(false);
    Database::connect(opt).await.expect("connect test db")
}

fn gen_keypair() -> (String, String) {
    let s = SigningKey::generate(&mut OsRng);
    let v = s.verifying_key();
    let priv_pem = s
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string();
    let pub_pem = v.to_public_key_pem(LineEnding::LF).expect("spki pem");
    (priv_pem, pub_pem)
}

// --------- request helpers -----------------------------------------------

pub fn json_req(method: &str, path: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub fn form_req(method: &str, path: &str, form: &[(&str, &str)]) -> Request<Body> {
    let encoded: String = form
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(encoded))
        .unwrap()
}

pub fn bearer_req(method: &str, path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

// --------- response helpers ----------------------------------------------

pub async fn send(app: &Router, req: Request<Body>) -> Response<Body> {
    app.clone().oneshot(req).await.expect("router response")
}

pub async fn read_json(resp: Response<Body>) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

#[allow(dead_code)]
pub async fn read_bytes(resp: Response<Body>) -> Vec<u8> {
    resp.into_body().collect().await.unwrap().to_bytes().to_vec()
}

// Tiny percent-encoder to avoid bringing in urlencoding crate just for tests.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
