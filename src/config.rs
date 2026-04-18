// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use std::collections::HashMap;
use std::env;

use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct Config {
    pub project_name: String,
    pub api_prefix: String,
    pub addr: String,

    pub access_token_expire_minutes: i64,
    pub refresh_token_expire_days: i64,

    pub jwt_private_key_path: String,
    pub jwt_public_key_path: String,
    pub jwt_key_id: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,

    pub backend_cors_origins: Vec<String>,

    pub database_url: String,

    pub default_user_groups: HashMap<String, String>,
    pub first_superuser_email: Option<String>,
    pub first_superuser_password: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        let _ = dotenvy::dotenv();

        let postgres_server = require("POSTGRES_SERVER")?;
        let postgres_user = require("POSTGRES_USER")?;
        let postgres_password = require("POSTGRES_PASSWORD")?;
        let postgres_db = getenv("POSTGRES_DB", "auth");
        let postgres_port = getenv("POSTGRES_PORT", "5432");

        let database_url = format!(
            "postgres://{}:{}@{}:{}/{}",
            urlencoding::encode(&postgres_user),
            urlencoding::encode(&postgres_password),
            postgres_server,
            postgres_port,
            postgres_db,
        );

        Ok(Self {
            project_name: getenv("PROJECT_NAME", "auth-svc"),
            api_prefix: getenv("API_PREFIX", "/auth"),
            addr: getenv("ADDR", "0.0.0.0:8001"),

            access_token_expire_minutes: parse_env_int("ACCESS_TOKEN_EXPIRE_MINUTES", 15)?,
            refresh_token_expire_days: parse_env_int("REFRESH_TOKEN_EXPIRE_DAYS", 14)?,

            jwt_private_key_path: getenv("JWT_PRIVATE_KEY_PATH", "/app/keys/jwt_private.pem"),
            jwt_public_key_path: getenv("JWT_PUBLIC_KEY_PATH", "/app/keys/jwt_public.pem"),
            jwt_key_id: getenv("JWT_KEY_ID", "auth-svc-key-1"),
            jwt_issuer: getenv("JWT_ISSUER", "auth-svc"),
            jwt_audience: getenv("JWT_AUDIENCE", "auth-svc"),

            backend_cors_origins: parse_cors(&env::var("BACKEND_CORS_ORIGINS").unwrap_or_default()),

            database_url,

            default_user_groups: parse_groups(&env::var("DEFAULT_USER_GROUPS").unwrap_or_default())?,
            first_superuser_email: opt("FIRST_SUPERUSER_EMAIL"),
            first_superuser_password: opt("FIRST_SUPERUSER_PASSWORD"),
        })
    }
}

fn require(key: &str) -> Result<String, AppError> {
    env::var(key).map_err(|_| AppError::Config(format!("{key} is required")))
}

fn getenv(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_string(),
    }
}

fn opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

fn parse_env_int(key: &str, default: i64) -> Result<i64, AppError> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v
            .parse::<i64>()
            .map_err(|e| AppError::Config(format!("{key}: {e}"))),
        _ => Ok(default),
    }
}

fn parse_cors(raw: &str) -> Vec<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return vec![];
    }
    if raw.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(raw) {
            return v;
        }
    }
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_groups(raw: &str) -> Result<HashMap<String, String>, AppError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    serde_json::from_str::<HashMap<String, String>>(raw)
        .map_err(|e| AppError::Config(format!("DEFAULT_USER_GROUPS: {e}")))
}

// minimal percent-encoder for DB URL user/password
mod urlencoding {
    pub fn encode(s: &str) -> String {
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
}
