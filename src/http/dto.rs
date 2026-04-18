// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({"email":"admin@example.com","password":"pw12345","full_name":"Admin"}))]
pub struct RegisterReq {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({"username":"admin@example.com","password":"pw12345"}))]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({"refresh_token":"yZ5vNA4Ly_AcbIyQZf2qLxDaEuYfEan_i5vR1AT0UNdKl26seNU0KwstUWHARmXr"}))]
pub struct RefreshReq {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenPair {
    /// Short-lived EdDSA JWT access token (default TTL: 15 min).
    pub access_token: String,
    /// Opaque refresh token (default TTL: 14 days). Store it securely.
    pub refresh_token: String,
    /// Always `bearer`.
    #[schema(example = "bearer")]
    pub token_type: &'static str,
    /// Access-token lifetime in seconds.
    #[schema(example = 900)]
    pub expires_in: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccessTokenResp {
    pub access_token: String,
    #[schema(example = "bearer")]
    pub token_type: &'static str,
    #[schema(example = 900)]
    pub expires_in: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserRead {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    pub is_active: bool,
    pub groups: Vec<String>,
}

/// Generic error payload (`{"detail": "..."}`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResp {
    pub detail: String,
}

/// `/health` response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResp {
    #[schema(example = "ok")]
    pub status: &'static str,
}
