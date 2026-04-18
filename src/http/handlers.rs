// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use axum::{
    extract::{Extension, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use uuid::Uuid;

use crate::{
    entities::{prelude::*, refresh_token, user, user_group, user_group_user},
    error::AppError,
    http::dto::*,
    http::middleware::AuthUser,
    security::Security,
    state::AppState,
};

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterReq>,
) -> Result<(StatusCode, Json<UserRead>), AppError> {
    let email = payload.email.trim().to_lowercase();
    if email.is_empty() || payload.password.is_empty() {
        return Err(AppError::Unprocessable("email and password required"));
    }

    let existing = User::find()
        .filter(user::Column::Email.eq(&email))
        .one(&state.db)
        .await?;
    if existing.is_some() {
        return Err(AppError::Conflict("Email already registered"));
    }

    let hashed = Security::hash_password(&payload.password)?;
    let now = Utc::now().naive_utc();

    let row = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email),
        hashed_password: Set(hashed),
        full_name: Set(payload.full_name),
        is_active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(UserRead {
            id: row.id,
            email: row.email,
            full_name: row.full_name,
            is_active: row.is_active,
            groups: vec![],
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<Json<TokenPair>, AppError> {
    let email = form.username.trim().to_lowercase();
    if email.is_empty() || form.password.is_empty() {
        return Err(AppError::Unprocessable("username and password required"));
    }

    let user = User::find()
        .filter(user::Column::Email.eq(&email))
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized("Incorrect email or password"))?;

    if !Security::verify_password(&form.password, &user.hashed_password) {
        return Err(AppError::Unauthorized("Incorrect email or password"));
    }
    if !user.is_active {
        return Err(AppError::Forbidden("Inactive user"));
    }

    let pair = issue_token_pair(&state, &user).await?;
    Ok(Json(pair))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshReq>,
) -> Result<Json<AccessTokenResp>, AppError> {
    if req.refresh_token.is_empty() {
        return Err(AppError::Unprocessable("refresh_token required"));
    }

    let token_hash = crate::security::hash_refresh_token(&req.refresh_token);
    let rt = RefreshToken::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash))
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized("Invalid or expired refresh token"))?;

    if rt.revoked || rt.expires_at < Utc::now().naive_utc() {
        return Err(AppError::Unauthorized("Invalid or expired refresh token"));
    }

    let user = User::find_by_id(rt.user_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized("User not available"))?;
    if !user.is_active {
        return Err(AppError::Unauthorized("User not available"));
    }

    let groups = load_groups(&state, user.id).await?;
    let access = state
        .security
        .create_access_token(&user.id.to_string(), &user.email, groups)?;

    Ok(Json(AccessTokenResp {
        access_token: access,
        token_type: "bearer",
        expires_in: state.security.access_ttl.num_seconds(),
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    body: Option<Json<RefreshReq>>,
) -> Result<StatusCode, AppError> {
    let Some(Json(req)) = body else {
        return Ok(StatusCode::NO_CONTENT);
    };
    if req.refresh_token.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let token_hash = crate::security::hash_refresh_token(&req.refresh_token);

    if let Some(rt) = RefreshToken::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash))
        .one(&state.db)
        .await?
    {
        let mut active: refresh_token::ActiveModel = rt.into();
        active.revoked = Set(true);
        active.update(&state.db).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn me(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<UserRead>, AppError> {
    let u = User::find_by_id(auth.id)
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized("Could not validate credentials"))?;
    let groups = load_groups(&state, u.id).await?;
    Ok(Json(UserRead {
        id: u.id,
        email: u.email,
        full_name: u.full_name,
        is_active: u.is_active,
        groups,
    }))
}

pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.security.jwks().to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public, max-age=300"),
    );
    (headers, body)
}

// ---- internal helpers ----

async fn issue_token_pair(state: &AppState, user: &user::Model) -> Result<TokenPair, AppError> {
    let groups = load_groups(state, user.id).await?;

    let access =
        state
            .security
            .create_access_token(&user.id.to_string(), &user.email, groups)?;

    let raw = crate::security::generate_refresh_token();
    let hashed = crate::security::hash_refresh_token(&raw);
    let now = Utc::now().naive_utc();

    refresh_token::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        token_hash: Set(hashed),
        expires_at: Set(now + state.security.refresh_ttl),
        revoked: Set(false),
        created_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(TokenPair {
        access_token: access,
        refresh_token: raw,
        token_type: "bearer",
        expires_in: state.security.access_ttl.num_seconds(),
    })
}

async fn load_groups(state: &AppState, user_id: Uuid) -> Result<Vec<String>, AppError> {
    let rows: Vec<String> = UserGroup::find()
        .select_only()
        .column(user_group::Column::Name)
        .inner_join(UserGroupUser)
        .filter(user_group_user::Column::UserId.eq(user_id))
        .order_by_asc(user_group::Column::Name)
        .into_tuple::<String>()
        .all(&state.db)
        .await?;
    Ok(rows)
}
