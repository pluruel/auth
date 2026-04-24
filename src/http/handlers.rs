// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use axum::{
    extract::{Extension, Path, State},
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

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is alive", body = HealthResp),
    ),
)]
pub async fn health() -> Json<HealthResp> {
    Json(HealthResp { status: "ok" })
}

#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = RegisterReq,
    responses(
        (status = 201, description = "User created", body = UserRead),
        (status = 409, description = "Email already registered", body = ErrorResp),
        (status = 422, description = "Validation error", body = ErrorResp),
    ),
)]
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

    let mut groups = vec![];
    if state.config.superuser_emails.iter().any(|e| e == &row.email) {
        let admin = ensure_group(&state, crate::ADMIN_GROUP).await?;
        user_group_user::ActiveModel {
            user_id: Set(row.id),
            user_group_id: Set(admin.id),
        }
        .insert(&state.db)
        .await?;
        groups.push(admin.name);
    }

    Ok((
        StatusCode::CREATED,
        Json(UserRead {
            id: row.id,
            email: row.email,
            full_name: row.full_name,
            is_active: row.is_active,
            groups,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body(
        content = LoginForm,
        description = "Login form body",
        content_type = "application/x-www-form-urlencoded",
    ),
    responses(
        (status = 200, description = "Access + refresh token pair", body = TokenPair),
        (status = 401, description = "Incorrect email or password", body = ErrorResp),
        (status = 403, description = "Inactive user", body = ErrorResp),
        (status = 422, description = "Validation error", body = ErrorResp),
    ),
)]
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

#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    request_body = RefreshReq,
    responses(
        (status = 200, description = "A fresh access token", body = AccessTokenResp),
        (status = 401, description = "Invalid or expired refresh token", body = ErrorResp),
        (status = 422, description = "Validation error", body = ErrorResp),
    ),
)]
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

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    request_body(
        content = RefreshReq,
        description = "Refresh token to revoke. Idempotent — unknown tokens also return 204.",
    ),
    responses(
        (status = 204, description = "Logged out"),
    ),
)]
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

#[utoipa::path(
    get,
    path = "/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current user", body = UserRead),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
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

#[utoipa::path(
    get,
    path = "/auth/.well-known/jwks.json",
    tag = "auth",
    responses(
        (status = 200, description = "JWKS (RFC 7517) with Ed25519 public keys"),
    ),
)]
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

#[utoipa::path(
    get,
    path = "/auth/groups",
    tag = "groups",
    responses(
        (status = 200, description = "All groups", body = [GroupRead]),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
        (status = 403, description = "Admin privileges required", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_groups(
    State(state): State<AppState>,
) -> Result<Json<Vec<GroupRead>>, AppError> {
    let rows = UserGroup::find()
        .order_by_asc(user_group::Column::Name)
        .all(&state.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|m| GroupRead { id: m.id, name: m.name })
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/auth/groups",
    tag = "groups",
    request_body = GroupCreateReq,
    responses(
        (status = 201, description = "Group created", body = GroupRead),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
        (status = 403, description = "Admin privileges required", body = ErrorResp),
        (status = 409, description = "Group name already in use", body = ErrorResp),
        (status = 422, description = "Validation error", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_group(
    State(state): State<AppState>,
    Json(payload): Json<GroupCreateReq>,
) -> Result<(StatusCode, Json<GroupRead>), AppError> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::Unprocessable("name required"));
    }

    let existing = UserGroup::find()
        .filter(user_group::Column::Name.eq(&name))
        .one(&state.db)
        .await?;
    if existing.is_some() {
        return Err(AppError::Conflict("Group name already in use"));
    }

    let row = user_group::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name),
    }
    .insert(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(GroupRead { id: row.id, name: row.name }),
    ))
}

#[utoipa::path(
    get,
    path = "/auth/groups/{group_id}",
    tag = "groups",
    params(("group_id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Group with members", body = GroupDetail),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
        (status = 403, description = "Admin privileges required", body = ErrorResp),
        (status = 404, description = "Group not found", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_group(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupDetail>, AppError> {
    let group = UserGroup::find_by_id(group_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let member_ids: Vec<Uuid> = UserGroupUser::find()
        .filter(user_group_user::Column::UserGroupId.eq(group_id))
        .all(&state.db)
        .await?
        .into_iter()
        .map(|m| m.user_id)
        .collect();

    let members = if member_ids.is_empty() {
        vec![]
    } else {
        User::find()
            .filter(user::Column::Id.is_in(member_ids))
            .order_by_asc(user::Column::Email)
            .all(&state.db)
            .await?
            .into_iter()
            .map(|u| GroupMember {
                id: u.id,
                email: u.email,
                full_name: u.full_name,
            })
            .collect()
    };

    Ok(Json(GroupDetail {
        id: group.id,
        name: group.name,
        members,
    }))
}

#[utoipa::path(
    patch,
    path = "/auth/groups/{group_id}",
    tag = "groups",
    request_body = GroupUpdateReq,
    params(("group_id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Group updated", body = GroupRead),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
        (status = 403, description = "Admin privileges required", body = ErrorResp),
        (status = 404, description = "Group not found", body = ErrorResp),
        (status = 409, description = "Group name already in use", body = ErrorResp),
        (status = 422, description = "Validation error", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn update_group(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(payload): Json<GroupUpdateReq>,
) -> Result<Json<GroupRead>, AppError> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::Unprocessable("name required"));
    }

    let group = UserGroup::find_by_id(group_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if group.name != name {
        let conflict = UserGroup::find()
            .filter(user_group::Column::Name.eq(&name))
            .one(&state.db)
            .await?;
        if conflict.is_some() {
            return Err(AppError::Conflict("Group name already in use"));
        }
    }

    let mut active: user_group::ActiveModel = group.into();
    active.name = Set(name);
    let row = active.update(&state.db).await?;

    Ok(Json(GroupRead { id: row.id, name: row.name }))
}

#[utoipa::path(
    delete,
    path = "/auth/groups/{group_id}",
    tag = "groups",
    params(("group_id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
        (status = 403, description = "Admin privileges required", body = ErrorResp),
        (status = 404, description = "Group not found", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_group(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let res = UserGroup::delete_by_id(group_id).exec(&state.db).await?;
    if res.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/groups/{group_id}/members",
    tag = "groups",
    request_body = GroupMemberAddReq,
    params(("group_id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 204, description = "Member added (idempotent)"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
        (status = 403, description = "Admin privileges required", body = ErrorResp),
        (status = 404, description = "Group or user not found", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn add_group_member(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(payload): Json<GroupMemberAddReq>,
) -> Result<StatusCode, AppError> {
    if UserGroup::find_by_id(group_id).one(&state.db).await?.is_none() {
        return Err(AppError::NotFound);
    }
    if User::find_by_id(payload.user_id).one(&state.db).await?.is_none() {
        return Err(AppError::NotFound);
    }

    let existing = UserGroupUser::find_by_id((payload.user_id, group_id))
        .one(&state.db)
        .await?;
    if existing.is_some() {
        return Ok(StatusCode::NO_CONTENT);
    }

    user_group_user::ActiveModel {
        user_id: Set(payload.user_id),
        user_group_id: Set(group_id),
    }
    .insert(&state.db)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/auth/groups/{group_id}/members/{user_id}",
    tag = "groups",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("user_id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 204, description = "Member removed (idempotent)"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResp),
        (status = 403, description = "Admin privileges required", body = ErrorResp),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn remove_group_member(
    State(state): State<AppState>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    UserGroupUser::delete_by_id((user_id, group_id))
        .exec(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
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

async fn ensure_group(state: &AppState, name: &str) -> Result<user_group::Model, AppError> {
    if let Some(g) = UserGroup::find()
        .filter(user_group::Column::Name.eq(name))
        .one(&state.db)
        .await?
    {
        return Ok(g);
    }
    let row = user_group::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name.to_string()),
    }
    .insert(&state.db)
    .await?;
    Ok(row)
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
