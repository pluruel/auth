// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{
    entities::prelude::*,
    error::AppError,
    state::AppState,
};
use sea_orm::EntityTrait;

/// Authenticated user info stashed into request extensions for handlers.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub groups: Vec<String>,
}

pub async fn require_bearer(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let raw = extract_bearer(&req).ok_or(AppError::Unauthorized("Not authenticated"))?;
    let claims = state.security.decode_access_token(&raw)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Could not validate credentials"))?;

    let user = User::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized("Could not validate credentials"))?;
    if !user.is_active {
        return Err(AppError::Unauthorized("Could not validate credentials"));
    }

    req.extensions_mut().insert(AuthUser {
        id: user.id,
        email: claims.email,
        groups: claims.groups,
    });

    Ok(next.run(req).await)
}

/// Authorization header first, then "Authorization" cookie. Scheme must be Bearer.
fn extract_bearer(req: &Request) -> Option<String> {
    let raw = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| cookie_value(req, "Authorization"));

    let raw = raw?;
    let mut parts = raw.splitn(2, ' ');
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn cookie_value(req: &Request, name: &str) -> Option<String> {
    let header = req
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    for pair in header.split(';') {
        let (k, v) = pair.trim().split_once('=')?;
        if k == name {
            return Some(v.to_string());
        }
    }
    None
}
