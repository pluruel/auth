// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("config: {0}")]
    Config(String),

    #[error("internal: {0}")]
    Internal(String),

    #[error("db: {0}")]
    Db(#[from] sea_orm::DbErr),

    #[error("conflict: {0}")]
    Conflict(&'static str),

    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),

    #[error("forbidden: {0}")]
    Forbidden(&'static str),

    #[error("unprocessable: {0}")]
    Unprocessable(&'static str),

    #[error("not found")]
    NotFound,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, detail, www_auth) = match &self {
            AppError::Config(_) | AppError::Internal(_) | AppError::Db(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
                false,
            ),
            AppError::Conflict(m) => (StatusCode::CONFLICT, (*m).to_string(), false),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, (*m).to_string(), true),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, (*m).to_string(), false),
            AppError::Unprocessable(m) => {
                (StatusCode::UNPROCESSABLE_ENTITY, (*m).to_string(), false)
            }
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string(), false),
        };

        if matches!(&self, AppError::Internal(_) | AppError::Db(_)) {
            tracing::error!(error = %self, "request failed");
        }

        let mut headers = HeaderMap::new();
        if www_auth {
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        (status, headers, Json(json!({"detail": detail}))).into_response()
    }
}
