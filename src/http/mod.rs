// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
pub mod dto;
pub mod handlers;
pub mod middleware;

use std::time::Duration;

use axum::{
    http::{header, HeaderValue, Method, StatusCode},
    routing::{get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let cors = build_cors(&state.config.backend_cors_origins);
    let prefix = state.config.api_prefix.clone();

    let public = Router::new()
        .route("/register", post(handlers::register))
        .route("/login", post(handlers::login))
        .route("/refresh", post(handlers::refresh))
        .route("/logout", post(handlers::logout))
        .route("/.well-known/jwks.json", get(handlers::jwks));

    let private = Router::new()
        .route("/me", get(handlers::me))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_bearer,
        ));

    let auth = Router::new().merge(public).merge(private);

    Router::new()
        .route("/health", get(handlers::health))
        .nest(&prefix, auth)
        .with_state(state)
        .layer(cors)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(TraceLayer::new_for_http())
}

fn build_cors(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        return CorsLayer::new();
    }
    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    // Credentialed CORS: origins / headers / methods must be explicit lists
    // (tower-http panics if credentials=true is combined with Any).
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
        ])
        .expose_headers([header::AUTHORIZATION])
        .allow_credentials(true)
        .max_age(Duration::from_secs(300))
}
