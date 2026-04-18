// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod openapi;

use std::time::Duration;

use axum::{
    http::{header, HeaderValue, Method, StatusCode},
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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

    let admin = Router::new()
        .route(
            "/groups",
            get(handlers::list_groups).post(handlers::create_group),
        )
        .route(
            "/groups/:group_id",
            get(handlers::get_group)
                .patch(handlers::update_group)
                .delete(handlers::delete_group),
        )
        .route(
            "/groups/:group_id/members",
            post(handlers::add_group_member),
        )
        .route(
            "/groups/:group_id/members/:user_id",
            delete(handlers::remove_group_member),
        )
        .route_layer(axum::middleware::from_fn(middleware::require_admin));

    let private = Router::new()
        .route("/me", get(handlers::me))
        .merge(admin)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_bearer,
        ));

    let auth = Router::new().merge(public).merge(private);

    Router::new()
        .route("/health", get(handlers::health))
        .nest(&prefix, auth)
        .merge(
            SwaggerUi::new("/docs")
                .url("/api-docs/openapi.json", openapi::ApiDoc::openapi()),
        )
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
