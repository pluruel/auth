// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use utoipa::{
    openapi::security::{Http, HttpAuthScheme, SecurityScheme},
    Modify, OpenApi,
};

use super::{dto, handlers};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "auth_rs",
        version = env!("CARGO_PKG_VERSION"),
        description = "Standalone authentication service. EdDSA JWTs, bcrypt passwords, \
                       opaque SHA-256-hashed refresh tokens. Wire-compatible with the \
                       Python and Go ports.",
        contact(name = "Junnoh Lee", email = "pluruel@gmail.com"),
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "health", description = "Operational"),
    ),
    paths(
        handlers::health,
        handlers::register,
        handlers::login,
        handlers::refresh,
        handlers::logout,
        handlers::me,
        handlers::jwks,
    ),
    components(schemas(
        dto::RegisterReq,
        dto::LoginForm,
        dto::RefreshReq,
        dto::TokenPair,
        dto::AccessTokenResp,
        dto::UserRead,
        dto::ErrorResp,
        dto::HealthResp,
    )),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .as_mut()
            .expect("components registered by ToSchema derives");
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
        // Silence unused-import lint for `Http` when the builder pattern is used
        let _ = std::marker::PhantomData::<Http>;
    }
}
