// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait};
use sea_orm_migration::MigratorTrait;
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use auth_rs::{
    config::Config,
    entities::{prelude::*, user_group},
    error::AppError,
    http,
    migrations::Migrator,
    security::Security,
    state::AppState,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    init_tracing();

    tracing::info!(
        project = cfg.project_name,
        addr = %cfg.addr,
        issuer = cfg.jwt_issuer,
        audiences = ?cfg.jwt_audiences,
        "starting auth_rs"
    );

    let security = Security::new(
        &cfg.jwt_private_key_path,
        &cfg.jwt_public_key_path,
        cfg.jwt_issuer.clone(),
        cfg.jwt_audiences.clone(),
        cfg.access_token_expire_minutes,
        cfg.refresh_token_expire_days,
    )?;

    let db = connect_db(&cfg.database_url).await?;

    Migrator::up(&db, None).await?;

    bootstrap(&db, &cfg).await?;

    let state = AppState {
        db,
        security,
        config: Arc::new(cfg.clone()),
    };

    let router = http::router(state);
    let listener = TcpListener::bind(&cfg.addr).await?;
    tracing::info!(addr = %cfg.addr, "listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn connect_db(url: &str) -> anyhow::Result<DatabaseConnection> {
    let mut opt = ConnectOptions::new(url.to_string());
    opt.max_connections(10)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .sqlx_logging(false);
    Ok(Database::connect(opt).await?)
}

async fn bootstrap(db: &DatabaseConnection, cfg: &Config) -> Result<(), AppError> {
    for name in cfg.default_user_groups.values() {
        let exists = UserGroup::find()
            .filter(user_group::Column::Name.eq(name))
            .one(db)
            .await?;
        if exists.is_none() {
            user_group::ActiveModel {
                id: Set(Uuid::new_v4()),
                name: Set(name.clone()),
            }
            .insert(db)
            .await?;
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("auth_rs=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async { signal::ctrl_c().await.ok(); };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
