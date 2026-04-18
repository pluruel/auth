// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::config::Config;
use crate::security::Security;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub security: Security,
    pub config: Arc<Config>,
}
