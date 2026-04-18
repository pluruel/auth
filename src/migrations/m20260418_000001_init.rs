// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260418_000001_init"
    }
}

const UP_SQL: &str = include_str!("m20260418_000001_init.sql");
const DOWN_SQL: &str = r#"
DROP TABLE IF EXISTS refresh_token;
DROP TABLE IF EXISTS user_group_user;
DROP TABLE IF EXISTS user_group;
DROP TABLE IF EXISTS "user";
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(UP_SQL)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(DOWN_SQL)
            .await?;
        Ok(())
    }
}
