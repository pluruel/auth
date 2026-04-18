// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_group")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique, indexed)]
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::user_group_user::Entity")]
    UserGroupUser,
}

impl Related<super::user_group_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserGroupUser.def()
    }
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        super::user_group_user::Relation::User.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::user_group_user::Relation::UserGroup.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
