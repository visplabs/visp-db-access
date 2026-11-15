//! Metadata records the query pipeline reads: a cluster and its policy.
use crate::{error::ApiError, policy::Policy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stored cluster configuration; credential ciphertext is never serialized.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ClusterRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub engine: String,
    pub provider: String,
    pub region: String,
    pub environment: String,
    pub host: String,
    pub port: i32,
    pub database: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_enc: String,
    pub tls_mode: String,
    pub replica_host: Option<String>,
    pub replica_port: Option<i32>,
    pub tags: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
/// Retrieve a cluster by primary key.
pub async fn cluster(pool: &sqlx::PgPool, id: Uuid) -> Result<ClusterRecord, ApiError> {
    Ok(sqlx::query_as("SELECT * FROM clusters WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await?)
}
/// Load the full cluster policy.
pub async fn policy(pool: &sqlx::PgPool, id: Uuid) -> Result<Policy, ApiError> {
    let value: serde_json::Value =
        sqlx::query_scalar("SELECT policy FROM cluster_policies WHERE cluster_id=$1")
            .bind(id)
            .fetch_one(pool)
            .await?;
    serde_json::from_value(value).map_err(|_| ApiError::internal())
}
