//! Who is asking, and the effective access that their grants give on a cluster.
use crate::{error::ApiError, records::ClusterRecord};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use vda_guard::AccessLevel;

/// The identity a request runs as, whatever door it came through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub user_id: Uuid,
    pub email: String,
    /// Organization administrators have admin access to every cluster.
    pub org_admin: bool,
}
/// Resolve the maximum level while ignoring expired grants.
pub fn resolve_level(
    admin: bool,
    grants: impl IntoIterator<Item = (AccessLevel, Option<DateTime<Utc>>)>,
    now: DateTime<Utc>,
) -> Option<AccessLevel> {
    if admin {
        return Some(AccessLevel::Admin);
    }
    grants
        .into_iter()
        .filter(|(_, expiry)| expiry.is_none_or(|e| e > now))
        .map(|(level, _)| level)
        .max()
}
/// Resolve persisted access for a cluster.
pub async fn effective(
    pool: &sqlx::PgPool,
    actor: &Actor,
    cluster: &ClusterRecord,
) -> Result<Option<AccessLevel>, ApiError> {
    if actor.org_admin {
        return Ok(Some(AccessLevel::Admin));
    }
    let levels:Vec<String>=sqlx::query_scalar(
"SELECT level FROM grants WHERE user_id=$1 AND ((scope='cluster' AND scope_id=$2) OR (scope='project'
         AND scope_id=$3)) AND (expires_at IS NULL OR expires_at>now())",
)
.bind(actor.user_id)
.bind(cluster.id)
.bind(cluster.project_id)
.fetch_all(pool).await?;
    Ok(levels
        .into_iter()
        .filter_map(|l| match l.as_str() {
            "read" => Some(AccessLevel::Read),
            "write" => Some(AccessLevel::Write),
            "admin" => Some(AccessLevel::Admin),
            _ => None,
        })
        .max())
}
/// Fetch a cluster and require a minimum effective level; returns the resolved level too.
pub async fn require_level_effective(
    pool: &sqlx::PgPool,
    actor: &Actor,
    id: Uuid,
    level: AccessLevel,
) -> Result<(ClusterRecord, AccessLevel), ApiError> {
    let cluster = crate::records::cluster(pool, id).await?;
    match effective(pool, actor, &cluster).await? {
        Some(effective) if effective >= level => Ok((cluster, effective)),
        _ => Err(ApiError::forbidden()),
    }
}
