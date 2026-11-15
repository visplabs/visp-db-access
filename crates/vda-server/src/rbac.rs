//! Effective access from organization role and unexpired project/cluster grants.
use crate::{auth::User, db::ClusterRecord, error::ApiError};
use uuid::Uuid;
pub use vda_core::access::resolve_level;
use vda_guard::AccessLevel;
/// Require organization administrator privileges.
pub fn require_admin(user: &User) -> Result<(), ApiError> {
    if user.org_role == "admin" {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}
/// Resolve persisted access for a cluster.
pub async fn effective(
    pool: &sqlx::PgPool,
    user: &User,
    cluster: &ClusterRecord,
) -> Result<Option<AccessLevel>, ApiError> {
    vda_core::access::effective(pool, &user.actor(), cluster).await
}
/// Fetch a cluster and require a minimum effective level.
pub async fn require_level(
    pool: &sqlx::PgPool,
    user: &User,
    id: Uuid,
    level: AccessLevel,
) -> Result<ClusterRecord, ApiError> {
    Ok(require_level_effective(pool, user, id, level).await?.0)
}
/// Like [`require_level`], but also returns the resolved level so callers need no second lookup.
pub async fn require_level_effective(
    pool: &sqlx::PgPool,
    user: &User,
    id: Uuid,
    level: AccessLevel,
) -> Result<(ClusterRecord, AccessLevel), ApiError> {
    vda_core::access::require_level_effective(pool, &user.actor(), id, level).await
}
/// Authorization predicate used by scoped list queries.
pub const ACCESS_SQL: &str = "
    (u.org_role='admin' OR EXISTS (
        SELECT 1 FROM grants g WHERE g.user_id=u.id
        AND (g.expires_at IS NULL OR g.expires_at>now())
        AND ((g.scope='cluster' AND g.scope_id=c.id)
            OR (g.scope='project' AND g.scope_id=c.project_id))))";
