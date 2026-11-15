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
    /// Set when an agent makes the request for this user. It narrows access.
    pub agent: Option<AgentScope>,
}
/// The limits of an agent. They narrow its owner's access and never widen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentScope {
    pub agent_id: Uuid,
    /// The token that authenticated this request.
    pub token_id: Uuid,
    /// The highest level the agent can have on any cluster.
    pub max_level: AccessLevel,
    /// The only clusters the agent can reach.
    pub clusters: Vec<Uuid>,
}
impl Actor {
    /// Organization-wide powers belong to a person, never to an agent.
    pub fn is_org_admin(&self) -> bool {
        self.org_admin && self.agent.is_none()
    }
    /// Whether this actor may cancel a running query. A person may cancel
    /// their own queries and those of their agents; an organization
    /// administrator may cancel any; an agent only what it started itself.
    pub fn may_cancel(&self, query: &crate::ActiveQuery) -> bool {
        match &self.agent {
            Some(scope) => query
                .agent
                .is_some_and(|(agent, _)| agent == scope.agent_id),
            None => self.org_admin || query.user_id == self.user_id,
        }
    }
}
/// Narrow the owner's level to what the agent can have on this cluster.
pub fn narrow(
    owner: Option<AccessLevel>,
    agent: Option<&AgentScope>,
    cluster: Uuid,
) -> Option<AccessLevel> {
    match agent {
        None => owner,
        Some(scope) if scope.clusters.contains(&cluster) => {
            owner.map(|level| level.min(scope.max_level))
        }
        Some(_) => None,
    }
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
    let owner = if actor.org_admin {
        Some(AccessLevel::Admin)
    } else {
        let levels: Vec<String> = sqlx::query_scalar(
            "SELECT level FROM grants WHERE user_id=$1 AND ((scope='cluster' AND scope_id=$2)
             OR (scope='project' AND scope_id=$3)) AND (expires_at IS NULL OR expires_at>now())",
        )
        .bind(actor.user_id)
        .bind(cluster.id)
        .bind(cluster.project_id)
        .fetch_all(pool)
        .await?;
        levels.iter().filter_map(|l| level(l)).max()
    };
    Ok(narrow(owner, actor.agent.as_ref(), cluster.id))
}
/// Parse a stored access level.
pub fn level(value: &str) -> Option<AccessLevel> {
    match value {
        "read" => Some(AccessLevel::Read),
        "write" => Some(AccessLevel::Write),
        "admin" => Some(AccessLevel::Admin),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_never_has_more_than_its_owner_or_its_own_limits() {
        let (inside, outside) = (Uuid::new_v4(), Uuid::new_v4());
        let scope = |max_level| AgentScope {
            agent_id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            max_level,
            clusters: vec![inside],
        };
        use AccessLevel::{Admin, Read, Write};
        // No agent: the owner's level is unchanged.
        assert_eq!(narrow(Some(Admin), None, outside), Some(Admin));
        // The agent's ceiling applies, even when the owner is an administrator.
        assert_eq!(narrow(Some(Admin), Some(&scope(Read)), inside), Some(Read));
        assert_eq!(
            narrow(Some(Admin), Some(&scope(Write)), inside),
            Some(Write)
        );
        // The owner's level applies when it is lower than the agent's ceiling.
        assert_eq!(narrow(Some(Read), Some(&scope(Write)), inside), Some(Read));
        // No owner access means no agent access.
        assert_eq!(narrow(None, Some(&scope(Write)), inside), None);
        // A cluster outside the agent's list is unreachable.
        assert_eq!(narrow(Some(Admin), Some(&scope(Write)), outside), None);
    }

    #[test]
    fn cancellation_follows_ownership_and_an_agent_has_no_organization_powers() {
        let query = |user_id, agent| crate::ActiveQuery {
            user_id,
            agent,
            cancel: tokio_util::sync::CancellationToken::new(),
        };
        let person = |org_admin| Actor {
            user_id: Uuid::new_v4(),
            email: "owner@example.test".into(),
            org_admin,
            agent: None,
        };
        let as_agent = |owner: &Actor| {
            let mut actor = owner.clone();
            actor.agent = Some(AgentScope {
                agent_id: Uuid::new_v4(),
                token_id: Uuid::new_v4(),
                max_level: AccessLevel::Read,
                clusters: vec![],
            });
            actor
        };
        let (member, admin, stranger) = (person(false), person(true), Uuid::new_v4());
        let (agent, admin_agent) = (as_agent(&member), as_agent(&admin));
        let id = |actor: &Actor| actor.agent.as_ref().map(|a| (a.agent_id, a.token_id));
        assert!(admin.is_org_admin() && !admin_agent.is_org_admin());
        // A person: their own queries and their agents' queries, nobody else's.
        assert!(member.may_cancel(&query(member.user_id, None)));
        assert!(member.may_cancel(&query(member.user_id, id(&agent))));
        assert!(!member.may_cancel(&query(stranger, None)));
        // An administrator: anything.
        assert!(admin.may_cancel(&query(stranger, id(&agent))));
        // An agent: only what it started, even when its owner is an administrator.
        assert!(agent.may_cancel(&query(member.user_id, id(&agent))));
        assert!(!agent.may_cancel(&query(member.user_id, None)));
        assert!(!agent.may_cancel(&query(member.user_id, id(&admin_agent))));
        assert!(!admin_agent.may_cancel(&query(stranger, None)));
        assert!(!admin_agent.may_cancel(&query(admin.user_id, None)));
    }
}
