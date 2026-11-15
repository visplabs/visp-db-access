//! Agent tokens: how an agent proves who it is, and whose access it borrows.
//!
//! A token is `vda_agent_` followed by 32 random bytes in URL-safe base64.
//! Only its SHA-256 digest is stored, so a copy of the metadata store cannot
//! be used to act as an agent.
use crate::{
    access::{Actor, AgentScope},
    error::ApiError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Marks a string as an agent token, so secret scanners and people can spot one.
pub const TOKEN_PREFIX: &str = "vda_agent_";
const SECRET_BYTES: usize = 32;

/// A freshly made token. `secret` is shown to its owner once and never stored.
pub struct NewToken {
    pub secret: String,
    pub hash: Vec<u8>,
    /// The last four characters, kept so a person can tell tokens apart.
    pub hint: String,
}
impl std::fmt::Debug for NewToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewToken")
            .field("secret", &"[redacted]")
            .field("hint", &self.hint)
            .finish()
    }
}
/// Make a new unpredictable token.
pub fn generate() -> NewToken {
    let mut bytes = [0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let body = URL_SAFE_NO_PAD.encode(bytes);
    let hint = body
        .chars()
        .skip(body.chars().count().saturating_sub(4))
        .collect();
    let secret = format!("{TOKEN_PREFIX}{body}");
    NewToken {
        hash: Sha256::digest(secret.as_bytes()).to_vec(),
        secret,
        hint,
    }
}
/// The stored digest of a token, or `None` when the text cannot be a token.
/// The shape check keeps malformed input away from the metadata store.
pub fn digest(token: &str) -> Option<Vec<u8>> {
    let body = token.strip_prefix(TOKEN_PREFIX)?;
    let decoded = URL_SAFE_NO_PAD.decode(body).ok()?;
    (decoded.len() == SECRET_BYTES).then(|| Sha256::digest(token.as_bytes()).to_vec())
}

/// An authenticated agent and the identity its requests run as.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: Uuid,
    pub agent_name: String,
    pub token_id: Uuid,
    /// The owner, narrowed by the agent's limits.
    pub actor: Actor,
}
#[derive(sqlx::FromRow)]
struct Row {
    agent_id: Uuid,
    agent_name: String,
    max_level: String,
    token_id: Uuid,
    owner_id: Uuid,
    owner_email: String,
    owner_role: String,
    clusters: Vec<Uuid>,
}
/// Resolve a presented token. Every failure gives the same answer, so a caller
/// cannot learn whether a token is unknown, expired, revoked or paused.
pub async fn authenticate(pool: &sqlx::PgPool, token: &str) -> Result<AgentIdentity, ApiError> {
    let hash = digest(token).ok_or_else(ApiError::unauthenticated)?;
    let row: Option<Row> = sqlx::query_as(
        "SELECT a.id AS agent_id,a.name AS agent_name,a.max_level,t.id AS token_id,
         u.id AS owner_id,u.email AS owner_email,u.org_role AS owner_role,
         COALESCE((SELECT array_agg(cluster_id) FROM agent_clusters WHERE agent_id=a.id),
         ARRAY[]::uuid[]) AS clusters
         FROM agent_tokens t JOIN agents a ON a.id=t.agent_id JOIN users u ON u.id=a.owner_id
         WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now()
         AND NOT a.paused AND NOT u.disabled",
    )
    .bind(hash)
    .fetch_optional(pool)
    .await?;
    let row = row.ok_or_else(ApiError::unauthenticated)?;
    // An unknown stored level fails closed.
    let max_level = crate::access::level(&row.max_level)
        .filter(|level| *level <= vda_guard::AccessLevel::Write)
        .ok_or_else(ApiError::unauthenticated)?;
    // At most one write per token per minute keeps busy agents off the write path.
    sqlx::query(
        "UPDATE agent_tokens SET last_used_at=now() WHERE id=$1
         AND (last_used_at IS NULL OR last_used_at<now()-interval '1 minute')",
    )
    .bind(row.token_id)
    .execute(pool)
    .await?;
    Ok(AgentIdentity {
        agent_id: row.agent_id,
        agent_name: row.agent_name,
        token_id: row.token_id,
        actor: Actor {
            user_id: row.owner_id,
            email: row.owner_email,
            org_admin: row.owner_role == "admin",
            agent: Some(AgentScope {
                agent_id: row.agent_id,
                token_id: row.token_id,
                max_level,
                clusters: row.clusters,
            }),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_prefixed_and_only_exact_shapes_have_a_digest() {
        let (a, b) = (generate(), generate());
        assert_ne!(a.secret, b.secret);
        assert!(a.secret.starts_with(TOKEN_PREFIX));
        assert_eq!(a.secret.len(), TOKEN_PREFIX.len() + 43);
        assert!(a.secret.ends_with(&a.hint));
        assert_eq!(a.hint.len(), 4);
        assert_eq!(digest(&a.secret), Some(a.hash.clone()));
        assert_ne!(digest(&a.secret), digest(&b.secret));
        let body = a.secret.trim_start_matches(TOKEN_PREFIX);
        for bad in [
            String::new(),
            body.to_owned(),
            format!("vda_at_{body}"),
            format!("{TOKEN_PREFIX}{}", body.get(1..).unwrap_or_default()),
            format!("{}x", a.secret),
            format!("{TOKEN_PREFIX}{}", "!".repeat(43)),
            format!(" {}", a.secret),
        ] {
            assert_eq!(digest(&bad), None, "{bad:?} must not be accepted");
        }
        assert!(!format!("{a:?}").contains(body));
    }
}
