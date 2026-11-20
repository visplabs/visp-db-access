//! The query pipeline of visp-db-access, with no router and no request handlers.
//!
//! Every door into the gateway (the web console today, agents next) builds an
//! [`access::Actor`] and calls [`query`]. The rules are therefore the same for
//! all of them: access level, policy, guard, masking, audit and limits.
pub mod access;
pub mod agents;
pub mod audit;
pub mod chain;
pub mod crypto;
pub mod error;
pub mod judge;
pub mod masking;
pub mod network;
pub mod policy;
pub mod pools;
pub mod preview;
pub mod query;
pub mod records;
pub mod sanitation;
pub mod teach;

use moka::future::Cache;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Shared, cheaply cloned state that the pipeline needs.
#[derive(Debug, Clone)]
pub struct Core {
    /// Metadata store.
    pub db: sqlx::PgPool,
    pub crypto: crypto::Crypto,
    pub pools: pools::Pools,
    /// Running queries on this node, by cancellation ID.
    pub active: Arc<dashmap::DashMap<Uuid, ActiveQuery>>,
    pub tasks: tokio_util::task::TaskTracker,
    pub replica_health: Cache<Uuid, bool>,
    /// Whether a cluster version's agent login was verified clean, for a short time.
    pub judged: Cache<(Uuid, chrono::DateTime<chrono::Utc>), (judge::Verdict, std::time::Instant)>,
    /// Permit loopback and private target addresses (local development).
    pub allow_private_targets: bool,
}
/// A running query and who it belongs to.
#[derive(Debug, Clone)]
pub struct ActiveQuery {
    /// The person the query runs as: the caller, or the agent's owner.
    pub user_id: Uuid,
    /// The agent that started it, and the token it used.
    pub agent: Option<(Uuid, Uuid)>,
    pub cancel: CancellationToken,
}
impl Core {
    /// Cancel every running query on this node that matches, and count them.
    /// Used to stop an agent's work the moment it is paused, deleted or revoked.
    pub fn cancel_where(&self, matches: impl Fn(&ActiveQuery) -> bool) -> usize {
        let mut cancelled = 0;
        for query in self.active.iter() {
            if matches(query.value()) {
                query.cancel.cancel();
                cancelled += 1;
            }
        }
        cancelled
    }
    /// Build pipeline state on top of an open metadata pool.
    pub fn new(db: sqlx::PgPool, crypto: crypto::Crypto, allow_private_targets: bool) -> Self {
        Self {
            db,
            crypto,
            pools: pools::Pools::new(),
            active: Arc::new(dashmap::DashMap::new()),
            tasks: tokio_util::task::TaskTracker::new(),
            replica_health: Cache::builder()
                .max_capacity(512)
                .time_to_live(Duration::from_secs(5))
                .build(),
            judged: Cache::builder()
                .max_capacity(2048)
                .time_to_live(Duration::from_secs(judge::TRUST_SECONDS))
                .build(),
            allow_private_targets,
        }
    }
}
