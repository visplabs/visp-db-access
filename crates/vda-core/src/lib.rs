//! The query pipeline of visp-db-access, with no router and no request handlers.
//!
//! Every door into the gateway (the web console today, agents next) builds an
//! [`access::Actor`] and calls [`query`]. The rules are therefore the same for
//! all of them: access level, policy, guard, masking, audit and limits.
pub mod access;
pub mod audit;
pub mod crypto;
pub mod error;
pub mod masking;
pub mod network;
pub mod policy;
pub mod pools;
pub mod query;
pub mod records;
pub mod sanitation;

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
    /// Running queries by cancellation ID, with the owner's user ID.
    pub active: Arc<dashmap::DashMap<Uuid, (Uuid, CancellationToken)>>,
    pub tasks: tokio_util::task::TaskTracker,
    pub replica_health: Cache<Uuid, bool>,
    /// Permit loopback and private target addresses (local development).
    pub allow_private_targets: bool,
}
impl Core {
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
            allow_private_targets,
        }
    }
}
