//! The limits of one agent at the agent door, shared by every node.
//!
//! A load balancer can send the calls of one agent to several nodes. The
//! call rate, the streaks of refusals and the turns of an agent are kept in
//! its row of `agent_limits` in the metadata database, so each limit holds
//! once for the agent, not once per node. The numbers and the rules are in
//! `mcp`; this module only stores them.
//!
//! A turn is one guard decision of `run_query`, or one `propose_write`, of an
//! agent at a time. It is a lease on the row: the id of the call that holds
//! it and the time the lease ends. One upsert takes it, and only when it is
//! free or its lease has lapsed. The holder renews the lease while it works,
//! so a turn may last as long as the work does (a proposal's read check or
//! dry run runs up to the policy's statement timeout, ten minutes at most)
//! while a node that crashed loses its turns within `LEASE`. The turn is
//! given back on every way out of the call, in a task of its own: `give_back`
//! starts it and waits for it, and when the call is cancelled or panics,
//! `Drop` starts it. Each try for a turn also runs in a task of its own, which
//! gives the turn back if the call was cancelled while the try was in flight.
//!
//! Callers on one node wait for the turn on a local lock first, so only one
//! of them at a time asks the database for it; a caller whose turn is held
//! on another node asks again after a short wait, as callers on one node
//! wait for each other.
use crate::{app::AppState, error::ApiError, mcp::ProposalStreak};
use chrono::{DateTime, Utc};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedMutexGuard};
use uuid::Uuid;

/// The window of the call rate.
pub(crate) const CALL_WINDOW_SECONDS: u64 = 60;
/// How long a turn lasts without being renewed. A crashed node's turns end
/// after this; three renewals fit in it, so one slow renewal loses nothing.
const LEASE: Duration = Duration::from_secs(30);
const RENEW_EVERY: Duration = Duration::from_secs(10);
/// The first wait for a turn held on another node, doubled up to the longest.
const FIRST_WAIT: Duration = Duration::from_millis(20);
const LONGEST_WAIT: Duration = Duration::from_millis(250);
/// Rows deleted by one maintenance cycle at most.
const PRUNE_ROWS: i64 = 1000;

/// Count one tool call of the agent and say how many it made in the current
/// window, this one included. One statement: a new window starts when the
/// last one has ended.
pub(crate) async fn count_call(db: &sqlx::PgPool, agent: Uuid) -> Result<u32, ApiError> {
    let calls: i32 = sqlx::query_scalar(
        "INSERT INTO agent_limits AS l (agent_id,calls,calls_since) VALUES ($1,1,now())
         ON CONFLICT (agent_id) DO UPDATE SET
           calls=CASE WHEN l.calls_since>now()-make_interval(secs=>$2) THEN l.calls+1 ELSE 1 END,
           calls_since=CASE WHEN l.calls_since>now()-make_interval(secs=>$2)
             THEN l.calls_since ELSE now() END
         RETURNING calls",
    )
    .bind(agent)
    .bind(CALL_WINDOW_SECONDS as f64)
    .fetch_one(db)
    .await?;
    Ok(u32::try_from(calls).unwrap_or(u32::MAX))
}

/// Add a refused query to the agent's streak, outside a turn: a query that
/// the guard accepted and that was then refused while it ran.
pub(crate) async fn count_denial(db: &sqlx::PgPool, agent: Uuid) {
    let done = sqlx::query("UPDATE agent_limits SET denials=denials+1 WHERE agent_id=$1")
        .bind(agent)
        .execute(db)
        .await;
    if let Err(error) = done {
        tracing::error!(%error, %agent, "refused query not counted");
    }
}

/// End the agent's streak of refused queries: a query succeeded.
pub(crate) async fn clear_denials(db: &sqlx::PgPool, agent: Uuid) {
    let done = sqlx::query(
        "UPDATE agent_limits SET denials=0,denials_since=NULL
         WHERE agent_id=$1 AND (denials<>0 OR denials_since IS NOT NULL)",
    )
    .bind(agent)
    .execute(db)
    .await;
    if let Err(error) = done {
        tracing::error!(%error, %agent, "streak of refused queries not ended");
    }
}

/// Delete the rows of agents whose windows and turns have all ended. A later
/// call starts from nothing, as it would after the windows. The conditions
/// are said again on the rows the DELETE takes: a row that a call wrote
/// after the inner select read it is checked again on its new version, so a
/// turn just taken is not deleted.
pub(crate) async fn prune(db: &sqlx::PgPool) -> Result<(), ApiError> {
    const ENDED: &str = "(calls_since IS NULL OR calls_since<=now()-make_interval(secs=>$1))
           AND (denials_since IS NULL OR denials_since<=now()-make_interval(secs=>$2))
           AND (proposals_seen_at IS NULL OR proposals_seen_at<=now()-make_interval(secs=>$2))
           AND (query_until IS NULL OR query_until<now())
           AND (proposal_until IS NULL OR proposal_until<now())";
    sqlx::query(&format!(
        "DELETE FROM agent_limits WHERE agent_id IN (SELECT agent_id FROM agent_limits
         WHERE {ENDED} LIMIT $3) AND {ENDED}"
    ))
    .bind(CALL_WINDOW_SECONDS as f64)
    .bind(crate::mcp::DENIAL_WINDOW_SECONDS as f64)
    .bind(PRUNE_ROWS)
    .execute(db)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Query,
    Proposal,
}
impl Kind {
    fn renew(self) -> &'static str {
        match self {
            Self::Query => {
                "UPDATE agent_limits SET query_until=now()+make_interval(secs=>$3)
                 WHERE agent_id=$1 AND query_holder=$2"
            }
            Self::Proposal => {
                "UPDATE agent_limits SET proposal_until=now()+make_interval(secs=>$3)
                 WHERE agent_id=$1 AND proposal_holder=$2"
            }
        }
    }
    fn clear(self) -> &'static str {
        match self {
            Self::Query => {
                "UPDATE agent_limits SET query_holder=NULL,query_until=NULL
                 WHERE agent_id=$1 AND query_holder=$2"
            }
            Self::Proposal => {
                "UPDATE agent_limits SET proposal_holder=NULL,proposal_until=NULL
                 WHERE agent_id=$1 AND proposal_holder=$2"
            }
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Proposal => "proposal",
        }
    }
}

/// A turn held in the database. The renewal stops when it is dropped; the
/// local lock is let go with it.
#[derive(Debug)]
struct Lease {
    db: sqlx::PgPool,
    agent: Uuid,
    holder: Uuid,
    renewal: tokio::task::AbortHandle,
    _local: OwnedMutexGuard<()>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.renewal.abort();
    }
}
impl Lease {
    /// Wait for the local lock, then for the turn in the database. `take`
    /// tries once and returns what it read, or `None` while the turn is held.
    ///
    /// Each try runs in a task of its own and sends its answer back. A call
    /// cancelled while a try is in flight cannot stop the statement on the
    /// database, which may still give it the turn; the task sees that nobody
    /// is waiting for the answer and gives the turn back itself, after the
    /// statement has ended. So there is nothing to give back while a call
    /// sleeps between tries, or when it is cancelled anywhere else here.
    async fn wait<T, F, Fut>(
        state: &AppState,
        kind: Kind,
        agent: Uuid,
        mut take: F,
    ) -> Result<(Self, T), ApiError>
    where
        T: Send + 'static,
        F: FnMut(Uuid) -> Fut,
        Fut: std::future::Future<Output = Result<Option<T>, sqlx::Error>> + Send + 'static,
    {
        let locks = match kind {
            Kind::Query => &state.agent_query_turns,
            Kind::Proposal => &state.agent_proposal_turns,
        };
        let local = locks
            .get_with(agent, async { Arc::new(Mutex::new(())) })
            .await
            .lock_owned()
            .await;
        let holder = Uuid::new_v4();
        let mut wait = FIRST_WAIT;
        let found = loop {
            if let Some(found) = try_take(&state.db, kind, agent, holder, take(holder)).await? {
                break found;
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(LONGEST_WAIT);
        };
        let renewal = tokio::spawn(renew(state.db.clone(), kind, agent, holder)).abort_handle();
        let lease = Self {
            db: state.db.clone(),
            agent,
            holder,
            renewal,
            _local: local,
        };
        Ok((lease, found))
    }
}
/// Run one try for the turn in a task of its own and wait for its answer. The
/// task gives the turn back when the answer cannot be delivered (the caller
/// was cancelled) or when the statement failed (it may have taken the turn
/// before the connection broke).
async fn try_take<T, Fut>(
    db: &sqlx::PgPool,
    kind: Kind,
    agent: Uuid,
    holder: Uuid,
    attempt: Fut,
) -> Result<Option<T>, ApiError>
where
    T: Send + 'static,
    Fut: std::future::Future<Output = Result<Option<T>, sqlx::Error>> + Send + 'static,
{
    let (send, receive) = tokio::sync::oneshot::channel();
    let db_for_waiting = db.clone();
    let db = db.clone();
    tokio::spawn(async move {
        let answer = attempt.await;
        if answer.is_err() {
            clear(&db, kind, agent, holder).await;
        }
        if let Err(Ok(Some(_))) = send.send(answer) {
            clear(&db, kind, agent, holder).await;
        }
    });
    let mut waiting = Waiting {
        receive: Some(receive),
        db: db_for_waiting,
        kind,
        agent,
        holder,
    };
    let answer = match waiting.receive.as_mut() {
        Some(receive) => receive.await,
        None => return Err(ApiError::internal()),
    };
    waiting.receive = None;
    match answer {
        Ok(answer) => Ok(answer?),
        Err(_) => Err(ApiError::internal()),
    }
}
/// The answer of a try that was sent but not yet read. Dropped before it is
/// read, it closes the channel: an answer already sent is read here and its
/// turn given back; a try still in flight sees the closed channel when it
/// ends and gives back its own turn.
struct Waiting<T> {
    receive: Option<tokio::sync::oneshot::Receiver<Result<Option<T>, sqlx::Error>>>,
    db: sqlx::PgPool,
    kind: Kind,
    agent: Uuid,
    holder: Uuid,
}
impl<T> Drop for Waiting<T> {
    fn drop(&mut self) {
        let Some(mut receive) = self.receive.take() else {
            return;
        };
        receive.close();
        if let Ok(Ok(Some(_))) = receive.try_recv() {
            let (db, kind, agent, holder) = (self.db.clone(), self.kind, self.agent, self.holder);
            give_back_apart(async move { clear(&db, kind, agent, holder).await });
        }
    }
}
/// Give a turn back by its holder: only the holder's own turn is cleared.
async fn clear(db: &sqlx::PgPool, kind: Kind, agent: Uuid, holder: Uuid) {
    let done = sqlx::query(kind.clear())
        .bind(agent)
        .bind(holder)
        .execute(db)
        .await;
    if let Err(error) = done {
        tracing::error!(%error, %agent, turn = kind.name(), "agent turn not given back; its lease will lapse");
    }
}

/// What the proposal path needs to check that its call still holds the
/// agent's turn. A turn that was lost refuses the proposal: another call may
/// have taken it, and the limits on requests hold only within a turn.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Held {
    pub(crate) agent: Uuid,
    holder: Uuid,
}
impl Held {
    /// Renew the turn, and refuse when it is no longer this call's. Called
    /// before the target is used.
    pub(crate) async fn renew(&self, db: &sqlx::PgPool) -> Result<(), ApiError> {
        let renewed = sqlx::query(Kind::Proposal.renew())
            .bind(self.agent)
            .bind(self.holder)
            .bind(LEASE.as_secs_f64())
            .execute(db)
            .await?;
        self.held(renewed.rows_affected() > 0)
    }
    /// Lock the turn in the transaction that stores the request, and refuse
    /// when it is no longer this call's. Until the transaction ends, no other
    /// call can take the turn.
    pub(crate) async fn lock(&self, tx: &mut sqlx::PgConnection) -> Result<(), ApiError> {
        let found: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM agent_limits WHERE agent_id=$1 AND proposal_holder=$2
               AND proposal_until>now() FOR UPDATE",
        )
        .bind(self.agent)
        .bind(self.holder)
        .fetch_optional(tx)
        .await?;
        self.held(found.is_some())
    }
    fn held(&self, held: bool) -> Result<(), ApiError> {
        if held {
            return Ok(());
        }
        metrics::counter!("vda_agent_turns_lost_total").increment(1);
        tracing::warn!(agent = %self.agent, "proposal refused: its turn was lost");
        Err(ApiError::internal())
    }
}

/// Keep a turn alive while its holder works. A turn that was lost (its lease
/// lapsed and another call took it) is not taken back.
async fn renew(db: sqlx::PgPool, kind: Kind, agent: Uuid, holder: Uuid) {
    loop {
        tokio::time::sleep(RENEW_EVERY).await;
        let renewed = sqlx::query(kind.renew())
            .bind(agent)
            .bind(holder)
            .bind(LEASE.as_secs_f64())
            .execute(&db)
            .await;
        match renewed {
            Ok(done) if done.rows_affected() > 0 => {}
            Ok(_) => {
                tracing::warn!(%agent, turn = kind.name(), "agent turn lost: its lease lapsed");
                return;
            }
            Err(error) => {
                tracing::warn!(%error, %agent, turn = kind.name(), "agent turn not renewed");
            }
        }
    }
}
/// Give a turn back in a task of its own, so that a call cancelled while it
/// gives the turn back still does. `give_back` waits for the task; `Drop`
/// cannot wait and leaves it running.
fn give_back_apart<F>(release: F) -> Option<tokio::task::JoinHandle<()>>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => Some(runtime.spawn(release)),
        // Without a runtime the lease lapses on its own.
        Err(_) => {
            tracing::warn!("agent turn left to lapse");
            None
        }
    }
}

/// The turn of one guard decision of `run_query`, with the agent's streak of
/// refused queries as it was when the turn began.
#[derive(Debug)]
pub(crate) struct QueryTurn {
    lease: Option<Lease>,
    denials: u32,
    refused: i32,
}
impl QueryTurn {
    /// Wait for the agent's turn. A streak whose window has ended starts
    /// again; a window starts with the first call that finds none.
    pub(crate) async fn take(state: &AppState, agent: Uuid) -> Result<Self, ApiError> {
        let db = state.db.clone();
        let (lease, denials) = Lease::wait(state, Kind::Query, agent, |holder| {
            let db = db.clone();
            async move {
            sqlx::query_scalar::<_, i32>(
                "INSERT INTO agent_limits AS l (agent_id,denials,denials_since,query_holder,query_until)
                 VALUES ($1,0,now(),$2,now()+make_interval(secs=>$3))
                 ON CONFLICT (agent_id) DO UPDATE SET
                   denials=CASE WHEN l.denials_since>now()-make_interval(secs=>$4)
                     THEN l.denials ELSE 0 END,
                   denials_since=CASE WHEN l.denials_since>now()-make_interval(secs=>$4)
                     THEN l.denials_since ELSE now() END,
                   query_holder=EXCLUDED.query_holder,query_until=EXCLUDED.query_until
                 WHERE l.query_holder IS NULL OR l.query_until<=now()
                 RETURNING denials",
            )
            .bind(agent)
            .bind(holder)
            .bind(LEASE.as_secs_f64())
            .bind(crate::mcp::DENIAL_WINDOW_SECONDS as f64)
            .fetch_optional(&db)
            .await
            }
        })
        .await?;
        Ok(Self {
            lease: Some(lease),
            denials: u32::try_from(denials).unwrap_or(0),
            refused: 0,
        })
    }
    /// Refused queries in a row when the turn began.
    pub(crate) fn denials(&self) -> u32 {
        self.denials
    }
    /// Count a refusal of this turn; it is added when the turn is given back.
    pub(crate) fn refused(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }
    /// Add the refusals of this turn and let the next call have its turn.
    pub(crate) async fn give_back(mut self) {
        if let Some(lease) = self.lease.take() {
            if let Some(release) = give_back_apart(release_query(lease, self.refused)) {
                let _ = release.await;
            }
        }
    }
}
impl Drop for QueryTurn {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            give_back_apart(release_query(lease, self.refused));
        }
    }
}
async fn release_query(lease: Lease, refused: i32) {
    lease.renewal.abort();
    let done = sqlx::query(
        "UPDATE agent_limits SET denials=denials+$3,
           query_holder=CASE WHEN query_holder=$2 THEN NULL ELSE query_holder END,
           query_until=CASE WHEN query_holder=$2 THEN NULL ELSE query_until END
         WHERE agent_id=$1",
    )
    .bind(lease.agent)
    .bind(lease.holder)
    .bind(refused)
    .execute(&lease.db)
    .await;
    if let Err(error) = done {
        tracing::error!(%error, agent = %lease.agent, "query turn not given back; its lease will lapse");
    }
}

/// The turn of one proposal, with the agent's streak of refused proposals.
/// The holder of the turn is the only writer of the streak, so it is read
/// when the turn begins and written back whole when it ends.
#[derive(Debug)]
pub(crate) struct ProposalTurn {
    lease: Option<Lease>,
    pub(crate) streak: ProposalStreak,
    /// The database's time when the turn began, and this node's clock then:
    /// every node reads the time of a stop on the same clock.
    began: (DateTime<Utc>, Instant),
}
impl ProposalTurn {
    /// Wait for the agent's turn. A streak is forgotten when no proposal
    /// began for the length of the stop.
    pub(crate) async fn take(state: &AppState, agent: Uuid) -> Result<Self, ApiError> {
        let db = state.db.clone();
        type Row = (i32, Option<DateTime<Utc>>, DateTime<Utc>);
        let (lease, (refused, stopped_at, now)) =
            Lease::wait(state, Kind::Proposal, agent, |holder| {
                let db = db.clone();
                async move {
                sqlx::query_as::<_, Row>(
                    "INSERT INTO agent_limits AS l (agent_id,proposals_seen_at,proposal_holder,proposal_until)
                     VALUES ($1,now(),$2,now()+make_interval(secs=>$3))
                     ON CONFLICT (agent_id) DO UPDATE SET
                       proposals_refused=CASE WHEN l.proposals_seen_at>now()-make_interval(secs=>$4)
                         THEN l.proposals_refused ELSE 0 END,
                       proposals_stopped_at=CASE WHEN l.proposals_seen_at>now()-make_interval(secs=>$4)
                         THEN l.proposals_stopped_at END,
                       proposals_seen_at=now(),
                       proposal_holder=EXCLUDED.proposal_holder,proposal_until=EXCLUDED.proposal_until
                     WHERE l.proposal_holder IS NULL OR l.proposal_until<=now()
                     RETURNING proposals_refused,proposals_stopped_at,now()",
                )
                .bind(agent)
                .bind(holder)
                .bind(LEASE.as_secs_f64())
                .bind(crate::mcp::DENIAL_WINDOW_SECONDS as f64)
                .fetch_optional(&db)
                .await
                }
            })
            .await?;
        Ok(Self {
            lease: Some(lease),
            streak: ProposalStreak {
                refused: u32::try_from(refused).unwrap_or(0),
                stopped_at,
            },
            began: (now, Instant::now()),
        })
    }
    /// What the proposal path needs to check that the turn is still held.
    pub(crate) fn held(&self) -> Held {
        Held {
            agent: self.lease.as_ref().map_or(Uuid::nil(), |lease| lease.agent),
            holder: self
                .lease
                .as_ref()
                .map_or(Uuid::nil(), |lease| lease.holder),
        }
    }
    /// The time now on the database's clock.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        let (at, then) = self.began;
        chrono::Duration::from_std(then.elapsed()).map_or(at, |since| at + since)
    }
    /// Write the streak back and let the next proposal have its turn.
    pub(crate) async fn give_back(mut self) {
        if let Some(lease) = self.lease.take() {
            let release = release_proposal(lease, self.streak.refused, self.streak.stopped_at);
            if let Some(release) = give_back_apart(release) {
                let _ = release.await;
            }
        }
    }
}
impl Drop for ProposalTurn {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            give_back_apart(release_proposal(
                lease,
                self.streak.refused,
                self.streak.stopped_at,
            ));
        }
    }
}
/// Only the holder writes the streak: a turn that was lost writes nothing,
/// so it cannot undo what the call that took it wrote.
async fn release_proposal(lease: Lease, refused: u32, stopped_at: Option<DateTime<Utc>>) {
    lease.renewal.abort();
    let done = sqlx::query(
        "UPDATE agent_limits SET proposals_refused=$3,proposals_stopped_at=$4,
           proposal_holder=NULL,proposal_until=NULL
         WHERE agent_id=$1 AND proposal_holder=$2",
    )
    .bind(lease.agent)
    .bind(lease.holder)
    .bind(i32::try_from(refused).unwrap_or(i32::MAX))
    .bind(stopped_at)
    .execute(&lease.db)
    .await;
    match done {
        Ok(done) if done.rows_affected() == 0 => {
            tracing::warn!(agent = %lease.agent, "proposal turn was lost before it was given back");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(%error, agent = %lease.agent, "proposal turn not given back; its lease will lapse");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A turn taken while the maintenance cycle prunes is not deleted: the
    /// DELETE waits for the take and checks the row's new version again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prune_keeps_a_turn_taken_while_it_runs() {
        let Ok(url) = std::env::var("VISP_GATE_TEST_DATABASE_URL") else {
            eprintln!("skipped: VISP_GATE_TEST_DATABASE_URL is not set");
            return;
        };
        let root = sqlx::PgPool::connect(&url).await.unwrap();
        let schema = format!("vda_limits_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&root)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema},public");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |c, _| {
                let path = path.clone();
                Box::pin(async move {
                    sqlx::query(&path).execute(c).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&db).await.unwrap();
        let owner = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,email,name,password_hash,org_role)
             VALUES ($1,'owner@limits.example','Owner','x','admin')",
        )
        .bind(owner)
        .execute(&db)
        .await
        .unwrap();
        let (busy, idle) = (Uuid::new_v4(), Uuid::new_v4());
        for (agent, name) in [(busy, "busy"), (idle, "idle")] {
            sqlx::query("INSERT INTO agents(id,owner_id,name) VALUES ($1,$2,$3)")
                .bind(agent)
                .bind(owner)
                .bind(name)
                .execute(&db)
                .await
                .unwrap();
            // Both rows have only windows that ended long ago.
            sqlx::query(
                "INSERT INTO agent_limits(agent_id,calls,calls_since)
                 VALUES ($1,3,now()-interval '1 hour')",
            )
            .bind(agent)
            .execute(&db)
            .await
            .unwrap();
        }
        // A call takes the turn of one agent and has not committed yet.
        let mut take = db.begin().await.unwrap();
        sqlx::query(
            "UPDATE agent_limits SET query_holder=$2,query_until=now()+interval '30 seconds'
             WHERE agent_id=$1",
        )
        .bind(busy)
        .bind(Uuid::new_v4())
        .execute(&mut *take)
        .await
        .unwrap();
        let pruning = tokio::spawn({
            let db = db.clone();
            async move { prune(&db).await }
        });
        // The DELETE has read the old version and waits for the take's lock.
        let mut waiting = 0i64;
        for _ in 0..400 {
            waiting = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE wait_event_type='Lock' AND query LIKE 'DELETE FROM agent_limits%'",
            )
            .fetch_one(&root)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(waiting, 1, "the prune did not wait for the take");
        take.commit().await.unwrap();
        pruning.await.unwrap().unwrap();
        let left: Vec<Uuid> = sqlx::query_scalar("SELECT agent_id FROM agent_limits")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(
            left,
            vec![busy],
            "the taken turn was deleted, or the idle row kept"
        );
        db.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&root)
            .await
            .unwrap();
        root.close().await;
    }
}
