//! Durable query intent and bounded asynchronous delivery of auxiliary audit events.
//!
//! Every audit row is written here, by one statement ([`persist_on`]) or, for
//! the queue, by its batched form ([`persist_many`]). Neither names `seq` or
//! `txid`: the database gives both, and the hash chain (`crate::chain`)
//! depends on that.
use chrono::Utc;
use serde_json::Value;
use std::{net::IpAddr, time::Duration};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Query identity and SQL captured synchronously before target I/O.
#[derive(Debug, Clone)]
pub struct History {
    pub id: Uuid,
    pub cluster_id: Uuid,
    pub cluster_name: String,
    pub user_id: Uuid,
    pub user_email: String,
    /// The agent that ran the query for this user, if any.
    pub agent_id: Option<Uuid>,
    /// What the caller said this query is for.
    pub task: Option<String>,
    pub sql: String,
    pub verdict: String,
    pub status: String,
    pub row_count: Option<i64>,
    pub elapsed_ms: Option<i64>,
    pub error: Option<String>,
}
/// An append-only audit event. Query SQL lives durably in history, never in the queue.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Event {
    pub id: Uuid,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub ip: Option<IpAddr>,
    pub details: Value,
    pub created_at: chrono::DateTime<Utc>,
}
/// Write an audit event using the same connection/transaction as its mutation.
pub async fn persist_on(
    connection: &mut sqlx::PgConnection,
    event: &Event,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log(id,actor_id,action,target_type,target_id,ip,details,created_at) VALUES
         ($1,$2,$3,$4,$5,$6::text::inet,$7,$8) ON CONFLICT(id) DO NOTHING",
    )
    .bind(event.id)
    .bind(event.actor_id)
    .bind(&event.action)
    .bind(&event.target_type)
    .bind(event.target_id)
    .bind(event.ip.map(|ip| ip.to_string()))
    .bind(&event.details)
    .bind(event.created_at)
    .execute(connection)
    .await?;
    Ok(())
}
/// Persist one idempotent event synchronously.
pub async fn persist(db: &sqlx::PgPool, event: &Event) -> Result<(), sqlx::Error> {
    persist_on(&mut *db.acquire().await?, event).await
}
/// Write query history and its audit intent on a caller's transaction.
pub async fn record_query(
    connection: &mut sqlx::PgConnection,
    history: &History,
    event: &Event,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO query_history(id,cluster_id,cluster_ref,cluster_name,user_id,user_email,
         sql,verdict,status,row_count,elapsed_ms,error,created_at,ip,agent_id,task) VALUES ($1,$2,
         (SELECT id FROM clusters WHERE id=$2),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::text::inet,
         (SELECT id FROM agents WHERE id=$14),$15)",
    )
    .bind(history.id)
    .bind(history.cluster_id)
    .bind(&history.cluster_name)
    .bind(history.user_id)
    .bind(&history.user_email)
    .bind(&history.sql)
    .bind(&history.verdict)
    .bind(&history.status)
    .bind(history.row_count)
    .bind(history.elapsed_ms)
    .bind(&history.error)
    .bind(event.created_at)
    .bind(event.ip.map(|ip| ip.to_string()))
    .bind(history.agent_id)
    .bind(&history.task)
    .execute(&mut *connection)
    .await?;
    persist_on(connection, event).await
}
/// Commit query history and its audit intent before any target operation.
pub async fn begin_query(
    db: &sqlx::PgPool,
    history: &History,
    event: &Event,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    record_query(&mut tx, history, event).await?;
    tx.commit().await
}
/// Retry transport failures and transaction serialization/deadlock failures only.
pub fn transient(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed => true,
        sqlx::Error::Database(db) => db.code().is_some_and(|code| {
            code.starts_with("08")
                || matches!(
                    code.as_ref(),
                    "40001" | "40P01" | "57P01" | "57P02" | "57P03"
                )
        }),
        _ => false,
    }
}
/// Events the writer takes from the queue and inserts in one statement.
pub const BATCH: usize = 256;
/// Persist several events in one statement, which is one transaction: all
/// of them are written or none is. An event that is already there is skipped.
pub async fn persist_many(db: &sqlx::PgPool, events: &[Event]) -> Result<(), sqlx::Error> {
    let ids: Vec<Uuid> = events.iter().map(|event| event.id).collect();
    let actors: Vec<Option<Uuid>> = events.iter().map(|event| event.actor_id).collect();
    let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
    let target_types: Vec<Option<&str>> = events
        .iter()
        .map(|event| event.target_type.as_deref())
        .collect();
    let targets: Vec<Option<Uuid>> = events.iter().map(|event| event.target_id).collect();
    let ips: Vec<Option<String>> = events
        .iter()
        .map(|event| event.ip.map(|ip| ip.to_string()))
        .collect();
    let details: Vec<&Value> = events.iter().map(|event| &event.details).collect();
    let times: Vec<chrono::DateTime<Utc>> = events.iter().map(|event| event.created_at).collect();
    sqlx::query(
        "INSERT INTO audit_log(id,actor_id,action,target_type,target_id,ip,details,created_at)
         SELECT u.id,u.actor_id,u.action,u.target_type,u.target_id,u.ip::inet,u.details,u.created_at
         FROM UNNEST($1::uuid[],$2::uuid[],$3::text[],$4::text[],$5::uuid[],$6::text[],$7::jsonb[],
                     $8::timestamptz[])
           WITH ORDINALITY AS u(id,actor_id,action,target_type,target_id,ip,details,created_at,n)
         ORDER BY u.n ON CONFLICT(id) DO NOTHING",
    )
    .bind(ids)
    .bind(actors)
    .bind(actions)
    .bind(target_types)
    .bind(targets)
    .bind(ips)
    .bind(details)
    .bind(times)
    .execute(db)
    .await?;
    Ok(())
}
fn dead_letter(events: &[Event], reason: &str) {
    for event in events {
        tracing::error!(audit_dead_letter=?event, reason, "audit_dead_letter");
    }
}
/// Write a batch, trying again after a failure that may pass. An event is
/// given up, and logged in full as `audit_dead_letter`, after six attempts
/// or when the database refuses it for good.
async fn deliver(db: &sqlx::PgPool, events: &[Event]) {
    let mut backoff = Duration::from_millis(50);
    for attempt in 0..6 {
        let written = match events {
            [event] => persist(db, event).await,
            events => persist_many(db, events).await,
        };
        match written {
            Ok(()) => return,
            Err(error) if transient(&error) && attempt < 5 => {
                tracing::warn!(events = events.len(), %error, attempt, "transient audit persistence failure");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
            Err(error) if transient(&error) || events.len() == 1 => {
                dead_letter(events, &error.to_string());
                return;
            }
            Err(error) => {
                // The statement failed as a whole because of one event that
                // the database will never take. Write the others one by one.
                tracing::warn!(events = events.len(), %error, "audit batch refused; writing its events one by one");
                for event in events {
                    Box::pin(deliver(db, std::slice::from_ref(event))).await;
                }
                return;
            }
        }
    }
}
/// Take what waits in the queue, up to [`BATCH`] events, and write it in one
/// statement. Close on shutdown and bound the entire drain, including
/// in-flight retries, to five seconds.
pub async fn writer(
    db: sqlx::PgPool,
    mut receiver: mpsc::Receiver<Event>,
    stop: CancellationToken,
) {
    let mut deadline = None;
    let mut batch: Vec<Event> = Vec::with_capacity(BATCH);
    loop {
        if stop.is_cancelled() && deadline.is_none() {
            receiver.close();
            deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
        }
        batch.clear();
        let received = tokio::select! {
            received = receiver.recv_many(&mut batch, BATCH) => received,
            _ = stop.cancelled(), if deadline.is_none() => {
                receiver.close();
                deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                receiver.recv_many(&mut batch, BATCH).await
            }
        };
        if received == 0 {
            break;
        }
        metrics::histogram!("vda_audit_writer_batch_events").record(received as f64);
        let delivery = deliver(&db, &batch);
        tokio::pin!(delivery);
        let finished = if let Some(end) = deadline {
            tokio::time::timeout_at(end, &mut delivery).await.is_ok()
        } else {
            tokio::select! {
                _ = &mut delivery => true,
                _ = stop.cancelled() => {
                    receiver.close();
                    let end = tokio::time::Instant::now() + Duration::from_secs(5);
                    deadline = Some(end);
                    tokio::time::timeout_at(end, &mut delivery).await.is_ok()
                }
            }
        };
        if !finished {
            dead_letter(&batch, "shutdown deadline");
            while let Ok(event) = receiver.try_recv() {
                dead_letter(std::slice::from_ref(&event), "shutdown deadline");
            }
            break;
        }
    }
}
