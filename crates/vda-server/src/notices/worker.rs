//! Delivery of the outbox.
//!
//! Every node runs one worker. A worker claims the notices that are due with
//! `FOR UPDATE SKIP LOCKED` and, in the same statement, moves their next
//! attempt a minute ahead. That lease is what keeps two workers from sending
//! the same notice at once: a send cannot take longer than the sender's ten
//! seconds, and a claimed notice is not due again until the lease ends. No
//! transaction is held open while a request is on the wire.
//!
//! The notices of one request are delivered in the order they were written.
//! A notice can be claimed only when no earlier notice of the same request
//! still waits, so one that is being sent, or is waiting for its next
//! attempt, holds the later ones back until it is sent or given up. Notices
//! of different requests do not wait for each other.
//!
//! A claim reads the notices that are due in the order of an index, oldest
//! wait first, and asks for each whether an earlier one of its request still
//! waits, with one probe of a second index; it stops at a full batch. So a
//! claim costs about a batch as long as few notices are due and held back.
//! To keep them few, a notice that waits behind an earlier one is not left
//! due: when an attempt fails, the later notices of the request get the
//! time of its next attempt, and a notice written behind one that waits for
//! a later attempt starts with that time (`enqueue`). That time is only a
//! way to look at fewer rows. Which notice may be sent is always decided by
//! the rule above, and a later notice is never due after the one before it.
//!
//! A notice is delivered at least once. If a node stops between the request
//! and the record of its outcome, the notice is sent again after the lease;
//! the receiver sees the same `X-VDA-Delivery` and can drop the repeat.
use super::{
    format::render,
    send::{Failure, Sender},
    Format, Lock, Settings,
};
use crate::{app::AppState, error::ApiError};
use futures::{stream, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

/// A notice is tried this many times, then marked dead.
pub const MAX_ATTEMPTS: i32 = 6;
/// The wait after the first failed attempt; each later wait is three times
/// the one before: 30 s, 90 s, 4.5 min, 13.5 min, 40.5 min. Six attempts
/// take about an hour.
const FIRST_WAIT_SECONDS: f64 = 30.0;
/// Each wait is moved by up to this share, up or down, so that notices that
/// failed together do not all come back together.
const JITTER: f64 = 0.2;
/// How long a claimed notice stays claimed. Longer than any one send.
pub(crate) const LEASE_SECONDS: i32 = 60;
/// Notices claimed at once, and sent at once, by one node.
const BATCH: usize = 8;
const CONCURRENCY: usize = 4;
const TICK: Duration = Duration::from_secs(5);
/// What a waiting notice is marked with when a change of the settings made
/// it wrong to send: notices were turned off, the address or the format
/// changed, or its event was deselected. Its body was built for the old
/// settings, so it is dropped, not sent to the new ones.
pub const TURNED_OFF: &str = "notices_off";
pub const ADDRESS_CHANGED: &str = "address_changed";
pub const FORMAT_CHANGED: &str = "format_changed";
pub const EVENT_OFF: &str = "event_off";
/// Every reason a change of the settings drops a waiting notice with.
const DROPPED: [&str; 4] = [TURNED_OFF, ADDRESS_CHANGED, FORMAT_CHANGED, EVENT_OFF];

/// The wait before the next attempt, after `attempts` failed ones. `random`
/// is a number in `0.0..=1.0` that places the wait inside its jitter range.
pub fn backoff(attempts: i32, random: f64) -> Duration {
    let step = attempts.clamp(1, MAX_ATTEMPTS) - 1;
    let wait = FIRST_WAIT_SECONDS * 3f64.powi(step);
    let moved = wait * (1.0 - JITTER + 2.0 * JITTER * random.clamp(0.0, 1.0));
    Duration::from_secs_f64(moved)
}

/// Where and how to send, read from the settings for each batch. The address
/// and the secret are held in types that do not print.
#[derive(Debug, Clone)]
pub(crate) struct Route {
    format: Format,
    url: SecretString,
    secret: Option<SecretString>,
}
/// Decrypt the address and the secret. A webhook without a secret is not
/// sent: an unsigned notice could not be told from a forged one.
pub(crate) fn route(state: &AppState, settings: &Settings) -> Result<Route, Failure> {
    let crypto = &state.core.crypto;
    let url = settings
        .url_enc
        .as_deref()
        .and_then(|stored| crypto.decrypt(super::URL_AAD, stored).ok())
        .ok_or(Failure::Config)?;
    let secret = match (settings.format, settings.secret_enc.as_deref()) {
        (Format::Slack, _) => None,
        (Format::Webhook, Some(stored)) => Some(
            crypto
                .decrypt(super::SECRET_AAD, stored)
                .map_err(|_| Failure::Config)?,
        ),
        (Format::Webhook, None) => return Err(Failure::Config),
    };
    Ok(Route {
        format: settings.format,
        url: url.into(),
        secret: secret.map(Into::into),
    })
}

/// Send one notice in the format that is set, and say how it went.
pub(crate) async fn send(
    sender: &Sender,
    route: &Route,
    delivery: Uuid,
    sequence: Option<i64>,
    payload: &Value,
) -> Result<u16, Failure> {
    let rendered = render(
        route.format,
        delivery,
        sequence,
        payload,
        route.secret.as_ref().map(|secret| secret.expose_secret()),
        chrono::Utc::now().timestamp(),
    );
    sender
        .send(route.url.expose_secret(), &rendered.headers, rendered.body)
        .await
}

/// A claimed notice: its id, its place in the order, its body, and the
/// attempts already made.
type Claimed = (Uuid, i64, Value, i32);

/// Claim the notices that are due, send them, and record each outcome.
/// Returns how many notices were claimed.
pub async fn run_once(state: &AppState) -> Result<usize, ApiError> {
    // Almost every pass finds nothing: look first, without a transaction and
    // without touching the settings row. The look asks for the notice that
    // is due first, which is one step into the index of what waits. Asked
    // as "is any waiting notice due", the planner may read the whole table,
    // a week of delivered notices included, to find none.
    let any: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT next_attempt_at FROM notices WHERE status='pending'
         ORDER BY next_attempt_at LIMIT 1)<=now(),false)",
    )
    .fetch_one(&state.db)
    .await?;
    if !any {
        return Ok(0);
    }
    // The settings are read and the notices are claimed under one shared lock
    // on the settings row. A change of the settings holds that row alone
    // while it cleans the outbox, so a claim happens wholly before a change
    // (and is sent under the settings it was written for) or wholly after
    // it (and sees only what the change left).
    let mut tx = state.db.begin().await?;
    let Some(settings) = super::load(&mut *tx, Lock::Share).await? else {
        // Unknown settings: nothing is sent and nothing is dropped.
        return Ok(0);
    };
    // The batch size is written into the statement: with a parameter the
    // planner cannot know that the limit is small, and a plan for a large
    // limit reads the whole outbox.
    let claim = format!(
        "UPDATE notices n SET next_attempt_at=now()+make_interval(secs=>$1)
         FROM (SELECT c.id FROM notices c WHERE c.status='pending' AND c.next_attempt_at<=now()
               AND NOT EXISTS(SELECT 1 FROM notices e WHERE e.approval_id=c.approval_id
                              AND e.status='pending' AND e.seq<c.seq)
               ORDER BY c.next_attempt_at,c.seq LIMIT {BATCH} FOR UPDATE OF c SKIP LOCKED) due
         WHERE n.id=due.id RETURNING n.id,n.seq,n.payload,n.attempts"
    );
    let claimed: Vec<Claimed> = sqlx::query_as(&claim)
        .bind(f64::from(LEASE_SECONDS))
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    if claimed.is_empty() {
        return Ok(0);
    }
    if !settings.enabled {
        // A change that turns notices off drops what waits itself; this is
        // for a row that reached the outbox some other way.
        let ids: Vec<Uuid> = claimed.iter().map(|(id, ..)| *id).collect();
        let dropped = sqlx::query(
            "UPDATE notices SET status='dead',last_error=$2,last_attempt_at=now()
             WHERE id=ANY($1) AND status='pending'",
        )
        .bind(&ids)
        .bind(TURNED_OFF)
        .execute(&state.db)
        .await?
        .rows_affected();
        metrics::counter!("vda_notices_dead_total").increment(dropped);
        return Ok(claimed.len());
    }
    let route = route(state, &settings);
    let count = claimed.len();
    stream::iter(claimed)
        .map(|(id, sequence, payload, attempts)| {
            let route = route.as_ref();
            async move {
                let outcome = match route {
                    Ok(route) => send(&state.notices, route, id, Some(sequence), &payload).await,
                    Err(failure) => Err(*failure),
                };
                if let Err(error) = record(state, id, attempts, outcome).await {
                    // The notice stays claimed and is tried again after the lease.
                    tracing::warn!(notice_id=%id, %error, "notice outcome was not recorded");
                }
            }
        })
        .buffer_unordered(CONCURRENCY)
        .collect::<()>()
        .await;
    Ok(count)
}

/// Record the outcome of one attempt: sent, to be tried again, or dead.
///
/// A change of the settings can drop a notice while it is on the wire: the
/// claim ended before the change began, so the change found the row waiting
/// and marked it dead with the reason of the change. The record stays true
/// to what happened. A delivery that succeeded is recorded as sent, with its
/// attempt: the receiver it was claimed for has it. A delivery that failed
/// leaves the row as the change left it, dead, and is not tried again.
/// Each counter is raised only when its row was really updated.
async fn record(
    state: &AppState,
    id: Uuid,
    claimed_attempts: i32,
    outcome: Result<u16, Failure>,
) -> Result<(), ApiError> {
    let attempts = claimed_attempts.saturating_add(1);
    match outcome {
        Ok(_) => {
            // The row still waits, or a change dropped it since the claim: a
            // drop leaves the attempts as they were claimed and one of the
            // four reasons, which no failed delivery is ever recorded with.
            let sent = sqlx::query(
                "UPDATE notices SET status='sent',sent_at=now(),last_attempt_at=now(),attempts=$2,
                 last_error=NULL WHERE id=$1 AND (status='pending'
                 OR (status='dead' AND attempts=$3 AND last_error=ANY($4)))",
            )
            .bind(id)
            .bind(attempts)
            .bind(claimed_attempts)
            .bind(DROPPED.as_slice())
            .execute(&state.db)
            .await?
            .rows_affected();
            if sent > 0 {
                metrics::counter!("vda_notices_sent_total").increment(sent);
            } else {
                tracing::info!(notice_id=%id, "a delivered notice was already recorded");
            }
        }
        Err(failure) => {
            let dead = attempts >= MAX_ATTEMPTS;
            let wait = backoff(attempts, rand::random::<f64>());
            // One transaction for the failed attempt and for holding back
            // the notices behind it: the failed row is locked from its
            // update to the commit, so a change of the settings cannot drop
            // it in between and leave the later ones with a dead notice's
            // time. The change waits, and then makes them due itself.
            let mut tx = state.db.begin().await?;
            let recorded: Option<(Uuid, i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "UPDATE notices SET status=$2,attempts=$3,last_error=$4,last_attempt_at=now(),
                 next_attempt_at=now()+make_interval(secs=>$5) WHERE id=$1 AND status='pending'
                 RETURNING approval_id,seq,next_attempt_at",
            )
            .bind(id)
            .bind(if dead { "dead" } else { "pending" })
            .bind(attempts)
            .bind(failure.class())
            .bind(if dead { 0.0 } else { wait.as_secs_f64() })
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((approval, sequence, next)) = recorded.filter(|_| !dead) {
                hold_back(&mut tx, approval, sequence, next).await?;
            }
            tx.commit().await?;
            let Some(_) = recorded else {
                // Dropped by a change of the settings while it was on the
                // wire (and counted there), or recorded by another node.
                tracing::info!(notice_id=%id, error=%failure.class(), "a failed notice no longer waits; it is not tried again");
                return Ok(());
            };
            if dead {
                metrics::counter!("vda_notices_dead_total").increment(1);
                tracing::warn!(notice_id=%id, error=%failure.class(), "notice gave up after its last attempt");
            } else {
                metrics::counter!("vda_notices_retried_total").increment(1);
                tracing::info!(notice_id=%id, error=%failure.class(), attempts, "notice will be tried again");
            }
        }
    }
    Ok(())
}

/// Give the notices that wait behind a failed one the time of its next
/// attempt, so that a claim does not read them again and again until then.
/// It runs on the transaction that recorded the failure, which holds the
/// failed row: that row still waits, so none of the later ones can be on
/// the wire. A row that something else holds is skipped, never waited for
/// (no deadlock with a change of the settings): this saves work and
/// decides nothing.
async fn hold_back(
    tx: &mut sqlx::PgConnection,
    approval: Uuid,
    sequence: i64,
    until: chrono::DateTime<chrono::Utc>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE notices SET next_attempt_at=$3 WHERE id IN (SELECT id FROM notices
         WHERE approval_id=$1 AND status='pending' AND seq>$2 AND next_attempt_at<$3
         FOR UPDATE SKIP LOCKED)",
    )
    .bind(approval)
    .bind(sequence)
    .bind(until)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Remove delivered notices after seven days and dead ones after thirty.
pub async fn prune(db: &sqlx::PgPool) -> Result<(), ApiError> {
    // Two statements, so each uses the index of its own status.
    sqlx::query("DELETE FROM notices WHERE status='sent' AND sent_at<now()-interval '7 days'")
        .execute(db)
        .await?;
    sqlx::query(
        "DELETE FROM notices WHERE status='dead' AND last_attempt_at<now()-interval '30 days'",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Deliver the outbox until the gateway stops. A database error is logged
/// and the next tick tries again. At shutdown, the sends that are on the
/// wire get five seconds to finish; one that does not is sent again later,
/// by this node or another, when its lease ends.
pub async fn worker(state: AppState) {
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {_=state.stop.cancelled()=>return,_=interval.tick()=>{}}
        // Keep going while a pass finds work, so a burst does not wait for
        // the next tick and the second notice of a request follows the
        // first at once. A pass that claims nothing ends the round: a
        // notice that failed is not due again until its wait is over.
        loop {
            let batch = run_once(&state);
            tokio::pin!(batch);
            let outcome = tokio::select! {
                outcome = &mut batch => outcome,
                _ = state.stop.cancelled() => {
                    let _ = tokio::time::timeout(Duration::from_secs(5), &mut batch).await;
                    return;
                }
            };
            match outcome {
                Ok(0) => break,
                Ok(_) => continue,
                Err(error) => {
                    tracing::warn!(%error, "notice delivery failed; it is tried again on the next tick");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_attempts_take_about_an_hour() {
        let waits: Vec<f64> = (1..MAX_ATTEMPTS)
            .map(|attempts| backoff(attempts, 0.5).as_secs_f64())
            .collect();
        for (wait, expected) in waits.iter().zip([30.0, 90.0, 270.0, 810.0, 2430.0]) {
            assert!((wait - expected).abs() < 1e-6, "{wait} {expected}");
        }
        assert_eq!(waits.len(), 5);
        let total: f64 = waits.iter().sum();
        assert!((3000.0..4200.0).contains(&total), "{total}");
    }

    #[test]
    fn each_wait_grows_and_stays_inside_its_jitter() {
        for attempts in 1..MAX_ATTEMPTS {
            let middle = backoff(attempts, 0.5).as_secs_f64();
            let (low, high) = (backoff(attempts, 0.0), backoff(attempts, 1.0));
            assert!((low.as_secs_f64() - middle * 0.8).abs() < 1e-6);
            assert!((high.as_secs_f64() - middle * 1.2).abs() < 1e-6);
            // The longest wait of one step is shorter than the shortest of the next.
            assert!(high < backoff(attempts + 1, 0.0));
        }
        // Out-of-range inputs are held to the schedule.
        assert_eq!(backoff(0, 0.5), backoff(1, 0.5));
        assert_eq!(backoff(-3, 0.5), backoff(1, 0.5));
        assert_eq!(backoff(99, 0.5), backoff(MAX_ATTEMPTS, 0.5));
        assert_eq!(backoff(1, 7.0), backoff(1, 1.0));
        assert_eq!(backoff(1, -7.0), backoff(1, 0.0));
    }
}
