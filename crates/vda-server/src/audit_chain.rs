//! Running the audit hash chain: the sealer, the background check, the
//! checkpoints, the two endpoints and the offline command. The chain itself,
//! its order and its bytes are in `vda_core::chain`.
//!
//! Every node runs one [`worker`]. On each tick it tries to seal, to take
//! the next step of the background check, and it refreshes the gauges. The
//! two jobs are each done by one node at a time: a job runs inside a
//! transaction that holds an advisory lock for it, and a node that does not
//! get the lock leaves the job to the node that has it. The lock goes with
//! the transaction, so a node that dies in the middle leaves nothing held
//! and nothing half written.
//!
//! A sealed chain that is cut off at its end still verifies: nothing in the
//! database says that it used to be longer. So each node also remembers the
//! last head it saw and checks that it is still there, and writes the head
//! to its log as `audit_checkpoint` now and then. A log store that the
//! database's administrator cannot change is what proves the end.
use crate::{
    app::AppState,
    audit::Event,
    auth::User,
    crypto::Crypto,
    error::{ApiError, Input},
    network::ClientIp,
    rbac,
};
use axum::{extract::State, Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::Write,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};
use uuid::Uuid;
use vda_core::chain::{self, Checkpoint, Head, Outcome, Problem, Status, Step};

/// How often a node looks for rows to seal.
pub const TICK: Duration = Duration::from_secs(2);
/// Links appended in one transaction.
pub const SEAL_BATCH: i64 = 500;
/// Transactions of the sealer in one tick, so that the other work of the
/// tick is not kept waiting by a long backlog: 20,000 rows a tick.
const SEAL_BATCHES: usize = 40;
/// Links the background check reads in one tick.
pub const VERIFY_SLICE: i64 = 5000;
/// A pass of the background check begins this long after the one before
/// began, or when that one ends, whichever is later.
pub const PASS_SECONDS: f64 = 60.0;
/// The head is written to the log at most this often, and only when it moved.
const CHECKPOINT_EVERY: Duration = Duration::from_secs(300);
/// `POST /audit/verify`: links checked when the caller names no number, and
/// the most that one call checks.
const VERIFY_DEFAULT: i64 = 1000;
const VERIFY_MOST: i64 = 10_000;
/// Calls of `POST /audit/verify` in one minute, by anyone, on one node.
pub const VERIFIES_PER_MINUTE: u32 = 6;

/// What this node has seen of the chain since it started.
#[derive(Debug, Default)]
pub struct Seen {
    inner: Mutex<Memory>,
}
#[derive(Debug, Default, Clone)]
struct Memory {
    /// The last head this node saw. It must stay in the chain for ever.
    head: Option<Checkpoint>,
    /// Set when that head was gone: the end of the chain was removed, or
    /// the chain was rebuilt, while this node was running.
    lost: Option<Problem>,
    /// The head of the last `audit_checkpoint` line, and when it was written.
    logged: Option<(i64, Instant)>,
}
impl Seen {
    fn memory(&self) -> Memory {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    fn update(&self, change: impl FnOnce(&mut Memory)) {
        change(&mut self.inner.lock().unwrap_or_else(PoisonError::into_inner));
    }
    /// The problem this node found by remembering the head, if any.
    pub fn lost(&self) -> Option<Problem> {
        self.memory().lost
    }
}

fn report(found: &Problem, source: &str) {
    metrics::counter!("vda_audit_chain_breaks_total").increment(1);
    tracing::error!(
        kind = ?found.kind,
        position = found.position,
        audit_id = ?found.audit_id,
        seq = ?found.seq,
        source,
        "audit_chain_break: {}",
        found.message
    );
}
fn checkpoint(head: &Head) {
    tracing::info!(
        position = head.position,
        hash = %head.hash,
        key_id = %head.key_id,
        "audit_checkpoint"
    );
}
/// Seal what can be sealed, a bounded number of batches, and return the
/// links appended: none when another node is sealing.
pub async fn seal(state: &AppState, batches: usize) -> Result<u64, sqlx::Error> {
    let mut total = 0u64;
    for _ in 0..batches {
        let Some(sealed) = chain::seal(&state.db, &state.core.crypto, SEAL_BATCH).await? else {
            break;
        };
        total += sealed.rows as u64;
        metrics::counter!("vda_audit_chain_sealed_total").increment(sealed.rows as u64);
        if let Some(previous) = sealed.previous_key {
            // Expected once after a change of the master key, and never
            // otherwise: two nodes with different keys would alternate.
            tracing::warn!(
                previous_key_id = %previous,
                key_id = %state.core.crypto.chain_key_id(),
                "the audit chain continues with another key; the links before it cannot be verified with this one"
            );
        }
        if (sealed.rows as i64) < SEAL_BATCH || state.stop.is_cancelled() {
            break;
        }
    }
    Ok(total)
}
/// Measure the backlog, check that the head this node remembers is still in
/// the chain, remember the new head and log it when a checkpoint is due.
async fn observe(state: &AppState) -> Result<(), sqlx::Error> {
    let mut connection = state.db.acquire().await?;
    let head = chain::head(&mut connection).await?;
    let backlog = chain::backlog(&mut connection, head.as_ref()).await?;
    metrics::gauge!("vda_audit_chain_head_position")
        .set(head.as_ref().map_or(0, |head| head.position) as f64);
    metrics::gauge!("vda_audit_chain_unsealed_rows").set(backlog.unsealed as f64);
    metrics::gauge!("vda_audit_chain_oldest_unsealed_seconds")
        .set(backlog.oldest_unsealed_seconds.unwrap_or(0.0));
    let memory = state.audit_chain.memory();
    if let (Some(seen), None) = (&memory.head, &memory.lost) {
        if let Some(found) = chain::check_checkpoint(&mut connection, seen).await? {
            report(&found, "remembered head");
            state.audit_chain.update(|memory| memory.lost = Some(found));
        }
    }
    let Some(head) = head else { return Ok(()) };
    let due = memory
        .logged
        .is_none_or(|(position, at)| position != head.position && at.elapsed() >= CHECKPOINT_EVERY);
    if due {
        checkpoint(&head);
    }
    state.audit_chain.update(|memory| {
        // A head that replaced a lost one is not remembered over it.
        if memory.lost.is_none() {
            memory.head = Some(Checkpoint {
                position: head.position,
                hash: head.hash,
                key_id: Some(head.key_id),
            });
        }
        if due {
            memory.logged = Some((head.position, Instant::now()));
        }
    });
    Ok(())
}
/// Take the next step of the background check, and set the gauges from the
/// stored result, so every node shows it and not only the one that ran the
/// pass.
async fn check(state: &AppState) -> Result<(), sqlx::Error> {
    let step =
        chain::verify_step(&state.db, &state.core.crypto, VERIFY_SLICE, PASS_SECONDS).await?;
    match step {
        Step::Idle => {}
        Step::Checked { links, .. } => {
            metrics::counter!("vda_audit_chain_verified_links_total").increment(links as u64);
        }
        Step::Finished { links, outcome } => {
            metrics::counter!("vda_audit_chain_verified_links_total").increment(links as u64);
            metrics::counter!("vda_audit_chain_passes_total").increment(1);
            if let Some(found) = &outcome.problem {
                report(found, "background check");
            }
        }
    }
    let stored = chain::verification(&mut *state.db.acquire().await?).await?;
    let result = stored.result.as_ref();
    let broken = state.audit_chain.lost().is_some()
        || result.is_some_and(|result| result.status == Status::Broken);
    metrics::gauge!("vda_audit_chain_broken").set(if broken { 1.0 } else { 0.0 });
    metrics::gauge!("vda_audit_chain_unverifiable_links")
        .set(result.map_or(0, |result| result.links - result.verified) as f64);
    metrics::gauge!("vda_audit_chain_last_pass_age_seconds")
        .set(stored.finished_seconds.unwrap_or(0.0));
    Ok(())
}
/// One tick: seal, measure and remember the head, check a slice. The three
/// parts do not depend on each other: a part that fails does not keep the
/// others from running, so a row that one of them cannot read never stops
/// the check. Returns the first failure.
pub async fn cycle(state: &AppState) -> Result<(), sqlx::Error> {
    let sealed = seal(state, SEAL_BATCHES).await.map(|_| ());
    let observed = observe(state).await;
    let checked = check(state).await;
    sealed.and(observed).and(checked)
}
/// Seal and check until the gateway stops. A failure is logged and the next
/// tick tries again: the database may be away for a while.
pub async fn worker(state: AppState) {
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {_=state.stop.cancelled()=>break,_=interval.tick()=>{}}
        let work = cycle(&state);
        // A tick that is cut short has written all of a batch or none of it.
        let done = tokio::select! {_=state.stop.cancelled()=>break,done=work=>done};
        if let Err(error) = done {
            metrics::counter!("vda_audit_chain_errors_total").increment(1);
            tracing::warn!(%error, "audit chain tick failed; trying again");
        }
    }
}
/// At shutdown, after the audit queue is drained: seal what can be sealed
/// and write the head to the log, so the last checkpoint of a node is the
/// chain as the node left it.
pub async fn finish(state: &AppState) {
    let sealing = async {
        chain::seal(&state.db, &state.core.crypto, SEAL_BATCH).await?;
        chain::head(&mut *state.db.acquire().await?).await
    };
    match tokio::time::timeout(Duration::from_secs(5), sealing).await {
        Ok(Ok(Some(head))) => checkpoint(&head),
        Ok(Ok(None)) => {}
        Ok(Err(error)) => tracing::warn!(%error, "no audit checkpoint at shutdown"),
        Err(_) => tracing::warn!("no audit checkpoint at shutdown: the database did not answer"),
    }
}

fn head_json(head: Option<&Head>) -> Value {
    head.map_or(Value::Null, |head| json!(head))
}
/// `GET /audit/integrity`: the head, how much waits to be sealed, and what
/// the background check last found.
pub(crate) async fn integrity(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<Value>, ApiError> {
    rbac::require_admin(&user)?;
    let mut connection = state.db.acquire().await?;
    let head = chain::head(&mut connection).await?;
    let backlog = chain::backlog(&mut connection, head.as_ref()).await?;
    let stored = chain::verification(&mut connection).await?;
    let lost = state.audit_chain.lost();
    let result = stored.result.as_ref();
    // What this node saw go missing is not something a later pass can see.
    let problem = lost
        .as_ref()
        .or_else(|| result.and_then(|result| result.problem.as_ref()));
    let status = match (problem, result) {
        (Some(_), _) => json!(Status::Broken),
        (None, Some(result)) => json!(result.status),
        (None, None) => json!("pending"),
    };
    Ok(Json(json!({
        "head": head_json(head.as_ref()),
        "key_id": state.core.crypto.chain_key_id(),
        "sealed": head.as_ref().map_or(0, |head| head.position),
        "unsealed": backlog.unsealed,
        "oldest_unsealed_at": backlog.oldest_unsealed_at,
        "oldest_unsealed_seconds": backlog.oldest_unsealed_seconds,
        "verification": {
            "status": status,
            "checked_at": stored.finished_at,
            "key_id": result.map(|result| &result.key_id),
            "links": result.map_or(0, |result| result.links),
            "verified": result.map_or(0, |result| result.verified),
            "unverifiable": result.map(|result| result.unverifiable.as_slice()).unwrap_or_default(),
            "problem": problem,
            "running": (stored.position > 0).then(|| json!({
                "position": stored.position,
                "started_at": stored.pass_started_at,
            })),
        },
    })))
}
/// The body of `POST /audit/verify`. Without `from_position` the newest
/// `limit` links are checked.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyRequest {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    from_position: Option<i64>,
}
/// `POST /audit/verify`: check a bounded range of the chain now. Reads
/// only; the call itself is written to the audit log.
pub(crate) async fn verify(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Input(body): Input<VerifyRequest>,
) -> Result<Json<Value>, ApiError> {
    rbac::require_admin(&user)?;
    let limit = body.limit.unwrap_or(VERIFY_DEFAULT);
    if !(1..=VERIFY_MOST).contains(&limit) {
        return Err(ApiError::validation(format!(
            "Limit must be 1..={VERIFY_MOST}"
        )));
    }
    if body.from_position.is_some_and(|from| from < 1) {
        return Err(ApiError::validation("Position must be 1 or more"));
    }
    state.check_audit_verify_rate().await?;
    let mut connection = state.db.acquire().await?;
    let head = chain::head(&mut connection).await?;
    let end = head.as_ref().map_or(0, |head| head.position);
    let from = body
        .from_position
        .unwrap_or_else(|| (end - limit + 1).max(1));
    let to = from.saturating_add(limit - 1).min(end);
    let outcome = chain::verify(&mut connection, &state.core.crypto, from, to).await?;
    drop(connection);
    crate::audit::persist(
        &state.db,
        &Event {
            id: Uuid::new_v4(),
            actor_id: Some(user.id),
            action: "audit.verify".into(),
            target_type: Some("audit".into()),
            target_id: None,
            ip: Some(ip.0),
            details: json!({
                "from_position": outcome.from_position,
                "to_position": outcome.to_position,
                "status": outcome.status,
                "problem": outcome.problem.as_ref().map(|found| json!({
                    "kind": found.kind,
                    "position": found.position,
                })),
            }),
            created_at: chrono::Utc::now(),
        },
    )
    .await?;
    if let Some(found) = &outcome.problem {
        report(found, "verify now");
    }
    let mut body = json!(outcome);
    if let Some(object) = body.as_object_mut() {
        object.insert("head".into(), head_json(head.as_ref()));
    }
    Ok(Json(body))
}

/// The exit codes of `verify-audit`. 1 is an error before a verdict (no
/// database, no key) and 2 is a wrong command line, as for every command.
pub const EXIT_INTACT: i32 = 0;
/// Something was changed, deleted, put in or cut off.
pub const EXIT_BROKEN: i32 = 3;
/// Nothing is wrong with what could be checked, but some links were sealed
/// with another master key and are not verified.
pub const EXIT_PARTIAL: i32 = 4;

fn describe(out: &mut impl Write, found: &Problem) -> std::io::Result<()> {
    writeln!(
        out,
        "problem: kind={} position={} audit_id={} seq={}\n  {}",
        json!(found.kind).as_str().unwrap_or("unknown"),
        found.position,
        found
            .audit_id
            .map_or_else(|| "-".to_owned(), |id| id.to_string()),
        found
            .seq
            .map_or_else(|| "-".to_owned(), |seq| seq.to_string()),
        found.message
    )
}
/// `verify-audit`: read the whole chain and every audit row it seals, in
/// one read-only snapshot, and say whether it is intact. Writes nothing and
/// does not migrate. Returns the exit code.
pub async fn verify_offline(
    url: &str,
    crypto: &Crypto,
    expect: Option<Checkpoint>,
    out: &mut impl Write,
) -> anyhow::Result<i32> {
    use sqlx::Connection;
    let mut connection = sqlx::PgConnection::connect(url).await?;
    sqlx::query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut connection)
        .await?;
    let present: bool = sqlx::query_scalar("SELECT to_regclass('audit_chain') IS NOT NULL")
        .fetch_one(&mut connection)
        .await?;
    anyhow::ensure!(
        present,
        "this database has no audit chain yet: run `migrate` with this version first"
    );
    let head = chain::head(&mut connection).await?;
    let end = head.as_ref().map_or(0, |head| head.position);
    let mut outcome: Option<Outcome> = None;
    let mut next = 1;
    loop {
        let to = (next + VERIFY_MOST - 1).min(end);
        let step = chain::verify(&mut connection, crypto, next, to).await?;
        let total = match outcome.take() {
            Some(mut total) => {
                total.extend(step);
                total
            }
            None => step,
        };
        let stop = total.problem.is_some() || to >= end;
        outcome = Some(total);
        if stop {
            break;
        }
        next = to + 1;
    }
    let backlog = chain::backlog(&mut connection, head.as_ref()).await?;
    let lost = match &expect {
        Some(expect) => chain::check_checkpoint(&mut connection, expect).await?,
        None => None,
    };
    sqlx::query("ROLLBACK").execute(&mut connection).await?;
    connection.close().await?;
    let Some(outcome) = outcome else {
        anyhow::bail!("nothing was checked");
    };
    match &head {
        Some(head) => writeln!(
            out,
            "head: position={} hash={} key_id={} sealed_at={}",
            head.position, head.hash, head.key_id, head.sealed_at
        )?,
        None => writeln!(out, "head: none (nothing is sealed yet)")?,
    }
    writeln!(
        out,
        "checked: {} links, {} verified with key {}",
        outcome.links, outcome.verified, outcome.key_id
    )?;
    for segment in &outcome.unverifiable {
        writeln!(
            out,
            "not verifiable with this key: positions {}-{} (key {})",
            segment.first_position, segment.last_position, segment.key_id
        )?;
    }
    writeln!(
        out,
        "unsealed: {} audit rows wait to be sealed{}",
        backlog.unsealed,
        backlog
            .oldest_unsealed_seconds
            .map_or_else(String::new, |seconds| format!(
                ", the oldest for {seconds:.0} s"
            ))
    )?;
    if let Some(found) = &outcome.problem {
        describe(out, found)?;
    }
    if let Some(found) = &lost {
        describe(out, found)?;
    } else if let Some(expect) = &expect {
        writeln!(
            out,
            "checkpoint: position={} is in the chain with that hash{}",
            expect.position,
            if expect.key_id.is_some() {
                " and key"
            } else {
                ""
            }
        )?;
    }
    let code = if outcome.problem.is_some() || lost.is_some() {
        writeln!(out, "result: BROKEN")?;
        EXIT_BROKEN
    } else if outcome.status == Status::Partial {
        writeln!(
            out,
            "result: NOT FULLY VERIFIED (run again with the master key of the other links)"
        )?;
        EXIT_PARTIAL
    } else {
        writeln!(out, "result: INTACT")?;
        EXIT_INTACT
    };
    Ok(code)
}
