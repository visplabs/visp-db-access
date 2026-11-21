//! The gateway's own record of what agents do: one step per tool call, and
//! sessions that group the steps of one token.
//!
//! The agent door keeps no session, and the agent sends nothing extra. The
//! session is made here, in the metadata database: a run of calls of one
//! agent token with no gap longer than [`SESSION_GAP`]. The writer locks the
//! token's row in `agent_session_heads` while it writes, so every node gives
//! the calls of one token the same session and numbers its steps `1, 2, 3…`
//! in the order they were written.
//!
//! Recording never slows a tool call down and never fails one: a step goes
//! into a bounded queue without waiting, and a writer takes what waits and
//! writes it in one transaction, as the audit writer does. A step that finds
//! the queue full is dropped and counted.
//!
//! A step holds the SQL text of the call, never result rows. People read
//! steps over the session API ([`sessions`], [`steps`]); the agent door
//! cannot.
use crate::{app::AppState, auth::User, db, error::ApiError};
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// A longer silence than this between two calls of a token starts a new session.
pub const SESSION_GAP: Duration = Duration::from_secs(30 * 60);
/// Steps that can wait for the writer. A step that finds it full is dropped.
const QUEUE: usize = 4096;
/// Steps the writer takes from the queue and writes in one transaction.
pub const BATCH: usize = 256;
/// How long the writer waits for more steps before it writes a batch that is
/// not full. A step is in the database within about this time.
const LINGER: Duration = Duration::from_millis(250);
/// SQL text kept with a step at most. A longer statement is cut and marked;
/// a query that ran is whole in query history.
pub const MAX_SQL_BYTES: usize = 16 * 1024;
/// The other texts of a step, in bytes. A tool name, an outcome code and an
/// action word are short words of the gateway. A task is at most 500
/// characters. A hint is a sentence or two; the longest today is under 400
/// bytes.
pub const MAX_WORD_BYTES: usize = 64;
pub const MAX_TASK_BYTES: usize = 2000;
pub const MAX_HINT_BYTES: usize = 1024;
/// Steps pruned in one pass of the maintenance cycle, and sessions.
const PRUNE_STEPS: i64 = 5000;
const PRUNE_SESSIONS: i64 = 500;

/// One tool call of an agent, as the gateway saw it.
#[derive(Debug, Clone)]
pub struct Step {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub token_id: Uuid,
    pub tool: String,
    pub task: Option<String>,
    pub database: Option<Uuid>,
    pub sql: Option<String>,
    pub sql_truncated: bool,
    /// The guard's verdict, when the call had one.
    pub verdict: Option<String>,
    /// `ok`, or the code of the error the agent got.
    pub outcome: String,
    /// The fix the agent was given: its action word and its hint.
    pub fix: Option<(String, String)>,
    pub row_count: Option<i32>,
    pub elapsed_ms: i32,
    pub history_id: Option<Uuid>,
    pub approval_id: Option<Uuid>,
    /// When the call arrived.
    pub at: DateTime<Utc>,
}
/// The first `most` bytes of a text, cut at a character boundary.
fn cut(text: &str, most: usize) -> &str {
    if text.len() <= most {
        return text;
    }
    let mut end = most;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}
/// Cut SQL text to what a step keeps, at a character boundary.
pub fn clip_sql(sql: &str) -> (String, bool) {
    (
        cut(sql, MAX_SQL_BYTES).to_owned(),
        sql.len() > MAX_SQL_BYTES,
    )
}
impl Step {
    /// The step with every text within what a step keeps. Most of these
    /// texts are the gateway's own and short. The limits make sure that
    /// nothing an agent sends can make a step large, whatever path it takes
    /// into one: a step is at most about 20 KiB.
    pub fn bounded(mut self) -> Self {
        let within = |text: &mut String, most: usize| {
            let end = cut(text, most).len();
            text.truncate(end);
        };
        within(&mut self.tool, MAX_WORD_BYTES);
        within(&mut self.outcome, MAX_WORD_BYTES);
        if let Some(task) = &mut self.task {
            within(task, MAX_TASK_BYTES);
        }
        if let Some((action, hint)) = &mut self.fix {
            within(action, MAX_WORD_BYTES);
            within(hint, MAX_HINT_BYTES);
        }
        if let Some(sql) = &mut self.sql {
            self.sql_truncated |= sql.len() > MAX_SQL_BYTES;
            within(sql, MAX_SQL_BYTES);
        }
        self
    }
}

/// The way into the queue, and the writer behind it.
#[derive(Debug, Clone)]
pub struct Recorder {
    sender: mpsc::Sender<Step>,
    writer: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}
impl Recorder {
    /// Start the writer. It ends when `stop` is cancelled and the queue is
    /// written, or five seconds later.
    pub fn start(db: sqlx::PgPool, stop: CancellationToken) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE);
        let writer = tokio::spawn(writer(db, receiver, stop, SESSION_GAP));
        Self {
            sender,
            writer: Arc::new(tokio::sync::Mutex::new(Some(writer))),
        }
    }
    /// Queue a step without waiting. When the queue is full or closed the
    /// step is dropped, counted and logged; the tool call goes on.
    pub fn record(&self, step: Step) {
        if let Err(error) = self.sender.try_send(step.bounded()) {
            let step = error.into_inner();
            metrics::counter!("vda_agent_steps_dropped_total").increment(1);
            tracing::error!(agent_id = %step.agent_id, tool = %step.tool, "agent step dropped: step queue full");
        }
    }
    /// Wait for the writer to end. Call it after `stop` is cancelled.
    pub async fn finish(&self) {
        let writer = self.writer.lock().await.take();
        if let Some(writer) = writer {
            if writer.await.is_err() {
                tracing::error!("agent step writer ended abnormally");
            }
        }
    }
}

/// A session as the writer sees it while it holds the token's lock.
struct Open {
    id: Uuid,
    last_step_at: DateTime<Utc>,
    steps: i32,
    /// The steps and refusals this batch adds, and whether the session is new.
    added: i32,
    refused: i32,
    created: Option<Step>,
}

/// Write steps in one transaction and give each its session and number.
///
/// Sessions are decided here, under a row lock per token, so that two nodes
/// that write steps of one token at the same moment agree: the second waits
/// for the first and then sees its session. `gap` is the silence that starts
/// a new session. A step whose agent or token is gone is skipped, and a step
/// that is already written (a batch tried again) is not written twice.
/// Returns how many steps were written.
pub async fn persist(
    db: &sqlx::PgPool,
    steps: &[Step],
    gap: Duration,
) -> Result<usize, sqlx::Error> {
    if steps.is_empty() {
        return Ok(0);
    }
    // Whatever made the steps, nothing larger than a step keeps is written.
    let steps: Vec<Step> = steps.iter().cloned().map(Step::bounded).collect();
    let steps = steps.as_slice();
    let gap = chrono::Duration::from_std(gap).unwrap_or(chrono::Duration::MAX);
    let mut agents: Vec<Uuid> = steps.iter().map(|step| step.agent_id).collect();
    agents.sort_unstable();
    agents.dedup();
    let mut tokens: Vec<Uuid> = steps.iter().map(|step| step.token_id).collect();
    tokens.sort_unstable();
    tokens.dedup();
    let mut tx = db.begin().await?;
    // Hold the agents first, then the heads, always in id order. A delete of
    // an agent takes its row and then its tokens and heads, so this order
    // cannot cross it; a delete that is under way is waited for here, before
    // anything is held.
    let alive: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM agents WHERE id=ANY($1) ORDER BY id FOR KEY SHARE")
            .bind(&agents)
            .fetch_all(&mut *tx)
            .await?;
    sqlx::query(
        "INSERT INTO agent_session_heads(token_id) SELECT t.id FROM agent_tokens t
         WHERE t.id=ANY($1) AND t.agent_id=ANY($2) ORDER BY t.id ON CONFLICT DO NOTHING",
    )
    .bind(&tokens)
    .bind(&alive)
    .execute(&mut *tx)
    .await?;
    // Lock first, read after. A statement that waits for a lock goes on with
    // the snapshot it began with, and would read the session as it was
    // before the other writer committed. The next statement sees it as it is.
    // Only the heads of the agents that are held: the others can be deleted
    // at any moment, in the other order.
    sqlx::query(
        "SELECT 1 FROM agent_session_heads WHERE token_id IN
           (SELECT id FROM agent_tokens WHERE id=ANY($1) AND agent_id=ANY($2))
         ORDER BY token_id FOR UPDATE",
    )
    .bind(&tokens)
    .bind(&alive)
    .execute(&mut *tx)
    .await?;
    type Head = (Uuid, Uuid, Option<Uuid>, Option<DateTime<Utc>>, Option<i32>);
    let heads: Vec<Head> = sqlx::query_as(
        "SELECT h.token_id,t.agent_id,s.id,s.last_step_at,s.steps FROM agent_session_heads h
         JOIN agent_tokens t ON t.id=h.token_id
         LEFT JOIN agent_sessions s ON s.id=h.session_id
         WHERE h.token_id=ANY($1) AND t.agent_id=ANY($2)",
    )
    .bind(&tokens)
    .bind(&alive)
    .fetch_all(&mut *tx)
    .await?;
    let ids: Vec<Uuid> = steps.iter().map(|step| step.id).collect();
    let written: HashSet<Uuid> = sqlx::query_scalar("SELECT id FROM agent_steps WHERE id=ANY($1)")
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .collect();
    // The session each token is in now, by token. `None`: no session yet.
    let mut current: HashMap<Uuid, Option<usize>> = HashMap::new();
    let mut owner: HashMap<Uuid, Uuid> = HashMap::new();
    let mut open: Vec<Open> = Vec::new();
    for (token, agent, session, last, count) in heads {
        owner.insert(token, agent);
        let index = match (session, last, count) {
            (Some(id), Some(last_step_at), Some(steps)) => {
                open.push(Open {
                    id,
                    last_step_at,
                    steps,
                    added: 0,
                    refused: 0,
                    created: None,
                });
                Some(open.len() - 1)
            }
            _ => None,
        };
        current.insert(token, index);
    }
    let mut placed: Vec<(&Step, Uuid, i32)> = Vec::with_capacity(steps.len());
    for step in steps {
        // The token must still belong to the agent that the step names.
        if written.contains(&step.id) || owner.get(&step.token_id) != Some(&step.agent_id) {
            continue;
        }
        let Some(slot) = current.get_mut(&step.token_id) else {
            continue;
        };
        let continues = (*slot)
            .and_then(|index| open.get(index))
            .is_some_and(|session| step.at.signed_duration_since(session.last_step_at) <= gap);
        if !continues {
            open.push(Open {
                id: Uuid::new_v4(),
                last_step_at: step.at,
                steps: 0,
                added: 0,
                refused: 0,
                created: Some(step.clone()),
            });
            *slot = Some(open.len() - 1);
        }
        let Some(session) = (*slot).and_then(|index| open.get_mut(index)) else {
            continue;
        };
        session.added += 1;
        session.refused += i32::from(step.outcome != "ok");
        session.last_step_at = session.last_step_at.max(step.at);
        placed.push((step, session.id, session.steps + session.added));
    }
    if placed.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }
    insert_sessions(&mut tx, &open).await?;
    insert_steps(&mut tx, &placed).await?;
    let touched: Vec<&Open> = open.iter().filter(|session| session.added > 0).collect();
    sqlx::query(
        "UPDATE agent_sessions s SET last_step_at=GREATEST(s.last_step_at,u.last),
           steps=s.steps+u.added,refusals=s.refusals+u.refused
         FROM UNNEST($1::uuid[],$2::timestamptz[],$3::int4[],$4::int4[]) AS u(id,last,added,refused)
         WHERE s.id=u.id",
    )
    .bind(touched.iter().map(|s| s.id).collect::<Vec<_>>())
    .bind(touched.iter().map(|s| s.last_step_at).collect::<Vec<_>>())
    .bind(touched.iter().map(|s| s.added).collect::<Vec<_>>())
    .bind(touched.iter().map(|s| s.refused).collect::<Vec<_>>())
    .execute(&mut *tx)
    .await?;
    let (moved_tokens, moved_sessions): (Vec<Uuid>, Vec<Uuid>) = current
        .iter()
        .filter_map(|(token, index)| Some((*token, open.get((*index)?)?.id)))
        .unzip();
    sqlx::query(
        "UPDATE agent_session_heads h SET session_id=u.session
         FROM UNNEST($1::uuid[],$2::uuid[]) AS u(token,session)
         WHERE h.token_id=u.token AND h.session_id IS DISTINCT FROM u.session",
    )
    .bind(moved_tokens)
    .bind(moved_sessions)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(placed.len())
}
async fn insert_sessions(tx: &mut sqlx::PgConnection, open: &[Open]) -> Result<(), sqlx::Error> {
    let new: Vec<(&Open, &Step)> = open
        .iter()
        .filter_map(|session| Some((session, session.created.as_ref()?)))
        .collect();
    if new.is_empty() {
        return Ok(());
    }
    // The counters start at zero; the update that follows adds this batch.
    sqlx::query(
        "INSERT INTO agent_sessions(id,agent_id,token_id,started_at,last_step_at,first_task)
         SELECT * FROM UNNEST($1::uuid[],$2::uuid[],$3::uuid[],$4::timestamptz[],$4::timestamptz[],
           $5::text[])",
    )
    .bind(new.iter().map(|(s, _)| s.id).collect::<Vec<_>>())
    .bind(
        new.iter()
            .map(|(_, step)| step.agent_id)
            .collect::<Vec<_>>(),
    )
    .bind(
        new.iter()
            .map(|(_, step)| step.token_id)
            .collect::<Vec<_>>(),
    )
    .bind(new.iter().map(|(_, step)| step.at).collect::<Vec<_>>())
    .bind(
        new.iter()
            .map(|(_, step)| step.task.as_deref())
            .collect::<Vec<_>>(),
    )
    .execute(tx)
    .await?;
    Ok(())
}
async fn insert_steps(
    tx: &mut sqlx::PgConnection,
    placed: &[(&Step, Uuid, i32)],
) -> Result<(), sqlx::Error> {
    let column = |pick: &dyn Fn(&Step) -> Option<String>| -> Vec<Option<String>> {
        placed.iter().map(|(step, _, _)| pick(step)).collect()
    };
    let ids = |pick: &dyn Fn(&Step) -> Option<Uuid>| -> Vec<Option<Uuid>> {
        placed.iter().map(|(step, _, _)| pick(step)).collect()
    };
    sqlx::query(
        "INSERT INTO agent_steps(session_id,n,id,tool,task,cluster_id,sql,sql_truncated,verdict,
           outcome,fix_action,fix_hint,row_count,elapsed_ms,history_id,approval_id,created_at)
         SELECT * FROM UNNEST($1::uuid[],$2::int4[],$3::uuid[],$4::text[],$5::text[],$6::uuid[],
           $7::text[],$8::bool[],$9::text[],$10::text[],$11::text[],$12::text[],$13::int4[],
           $14::int4[],$15::uuid[],$16::uuid[],$17::timestamptz[])",
    )
    .bind(
        placed
            .iter()
            .map(|(_, session, _)| *session)
            .collect::<Vec<_>>(),
    )
    .bind(placed.iter().map(|(_, _, n)| *n).collect::<Vec<_>>())
    .bind(
        placed
            .iter()
            .map(|(step, _, _)| step.id)
            .collect::<Vec<_>>(),
    )
    .bind(column(&|step| Some(step.tool.clone())))
    .bind(column(&|step| step.task.clone()))
    .bind(ids(&|step| step.database))
    .bind(column(&|step| step.sql.clone()))
    .bind(
        placed
            .iter()
            .map(|(step, _, _)| step.sql_truncated)
            .collect::<Vec<_>>(),
    )
    .bind(column(&|step| step.verdict.clone()))
    .bind(column(&|step| Some(step.outcome.clone())))
    .bind(column(&|step| step.fix.as_ref().map(|fix| fix.0.clone())))
    .bind(column(&|step| step.fix.as_ref().map(|fix| fix.1.clone())))
    .bind(
        placed
            .iter()
            .map(|(step, _, _)| step.row_count)
            .collect::<Vec<_>>(),
    )
    .bind(
        placed
            .iter()
            .map(|(step, _, _)| step.elapsed_ms)
            .collect::<Vec<_>>(),
    )
    .bind(ids(&|step| step.history_id))
    .bind(ids(&|step| step.approval_id))
    .bind(
        placed
            .iter()
            .map(|(step, _, _)| step.at)
            .collect::<Vec<_>>(),
    )
    .execute(tx)
    .await?;
    Ok(())
}

/// Write a batch, trying again after a failure that may pass. Steps are a
/// convenience for people, not the audit trail (that is the `agent.tool`
/// event and query history), so a batch that cannot be written is dropped
/// and counted, not kept.
async fn deliver(db: &sqlx::PgPool, steps: &[Step], gap: Duration) {
    let mut backoff = Duration::from_millis(50);
    for attempt in 0..4 {
        match persist(db, steps, gap).await {
            Ok(_) => return,
            Err(error) if crate::audit::transient(&error) && attempt < 3 => {
                tracing::warn!(steps = steps.len(), %error, attempt, "transient failure writing agent steps");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
            Err(error) => {
                metrics::counter!("vda_agent_steps_dropped_total").increment(steps.len() as u64);
                tracing::error!(steps = steps.len(), %error, "agent steps dropped: they could not be written");
                return;
            }
        }
    }
}
/// Take what waits in the queue, up to [`BATCH`] steps, and write it in one
/// transaction. On shutdown the queue is closed and what is left is written
/// within five seconds.
pub async fn writer(
    db: sqlx::PgPool,
    mut receiver: mpsc::Receiver<Step>,
    stop: CancellationToken,
    gap: Duration,
) {
    let mut batch: Vec<Step> = Vec::with_capacity(BATCH);
    let mut deadline = None;
    loop {
        batch.clear();
        let received = tokio::select! {
            received = receiver.recv_many(&mut batch, BATCH) => received,
            _ = stop.cancelled(), if deadline.is_none() => {
                receiver.close();
                deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                continue;
            }
        };
        if received == 0 {
            break;
        }
        // Wait a moment for more steps, so that a quiet gateway writes a few
        // transactions a second and not one per call. A full batch does not
        // wait, and nothing waits once the gateway is stopping.
        if deadline.is_none() {
            let until = tokio::time::Instant::now() + LINGER;
            while batch.len() < BATCH {
                let room = BATCH - batch.len();
                tokio::select! {
                    more = receiver.recv_many(&mut batch, room) => if more == 0 { break },
                    _ = tokio::time::sleep_until(until) => break,
                    _ = stop.cancelled() => break,
                }
            }
        }
        let received = batch.len();
        metrics::histogram!("vda_agent_step_writer_batch_steps").record(received as f64);
        let delivery = deliver(&db, &batch, gap);
        let finished = match deadline {
            Some(end) => tokio::time::timeout_at(end, delivery).await.is_ok(),
            None => {
                delivery.await;
                true
            }
        };
        if !finished {
            metrics::counter!("vda_agent_steps_dropped_total").increment(received as u64);
            tracing::error!(steps = received, "agent steps dropped: shutdown deadline");
            break;
        }
    }
}

/// Delete steps older than `days`, and sessions that ended before then and
/// have no step left. Each call deletes a bounded number; the maintenance
/// cycle calls it again.
pub async fn prune(db: &sqlx::PgPool, days: u32) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM agent_steps WHERE (session_id,n) IN (SELECT session_id,n FROM agent_steps
         WHERE created_at<now()-make_interval(days => $1) ORDER BY created_at LIMIT $2)",
    )
    .bind(days as i32)
    .bind(PRUNE_STEPS)
    .execute(db)
    .await?;
    sqlx::query(
        "DELETE FROM agent_sessions WHERE id IN (SELECT s.id FROM agent_sessions s
         WHERE s.last_step_at<now()-make_interval(days => $1)
           AND NOT EXISTS(SELECT 1 FROM agent_steps p WHERE p.session_id=s.id)
         ORDER BY s.last_step_at LIMIT $2)",
    )
    .bind(days as i32)
    .bind(PRUNE_SESSIONS)
    .execute(db)
    .await?;
    Ok(())
}

// A session, as people read it. `active` says that the gap has not passed
// since its last step, so another call of the token would join it.
const SESSION_SQL: &str = "SELECT jsonb_build_object('id',s.id,'agent_id',s.agent_id,
    'token',jsonb_build_object('id',t.id,'hint',t.hint),
    'started_at',s.started_at,'last_step_at',s.last_step_at,'steps',s.steps,
    'refusals',s.refusals,'first_task',s.first_task,
    'active',s.last_step_at>now()-make_interval(secs => $1))
    FROM agent_sessions s JOIN agent_tokens t ON t.id=s.token_id";

/// The agent, when the caller may see it: its owner or an organization
/// administrator, as for the agent itself. Anyone else gets "not found".
async fn visible_agent(state: &AppState, user: &User, id: &str) -> Result<Uuid, ApiError> {
    let id = db::id(id)?;
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM agents WHERE id=$1 AND ($2 OR owner_id=$3)")
            .bind(id)
            .bind(user.org_role == "admin")
            .bind(user.id)
            .fetch_optional(&state.db)
            .await?;
    found.ok_or_else(ApiError::not_found)
}

/// List an agent's sessions, newest first.
pub(crate) async fn sessions(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<String>,
    Query(page): Query<db::Page>,
) -> Result<Json<Value>, ApiError> {
    let agent = visible_agent(&state, &user, &id).await?;
    let (limit, cursor) = page.bounds()?;
    let mut rows: Vec<Value> = sqlx::query_scalar(&format!(
        "{SESSION_SQL} WHERE s.agent_id=$2
         AND ($3::timestamptz IS NULL OR (s.started_at,s.id)<($3,$4))
         ORDER BY s.started_at DESC,s.id DESC LIMIT $5"
    ))
    .bind(SESSION_GAP.as_secs_f64())
    .bind(agent)
    .bind(cursor.as_ref().map(|c| c.created_at))
    .bind(cursor.as_ref().map(|c| c.id))
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let field = |row: &Value, name: &str| row.get(name).cloned().unwrap_or(Value::Null);
    let next = match rows.last().filter(|_| more) {
        Some(last) => Some(
            db::cursor::Cursor {
                created_at: serde_json::from_value(field(last, "started_at"))
                    .map_err(|_| ApiError::internal())?,
                id: serde_json::from_value(field(last, "id")).map_err(|_| ApiError::internal())?,
            }
            .encode(),
        ),
        None => None,
    };
    Ok(Json(json!({"items": rows, "next_cursor": next})))
}

#[derive(Debug, Deserialize)]
pub(crate) struct After {
    /// The number of the last step the caller has; 0 or absent for all.
    after: Option<i32>,
    limit: Option<i64>,
}
/// Read one session and its steps after a marker, oldest first. The answer
/// carries the marker for the next call, so a caller that polls reads only
/// the steps that are new.
pub(crate) async fn steps(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path((id, session)): Path<(String, String)>,
    Query(query): Query<After>,
) -> Result<Json<Value>, ApiError> {
    let agent = visible_agent(&state, &user, &id).await?;
    let session = db::id(&session)?;
    let after = query.after.unwrap_or(0);
    let limit = query.limit.unwrap_or(200);
    if after < 0 || !(1..=500).contains(&limit) {
        return Err(ApiError::validation(
            "`after` must be 0 or more and `limit` 1..=500",
        ));
    }
    let summary: Option<Value> =
        sqlx::query_scalar(&format!("{SESSION_SQL} WHERE s.id=$2 AND s.agent_id=$3"))
            .bind(SESSION_GAP.as_secs_f64())
            .bind(session)
            .bind(agent)
            .fetch_optional(&state.db)
            .await?;
    let summary = summary.ok_or_else(ApiError::not_found)?;
    let mut rows: Vec<(Value, i32)> = sqlx::query_as(
        "SELECT jsonb_build_object('n',p.n,'id',p.id,'tool',p.tool,'task',p.task,
           'database',p.cluster_id,'sql',p.sql,'sql_truncated',p.sql_truncated,
           'verdict',p.verdict,'outcome',p.outcome,
           'fix',CASE WHEN p.fix_action IS NULL THEN NULL
             ELSE jsonb_build_object('action',p.fix_action,'hint',p.fix_hint) END,
           'row_count',p.row_count,'elapsed_ms',p.elapsed_ms,'history_id',p.history_id,
           'approval_id',p.approval_id,'created_at',p.created_at),p.n
         FROM agent_steps p WHERE p.session_id=$1 AND p.n>$2 ORDER BY p.n LIMIT $3",
    )
    .bind(session)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let marker = rows.last().map_or(after, |row| row.1);
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(mut step, _)| {
            // What the agent was told, and the same in words for a person.
            let fix = step.get_mut("fix").and_then(Value::as_object_mut);
            if let Some(fix) = fix {
                let told = fix
                    .get("action")
                    .and_then(Value::as_str)
                    .map(vda_core::teach::told);
                fix.insert("told".into(), json!(told));
            }
            step
        })
        .collect();
    Ok(Json(
        json!({"session": summary, "items": items, "after": marker, "more": more}),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::print_stdout
    )]
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::ConnectInfo,
        http::Request,
        Router,
    };
    use clap::Parser;
    use std::{net::SocketAddr, time::Instant};
    use tower::ServiceExt;

    #[test]
    fn every_text_of_a_step_is_bounded_at_a_character_boundary() {
        let huge = "é".repeat(1_000_000);
        let step = Step {
            id: Uuid::nil(),
            agent_id: Uuid::nil(),
            token_id: Uuid::nil(),
            tool: huge.clone(),
            task: Some(huge.clone()),
            database: None,
            sql: Some(huge.clone()),
            sql_truncated: false,
            verdict: None,
            outcome: huge.clone(),
            fix: Some((huge.clone(), huge.clone())),
            row_count: None,
            elapsed_ms: 0,
            history_id: None,
            approval_id: None,
            at: Utc::now(),
        }
        .bounded();
        let (action, hint) = step.fix.clone().unwrap();
        for (text, most) in [
            (&step.tool, MAX_WORD_BYTES),
            (&step.outcome, MAX_WORD_BYTES),
            (&action, MAX_WORD_BYTES),
            (&hint, MAX_HINT_BYTES),
            (step.task.as_ref().unwrap(), MAX_TASK_BYTES),
            (step.sql.as_ref().unwrap(), MAX_SQL_BYTES),
        ] {
            assert!(
                text.len() <= most && text.len() + 2 > most,
                "{}",
                text.len()
            );
            assert!(text.chars().all(|c| c == 'é'));
        }
        assert!(step.sql_truncated);
        // What is already small is left as it is.
        let small = Step {
            tool: "run_query".into(),
            task: Some("Read".into()),
            sql: Some("SELECT 1".into()),
            outcome: "ok".into(),
            fix: None,
            sql_truncated: false,
            ..step
        }
        .bounded();
        assert_eq!(
            (small.tool.as_str(), small.outcome.as_str()),
            ("run_query", "ok")
        );
        assert_eq!(small.sql.as_deref(), Some("SELECT 1"));
        assert!(!small.sql_truncated);
    }

    #[test]
    fn sql_is_cut_at_a_character_boundary_and_marked() {
        assert_eq!(clip_sql("SELECT 1"), ("SELECT 1".to_owned(), false));
        let exact = "x".repeat(MAX_SQL_BYTES);
        assert_eq!(clip_sql(&exact), (exact.clone(), false));
        // A two-byte character across the limit is left out whole.
        let wide = format!("{}é", "x".repeat(MAX_SQL_BYTES - 1));
        let (cut, marked) = clip_sql(&wide);
        assert!(marked);
        assert_eq!(cut.len(), MAX_SQL_BYTES - 1);
        assert!(cut.is_char_boundary(cut.len()));
    }

    async fn call(app: &Router, token: &str) {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_databases","arguments":{"task":"Load: see what I can reach"}}}"#;
        let mut req = Request::post("/api/v1/mcp")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
        let response = app.clone().oneshot(req).await.unwrap();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            answer.pointer("/result/isError"),
            Some(&Value::Bool(false)),
            "{answer}"
        );
    }

    /// What recording costs. Run it alone, in release mode, against a local
    /// metadata database:
    ///
    /// ```sh
    /// cargo test --release -p vda-server --lib steps::tests::load -- --ignored --nocapture
    /// ```
    ///
    /// It drives `list_databases` (a tool that reads only the metadata
    /// database) from many agents at once through the real router, with the
    /// recorder and then with one that throws every step away, several
    /// rounds each, and prints calls per second. It also prints what one
    /// `record` call costs on the call path and how fast the writer stores.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "a load measurement; needs VDA_TEST_DATABASE_URL"]
    async fn load() {
        const AGENTS: usize = 64;
        const CALLS: usize = 100;
        const ROUNDS: usize = 5;
        let Ok(url) = std::env::var("VDA_TEST_DATABASE_URL") else {
            eprintln!("skipped: VDA_TEST_DATABASE_URL is not set");
            return;
        };
        let root = sqlx::PgPool::connect(&url).await.unwrap();
        let schema = format!("vda_load_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&root)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema},public");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .after_connect(move |c, _| {
                let path = path.clone();
                Box::pin(async move {
                    sqlx::query(&path).execute(&mut *c).await?;
                    sqlx::query("SET TIME ZONE 'UTC'").execute(c).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&db).await.unwrap();
        let config = crate::config::Cli::parse_from(["test"]).config;
        let (state, _writer) = AppState::new(
            db.clone(),
            config,
            crate::crypto::Crypto::new(&[4; 32]),
            None,
        )
        .await
        .unwrap();
        let (owner, project, cluster) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        sqlx::query(
            "INSERT INTO users(id,email,name,password_hash,org_role) VALUES ($1,'load@steps.example','Load',$2,'admin')",
        )
        .bind(owner)
        .bind(&state.dummy_password_hash)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO projects(id,name) VALUES ($1,'Load')")
            .bind(project)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO clusters(id,project_id,name,engine,provider,region,environment,host,port,database,username,password_enc,tls_mode)
            VALUES ($1,$2,'Load','postgres','onprem','local','development','127.0.0.1',9,'x','x',$3,'disable')")
            .bind(cluster).bind(project).bind(Vec::<u8>::new()).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO cluster_policies(cluster_id,policy) VALUES ($1,$2)")
            .bind(cluster)
            .bind(json!(crate::policy::Policy::for_environment("development")))
            .execute(&db)
            .await
            .unwrap();
        let mut tokens = Vec::new();
        let mut identities = Vec::new();
        for n in 0..AGENTS {
            let (agent, token_id) = (Uuid::new_v4(), Uuid::new_v4());
            let token = vda_core::agents::generate();
            sqlx::query("INSERT INTO agents(id,owner_id,name) VALUES ($1,$2,$3)")
                .bind(agent)
                .bind(owner)
                .bind(format!("load-{n}"))
                .execute(&db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO agent_clusters(agent_id,cluster_id) VALUES ($1,$2)")
                .bind(agent)
                .bind(cluster)
                .execute(&db)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO agent_tokens(id,agent_id,token_hash,hint,expires_at)
                 VALUES ($1,$2,$3,$4,now()+interval '1 day')",
            )
            .bind(token_id)
            .bind(agent)
            .bind(&token.hash)
            .bind(&token.hint)
            .execute(&db)
            .await
            .unwrap();
            tokens.push(token.secret);
            identities.push((agent, token_id));
        }
        // The same gateway, with a recorder that throws every step away.
        let (sender, mut discard) = mpsc::channel(QUEUE);
        tokio::spawn(async move { while discard.recv().await.is_some() {} });
        let mut silent = state.clone();
        silent.steps = Recorder {
            sender,
            writer: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let (recording, without) = (
            crate::app::router(state.clone()),
            crate::app::router(silent),
        );
        let round = |app: Router| {
            let tokens = tokens.clone();
            async move {
                let start = Instant::now();
                let workers: Vec<_> = tokens
                    .into_iter()
                    .map(|token| {
                        let app = app.clone();
                        tokio::spawn(async move {
                            for _ in 0..CALLS {
                                call(&app, &token).await;
                            }
                        })
                    })
                    .collect();
                for worker in workers {
                    worker.await.unwrap();
                }
                (AGENTS * CALLS) as f64 / start.elapsed().as_secs_f64()
            }
        };
        let (mut with, mut none) = (Vec::new(), Vec::new());
        for n in 0..ROUNDS {
            // Each round starts a new minute of the call limit.
            for (app, rates, label) in [
                (&without, &mut none, "without"),
                (&recording, &mut with, "with"),
            ] {
                state.agent_calls.invalidate_all();
                state.agent_calls.run_pending_tasks().await;
                let rate = round(app.clone()).await;
                println!("round {n} {label:>7} recording: {rate:8.0} calls/s");
                rates.push(rate);
            }
        }
        let median = |rates: &mut Vec<f64>| {
            rates.sort_by(|a, b| a.total_cmp(b));
            rates[rates.len() / 2]
        };
        let (with, none) = (median(&mut with), median(&mut none));
        println!(
            "median of {ROUNDS} rounds, {AGENTS} agents x {CALLS} calls: without recording {none:.0} calls/s, with recording {with:.0} calls/s ({:+.1}%)",
            (with / none - 1.0) * 100.0
        );
        // Every step of the recorded rounds is written, and none was dropped.
        let expected = (AGENTS * CALLS * ROUNDS) as i64;
        let mut written = 0i64;
        for _ in 0..600 {
            written = sqlx::query_scalar("SELECT count(*) FROM agent_steps")
                .fetch_one(&db)
                .await
                .unwrap();
            if written >= expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!("steps written: {written} of {expected}");
        assert_eq!(written, expected);
        // The cost on the call path: one `record` is a `try_send`.
        let step = |n: usize| {
            let (agent_id, token_id) = identities[n % AGENTS];
            Step {
                id: Uuid::new_v4(),
                agent_id,
                token_id,
                tool: "run_query".into(),
                task: Some("Load: a step".into()),
                database: Some(cluster),
                sql: Some("SELECT id, name FROM customers WHERE id = 1".into()),
                sql_truncated: false,
                verdict: Some("allow".into()),
                outcome: "ok".into(),
                fix: None,
                row_count: Some(1),
                elapsed_ms: 3,
                history_id: None,
                approval_id: None,
                at: Utc::now(),
            }
        };
        let (sender, mut sink) = mpsc::channel(QUEUE);
        let recorder = Recorder {
            sender,
            writer: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let prepared: Vec<Step> = (0..QUEUE).map(step).collect();
        let start = Instant::now();
        for step in prepared {
            recorder.record(step);
        }
        println!(
            "record(): {:.0} ns per call",
            start.elapsed().as_nanos() as f64 / QUEUE as f64
        );
        while sink.try_recv().is_ok() {}
        // The writer alone: batches of 256 into the session tables.
        let batches: Vec<Vec<Step>> = (0..80)
            .map(|batch| (0..BATCH).map(|n| step(batch * BATCH + n)).collect())
            .collect();
        let start = Instant::now();
        for batch in &batches {
            assert_eq!(persist(&db, batch, SESSION_GAP).await.unwrap(), BATCH);
        }
        let stored = (80 * BATCH) as f64;
        println!(
            "writer: {:.0} steps/s in batches of {BATCH} ({:.1} ms per batch)",
            stored / start.elapsed().as_secs_f64(),
            start.elapsed().as_secs_f64() * 1000.0 / 80.0
        );
        state.stop.cancel();
        state.steps.finish().await;
        db.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&root)
            .await
            .unwrap();
        root.close().await;
    }
}
