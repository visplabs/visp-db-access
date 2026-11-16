//! Guard, cost gate, concurrency, routing, cancellation, masking and query history.
use crate::{
    access::Actor,
    audit::{Event, History},
    error::ApiError,
    policy::Policy,
    records::ClusterRecord,
    Core,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;
use vda_guard::{AccessLevel, Analysis, Verdict};

/// SQL input; the optional client-generated query ID enables early cancellation.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryInput {
    pub sql: String,
    pub query_id: Option<Uuid>,
    /// What this query is for, in the caller's words. Kept in history.
    #[serde(default)]
    pub task: Option<String>,
}
/// Complete guarded query result wire shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub query_id: Uuid,
    pub columns: Vec<crate::masking::Column>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    pub truncated: bool,
    pub affected_rows: Option<u64>,
    pub elapsed_ms: u64,
    pub executed_sql: String,
    pub routed_to: String,
    pub analysis: Analysis,
}
fn validate_sql(sql: &str) -> Result<(), ApiError> {
    crate::sanitation::text(sql)?;
    if sql.trim().is_empty() || sql.len() > 1024 * 1024 {
        Err(ApiError::validation("SQL must contain 1..=1048576 bytes"))
    } else {
        Ok(())
    }
}
/// A task note is short plain text.
pub fn validate_task(task: &str) -> Result<(), ApiError> {
    crate::sanitation::text(task)?;
    if task.trim().is_empty() || task.chars().count() > 500 {
        return Err(ApiError::validation("Task must contain 1..=500 characters"));
    }
    // One line of visible text: it is shown to people in history and audit.
    if task.contains(['\n', '\r', '\t']) || !crate::sanitation::shows_all(task.trim()) {
        return Err(ApiError::validation(
            "Task must be one line with no invisible or direction-changing characters",
        ));
    }
    Ok(())
}
fn dialect(c: &ClusterRecord) -> vda_guard::Dialect {
    if c.engine == "mysql" {
        vda_guard::Dialect::MySql
    } else {
        vda_guard::Dialect::Postgres
    }
}
/// The policy as it applies to this actor. Analysis and execution both use it,
/// so what an actor is told always matches what then happens.
fn for_actor(mut policy: Policy, actor: &Actor, approved: bool) -> Policy {
    if approved {
        policy.require_approval_for_writes = false;
    } else if actor.agent.is_some() {
        // An agent never writes on its own word. A person approves each write.
        policy.require_approval_for_writes = true;
    }
    policy
}
/// Guard verdict plus the masking checks, for one statement text.
fn judge(sql: &str, cluster: &ClusterRecord, level: AccessLevel, policy: &Policy) -> Analysis {
    let mut analysis = vda_guard::analyze(sql, dialect(cluster), level, &policy.guard());
    crate::masking::harden_analysis(&mut analysis, &policy.masked_columns, sql, dialect(cluster));
    analysis
}
/// Analyze without target I/O, under the actor's current access and policy.
pub async fn analyze(
    core: &Core,
    actor: &Actor,
    cluster_id: Uuid,
    sql: &str,
    ip: std::net::IpAddr,
) -> Result<Analysis, ApiError> {
    validate_sql(sql)?;
    let (access, policy) = tokio::join!(
        crate::access::require_level_effective(&core.db, actor, cluster_id, AccessLevel::Read),
        crate::records::policy(&core.db, cluster_id)
    );
    let (c, level) = access?;
    let policy = policy?;
    if !crate::network::allowed(ip, &crate::network::parse_cidrs(&policy.allowed_cidrs)?) {
        return Err(ApiError::forbidden());
    }
    Ok(judge(sql, &c, level, &for_actor(policy, actor, false)))
}
struct Registration {
    core: Core,
    id: Uuid,
    token: CancellationToken,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.token.cancel();
        self.core.active.remove(&self.id);
    }
}
/// Run the pipeline; approved executions still re-check current grants and policy.
pub async fn run(
    core: &Core,
    actor: &Actor,
    cluster_id: Uuid,
    body: QueryInput,
    ip: std::net::IpAddr,
    approved: bool,
) -> Result<QueryResult, ApiError> {
    run_inner(core, actor, cluster_id, body, ip, (approved, None)).await
}

/// Use the claim's timeout ceiling even if policy changes while approval work starts.
pub async fn run_approved(
    core: &Core,
    actor: &Actor,
    cluster_id: Uuid,
    body: QueryInput,
    ip: std::net::IpAddr,
    timeout_ms: u64,
) -> Result<QueryResult, ApiError> {
    run_inner(core, actor, cluster_id, body, ip, (true, Some(timeout_ms))).await
}

async fn run_inner(
    core: &Core,
    actor: &Actor,
    cluster_id: Uuid,
    body: QueryInput,
    ip: std::net::IpAddr,
    approval: (bool, Option<u64>),
) -> Result<QueryResult, ApiError> {
    let (approved, timeout_ms) = approval;
    validate_sql(&body.sql)?;
    if let Some(task) = &body.task {
        validate_task(task)?;
    }
    let (access, policy) = tokio::join!(
        crate::access::require_level_effective(&core.db, actor, cluster_id, AccessLevel::Read),
        crate::records::policy(&core.db, cluster_id)
    );
    let (c, level) = access?;
    let mut policy = policy?;
    if !crate::network::allowed(ip, &crate::network::parse_cidrs(&policy.allowed_cidrs)?) {
        return Err(ApiError::forbidden());
    }
    if let Some(timeout_ms) = timeout_ms {
        policy.statement_timeout_ms = policy.statement_timeout_ms.min(timeout_ms);
        policy.lock_timeout_ms = policy.lock_timeout_ms.min(policy.statement_timeout_ms);
    }
    let policy = for_actor(policy, actor, approved);
    let analysis = judge(&body.sql, &c, level, &policy);
    let query_id = body.query_id.unwrap_or_else(Uuid::new_v4);
    let token = CancellationToken::new();
    match core.active.entry(query_id) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return Err(ApiError::conflict("Query ID is already active"))
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(crate::ActiveQuery {
                user_id: actor.user_id,
                agent: actor.agent.as_ref().map(|a| (a.agent_id, a.token_id)),
                cancel: token.clone(),
            });
        }
    }
    let registration = Registration {
        core: core.clone(),
        id: query_id,
        token: token.clone(),
    };
    // The agent may have been paused or its token revoked after this request
    // was authenticated. Now that the query is registered a later stop will
    // cancel it; this check closes the gap before that.
    if let Some(scope) = &actor.agent {
        if !crate::agents::still_valid(&core.db, scope.token_id).await? {
            return Err(ApiError::unauthenticated());
        }
    }
    // A client UUID is only a cancellation handle; every attempt has a fresh audit identity.
    let history_id = Uuid::new_v4();
    let verdict = serde_json::to_value(analysis.verdict)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "deny".into());
    let blocked = analysis.verdict == Verdict::Deny
        || (analysis.verdict == Verdict::RequiresApproval && !approved);
    let history = History {
        id: history_id,
        cluster_id: c.id,
        cluster_name: c.name.clone(),
        user_id: actor.user_id,
        user_email: actor.email.clone(),
        agent_id: actor.agent.as_ref().map(|a| a.agent_id),
        task: body.task.as_deref().map(|task| task.trim().to_owned()),
        sql: body.sql,
        verdict: verdict.clone(),
        status: if blocked { "blocked" } else { "running" }.into(),
        row_count: None,
        elapsed_ms: blocked.then_some(0),
        error: if analysis.verdict == Verdict::Deny {
            Some("Query denied by policy".into())
        } else if blocked {
            Some("Query requires approval".into())
        } else {
            None
        },
    };
    let intent = Event {
        id: Uuid::new_v4(),
        actor_id: Some(actor.user_id),
        action: "query.execute".into(),
        target_type: Some("cluster".into()),
        target_id: Some(c.id),
        ip: Some(ip),
        details: json!({"query_id":query_id,"history_id":history_id,"status":history.status,"agent_id":history.agent_id}),
        created_at: chrono::Utc::now(),
    };
    let unavailable = |error: sqlx::Error| {
        tracing::error!(%error, "query intent persistence failed; refusing target I/O");
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal",
            "Audit unavailable",
        )
    };
    let mut tx = core.db.begin().await.map_err(unavailable)?;
    if let Some(agent_id) = history.agent_id {
        // The budget is taken and the attempt recorded in one transaction.
        crate::agents::reserve_budget(&mut tx, agent_id).await?;
    }
    crate::audit::record_query(&mut tx, &history, &intent)
        .await
        .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    let agent = actor.agent.is_some();
    let cancel_on_drop = token.clone().drop_guard();
    let core = core.clone();
    let tracker = core.tasks.clone();
    let task = tracker.spawn(
        async move {
            let _registration = registration;
            let start = Instant::now();
            // EXPLAIN and execution share an absolute lifetime. Keep that lifetime
            // below the crash-recovery threshold, with bounded pool/DNS overhead.
            let deadline =
                Duration::from_millis(policy.statement_timeout_ms) + Duration::from_secs(30);
            let mut result = tokio::time::timeout(
                deadline,
                pipeline(
                    &core,
                    &c,
                    &policy,
                    analysis.clone(),
                    query_id,
                    token,
                    (approved, agent),
                ),
            )
            .await
            .unwrap_or_else(|_| Err(vda_connectors::ConnectorError::Timeout.into()));
            if crate::masking::touches_masked(&analysis, &policy.masked_columns) {
                if let Err(error) = &mut result {
                    if error.kind == crate::error::ErrorKind::Database {
                        error.message =
                            "Query failed (details hidden because the query touches masked data)"
                                .into();
                        error.details = Value::Null;
                    }
                }
            }
            let status = match &result {
                Ok(_) => "ok",
                Err(e)
                    if matches!(
                        e.code,
                        "query_denied" | "approval_required" | "cost_exceeded"
                    ) =>
                {
                    "blocked"
                }
                Err(e) if e.kind == crate::error::ErrorKind::Cancelled => "cancelled",
                Err(_) => "error",
            };
            metrics::histogram!(
                "vda_query_duration_seconds",
                "cluster" => c.id.to_string(),
                "verdict" => verdict.clone()
            )
            .record(start.elapsed().as_secs_f64());
            if status == "blocked" {
                metrics::counter!(
                    "vda_blocked_queries_total",
                    "cluster" => c.id.to_string()
                )
                .increment(1);
            }
            // Finalization is synchronous and contains no caller-controlled identity.
            // On failure/crash the committed intent survives for maintenance recovery.
            if !blocked {
                sqlx::query(
                    "UPDATE query_history SET status=$2,row_count=$3,elapsed_ms=$4,error=$5
             WHERE id=$1 AND status IN ('running','blocked')",
                )
                .bind(history_id)
                .bind(status)
                .bind(result.as_ref().ok().map(|r| r.row_count as i64))
                .bind(start.elapsed().as_millis() as i64)
                .bind(result.as_ref().err().map(|e| &e.message))
                .execute(&core.db)
                .await?;
            }
            result
        }
        .instrument(tracing::Span::current()),
    );
    let result = task.await.map_err(|_| ApiError::internal())?;
    drop(cancel_on_drop);
    result
}

async fn pipeline(
    core: &Core,
    c: &ClusterRecord,
    policy: &Policy,
    analysis: Analysis,
    query_id: Uuid,
    token: CancellationToken,
    (approved, agent): (bool, bool),
) -> Result<QueryResult, ApiError> {
    match analysis.verdict {
        Verdict::Deny => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "query_denied",
                "Query denied by policy",
            )
            .details(&analysis))
        }
        Verdict::RequiresApproval if !approved => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "approval_required",
                "Query requires approval",
            )
            .details(&analysis))
        }
        _ => {}
    }
    let sql = analysis
        .rewritten_sql
        .clone()
        .ok_or_else(ApiError::internal)?;
    let pools = core.pools.get(core, c, policy).await?;
    // An agent's query runs as the cluster's agent login when one is set, and
    // only while the database itself is verified to allow no more than the
    // policy. The guard above is then the first check and the database the last.
    let (primary, standby) = if agent && crate::judge::require(core, c, policy).await? {
        let agent = pools.agent.as_ref().ok_or_else(ApiError::internal)?;
        (&agent.primary, agent.replica.as_ref())
    } else {
        (&pools.primary, pools.replica.as_ref())
    };
    let limits = policy.limits();
    let read = analysis.is_read_only();
    let replica = if read && policy.route_reads_to_replica && standby.is_some() {
        core.replica_health.try_get_with(c.id, async {
            sqlx::query_scalar::<_,bool>(
                "SELECT COALESCE((SELECT status IN ('healthy','degraded') AND checked_at>now()-interval '2 minutes'
         FROM health_checks WHERE cluster_id=$1 AND endpoint='replica' ORDER BY checked_at DESC,id DESC LIMIT
         1),false)",
            )
.bind(c.id)
.fetch_one(&core.db).await.map_err(ApiError::from)
        }).await.map_err(|e| (*e).clone())?
    } else {
        false
    };
    let pool = if replica {
        standby.unwrap_or(primary)
    } else {
        primary
    };
    // EXPLAIN also consumes production resources and must share the concurrency cap.
    let permit = tokio::select! {
        _=token.cancelled()=>return Err(vda_connectors::ConnectorError::Cancelled.into()),
        value = tokio::time::timeout(Duration::from_secs(2), pools.semaphore.clone().acquire_owned()) => {
            value.map_err(|_| ApiError::new(StatusCode::TOO_MANY_REQUESTS, "busy", "Cluster is busy"))?
                .map_err(|_| ApiError::internal())?
        }
    };
    if read {
        if let Some(max_cost) = policy.max_cost {
            let cost = tokio::select! {
                _ = token.cancelled() => return Err(vda_connectors::ConnectorError::Cancelled.into()),
                value = pool.explain_cost(&sql, &limits) => value?,
            };
            let cost = cost.filter(|v| v.is_finite()).ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "upstream",
                    "Query cost could not be determined",
                )
            })?;
            if cost > max_cost {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "cost_exceeded",
                    "Estimated query cost exceeds policy",
                )
                .details(json!({"cost":cost,"max_cost":max_cost})));
            }
        }
    }
    let mut result = if read {
        pool.execute_read(&sql, &limits, token).await?
    } else {
        pool.execute_write(&sql, &limits, policy.max_affected_rows, token)
            .await?
    };
    drop(permit);
    let tables = analysis
        .statements
        .iter()
        .flat_map(|s| s.tables.iter().cloned())
        .collect::<Vec<_>>();
    let columns = crate::masking::apply(&mut result, &policy.masked_columns, &tables);
    Ok(QueryResult {
        query_id,
        columns,
        rows: result.rows,
        row_count: result.row_count,
        truncated: result.truncated,
        affected_rows: result.affected_rows,
        elapsed_ms: result.elapsed_ms,
        executed_sql: sql,
        routed_to: if replica { "replica" } else { "primary" }.into(),
        analysis,
    })
}
/// Cancel an active local query, when [`Actor::may_cancel`] allows it.
pub fn cancel(core: &Core, actor: &Actor, query_id: Uuid) -> Result<(), ApiError> {
    let Some(query) = core.active.get(&query_id) else {
        return Err(ApiError::not_found());
    };
    if !actor.may_cancel(query.value()) {
        return Err(ApiError::forbidden());
    }
    query.cancel.cancel();
    Ok(())
}
