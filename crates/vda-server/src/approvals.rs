//! Four-eyes review, dry runs, effect-bound execution and signed receipts.
//!
//! A request for a write is previewed when it is made: the write runs in a
//! transaction that is rolled back, and the approval is bound to what that
//! run saw. An approved write then runs only if it still changes the same
//! rows, and the same number of them. An agent can ask for a write; a person
//! who is not its owner approves it, and a person runs it.
use crate::{
    app::AppState,
    auth::User,
    db,
    error::{ApiError, Input},
    network::ClientIp,
    query::QueryInput,
    rbac,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::Instrument;
use uuid::Uuid;
use vda_core::agents::AgentIdentity;
use vda_guard::{AccessLevel, Verdict};

const APPROVAL_SQL: &str = "SELECT jsonb_build_object( 'id',a.id,'cluster_id',a.cluster_id,'cluster_name',c.name,
         'requester',jsonb_build_object('id',u.id,'email',u.email,'name',u.name),
         'agent',CASE WHEN a.agent_name IS NULL THEN NULL ELSE
           jsonb_build_object('id',a.agent_id,'name',a.agent_name) END,
         'sql',a.sql,'sql_truncated',false,'reason',a.reason,'analysis',a.analysis,
         'preview',a.preview,
         'status',a.status,'error',a.error,'error_code',a.error_code, 'reviewer',CASE WHEN r.id IS NULL THEN NULL ELSE
         jsonb_build_object('id',r.id,'email',r.email,'name',r.name) END,
         'review_note',a.review_note,'result',a.result,'receipt',a.receipt,'created_at',a.created_at,
         'reviewed_at',a.reviewed_at,'executed_at',a.executed_at,'expires_at',a.expires_at) FROM approvals a
         JOIN clusters c ON c.id=a.cluster_id JOIN users u ON u.id=a.requester_id LEFT JOIN users r ON
         r.id=a.reviewer_id";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalInput {
    cluster_id: Uuid,
    sql: String,
    reason: String,
}
fn dialect(cluster: &db::ClusterRecord) -> vda_guard::Dialect {
    if cluster.engine == "mysql" {
        vda_guard::Dialect::MySql
    } else {
        vda_guard::Dialect::Postgres
    }
}
/// Check, preview and store a request for a write. Shared by people and
/// agents; `actor` carries the agent's scope when an agent asks.
async fn open(
    state: &AppState,
    actor: &vda_core::access::Actor,
    cluster_id: Uuid,
    sql: String,
    reason: String,
    ip: std::net::IpAddr,
) -> Result<Uuid, ApiError> {
    let (c, level) =
        vda_core::access::require_level_effective(&state.db, actor, cluster_id, AccessLevel::Read)
            .await?;
    if level < AccessLevel::Write {
        // An agent that can read here is told that its level is the problem,
        // so it asks its owner instead of looking for another database.
        return Err(match actor.agent {
            Some(_) => ApiError::new(
                StatusCode::FORBIDDEN,
                "insufficient_access",
                "Your access level does not allow writes on this database",
            ),
            None => ApiError::forbidden(),
        });
    }
    if reason.trim().is_empty()
        || reason.len() > 10000
        || sql.trim().is_empty()
        || sql.len() > 1024 * 1024
    {
        return Err(ApiError::validation("Invalid SQL or approval reason"));
    }
    crate::sanitation::text(&reason)?;
    let policy = db::policy(&state.db, c.id).await?;
    if !crate::network::allowed(ip, &crate::network::parse_cidrs(&policy.allowed_cidrs)?) {
        return Err(ApiError::forbidden());
    }
    let mut analysis = vda_guard::analyze(&sql, dialect(&c), level, &policy.guard());
    crate::masking::harden_analysis(&mut analysis, &policy.masked_columns, &sql, dialect(&c));
    if analysis.verdict == Verdict::Deny {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "query_denied",
            "Query denied by policy",
        )
        .details(analysis));
    }
    if analysis.is_read_only() {
        return Err(ApiError::validation(
            "Only a statement that changes data needs an approval",
        ));
    }
    // A write hidden in WITH is not counted or bound: refuse it.
    if analysis
        .issues
        .iter()
        .any(|issue| issue.code == "data_modifying_cte")
    {
        return Err(unsupported_write(
            "A write inside WITH cannot be previewed or bound. Send each change as its own statement.",
        ));
    }
    if actor.agent.is_some() && dialect(&c) == vda_guard::Dialect::Postgres {
        check_agent_reads(state, actor, c.id, &sql, &reason, ip).await?;
    }
    // The dry run: the write runs and is rolled back. A write that fails here
    // would fail when it runs, so it is not stored. An agent's write is not
    // tried now: nothing an agent sends runs before a person looks at it. A
    // person starts its dry run with `preview`. (A dry run runs as the
    // cluster's own login, so an agent could otherwise use it to act, or to
    // learn from a count, beyond what its own reads allow.)
    let preview = if actor.agent.is_some() && dialect(&c) == vda_guard::Dialect::Postgres {
        None
    } else {
        Some(
            vda_core::query::dry_run(
                &state.core,
                actor,
                c.id,
                QueryInput {
                    sql: sql.clone(),
                    query_id: None,
                    task: None,
                },
                ip,
            )
            .await?,
        )
    };
    let binding = preview.as_ref().and_then(|preview| preview.binding.clone());
    let id = Uuid::new_v4();
    let owner = db::user(&state.db, actor.user_id).await?;
    let agent = match &actor.agent {
        Some(scope) => {
            let name: String = sqlx::query_scalar("SELECT name FROM agents WHERE id=$1")
                .bind(scope.agent_id)
                .fetch_one(&state.db)
                .await?;
            Some((scope.agent_id, name))
        }
        None => None,
    };
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO approvals(id,cluster_id,requester_id,sql,reason,analysis,status,preview,binding,
         agent_id,agent_name) VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10)",
    )
    .bind(id)
    .bind(c.id)
    .bind(actor.user_id)
    .bind(sql)
    .bind(reason)
    .bind(json!(analysis))
    .bind(preview.as_ref().map(|preview| json!(preview)))
    .bind(binding.map(|binding| json!(binding)))
    .bind(agent.as_ref().map(|agent| agent.0))
    .bind(agent.as_ref().map(|agent| agent.1.clone()))
    .execute(&mut *tx)
    .await?;
    let details = json!({
        "agent_id": agent.as_ref().map(|agent| agent.0),
        "affected_rows": preview.as_ref().and_then(|preview| preview.affected_rows),
        "bound_to": preview.as_ref().and_then(|preview| preview.bound_to.clone()),
    });
    state
        .audit_details(&mut tx, &owner, "approval.create", Some(id), ip, details)
        .await?;
    tx.commit().await?;
    Ok(id)
}
fn unsupported_write(message: &str) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_write",
        message.to_owned(),
    )
}
/// The task recorded for an agent's read check: the agent's own task after a
/// prefix, cut on a character boundary so that the whole stays within the
/// 500 characters a task may have.
fn read_check_task(task: &str) -> String {
    const PREFIX: &str = "Read check for a proposed write: ";
    let room = 500usize.saturating_sub(PREFIX.chars().count());
    let task: String = task.trim().chars().take(room).collect();
    format!("{PREFIX}{}", task.trim_end())
}
/// Before an agent's write is tried, the agent must be allowed to run, as a
/// read, everything the write reads and computes. The dry run runs on the
/// cluster's own login, so without this an agent could learn, from the count
/// or from an error, a value that its own reads may not see. The read goes
/// through the agent's normal path (guard, the database as the judge, budget,
/// history) in a read-only transaction, so a function with side effects in
/// the statement fails here instead of running in the dry run.
async fn check_agent_reads(
    state: &AppState,
    actor: &vda_core::access::Actor,
    cluster: Uuid,
    sql: &str,
    task: &str,
    ip: std::net::IpAddr,
) -> Result<(), ApiError> {
    let plan = vda_guard::write_plan(sql, vda_guard::Dialect::Postgres);
    // An agent never sees returned rows, and RETURNING would be evaluated by
    // the dry run outside the read check.
    if plan.as_ref().is_some_and(|plan| plan.returning) {
        return Err(unsupported_write(
            "An agent's write cannot have RETURNING. Leave it out; you get the count of changed rows.",
        ));
    }
    let read = plan.and_then(|plan| plan.read_check).ok_or_else(|| {
        unsupported_write(
            "An agent can ask for one plain INSERT, UPDATE or DELETE: no WITH, ONLY, ON CONFLICT, RETURNING, parameters, joins in the target, or column lists in a tuple.",
        )
    })?;
    vda_core::query::run(
        &state.core,
        actor,
        cluster,
        QueryInput {
            sql: read,
            query_id: None,
            task: Some(read_check_task(task)),
        },
        ip,
        false,
    )
    .await?;
    Ok(())
}
/// Re-analyze, preview and store a request for a write.
pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Input(body): Input<ApprovalInput>,
) -> Result<Json<Value>, ApiError> {
    let id = open(
        &state,
        &user.actor(),
        body.cluster_id,
        body.sql,
        body.reason,
        ip.0,
    )
    .await?;
    Ok(Json(view(&state, id).await?))
}
async fn view(state: &AppState, id: Uuid) -> Result<Value, ApiError> {
    Ok(sqlx::query_scalar(&format!("{APPROVAL_SQL} WHERE a.id=$1"))
        .bind(id)
        .fetch_one(&state.db)
        .await?)
}
#[derive(Debug, Deserialize, Default)]
pub struct ApprovalFilters {
    status: Option<String>,
    cluster_id: Option<Uuid>,
    #[serde(default)]
    mine: bool,
    limit: Option<i64>,
    cursor: Option<String>,
}
const STATUSES: [&str; 8] = [
    "pending",
    "approved",
    "rejected",
    "executing",
    "executed",
    "failed",
    "expired",
    "withdrawn",
];
/// List accessible approval requests; expiration is also enforced without a scheduler.
pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(filters): Query<ApprovalFilters>,
) -> Result<Json<Value>, ApiError> {
    if filters
        .status
        .as_ref()
        .is_some_and(|s| !STATUSES.contains(&s.as_str()))
    {
        return Err(ApiError::validation("Invalid approval status"));
    }
    sqlx::query(
"UPDATE approvals SET status='expired' WHERE status IN ('pending','approved') AND expires_at<=now()",
)
.execute(&state.db).await?;
    let limit = filters.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::validation("Limit must be 1..=100"));
    }
    let cursor = filters
        .cursor
        .as_deref()
        .map(db::cursor::Cursor::decode)
        .transpose()?;
    // The list is light: rows of a preview and the receipt are on the request.
    let projection = APPROVAL_SQL
        .replace(
            "'sql',a.sql,'sql_truncated',false",
            "'sql',encode(substring(convert_to(a.sql,'UTF8') from 1 for 8000),'base64'),'sql_truncated',octet_length(a.sql)>8000",
        )
        .replace("'result',a.result", "'result',NULL")
        .replace("'preview',a.preview", "'preview',NULL")
        .replace("'receipt',a.receipt", "'receipt',NULL");
    let sql = format!("{projection} JOIN users viewer ON viewer.id=$1
        WHERE (viewer.org_role='admin' OR a.requester_id=$1 OR EXISTS(
            SELECT 1 FROM grants g WHERE g.user_id=$1 AND g.level='admin'
            AND (g.expires_at IS NULL OR g.expires_at>now())
            AND ((g.scope='cluster' AND g.scope_id=c.id) OR (g.scope='project' AND g.scope_id=c.project_id))))
        AND ($2::text IS NULL OR a.status=$2) AND ($3::uuid IS NULL OR a.cluster_id=$3)
        AND (NOT $4 OR a.requester_id=$1)
        AND ($5::timestamptz IS NULL OR (a.created_at,a.id)<($5,$6))
        ORDER BY a.created_at DESC,a.id DESC LIMIT $7");
    let mut items: Vec<Value> = sqlx::query_scalar(&sql)
        .bind(user.id)
        .bind(filters.status)
        .bind(filters.cluster_id)
        .bind(filters.mine)
        .bind(cursor.as_ref().map(|c| c.created_at))
        .bind(cursor.as_ref().map(|c| c.id))
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await?;
    // Bound SQL transfer to 8 KiB (2,000 maximum-width UTF-8 characters),
    // then truncate by Unicode characters independent of metadata DB encoding.
    use base64::Engine;
    for item in &mut items {
        let encoded = item["sql"].as_str().ok_or_else(ApiError::internal)?;
        let encoded = encoded.split_whitespace().collect::<String>();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| ApiError::internal())?;
        let sql = String::from_utf8_lossy(&bytes);
        let truncated = item["sql_truncated"] == true || sql.chars().count() > 2000;
        item["sql"] = Value::String(sql.chars().take(2000).collect());
        item["sql_truncated"] = Value::Bool(truncated);
    }
    Ok(Json(db::page(items, limit)?))
}
async fn visible(state: &AppState, user: &User, id: Uuid) -> Result<(Uuid, Uuid), ApiError> {
    let (cluster_id, requester): (Uuid, Uuid) =
        sqlx::query_as("SELECT cluster_id,requester_id FROM approvals WHERE id=$1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    if user.id != requester {
        rbac::require_level(&state.db, user, cluster_id, AccessLevel::Admin).await?;
    } else {
        rbac::require_level(&state.db, user, cluster_id, AccessLevel::Read).await?;
    }
    Ok((cluster_id, requester))
}
async fn expire(state: &AppState, id: Uuid) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE approvals SET status='expired' WHERE id=$1 AND status IN ('pending','approved') AND expires_at<=now()",
    )
    .bind(id)
    .execute(&state.db)
    .await?;
    Ok(())
}
/// Return a visible approval request.
pub async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    visible(&state, &user, id).await?;
    expire(&state, id).await?;
    Ok(Json(view(&state, id).await?))
}
/// An agent's request may be previewed or run only while the agent may act.
async fn require_active_agent(state: &AppState, agent_id: Option<Uuid>) -> Result<(), ApiError> {
    let active: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE id=$1 AND NOT paused)")
            .bind(agent_id)
            .fetch_one(&state.db)
            .await?;
    if active {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "The agent that asked for this write was paused or deleted",
        ))
    }
}
/// A person starts the dry run of a request that has none yet (an agent's
/// request). It runs once; the approval is then bound to what it saw.
pub async fn preview(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    let (cluster, _) = visible(&state, &user, id).await?;
    crate::network::require_cluster(&state, cluster, ip.0).await?;
    expire(&state, id).await?;
    type Row = (String, String, bool, Option<Uuid>, bool);
    let (sql, status, previewed, agent_id, from_agent): Row = sqlx::query_as(
        "SELECT sql,status,preview IS NOT NULL,agent_id,agent_name IS NOT NULL FROM approvals WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    if status != "pending" || previewed {
        return Err(ApiError::conflict(
            "Only a pending request without a preview can be previewed",
        ));
    }
    if from_agent {
        require_active_agent(&state, agent_id).await?;
        // The preview runs the agent's statement on the cluster's own login.
        // A function defined in the database could do anything there, so the
        // agent's statement may call only built-in functions. The database
        // says which functions its expressions call, however they are written.
        let plan = vda_guard::write_plan(&sql, vda_guard::Dialect::Postgres);
        let found = match plan
            .as_ref()
            .and_then(|plan| plan.read_check.as_deref().map(|select| (plan, select)))
        {
            Some((plan, select)) => {
                // The written columns, or all of them when they are not known.
                let columns: Option<Vec<String>> = plan
                    .assigned
                    .as_ref()
                    .map(|assigned| assigned.iter().map(|(name, _)| name.clone()).collect());
                vda_core::query::database_functions(
                    &state.core,
                    cluster,
                    select,
                    Some((plan.target.as_str(), columns.as_deref())),
                )
                .await?
            }
            None => {
                return Err(unsupported_write(
                    "This agent's statement cannot be checked before a preview.",
                ))
            }
        };
        if !found.is_empty() {
            return Err(unsupported_write(&format!(
                "This agent's statement calls functions defined in this database ({}). A preview would run them. Reject it, or make the change as your own request.",
                found.join(", ")
            )));
        }
    }
    let preview = vda_core::query::dry_run(
        &state.core,
        &user.actor(),
        cluster,
        QueryInput {
            sql,
            query_id: None,
            task: None,
        },
        ip.0,
    )
    .await?;
    let mut tx = state.db.begin().await?;
    let stored = sqlx::query(
        "UPDATE approvals SET preview=$2,binding=$3 WHERE id=$1 AND status='pending' AND preview IS NULL
         AND expires_at>now()",
    )
    .bind(id)
    .bind(json!(preview))
    .bind(preview.binding.as_ref().map(|binding| json!(binding)))
    .execute(&mut *tx)
    .await?;
    if stored.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "Only a pending request without a preview can be previewed",
        ));
    }
    state
        .audit_details(
            &mut tx,
            &user,
            "approval.preview",
            Some(id),
            ip.0,
            json!({"affected_rows": preview.affected_rows, "bound_to": preview.bound_to}),
        )
        .await?;
    tx.commit().await?;
    Ok(Json(view(&state, id).await?))
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    note: Option<String>,
    /// Approve and run in one step.
    #[serde(default)]
    run: bool,
}
async fn review(
    state: &AppState,
    user: &User,
    id: Uuid,
    note: Option<String>,
    approved: bool,
    ip: std::net::IpAddr,
) -> Result<Value, ApiError> {
    // `visible` already requires cluster admin for every non-requester; requesters never self-review.
    // An agent's request is the request of its owner, so its owner cannot approve it either.
    let (cluster_id, requester) = visible(state, user, id).await?;
    if requester == user.id {
        return Err(ApiError::forbidden());
    }
    crate::network::require_cluster(state, cluster_id, ip).await?;
    if note.as_ref().is_some_and(|n| n.len() > 10000)
        || (!approved && note.as_ref().is_none_or(|n| n.trim().is_empty()))
    {
        return Err(ApiError::validation(
            "Rejection requires a note; notes must be at most 10000 bytes",
        ));
    }
    // An agent's request is approved for what its preview showed, so there
    // must be one. (A person's request has had its preview since it was made;
    // requests from before previews existed keep working.)
    if approved {
        let previewed: bool = sqlx::query_scalar(
            "SELECT preview IS NOT NULL OR agent_name IS NULL FROM approvals WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&state.db)
        .await?;
        if !previewed {
            return Err(ApiError::conflict(format!(
                "Preview the write before you approve it (POST /approvals/{id}/preview)"
            )));
        }
    }
    let mut tx = state.db.begin().await?;
    let result=sqlx::query(
"UPDATE approvals SET status=$2,reviewer_id=$3,review_note=$4,reviewed_at=now() WHERE id=$1 AND
         status='pending' AND expires_at>now() AND requester_id<>$3
         AND (preview IS NOT NULL OR agent_name IS NULL OR $2='rejected')",
)
        .bind(id)
.bind(if approved {"approved"} else {"rejected"})
.bind(user.id)
.bind(note)
.execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "Approval is expired or already reviewed",
        ));
    }
    state
        .audit_change(
            &mut tx,
            user,
            if approved {
                "approval.approve"
            } else {
                "approval.reject"
            },
            Some(id),
            ip,
        )
        .await?;
    tx.commit().await?;
    view(state, id).await
}
/// Approve a pending request as a distinct cluster administrator, and with
/// `run` also run it at once.
pub async fn approve(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    Input(body): Input<Review>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    let approved = review(&state, &user, id, body.note, true, ip.0).await?;
    if !body.run {
        return Ok(Json(approved));
    }
    Ok(Json(execute_inner(state, &user, id, ip.0).await?))
}
/// Reject a pending request, requiring a review note.
pub async fn reject(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    Input(body): Input<Review>,
) -> Result<Json<Value>, ApiError> {
    if body.run {
        return Err(ApiError::validation("A rejected request cannot run"));
    }
    Ok(Json(
        review(&state, &user, db::id(&id)?, body.note, false, ip.0).await?,
    ))
}
/// The requester withdraws a request that has not run.
pub async fn withdraw(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    let (_, requester) = visible(&state, &user, id).await?;
    if requester != user.id {
        return Err(ApiError::forbidden());
    }
    withdraw_as(&state, &user, id, ip.0, None).await?;
    Ok(Json(view(&state, id).await?))
}
async fn withdraw_as(
    state: &AppState,
    owner: &User,
    id: Uuid,
    ip: std::net::IpAddr,
    agent: Option<Uuid>,
) -> Result<(), ApiError> {
    expire(state, id).await?;
    let mut tx = state.db.begin().await?;
    let changed = sqlx::query(
        "UPDATE approvals SET status='withdrawn' WHERE id=$1 AND status IN ('pending','approved')",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "Only a request that is pending or approved can be withdrawn",
        ));
    }
    state
        .audit_details(
            &mut tx,
            owner,
            "approval.withdraw",
            Some(id),
            ip,
            json!({"agent_id": agent}),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}
/// Atomically claim an approved request before executing; failed claims are never replayed.
pub async fn execute(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(execute_inner(state, &user, db::id(&id)?, ip.0).await?))
}
async fn execute_inner(
    state: AppState,
    user: &User,
    id: Uuid,
    ip: std::net::IpAddr,
) -> Result<Value, ApiError> {
    type Row = (
        Uuid,
        Uuid,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Option<Value>,
    );
    let (cluster, requester, reviewer, agent_id, agent_name, binding): Row = sqlx::query_as(
        "SELECT cluster_id,requester_id,reviewer_id,agent_id,agent_name,binding FROM approvals WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    if user.id != requester && Some(user.id) != reviewer {
        return Err(ApiError::forbidden());
    }
    let reviewer_id = reviewer.ok_or_else(ApiError::forbidden)?;
    let (original, reviewer, policy) = tokio::try_join!(
        db::user(&state.db, requester),
        db::user(&state.db, reviewer_id),
        db::policy(&state.db, cluster),
    )?;
    if original.disabled || reviewer.disabled {
        return Err(ApiError::forbidden());
    }
    // An agent's request runs only while the agent may still act: a pause or
    // a delete after the approval stops it too.
    if agent_name.is_some() {
        require_active_agent(&state, agent_id).await?;
    }
    // The caller, the requester and the reviewer must all retain their required rights at execution.
    tokio::try_join!(
        rbac::require_level(&state.db, user, cluster, AccessLevel::Write),
        rbac::require_level(&state.db, &original, cluster, AccessLevel::Write),
        rbac::require_level(&state.db, &reviewer, cluster, AccessLevel::Admin),
    )?;
    if !crate::network::allowed(ip, &crate::network::parse_cidrs(&policy.allowed_cidrs)?) {
        return Err(ApiError::forbidden());
    }
    let expected = binding
        .map(serde_json::from_value::<vda_connectors::Expected>)
        .transpose()
        .map_err(|_| ApiError::internal())?;
    let timeout_ms = policy.statement_timeout_ms;
    let mut tx = state.db.begin().await?;
    let sql: Option<String> = sqlx::query_scalar(
        "UPDATE approvals SET execution_timeout_ms=$2,execution_started_at=now(),status='executing',
         executed_by=$3 WHERE id=$1 AND status='approved' AND expires_at>now() RETURNING sql",
    )
    .bind(id)
    .bind(timeout_ms as i64)
    .bind(user.id)
    .fetch_optional(&mut *tx)
    .await?;
    let sql = sql.ok_or_else(|| {
        ApiError::conflict("Approval is expired, not approved or already consumed")
    })?;
    state
        .audit_change(&mut tx, user, "approval.execute", Some(id), ip)
        .await?;
    tx.commit().await?;
    let tracker = state.core.tasks.clone();
    let run = Execution {
        state,
        requester: original,
        executor: user.clone(),
        cluster,
        sql,
        id,
        ip,
        timeout_ms,
        expected,
    };
    let task = tracker.spawn(run.finish().instrument(tracing::Span::current()));
    task.await.map_err(|_| ApiError::internal())?
}

struct Execution {
    state: AppState,
    requester: User,
    executor: User,
    cluster: Uuid,
    sql: String,
    id: Uuid,
    ip: std::net::IpAddr,
    timeout_ms: u64,
    expected: Option<vda_connectors::Expected>,
}
impl Execution {
    async fn finish(self) -> Result<Value, ApiError> {
        let Self {
            state,
            requester,
            executor,
            cluster,
            sql,
            id,
            ip,
            timeout_ms,
            expected,
        } = self;
        let bound_to = expected.as_ref().map(|expected| {
            if expected.rows_fingerprint.is_some() {
                "rows"
            } else {
                "count"
            }
        });
        let result = vda_core::query::run_approved_bound(
            &state.core,
            &requester.actor(),
            cluster,
            QueryInput {
                sql,
                query_id: None,
                task: None,
            },
            ip,
            timeout_ms,
            expected,
        )
        .await;
        let mut tx = state.db.begin().await?;
        match result {
            Ok(result) => {
                sqlx::query(
                    "UPDATE approvals SET status='executed',result=$2,executed_at=now() WHERE id=$1 AND status='executing'",
                )
                .bind(id)
                .bind(json!(result))
                .execute(&mut *tx)
                .await?;
                let receipt = receipt(&state, &mut tx, id, &executor, bound_to).await?;
                sqlx::query("UPDATE approvals SET receipt=$2 WHERE id=$1")
                    .bind(id)
                    .bind(&receipt)
                    .execute(&mut *tx)
                    .await?;
                state
                    .audit_details(
                        &mut tx,
                        &requester,
                        "approval.executed",
                        Some(id),
                        ip,
                        json!({
                            "affected_rows": result.affected_rows,
                            "receipt_digest": receipt.get("digest"),
                        }),
                    )
                    .await?;
                tx.commit().await?;
                view(&state, id).await
            }
            Err(error) => {
                sqlx::query(
                    "UPDATE approvals SET status='failed',error=$2,error_code=$3,executed_at=now()
                     WHERE id=$1 AND status='executing'",
                )
                .bind(id)
                .bind(&error.message)
                .bind(error.code)
                .execute(&mut *tx)
                .await?;
                state
                    .audit_details(
                        &mut tx,
                        &requester,
                        "approval.failed",
                        Some(id),
                        ip,
                        json!({"code": error.code}),
                    )
                    .await?;
                tx.commit().await?;
                Err(error)
            }
        }
    }
}

/// The record of a write that ran: what, on which database, who asked, who
/// approved, who ran it, when, and its effect. Its digest covers all of that,
/// and its signature can only be made with the master key.
async fn receipt(
    state: &AppState,
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    executor: &User,
    bound_to: Option<&str>,
) -> Result<Value, ApiError> {
    let body: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('version',1,'approval_id',a.id,
           'cluster',jsonb_build_object('id',c.id,'name',c.name,'engine',c.engine),
           'sql',a.sql,'reason',a.reason,
           'requested_by',jsonb_build_object('id',u.id,'email',u.email),
           'agent',CASE WHEN a.agent_name IS NULL THEN NULL ELSE
             jsonb_build_object('id',a.agent_id,'name',a.agent_name) END,
           'approved_by',jsonb_build_object('id',r.id,'email',r.email),'review_note',a.review_note,
           'requested_at',a.created_at,'approved_at',a.reviewed_at,'executed_at',a.executed_at,
           'previewed_rows',a.preview->'affected_rows',
           'affected_rows',a.result->'affected_rows')
         FROM approvals a JOIN clusters c ON c.id=a.cluster_id JOIN users u ON u.id=a.requester_id
         JOIN users r ON r.id=a.reviewer_id WHERE a.id=$1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let mut body = body;
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "executed_by".into(),
            json!({"id": executor.id, "email": executor.email}),
        );
        object.insert("bound_to".into(), json!(bound_to));
        object.insert("key_id".into(), json!(key_id(state)));
    }
    Ok(seal(state, body))
}
/// Add the digest and the signature to a receipt body.
fn seal(state: &AppState, mut body: Value) -> Value {
    let digest = digest_of(&body);
    let signature = state.core.crypto.sign(digest.as_bytes());
    if let Some(object) = body.as_object_mut() {
        object.insert("digest".into(), Value::String(digest));
        object.insert("signature".into(), Value::String(signature));
    }
    body
}
/// The same value with the keys of every object in sorted order. A crate in
/// the build turns on `preserve_order` for serde_json, so a map keeps the order
/// it was built in, and a receipt read back from `jsonb` has another order.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .filter_map(|key| map.get(key).map(|item| (key.clone(), canonical(item))))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}
/// The receipt of an executed write, and whether it is intact: its digest
/// matches its content and its signature was made with this master key.
pub async fn get_receipt(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    visible(&state, &user, id).await?;
    type Row = (Option<Value>, String, Uuid, String);
    let (receipt, sql, cluster, status): Row =
        sqlx::query_as("SELECT receipt,sql,cluster_id,status FROM approvals WHERE id=$1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    let receipt = receipt.ok_or_else(ApiError::not_found)?;
    // The receipt must be this request's: a valid receipt copied from another
    // request is not valid here.
    let belongs = status == "executed"
        && receipt.get("approval_id") == Some(&json!(id))
        && receipt.get("sql") == Some(&json!(sql))
        && receipt.pointer("/cluster/id") == Some(&json!(cluster));
    let signed_here = receipt.get("key_id") == Some(&json!(key_id(&state)));
    // The content matches its own digest. That needs no key, so it can be
    // checked also for a receipt signed before the master key changed.
    let content_matches = digest_matches(&receipt);
    Ok(Json(json!({
        "receipt": receipt,
        "valid": belongs && content_matches && intact(&state, &receipt),
        "digest_matches": content_matches,
        "signed_with_current_key": signed_here,
    })))
}
/// Names the signing key without revealing it, so a receipt signed before a
/// change of the master key can be told apart from a forged one.
fn key_id(state: &AppState) -> String {
    state
        .core
        .crypto
        .sign(b"receipt key id")
        .chars()
        .take(16)
        .collect()
}
/// The SHA-256 of a receipt body, as `seal` computes it.
fn digest_of(body: &Value) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(canonical(body).to_string().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
/// The receipt's content is what its digest says, whoever signed it.
fn digest_matches(receipt: &Value) -> bool {
    let mut body = receipt.clone();
    let Some(object) = body.as_object_mut() else {
        return false;
    };
    object.remove("signature");
    let Some(Value::String(digest)) = object.remove("digest") else {
        return false;
    };
    // Keys may come back from `jsonb` in any order; the digest does not care.
    digest_of(&body) == digest
}
/// The digest matches the content and was signed with this master key.
fn intact(state: &AppState, receipt: &Value) -> bool {
    let (Some(Value::String(digest)), Some(Value::String(signature))) =
        (receipt.get("digest"), receipt.get("signature"))
    else {
        return false;
    };
    digest_matches(receipt) && state.core.crypto.verify(digest.as_bytes(), signature)
}

/// How many requests one agent may have waiting at once.
pub(crate) const OPEN_REQUESTS_PER_AGENT: i64 = 10;
/// How many requests one agent may make in an hour, withdrawn ones included.
pub(crate) const PROPOSALS_PER_HOUR: i64 = 30;
/// An agent asks for a write. The request is its owner's; a person previews
/// it, a person who is not the owner approves it, and a person runs it.
pub(crate) async fn propose_for_agent(
    state: &AppState,
    identity: &AgentIdentity,
    cluster: Uuid,
    sql: String,
    task: String,
    ip: std::net::IpAddr,
) -> Result<Value, ApiError> {
    // Each request costs a person's time, so an agent may have only a few
    // open at once.
    let open_requests: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approvals WHERE agent_id=$1 AND status IN ('pending','approved','executing')
           AND expires_at>now()",
    )
    .bind(identity.agent_id)
    .fetch_one(&state.db)
    .await?;
    let last_hour: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approvals WHERE agent_id=$1 AND created_at>now()-interval '1 hour'",
    )
    .bind(identity.agent_id)
    .fetch_one(&state.db)
    .await?;
    if last_hour >= PROPOSALS_PER_HOUR {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many writes asked for in one hour",
        )
        .details(json!({"retry_after_seconds": 600})));
    }
    if open_requests >= OPEN_REQUESTS_PER_AGENT {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_open_requests",
            "You have too many writes waiting for a person; wait for them or withdraw one",
        )
        .details(json!({
            "limit": OPEN_REQUESTS_PER_AGENT,
            "requests": open_for_agent(state, identity).await?,
        })));
    }
    let id = open(state, &identity.actor, cluster, sql, task, ip).await?;
    status_for_agent(state, identity, id).await
}
/// The agent's requests that wait for a person or are running, newest
/// first: the same requests that count toward `OPEN_REQUESTS_PER_AGENT`.
pub(crate) async fn open_for_agent(
    state: &AppState,
    identity: &AgentIdentity,
) -> Result<Vec<Value>, ApiError> {
    sqlx::query(
        "UPDATE approvals SET status='expired' WHERE agent_id=$1 AND status IN ('pending','approved')
           AND expires_at<=now()",
    )
    .bind(identity.agent_id)
    .execute(&state.db)
    .await?;
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_object('approval_id',a.id,'database',a.cluster_id,'status',a.status,
           'task',a.reason,'created_at',a.created_at,'expires_at',a.expires_at)
         FROM approvals a WHERE a.agent_id=$1 AND a.status IN ('pending','approved','executing')
           AND a.expires_at>now()
         ORDER BY a.created_at DESC,a.id DESC LIMIT $2",
    )
    .bind(identity.agent_id)
    .bind(OPEN_REQUESTS_LISTED)
    .fetch_all(&state.db)
    .await?)
}
/// How many open requests `open_for_agent` lists at most.
const OPEN_REQUESTS_LISTED: i64 = 20;
/// What an agent reads about a write that failed when it ran. The text in
/// `error` is for people: it can hold counts from the dry run and database
/// messages.
const FAILED_CHANGED: &str = "The data changed after the approval, so the write was not run.";
const FAILED_UNKNOWN: &str = "Nobody knows whether the write ran. Your owner can see more.";
const FAILED_OTHER: &str = "The write failed when it ran. Your owner can see why.";
/// What an agent is told about a failed write, from the code stored for
/// people: one of three codes, a fixed sentence and a fix. The data changed
/// (ask again), nobody knows whether it ran (stop), and any other failure,
/// or none stored (ask the owner). A failed write is never told to retry, to
/// pick another database or to rewrite its SQL.
fn failure(stored: Option<&str>) -> (&'static str, &'static str, vda_core::teach::Fix) {
    let (code, text) = match stored {
        Some("effect_changed") => ("effect_changed", FAILED_CHANGED),
        Some("outcome_unknown") => ("outcome_unknown", FAILED_UNKNOWN),
        _ => ("write_failed", FAILED_OTHER),
    };
    let fix = vda_core::teach::for_error(&ApiError::new(StatusCode::CONFLICT, code, text));
    (code, text, fix)
}
/// What an agent may know about its request: the state, whether a person
/// has previewed it, the reviewer's note, and after it ran the count of
/// changed rows. When it failed: one of three codes, a fixed sentence and a
/// fix. Never rows, never counts before a person approved it.
pub(crate) async fn status_for_agent(
    state: &AppState,
    identity: &AgentIdentity,
    id: Uuid,
) -> Result<Value, ApiError> {
    expire(state, id).await?;
    type Row = (Value, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT jsonb_build_object('approval_id',a.id,'database',a.cluster_id,'status',a.status,
           'previewed',coalesce((a.preview->>'supported')::boolean,false),'review_note',a.review_note,
           'executed_rows',a.result->'affected_rows','error_code',NULL,'error',NULL,
           'created_at',a.created_at,'expires_at',a.expires_at,'executed_at',a.executed_at),
           a.error_code
         FROM approvals a WHERE a.id=$1 AND a.agent_id=$2",
    )
    .bind(id)
    .bind(identity.agent_id)
    .fetch_optional(&state.db)
    .await?;
    let (mut view, stored) = row.ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "approval_not_found",
            "No request of this agent has this id",
        )
    })?;
    // The stored code is for people; the agent reads one of three.
    if view.get("status").and_then(Value::as_str) == Some("failed") {
        let (code, text, fix) = failure(stored.as_deref());
        if let Some(object) = view.as_object_mut() {
            object.insert("error_code".into(), json!(code));
            object.insert("error".into(), json!(text));
            object.insert("fix".into(), json!(fix));
        }
    }
    Ok(view)
}
/// An agent withdraws a request that it made and that has not run.
pub(crate) async fn withdraw_for_agent(
    state: &AppState,
    identity: &AgentIdentity,
    id: Uuid,
    ip: std::net::IpAddr,
) -> Result<Value, ApiError> {
    // Only its own request: this also answers "not found" for anything else.
    status_for_agent(state, identity, id).await?;
    let owner = db::user(&state.db, identity.actor.user_id).await?;
    withdraw_as(state, &owner, id, ip, Some(identity.agent_id)).await?;
    status_for_agent(state, identity, id).await
}

#[cfg(test)]
mod tests {
    use super::{canonical, failure, read_check_task};

    #[test]
    fn an_agent_reads_one_of_three_outcomes_of_a_failed_write() {
        for (stored, code, action) in [
            (Some("effect_changed"), "effect_changed", "propose_write"),
            (Some("outcome_unknown"), "outcome_unknown", "stop"),
            (Some("upstream"), "write_failed", "ask_owner"),
            (Some("busy"), "write_failed", "ask_owner"),
            (None, "write_failed", "ask_owner"),
        ] {
            let (shown, text, fix) = failure(stored);
            assert_eq!((shown, fix.action), (code, action), "{stored:?}");
            assert!(!text.chars().any(|c| c.is_ascii_digit()));
            assert_eq!(fix.retry_after_seconds, None);
        }
        assert!(failure(Some("outcome_unknown"))
            .1
            .starts_with("Nobody knows"));
    }

    #[test]
    fn a_read_check_task_stays_within_the_task_limit() {
        let long = "é".repeat(500);
        let task = read_check_task(&long);
        assert_eq!(task.chars().count(), 500);
        assert!(vda_core::query::validate_task(&task).is_ok());
        assert_eq!(
            read_check_task("Fix note 2"),
            "Read check for a proposed write: Fix note 2"
        );
    }
    use serde_json::{json, Map, Value};

    #[test]
    fn canonical_text_does_not_depend_on_key_order() {
        let mut first = Map::new();
        first.insert("b".into(), json!({"y": 1, "x": [ {"d": 1, "c": 2} ]}));
        first.insert("a".into(), json!(null));
        let mut second = Map::new();
        second.insert("a".into(), json!(null));
        second.insert("b".into(), json!({"x": [ {"c": 2, "d": 1} ], "y": 1}));
        let (first, second) = (Value::Object(first), Value::Object(second));
        assert_eq!(
            canonical(&first).to_string(),
            canonical(&second).to_string()
        );
        assert_eq!(
            canonical(&first).to_string(),
            r#"{"a":null,"b":{"x":[{"c":2,"d":1}],"y":1}}"#
        );
    }
}
