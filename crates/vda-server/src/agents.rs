//! Agents and their tokens: managed by people over the session API, and the
//! bearer-token door that an agent itself uses.
use crate::{
    app::AppState,
    auth::User,
    db,
    error::{ApiError, Input},
    network::ClientIp,
    rbac::ACCESS_SQL,
};
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use vda_core::agents::AgentIdentity;

const MAX_AGENTS_PER_OWNER: i64 = 50;
const MAX_CLUSTERS_PER_AGENT: usize = 100;
const MAX_ACTIVE_TOKENS: i64 = 5;
const DEFAULT_TOKEN_DAYS: i32 = 30;
const MAX_TOKEN_DAYS: i32 = 90;

// Token digests are never selected; a person sees only the four-character hint.
const AGENT_SQL: &str = "SELECT jsonb_build_object('id',a.id,'name',a.name,
    'description',a.description,'max_level',a.max_level,'paused',a.paused,
    'hourly_query_budget',a.hourly_query_budget,
    'owner',jsonb_build_object('id',u.id,'email',u.email,'name',u.name),
    'cluster_ids',COALESCE((SELECT jsonb_agg(cluster_id ORDER BY cluster_id)
        FROM agent_clusters WHERE agent_id=a.id),'[]'::jsonb),
    'tokens',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',t.id,'hint',t.hint,
        'created_at',t.created_at,'expires_at',t.expires_at,'revoked_at',t.revoked_at,
        'last_used_at',t.last_used_at) ORDER BY t.created_at DESC,t.id)
        FROM agent_tokens t WHERE t.agent_id=a.id),'[]'::jsonb),
    'created_at',a.created_at,'updated_at',a.updated_at)
    FROM agents a JOIN users u ON u.id=a.owner_id";

async fn agent(db: &sqlx::PgPool, id: Uuid) -> Result<Value, ApiError> {
    Ok(sqlx::query_scalar(&format!("{AGENT_SQL} WHERE a.id=$1"))
        .bind(id)
        .fetch_one(db)
        .await?)
}
/// Validate a name and return it as it is stored.
fn name(value: &str) -> Result<&str, ApiError> {
    crate::sanitation::text(value)?;
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 100 {
        return Err(ApiError::validation("Name must contain 1..=100 characters"));
    }
    if !crate::sanitation::shows_all(value) {
        return Err(ApiError::validation(
            "Name must not contain invisible or direction-changing characters",
        ));
    }
    Ok(value)
}
fn description(value: &str) -> Result<(), ApiError> {
    crate::sanitation::text(value)?;
    if value.chars().count() > 2000 {
        return Err(ApiError::validation(
            "Description must contain at most 2000 characters",
        ));
    }
    Ok(())
}
fn max_level(value: &str) -> Result<(), ApiError> {
    if matches!(value, "read" | "write") {
        Ok(())
    } else {
        Err(ApiError::validation("Agent level must be read or write"))
    }
}
/// The owner can put only clusters that they can reach now into an agent.
async fn reachable(
    tx: &mut sqlx::PgConnection,
    owner: Uuid,
    clusters: &mut Vec<Uuid>,
) -> Result<(), ApiError> {
    clusters.sort_unstable();
    clusters.dedup();
    if clusters.is_empty() || clusters.len() > MAX_CLUSTERS_PER_AGENT {
        return Err(ApiError::validation("An agent must have 1..=100 clusters"));
    }
    let found: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM clusters c JOIN users u ON u.id=$1 WHERE c.id=ANY($2) AND {ACCESS_SQL}"
    ))
    .bind(owner)
    .bind(&*clusters)
    .fetch_one(tx)
    .await?;
    if found as usize != clusters.len() {
        return Err(ApiError::validation(
            "Every cluster must exist and be one that you can access",
        ));
    }
    Ok(())
}
async fn set_clusters(
    tx: &mut sqlx::PgConnection,
    agent: Uuid,
    clusters: &[Uuid],
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM agent_clusters WHERE agent_id=$1")
        .bind(agent)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO agent_clusters(agent_id,cluster_id) SELECT $1,unnest($2::uuid[])")
        .bind(agent)
        .bind(clusters)
        .execute(tx)
        .await?;
    Ok(())
}
/// Lock an agent row and say whether the caller owns it. An agent that the
/// caller cannot manage looks the same as one that does not exist.
async fn lock(tx: &mut sqlx::PgConnection, user: &User, id: Uuid) -> Result<bool, ApiError> {
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_id FROM agents WHERE id=$1 FOR NO KEY UPDATE")
            .bind(id)
            .fetch_optional(tx)
            .await?;
    match owner {
        Some(owner) if owner == user.id => Ok(true),
        Some(_) if user.org_role == "admin" => Ok(false),
        _ => Err(ApiError::not_found()),
    }
}

/// List the caller's agents; an organization administrator sees every agent.
pub(crate) async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(page): Query<db::Page>,
) -> Result<Json<Value>, ApiError> {
    let (limit, cursor) = page.bounds()?;
    let rows: Vec<Value> = sqlx::query_scalar(&format!(
        "{AGENT_SQL} WHERE ($1 OR a.owner_id=$2)
         AND ($3::timestamptz IS NULL OR (a.created_at,a.id)<($3,$4))
         ORDER BY a.created_at DESC,a.id DESC LIMIT $5"
    ))
    .bind(user.org_role == "admin")
    .bind(user.id)
    .bind(cursor.as_ref().map(|c| c.created_at))
    .bind(cursor.as_ref().map(|c| c.id))
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(db::page(rows, limit)?))
}
/// Fetch one agent that the caller owns or administers.
pub(crate) async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    let value: Option<Value> = sqlx::query_scalar(&format!(
        "{AGENT_SQL} WHERE a.id=$1 AND ($2 OR a.owner_id=$3)"
    ))
    .bind(id)
    .bind(user.org_role == "admin")
    .bind(user.id)
    .fetch_optional(&state.db)
    .await?;
    Ok(Json(value.ok_or_else(ApiError::not_found)?))
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateAgent {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "read_level")]
    max_level: String,
    cluster_ids: Vec<Uuid>,
    hourly_query_budget: Option<i32>,
}
fn budget(value: i32) -> Result<(), ApiError> {
    if (1..=100_000).contains(&value) {
        Ok(())
    } else {
        Err(ApiError::validation(
            "Hourly query budget must be 1..=100000",
        ))
    }
}
fn read_level() -> String {
    "read".into()
}
/// Create an agent that acts for the caller.
pub(crate) async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Input(mut body): Input<CreateAgent>,
) -> Result<Json<Value>, ApiError> {
    let name = name(&body.name)?.to_owned();
    description(&body.description)?;
    max_level(&body.max_level)?;
    let hourly = body.hourly_query_budget.unwrap_or(300);
    budget(hourly)?;
    let id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    // Serialize creation per owner so the count below cannot be raced past.
    // NO KEY: rows that reference this user (sessions, history) are not blocked.
    sqlx::query("SELECT 1 FROM users WHERE id=$1 FOR NO KEY UPDATE")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    reachable(&mut tx, user.id, &mut body.cluster_ids).await?;
    let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE owner_id=$1")
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await?;
    if owned >= MAX_AGENTS_PER_OWNER {
        return Err(ApiError::conflict("You have the maximum number of agents"));
    }
    sqlx::query(
        "INSERT INTO agents(id,owner_id,name,description,max_level,hourly_query_budget)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(user.id)
    .bind(&name)
    .bind(&body.description)
    .bind(&body.max_level)
    .bind(hourly)
    .execute(&mut *tx)
    .await?;
    set_clusters(&mut tx, id, &body.cluster_ids).await?;
    let details = json!({"owner_id":user.id,"name":name,"max_level":body.max_level,
        "cluster_ids":body.cluster_ids,"hourly_query_budget":hourly});
    state
        .audit_details(&mut tx, &user, "agent.create", Some(id), ip.0, details)
        .await?;
    tx.commit().await?;
    Ok(Json(agent(&state.db, id).await?))
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateAgent {
    name: Option<String>,
    description: Option<String>,
    max_level: Option<String>,
    cluster_ids: Option<Vec<Uuid>>,
    hourly_query_budget: Option<i32>,
    paused: Option<bool>,
}
/// Change an agent. Its owner can change everything. An administrator who is
/// not the owner can only pause or resume it, because any other change would
/// let them shape what runs under another person's name.
pub(crate) async fn update(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    Input(mut body): Input<UpdateAgent>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    let new_name = body.name.as_deref().map(name).transpose()?;
    if let Some(value) = &body.description {
        description(value)?;
    }
    if let Some(value) = &body.max_level {
        max_level(value)?;
    }
    if let Some(value) = body.hourly_query_budget {
        budget(value)?;
    }
    let shape = new_name.is_some()
        || body.hourly_query_budget.is_some()
        || body.description.is_some()
        || body.max_level.is_some()
        || body.cluster_ids.is_some();
    if !shape && body.paused.is_none() {
        return Err(ApiError::validation("Nothing to change"));
    }
    let mut tx = state.db.begin().await?;
    if !lock(&mut tx, &user, id).await? && shape {
        return Err(ApiError::forbidden());
    }
    if let Some(clusters) = &mut body.cluster_ids {
        reachable(&mut tx, user.id, clusters).await?;
    }
    let (old_name, old_description, old_level, old_paused, old_budget, old_clusters): (
        String,
        String,
        String,
        bool,
        i32,
        Vec<Uuid>,
    ) = sqlx::query_as(
        "SELECT name,description,max_level,paused,hourly_query_budget,COALESCE((SELECT array_agg(cluster_id
         ORDER BY cluster_id) FROM agent_clusters WHERE agent_id=a.id),ARRAY[]::uuid[])
         FROM agents a WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    // What really changes, with the old and the new value, for the audit log.
    let mut changes = serde_json::Map::new();
    let mut note = |field: &str, from: Value, to: Value| {
        if from != to {
            changes.insert(field.into(), json!({"from":from,"to":to}));
        }
    };
    if let Some(value) = new_name {
        note("name", json!(old_name), json!(value));
    }
    if let Some(value) = &body.max_level {
        note("max_level", json!(old_level), json!(value));
    }
    if let Some(value) = &body.cluster_ids {
        note("cluster_ids", json!(old_clusters), json!(value));
    }
    if let Some(value) = body.hourly_query_budget {
        note("hourly_query_budget", json!(old_budget), json!(value));
    }
    if body
        .description
        .as_ref()
        .is_some_and(|value| *value != old_description)
    {
        // Free text can be long; the log records that it changed, not its content.
        changes.insert("description".into(), json!("changed"));
    }
    let shaped = !changes.is_empty();
    let paused = body.paused.filter(|value| *value != old_paused);
    if !shaped && paused.is_none() {
        // The request asks for the state the agent already has. A repeated
        // pause still sweeps, in case a request slipped in after the first one.
        drop(tx);
        if body.paused == Some(true) {
            stop(&state, id, None);
        }
        return Ok(Json(agent(&state.db, id).await?));
    }
    if let Some(clusters) = &body.cluster_ids {
        set_clusters(&mut tx, id, clusters).await?;
    }
    sqlx::query(
        "UPDATE agents SET name=COALESCE($2,name),description=COALESCE($3,description),
         max_level=COALESCE($4,max_level),paused=COALESCE($5,paused),
         hourly_query_budget=COALESCE($6,hourly_query_budget),updated_at=now() WHERE id=$1",
    )
    .bind(id)
    .bind(new_name)
    .bind(&body.description)
    .bind(&body.max_level)
    .bind(paused)
    .bind(body.hourly_query_budget)
    .execute(&mut *tx)
    .await?;
    // A change of shape is always its own event, so a wider reach or a higher
    // level can never hide behind a pause or a resume.
    if shaped {
        state
            .audit_details(
                &mut tx,
                &user,
                "agent.update",
                Some(id),
                ip.0,
                Value::Object(changes),
            )
            .await?;
    }
    if let Some(paused) = paused {
        let action = if paused {
            "agent.pause"
        } else {
            "agent.resume"
        };
        state
            .audit_change(&mut tx, &user, action, Some(id), ip.0)
            .await?;
    }
    tx.commit().await?;
    if paused == Some(true) {
        stop(&state, id, None);
    }
    Ok(Json(agent(&state.db, id).await?))
}
/// Revoke every active token of every agent that a person owns, and count them.
/// Call it in the transaction that takes the person's access away.
pub(crate) async fn revoke_for_owner(
    tx: &mut sqlx::PgConnection,
    owner: Uuid,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE agent_tokens SET revoked_at=now() WHERE revoked_at IS NULL
         AND agent_id IN (SELECT id FROM agents WHERE owner_id=$1)",
    )
    .bind(owner)
    .execute(tx)
    .await?;
    Ok(result.rows_affected())
}
/// Cancel what a person's agents are running on this node. Their own queries go on.
pub(crate) fn stop_for_owner(state: &AppState, owner: Uuid) {
    state
        .core
        .cancel_where(|query| query.user_id == owner && query.agent.is_some());
}
/// Cancel what an agent is running on this node, for all its tokens or for one.
/// New requests are refused by authentication; this ends the ones in flight.
fn stop(state: &AppState, agent: Uuid, token: Option<Uuid>) {
    let stopped = state.core.cancel_where(|query| {
        query
            .agent
            .is_some_and(|(a, t)| a == agent && token.is_none_or(|token| token == t))
    });
    if stopped > 0 {
        tracing::info!(agent_id = %agent, stopped, "cancelled the agent's running queries");
    }
}
/// Delete an agent and, with it, every one of its tokens.
pub(crate) async fn remove(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = db::id(&id)?;
    let mut tx = state.db.begin().await?;
    lock(&mut tx, &user, id).await?;
    // The row is about to go; keep who owned it and what it was called.
    let (owner, name): (Uuid, String) =
        sqlx::query_as("DELETE FROM agents WHERE id=$1 RETURNING owner_id,name")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let details = json!({"owner_id":owner,"name":name});
    state
        .audit_details(&mut tx, &user, "agent.delete", Some(id), ip.0, details)
        .await?;
    tx.commit().await?;
    stop(&state, id, None);
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateToken {
    expires_in_days: Option<i32>,
}
/// Issue a token. The secret is in this response only; it cannot be read again.
/// Only the owner can issue one: a token acts with the owner's access.
pub(crate) async fn create_token(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(id): Path<String>,
    Input(body): Input<CreateToken>,
) -> Result<Json<Value>, ApiError> {
    let id = db::id(&id)?;
    let days = body.expires_in_days.unwrap_or(DEFAULT_TOKEN_DAYS);
    if !(1..=MAX_TOKEN_DAYS).contains(&days) {
        return Err(ApiError::validation("Token lifetime must be 1..=90 days"));
    }
    let mut tx = state.db.begin().await?;
    // A disable, a password change or a role change of this person updates
    // their row and then ends their sessions and tokens. A share lock on that
    // row waits for such a change to finish. The session is then checked again,
    // so a token is never minted in the same instant and left alive.
    let session = jar
        .get("vda_session")
        .map(|cookie| crate::auth::token_hash(cookie.value()))
        .ok_or_else(ApiError::unauthenticated)?;
    sqlx::query("SELECT 1 FROM users WHERE id=$1 FOR SHARE")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    // A new statement, so it sees what was committed while the lock waited.
    let current: bool = sqlx::query_scalar(
        "SELECT NOT u.disabled AND EXISTS(SELECT 1 FROM sessions s WHERE s.token_hash=$2
         AND s.user_id=u.id AND s.expires_at>now() AND s.absolute_expires_at>now())
         FROM users u WHERE u.id=$1",
    )
    .bind(user.id)
    .bind(session)
    .fetch_one(&mut *tx)
    .await?;
    if !current {
        return Err(ApiError::unauthenticated());
    }
    if !lock(&mut tx, &user, id).await? {
        return Err(ApiError::forbidden());
    }
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent_tokens WHERE agent_id=$1 AND revoked_at IS NULL AND expires_at>now()",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if active >= MAX_ACTIVE_TOKENS {
        return Err(ApiError::conflict(
            "This agent has the maximum number of active tokens; revoke one first",
        ));
    }
    let token = vda_core::agents::generate();
    let token_id = Uuid::new_v4();
    let expires_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "INSERT INTO agent_tokens(id,agent_id,token_hash,hint,created_by,expires_at)
         VALUES ($1,$2,$3,$4,$5,now()+make_interval(days => $6)) RETURNING expires_at",
    )
    .bind(token_id)
    .bind(id)
    .bind(&token.hash)
    .bind(&token.hint)
    .bind(user.id)
    .bind(days)
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"token_id":token_id,"hint":token.hint,"expires_at":expires_at});
    state
        .audit_details(
            &mut tx,
            &user,
            "agent.token_create",
            Some(id),
            ip.0,
            details,
        )
        .await?;
    tx.commit().await?;
    Ok(Json(json!({
        "id": token_id,
        "token": token.secret,
        "hint": token.hint,
        "expires_at": expires_at,
    })))
}
/// Revoke a token at once. The owner or an administrator can do this.
pub(crate) async fn revoke_token(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path((id, token)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (id, token) = (db::id(&id)?, db::id(&token)?);
    let mut tx = state.db.begin().await?;
    lock(&mut tx, &user, id).await?;
    let known: Option<bool> = sqlx::query_scalar(
        "UPDATE agent_tokens SET revoked_at=COALESCE(revoked_at,now())
         WHERE id=$1 AND agent_id=$2 RETURNING true",
    )
    .bind(token)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if known.is_none() {
        return Err(ApiError::not_found());
    }
    let details = json!({"token_id":token});
    state
        .audit_details(
            &mut tx,
            &user,
            "agent.token_revoke",
            Some(id),
            ip.0,
            details,
        )
        .await?;
    tx.commit().await?;
    stop(&state, id, Some(token));
    Ok(StatusCode::NO_CONTENT)
}

/// Authenticate an agent by its bearer token. A session cookie is never read
/// here, and an agent token is never accepted by the session API.
pub async fn authenticate(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return ApiError::unauthenticated().into_response();
    };
    match vda_core::agents::authenticate(&state.db, token).await {
        Ok(identity) => {
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        Err(error) => error.into_response(),
    }
}
/// The clusters an actor can reach right now, with the effective level on
/// each. The same function that guards a query decides what is listed.
pub(crate) async fn reachable_now(
    state: &AppState,
    actor: &vda_core::access::Actor,
    ip: std::net::IpAddr,
) -> Result<Vec<Value>, ApiError> {
    let scope = actor.agent.as_ref().ok_or_else(ApiError::internal)?;
    let records: Vec<db::ClusterRecord> =
        sqlx::query_as("SELECT * FROM clusters WHERE id=ANY($1) ORDER BY lower(name),id")
            .bind(&scope.clusters)
            .fetch_all(&state.db)
            .await?;
    let mut clusters = Vec::with_capacity(records.len());
    for record in records {
        // A cluster whose own network policy excludes this address is not
        // listed: every call to it would be refused.
        let policy = db::policy(&state.db, record.id).await?;
        if !crate::network::allowed(ip, &crate::network::parse_cidrs(&policy.allowed_cidrs)?) {
            continue;
        }
        if let Some(level) = vda_core::access::effective(&state.db, actor, &record).await? {
            clusters.push(json!({
                "id": record.id,
                "name": record.name,
                "engine": record.engine,
                "provider": record.provider,
                "region": record.region,
                "environment": record.environment,
                "level": level,
                // Who has the last word on what this agent can read: the
                // target database itself, or only the gateway's own checks.
                "enforced_by": if vda_core::judge::login(&state.db, record.id).await?.is_some() {
                    "database"
                } else {
                    "gateway"
                },
            }));
        }
    }
    Ok(clusters)
}
/// Tell an agent who it is and which clusters it can reach right now.
pub(crate) async fn whoami(
    State(state): State<AppState>,
    Extension(identity): Extension<AgentIdentity>,
    Extension(ip): Extension<ClientIp>,
) -> Result<Json<Value>, ApiError> {
    let scope = identity
        .actor
        .agent
        .as_ref()
        .ok_or_else(ApiError::internal)?;
    Ok(Json(json!({
        "agent": {"id": identity.agent_id, "name": identity.agent_name, "max_level": scope.max_level},
        "owner": {"email": identity.actor.email},
        "clusters": reachable_now(&state, &identity.actor, ip.0).await?,
    })))
}
