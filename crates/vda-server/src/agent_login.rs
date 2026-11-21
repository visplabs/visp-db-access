//! The agent login of a cluster: the least-privilege database login that
//! agents' queries run as. People with admin access to the cluster manage it
//! here; the rules themselves are in `vda_core::judge`.
use crate::{
    app::AppState,
    auth::User,
    db,
    error::{ApiError, Input},
    network::ClientIp,
    rbac,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use vda_guard::AccessLevel;

const DEFAULT_ROLE: &str = "vda_agent";

/// The cluster, for a caller who administers it. Only PostgreSQL is supported.
async fn cluster(state: &AppState, user: &User, id: &str) -> Result<db::ClusterRecord, ApiError> {
    let cluster = rbac::require_level(&state.db, user, db::id(id)?, AccessLevel::Admin).await?;
    if cluster.engine != "postgres" {
        return Err(ApiError::validation(
            "An agent login is supported for PostgreSQL clusters only",
        ));
    }
    Ok(cluster)
}
fn role(name: &str) -> Result<(), ApiError> {
    if vda_core::judge::valid_role(name) {
        Ok(())
    } else {
        Err(ApiError::validation(
            "Login name must be 1..=63 characters: lower-case letters, digits and underscore, not starting with a digit or pg_",
        ))
    }
}
/// What is stored about the login. `stale` means the cluster or its policy
/// changed after the last check; the next agent query checks again first.
async fn view(state: &AppState, cluster: Uuid) -> Result<Value, ApiError> {
    let row: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('configured',true,'username',l.username,'status',l.status,
         'findings',l.findings,'checked_at',l.checked_at,
         'stale',l.checked_version IS DISTINCT FROM c.updated_at,
         'needs_password',l.password_enc='')
         FROM cluster_agent_logins l JOIN clusters c ON c.id=l.cluster_id WHERE l.cluster_id=$1",
    )
    .bind(cluster)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.unwrap_or_else(|| json!({"configured": false})))
}
/// Verify now, as the agent login, and store the result.
async fn verify(state: &AppState, cluster: Uuid) -> Result<(), ApiError> {
    // Read again: setting the login gave the cluster a new version.
    let record = db::cluster(&state.db, cluster).await?;
    let policy = db::policy(&state.db, cluster).await?;
    vda_core::judge::check(&state.core, &record, &policy).await?;
    Ok(())
}

/// Show the agent login and the result of its last check.
pub(crate) async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cluster = cluster(&state, &user, &id).await?;
    Ok(Json(view(&state, cluster.id).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetLogin {
    username: String,
    password: String,
}
impl std::fmt::Debug for SetLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetLogin")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}
/// Store the login that a database administrator created, then verify it.
/// It must differ from the cluster's own login: the point is a second,
/// narrower account.
pub(crate) async fn put(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    Input(body): Input<SetLogin>,
) -> Result<Json<Value>, ApiError> {
    let cluster = cluster(&state, &user, &id).await?;
    crate::network::require_cluster(&state, cluster.id, ip.0).await?;
    role(&body.username)?;
    if body.username == cluster.username {
        return Err(ApiError::validation(
            "The agent login must be a different login from the cluster's own",
        ));
    }
    if body.password.is_empty() || body.password.len() > 1024 {
        return Err(ApiError::validation("Password must contain 1..=1024 bytes"));
    }
    let secret = state
        .core
        .crypto
        .encrypt(cluster.id, &body.password)
        .map_err(|_| ApiError::internal())?;
    let mut tx = state.db.begin().await?;
    // Setting the login again makes it unchecked; that is a change of its
    // status like any other, and is recorded as one.
    let before: Option<String> = sqlx::query_scalar(
        "SELECT status FROM cluster_agent_logins WHERE cluster_id=$1 FOR UPDATE",
    )
    .bind(cluster.id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(before) = before.filter(|before| before != "unchecked") {
        vda_core::judge::status_changed(&mut tx, cluster.id, &before, "unchecked").await?;
    }
    sqlx::query(
        "INSERT INTO cluster_agent_logins(cluster_id,username,password_enc) VALUES ($1,$2,$3)
         ON CONFLICT(cluster_id) DO UPDATE SET username=$2,password_enc=$3,status='unchecked',
         findings='[]',checked_at=NULL,checked_version=NULL,updated_at=now()",
    )
    .bind(cluster.id)
    .bind(&body.username)
    .bind(secret)
    .execute(&mut *tx)
    .await?;
    // A new cluster version: pools are rebuilt and old check results expire.
    sqlx::query("UPDATE clusters SET updated_at=clock_timestamp() WHERE id=$1")
        .bind(cluster.id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"username": body.username});
    state
        .audit_details(
            &mut tx,
            &user,
            "agent_login.set",
            Some(cluster.id),
            ip.0,
            details,
        )
        .await?;
    tx.commit().await?;
    state.core.pools.invalidate(cluster.id).await;
    state.forget_held(cluster.id);
    verify(&state, cluster.id).await?;
    Ok(Json(view(&state, cluster.id).await?))
}
/// Remove the agent login. Agents then use the cluster's own login again, and
/// only the gateway's checks stand between them and the data.
pub(crate) async fn remove(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    // No engine check here: a login must be removable whatever the cluster is now.
    let cluster = rbac::require_level(&state.db, &user, db::id(&id)?, AccessLevel::Admin).await?;
    let mut tx = state.db.begin().await?;
    let removed = sqlx::query("DELETE FROM cluster_agent_logins WHERE cluster_id=$1")
        .bind(cluster.id)
        .execute(&mut *tx)
        .await?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    sqlx::query("UPDATE clusters SET updated_at=clock_timestamp() WHERE id=$1")
        .bind(cluster.id)
        .execute(&mut *tx)
        .await?;
    state
        .audit_change(&mut tx, &user, "agent_login.remove", Some(cluster.id), ip.0)
        .await?;
    tx.commit().await?;
    state.core.pools.invalidate(cluster.id).await;
    state.forget_held(cluster.id);
    Ok(StatusCode::NO_CONTENT)
}
/// Verify now and return the result.
pub(crate) async fn check(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cluster = cluster(&state, &user, &id).await?;
    crate::network::require_cluster(&state, cluster.id, ip.0).await?;
    verify(&state, cluster.id).await?;
    Ok(Json(view(&state, cluster.id).await?))
}
#[derive(Deserialize)]
pub(crate) struct ScriptQuery {
    username: Option<String>,
}
/// The SQL for a database administrator to run. It is made from the current
/// catalog and the current policy, and contains no secret.
pub(crate) async fn script(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    Query(query): Query<ScriptQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let cluster = cluster(&state, &user, &id).await?;
    crate::network::require_cluster(&state, cluster.id, ip.0).await?;
    let name = match query.username {
        Some(name) => name,
        None => vda_core::judge::login(&state.db, cluster.id)
            .await?
            .map_or_else(|| DEFAULT_ROLE.to_owned(), |login| login.username),
    };
    role(&name)?;
    // The script strips the login it names. It must never name the login
    // that people's queries and the gateway itself use.
    if name == cluster.username {
        return Err(ApiError::validation(
            "The agent login must be a different login from the cluster's own",
        ));
    }
    let policy = db::policy(&state.db, cluster.id).await?;
    // Always from a fresh catalog: a script from a stale one would miss tables.
    let schema = crate::clusters::load_schema(&state, &cluster, &policy, true).await?;
    let pools = state.core.pools.get(&state.core, &cluster, &policy).await?;
    let family = vda_core::judge::inheritance(&pools.primary).await?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        vda_core::judge::script(&name, &cluster.database, &schema, &policy, &family)?,
    ))
}
