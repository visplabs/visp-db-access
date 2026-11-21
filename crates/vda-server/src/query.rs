//! HTTP handlers for analysis, execution, cancellation and query history.
use crate::{
    app::AppState,
    auth::User,
    db,
    error::{ApiError, Input},
    network::ClientIp,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde_json::Value;
pub use vda_core::query::{Checked, QueryInput, QueryResult};

/// Analyze without target I/O, under the caller's current access and policy.
/// The answer is the analysis with one more field, `preflight`: the state of
/// the check, why, and the one next step for this caller.
pub async fn analyze(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    Input(body): Input<QueryInput>,
) -> Result<Json<Checked>, ApiError> {
    let cluster_id = db::id(&id)?;
    Ok(Json(
        vda_core::query::check(&state.core, &user.actor(), cluster_id, &body.sql, ip.0).await?,
    ))
}
/// Execute a guarded query for the caller.
pub async fn execute(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    Input(body): Input<QueryInput>,
) -> Result<Json<QueryResult>, ApiError> {
    let cluster_id = db::id(&id)?;
    Ok(Json(
        vda_core::query::run(&state.core, &user.actor(), cluster_id, body, ip.0, false).await?,
    ))
}
/// Cancel an active local query, with ownership checks.
pub async fn cancel(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    vda_core::query::cancel(&state.core, &user.actor(), db::id(&id)?)?;
    Ok(StatusCode::NO_CONTENT)
}
/// Fetch scoped history with descending keyset pagination.
pub async fn history_items(
    state: &AppState,
    user: &User,
    page: &db::Page,
) -> Result<Value, ApiError> {
    let (limit, cursor) = page.bounds()?;
    if page.status.as_ref().is_some_and(|s| {
        !matches!(
            s.as_str(),
            "running" | "unknown" | "ok" | "blocked" | "error" | "cancelled"
        )
    }) {
        return Err(ApiError::validation("Invalid history status"));
    }
    let rows:Vec<Value>=sqlx::query_scalar(
"SELECT to_jsonb(h)-'cluster_ref' FROM query_history h WHERE ($1 OR h.user_id=$2) AND ($3::uuid IS
         NULL OR h.cluster_id=$3) AND ($4::uuid IS NULL OR h.user_id=$4) AND ($5::text IS NULL OR h.status=$5)
         AND ($6::timestamptz IS NULL OR (h.created_at,h.id)<($6,$7)) ORDER BY h.created_at DESC,h.id DESC
         LIMIT $8",
)
        .bind(user.org_role=="admin")
.bind(user.id)
.bind(page.cluster_id)
.bind(page.user_id)
.bind(&page.status)
.bind(cursor.as_ref().map(|c|c.created_at))
.bind(cursor.as_ref().map(|c|c.id))
.bind(limit+1)
.fetch_all(&state.db).await?;
    db::page(rows, limit)
}
/// History list endpoint.
pub async fn history(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(page): Query<db::Page>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(history_items(&state, &user, &page).await?))
}
