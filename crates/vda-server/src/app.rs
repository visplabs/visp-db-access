//! Router composition, shared state and cross-cutting request middleware.
use crate::{
    audit::Event, auth::User, config::Config, crypto::Crypto, error::ApiError,
    network::NetworkSettings,
};
use axum::{
    extract::{MatchedPath, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use moka::future::Cache;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

/// Shared, cheaply cloned application state.
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    /// Cloud API provider, injectable for deterministic integration tests.
    pub discovery: Arc<dyn vda_discovery::Provider>,
    /// Short-lived, actor-scoped draft test summaries transferred on saving.
    pub discovery_tests: Cache<(Uuid, [u8; 32]), serde_json::Value>,
    pub config: Arc<Config>,
    /// Query pipeline state; `db` above is a handle to the same pool.
    pub core: vda_core::Core,
    pub schema_cache: Cache<Uuid, (chrono::DateTime<chrono::Utc>, vda_connectors::SchemaTree)>,
    pub audit_sender: mpsc::Sender<Event>,
    pub stop: CancellationToken,
    pub password_workers: Arc<Semaphore>,
    pub dummy_password_hash: String,
    network_cache: Cache<(), NetworkSettings>,
    /// Test notices sent in the current minute, by anyone, on this node.
    notice_tests: Cache<(), Arc<AtomicU32>>,
    /// Sends notices to the webhook; see `notices::send` for what it refuses.
    pub notices: crate::notices::send::Sender,
    account_failures: Cache<String, Arc<AtomicU32>>,
    /// Refused queries in a row, per agent, for the loop breaker in `mcp`.
    pub(crate) agent_denials: Cache<Uuid, Arc<tokio::sync::Mutex<u32>>>,
    /// Refused proposals in a row, per agent, and when they reached the
    /// limit; the lock also lets one agent make one proposal at a time.
    pub(crate) agent_proposals: Cache<Uuid, Arc<tokio::sync::Mutex<crate::mcp::ProposalStreak>>>,
    /// Tool calls in the current minute, per agent.
    pub(crate) agent_calls: Cache<Uuid, Arc<AtomicU32>>,
    login_rates: Cache<(IpAddr, String), Arc<AtomicU32>>,
    pub prometheus: Option<metrics_exporter_prometheus::PrometheusHandle>,
}
impl AppState {
    /// Initialize state and spawn the bounded history writer.
    pub async fn new(
        db: sqlx::PgPool,
        mut config: Config,
        crypto: Crypto,
        prometheus: Option<metrics_exporter_prometheus::PrometheusHandle>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), ApiError> {
        config
            .trusted_proxy_cidrs
            .0
            .extend(config.legacy_trusted_proxy_cidrs.0.iter().copied());
        #[cfg(feature = "fake-discovery")]
        let discovery: Arc<dyn vda_discovery::Provider> = if std::env::var_os(
            "VDA_DISCOVERY_FAKE_FIXTURE",
        )
        .is_some()
        {
            tracing::warn!("FAKE DISCOVERY PROVIDER ACTIVE: fixture data replaces AWS APIs; local testing only");
            Arc::new(
                vda_discovery::FakeProvider::from_env()
                    .map_err(|_| ApiError::validation("Invalid discovery fixture"))?,
            )
        } else {
            Arc::new(vda_discovery::AwsProvider::new().await)
        };
        #[cfg(not(feature = "fake-discovery"))]
        let discovery: Arc<dyn vda_discovery::Provider> =
            Arc::new(vda_discovery::AwsProvider::new().await);
        let (audit_sender, receiver) = mpsc::channel(4096);
        let stop = CancellationToken::new();
        let dummy_password_hash =
            crate::auth::hash_password("dummy-password-never-used".into()).await?;
        let writer = tokio::spawn(crate::audit::writer(db.clone(), receiver, stop.clone()));
        let notices =
            crate::notices::send::Sender::new(config.allow_private_targets).map_err(|error| {
                tracing::error!(%error, "cannot set up TLS for notices");
                ApiError::internal()
            })?;
        Ok((
            Self {
                discovery,
                discovery_tests: Cache::builder()
                    .max_capacity(512)
                    .time_to_live(Duration::from_secs(600))
                    .build(),
                core: vda_core::Core::new(db.clone(), crypto, config.allow_private_targets),
                db,
                config: Arc::new(config),
                schema_cache: Cache::builder()
                    .max_capacity(512)
                    .time_to_live(Duration::from_secs(300))
                    .build(),
                audit_sender,
                stop,
                password_workers: Arc::new(Semaphore::new(8)),
                dummy_password_hash,
                network_cache: Cache::builder()
                    .max_capacity(1)
                    .time_to_live(Duration::from_secs(30))
                    .build(),
                notice_tests: Cache::builder()
                    .max_capacity(1)
                    .time_to_live(Duration::from_secs(60))
                    .build(),
                notices,
                agent_calls: Cache::builder()
                    .max_capacity(20000)
                    .time_to_live(Duration::from_secs(60))
                    .build(),
                agent_denials: Cache::builder()
                    .max_capacity(20000)
                    .time_to_live(Duration::from_secs(crate::mcp::DENIAL_WINDOW_SECONDS))
                    .build(),
                // Idle, not total, time: an entry is not dropped while calls
                // keep coming, so the lock is not replaced while it is held.
                // The length of a stop comes from the time stored in the
                // entry, so calls during a stop do not make it longer.
                agent_proposals: Cache::builder()
                    .max_capacity(20000)
                    .time_to_idle(Duration::from_secs(crate::mcp::DENIAL_WINDOW_SECONDS))
                    .build(),
                account_failures: Cache::builder()
                    .max_capacity(20000)
                    .time_to_live(Duration::from_secs(900))
                    .build(),
                login_rates: Cache::builder()
                    .max_capacity(20000)
                    .time_to_live(Duration::from_secs(900))
                    .build(),
                prometheus,
            },
            writer,
        ))
    }
    /// Cached organization network policy; database failures fail closed.
    pub async fn network_settings(&self) -> Result<NetworkSettings, ApiError> {
        self.network_cache
            .try_get_with((), async {
                let value: serde_json::Value =
                    sqlx::query_scalar("SELECT value FROM settings WHERE key='network'")
                        .fetch_one(&self.db)
                        .await?;
                serde_json::from_value(value).map_err(|_| ApiError::internal())
            })
            .await
            .map_err(|error: Arc<ApiError>| (*error).clone())
    }
    /// Immediately invalidate a local settings cache after an update.
    pub async fn invalidate_network(&self) {
        self.network_cache.invalidate(&()).await;
    }
    /// Count one test notice against the limit of this node. A test notice
    /// makes the gateway call an outside host and report how it answered, so
    /// it is bounded for the whole organization, not per administrator.
    pub async fn check_notice_test_rate(&self) -> Result<(), ApiError> {
        let sent = self
            .notice_tests
            .get_with((), async { Arc::new(AtomicU32::new(0)) })
            .await
            .fetch_add(1, Ordering::Relaxed);
        if sent >= crate::notices::TESTS_PER_MINUTE {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many test notices in one minute",
            )
            .details(serde_json::json!({"retry_after_seconds": 60})));
        }
        Ok(())
    }
    /// Fixed-window, bounded per-IP and per-IP/email login throttling.
    pub async fn check_login_rate(&self, ip: IpAddr, email: &str) -> Result<(), ApiError> {
        for (key, limit) in [(String::new(), 100), (email.to_owned(), 10)] {
            let counter = self
                .login_rates
                .get_with((ip, key), async { Arc::new(AtomicU32::new(0)) })
                .await;
            if counter.fetch_add(1, Ordering::Relaxed) >= limit {
                return Err(ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    "Too many login attempts; try again later",
                ));
            }
        }
        Ok(())
    }
    /// Generic per-account lock across all source IPs after ten failed authentications.
    pub async fn check_account(&self, email: &str) -> Result<(), ApiError> {
        if self
            .account_failures
            .get(email)
            .await
            .is_some_and(|n| n.load(Ordering::Relaxed) >= 10)
        {
            return Err(ApiError::unauthenticated());
        }
        Ok(())
    }
    /// Count only failures; cache TTL provides the temporary 15-minute lock window.
    pub async fn login_failed(&self, email: &str) {
        self.account_failures
            .get_with(email.to_owned(), async { Arc::new(AtomicU32::new(0)) })
            .await
            .fetch_add(1, Ordering::Relaxed);
    }
    /// Successful authentication clears prior account failures.
    pub async fn login_succeeded(&self, email: &str) {
        self.account_failures.invalidate(email).await;
    }
    /// Append an administrative event inside the mutation's transaction.
    pub async fn audit_change(
        &self,
        tx: &mut sqlx::PgConnection,
        user: &User,
        action: &str,
        id: Option<Uuid>,
        ip: IpAddr,
    ) -> Result<(), ApiError> {
        self.audit_details(tx, user, action, id, ip, serde_json::json!({}))
            .await
    }
    /// Append an event that no person caused, such as a request that ran
    /// out of time, inside the transaction that makes the change.
    pub async fn audit_system(
        &self,
        tx: &mut sqlx::PgConnection,
        action: &str,
        id: Uuid,
        details: serde_json::Value,
    ) -> Result<(), ApiError> {
        crate::audit::persist_on(
            tx,
            &Event {
                id: Uuid::new_v4(),
                actor_id: None,
                action: action.into(),
                target_type: action.split('.').next().map(str::to_owned),
                target_id: Some(id),
                ip: None,
                details,
                created_at: chrono::Utc::now(),
            },
        )
        .await?;
        Ok(())
    }
    /// Like [`Self::audit_change`], with what changed. Never put a secret in `details`.
    pub async fn audit_details(
        &self,
        tx: &mut sqlx::PgConnection,
        user: &User,
        action: &str,
        id: Option<Uuid>,
        ip: IpAddr,
        details: serde_json::Value,
    ) -> Result<(), ApiError> {
        crate::audit::persist_on(
            tx,
            &Event {
                id: Uuid::new_v4(),
                actor_id: Some(user.id),
                action: action.into(),
                target_type: action.split('.').next().map(str::to_owned),
                target_id: id,
                ip: Some(ip),
                details,
                created_at: chrono::Utc::now(),
            },
        )
        .await?;
        Ok(())
    }
}
/// Build the complete API and SPA router.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .merge(crate::discovery::routes::router())
        .route("/auth/logout", post(crate::auth::logout))
        .route("/auth/me", get(crate::auth::me))
        .route("/auth/change-password", post(crate::auth::change_password))
        .route("/overview", get(crate::admin::overview))
        .route(
            "/users",
            get(crate::admin::users).post(crate::admin::create_user),
        )
        .route("/users/lookup", get(crate::access::users))
        .route(
            "/users/{id}",
            axum::routing::patch(crate::admin::update_user).delete(crate::admin::delete_user),
        )
        .route(
            "/projects",
            get(crate::admin::projects).post(crate::admin::create_project),
        )
        .route(
            "/projects/{id}",
            axum::routing::patch(crate::admin::update_project).delete(crate::admin::delete_project),
        )
        .route(
            "/clusters",
            get(crate::clusters::list).post(crate::clusters::create),
        )
        .route(
            "/clusters/test-connection",
            post(crate::clusters::test_connection),
        )
        .route(
            "/clusters/{id}",
            get(crate::clusters::get_cluster)
                .patch(crate::clusters::update)
                .delete(crate::clusters::remove),
        )
        .route("/clusters/{id}/health", get(crate::health::history))
        .route("/clusters/{id}/health/check", post(crate::health::check))
        .route("/clusters/{id}/schema", get(crate::clusters::schema))
        .route(
            "/clusters/{id}/policy",
            get(crate::clusters::get_policy).put(crate::clusters::put_policy),
        )
        .route(
            "/clusters/{id}/agent-login",
            get(crate::agent_login::get)
                .put(crate::agent_login::put)
                .delete(crate::agent_login::remove),
        )
        .route(
            "/clusters/{id}/agent-login/script",
            get(crate::agent_login::script),
        )
        .route(
            "/clusters/{id}/agent-login/check",
            post(crate::agent_login::check),
        )
        .route("/clusters/{id}/grants", get(crate::admin::cluster_grants))
        .route(
            "/grants",
            get(crate::access::grants).post(crate::admin::create_grant),
        )
        .route("/grants/{id}", delete(crate::admin::delete_grant))
        .route("/clusters/{id}/analyze", post(crate::query::analyze))
        .route("/clusters/{id}/query", post(crate::query::execute))
        .route("/queries/{id}/cancel", post(crate::query::cancel))
        .route("/history", get(crate::query::history))
        .route(
            "/approvals",
            get(crate::approvals::list).post(crate::approvals::create),
        )
        .route("/approvals/{id}", get(crate::approvals::get))
        .route("/approvals/{id}/approve", post(crate::approvals::approve))
        .route("/approvals/{id}/reject", post(crate::approvals::reject))
        .route("/approvals/{id}/execute", post(crate::approvals::execute))
        .route("/approvals/{id}/withdraw", post(crate::approvals::withdraw))
        .route("/approvals/{id}/preview", post(crate::approvals::preview))
        .route(
            "/approvals/{id}/receipt",
            get(crate::approvals::get_receipt),
        )
        .route(
            "/agents",
            get(crate::agents::list).post(crate::agents::create),
        )
        .route(
            "/agents/{id}",
            get(crate::agents::get)
                .patch(crate::agents::update)
                .delete(crate::agents::remove),
        )
        .route("/agents/{id}/tokens", post(crate::agents::create_token))
        .route(
            "/agents/{id}/tokens/{token_id}",
            delete(crate::agents::revoke_token),
        )
        .route("/audit", get(crate::admin::audit))
        .route(
            "/settings/network",
            get(crate::admin::network).put(crate::admin::set_network),
        )
        .route(
            "/settings/notices",
            get(crate::notices::api::get).put(crate::notices::api::put),
        )
        .route(
            "/settings/notices/secret",
            post(crate::notices::api::rotate_secret),
        )
        .route("/settings/notices/test", post(crate::notices::api::test))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            audit_mutation,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::authenticate,
        ));
    // The agent door: a bearer token, never a session cookie.
    let agent = Router::new()
        .route("/agent/whoami", get(crate::agents::whoami))
        .route("/mcp", post(crate::mcp::handle))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::agents::authenticate,
        ));
    // The CSRF header protects cookie sessions in a browser. A bearer token is
    // not sent by a browser on its own, so the agent door does not need it.
    let api = protected
        .route("/auth/login", post(crate::auth::login))
        .fallback(|| async { ApiError::not_found() })
        .layer(middleware::from_fn(crate::auth::csrf))
        .merge(agent);
    Router::new()
        .nest("/api/v1", api)
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(ready))
        .route("/metrics", get(prometheus))
        .fallback(crate::web::serve)
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(|_| {
            ApiError::internal().into_response()
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_middleware,
        ))
        .with_state(state)
}
async fn ready(State(state): State<AppState>) -> Response {
    match tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query("SELECT 1").execute(&state.db),
    )
    .await
    {
        Ok(Ok(_)) => StatusCode::OK.into_response(),
        _ => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Metadata database unavailable",
        )
        .into_response(),
    }
}
async fn prometheus(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    use secrecy::ExposeSecret;
    use subtle::ConstantTimeEq;
    if let Some(token) = &state.config.metrics_token {
        let supplied = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or_default();
        if token.expose_secret().is_empty()
            || !bool::from(supplied.as_bytes().ct_eq(token.expose_secret().as_bytes()))
        {
            return ApiError::unauthenticated().into_response();
        }
    }
    let text = state
        .prometheus
        .as_ref()
        .map(|h| h.render())
        .unwrap_or_default();
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        text,
    )
        .into_response()
}
async fn audit_mutation(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        return next.run(req).await;
    }
    let path = req.uri().path();
    let durable_handler = path.ends_with("/auth/change-password")
        || path.ends_with("/auth/logout")
        || [
            "/users",
            "/projects",
            "/clusters",
            "/grants",
            "/agents",
            "/approvals",
            "/settings",
            "/discovery",
        ]
        .iter()
        .any(|segment| path.contains(segment));
    let actor = req.extensions().get::<User>().map(|u| u.id);
    let ip = req
        .extensions()
        .get::<crate::network::ClientIp>()
        .map(|v| v.0);
    let action = format!(
        "{} {}",
        req.method(),
        req.extensions()
            .get::<MatchedPath>()
            .map(|p| p.as_str())
            .unwrap_or("unknown")
    );
    let target_id = req
        .uri()
        .path()
        .split('/')
        .find_map(|s| s.parse::<Uuid>().ok());
    let response = next.run(req).await;
    if durable_handler && response.status().is_success() {
        return response;
    }
    let event = Event {
        id: Uuid::new_v4(),
        actor_id: actor,
        action,
        target_type: None,
        target_id,
        ip,
        details: serde_json::json!({"status":response.status().as_u16()}),
        created_at: chrono::Utc::now(),
    };
    let persisted =
        tokio::time::timeout(Duration::from_millis(250), state.audit_sender.send(event)).await;
    if !matches!(persisted, Ok(Ok(()))) {
        tracing::error!("auxiliary request audit queue unavailable");
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal",
            "Audit unavailable",
        )
        .into_response();
    }
    response
}
async fn request_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|v| v.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    // A query can run up to the statement timeout; the agent door runs queries too.
    let timeout =
        if path.ends_with("/query") || path.ends_with("/execute") || path.ends_with("/mcp") {
            Duration::from_secs(610)
        } else {
            Duration::from_secs(30)
        };
    let span = tracing::info_span!("http",request_id=%request_id,route=%route,method=%method);
    let start = Instant::now();
    let response = async {
        let next = if matches!(path.as_str(), "/healthz" | "/readyz") {
            next.run(req)
        } else {
            return crate::network::gate(State(state.clone()), req, next).await;
        };
        next.await
    }
    .instrument(span.clone());
    let mut response = match tokio::time::timeout(timeout, response).await {
        Ok(r) => r,
        Err(_) => ApiError::new(StatusCode::GATEWAY_TIMEOUT, "timeout", "Request timed out")
            .into_response(),
    };
    if response.status().is_client_error()
        && response
            .headers()
            .get("content-type")
            .is_none_or(|v| !v.as_bytes().starts_with(b"application/json"))
    {
        let status = response.status();
        response = ApiError::new(
            status,
            if status == StatusCode::NOT_FOUND {
                "not_found"
            } else {
                "validation"
            },
            "Invalid request",
        )
        .into_response();
    }
    metrics::counter!("vda_http_requests_total","route"=>route,"status"=>response.status().as_u16().to_string()).increment(1);
    tracing::info!(parent:&span,status=response.status().as_u16(),elapsed_ms=start.elapsed().as_millis(),"request completed");
    let headers = response.headers_mut();
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).unwrap_or(HeaderValue::from_static("unknown")),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(concat!(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; ",
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if path.starts_with("/api/") {
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
    }
    if state.config.cookie_secure {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}
