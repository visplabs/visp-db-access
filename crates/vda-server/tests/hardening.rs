#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Security regressions against isolated metadata schemas and an optional live target.
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use clap::Parser;
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;
use vda_server::{
    app::{router, AppState},
    config::Cli,
    crypto::Crypto,
    policy::Policy,
};

struct Fixture {
    db: sqlx::PgPool,
    root: sqlx::PgPool,
    schema: String,
    state: AppState,
    writer: tokio::task::JoinHandle<()>,
    app: Router,
    admin: Uuid,
    grantor: Uuid,
    recipient: Uuid,
    cluster: Uuid,
    project: Uuid,
    admin_cookie: String,
    grantor_cookie: String,
}
impl Fixture {
    async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("VDA_TEST_DATABASE_URL") else {
            eprintln!("skipped: VDA_TEST_DATABASE_URL is not set");
            return None;
        };
        let root = sqlx::PgPool::connect(&url).await.unwrap();
        let schema = format!("vda_harden_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&root)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema},public");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
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
        vda_server::db::migrate(&db).await.unwrap();
        let mut config = Cli::parse_from(["test"]).config;
        config.allow_private_targets = true;
        config.metrics_token = Some("metrics-secret".into());
        let crypto = Crypto::new(&[4; 32]);
        let (state, writer) = AppState::new(db.clone(), config, crypto.clone(), None)
            .await
            .unwrap();
        let (admin, grantor, recipient, project, cluster) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        for (id, email, role) in [
            (admin, "admin@harden.example", "admin"),
            (grantor, "grantor@harden.example", "member"),
            (recipient, "recipient@harden.example", "member"),
        ] {
            sqlx::query(
                "INSERT INTO users(id,email,name,password_hash,org_role) VALUES ($1,$2,$2,$3,$4)",
            )
            .bind(id)
            .bind(email)
            .bind(&state.dummy_password_hash)
            .bind(role)
            .execute(&db)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO projects(id,name) VALUES ($1,'Project')")
            .bind(project)
            .execute(&db)
            .await
            .unwrap();
        let target_url = std::env::var("VDA_TEST_POSTGRES_URL")
            .unwrap_or_else(|_| "postgres://vda@127.0.0.1:9/postgres".into());
        let target = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy(&target_url)
            .unwrap();
        let opts = target.connect_options();
        let password = target_url
            .split_once("://")
            .and_then(|(_, s)| s.split_once('@'))
            .and_then(|(s, _)| s.split_once(':'))
            .map(|(_, p)| p)
            .unwrap_or("");
        sqlx::query("INSERT INTO clusters(id,project_id,name,engine,provider,region,environment,host,port,database,username,password_enc,tls_mode)
            VALUES ($1,$2,'Cluster','postgres','onprem','local','development',$3,$4,$5,$6,$7,'disable')")
            .bind(cluster).bind(project).bind(opts.get_host()).bind(i32::from(opts.get_port()))
            .bind(opts.get_database().unwrap_or("postgres")).bind(opts.get_username())
            .bind(crypto.encrypt(cluster,password).unwrap()).execute(&db).await.unwrap();
        target.close().await;
        let mut policy = Policy::for_environment("development");
        policy.require_approval_for_writes = false;
        sqlx::query("INSERT INTO cluster_policies(cluster_id,policy) VALUES ($1,$2)")
            .bind(cluster)
            .bind(json!(policy))
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO grants(id,user_id,scope,scope_id,level,expires_at) VALUES ($1,$2,'cluster',$3,'admin',now()+interval '1 hour')")
            .bind(Uuid::new_v4()).bind(grantor).bind(cluster).execute(&db).await.unwrap();
        let admin_cookie = Self::session(&db, admin).await;
        let grantor_cookie = Self::session(&db, grantor).await;
        let app = router(state.clone());
        Some(Self {
            db,
            root,
            schema,
            state,
            writer,
            app,
            admin,
            grantor,
            recipient,
            cluster,
            project,
            admin_cookie,
            grantor_cookie,
        })
    }
    async fn session(db: &sqlx::PgPool, user: Uuid) -> String {
        use base64::Engine;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            Uuid::new_v4()
                .as_bytes()
                .iter()
                .copied()
                .chain(Uuid::new_v4().as_bytes().iter().copied())
                .collect::<Vec<_>>(),
        );
        sqlx::query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES ($1,$2,now()+interval '1 hour')")
            .bind(vda_server::auth::token_hash(&token)).bind(user).execute(db).await.unwrap();
        format!("vda_session={token}")
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(
            &self.app,
            method,
            &format!("/api/v1{path}"),
            cookie,
            body,
            None,
            "127.0.0.1:1234",
        )
        .await
    }
    async fn policy(&self, policy: &Policy) {
        let (s, v) = self
            .request(
                "PUT",
                &format!("/clusters/{}/policy", self.cluster),
                &self.admin_cookie,
                Some(json!(policy)),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    async fn approval(&self, sql: &str, status: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO approvals(id,cluster_id,requester_id,sql,reason,analysis,status,reviewer_id,reviewed_at)
            VALUES ($1,$2,$3,$4,'Test','{}',$5,$6,now())")
            .bind(id).bind(self.cluster).bind(self.grantor).bind(sql).bind(status)
            .bind(if status=="pending" {None} else {Some(self.admin)}).execute(&self.db).await.unwrap();
        id
    }
    async fn close(self) {
        self.state.core.tasks.close();
        self.state.core.tasks.wait().await;
        self.state.stop.cancel();
        self.writer.await.unwrap();
        self.state.core.pools.close().await;
        self.db.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.root)
            .await
            .unwrap();
        self.root.close().await;
    }
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<Value>,
    bearer: Option<&str>,
    peer: &str,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookie)
        .header("x-requested-with", "vda");
    if let Some(bearer) = bearer {
        req = req.header("authorization", bearer);
    }
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let mut req = req.body(body).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 40 * 1024 * 1024)
        .await
        .unwrap();
    let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn endpoint_changes_and_delegation_cannot_reuse_or_extend_authority() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let path = format!("/clusters/{}", f.cluster);
    let stored = vda_server::db::cluster(&f.db, f.cluster).await.unwrap();
    for patch in [
        // Must differ from the fixture host, which is "localhost" in CI.
        json!({"host":"changed.example.invalid"}),
        json!({"port":1234}),
        json!({"database":"other"}),
        json!({"username":"other"}),
        json!({"engine":"mysql"}),
        json!({"tls_mode":"prefer"}),
        json!({"replica_host":"localhost"}),
        json!({"replica_port":1234}),
    ] {
        for cookie in [&f.grantor_cookie, &f.admin_cookie] {
            let (s, v) = f.request("PATCH", &path, cookie, Some(patch.clone())).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{patch}: {v}");
            assert_eq!(
                v["error"]["message"],
                "Changing the connection endpoint requires re-entering the password"
            );
        }
    }
    let (s, v) = f
        .request(
            "PATCH",
            &path,
            &f.grantor_cookie,
            Some(json!({"host":stored.host,"name":"Renamed"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = f
        .request(
            "PATCH",
            &path,
            &f.grantor_cookie,
            Some(json!({"host":"localhost","password":"fresh-password"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let fresh = vda_server::db::cluster(&f.db, f.cluster).await.unwrap();
    assert_eq!(
        f.state
            .core
            .crypto
            .decrypt(f.cluster, &fresh.password_enc)
            .unwrap(),
        "fresh-password"
    );
    let (s,v)=f.request("POST","/clusters/test-connection",&f.admin_cookie,Some(json!({"cluster_id":f.cluster,"engine":"postgres","host":"127.0.0.1","port":fresh.port,"database":fresh.database,"username":fresh.username,"tls_mode":"disable"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let grant =
        json!({"user_id":f.recipient,"scope":"cluster","scope_id":f.cluster,"level":"read"});
    for expiry in [
        Value::Null,
        json!(chrono::Utc::now() + chrono::Duration::hours(2)),
    ] {
        let mut body = grant.clone();
        body["expires_at"] = expiry;
        assert_eq!(
            f.request("POST", "/grants", &f.grantor_cookie, Some(body))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let mut self_grant = grant.clone();
    self_grant["user_id"] = json!(f.grantor);
    self_grant["expires_at"] = json!(chrono::Utc::now() + chrono::Duration::minutes(30));
    assert_eq!(
        f.request("POST", "/grants", &f.grantor_cookie, Some(self_grant))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let mut valid = grant.clone();
    valid["expires_at"] = json!(chrono::Utc::now() + chrono::Duration::minutes(30));
    valid["level"] = json!("admin");
    assert_eq!(
        f.request("POST", "/grants", &f.grantor_cookie, Some(valid.clone()))
            .await
            .0,
        StatusCode::OK
    );
    valid["scope"] = json!("project");
    valid["scope_id"] = json!(f.project);
    assert_eq!(
        f.request("POST", "/grants", &f.grantor_cookie, Some(valid.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request("POST", "/grants", &f.admin_cookie, Some(grant))
            .await
            .0,
        StatusCode::OK
    );
    sqlx::query("INSERT INTO grants(id,user_id,scope,scope_id,level,expires_at) VALUES ($1,$2,'project',$3,'admin',now()+interval '20 minutes')")
        .bind(Uuid::new_v4()).bind(f.grantor).bind(f.project).execute(&f.db).await.unwrap();
    assert_eq!(
        f.request("POST", "/grants", &f.grantor_cookie, Some(valid.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    valid["expires_at"] = json!(chrono::Utc::now() + chrono::Duration::minutes(10));
    assert_eq!(
        f.request("POST", "/grants", &f.grantor_cookie, Some(valid))
            .await
            .0,
        StatusCode::OK
    );
    // Failure to insert the transactional audit must roll back the security change.
    sqlx::query("CREATE FUNCTION fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$")
        .execute(&f.db).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_audit()")
        .execute(&f.db).await.unwrap();
    assert_eq!(
        f.request(
            "PATCH",
            &path,
            &f.admin_cookie,
            Some(json!({"name":"Must roll back"}))
        )
        .await
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        vda_server::db::cluster(&f.db, f.cluster)
            .await
            .unwrap()
            .name,
        "Renamed"
    );
    sqlx::query("DROP TRIGGER fail_audit ON audit_log")
        .execute(&f.db)
        .await
        .unwrap();
    f.close().await;
}

#[tokio::test]
async fn approval_lists_recovery_cidrs_and_metrics_are_enforced() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let long = "λ".repeat(2100);
    let id = f.approval(&long, "executed").await;
    sqlx::query("UPDATE approvals SET result=$2,error='failure diagnostic' WHERE id=$1")
        .bind(id)
        .bind(json!({"large":"result"}))
        .execute(&f.db)
        .await
        .unwrap();
    f.approval("SELECT 1", "failed").await;
    let current = f.approval("SELECT 2", "executing").await;
    let stale = f.approval("SELECT 3", "executing").await;
    sqlx::query("UPDATE approvals SET expires_at=now()-interval '1 second',execution_started_at=now() WHERE status='executing'").execute(&f.db).await.unwrap();
    sqlx::query(
        "UPDATE approvals SET execution_started_at=now()-interval '20 minutes' WHERE id=$1",
    )
    .bind(stale)
    .execute(&f.db)
    .await
    .unwrap();
    // The claim used a ten-minute budget; the current one-minute policy must
    // not shorten that claim's recovery window.
    sqlx::query("UPDATE approvals SET execution_started_at=now()-interval '7 minutes' WHERE id=$1")
        .bind(current)
        .execute(&f.db)
        .await
        .unwrap();
    let mut cursor = None;
    let mut seen = Vec::new();
    loop {
        let path = match cursor {
            Some(ref c) => format!("/approvals?limit=1&cursor={c}"),
            None => "/approvals?limit=1".into(),
        };
        let (s, v) = f.request("GET", &path, &f.admin_cookie, None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        for item in v["items"].as_array().unwrap() {
            assert!(item["result"].is_null());
            seen.push(item["id"].as_str().unwrap().to_owned());
            if item["id"] == json!(id) {
                assert_eq!(item["sql"].as_str().unwrap().chars().count(), 2000);
                assert_eq!(item["sql_truncated"], true);
            }
        }
        cursor = v["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    let unique = seen.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(seen.len(), 4);
    assert_eq!(unique.len(), 4);
    let (s, v) = f
        .request("GET", &format!("/approvals/{id}"), &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["sql"], long);
    assert_eq!(v["sql_truncated"], false);
    assert_eq!(v["result"]["large"], "result");
    assert_eq!(
        f.request("GET", "/approvals?limit=101", &f.admin_cookie, None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.request("GET", "/approvals?cursor=invalid", &f.admin_cookie, None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (_, v) = f
        .request("GET", "/approvals?status=executing", &f.admin_cookie, None)
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    vda_server::health::recover_executions(&f.db).await.unwrap();
    let statuses: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id,status,error FROM approvals WHERE status IN ('executing','failed')",
    )
    .fetch_all(&f.db)
    .await
    .unwrap();
    assert!(statuses
        .iter()
        .any(|(id, s, _)| *id == current && s == "executing"));
    assert!(statuses.iter().any(|(id, s, e)| *id == stale
        && s == "failed"
        && e.as_deref() == Some("execution outcome unknown (node crashed or lost)")));
    let pending = f.approval("SELECT 4", "pending").await;
    let approved = f.approval("SELECT 5", "approved").await;
    let mut p = Policy::for_environment("development");
    p.allowed_cidrs = vec!["203.0.113.0/24".into()];
    f.policy(&p).await;
    for (path, body) in [
        (format!("/approvals/{pending}/approve"), Some(json!({}))),
        (
            format!("/approvals/{pending}/reject"),
            Some(json!({"note":"Rejected"})),
        ),
        (format!("/approvals/{approved}/execute"), None),
        (format!("/clusters/{}/health/check", f.cluster), None),
    ] {
        let (s, v) = f.request("POST", &path, &f.admin_cookie, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}: {v}");
    }
    assert_eq!(
        f.request(
            "GET",
            &format!("/clusters/{}/schema", f.cluster),
            &f.admin_cookie,
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let status: String = sqlx::query_scalar("SELECT status FROM approvals WHERE id=$1")
        .bind(approved)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(status, "approved");
    assert_eq!(
        call(&f.app, "GET", "/metrics", "", None, None, "127.0.0.1:1234")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &f.app,
            "GET",
            "/metrics",
            "",
            None,
            Some("Bearer wrong"),
            "127.0.0.1:1234"
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &f.app,
            "GET",
            "/metrics",
            "",
            None,
            Some("Bearer metrics-secret"),
            "127.0.0.1:1234"
        )
        .await
        .0,
        StatusCode::OK
    );
    sqlx::query("UPDATE settings SET value=$1 WHERE key='network'")
        .bind(json!({"allowed_cidrs":["203.0.113.0/24"],"trust_proxy_headers":false}))
        .execute(&f.db)
        .await
        .unwrap();
    f.state.invalidate_network().await;
    assert_eq!(
        call(
            &f.app,
            "GET",
            "/metrics",
            "",
            None,
            Some("Bearer metrics-secret"),
            "127.0.0.1:1234"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    f.close().await;
}

#[tokio::test]
async fn query_intent_is_durable_unique_fail_closed_and_masks_diagnostics() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    let table = format!("vda_harden_data_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE TABLE {table}(id integer PRIMARY KEY,email text)"
    ))
    .execute(&target)
    .await
    .unwrap();
    sqlx::query(&format!("INSERT INTO {table} VALUES (1,'secret-address')"))
        .execute(&target)
        .await
        .unwrap();
    let query_path = format!("/clusters/{}/query", f.cluster);
    let handle = Uuid::new_v4();
    for _ in 0..2 {
        let (s, v) = f
            .request(
                "POST",
                &query_path,
                &f.admin_cookie,
                Some(json!({"sql":format!("SELECT * FROM {table}"),"query_id":handle})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["query_id"], json!(handle));
    }
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM query_history")
        .fetch_all(&f.db)
        .await
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    assert!(!ids.contains(&handle));
    let (s, v) = f
        .request(
            "POST",
            &query_path,
            &f.admin_cookie,
            Some(json!({"sql":format!("SELECT * FROM {table}"),"query_id":ids[0]})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM query_history")
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(count, 3);
    for body in [
        json!({"sql":"SELECT 1\u{0}"}),
        json!({"sql":"SELECT\u{1}1"}),
    ] {
        assert_eq!(
            f.request("POST", &query_path, &f.admin_cookie, Some(body))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (s, v) = f
        .request(
            "POST",
            &query_path,
            &f.admin_cookie,
            Some(json!({"sql":format!("DROP TABLE {table}")})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let blocked: (String, String, String) = sqlx::query_as(
        "SELECT status,sql,host(ip) FROM query_history ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(blocked.0, "blocked");
    assert_eq!(blocked.1, format!("DROP TABLE {table}"));
    assert_eq!(blocked.2, "127.0.0.1");
    // Inject a metadata INSERT failure; the authorized target write must never run.
    sqlx::query("CREATE FUNCTION fail_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'history unavailable'; END $$").execute(&f.db).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_history BEFORE INSERT ON query_history FOR EACH ROW EXECUTE FUNCTION fail_history()").execute(&f.db).await.unwrap();
    let (s, v) = f
        .request(
            "POST",
            &query_path,
            &f.admin_cookie,
            Some(json!({"sql":format!("UPDATE {table} SET email='changed' WHERE id=1")})),
        )
        .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["error"]["code"], "internal");
    let email: String = sqlx::query_scalar(&format!("SELECT email FROM {table} WHERE id=1"))
        .fetch_one(&target)
        .await
        .unwrap();
    assert_eq!(email, "secret-address");
    assert!(f.state.core.active.is_empty());
    sqlx::query("DROP TRIGGER fail_history ON query_history")
        .execute(&f.db)
        .await
        .unwrap();
    // Intent survives while the actual target statement is blocked on a lock.
    let mut p = Policy::for_environment("development");
    p.require_approval_for_writes = false;
    p.lock_timeout_ms = 10000;
    f.policy(&p).await;
    let mut lock = target.begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *lock)
        .await
        .unwrap();
    let sql = format!("SELECT id,email FROM {table}");
    let active = Uuid::new_v4();
    let app = f.app.clone();
    let cookie = f.admin_cookie.clone();
    let path = format!("/api/v1{query_path}");
    let sql2 = sql.clone();
    let running = tokio::spawn(async move {
        call(
            &app,
            "POST",
            &path,
            &cookie,
            Some(json!({"sql":sql2,"query_id":active})),
            None,
            "127.0.0.1:1234",
        )
        .await
    });
    let mut intent = None;
    for _ in 0..200 {
        intent = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id,status FROM query_history WHERE sql=$1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&sql)
        .fetch_optional(&f.db)
        .await
        .unwrap();
        if intent
            .as_ref()
            .is_some_and(|(_, status)| status == "running")
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let (history_id, status) = intent.unwrap();
    assert_eq!(status, "running");
    assert_ne!(history_id, active);
    assert_eq!(
        f.request(
            "POST",
            &format!("/queries/{active}/cancel"),
            &f.admin_cookie,
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(running.await.unwrap().0, StatusCode::BAD_GATEWAY);
    lock.rollback().await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM query_history WHERE id=$1")
        .bind(history_id)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(status, "cancelled");
    // Recovery preserves recent running records and retires only abandoned ones.
    sqlx::query("UPDATE query_history SET status='running',created_at=now()-interval '16 minutes' WHERE id=$1").bind(history_id).execute(&f.db).await.unwrap();
    sqlx::query("UPDATE query_history SET status='running' WHERE id=$1")
        .bind(ids[0])
        .execute(&f.db)
        .await
        .unwrap();
    vda_server::health::recover_executions(&f.db).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM query_history WHERE id=$1")
        .bind(history_id)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(status, "unknown");
    let status: String = sqlx::query_scalar("SELECT status FROM query_history WHERE id=$1")
        .bind(ids[0])
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(status, "running");
    let (_, v) = f
        .request("GET", "/history?status=unknown", &f.admin_cookie, None)
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    p.masked_columns = vec![format!("{table}.email")];
    f.policy(&p).await;
    let (s, v) = f
        .request(
            "POST",
            &query_path,
            &f.admin_cookie,
            Some(json!({"sql":format!("SELECT email::integer FROM {table}")})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    let hidden = "Query failed (details hidden because the query touches masked data)";
    assert_eq!(v["error"]["message"], hidden);
    let error: String =
        sqlx::query_scalar("SELECT error FROM query_history ORDER BY created_at DESC LIMIT 1")
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(error, hidden);
    for sql in [
        format!("SELECT row_to_json(u) FROM {table} u"),
        format!("SELECT u FROM {table} u"),
    ] {
        let (s, v) = f
            .request(
                "POST",
                &query_path,
                &f.admin_cookie,
                Some(json!({"sql":sql})),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "query_denied");
        assert!(v["error"]["details"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["code"] == "masked_data_serialization"));
    }
    let (s, v) = f
        .request(
            "POST",
            &query_path,
            &f.admin_cookie,
            Some(json!({"sql":format!("SELECT * FROM {table}")})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["rows"][0][1], "••••••");
    p.max_cost = Some(0.000001);
    f.policy(&p).await;
    let (s, v) = f
        .request(
            "POST",
            &query_path,
            &f.admin_cookie,
            Some(json!({"sql":format!("SELECT * FROM {table}")})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["code"], "cost_exceeded");
    let status: String =
        sqlx::query_scalar("SELECT status FROM query_history ORDER BY created_at DESC LIMIT 1")
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(status, "blocked");
    p.max_cost = None;
    p.require_approval_for_writes = true;
    f.policy(&p).await;
    let (s, v) = f
        .request(
            "POST",
            &query_path,
            &f.admin_cookie,
            Some(json!({"sql":format!("UPDATE {table} SET email='new' WHERE id=1")})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"]["code"], "approval_required");
    let id = f
        .approval(
            &format!("UPDATE {table} SET email='changed' WHERE id=999 AND email::integer=1"),
            "approved",
        )
        .await;
    // Use a guaranteed failing approved read to exercise the real failed wire state.
    sqlx::query("UPDATE approvals SET sql=$2 WHERE id=$1")
        .bind(id)
        .bind(format!("SELECT email::integer FROM {table}"))
        .execute(&f.db)
        .await
        .unwrap();
    assert_eq!(
        f.request(
            "POST",
            &format!("/approvals/{id}/execute"),
            &f.admin_cookie,
            None
        )
        .await
        .0,
        StatusCode::BAD_GATEWAY
    );
    let (s, v) = f
        .request("GET", &format!("/approvals/{id}"), &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["status"], "failed");
    assert_eq!(v["error"], hidden);
    assert_eq!(
        f.request(
            "POST",
            &format!("/approvals/{id}/execute"),
            &f.admin_cookie,
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&target)
        .await
        .unwrap();
    target.close().await;
    f.close().await;
}

#[tokio::test]
async fn audit_writer_skips_permanent_errors_and_classifies_serialization_failures() {
    use vda_server::audit::{persist, transient, Event};
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut event = Event {
        id: Uuid::new_v4(),
        actor_id: Some(f.admin),
        action: "bad\u{0}".into(),
        target_type: None,
        target_id: None,
        ip: None,
        details: json!({"payload":"complete dead letter"}),
        created_at: chrono::Utc::now(),
    };
    let error = persist(&f.db, &event).await.unwrap_err();
    assert!(!transient(&error));
    f.state.audit_sender.send(event.clone()).await.unwrap();
    event.id = Uuid::new_v4();
    event.action = "after.permanent.failure".into();
    f.state.audit_sender.send(event.clone()).await.unwrap();
    let mut written = false;
    for _ in 0..100 {
        written = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_log WHERE id=$1)")
            .bind(event.id)
            .fetch_one(&f.db)
            .await
            .unwrap();
        if written {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        written,
        "a permanent data error must not poison subsequent audit delivery"
    );
    sqlx::query("CREATE FUNCTION serialization_error() RETURNS void LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'retry me' USING ERRCODE='40001'; END $$").execute(&f.db).await.unwrap();
    let error = sqlx::query("SELECT serialization_error()")
        .execute(&f.db)
        .await
        .unwrap_err();
    assert!(transient(&error));
    assert!(transient(&sqlx::Error::PoolTimedOut));
    assert!(!transient(&sqlx::Error::RowNotFound));
    f.close().await;
}

#[tokio::test]
async fn account_lock_applies_across_source_ips_and_dns_is_checked_on_cached_health_pools() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    for i in 1..=10 {
        let (s, v) = call(
            &f.app,
            "POST",
            "/api/v1/auth/login",
            "",
            Some(json!({"email":"ADMIN@HARDEN.EXAMPLE","password":"wrong-password"})),
            None,
            &format!("203.0.113.{i}:1234"),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    }
    let (s, v) = call(
        &f.app,
        "POST",
        "/api/v1/auth/login",
        "",
        Some(json!({"email":"admin@harden.example","password":"dummy-password-never-used"})),
        None,
        "203.0.113.20:1234",
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(
        v["error"]["message"],
        "Authentication required or invalid credentials"
    );
    f.state.login_succeeded("admin@harden.example").await;
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/v1/auth/login",
            "",
            Some(json!({"email":"admin@harden.example","password":"dummy-password-never-used"})),
            None,
            "203.0.113.21:1234"
        )
        .await
        .0,
        StatusCode::OK
    );
    if std::env::var_os("VDA_TEST_POSTGRES_URL").is_some() {
        let c = vda_server::db::cluster(&f.db, f.cluster).await.unwrap();
        let p = vda_server::db::policy(&f.db, f.cluster).await.unwrap();
        f.state.core.pools.get(&f.state.core, &c, &p).await.unwrap();
        // Keep the pool's version key to simulate an endpoint whose DNS changed
        // after a pool was cached. Health must validate even on a cache hit.
        sqlx::query("UPDATE clusters SET host='169.254.169.254' WHERE id=$1")
            .bind(f.cluster)
            .execute(&f.db)
            .await
            .unwrap();
        let c = vda_server::db::cluster(&f.db, f.cluster).await.unwrap();
        let health = vda_server::health::probe(&f.state, &c).await.unwrap();
        assert_eq!(health.status, "down");
    }
    f.close().await;
}

#[tokio::test]
async fn replica_health_is_reused_for_five_seconds_then_refreshed() {
    if std::env::var_os("VDA_TEST_POSTGRES_URL").is_none() {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    }
    let Some(f) = Fixture::new().await else {
        return;
    };
    sqlx::query("UPDATE clusters SET replica_host=host,replica_port=port WHERE id=$1")
        .bind(f.cluster)
        .execute(&f.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO health_checks(cluster_id,endpoint,status) VALUES ($1,'replica','healthy')",
    )
    .bind(f.cluster)
    .execute(&f.db)
    .await
    .unwrap();
    let path = format!("/clusters/{}/query", f.cluster);
    let (s, v) = f
        .request(
            "POST",
            &path,
            &f.admin_cookie,
            Some(json!({"sql":"SELECT 1"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["routed_to"], "replica");
    // Remove the metadata source temporarily: a cache hit still executes. Once
    // TTL elapses the missing source must fail closed instead of using stale health.
    sqlx::query("ALTER TABLE health_checks RENAME TO hidden_health_checks")
        .execute(&f.db)
        .await
        .unwrap();
    let (s, v) = f
        .request(
            "POST",
            &path,
            &f.admin_cookie,
            Some(json!({"sql":"SELECT 2"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["routed_to"], "replica");
    tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
    assert_eq!(
        f.request(
            "POST",
            &path,
            &f.admin_cookie,
            Some(json!({"sql":"SELECT 3"}))
        )
        .await
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    sqlx::query("ALTER TABLE hidden_health_checks RENAME TO health_checks")
        .execute(&f.db)
        .await
        .unwrap();
    sqlx::query("UPDATE health_checks SET status='down'")
        .execute(&f.db)
        .await
        .unwrap();
    let (s, v) = f
        .request(
            "POST",
            &path,
            &f.admin_cookie,
            Some(json!({"sql":"SELECT 4"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["routed_to"], "primary");
    f.close().await;
}

#[tokio::test]
async fn grant_directory_is_paginated_filtered_and_scoped_to_administered_scopes() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let empty_project = Uuid::new_v4();
    sqlx::query("INSERT INTO projects(id,name) VALUES ($1,'Empty project')")
        .bind(empty_project)
        .execute(&f.db)
        .await
        .unwrap();
    for (scope, scope_id, user_id, level) in [
        ("project", empty_project, f.recipient, "read"),
        ("project", f.project, f.recipient, "read"),
        ("cluster", f.cluster, f.recipient, "write"),
    ] {
        sqlx::query("INSERT INTO grants(id,user_id,scope,scope_id,level) VALUES ($1,$2,$3,$4,$5)")
            .bind(Uuid::new_v4())
            .bind(user_id)
            .bind(scope)
            .bind(scope_id)
            .bind(level)
            .execute(&f.db)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE grants SET created_at='2026-01-01T00:00:00Z'")
        .execute(&f.db)
        .await
        .unwrap();
    let (s, first) = f
        .request("GET", "/grants?limit=2", &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{first}");
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let cursor = first["next_cursor"].as_str().unwrap();
    let (s, second) = f
        .request(
            "GET",
            &format!("/grants?limit=2&cursor={cursor}"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{second}");
    assert_eq!(second["items"].as_array().unwrap().len(), 2);
    assert!(second["next_cursor"].is_null());
    for a in first["items"].as_array().unwrap() {
        assert!(!second["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| a["id"] == b["id"]));
    }
    let (s, scoped) = f.request("GET", "/grants", &f.grantor_cookie, None).await;
    assert_eq!(s, StatusCode::OK, "{scoped}");
    assert_eq!(scoped["items"].as_array().unwrap().len(), 2);
    assert!(scoped["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|g| g["scope"] == "cluster"));
    let (s, filtered) = f
        .request(
            "GET",
            &format!(
                "/grants?scope=project&scope_id={empty_project}&user_id={}",
                f.recipient
            ),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{filtered}");
    assert_eq!(filtered["items"][0]["scope_name"], "Empty project");
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    // Project administration includes child clusters, even with no direct cluster grant.
    sqlx::query("UPDATE grants SET scope='project',scope_id=$1 WHERE user_id=$2")
        .bind(f.project)
        .bind(f.grantor)
        .execute(&f.db)
        .await
        .unwrap();
    let (s, scoped) = f.request("GET", "/grants", &f.grantor_cookie, None).await;
    assert_eq!(s, StatusCode::OK, "{scoped}");
    assert_eq!(scoped["items"].as_array().unwrap().len(), 3);
    let recipient_cookie = Fixture::session(&f.db, f.recipient).await;
    assert_eq!(
        f.request("GET", "/grants", &recipient_cookie, None).await.0,
        StatusCode::FORBIDDEN
    );
    for query in [
        "limit=0",
        "limit=201",
        "cursor=garbage",
        "scope=org",
        "scope_id=garbage",
        "user_id=garbage",
    ] {
        let (s, error) = f
            .request("GET", &format!("/grants?{query}"), &f.admin_cookie, None)
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{query}: {error}");
        assert_eq!(error["error"]["code"], "validation");
    }
    sqlx::query("UPDATE grants SET expires_at=now()-interval '1 second' WHERE user_id=$1")
        .bind(f.grantor)
        .execute(&f.db)
        .await
        .unwrap();
    assert_eq!(
        f.request("GET", "/grants", &f.grantor_cookie, None).await.0,
        StatusCode::FORBIDDEN
    );
    f.close().await;
}

#[tokio::test]
async fn user_lookup_is_minimal_bounded_and_requires_unexpired_scope_admin() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    for n in 0..25 {
        sqlx::query("INSERT INTO users(id,email,name,password_hash,org_role,disabled) VALUES ($1,$2,$3,'unused','member',$4)")
            .bind(Uuid::new_v4()).bind(format!("picker{n}@example.com")).bind(format!("Picker {n:02}"))
            .bind(n == 0).execute(&f.db).await.unwrap();
    }
    let (s, found) = f
        .request("GET", "/users/lookup?q=PiCkEr", &f.grantor_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{found}");
    let items = found["items"].as_array().unwrap();
    assert_eq!(items.len(), 20);
    assert!(items
        .iter()
        .all(|u| u.as_object().unwrap().len() == 3 && u["name"] != "Picker 00"));
    assert_eq!(items[0]["name"], "Picker 01");
    // Wildcards are literal search characters, not a way to enumerate the directory.
    assert!(f
        .request("GET", "/users/lookup?q=%25%25", &f.admin_cookie, None)
        .await
        .1["items"]
        .as_array()
        .unwrap()
        .is_empty());
    for query in ["", "?q=x", "?q=%00aa"] {
        let (s, error) = f
            .request(
                "GET",
                &format!("/users/lookup{query}"),
                &f.admin_cookie,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["error"]["code"], "validation");
    }
    let recipient_cookie = Fixture::session(&f.db, f.recipient).await;
    assert_eq!(
        f.request("GET", "/users/lookup?q=Picker", &recipient_cookie, None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request("GET", "/users", &f.grantor_cookie, None).await.0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE grants SET expires_at=now()-interval '1 second' WHERE user_id=$1")
        .bind(f.grantor)
        .execute(&f.db)
        .await
        .unwrap();
    assert_eq!(
        f.request("GET", "/users/lookup?q=Picker", &f.grantor_cookie, None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    f.close().await;
}

#[tokio::test]
async fn master_key_change_reports_unreadable_credentials_and_new_password_recovers() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    // Simulate ciphertext written under a previous VDA_MASTER_KEY.
    let target_url = std::env::var("VDA_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://vda@127.0.0.1:9/postgres".into());
    let password = target_url
        .split_once("://")
        .and_then(|(_, s)| s.split_once('@'))
        .and_then(|(s, _)| s.split_once(':'))
        .map(|(_, p)| p)
        .unwrap_or("");
    let stale = Crypto::new(&[9; 32]).encrypt(f.cluster, password).unwrap();
    sqlx::query("UPDATE clusters SET password_enc=$1 WHERE id=$2")
        .bind(stale)
        .bind(f.cluster)
        .execute(&f.db)
        .await
        .unwrap();
    let check = format!("/clusters/{}/health/check", f.cluster);
    let (s, v) = f.request("POST", &check, &f.admin_cookie, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "down");
    assert!(
        v["error"].as_str().unwrap().contains("can't be decrypted"),
        "{v}"
    );
    let (s, v) = f
        .request(
            "POST",
            &format!("/clusters/{}/query", f.cluster),
            &f.admin_cookie,
            Some(json!({"sql":"SELECT 1"})),
        )
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_eq!(v["error"]["code"], "credentials_unreadable");
    // Re-entering the password must not require decrypting the stale ciphertext.
    let (s, v) = f
        .request(
            "PATCH",
            &format!("/clusters/{}", f.cluster),
            &f.admin_cookie,
            Some(json!({"password": password})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    if std::env::var("VDA_TEST_POSTGRES_URL").is_ok() {
        let (s, v) = f.request("POST", &check, &f.admin_cookie, None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_ne!(v["status"], "down", "{v}");
    }
    f.close().await;
}

async fn bearer(f: &Fixture, path: &str, token: &str) -> (StatusCode, Value) {
    call(
        &f.app,
        "GET",
        &format!("/api/v1{path}"),
        "",
        None,
        Some(&format!("Bearer {token}")),
        "127.0.0.1:1234",
    )
    .await
}
async fn new_agent(f: &Fixture, cookie: &str, name: &str, level: &str) -> Uuid {
    let (s, v) = f
        .request(
            "POST",
            "/agents",
            cookie,
            Some(json!({"name":name,"max_level":level,"cluster_ids":[f.cluster]})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().parse().unwrap()
}
async fn new_token(f: &Fixture, cookie: &str, agent: Uuid) -> (Uuid, String) {
    let (s, v) = f
        .request(
            "POST",
            &format!("/agents/{agent}/tokens"),
            cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    (
        v["id"].as_str().unwrap().parse().unwrap(),
        v["token"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn agents_are_owned_scoped_and_managed_only_by_the_right_people() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let recipient_cookie = Fixture::session(&f.db, f.recipient).await;
    // A person cannot give an agent a cluster that they cannot reach.
    let (s, v) = f
        .request(
            "POST",
            "/agents",
            &recipient_cookie,
            Some(json!({"name":"Reach","cluster_ids":[f.cluster]})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    for body in [
        json!({"name":"","cluster_ids":[f.cluster]}),
        json!({"name":"x".repeat(101),"cluster_ids":[f.cluster]}),
        json!({"name":"No clusters","cluster_ids":[]}),
        json!({"name":"Unknown","cluster_ids":[Uuid::new_v4()]}),
        json!({"name":"Admin level","max_level":"admin","cluster_ids":[f.cluster]}),
        json!({"name":"Extra","cluster_ids":[f.cluster],"owner_id":f.admin}),
        json!({"name":"Control\u{1}","cluster_ids":[f.cluster]}),
        json!({"name":"Reporter\u{200b}","cluster_ids":[f.cluster]}),
        json!({"name":"\u{202e}retropeR","cluster_ids":[f.cluster]}),
        json!({"name":"   ","cluster_ids":[f.cluster]}),
        json!({"name":"a\u{3164}b","cluster_ids":[f.cluster]}),
        json!({"name":"a\u{a0}b","cluster_ids":[f.cluster]}),
        json!({"name":"a\u{fe0f}b","cluster_ids":[f.cluster]}),
        json!({"name":"a\u{e0001}b","cluster_ids":[f.cluster]}),
        json!({"name":"a\u{2028}b","cluster_ids":[f.cluster]}),
        json!({"name":"Reporter\u{200d}","cluster_ids":[f.cluster]}),
        json!({"name":"Reporter\u{fe0f}","cluster_ids":[f.cluster]}),
    ] {
        let (s, v) = f
            .request("POST", "/agents", &f.grantor_cookie, Some(body))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    }
    // Real names in other scripts, and emoji, are accepted.
    for name in [
        "Zoë's reader",
        "レポート 作成",
        "\u{2764}\u{fe0f} favourite",
        "\u{1f469}\u{200d}\u{1f4bb} dev agent",
        "\u{0dc1}\u{0dca}\u{200d}\u{0dbb}\u{0dd3}",
        "\u{0645}\u{06cc}\u{200c}\u{062e}\u{0648}\u{0627}\u{0647}\u{0645}",
    ] {
        let id = new_agent(&f, &f.grantor_cookie, name, "read").await;
        let (s, _) = f
            .request("DELETE", &format!("/agents/{id}"), &f.grantor_cookie, None)
            .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{name}");
    }
    let agent = new_agent(&f, &f.grantor_cookie, "Reporter", "read").await;
    let (s, v) = f
        .request(
            "POST",
            "/agents",
            &f.grantor_cookie,
            Some(json!({"name":"reporter","cluster_ids":[f.cluster]})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let path = format!("/agents/{agent}");
    // Another member cannot see or touch it; it looks like it does not exist.
    for (method, body) in [
        ("GET", None),
        ("PATCH", Some(json!({"paused":true}))),
        ("DELETE", None),
    ] {
        let (s, v) = f.request(method, &path, &recipient_cookie, body).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {v}");
    }
    let (s, v) = f
        .request(
            "POST",
            &format!("{path}/tokens"),
            &recipient_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    let (s, v) = f.request("GET", "/agents", &recipient_cookie, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"], json!([]));
    // An administrator sees it and can stop it, but cannot reshape it or mint a
    // token that would act as its owner.
    let (s, v) = f.request("GET", "/agents", &f.admin_cookie, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"][0]["id"], json!(agent));
    assert_eq!(v["items"][0]["owner"]["id"], json!(f.grantor));
    // A request that changes nothing is refused before any write or audit row.
    for body in [json!({}), json!({"paused":null,"name":null})] {
        let (s, v) = f.request("PATCH", &path, &f.admin_cookie, Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    }
    for body in [
        json!({"name":"Renamed"}),
        json!({"max_level":"write"}),
        json!({"cluster_ids":[f.cluster]}),
        json!({"description":"x","paused":true}),
    ] {
        let (s, v) = f.request("PATCH", &path, &f.admin_cookie, Some(body)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    }
    let (s, v) = f
        .request(
            "POST",
            &format!("{path}/tokens"),
            &f.admin_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, v) = f
        .request(
            "PATCH",
            &path,
            &f.admin_cookie,
            Some(json!({"paused":true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["paused"], true);
    assert_eq!(v["name"], "Reporter");
    // The owner changes everything, within their own reach.
    let (s, v) = f
        .request(
            "PATCH",
            &path,
            &f.grantor_cookie,
            Some(
                json!({"name":" Nightly report ","description":"Reads orders","paused":false,
                "max_level":"write"}),
            ),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "Nightly report");
    assert_eq!(v["paused"], false);
    // Asking for the state it already has writes nothing.
    let before = v["updated_at"].clone();
    let (s, v) = f
        .request(
            "PATCH",
            &path,
            &f.grantor_cookie,
            Some(json!({"paused":false,"max_level":"write"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["updated_at"], before);
    let (s, v) = f
        .request(
            "PATCH",
            &path,
            &f.grantor_cookie,
            Some(json!({"cluster_ids":[Uuid::new_v4()]})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    for days in [0, 91, -1] {
        let (s, v) = f
            .request(
                "POST",
                &format!("{path}/tokens"),
                &f.grantor_cookie,
                Some(json!({"expires_in_days":days})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    }
    // Five active tokens at most.
    let mut tokens = vec![];
    for _ in 0..5 {
        tokens.push(new_token(&f, &f.grantor_cookie, agent).await);
    }
    let (s, v) = f
        .request(
            "POST",
            &format!("{path}/tokens"),
            &f.grantor_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    // The secret is returned once and is stored nowhere.
    let (s, v) = f.request("GET", &path, &f.grantor_cookie, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["tokens"].as_array().unwrap().len(), 5);
    let (_, secret) = &tokens[0];
    assert!(secret.starts_with("vda_agent_"));
    let body = secret.trim_start_matches("vda_agent_");
    assert!(!v.to_string().contains(body));
    let stored: String = sqlx::query_scalar(
        "SELECT (SELECT string_agg(encode(token_hash,'escape')||hint,'') FROM agent_tokens)
         ||(SELECT string_agg(details::text,'') FROM audit_log)",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert!(!stored.contains(body));
    // Revocation: another member cannot, an administrator can, and it is idempotent.
    let revoke = format!("{path}/tokens/{}", tokens[0].0);
    let (s, _) = f.request("DELETE", &revoke, &recipient_cookie, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = bearer(&f, "/agent/whoami", secret).await;
    assert_eq!(s, StatusCode::OK);
    for _ in 0..2 {
        let (s, v) = f.request("DELETE", &revoke, &f.admin_cookie, None).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    }
    let (s, _) = bearer(&f, "/agent/whoami", secret).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = f
        .request(
            "DELETE",
            &format!("{path}/tokens/{}", Uuid::new_v4()),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Every change is in the audit log under the person who made it.
    let actions: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT action,actor_id FROM audit_log WHERE action LIKE 'agent.%' ORDER BY created_at,id",
    )
    .fetch_all(&f.db)
    .await
    .unwrap();
    // A raise of level in the same request as a resume is its own event, with
    // the old and the new value. A no-op request left no row.
    let details = |action: &'static str| {
        let db = f.db.clone();
        async move {
            sqlx::query_scalar::<_, Value>(
                "SELECT details FROM audit_log WHERE action=$1 ORDER BY created_at,id",
            )
            .bind(action)
            .fetch_all(&db)
            .await
            .unwrap()
        }
    };
    let updates = details("agent.update").await;
    assert_eq!(updates.len(), 1, "{updates:?}");
    assert_eq!(updates[0]["max_level"], json!({"from":"read","to":"write"}));
    assert_eq!(
        updates[0]["name"],
        json!({"from":"Reporter","to":"Nightly report"})
    );
    let created = &details("agent.create").await[0];
    assert_eq!(created["owner_id"], json!(f.grantor));
    assert_eq!(created["cluster_ids"], json!([f.cluster]));
    let minted = details("agent.token_create").await;
    assert_eq!(minted.len(), 5);
    assert!(minted.iter().any(|d| d["token_id"] == json!(tokens[0].0)));
    assert_eq!(
        details("agent.token_revoke").await[0]["token_id"],
        json!(tokens[0].0)
    );
    for expected in [
        ("agent.create", f.grantor),
        ("agent.update", f.grantor),
        ("agent.pause", f.admin),
        ("agent.resume", f.grantor),
        ("agent.token_create", f.grantor),
        ("agent.token_revoke", f.admin),
    ] {
        assert!(
            actions.iter().any(|(a, u)| (a.as_str(), *u) == expected),
            "missing {expected:?} in {actions:?}"
        );
    }
    // Deleting the agent removes its tokens.
    let (s, _) = bearer(&f, "/agent/whoami", &tokens[1].1).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = f.request("DELETE", &path, &f.admin_cookie, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (s, _) = bearer(&f, "/agent/whoami", &tokens[1].1).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        details("agent.delete").await.last(),
        Some(&json!({"owner_id":f.grantor,"name":"Nightly report"}))
    );
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_tokens")
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
    f.close().await;
}

#[tokio::test]
async fn an_agent_token_works_only_at_the_agent_door_and_only_while_everything_is_valid() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    // The owner is a cluster administrator; the agent's ceiling is read.
    let agent = new_agent(&f, &f.grantor_cookie, "Reader", "read").await;
    let (token_id, token) = new_token(&f, &f.grantor_cookie, agent).await;
    let (s, v) = bearer(&f, "/agent/whoami", &token).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["agent"]["id"], json!(agent));
    assert_eq!(v["owner"]["email"], "grantor@harden.example");
    assert_eq!(v["clusters"][0]["id"], json!(f.cluster));
    assert_eq!(v["clusters"][0]["level"], "read");
    assert!(!v.to_string().contains("password"));
    // The session API never accepts an agent token, in any position.
    for path in ["/auth/me", "/agents", "/clusters"] {
        let (s, _) = bearer(&f, path, &token).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
        let (s, _) = f
            .request("GET", path, &format!("vda_session={token}"), None)
            .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
    }
    // The agent door never accepts a session.
    let (s, _) = f
        .request("GET", "/agent/whoami", &f.grantor_cookie, None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let session = f.grantor_cookie.trim_start_matches("vda_session=");
    let body = token.trim_start_matches("vda_agent_");
    for bad in [
        String::new(),
        session.to_owned(),
        body.to_owned(),
        format!("vda_agent_{session}"),
        format!("{token}x"),
        token.to_uppercase(),
        format!("vda_agent_{}", "A".repeat(43)),
    ] {
        let (s, v) = bearer(&f, "/agent/whoami", &bad).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{bad:?}");
        assert_eq!(v["error"]["code"], "unauthenticated");
    }
    // The agent door is outside the browser CSRF check. Without that header a
    // wrong method is 405 and a missing token is 401, never the CSRF 403. The
    // session API keeps its check.
    for (path, cookie, bearer, expected) in [
        (
            "/api/v1/agent/whoami",
            "",
            Some(format!("Bearer {token}")),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        ("/api/v1/agent/whoami", "", None, StatusCode::UNAUTHORIZED),
        (
            "/api/v1/agents",
            f.grantor_cookie.as_str(),
            None,
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut req = Request::post(path).header("cookie", cookie);
        if let Some(bearer) = &bearer {
            req = req.header("authorization", bearer);
        }
        let mut req = req.body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
        let response = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), expected, "{path}");
    }
    for scheme in ["bearer", "Basic", "Token"] {
        let (s, _) = call(
            &f.app,
            "GET",
            "/api/v1/agent/whoami",
            "",
            None,
            Some(&format!("{scheme} {token}")),
            "127.0.0.1:1234",
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{scheme}");
    }
    // Each of these stops the token at once; undoing it makes the token work again.
    for (stop, undo) in [
        (
            format!("UPDATE agents SET paused=true WHERE id='{agent}'"),
            format!("UPDATE agents SET paused=false WHERE id='{agent}'"),
        ),
        (
            format!("UPDATE users SET disabled=true WHERE id='{}'", f.grantor),
            format!("UPDATE users SET disabled=false WHERE id='{}'", f.grantor),
        ),
        (
            format!("UPDATE agent_tokens SET expires_at=now() WHERE id='{token_id}'"),
            format!(
                "UPDATE agent_tokens SET expires_at=now()+interval '1 day' WHERE id='{token_id}'"
            ),
        ),
    ] {
        sqlx::query(&stop).execute(&f.db).await.unwrap();
        let (s, v) = bearer(&f, "/agent/whoami", &token).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{stop} {v}");
        sqlx::query(&undo).execute(&f.db).await.unwrap();
        let (s, v) = bearer(&f, "/agent/whoami", &token).await;
        assert_eq!(s, StatusCode::OK, "{undo} {v}");
    }
    // The agent loses a cluster the moment its owner does.
    sqlx::query("UPDATE grants SET expires_at=now()-interval '1 second' WHERE user_id=$1")
        .bind(f.grantor)
        .execute(&f.db)
        .await
        .unwrap();
    let (s, v) = bearer(&f, "/agent/whoami", &token).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["clusters"], json!([]));
    let identity = vda_core::agents::authenticate(&f.db, &token).await.unwrap();
    let error = vda_core::query::analyze(
        &f.state.core,
        &identity.actor,
        f.cluster,
        "SELECT 1",
        "127.0.0.1".parse().unwrap(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "forbidden");
    // The network allowlist applies to the agent door too.
    let (s, v) = f
        .request(
            "PUT",
            "/settings/network",
            &f.admin_cookie,
            Some(json!({"allowed_cidrs":["127.0.0.1/32"],"trust_proxy_headers":false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    f.state.invalidate_network().await;
    let (s, _) = call(
        &f.app,
        "GET",
        "/api/v1/agent/whoami",
        "",
        None,
        Some(&format!("Bearer {token}")),
        "10.9.8.7:1234",
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let used: bool =
        sqlx::query_scalar("SELECT last_used_at IS NOT NULL FROM agent_tokens WHERE id=$1")
            .bind(token_id)
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert!(used);
    // A person who changes their own password also ends their agents' tokens.
    sqlx::query("DELETE FROM settings WHERE key='network'")
        .execute(&f.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO settings(key,value) VALUES ('network','{\"allowed_cidrs\":[],\"trust_proxy_headers\":false}')")
        .execute(&f.db)
        .await
        .unwrap();
    f.state.invalidate_network().await;
    sqlx::query("UPDATE grants SET expires_at=NULL WHERE user_id=$1")
        .bind(f.grantor)
        .execute(&f.db)
        .await
        .unwrap();
    let (s, _) = bearer(&f, "/agent/whoami", &token).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = f
        .request(
            "POST",
            "/auth/change-password",
            &f.grantor_cookie,
            Some(json!({"current_password":"dummy-password-never-used",
                "new_password":"a-new-long-password-93"})),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (s, _) = bearer(&f, "/agent/whoami", &token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    f.close().await;
}

#[tokio::test]
async fn agent_queries_are_capped_recorded_and_never_write_on_their_own() {
    if std::env::var("VDA_TEST_POSTGRES_URL").is_err() {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    }
    let Some(f) = Fixture::new().await else {
        return;
    };
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let input = |sql: &str| vda_core::query::QueryInput {
        sql: sql.into(),
        query_id: None,
        task: None,
    };
    // The fixture policy lets a person write without approval. The owner here
    // is an organization administrator, the most powerful owner there is.
    let reader = new_agent(&f, &f.admin_cookie, "Reader", "read").await;
    let writer = new_agent(&f, &f.admin_cookie, "Writer", "write").await;
    let (_, reader_token) = new_token(&f, &f.admin_cookie, reader).await;
    let (_, writer_token) = new_token(&f, &f.admin_cookie, writer).await;
    let reader = vda_core::agents::authenticate(&f.db, &reader_token)
        .await
        .unwrap();
    let writer = vda_core::agents::authenticate(&f.db, &writer_token)
        .await
        .unwrap();
    let core = &f.state.core;
    let result = vda_core::query::run(
        core,
        &reader.actor,
        f.cluster,
        input("SELECT 1 AS n"),
        ip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(result.rows, vec![vec![json!(1)]]);
    let write = "CREATE TABLE vda_agent_must_not_exist(id integer)";
    // What an agent is told by analysis is what then happens when it runs.
    let told = vda_core::query::analyze(
        core,
        &writer.actor,
        f.cluster,
        "DELETE FROM pg_class WHERE false",
        ip,
    )
    .await
    .unwrap();
    assert_eq!(json!(told.verdict), "requires_approval");
    let (s, v) = f
        .request(
            "POST",
            &format!("/clusters/{}/analyze", f.cluster),
            &f.admin_cookie,
            Some(json!({"sql":"DELETE FROM pg_class WHERE false"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["verdict"], "allow", "a person keeps the cluster policy");
    for (actor, sql, code) in [
        (
            &reader.actor,
            "DELETE FROM pg_class WHERE false",
            "query_denied",
        ),
        (&reader.actor, write, "query_denied"),
        (
            &writer.actor,
            "DELETE FROM pg_class WHERE false",
            "approval_required",
        ),
        (&writer.actor, write, "query_denied"),
    ] {
        let error = vda_core::query::run(core, actor, f.cluster, input(sql), ip, false)
            .await
            .unwrap_err();
        assert_eq!(error.code, code, "{sql}: {error}");
    }
    // A cluster outside the agent's list is unreachable, even for an administrator's agent.
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO clusters SELECT $1,project_id,'Other',engine,provider,region,environment,host,port,database,username,password_enc,tls_mode FROM clusters WHERE id=$2")
        .bind(other).bind(f.cluster).execute(&f.db).await.unwrap();
    sqlx::query(
        "INSERT INTO cluster_policies SELECT $1,policy FROM cluster_policies WHERE cluster_id=$2",
    )
    .bind(other)
    .bind(f.cluster)
    .execute(&f.db)
    .await
    .unwrap();
    let error = vda_core::query::run(core, &writer.actor, other, input("SELECT 1"), ip, false)
        .await
        .unwrap_err();
    assert_eq!(error.code, "forbidden");
    // History and audit name the agent, under its owner.
    let rows: Vec<(Option<Uuid>, Uuid, String)> =
        sqlx::query_as("SELECT agent_id,user_id,status FROM query_history ORDER BY created_at,id")
            .fetch_all(&f.db)
            .await
            .unwrap();
    assert_eq!(rows.len(), 5, "{rows:?}");
    assert!(rows.iter().all(|r| r.1 == f.admin && r.0.is_some()));
    assert_eq!(rows[0], (Some(reader.agent_id), f.admin, "ok".into()));
    assert!(rows[1..].iter().all(|r| r.2 == "blocked"));
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action='query.execute' AND details->>'agent_id'=$1",
    )
    .bind(writer.agent_id.to_string())
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(audited, 2);
    // A person's own query has no agent.
    let (s, v) = f
        .request(
            "POST",
            &format!("/clusters/{}/query", f.cluster),
            &f.admin_cookie,
            Some(json!({"sql":"SELECT 2"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let human: Option<Uuid> = sqlx::query_scalar(
        "SELECT agent_id FROM query_history ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(human, None);
    // Cancellation: an agent stops only what it started, even when its owner
    // is an administrator. A person can stop their own agent's query.
    let running = |user_id, agent: Option<&vda_core::agents::AgentIdentity>| {
        let id = Uuid::new_v4();
        let cancel = tokio_util::sync::CancellationToken::new();
        core.active.insert(
            id,
            vda_core::ActiveQuery {
                user_id,
                agent: agent.map(|a| (a.agent_id, a.token_id)),
                cancel: cancel.clone(),
            },
        );
        (id, cancel)
    };
    let (mine, theirs) = (running(f.admin, Some(&reader)), running(f.grantor, None));
    for (actor, query) in [(&reader.actor, theirs.0), (&writer.actor, mine.0)] {
        let error = vda_core::query::cancel(core, actor, query).unwrap_err();
        assert_eq!(error.code, "forbidden");
    }
    assert!(!mine.1.is_cancelled() && !theirs.1.is_cancelled());
    vda_core::query::cancel(core, &reader.actor, mine.0).unwrap();
    assert!(mine.1.is_cancelled());
    let cancel_path = |id: Uuid| format!("/queries/{id}/cancel");
    let (s, _) = f
        .request("POST", &cancel_path(theirs.0), &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(theirs.1.is_cancelled());
    // A member owns an agent: they can stop its query, a stranger cannot.
    let owned = new_agent(&f, &f.grantor_cookie, "Owned", "read").await;
    let (_, owned_token) = new_token(&f, &f.grantor_cookie, owned).await;
    let owned = vda_core::agents::authenticate(&f.db, &owned_token)
        .await
        .unwrap();
    let query = running(f.grantor, Some(&owned));
    let stranger = Fixture::session(&f.db, f.recipient).await;
    let (s, _) = f
        .request("POST", &cancel_path(query.0), &stranger, None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = f
        .request("POST", &cancel_path(query.0), &f.grantor_cookie, None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(query.1.is_cancelled());
    // Pause, revoke, owner-disable and delete each end what the agent is running.
    let agent_path = format!("/agents/{}", owned.agent_id);
    let other_agent = running(f.admin, Some(&writer));
    let query = running(f.grantor, Some(&owned));
    let (s, _) = f
        .request(
            "PATCH",
            &agent_path,
            &f.admin_cookie,
            Some(json!({"paused":true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(query.1.is_cancelled());
    let query = running(f.grantor, Some(&owned));
    let (s, _) = f
        .request(
            "DELETE",
            &format!("{agent_path}/tokens/{}", owned.token_id),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(query.1.is_cancelled());
    let (query, person) = (running(f.grantor, Some(&owned)), running(f.grantor, None));
    let user_path = format!("/users/{}", f.grantor);
    let (s, _) = f.request("DELETE", &user_path, &f.admin_cookie, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(query.1.is_cancelled());
    let query = running(f.grantor, Some(&owned));
    let (s, _) = f
        .request("DELETE", &agent_path, &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(query.1.is_cancelled());
    // Nothing else was touched: another agent's query and the person's own.
    assert!(!other_agent.1.is_cancelled() && !person.1.is_cancelled());
    // Enabling the account again does not bring its agent tokens back. The
    // same holds for each way to take a person's credentials away.
    let enable = json!({"disabled":false});
    let (s, v) = f
        .request("PATCH", &user_path, &f.admin_cookie, Some(enable.clone()))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for (round, (method, body)) in [
        ("DELETE", None),
        ("PATCH", Some(json!({"disabled":true}))),
        ("PATCH", Some(json!({"password":"a-new-long-password-93"}))),
        ("PATCH", Some(json!({"org_role":"admin"}))),
        ("PATCH", Some(json!({"org_role":"member"}))),
    ]
    .into_iter()
    .enumerate()
    {
        let cookie = Fixture::session(&f.db, f.grantor).await;
        let agent = new_agent(&f, &cookie, &format!("Fresh {round}"), "read").await;
        let (_, token) = new_token(&f, &cookie, agent).await;
        let identity = vda_core::agents::authenticate(&f.db, &token).await.unwrap();
        let (query, person) = (
            running(f.grantor, Some(&identity)),
            running(f.grantor, None),
        );
        let (s, v) = f
            .request(method, &user_path, &f.admin_cookie, body.clone())
            .await;
        assert!(s.is_success(), "{method} {body:?} {v}");
        assert!(query.1.is_cancelled(), "{method} {body:?}");
        assert!(!person.1.is_cancelled(), "{method} {body:?}");
        let (s, v) = f
            .request("PATCH", &user_path, &f.admin_cookie, Some(enable.clone()))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(
            vda_core::agents::authenticate(&f.db, &token).await.is_err(),
            "{method} {body:?} left the token alive"
        );
    }
    // A change that takes nothing away leaves tokens and running queries
    // alone. The third body is what the console sends when a name is fixed.
    let cookie = Fixture::session(&f.db, f.grantor).await;
    let agent = new_agent(&f, &cookie, "Kept", "read").await;
    let (_, token) = new_token(&f, &cookie, agent).await;
    let kept = vda_core::agents::authenticate(&f.db, &token).await.unwrap();
    for body in [
        json!({"disabled":false}),
        json!({"org_role":"member"}),
        json!({"name":"Typo fixed","org_role":"member","disabled":false}),
        json!({"name":"Renamed"}),
    ] {
        let query = running(f.grantor, Some(&kept));
        let (s, v) = f
            .request("PATCH", &user_path, &f.admin_cookie, Some(body.clone()))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(!query.1.is_cancelled(), "{body}");
        assert!(
            vda_core::agents::authenticate(&f.db, &token).await.is_ok(),
            "{body} revoked a token"
        );
    }
    let revoked: Vec<Option<Value>> = sqlx::query_scalar(
        "SELECT details->'agent_tokens_revoked' FROM audit_log
         WHERE action IN ('user.disable','user.update') AND target_id=$1 ORDER BY created_at,id",
    )
    .bind(f.grantor)
    .fetch_all(&f.db)
    .await
    .unwrap();
    // Five removals revoked one token each; the harmless edits revoked none and say nothing.
    assert_eq!(
        revoked.iter().filter(|v| **v == Some(json!(1))).count(),
        5,
        "{revoked:?}"
    );
    assert_eq!(revoked.last(), Some(&None));
    // A repeated pause sweeps again, for a request that slipped past the first.
    let kept_path = format!("/agents/{agent}");
    for _ in 0..2 {
        let query = running(f.grantor, Some(&kept));
        let (s, _) = f
            .request(
                "PATCH",
                &kept_path,
                &f.admin_cookie,
                Some(json!({"paused":true})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        assert!(query.1.is_cancelled());
    }
    core.active.clear();
    // Deleting an agent keeps its history, without the link.
    let (s, _) = f
        .request(
            "DELETE",
            &format!("/agents/{}", reader.agent_id),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let kept: (i64, i64) =
        sqlx::query_as("SELECT count(*),count(agent_id) FROM query_history WHERE user_id=$1")
            .bind(f.admin)
            .fetch_one(&f.db)
            .await
            .unwrap();
    // Six rows stay; only the two from the agent that still exists keep a link.
    assert_eq!(kept, (6, 2));
    f.close().await;
}

/// One JSON-RPC message to the agent door, with optional extra headers.
async fn mcp_raw(
    f: &Fixture,
    token: Option<&str>,
    body: String,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut req = Request::post("/api/v1/mcp").header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in extra {
        req = req.header(*name, *value);
    }
    let mut req = req.body(Body::from(body)).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    let response = f.app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 40 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}
async fn mcp(f: &Fixture, token: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc":"2.0","id":7,"method":method,"params":params});
    let (s, v) = mcp_raw(f, Some(token), body.to_string(), &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["id"], 7);
    v
}
/// Call a tool and return (is_error, structured content).
async fn tool(f: &Fixture, token: &str, name: &str, arguments: Value) -> (bool, Value) {
    let v = mcp(
        f,
        token,
        "tools/call",
        json!({"name":name,"arguments":arguments}),
    )
    .await;
    let result = &v["result"];
    // The text block is the same JSON as the structured block.
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"], "{v}");
    (
        result["isError"].as_bool().unwrap(),
        result["structuredContent"].clone(),
    )
}

#[tokio::test]
async fn agent_door_speaks_the_protocol_and_refuses_everything_else() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let agent = new_agent(&f, &f.grantor_cookie, "Door", "read").await;
    let (_, token) = new_token(&f, &f.grantor_cookie, agent).await;
    // Version negotiation: a known version is echoed, anything else gets the newest.
    for (asked, answered) in [
        (json!("2025-03-26"), "2025-03-26"),
        (json!("2024-11-05"), "2024-11-05"),
        (json!("1999-01-01"), "2025-06-18"),
        (Value::Null, "2025-06-18"),
    ] {
        let v = mcp(&f, &token, "initialize", json!({"protocolVersion":asked})).await;
        assert_eq!(v["result"]["protocolVersion"], answered, "{v}");
        assert!(v["result"]["capabilities"]["tools"].is_object());
        assert!(v["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("task"));
    }
    assert_eq!(
        mcp(&f, &token, "ping", Value::Null).await["result"],
        json!({})
    );
    let listed = mcp(&f, &token, "tools/list", Value::Null).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "list_databases",
            "search_schema",
            "describe_table",
            "check_sql",
            "run_query",
            "propose_write",
            "get_approval",
            "withdraw"
        ]
    );
    for t in tools {
        let schema = &t["inputSchema"];
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("task")));
    }
    // A notification gets 202 and no body.
    let (s, v) = mcp_raw(
        &f,
        Some(&token),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
        &[],
    )
    .await;
    assert_eq!((s, v), (StatusCode::ACCEPTED, Value::Null));
    // Protocol errors.
    for (body, status, code) in [
        ("not json".to_owned(), StatusCode::BAD_REQUEST, -32700),
        ("[]".to_owned(), StatusCode::BAD_REQUEST, -32600),
        (
            json!([{"jsonrpc":"2.0","id":1,"method":"ping"}]).to_string(),
            StatusCode::BAD_REQUEST,
            -32600,
        ),
        (json!({"id":1,"method":"ping"}).to_string(), StatusCode::BAD_REQUEST, -32600),
        (
            json!({"jsonrpc":"2.0","id":null,"method":"ping"}).to_string(),
            StatusCode::BAD_REQUEST,
            -32600,
        ),
        (
            json!({"jsonrpc":"2.0","id":{"a":1},"method":"ping"}).to_string(),
            StatusCode::BAD_REQUEST,
            -32600,
        ),
        (json!({"jsonrpc":"2.0","id":1}).to_string(), StatusCode::BAD_REQUEST, -32600),
        (
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#.to_owned(),
            StatusCode::BAD_REQUEST,
            -32600,
        ),
        (
            r#"{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"ping"}"#.to_owned(),
            StatusCode::BAD_REQUEST,
            -32600,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"method":"ping\u{0}"}).to_string(),
            StatusCode::BAD_REQUEST,
            -32600,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"method":"resources/list"}).to_string(),
            StatusCode::OK,
            -32601,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_everything"}})
                .to_string(),
            StatusCode::OK,
            -32602,
        ),
    ] {
        let (s, v) = mcp_raw(&f, Some(&token), body.clone(), &[]).await;
        assert_eq!(s, status, "{body}");
        assert_eq!(v["error"]["code"], code, "{body} {v}");
    }
    for id in [
        json!(0),
        json!(-7),
        json!(u64::MAX),
        json!("abc"),
        json!(""),
    ] {
        let body = json!({"jsonrpc":"2.0","id":id,"method":"ping"}).to_string();
        let (s, v) = mcp_raw(&f, Some(&token), body, &[]).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["id"], id);
    }
    // A tool call sent as a notification is acknowledged and not run.
    let (s, _) = mcp_raw(
        &f,
        Some(&token),
        json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_databases",
            "arguments":{"task":"Must not run"}}})
        .to_string(),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    // The door itself: only a valid agent token, only POST, never a browser.
    let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string();
    let (s, _) = mcp_raw(&f, None, ping.clone(), &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = mcp_raw(
        &f,
        None,
        ping.clone(),
        &[("cookie", f.grantor_cookie.as_str())],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = mcp_raw(
        &f,
        Some(&token),
        ping.clone(),
        &[("origin", "https://evil.example")],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = mcp_raw(
        &f,
        Some(&token),
        ping.clone(),
        &[("mcp-protocol-version", "1999-01-01")],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = mcp_raw(
        &f,
        Some(&token),
        ping.clone(),
        &[("mcp-protocol-version", "2025-06-18")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = bearer(&f, "/mcp", &token).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    // Every tool call must say what it is for, and takes no unknown argument.
    for arguments in [
        json!({}),
        json!({"task":"  "}),
        json!({"task":"x".repeat(501)}),
        json!({"task":"List","verbose":true}),
        json!({"task":"List","database":"not-a-uuid"}),
        json!({"task":"List","database":f.cluster,"sql":"SELECT 1"}),
        json!({"task":"Hidden\u{202e}text"}),
        json!({"task":"Two\nlines"}),
    ] {
        let (failed, v) = tool(&f, &token, "list_databases", arguments).await;
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "validation", "{v}");
        assert_eq!(v["error"]["fix"]["action"], "fix_arguments", "{v}");
    }
    let (failed, v) = tool(
        &f,
        &token,
        "list_databases",
        json!({"task":"See what I can reach"}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["databases"][0]["id"], json!(f.cluster));
    assert_eq!(v["databases"][0]["level"], "read");
    assert!(!v.to_string().contains("password") && !v.to_string().contains("host"));
    // A tool that needs a database says so, and an unreachable one teaches.
    let (failed, v) = tool(
        &f,
        &token,
        "check_sql",
        json!({"task":"Check","sql":"SELECT 1"}),
    )
    .await;
    assert!(failed);
    assert_eq!(v["error"]["fix"]["action"], "fix_arguments", "{v}");
    for (name, key, value) in [
        ("search_schema", "query", "a"),
        ("describe_table", "table", "a"),
        ("check_sql", "sql", "SELECT 1"),
        ("run_query", "sql", "SELECT 1"),
    ] {
        let (failed, v) = tool(
            &f,
            &token,
            name,
            json!({"task":"Probe","database":Uuid::new_v4(),key:value}),
        )
        .await;
        assert!(failed, "{name} {v}");
        assert_eq!(v["error"]["fix"]["action"], "choose_database", "{name} {v}");
    }
    // Each call is on the agent's trail with its task, under its owner.
    let mut trail: Vec<Value> = vec![];
    // The audit writer is asynchronous; give it time, also on a loaded machine.
    for _ in 0..600 {
        trail = sqlx::query_scalar(
            "SELECT details FROM audit_log WHERE action='agent.tool' AND target_id=$1 AND actor_id=$2
             ORDER BY created_at,id",
        )
        .bind(agent)
        .bind(f.grantor)
        .fetch_all(&f.db)
        .await
        .unwrap();
        if trail.len() >= 6 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Calls with arguments that do not parse have no usable task and are not recorded.
    assert_eq!(trail.len(), 6, "{trail:?}");
    assert!(trail.iter().any(|d| *d
        == json!({"tool":"list_databases","task":"See what I can reach","database":null,"outcome":"ok"})));
    assert!(trail
        .iter()
        .any(|d| d["tool"] == "run_query" && d["outcome"] != "ok"));
    assert!(!trail.iter().any(|d| d["task"] == "Must not run"));
    // A cluster whose own network policy excludes the agent is not listed,
    // and a call to it says why instead of sending the agent in a circle.
    let mut policy = Policy::for_environment("development");
    policy.allowed_cidrs = vec!["10.0.0.0/8".into()];
    sqlx::query("UPDATE cluster_policies SET policy=$1 WHERE cluster_id=$2")
        .bind(json!(policy))
        .bind(f.cluster)
        .execute(&f.db)
        .await
        .unwrap();
    let (failed, v) = tool(&f, &token, "list_databases", json!({"task":"Recheck"})).await;
    assert!(!failed);
    assert_eq!(v["databases"], json!([]));
    for (name, key, value) in [
        ("search_schema", "query", "a"),
        ("describe_table", "table", "a"),
        ("check_sql", "sql", "SELECT 1"),
        ("run_query", "sql", "SELECT 1"),
    ] {
        let (failed, v) = tool(
            &f,
            &token,
            name,
            json!({"task":"Probe","database":f.cluster,key:value}),
        )
        .await;
        assert!(failed, "{name} {v}");
        assert_eq!(v["error"]["code"], "network_denied", "{name} {v}");
        assert_eq!(v["error"]["fix"]["action"], "stop", "{name} {v}");
    }
    // One agent can make 120 tool calls in a minute, all tools together.
    let busy = new_agent(&f, &f.grantor_cookie, "Busy", "read").await;
    let (_, busy_token) = new_token(&f, &f.grantor_cookie, busy).await;
    let calls = (0..125).map(|_| tool(&f, &busy_token, "list_databases", json!({"task":"Flood"})));
    let results = futures::future::join_all(calls).await;
    let limited: Vec<&Value> = results
        .iter()
        .filter(|(failed, _)| *failed)
        .map(|(_, v)| v)
        .collect();
    assert_eq!(limited.len(), 5, "{limited:?}");
    assert!(limited.iter().all(|v| v["error"]["code"] == "rate_limited"
        && v["error"]["fix"]["action"] == "retry_later"
        && v["error"]["fix"]["retry_after_seconds"] == 60));
    // The first agent is not affected by the second one's flood.
    let (failed, _) = tool(&f, &token, "list_databases", json!({"task":"Still fine"})).await;
    assert!(!failed);
    // A paused agent is locked out of the door at once.
    let (s, _) = f
        .request(
            "PATCH",
            &format!("/agents/{agent}"),
            &f.grantor_cookie,
            Some(json!({"paused":true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = mcp_raw(&f, Some(&token), ping, &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    f.close().await;
}

#[tokio::test]
async fn agent_tools_read_guarded_data_teach_on_refusal_and_stop_loops() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let (table, secret) = (format!("vda_door_{suffix}"), format!("vda_vault_{suffix}"));
    for sql in [
        format!("CREATE TABLE {table}(id integer PRIMARY KEY,email text,note text NOT NULL)"),
        format!("INSERT INTO {table} VALUES (1,'ada@secret.example','first'),(2,'bob@secret.example','second'),(3,'cy@secret.example','third')"),
        format!("CREATE TABLE {secret}(id integer,api_key text)"),
    ] {
        sqlx::query(&sql).execute(&target).await.unwrap();
    }
    let mut policy = Policy::for_environment("development");
    policy.masked_columns = vec!["email".into()];
    policy.blocked_tables = vec![secret.clone()];
    f.policy(&policy).await;
    let agent = new_agent(&f, &f.grantor_cookie, "Analyst", "read").await;
    let (_, token) = new_token(&f, &f.grantor_cookie, agent).await;
    let db = json!(f.cluster);
    // Find the table; the blocked one is not listed under any spelling.
    let (failed, v) = tool(
        &f,
        &token,
        "search_schema",
        json!({"task":"Find the door tables","database":db,"query":suffix}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["tables"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["tables"][0]["table"], format!("public.{table}"));
    let (_, v) = tool(
        &f,
        &token,
        "search_schema",
        json!({"task":"Find key columns","database":db,"query":"API_KEY"}),
    )
    .await;
    assert!(!v.to_string().contains(&secret), "{v}");
    // Describe it; the protected column is marked, the blocked table is "not found".
    for name in [
        table.clone(),
        format!("public.{table}"),
        table.to_uppercase(),
    ] {
        let (failed, v) = tool(
            &f,
            &token,
            "describe_table",
            json!({"task":"Learn the columns","database":db,"table":name}),
        )
        .await;
        assert!(!failed, "{v}");
        let columns = v["columns"].as_array().unwrap();
        assert_eq!(columns.len(), 3);
        assert_eq!(
            columns[1],
            json!({"name":"email","type":"text","nullable":true,"primary_key":false,"protected":true})
        );
        assert_eq!(columns[0]["primary_key"], true);
        assert_eq!(columns[2]["protected"], false);
    }
    for name in [
        secret.clone(),
        format!("public.{secret}"),
        "no_such_table".into(),
    ] {
        let (failed, v) = tool(
            &f,
            &token,
            "describe_table",
            json!({"task":"Look","database":db,"table":name}),
        )
        .await;
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "table_not_found", "{v}");
        assert_eq!(v["error"]["fix"]["action"], "fix_arguments", "{v}");
        assert!(v["error"]["fix"]["hint"]
            .as_str()
            .unwrap()
            .contains("search_schema"));
    }
    // check_sql: an accepted statement shows what will run; a refused one teaches.
    let (failed, v) = tool(
        &f,
        &token,
        "check_sql",
        json!({"task":"Check before I run","database":db,"sql":format!("SELECT id,note FROM {table}")}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["verdict"], "allow");
    assert!(v["will_run_as"].as_str().unwrap().contains("LIMIT"), "{v}");
    assert_eq!(v["fix"], Value::Null);
    for (sql, action) in [
        (format!("SELECT * FROM {secret}"), "stop"),
        ("SELECT 1; SELECT 2".to_owned(), "rewrite_sql"),
        (format!("SELEC id FROM {table}"), "rewrite_sql"),
        (format!("DELETE FROM {table} WHERE id=1"), "ask_owner"),
        (format!("UPDATE {table} SET note=note"), "ask_owner"),
    ] {
        let (failed, v) = tool(
            &f,
            &token,
            "check_sql",
            json!({"task":"Check","database":db,"sql":sql}),
        )
        .await;
        assert!(!failed, "{v}");
        assert_eq!(v["verdict"], "deny", "{sql} {v}");
        assert_eq!(v["fix"]["action"], action, "{sql} {v}");
        assert!(!v["fix"]["hint"].as_str().unwrap().is_empty());
    }
    // run_query: rows come back, the protected column is masked, the row cap holds.
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read the notes for the weekly report","database":db,
            "sql":format!("SELECT id,email,note FROM {table} ORDER BY id"),"max_rows":2}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["row_count"], 2);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["rows"][0][2], "first");
    assert!(!v.to_string().contains("secret.example"), "{v}");
    assert!(v["ran_as"].as_str().unwrap().contains("LIMIT"));
    let (task, linked): (Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT task,agent_id FROM query_history ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(
        task.as_deref(),
        Some("Read the notes for the weekly report")
    );
    assert_eq!(linked, Some(agent));
    // A result is cut at about one megabyte of rows, whatever max_rows says.
    sqlx::query(&format!("UPDATE {table} SET note=repeat('x',400000)"))
        .execute(&target)
        .await
        .unwrap();
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read large notes","database":db,
            "sql":format!("SELECT id,note FROM {table} ORDER BY id"),"max_rows":1000}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(
        (v["row_count"].clone(), v["truncated"].clone()),
        (json!(2), json!(true))
    );
    // One row that cannot fit is an error with a fix, not an empty answer.
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read one huge value","database":db,
            "sql":format!("SELECT note||note||note||note FROM {table} WHERE id=1")}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "result_too_large", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "rewrite_sql");
    // A database error teaches too, and does not count as a refusal.
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Typo","database":db,"sql":format!("SELECT nope FROM {table}")}),
    )
    .await;
    assert!(failed);
    assert_eq!(v["error"]["code"], "upstream", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "rewrite_sql");
    // Five refusals in a row: the sixth call is stopped, even for a good query.
    for attempt in 0..5 {
        let (failed, v) = tool(
            &f,
            &token,
            "run_query",
            json!({"task":"Try the vault","database":db,"sql":format!("SELECT * FROM {secret} -- {attempt}")}),
        )
        .await;
        assert!(failed);
        assert_eq!(v["error"]["code"], "query_denied", "{v}");
        assert_eq!(v["error"]["fix"]["action"], "stop", "{v}");
    }
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM query_history")
        .fetch_one(&f.db)
        .await
        .unwrap();
    let good = json!({"task":"A good query","database":db,"sql":"SELECT 1"});
    let (failed, v) = tool(&f, &token, "run_query", good.clone()).await;
    assert!(failed);
    assert_eq!(v["error"]["code"], "too_many_denials", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "stop");
    assert_eq!(v["error"]["fix"]["retry_after_seconds"], 600);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM query_history")
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(before, after, "a stopped call must not reach the database");
    // The other tools still work, so the agent can explain itself to its owner.
    let (failed, _) = tool(&f, &token, "list_databases", json!({"task":"Recheck"})).await;
    assert!(!failed);
    // A success resets the streak: four refusals, one success, four more are fine.
    let other = new_agent(&f, &f.grantor_cookie, "Careful", "read").await;
    let (_, other_token) = new_token(&f, &f.grantor_cookie, other).await;
    for round in 0..2 {
        for attempt in 0..4 {
            let (failed, v) = tool(
                &f,
                &other_token,
                "run_query",
                json!({"task":"Try","database":db,"sql":format!("SELECT * FROM {secret} -- {round} {attempt}")}),
            )
            .await;
            assert!(failed);
            assert_eq!(v["error"]["code"], "query_denied", "{v}");
        }
        let (failed, v) = tool(&f, &other_token, "run_query", good.clone()).await;
        assert!(!failed, "{v}");
    }
    // Parallel refused calls cannot all slip past the breaker: five get the
    // guard's answer, the rest are stopped.
    let looper = new_agent(&f, &f.grantor_cookie, "Looper", "read").await;
    let (_, looper_token) = new_token(&f, &f.grantor_cookie, looper).await;
    let calls = (0..20).map(|i| {
        tool(
            &f,
            &looper_token,
            "run_query",
            json!({"task":"Race","database":db,"sql":format!("SELECT * FROM {secret} -- {i}")}),
        )
    });
    let results = futures::future::join_all(calls).await;
    let count = |code: &str| {
        results
            .iter()
            .filter(|(_, v)| v["error"]["code"] == code)
            .count()
    };
    assert_eq!((count("query_denied"), count("too_many_denials")), (5, 15));
    // A database outside the agent's reach counts toward the breaker too.
    let lost = new_agent(&f, &f.grantor_cookie, "Lost", "read").await;
    let (_, lost_token) = new_token(&f, &f.grantor_cookie, lost).await;
    let nowhere = json!({"task":"Guess","database":Uuid::new_v4(),"sql":"SELECT 1"});
    for attempt in 0..6 {
        let (failed, v) = tool(&f, &lost_token, "run_query", nowhere.clone()).await;
        assert!(failed);
        let expected = if attempt < 5 {
            "not_found"
        } else {
            "too_many_denials"
        };
        assert_eq!(v["error"]["code"], expected, "{v}");
    }
    // The hourly budget counts every recorded attempt and says how long to wait.
    let (s, v) = f
        .request(
            "POST",
            "/agents",
            &f.grantor_cookie,
            Some(json!({"name":"Small budget","cluster_ids":[f.cluster],"hourly_query_budget":2})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["hourly_query_budget"], 2);
    let small: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    let (_, small_token) = new_token(&f, &f.grantor_cookie, small).await;
    for _ in 0..2 {
        let (failed, v) = tool(&f, &small_token, "run_query", good.clone()).await;
        assert!(!failed, "{v}");
    }
    let (failed, v) = tool(&f, &small_token, "run_query", good.clone()).await;
    assert!(failed);
    assert_eq!(v["error"]["code"], "budget_exceeded", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "retry_later");
    let wait = v["error"]["fix"]["retry_after_seconds"].as_u64().unwrap();
    assert!((3500..=3600).contains(&wait), "{wait}");
    // Parallel calls cannot overshoot the budget either: exactly five run.
    let (s, v) = f
        .request(
            "POST",
            "/agents",
            &f.grantor_cookie,
            Some(json!({"name":"Racer","cluster_ids":[f.cluster],"hourly_query_budget":5})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let racer: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    let (_, racer_token) = new_token(&f, &f.grantor_cookie, racer).await;
    let calls = (0..20).map(|_| tool(&f, &racer_token, "run_query", good.clone()));
    let results = futures::future::join_all(calls).await;
    let ran = results.iter().filter(|(failed, _)| !failed).count();
    let over = results
        .iter()
        .filter(|(_, v)| v["error"]["code"] == "budget_exceeded")
        .count();
    assert_eq!(
        (ran, over),
        (5, 15),
        "{:?}",
        results
            .iter()
            .map(|(_, v)| v["error"].clone())
            .collect::<Vec<_>>()
    );
    let recorded: i64 = sqlx::query_scalar("SELECT count(*) FROM query_history WHERE agent_id=$1")
        .bind(racer)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(recorded, 5, "a refusal for the budget records nothing");
    // Raising the budget lets it go on; the change is audited with both values.
    for bad in [0, 100_001, -5] {
        let (s, _) = f
            .request(
                "PATCH",
                &format!("/agents/{small}"),
                &f.grantor_cookie,
                Some(json!({"hourly_query_budget":bad})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    let (s, _) = f
        .request(
            "PATCH",
            &format!("/agents/{small}"),
            &f.admin_cookie,
            Some(json!({"hourly_query_budget":50})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "only the owner sets the budget");
    let (s, v) = f
        .request(
            "PATCH",
            &format!("/agents/{small}"),
            &f.grantor_cookie,
            Some(json!({"hourly_query_budget":50})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (failed, v) = tool(&f, &small_token, "run_query", good).await;
    assert!(!failed, "{v}");
    let change: Value = sqlx::query_scalar(
        "SELECT details FROM audit_log WHERE action='agent.update' AND target_id=$1",
    )
    .bind(small)
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(change, json!({"hourly_query_budget":{"from":2,"to":50}}));
    for name in [&table, &secret] {
        sqlx::query(&format!("DROP TABLE {name}"))
            .execute(&target)
            .await
            .unwrap();
    }
    target.close().await;
    f.close().await;
}

#[tokio::test]
async fn a_token_cannot_be_minted_while_its_owner_is_losing_access() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let agent = new_agent(&f, &f.grantor_cookie, "Racer", "read").await;
    let path = format!("/agents/{agent}/tokens");
    // What an administrator's password reset does, held open before commit.
    let mut reset = f.db.begin().await.unwrap();
    for sql in [
        "SELECT org_role,disabled FROM users WHERE id=$1 FOR NO KEY UPDATE",
        "UPDATE users SET password_hash=password_hash WHERE id=$1",
        "DELETE FROM sessions WHERE user_id=$1",
        "UPDATE agent_tokens SET revoked_at=now() WHERE revoked_at IS NULL
         AND agent_id IN (SELECT id FROM agents WHERE owner_id=$1)",
    ] {
        sqlx::query(sql)
            .bind(f.grantor)
            .execute(&mut *reset)
            .await
            .unwrap();
    }
    // The mint waits for the reset instead of finishing beside it. After
    // the reset the old session is gone, so the mint is refused.
    let (s, v) = {
        let mint = f.request("POST", &path, &f.grantor_cookie, Some(json!({})));
        tokio::pin!(mint);
        let early = tokio::time::timeout(std::time::Duration::from_millis(500), &mut mint).await;
        assert!(early.is_err(), "the mint did not wait: {early:?}");
        reset.commit().await.unwrap();
        mint.await
    };
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent_tokens WHERE agent_id=$1 AND revoked_at IS NULL",
    )
    .bind(agent)
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(live, 0);
    // A fresh session mints normally.
    let cookie = Fixture::session(&f.db, f.grantor).await;
    let (s, v) = f.request("POST", &path, &cookie, Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    f.close().await;
}

/// A GET that returns the body as text, for the setup script.
async fn get_text(f: &Fixture, path: &str, cookie: &str) -> (StatusCode, String) {
    let mut req = Request::get(format!("/api/v1{path}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    let response = f.app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn the_database_is_the_judge_for_agents() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    // This test is the database administrator. It makes a database of its own
    // and points the cluster at it, so that its grants and other tests' tables
    // do not get in each other's way.
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let (schema, role) = (format!("judge_{suffix}"), format!("vda_agent_{suffix}"));
    let database = format!("judge_db_{suffix}");
    let server = sqlx::PgPool::connect(&target_url).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&server)
        .await
        .unwrap();
    let (base_url, _) = target_url.rsplit_once('/').unwrap();
    let target_url = format!("{base_url}/{database}");
    let dba = sqlx::PgPool::connect(&target_url).await.unwrap();
    sqlx::query("UPDATE clusters SET database=$1,updated_at=clock_timestamp() WHERE id=$2")
        .bind(&database)
        .bind(f.cluster)
        .execute(&f.db)
        .await
        .unwrap();
    let run = |sql: String| {
        let dba = dba.clone();
        async move {
            sqlx::raw_sql(&sql).execute(&dba).await.unwrap();
        }
    };
    // Older PostgreSQL lets everyone create in `public`; a hardened database does not.
    run("REVOKE CREATE ON SCHEMA public FROM PUBLIC".into()).await;
    run(format!(
        "CREATE SCHEMA {schema};
         CREATE TABLE {schema}.users(id integer PRIMARY KEY,email text,note text);
         INSERT INTO {schema}.users VALUES (1,'ada@canary.example','first'),(2,'bob@canary.example','second');
         CREATE TABLE {schema}.vault(id integer,api_key text);
         INSERT INTO {schema}.vault VALUES (1,'canary-api-key');
         CREATE VIEW {schema}.v_vault AS SELECT * FROM {schema}.vault;
         CREATE MATERIALIZED VIEW {schema}.m_users AS SELECT * FROM {schema}.users;
         CREATE TABLE {schema}.orders(id integer,who text) PARTITION BY RANGE (id);
         CREATE TABLE {schema}.orders_p1 PARTITION OF {schema}.orders FOR VALUES FROM (0) TO (100);
         INSERT INTO {schema}.orders VALUES (1,'canary-partition');
         CREATE TABLE {schema}.people(id integer,name text);
         CREATE TABLE {schema}.vip_people(extra text) INHERITS ({schema}.people);
         INSERT INTO {schema}.vip_people VALUES (7,'canary-vip','x');
         CREATE TABLE {schema}.accounts(id integer,ssn text) PARTITION BY RANGE (id);
         CREATE TABLE {schema}.accounts_p1 PARTITION OF {schema}.accounts FOR VALUES FROM (0) TO (100);
         INSERT INTO {schema}.accounts VALUES (1,'canary-ssn');
         CREATE TABLE {schema}.pa(id integer,tag text);
         CREATE TABLE {schema}.pb(id integer,tag text);
         CREATE TABLE {schema}.kid() INHERITS ({schema}.pa,{schema}.pb);
         INSERT INTO {schema}.kid VALUES (7,'canary-two-parents');"
    ))
    .await;
    let mut policy = Policy::for_environment("development");
    policy.masked_columns = vec!["email".into(), "accounts.ssn".into()];
    policy.blocked_tables = vec![
        format!("{schema}.vault"),
        format!("{schema}.orders"),
        format!("{schema}.vip_people"),
        format!("{schema}.pa"),
    ];
    f.policy(&policy).await;
    // The owner is an organization administrator: the strongest owner there is.
    let agent = new_agent(&f, &f.admin_cookie, "Judge", "read").await;
    let (_, token) = new_token(&f, &f.admin_cookie, agent).await;
    let identity = vda_core::agents::authenticate(&f.db, &token).await.unwrap();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let ask = |sql: String| {
        let (core, actor, cluster) = (f.state.core.clone(), identity.actor.clone(), f.cluster);
        async move {
            let input = vda_core::query::QueryInput {
                sql,
                query_id: None,
                task: Some("Probe".into()),
            };
            vda_core::query::run(&core, &actor, cluster, input, ip, false).await
        }
    };
    let canaries = [
        "canary.example",
        "canary-api-key",
        "canary-partition",
        "canary-vip",
        "canary-ssn",
        "canary-two-parents",
        "canary-ext",
    ];
    let leaked = |result: &Result<vda_core::query::QueryResult, vda_server::error::ApiError>| {
        let text = format!("{result:?}");
        canaries.iter().any(|canary| text.contains(canary))
    };
    // Statements that try to get a hidden value out. Some fool a guard that
    // reads SQL text; none may fool the database.
    let attacks: Vec<String> = [
        "SELECT * FROM {s}.v_vault",
        "SELECT api_key FROM {s}.v_vault",
        "SELECT * FROM {s}.m_users",
        "SELECT email FROM {s}.m_users",
        "SELECT * FROM {s}.vault",
        "TABLE {s}.vault",
        "SELECT * FROM ONLY {s}.vault",
        "SELECT email FROM {s}.users",
        "SELECT * FROM {s}.users",
        "SELECT u.* FROM {s}.users u",
        "SELECT (u).* FROM {s}.users u",
        "SELECT u FROM {s}.users u",
        "SELECT u::text FROM {s}.users u",
        "SELECT row_to_json(u) FROM {s}.users u",
        "SELECT to_jsonb(u) FROM {s}.users u",
        "SELECT x.e FROM {s}.users u, LATERAL (VALUES (u.email)) x(e)",
        "SELECT e FROM {s}.users u CROSS JOIN LATERAL unnest(ARRAY[u.email]) e",
        "SELECT (SELECT u.email) FROM {s}.users u",
        "SELECT max(email) FROM {s}.users",
        "SELECT string_agg(email, ',') FROM {s}.users",
        "SELECT substr(email, 1, 20) FROM {s}.users",
        "SELECT id FROM {s}.users WHERE email LIKE 'ada%'",
        "SELECT id FROM {s}.users ORDER BY email",
        "SELECT count(*) FROM {s}.users GROUP BY email",
        "SELECT id, CASE WHEN email LIKE 'a%' THEN 1 ELSE 0 END FROM {s}.users",
        "WITH t AS (SELECT * FROM {s}.users) SELECT * FROM t",
        "SELECT * FROM {s}.users NATURAL JOIN {s}.vault",
        "SELECT a.id FROM {s}.users a JOIN {s}.vault b ON b.api_key LIKE 'canary%'",
        // A blocked table is also closed through its partitions, and through
        // the parent of a blocked child. A protected column follows too.
        "SELECT who FROM {s}.orders_p1",
        "SELECT * FROM {s}.orders",
        "SELECT name FROM {s}.people",
        "SELECT id FROM {s}.people",
        "SELECT ssn FROM {s}.accounts_p1",
        "SELECT ssn FROM {s}.accounts",
        // A child with two parents: the other parent of a blocked table's child.
        "SELECT tag FROM {s}.pb",
        "SELECT id FROM {s}.pb",
        "SELECT tag FROM {s}.kid",
    ]
    .iter()
    .map(|sql| sql.replace("{s}", &schema))
    .collect();
    // Before the agent login exists, the cluster's own login decides. The
    // guard does not know that the view reads the blocked table: it leaks.
    let through_view = ask(attacks[0].clone()).await;
    assert!(
        leaked(&through_view),
        "expected the known hole: {through_view:?}"
    );
    let (failed, v) = tool(&f, &token, "list_databases", json!({"task":"Look"})).await;
    assert!(!failed);
    assert_eq!(v["databases"][0]["enforced_by"], "gateway");
    // The gateway writes the script; the administrator runs it and sets a password.
    let base = format!("/clusters/{}/agent-login", f.cluster);
    let (s, v) = f.request("GET", &base, &f.admin_cookie, None).await;
    assert_eq!((s, v), (StatusCode::OK, json!({"configured":false})));
    let (s, script) = get_text(
        &f,
        &format!("{base}/script?username={role}"),
        &f.admin_cookie,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{script}");
    assert!(script.contains(&format!(
        "GRANT SELECT (\"id\", \"note\") ON \"{schema}\".\"users\" TO \"{role}\";"
    )));
    assert!(!script.contains("canary") && !script.contains("test-password"));
    run(script).await;
    run(format!("ALTER ROLE {role} PASSWORD 'agent-login-pw'")).await;
    // Only a cluster administrator can see or set it, and only a sound name.
    let recipient = Fixture::session(&f.db, f.recipient).await;
    for (method, path, body) in [
        ("GET", base.clone(), None),
        (
            "PUT",
            base.clone(),
            Some(json!({"username":role,"password":"agent-login-pw"})),
        ),
        ("DELETE", base.clone(), None),
        ("POST", format!("{base}/check"), None),
        ("GET", format!("{base}/script"), None),
    ] {
        let (s, _) = f.request(method, &path, &recipient, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {path}");
    }
    let cluster_login: String = sqlx::query_scalar("SELECT username FROM clusters WHERE id=$1")
        .bind(f.cluster)
        .fetch_one(&f.db)
        .await
        .unwrap();
    for name in [
        cluster_login.as_str(),
        "Bad-Name",
        "pg_monitor",
        "",
        "a\"; DROP ROLE x; --",
    ] {
        let (s, v) = f
            .request(
                "PUT",
                &base,
                &f.admin_cookie,
                Some(json!({"username":name,"password":"agent-login-pw"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{name} {v}");
    }
    let (s, bad) = get_text(
        &f,
        &format!("{base}/script?username=x%22y"),
        &f.admin_cookie,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    // A wrong password is stored but fails the check, and agents are refused.
    let (s, v) = f
        .request(
            "PUT",
            &base,
            &f.admin_cookie,
            Some(json!({"username":role,"password":"wrong"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["findings"][0]["code"], "check_failed", "{v}");
    let refused = ask(format!("SELECT id FROM {schema}.users"))
        .await
        .unwrap_err();
    // Not drift: the agent is told to try later, not that a person must act.
    assert_eq!(refused.code, "database_check_failed");
    // The right password: the check passes. What is left are notes about
    // tables the policy would allow but the login cannot read.
    let (s, v) = f
        .request(
            "PUT",
            &base,
            &f.admin_cookie,
            Some(json!({"username":role,"password":"agent-login-pw"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "ok", "{v}");
    assert_eq!(v["stale"], false);
    assert!(!v.to_string().contains("agent-login-pw"));
    assert!(v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["severity"] == "warning"));
    let stored: String = sqlx::query_scalar(
        "SELECT password_enc||(SELECT string_agg(details::text,'') FROM audit_log) FROM cluster_agent_logins",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert!(!stored.contains("agent-login-pw"));
    let (_, v) = tool(&f, &token, "list_databases", json!({"task":"Look"})).await;
    assert_eq!(v["databases"][0]["enforced_by"], "database");
    // Now the database decides. Allowed columns still read.
    let rows = ask(format!("SELECT id, note FROM {schema}.users ORDER BY id"))
        .await
        .unwrap();
    assert_eq!(
        rows.rows,
        vec![
            vec![json!(1), json!("first")],
            vec![json!(2), json!("second")]
        ]
    );
    let rows = ask(format!("SELECT id FROM {schema}.accounts_p1"))
        .await
        .unwrap();
    assert_eq!(rows.rows, vec![vec![json!(1)]]);
    // Every attack fails to produce a hidden value. The statements that reach
    // the database are refused by the database, not by a text rule.
    let mut refused_by_database = 0;
    for sql in &attacks {
        let result = ask(sql.clone()).await;
        assert!(!leaked(&result), "{sql} leaked: {result:?}");
        assert!(result.is_err(), "{sql} must not succeed: {result:?}");
        if result.is_err_and(|error| error.code == "upstream") {
            refused_by_database += 1;
        }
    }
    assert!(
        refused_by_database >= 5,
        "only {refused_by_database} reached the database"
    );
    // The agent login cannot change anything either, whatever the guard thinks.
    let attempt: Result<_, sqlx::Error> = async {
        let login = target_url.replacen("vda:test-password", &format!("{role}:agent-login-pw"), 1);
        let pool = sqlx::PgPool::connect(&login).await?;
        let outcome = sqlx::query(&format!("UPDATE {schema}.users SET note='x'"))
            .execute(&pool)
            .await;
        pool.close().await;
        outcome
    }
    .await;
    assert!(attempt.is_err(), "the agent login could write");
    // A person's query is not affected: it still uses the cluster's own login.
    let (s, v) = f
        .request(
            "POST",
            &format!("/clusters/{}/query", f.cluster),
            &f.admin_cookie,
            Some(json!({"sql":format!("SELECT id FROM {schema}.vault")})),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the guard still blocks the table: {v}"
    );
    // A column added later is closed until someone decides about it.
    run(format!(
        "ALTER TABLE {schema}.users ADD COLUMN ssn text DEFAULT 'canary-ssn'"
    ))
    .await;
    let result = ask(format!("SELECT ssn FROM {schema}.users")).await;
    assert!(result.is_err() && !format!("{result:?}").contains("canary-ssn"));
    // Drift: each way the database can be left more open than the policy is
    // found by the check, and agents are refused until it is repaired.
    let check = || async {
        let (s, v) = f
            .request("POST", &format!("{base}/check"), &f.admin_cookie, None)
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v
    };
    assert_eq!(check().await["status"], "ok");
    for (open, close, code, object) in [
        (
            format!("GRANT SELECT ON {schema}.vault TO PUBLIC"),
            format!("REVOKE SELECT ON {schema}.vault FROM PUBLIC"),
            "readable_beyond_policy",
            format!("{schema}.vault"),
        ),
        (
            format!("GRANT SELECT (email) ON {schema}.users TO {role}"),
            format!("REVOKE SELECT (email) ON {schema}.users FROM {role}"),
            "readable_beyond_policy",
            format!("{schema}.users"),
        ),
        (
            format!("GRANT SELECT ON {schema}.v_vault TO {role}"),
            format!("REVOKE SELECT ON {schema}.v_vault FROM {role}"),
            "readable_beyond_policy",
            format!("{schema}.v_vault"),
        ),
        (
            format!("GRANT UPDATE (note) ON {schema}.users TO {role}"),
            format!("REVOKE UPDATE (note) ON {schema}.users FROM {role}"),
            "can_write",
            format!("{schema}.users"),
        ),
        (
            format!("GRANT CREATE ON SCHEMA {schema} TO {role}"),
            format!("REVOKE CREATE ON SCHEMA {schema} FROM {role}"),
            "can_create",
            schema.clone(),
        ),
        (
            format!("CREATE FUNCTION {schema}.peek() RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT api_key FROM {schema}.vault'"),
            format!("DROP FUNCTION {schema}.peek()"),
            "definer_function",
            format!("{schema}.peek"),
        ),
        (
            "GRANT SELECT ON pg_catalog.pg_statistic TO PUBLIC".to_owned(),
            "REVOKE SELECT ON pg_catalog.pg_statistic FROM PUBLIC".to_owned(),
            "system_catalog_readable",
            "pg_catalog.pg_statistic".to_owned(),
        ),
        (
            "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO PUBLIC".to_owned(),
            "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM PUBLIC".to_owned(),
            "dangerous_function",
            "pg_catalog.pg_read_file".to_owned(),
        ),
        (
            format!("CREATE EXTENSION IF NOT EXISTS postgres_fdw; CREATE SERVER loop_{suffix} FOREIGN DATA WRAPPER postgres_fdw; GRANT USAGE ON FOREIGN SERVER loop_{suffix} TO PUBLIC"),
            format!("DROP SERVER loop_{suffix} CASCADE"),
            "foreign_server",
            format!("loop_{suffix}"),
        ),
        (
            // Objects that someone put into a system schema are checked too.
            format!("CREATE VIEW information_schema.leak_{suffix} AS SELECT * FROM {schema}.vault; GRANT SELECT ON information_schema.leak_{suffix} TO PUBLIC"),
            format!("DROP VIEW information_schema.leak_{suffix}"),
            "system_catalog_readable",
            format!("information_schema.leak_{suffix}"),
        ),
        (
            format!("CREATE FUNCTION pg_catalog.peek_{suffix}() RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT api_key FROM {schema}.vault LIMIT 1'"),
            format!("DROP FUNCTION pg_catalog.peek_{suffix}()"),
            "definer_function",
            format!("pg_catalog.peek_{suffix}"),
        ),
        (
            // A definer function in a schema the login cannot use is still
            // reachable through an aggregate that calls it.
            format!("CREATE SCHEMA priv_{suffix}; CREATE FUNCTION priv_{suffix}.step(text, integer) RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT api_key FROM {schema}.vault LIMIT 1'; CREATE AGGREGATE {schema}.peekagg(integer) (SFUNC = priv_{suffix}.step, STYPE = text)"),
            format!("DROP SCHEMA priv_{suffix} CASCADE"),
            "definer_function",
            format!("priv_{suffix}.step"),
        ),
        (
            // An extension's own table is not excused when the policy names it.
            format!("CREATE EXTENSION IF NOT EXISTS hstore; CREATE TABLE {schema}.ext_cfg(id integer,email text); INSERT INTO {schema}.ext_cfg VALUES (1,'canary-ext'); ALTER EXTENSION hstore ADD TABLE {schema}.ext_cfg; GRANT SELECT ON {schema}.ext_cfg TO PUBLIC"),
            format!("ALTER EXTENSION hstore DROP TABLE {schema}.ext_cfg; DROP TABLE {schema}.ext_cfg"),
            "readable_beyond_policy",
            format!("{schema}.ext_cfg"),
        ),
        (
            format!("GRANT SELECT ON {schema}.pb TO PUBLIC"),
            format!("REVOKE SELECT ON {schema}.pb FROM PUBLIC"),
            "readable_beyond_policy",
            format!("{schema}.pb"),
        ),
        (
            "CREATE EXTENSION dblink".to_owned(),
            "DROP EXTENSION dblink".to_owned(),
            "dangerous_function",
            "public.dblink functions".to_owned(),
        ),
        (
            format!("GRANT SELECT ON {schema}.orders_p1 TO PUBLIC"),
            format!("REVOKE SELECT ON {schema}.orders_p1 FROM PUBLIC"),
            "readable_beyond_policy",
            format!("{schema}.orders_p1"),
        ),
        (
            format!("ALTER ROLE {role} CREATEROLE"),
            format!("ALTER ROLE {role} NOCREATEROLE"),
            "role_too_powerful",
            "login".to_owned(),
        ),
        (
            format!("GRANT pg_read_all_data TO {role}"),
            format!("REVOKE pg_read_all_data FROM {role}"),
            "role_too_powerful",
            "login".to_owned(),
        ),
    ] {
        run(open.clone()).await;
        let v = check().await;
        assert_eq!(v["status"], "drift", "{open}: {v}");
        assert!(
            v["findings"].as_array().unwrap().iter().any(|f| f["severity"] == "critical"
                && f["code"] == code
                && f["object"] == json!(object)),
            "{open}: {v}"
        );
        let refused = ask(format!("SELECT id FROM {schema}.users")).await.unwrap_err();
        assert_eq!(refused.code, "database_setup_drift", "{open}");
        run(close).await;
        assert_eq!(check().await["status"], "ok", "{open}");
        ask(format!("SELECT id FROM {schema}.users")).await.unwrap();
    }
    // Things that are worth a note but do not close the cluster.
    run(format!(
        "ALTER ROLE {role} RESET default_transaction_read_only; CREATE EXTENSION pg_stat_statements"
    ))
    .await;
    let v = check().await;
    assert_eq!(v["status"], "ok", "{v}");
    let noted = |code: &str, object: &str| {
        v["findings"].as_array().unwrap().iter().any(|f| {
            f["severity"] == "warning" && f["code"] == code && f["object"] == json!(object)
        })
    };
    assert!(noted("not_read_only", "login"), "{v}");
    assert!(
        noted("extension_object_readable", "public.pg_stat_statements"),
        "{v}"
    );
    run(format!(
        "ALTER ROLE {role} SET default_transaction_read_only = on; DROP EXTENSION pg_stat_statements"
    ))
    .await;
    // The script refuses a login that owns something: it would strip it and
    // drop what it owns. Nothing is changed when it stops.
    let owner = format!("app_owner_{suffix}");
    run(format!(
        "CREATE ROLE {owner}; CREATE TABLE {schema}.app_data(id integer); ALTER TABLE {schema}.app_data OWNER TO {owner}"
    ))
    .await;
    let (s, harmful) = get_text(
        &f,
        &format!("{base}/script?username={owner}"),
        &f.admin_cookie,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // The script stops inside its transaction; roll that back, as psql's
    // ON_ERROR_STOP or closing the session would.
    let mut session = dba.acquire().await.unwrap();
    let stopped = sqlx::raw_sql(&harmful)
        .execute(&mut *session)
        .await
        .unwrap_err();
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut *session)
        .await
        .unwrap();
    drop(session);
    assert!(stopped.to_string().contains("owns objects"), "{stopped}");
    let kept: bool = sqlx::query_scalar(&format!(
        "SELECT to_regclass('{schema}.app_data') IS NOT NULL AND NOT rolcanlogin FROM pg_roles WHERE rolname='{owner}'"
    ))
    .fetch_one(&dba)
    .await
    .unwrap();
    assert!(kept, "the script changed a login that owns objects");
    run(format!("DROP TABLE {schema}.app_data; DROP ROLE {owner}")).await;
    // Nor will the gateway write a script for the cluster's own login.
    let (s, _) = get_text(
        &f,
        &format!("{base}/script?username={cluster_login}"),
        &f.admin_cookie,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // A stricter policy takes effect at once, without anyone running a check:
    // the next agent query checks first, finds the login too open, and stops.
    policy.blocked_tables.push(format!("{schema}.users"));
    f.policy(&policy).await;
    let (_, v) = f.request("GET", &base, &f.admin_cookie, None).await;
    assert_eq!(v["stale"], true, "{v}");
    let refused = ask(format!("SELECT id FROM {schema}.users"))
        .await
        .unwrap_err();
    assert!(
        matches!(refused.code, "query_denied" | "database_setup_drift"),
        "{refused}"
    );
    let refused = ask("SELECT 1".into()).await.unwrap_err();
    assert_eq!(refused.code, "database_setup_drift");
    // Running the new script closes the table in the database too.
    let (_, script) = get_text(&f, &format!("{base}/script"), &f.admin_cookie).await;
    assert!(
        script.contains(&format!("TO \"{role}\"")),
        "the stored name is the default"
    );
    assert!(!script.contains(&format!("ON \"{schema}\".\"users\"")));
    run(script).await;
    assert_eq!(check().await["status"], "ok");
    assert_eq!(
        ask("SELECT 1 AS n".into()).await.unwrap().rows,
        vec![vec![json!(1)]]
    );
    // Removing the login puts agents back on the cluster's own login.
    let (s, _) = f.request("DELETE", &base, &f.admin_cookie, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = f.request("DELETE", &base, &f.admin_cookie, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, v) = tool(&f, &token, "list_databases", json!({"task":"Look"})).await;
    assert_eq!(v["databases"][0]["enforced_by"], "gateway");
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE action LIKE 'agent_login.%' ORDER BY created_at,id",
    )
    .fetch_all(&f.db)
    .await
    .unwrap();
    assert_eq!(
        events,
        ["agent_login.set", "agent_login.set", "agent_login.remove"]
    );
    // When the cluster's endpoint changes, the stored agent password is
    // cleared: it is never sent to an endpoint it was not entered for. The
    // login stays, so agents are refused; they do not quietly fall back to
    // the cluster's own login.
    let (s, v) = f
        .request(
            "PUT",
            &base,
            &f.admin_cookie,
            Some(json!({"username":role,"password":"agent-login-pw"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "ok", "{v}");
    let cluster_password = target_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('@'))
        .and_then(|(login, _)| login.split_once(':'))
        .map(|(_, password)| password.to_owned())
        .unwrap();
    let (s, v) = f
        .request(
            "PATCH",
            &format!("/clusters/{}", f.cluster),
            &f.admin_cookie,
            Some(json!({"tls_mode":"prefer","password":cluster_password})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, v) = f.request("GET", &base, &f.admin_cookie, None).await;
    assert_eq!(
        (v["configured"].clone(), v["needs_password"].clone()),
        (json!(true), json!(true))
    );
    let kept: String = sqlx::query_scalar("SELECT password_enc FROM cluster_agent_logins")
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(kept, "");
    let noted: Value = sqlx::query_scalar(
        "SELECT details FROM audit_log WHERE action='cluster.update' ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(noted, json!({"agent_login_password_cleared":true}));
    let refused = ask("SELECT 1".into()).await.unwrap_err();
    assert_eq!(refused.code, "database_setup_drift");
    let v = check().await;
    assert_eq!(v["findings"][0]["code"], "password_needed", "{v}");
    let (_, v) = tool(&f, &token, "list_databases", json!({"task":"Look"})).await;
    assert_eq!(v["databases"][0]["enforced_by"], "database");
    // A change that does not move the endpoint keeps it.
    let (s, _) = f
        .request(
            "PUT",
            &base,
            &f.admin_cookie,
            Some(json!({"username":role,"password":"agent-login-pw"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = f
        .request(
            "PATCH",
            &format!("/clusters/{}", f.cluster),
            &f.admin_cookie,
            Some(json!({"name":"Renamed cluster"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, v) = f.request("GET", &base, &f.admin_cookie, None).await;
    assert_eq!(
        (v["status"].clone(), v["needs_password"].clone()),
        (json!("ok"), json!(false))
    );
    ask("SELECT 1".into()).await.unwrap();
    f.close().await;
    run(format!("DROP OWNED BY {role}")).await;
    dba.close().await;
    for sql in [
        format!("DROP DATABASE {database} WITH (FORCE)"),
        format!("DROP ROLE {role}"),
    ] {
        sqlx::query(&sql).execute(&server).await.unwrap();
    }
    server.close().await;
}

/// A target table for the safe-write tests, with a protected `email` column.
async fn safe_table(f: &Fixture, target: &sqlx::PgPool) -> String {
    let table = format!("vda_safe_{}", Uuid::new_v4().simple());
    for sql in [
        format!("CREATE TABLE {table}(id integer PRIMARY KEY,email text,note text,n integer NOT NULL DEFAULT 0)"),
        format!("INSERT INTO {table}(id,email,note) VALUES (1,'ada@secret.example','first'),(2,'bob@secret.example','second'),(3,'cy@secret.example','third'),(4,'di@secret.example','fourth'),(5,'ed@secret.example','fifth')"),
    ] {
        sqlx::query(&sql).execute(target).await.unwrap();
    }
    let mut policy = Policy::for_environment("development");
    policy.masked_columns = vec!["email".into()];
    f.policy(&policy).await;
    table
}
async fn request_write(f: &Fixture, sql: &str) -> (StatusCode, Value) {
    f.request(
        "POST",
        "/approvals",
        &f.grantor_cookie,
        Some(json!({"cluster_id":f.cluster,"sql":sql,"reason":"Fix the notes"})),
    )
    .await
}
async fn note_and_n(target: &sqlx::PgPool, table: &str, id: i32) -> (String, i32) {
    sqlx::query_as(&format!("SELECT note,n FROM {table} WHERE id=$1"))
        .bind(id)
        .fetch_one(target)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_write_is_previewed_bound_to_its_effect_and_leaves_a_signed_receipt() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    let table = safe_table(&f, &target).await;
    // The preview shows the rows before and after, masks the protected
    // column, and changes nothing.
    let (s, v) = request_write(
        &f,
        &format!("UPDATE {table} SET note='fixed' WHERE id IN (1,2)"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let preview = &v["preview"];
    assert_eq!(preview["supported"], true, "{v}");
    assert_eq!(preview["affected_rows"], 2);
    assert_eq!(preview["bound_to"], "rows");
    assert_eq!(preview["before"]["total"], 2);
    assert!(preview["before"]["hidden"]
        .as_array()
        .unwrap()
        .contains(&json!("email")));
    let note = preview["after"]["columns"]
        .as_array()
        .unwrap()
        .iter()
        .position(|c| c == "note")
        .unwrap();
    assert_eq!(preview["after"]["rows"][0][note], "fixed", "{v}");
    let text = v.to_string();
    assert!(!text.contains("secret.example"), "{text}");
    assert!(
        !text.contains("fingerprint") && !text.contains("binding"),
        "{text}"
    );
    assert_eq!(note_and_n(&target, &table, 1).await.0, "first");
    // A new value made from a protected column is hidden too.
    let (s, v) = request_write(&f, &format!("UPDATE {table} SET note=email WHERE id=3")).await;
    if s == StatusCode::OK {
        assert!(
            v["preview"]["after"]["hidden"]
                .as_array()
                .unwrap()
                .contains(&json!("note")),
            "{v}"
        );
        assert!(!v.to_string().contains("secret.example"), "{v}");
    } else {
        assert_eq!(v["error"]["code"], "query_denied", "{v}");
    }
    // A read needs no approval, and a write that fails in the dry run is not stored.
    let (s, _) = request_write(&f, &format!("SELECT id FROM {table}")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM approvals")
        .fetch_one(&f.db)
        .await
        .unwrap();
    let (s, v) = request_write(
        &f,
        &format!("UPDATE {table} SET no_such_column=1 WHERE id=1"),
    )
    .await;
    assert!(s.is_client_error() || s.is_server_error(), "{v}");
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM approvals")
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(before, after);
    // The requester cannot approve; a rejection cannot run.
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.grantor_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{id}/reject"),
            &f.admin_cookie,
            Some(json!({"note":"no","run":true})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Approve and run in one step; the receipt is signed and checks out.
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.admin_cookie,
            Some(json!({"note":"ok","run":true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "executed", "{v}");
    assert_eq!(v["result"]["affected_rows"], 2);
    assert_eq!(note_and_n(&target, &table, 2).await.0, "fixed");
    let receipt = &v["receipt"];
    assert_eq!(receipt["approved_by"]["email"], "admin@harden.example");
    assert_eq!(receipt["executed_by"]["email"], "admin@harden.example");
    assert_eq!(receipt["requested_by"]["email"], "grantor@harden.example");
    assert_eq!(receipt["affected_rows"], 2);
    assert_eq!(receipt["previewed_rows"], 2);
    assert_eq!(receipt["bound_to"], "rows");
    let (s, v) = f
        .request(
            "GET",
            &format!("/approvals/{id}/receipt"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["valid"], true, "{v}");
    let (s, _) = f
        .request(
            "GET",
            &format!("/approvals/{id}/receipt"),
            &Fixture::session(&f.db, f.recipient).await,
            None,
        )
        .await;
    assert_ne!(s, StatusCode::OK);
    sqlx::query("UPDATE approvals SET receipt=jsonb_set(receipt,'{sql}','\"DELETE FROM x\"') WHERE id=$1::uuid")
        .bind(&id)
        .execute(&f.db)
        .await
        .unwrap();
    let (_, v) = f
        .request(
            "GET",
            &format!("/approvals/{id}/receipt"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(v["valid"], false, "{v}");
    // Bound to the rows: a change to a target row after approval stops the write.
    let (s, v) = request_write(&f, &format!("UPDATE {table} SET n=n+1 WHERE id=3")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let bound = v["id"].as_str().unwrap().to_owned();
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{bound}/approve"),
            &f.admin_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    sqlx::query(&format!(
        "UPDATE {table} SET note='changed meanwhile' WHERE id=3"
    ))
    .execute(&target)
    .await
    .unwrap();
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{bound}/execute"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"]["code"], "effect_changed", "{v}");
    assert_eq!(note_and_n(&target, &table, 3).await.1, 0);
    let (_, v) = f
        .request("GET", &format!("/approvals/{bound}"), &f.admin_cookie, None)
        .await;
    assert_eq!(v["status"], "failed");
    assert_eq!(v["receipt"], Value::Null);
    // Bound to the count only: other columns may change, the count may not.
    let (s, v) = request_write(
        &f,
        &format!("UPDATE ONLY {table} SET n=7 WHERE id IN (4,5)"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["preview"]["bound_to"], "count", "{v}");
    let counted = v["id"].as_str().unwrap().to_owned();
    let (s, v) = request_write(
        &f,
        &format!("UPDATE ONLY {table} SET n=8 WHERE id IN (4,5)"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let shrunk = v["id"].as_str().unwrap().to_owned();
    for id in [&counted, &shrunk] {
        let (s, _) = f
            .request(
                "POST",
                &format!("/approvals/{id}/approve"),
                &f.admin_cookie,
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
    }
    sqlx::query(&format!("UPDATE {table} SET note='other' WHERE id=4"))
        .execute(&target)
        .await
        .unwrap();
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{counted}/execute"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["receipt"]["bound_to"], "count");
    sqlx::query(&format!("DELETE FROM {table} WHERE id=5"))
        .execute(&target)
        .await
        .unwrap();
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{shrunk}/execute"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(note_and_n(&target, &table, 4).await.1, 7);
    // Withdraw: only the requester, only before it runs.
    let (s, v) = request_write(&f, &format!("DELETE FROM {table} WHERE id=1")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["preview"]["before"]["total"], 1, "{v}");
    let gone = v["id"].as_str().unwrap().to_owned();
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{gone}/withdraw"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{gone}/withdraw"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "withdrawn");
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{gone}/approve"),
            &f.admin_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{gone}/withdraw"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (_, v) = f
        .request("GET", "/approvals?status=withdrawn", &f.admin_cookie, None)
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["items"][0]["preview"], Value::Null);
    assert!(sqlx::query_scalar::<_, bool>(&format!(
        "SELECT EXISTS(SELECT 1 FROM {table} WHERE id=1)"
    ))
    .fetch_one(&target)
    .await
    .unwrap());
    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&target)
        .await
        .unwrap();
    target.close().await;
    f.close().await;
}

#[tokio::test]
async fn an_agent_proposes_a_write_sees_no_rows_and_a_person_decides() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    let table = safe_table(&f, &target).await;
    let agent = new_agent(&f, &f.grantor_cookie, "Fixer", "write").await;
    let (_, token) = new_token(&f, &f.grantor_cookie, agent).await;
    let other = new_agent(&f, &f.grantor_cookie, "Other", "write").await;
    let (_, other_token) = new_token(&f, &f.grantor_cookie, other).await;
    let reader = new_agent(&f, &f.grantor_cookie, "Reader", "read").await;
    let (_, reader_token) = new_token(&f, &f.grantor_cookie, reader).await;
    let db = json!(f.cluster);
    let sql = format!("UPDATE {table} SET note='agent fix' WHERE id=2");
    // run_query refuses a write and points at propose_write.
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Fix note 2","database":db,"sql":sql}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "approval_required", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "propose_write", "{v}");
    // The proposal: nothing runs, no counts, no rows, no protected values.
    let (failed, v) = tool(
        &f,
        &token,
        "propose_write",
        json!({"task":"Fix note 2 for ticket 7","database":db,"sql":sql}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["status"], "pending");
    assert_eq!(v["previewed"], false);
    let text = v.to_string();
    for word in [
        "secret.example",
        "before",
        "after",
        "\"rows\":[",
        "affected_rows",
    ] {
        assert!(!text.contains(word), "{word}: {text}");
    }
    assert_eq!(note_and_n(&target, &table, 2).await.0, "second");
    let id = v["approval_id"].as_str().unwrap().to_owned();
    // People see who asked; the owner is the requester.
    let (_, v) = f
        .request("GET", &format!("/approvals/{id}"), &f.admin_cookie, None)
        .await;
    assert_eq!(v["agent"]["name"], "Fixer", "{v}");
    assert_eq!(v["requester"]["email"], "grantor@harden.example");
    assert_eq!(v["reason"], "Fix note 2 for ticket 7");
    // Only this agent can read or withdraw its request.
    for (token, id) in [
        (&other_token, id.clone()),
        (&token, Uuid::new_v4().to_string()),
    ] {
        let (failed, v) = tool(
            &f,
            token,
            "get_approval",
            json!({"task":"Check","approval_id":id}),
        )
        .await;
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "approval_not_found", "{v}");
        assert_eq!(v["error"]["fix"]["action"], "fix_arguments", "{v}");
        let (failed, v) = tool(
            &f,
            token,
            "withdraw",
            json!({"task":"Stop","approval_id":id}),
        )
        .await;
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "approval_not_found", "{v}");
    }
    // A read-only agent cannot propose a write. It can reach the database,
    // so it is told to ask its owner, not to pick another database.
    let (failed, v) = tool(
        &f,
        &reader_token,
        "propose_write",
        json!({"task":"Try","database":db,"sql":sql}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "insufficient_access", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "ask_owner", "{v}");
    // A database it cannot reach at all keeps its own answer.
    let (failed, v) = tool(
        &f,
        &reader_token,
        "propose_write",
        json!({"task":"Try","database":Uuid::new_v4(),"sql":sql}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["fix"]["action"], "choose_database", "{v}");
    // The owner cannot approve the agent's request; another admin can, after
    // a person has previewed it. The preview runs once.
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.grantor_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.admin_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let other_cookie = Fixture::session(&f.db, f.recipient).await;
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{id}/preview"),
            &other_cookie,
            None,
        )
        .await;
    assert_ne!(s, StatusCode::OK);
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/preview"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["preview"]["affected_rows"], 1, "{v}");
    assert_eq!(v["preview"]["bound_to"], "rows", "{v}");
    assert!(!v.to_string().contains("secret.example"), "{v}");
    assert_eq!(note_and_n(&target, &table, 2).await.0, "second");
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{id}/preview"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (failed, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Check","approval_id":id}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["previewed"], true);
    assert!(v.get("affected_rows").is_none(), "{v}");
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.admin_cookie,
            Some(json!({"note":"fine"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (failed, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Check","approval_id":id}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["status"], "approved");
    assert_eq!(v["review_note"], "fine");
    // A paused agent's request does not run.
    let (s, _) = f
        .request(
            "PATCH",
            &format!("/agents/{agent}"),
            &f.grantor_cookie,
            Some(json!({"paused":true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/execute"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(note_and_n(&target, &table, 2).await.0, "second");
    let (s, _) = f
        .request(
            "PATCH",
            &format!("/agents/{agent}"),
            &f.grantor_cookie,
            Some(json!({"paused":false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/execute"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["receipt"]["agent"]["name"], "Fixer");
    assert_eq!(note_and_n(&target, &table, 2).await.0, "agent fix");
    let (failed, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Check","approval_id":id}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["status"], "executed");
    assert_eq!(v["executed_rows"], 1);
    // The agent withdraws a request it no longer needs; twice is a conflict.
    let (_, v) = tool(&f, &token, "propose_write", json!({"task":"Clear note 3","database":db,"sql":format!("UPDATE {table} SET note=NULL WHERE id=3")})).await;
    let second = v["approval_id"].as_str().unwrap().to_owned();
    let (failed, v) = tool(
        &f,
        &token,
        "withdraw",
        json!({"task":"Not needed","approval_id":second}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["status"], "withdrawn");
    let (failed, v) = tool(
        &f,
        &token,
        "withdraw",
        json!({"task":"Not needed","approval_id":second}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["fix"]["action"], "stop", "{v}");
    // An agent may have only a few requests waiting.
    for _ in 0..10 {
        sqlx::query("INSERT INTO approvals(id,cluster_id,requester_id,sql,reason,analysis,status,agent_id,agent_name)
            VALUES ($1,$2,$3,'UPDATE x SET y=1 WHERE id=1','Test','{}','pending',$4,'Fixer')")
            .bind(Uuid::new_v4()).bind(f.cluster).bind(f.grantor).bind(agent)
            .execute(&f.db).await.unwrap();
    }
    let (failed, v) = tool(
        &f,
        &token,
        "propose_write",
        json!({"task":"One more","database":db,"sql":sql}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "too_many_open_requests", "{v}");
    // The refusal lists the open requests, so the agent can find their ids.
    let open = v["error"]["details"]["requests"].as_array().unwrap();
    assert_eq!(open.len(), 10, "{v}");
    assert!(open
        .iter()
        .all(|r| r["task"] == "Test" && r["status"] == "pending"));
    // Deleting the agent keeps its name on the request.
    let (s, _) = f
        .request(
            "DELETE",
            &format!("/agents/{agent}"),
            &f.grantor_cookie,
            None,
        )
        .await;
    assert!(s.is_success());
    let (_, v) = f
        .request("GET", &format!("/approvals/{id}"), &f.admin_cookie, None)
        .await;
    assert_eq!(v["agent"]["name"], "Fixer", "{v}");
    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&target)
        .await
        .unwrap();
    target.close().await;
    f.close().await;
}

#[tokio::test]
async fn an_agent_that_follows_the_write_fix_is_not_stopped_and_reads_a_coded_outcome() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    let table = safe_table(&f, &target).await;
    let agent = new_agent(&f, &f.grantor_cookie, "Follower", "write").await;
    let (_, token) = new_token(&f, &f.grantor_cookie, agent).await;
    let other = new_agent(&f, &f.grantor_cookie, "Neighbour", "write").await;
    let (_, other_token) = new_token(&f, &f.grantor_cookie, other).await;
    let db = json!(f.cluster);
    // run_query refuses each write and points at propose_write. An agent that
    // does what the fix says, six times, is never stopped for it.
    let mut ids = Vec::new();
    for round in 1..=6 {
        let sql = format!("UPDATE {table} SET n={round} WHERE id={}", round % 5 + 1);
        let (failed, v) = tool(
            &f,
            &token,
            "run_query",
            json!({"task":"Bump a counter","database":db,"sql":sql}),
        )
        .await;
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "approval_required", "{round}: {v}");
        assert_eq!(v["error"]["fix"]["action"], "propose_write", "{v}");
        let (failed, v) = tool(
            &f,
            &token,
            "propose_write",
            json!({"task":format!("Bump counter, round {round}"),"database":db,"sql":sql}),
        )
        .await;
        assert!(!failed, "{round}: {v}");
        ids.push(v["approval_id"].as_str().unwrap().to_owned());
    }
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read the counters","database":db,"sql":format!("SELECT id,n FROM {table}")}),
    )
    .await;
    assert!(!failed, "{v}");
    // Without an id, get_approval lists the agent's own open requests, newest
    // first; another agent's requests are not in it.
    let (failed, v) = tool(
        &f,
        &other_token,
        "propose_write",
        json!({"task":"Neighbour's write","database":db,
            "sql":format!("UPDATE {table} SET note='n' WHERE id=1")}),
    )
    .await;
    assert!(!failed, "{v}");
    let neighbour = v["approval_id"].as_str().unwrap().to_owned();
    let (failed, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Find my requests"}),
    )
    .await;
    assert!(!failed, "{v}");
    let listed: Vec<&str> = v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["approval_id"].as_str().unwrap())
        .collect();
    let newest_first: Vec<&str> = ids.iter().rev().map(String::as_str).collect();
    assert_eq!(listed, newest_first, "{v}");
    assert_eq!(v["requests"][0]["task"], "Bump counter, round 6", "{v}");
    assert_eq!(v["requests"][0]["status"], "pending", "{v}");
    assert!(v["requests"][0]["expires_at"].is_string(), "{v}");
    assert_eq!(v["requests"][0]["database"], db, "{v}");
    assert!(!v.to_string().contains(&neighbour), "{v}");
    let (_, v) = tool(&f, &other_token, "get_approval", json!({"task":"Mine"})).await;
    assert_eq!(v["requests"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["requests"][0]["approval_id"], json!(neighbour), "{v}");
    // A write whose effect changed after the approval fails. People see why;
    // the agent sees a code, a fix and a fixed sentence without the counts.
    let id = ids[0].clone();
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/preview"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["preview"]["affected_rows"], 1, "{v}");
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.admin_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // As if the dry run had counted seven rows: the write changes one.
    sqlx::query(
        "UPDATE approvals SET binding=jsonb_set(binding,'{affected_rows}','7') WHERE id=$1::uuid",
    )
    .bind(&id)
    .execute(&f.db)
    .await
    .unwrap();
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/execute"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"]["code"], "effect_changed", "{v}");
    assert_eq!(note_and_n(&target, &table, 2).await.1, 0);
    let (_, v) = f
        .request("GET", &format!("/approvals/{id}"), &f.admin_cookie, None)
        .await;
    assert_eq!(v["status"], "failed", "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("it changes 1 rows, and 7 were approved"),
        "{v}"
    );
    let (failed, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Check","approval_id":id}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["status"], "failed", "{v}");
    assert_eq!(v["error_code"], "effect_changed", "{v}");
    assert_eq!(v["fix"]["action"], "propose_write", "{v}");
    let error = v["error"].as_str().unwrap();
    assert_eq!(
        error,
        "The data changed after the approval, so the write was not run."
    );
    assert!(!error.chars().any(|c| c.is_ascii_digit()), "{v}");
    assert!(!v.to_string().contains("were approved"), "{v}");
    // Any other failure reads as `write_failed` with the generic sentence;
    // the stored code stays for people.
    sqlx::query("UPDATE approvals SET status='failed',error='it changes 3 rows',error_code='upstream' WHERE id=$1::uuid")
        .bind(&ids[1])
        .execute(&f.db)
        .await
        .unwrap();
    let (_, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Check","approval_id":ids[1]}),
    )
    .await;
    assert_eq!(v["error_code"], "write_failed", "{v}");
    let stored: Option<String> =
        sqlx::query_scalar("SELECT error_code FROM approvals WHERE id=$1::uuid")
            .bind(&ids[1])
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(stored.as_deref(), Some("upstream"));
    assert_eq!(
        v["error"], "The write failed when it ran. Your owner can see why.",
        "{v}"
    );
    // Whatever the code, a failed write sends the agent to its owner: never
    // to retry, to another database, or to rewrite the SQL.
    assert_eq!(v["fix"]["action"], "ask_owner", "{v}");
    assert!(v["fix"].get("retry_after_seconds").is_none(), "{v}");
    // A lost node: nobody knows whether the write ran, so it does not say it
    // failed. An old failed row without a code reads as `write_failed`.
    for (id, stored, code, action, error) in [
        (
            &ids[3],
            Some("outcome_unknown"),
            "outcome_unknown",
            "stop",
            "Nobody knows whether the write ran. Your owner can see more.",
        ),
        (
            &ids[4],
            None,
            "write_failed",
            "ask_owner",
            "The write failed when it ran. Your owner can see why.",
        ),
    ] {
        sqlx::query(
            "UPDATE approvals SET status='failed',error='lost',error_code=$2 WHERE id=$1::uuid",
        )
        .bind(id)
        .bind(stored)
        .execute(&f.db)
        .await
        .unwrap();
        let (_, v) = tool(
            &f,
            &token,
            "get_approval",
            json!({"task":"Check","approval_id":id}),
        )
        .await;
        assert_eq!(v["error_code"], code, "{v}");
        assert_eq!(v["error"], error, "{v}");
        assert_eq!(v["fix"]["action"], action, "{v}");
    }
    // A request that has not failed has no fix.
    let (_, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Check","approval_id":ids[2]}),
    )
    .await;
    assert_eq!(v["error_code"], Value::Null, "{v}");
    assert!(v.get("fix").is_none(), "{v}");
    // The list holds only open requests: the failed ones are gone.
    let (_, v) = tool(
        &f,
        &token,
        "get_approval",
        json!({"task":"Find my requests"}),
    )
    .await;
    assert_eq!(v["requests"].as_array().unwrap().len(), 2, "{v}");
    // A task of the full 500 characters is accepted: the read check keeps its
    // own record of the task within the limit.
    let long = "Bump the counter for the weekly report. ".repeat(13);
    let long: String = long.chars().take(500).collect();
    assert_eq!(long.chars().count(), 500);
    let (failed, v) = tool(
        &f,
        &token,
        "propose_write",
        json!({"task":long,"database":db,"sql":format!("UPDATE {table} SET n=9 WHERE id=4")}),
    )
    .await;
    assert!(!failed, "{v}");
    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&target)
        .await
        .unwrap();
    target.close().await;
    f.close().await;
}

#[tokio::test]
async fn a_mysql_write_request_says_it_has_no_preview() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    sqlx::query("UPDATE clusters SET engine='mysql' WHERE id=$1")
        .bind(f.cluster)
        .execute(&f.db)
        .await
        .unwrap();
    let (s, v) = request_write(&f, "UPDATE t SET a=1 WHERE id=1").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["preview"]["supported"], false, "{v}");
    assert!(v["preview"]["reason"].as_str().unwrap().contains("MySQL"));
    let binding: Option<Value> =
        sqlx::query_scalar("SELECT binding FROM approvals WHERE id=$1::uuid")
            .bind(v["id"].as_str().unwrap())
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(binding, None);
    f.close().await;
}

#[tokio::test]
async fn the_attacks_found_on_safe_writes_stay_closed() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    let table = safe_table(&f, &target).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (link, seq, func) = (
        format!("vda_link_{suffix}"),
        format!("vda_seq_{suffix}"),
        format!("vda_fn_{suffix}"),
    );
    for sql in [
        format!("CREATE TABLE {link}(tid integer)"),
        format!("INSERT INTO {link} VALUES (1)"),
        format!("CREATE SEQUENCE {seq}"),
        format!("CREATE FUNCTION {func}() RETURNS integer LANGUAGE sql AS 'SELECT setval(''{seq}'', 5000)::integer'"),
    ] {
        sqlx::query(&sql).execute(&target).await.unwrap();
    }
    // A whole-row reference does not show the protected value in the preview.
    for value in [
        format!("{table}::text"),
        format!("concat({table}.*)"),
        format!("({table}.*)::text"),
        format!("json_build_array({table}.*)::text"),
    ] {
        let (s, v) =
            request_write(&f, &format!("UPDATE {table} SET note = {value} WHERE id=1")).await;
        if s == StatusCode::OK {
            assert!(!v.to_string().contains("secret.example"), "{value}: {v}");
        }
    }
    // A write through a view is previewed by its count, and runs.
    let view = format!("vda_view_{suffix}");
    sqlx::query(&format!(
        "CREATE VIEW {view} AS SELECT id,note FROM {table}"
    ))
    .execute(&target)
    .await
    .unwrap();
    let (s, v) = request_write(&f, &format!("UPDATE {view} SET note='via view' WHERE id=5")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["preview"]["bound_to"], "count", "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.admin_cookie,
            Some(json!({"run":true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(note_and_n(&target, &table, 5).await.0, "via view");
    sqlx::query(&format!("DROP VIEW {view}"))
        .execute(&target)
        .await
        .unwrap();
    // A write hidden in WITH is refused.
    let (s, v) = request_write(
        &f,
        &format!("WITH d AS (DELETE FROM {table} WHERE id=5 RETURNING id) UPDATE {table} SET note='x' WHERE id=1"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["code"], "unsupported_write", "{v}");
    // A row that joins the target set after the check is not written.
    let (s, v) = request_write(
        &f,
        &format!("UPDATE {table} SET note='hit' WHERE id IN (SELECT tid FROM {link})"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["preview"]["bound_to"], "rows", "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let (s, _) = f
        .request(
            "POST",
            &format!("/approvals/{id}/approve"),
            &f.admin_cookie,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let mut other = target.begin().await.unwrap();
    sqlx::query(&format!("UPDATE {table} SET note=note WHERE id=1"))
        .execute(&mut *other)
        .await
        .unwrap();
    sqlx::query(&format!("UPDATE {link} SET tid=2"))
        .execute(&mut *other)
        .await
        .unwrap();
    let app = f.app.clone();
    let cookie = f.admin_cookie.clone();
    let run = tokio::spawn(async move {
        call(
            &app,
            "POST",
            &format!("/api/v1/approvals/{id}/execute"),
            &cookie,
            None,
            None,
            "127.0.0.1:1234",
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    other.commit().await.unwrap();
    let (s, v) = run.await.unwrap();
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"]["code"], "effect_changed", "{v}");
    assert_eq!(note_and_n(&target, &table, 2).await.0, "second");
    // A receipt copied from another request is not valid on this one.
    let mut executed = Vec::new();
    for sql in [
        format!("UPDATE {table} SET n=1 WHERE id=3"),
        format!("DELETE FROM {table} WHERE id=4"),
    ] {
        let (s, v) = request_write(&f, &sql).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let id = v["id"].as_str().unwrap().to_owned();
        let (s, v) = f
            .request(
                "POST",
                &format!("/approvals/{id}/approve"),
                &f.admin_cookie,
                Some(json!({"run":true})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        executed.push(id);
    }
    sqlx::query("UPDATE approvals SET receipt=(SELECT receipt FROM approvals WHERE id=$1::uuid) WHERE id=$2::uuid")
        .bind(&executed[0])
        .bind(&executed[1])
        .execute(&f.db)
        .await
        .unwrap();
    let (_, v) = f
        .request(
            "GET",
            &format!("/approvals/{}/receipt", executed[1]),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(v["valid"], false, "{v}");
    let (_, v) = f
        .request(
            "GET",
            &format!("/approvals/{}/receipt", executed[0]),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(v["valid"], true, "{v}");
    assert_eq!(v["signed_with_current_key"], true, "{v}");
    // An agent's write is first checked as a read, in a read-only transaction:
    // a protected value in its condition or a function with side effects stops
    // it before anything runs.
    let agent = new_agent(&f, &f.grantor_cookie, "Prober", "write").await;
    let (_, token) = new_token(&f, &f.grantor_cookie, agent).await;
    let db = json!(f.cluster);
    let before: i64 = sqlx::query_scalar(&format!("SELECT last_value FROM {seq}"))
        .fetch_one(&target)
        .await
        .unwrap();
    // SQL that acts only when it is not in a read-only transaction passes the
    // read check, but nothing of an agent's runs before a person previews it.
    let (failed, v) = tool(&f, &token, "propose_write", json!({"task":"Probe","database":db,
        "sql":format!("UPDATE {table} SET n = CASE WHEN current_setting('transaction_read_only')='off' THEN {func}() ELSE n END WHERE id=1")})).await;
    assert!(!failed, "{v}");
    assert_eq!(v["previewed"], false, "{v}");
    assert!(v.get("affected_rows").is_none(), "{v}");
    let probe = v["approval_id"].as_str().unwrap().to_owned();
    // A person's preview of it is refused too: it calls a function defined in
    // the database. A paused agent's request cannot be previewed at all.
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{probe}/preview"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"]["message"].as_str().unwrap().contains(&func),
        "{v}"
    );
    let (s, _) = f
        .request(
            "PATCH",
            &format!("/agents/{agent}"),
            &f.grantor_cookie,
            Some(json!({"paused":true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{probe}/preview"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _) = f
        .request(
            "PATCH",
            &format!("/agents/{agent}"),
            &f.grantor_cookie,
            Some(json!({"paused":false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (failed, v) = tool(
        &f,
        &token,
        "withdraw",
        json!({"task":"Done","approval_id":probe}),
    )
    .await;
    assert!(!failed, "{v}");
    // The database itself says which functions a statement calls: through
    // attribute notation, a view, or a name with a dot in it.
    let (attr, view, dotted) = (
        format!("vda_attr_{suffix}"),
        format!("vda_calls_{suffix}"),
        format!("\"vda.dot_{suffix}\""),
    );
    for sql in [
        format!("CREATE FUNCTION {attr}({table}) RETURNS integer LANGUAGE sql AS 'SELECT setval(''{seq}'', 6000)::integer'"),
        format!("CREATE VIEW {view} AS SELECT {func}() AS x"),
        format!("CREATE FUNCTION {dotted}() RETURNS integer LANGUAGE sql AS 'SELECT setval(''{seq}'', 7000)::integer'"),
    ] {
        sqlx::query(&sql).execute(&target).await.unwrap();
    }
    let branch = "current_setting('transaction_read_only')='off'";
    for value in [
        format!("x.{attr}"),
        format!("(SELECT v.x FROM {view} v)"),
        format!("public.{dotted}()"),
    ] {
        let sql = format!(
            "UPDATE {table} x SET n = CASE WHEN {branch} THEN {value} ELSE n END WHERE id=1"
        );
        let (failed, v) = tool(
            &f,
            &token,
            "propose_write",
            json!({"task":"Probe","database":db,"sql":sql}),
        )
        .await;
        assert!(!failed, "{value}: {v}");
        let probe = v["approval_id"].as_str().unwrap().to_owned();
        let (s, v) = f
            .request(
                "POST",
                &format!("/approvals/{probe}/preview"),
                &f.admin_cookie,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{value}: {v}");
        tool(
            &f,
            &token,
            "withdraw",
            json!({"task":"Done","approval_id":probe}),
        )
        .await;
    }
    for sql in [
        format!("DROP VIEW {view}"),
        format!("DROP FUNCTION {attr}({table})"),
        format!("DROP FUNCTION {dotted}()"),
    ] {
        sqlx::query(&sql).execute(&target).await.unwrap();
    }
    // A cast into a written column's type can call a database function too.
    let (ty, cast_fn) = (format!("vda_ty_{suffix}"), format!("vda_cast_{suffix}"));
    for sql in [
        format!("CREATE TYPE {ty} AS (a integer)"),
        format!("CREATE FUNCTION {cast_fn}(text) RETURNS {ty} LANGUAGE sql AS 'SELECT ROW(setval(''{seq}'', 8000)::integer)::{ty}'"),
        format!("CREATE CAST (text AS {ty}) WITH FUNCTION {cast_fn}(text) AS ASSIGNMENT"),
        format!("ALTER TABLE {table} ADD COLUMN p {ty}"),
    ] {
        sqlx::query(&sql).execute(&target).await.unwrap();
    }
    let (failed, v) = tool(
        &f,
        &token,
        "propose_write",
        json!({"task":"Probe","database":db,
        "sql":format!("UPDATE {table} SET p = note WHERE id=1")}),
    )
    .await;
    assert!(!failed, "{v}");
    let probe = v["approval_id"].as_str().unwrap().to_owned();
    let (s, v) = f
        .request(
            "POST",
            &format!("/approvals/{probe}/preview"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"]["message"].as_str().unwrap().contains(&cast_fn),
        "{v}"
    );
    tool(
        &f,
        &token,
        "withdraw",
        json!({"task":"Done","approval_id":probe}),
    )
    .await;
    for sql in [
        format!("ALTER TABLE {table} DROP COLUMN p"),
        format!("DROP CAST (text AS {ty})"),
        format!("DROP FUNCTION {cast_fn}(text)"),
        format!("DROP TYPE {ty}"),
    ] {
        sqlx::query(&sql).execute(&target).await.unwrap();
    }
    let after: i64 = sqlx::query_scalar(&format!("SELECT last_value FROM {seq}"))
        .fetch_one(&target)
        .await
        .unwrap();
    assert_eq!(before, after, "a preview ran a database function");
    for (sql, word) in [
        (format!("UPDATE {table} SET note=note WHERE id=1 AND (SELECT email FROM {table} WHERE id=2)::integer=1"), "email"),
        (format!("UPDATE {table} SET n={func}() WHERE id=1"), "function"),
        (format!("UPDATE ONLY {table} SET n=1 WHERE id=1"), "only"),
    ] {
        let (failed, v) = tool(&f, &token, "propose_write", json!({"task":"Probe","database":db,"sql":sql})).await;
        assert!(failed, "{word}: {v}");
        assert!(!v.to_string().contains("secret.example"), "{word}: {v}");
    }
    let after: i64 = sqlx::query_scalar(&format!("SELECT last_value FROM {seq}"))
        .fetch_one(&target)
        .await
        .unwrap();
    assert_eq!(before, after, "the function ran");
    // RETURNING is refused for agents; a failed dry run shows no database text.
    let (failed, v) = tool(
        &f,
        &token,
        "propose_write",
        json!({"task":"Probe","database":db,
        "sql":format!("DELETE FROM {table} WHERE id=2 RETURNING email")}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "unsupported_write", "{v}");
    // A successful read does not reset the streak of refused proposals.
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read","database":db,
        "sql":format!("SELECT id FROM {table}")}),
    )
    .await;
    assert!(!failed, "{v}");
    let (failed, v) = tool(
        &f,
        &token,
        "propose_write",
        json!({"task":"Probe","database":db,"sql":"UPDATE nope SET a=1 WHERE id=1"}),
    )
    .await;
    assert!(failed, "{v}");
    let (failed, v) = tool(
        &f,
        &token,
        "propose_write",
        json!({"task":"Probe","database":db,"sql":format!("UPDATE {table} SET n=2 WHERE id=1")}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "too_many_denials", "{v}");
    for sql in [
        format!("DROP TABLE {table}"),
        format!("DROP TABLE {link}"),
        format!("DROP FUNCTION {func}()"),
        format!("DROP SEQUENCE {seq}"),
    ] {
        sqlx::query(&sql).execute(&target).await.unwrap();
    }
    target.close().await;
    f.close().await;
}
