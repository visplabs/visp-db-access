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
            "run_query"
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
