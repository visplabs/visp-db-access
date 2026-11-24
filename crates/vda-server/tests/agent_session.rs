#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Agent steps and sessions, `fetch_rows` and the pre-flight answer, against
//! a real PostgreSQL: the metadata store in a schema of its own, and a target
//! table that the tools read.
//!
//! The writer of steps is asynchronous, so a test waits until the steps it
//! expects are there and gives up after a minute. Nothing here sleeps to let
//! time pass: a session gap is made by writing steps with the times it
//! needs, and a held result is expired by sweeping with a later clock.
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use clap::Parser;
use futures::FutureExt;
use serde_json::{json, Value};
use std::panic::AssertUnwindSafe;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tower::ServiceExt;
use uuid::Uuid;
use vda_server::{
    app::{router, AppState},
    config::{Cli, Config},
    crypto::Crypto,
    held,
    policy::Policy,
    steps::{self, Step},
};

struct Fixture {
    db: sqlx::PgPool,
    root: sqlx::PgPool,
    schema: String,
    state: AppState,
    writers: Vec<tokio::task::JoinHandle<()>>,
    states: Vec<AppState>,
    app: Router,
    owner: Uuid,
    cluster: Uuid,
    admin_cookie: String,
    owner_cookie: String,
    other_cookie: String,
    reader_cookie: String,
    writer_cookie: String,
    target: sqlx::PgPool,
    table: String,
    vault: String,
}
impl Fixture {
    async fn new() -> Option<Self> {
        Self::with(|_| {}).await
    }
    async fn with(configure: impl FnOnce(&mut Config)) -> Option<Self> {
        let (Ok(url), Ok(target_url)) = (
            std::env::var("VISP_GATE_TEST_DATABASE_URL"),
            std::env::var("VISP_GATE_TEST_POSTGRES_URL"),
        ) else {
            eprintln!(
                "skipped: VISP_GATE_TEST_DATABASE_URL and VISP_GATE_TEST_POSTGRES_URL are not set"
            );
            return None;
        };
        let root = sqlx::PgPool::connect(&url).await.unwrap();
        let schema = format!("vda_steps_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&root)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema},public");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(60))
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
        configure(&mut config);
        let crypto = Crypto::new(&[4; 32]);
        let (state, writer) = AppState::new(db.clone(), config, crypto.clone(), None)
            .await
            .unwrap();
        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
        let (admin, owner, other, reader, writer_user) = (ids[0], ids[1], ids[2], ids[3], ids[4]);
        for (id, email, role) in [
            (admin, "admin@steps.example", "admin"),
            (owner, "owner@steps.example", "member"),
            (other, "other@steps.example", "member"),
            (reader, "reader@steps.example", "member"),
            (writer_user, "writer@steps.example", "member"),
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
        let (project, cluster) = (Uuid::new_v4(), Uuid::new_v4());
        sqlx::query("INSERT INTO projects(id,name) VALUES ($1,'Project')")
            .bind(project)
            .execute(&db)
            .await
            .unwrap();
        let target = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&target_url)
            .await
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
            .bind(crypto.encrypt(cluster, password).unwrap()).execute(&db).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let (table, vault) = (format!("vda_step_{suffix}"), format!("vda_vault_{suffix}"));
        for sql in [
            format!("CREATE TABLE {table}(id integer PRIMARY KEY,email text,note text NOT NULL)"),
            format!(
                "INSERT INTO {table} SELECT n,'person'||n||'@hidden.example','note-'||n
                 FROM generate_series(1,250) n"
            ),
            format!("CREATE TABLE {vault}(id integer,word text)"),
        ] {
            sqlx::query(&sql).execute(&target).await.unwrap();
        }
        let mut policy = Policy::for_environment("development");
        policy.masked_columns = vec!["email".into()];
        policy.blocked_tables = vec![vault.clone()];
        policy.max_rows = 120;
        sqlx::query("INSERT INTO cluster_policies(cluster_id,policy) VALUES ($1,$2)")
            .bind(cluster)
            .bind(json!(policy))
            .execute(&db)
            .await
            .unwrap();
        for (user, level) in [
            (owner, "admin"),
            (other, "admin"),
            (reader, "read"),
            (writer_user, "write"),
        ] {
            sqlx::query("INSERT INTO grants(id,user_id,scope,scope_id,level,expires_at) VALUES ($1,$2,'cluster',$3,$4,now()+interval '1 hour')")
                .bind(Uuid::new_v4()).bind(user).bind(cluster).bind(level).execute(&db).await.unwrap();
        }
        let app = router(state.clone());
        Some(Self {
            admin_cookie: session(&db, admin).await,
            owner_cookie: session(&db, owner).await,
            other_cookie: session(&db, other).await,
            reader_cookie: session(&db, reader).await,
            writer_cookie: session(&db, writer_user).await,
            db,
            root,
            schema,
            states: vec![state.clone()],
            state,
            writers: vec![writer],
            app,
            owner,
            cluster,
            target,
            table,
            vault,
        })
    }
    /// A second gateway node on the same metadata store.
    async fn node(&mut self) -> (AppState, Router) {
        let mut config = Cli::parse_from(["test"]).config;
        config.allow_private_targets = true;
        let (state, writer) = AppState::new(self.db.clone(), config, Crypto::new(&[4; 32]), None)
            .await
            .unwrap();
        self.writers.push(writer);
        self.states.push(state.clone());
        (state.clone(), router(state))
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(&self.app, method, path, cookie, body, None).await
    }
    async fn policy(&self, change: impl FnOnce(&mut Policy)) {
        let mut policy = Policy::for_environment("development");
        policy.masked_columns = vec!["email".into()];
        policy.blocked_tables = vec![self.vault.clone()];
        policy.max_rows = 120;
        change(&mut policy);
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
    async fn agent(&self, name: &str, level: &str) -> (Uuid, Uuid, String) {
        let (s, v) = self
            .request(
                "POST",
                "/agents",
                &self.owner_cookie,
                Some(json!({"name":name,"max_level":level,"cluster_ids":[self.cluster]})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let agent: Uuid = v["id"].as_str().unwrap().parse().unwrap();
        let (token_id, token) = self.token(agent).await;
        (agent, token_id, token)
    }
    async fn token(&self, agent: Uuid) -> (Uuid, String) {
        let (s, v) = self
            .request(
                "POST",
                &format!("/agents/{agent}/tokens"),
                &self.owner_cookie,
                Some(json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        (
            v["id"].as_str().unwrap().parse().unwrap(),
            v["token"].as_str().unwrap().to_owned(),
        )
    }
    /// Queries of an agent in query history: each one took from its budget.
    async fn queries(&self, agent: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM query_history WHERE agent_id=$1")
            .bind(agent)
            .fetch_one(&self.db)
            .await
            .unwrap()
    }
    /// Wait until the writer has written this many steps of an agent.
    async fn written(&self, agent: Uuid, steps: i64) {
        let mut found = 0;
        for _ in 0..1200 {
            found = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM agent_steps p JOIN agent_sessions s ON s.id=p.session_id
                 WHERE s.agent_id=$1",
            )
            .bind(agent)
            .fetch_one(&self.db)
            .await
            .unwrap();
            if found >= steps {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(found, steps, "steps written for the agent");
    }
    async fn sessions(&self, agent: Uuid) -> Vec<Value> {
        let (s, v) = self
            .request(
                "GET",
                &format!("/agents/{agent}/sessions"),
                &self.owner_cookie,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["items"].as_array().unwrap().clone()
    }
    async fn steps(&self, agent: Uuid, session: &Value, query: &str) -> Value {
        let (s, v) = self
            .request(
                "GET",
                &format!(
                    "/agents/{agent}/sessions/{}/steps{query}",
                    session["id"].as_str().unwrap()
                ),
                &self.owner_cookie,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v
    }
    async fn close(self) {
        for state in &self.states {
            state.core.tasks.close();
            state.core.tasks.wait().await;
            state.stop.cancel();
        }
        for writer in self.writers {
            writer.await.unwrap();
        }
        for state in &self.states {
            state.steps.finish().await;
            state.core.pools.close().await;
        }
        for name in [&self.table, &self.vault] {
            sqlx::query(&format!("DROP TABLE IF EXISTS {name}"))
                .execute(&self.target)
                .await
                .unwrap();
        }
        self.target.close().await;
        self.db.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.root)
            .await
            .unwrap();
        self.root.close().await;
    }
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
    sqlx::query(
        "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES ($1,$2,now()+interval '1 hour')",
    )
    .bind(vda_server::auth::token_hash(&token))
    .bind(user)
    .execute(db)
    .await
    .unwrap();
    format!("vda_session={token}")
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(format!("/api/v1{path}"))
        .header("x-requested-with", "vda");
    if !cookie.is_empty() {
        req = req.header("cookie", cookie);
    }
    if let Some(bearer) = bearer {
        req = req.header("authorization", format!("Bearer {bearer}"));
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
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 40 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}
/// Call a tool at the agent door of one node: (is_error, structured content).
async fn tool_at(app: &Router, token: &str, name: &str, arguments: Value) -> (bool, Value) {
    let body = json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
        "params":{"name":name,"arguments":arguments}});
    let mut req = Request::post("/api/v1/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 40 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    let result = &v["result"];
    (
        result["isError"].as_bool().unwrap_or_else(|| panic!("{v}")),
        result["structuredContent"].clone(),
    )
}
async fn tool(f: &Fixture, token: &str, name: &str, arguments: Value) -> (bool, Value) {
    tool_at(&f.app, token, name, arguments).await
}
/// A refusal with the one stable code for rows that are not held.
fn assert_expired(answer: &(bool, Value)) {
    let (failed, v) = answer;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "result_expired", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "rewrite_sql", "{v}");
    let hint = v["error"]["fix"]["hint"].as_str().unwrap();
    assert!(
        hint.contains("run_query") && hint.contains("narrower"),
        "{hint}"
    );
}
fn ids(rows: &Value) -> Vec<i64> {
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| row[0].as_i64().unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_tool_call_is_a_step_of_a_session_and_refusals_are_bounded() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (agent, _, token) = f.agent("Analyst", "write").await;
    let db = json!(f.cluster);
    let table = &f.table;
    let read = format!("SELECT id,note FROM {table} WHERE id<=3 ORDER BY id");
    let write = format!("UPDATE {table} SET note='changed' WHERE id=1");
    let blocked = format!("SELECT * FROM {}", f.vault);
    let calls: Vec<(&str, Value, &str)> = vec![
        (
            "list_databases",
            json!({"task":"See what I can reach"}),
            "ok",
        ),
        (
            "search_schema",
            json!({"task":"Find the table","database":db,"query":"vda_step"}),
            "ok",
        ),
        (
            "describe_table",
            json!({"task":"Learn the columns","database":db,"table":table}),
            "ok",
        ),
        (
            "describe_table",
            json!({"task":"Look for another","database":db,"table":"no_such_table"}),
            "table_not_found",
        ),
        (
            "check_sql",
            json!({"task":"Check the read","database":db,"sql":read}),
            "ok",
        ),
        (
            "check_sql",
            json!({"task":"Check the vault","database":db,"sql":blocked}),
            "ok",
        ),
        (
            "run_query",
            json!({"task":"Read three notes","database":db,"sql":read}),
            "ok",
        ),
        (
            "run_query",
            json!({"task":"Read the vault","database":db,"sql":blocked}),
            "query_denied",
        ),
        (
            "run_query",
            json!({"task":"Change a note","database":db,"sql":write}),
            "approval_required",
        ),
        (
            "propose_write",
            json!({"task":"Fix note 1","database":db,"sql":write}),
            "ok",
        ),
    ];
    let mut approval = Value::Null;
    for (name, arguments, outcome) in &calls {
        let (failed, v) = tool(&f, &token, name, arguments.clone()).await;
        assert_eq!(failed, *outcome != "ok", "{name} {v}");
        if failed {
            assert_eq!(v["error"]["code"], *outcome, "{name} {v}");
        }
        if *name == "propose_write" {
            approval = v["approval_id"].clone();
        }
    }
    assert!(approval.is_string());
    for name in ["get_approval", "withdraw"] {
        let (failed, v) = tool(
            &f,
            &token,
            name,
            json!({"task":"Follow my request","approval_id":approval}),
        )
        .await;
        assert!(!failed, "{name} {v}");
    }
    assert_expired(
        &tool(
            &f,
            &token,
            "fetch_rows",
            json!({"task":"Read more rows","cursor":"not-a-cursor"}),
        )
        .await,
    );
    // Refused before a tool ran: an argument the tool does not take, and a
    // task that is not one. Both are steps; the second has no task to show.
    let (failed, v) = tool(
        &f,
        &token,
        "check_sql",
        json!({"task":"Check with more","database":db,"sql":"SELECT 1","extra":1}),
    )
    .await;
    assert!(failed && v["error"]["code"] == "validation", "{v}");
    let (failed, _) = tool(&f, &token, "list_databases", json!({"task":" \n "})).await;
    assert!(failed);
    // A tool that does not exist is a protocol error, not a step.
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"read_sessions","arguments":{"task":"x"}}});
    let (_, v) = call(&f.app, "POST", "/mcp", "", Some(body), Some(&token)).await;
    assert_eq!(v["error"]["code"], -32602, "{v}");
    f.written(agent, 15).await;

    let sessions = f.sessions(agent).await;
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    let session = &sessions[0];
    assert_eq!(session["steps"], 15);
    assert_eq!(session["refusals"], 6);
    assert_eq!(session["first_task"], "See what I can reach");
    assert_eq!(session["active"], true);
    assert_eq!(session["agent_id"], json!(agent));
    assert_eq!(session["token"]["hint"].as_str().unwrap().len(), 4);
    assert!(token.ends_with(session["token"]["hint"].as_str().unwrap()));
    let all = f.steps(agent, session, "").await;
    assert_eq!(all["session"]["id"], session["id"]);
    assert_eq!(
        (all["after"].clone(), all["more"].clone()),
        (json!(15), json!(false))
    );
    let listed = all["items"].as_array().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|s| s["n"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        (1..=15).collect::<Vec<_>>(),
        "steps are numbered in order, with no gap"
    );
    let tools: Vec<&str> = listed.iter().map(|s| s["tool"].as_str().unwrap()).collect();
    assert_eq!(
        tools,
        [
            "list_databases",
            "search_schema",
            "describe_table",
            "describe_table",
            "check_sql",
            "check_sql",
            "run_query",
            "run_query",
            "run_query",
            "propose_write",
            "get_approval",
            "withdraw",
            "fetch_rows",
            "check_sql",
            "list_databases"
        ]
    );
    let step = |n: usize| &listed[n - 1];
    // A plain call: the task, no SQL, no verdict, nothing to fix.
    assert_eq!(step(1)["task"], "See what I can reach");
    assert_eq!(step(1)["outcome"], "ok");
    for field in [
        "database",
        "sql",
        "verdict",
        "fix",
        "row_count",
        "history_id",
        "approval_id",
    ] {
        assert_eq!(step(1)[field], Value::Null, "{field}");
    }
    assert!(step(1)["elapsed_ms"].as_i64().unwrap() >= 0);
    assert_eq!(step(2)["database"], db);
    // A refusal carries the code and the fix the agent was given, and the
    // same in words for a person.
    assert_eq!(step(4)["outcome"], "table_not_found");
    assert_eq!(step(4)["fix"]["action"], "fix_arguments");
    assert!(step(4)["fix"]["hint"]
        .as_str()
        .unwrap()
        .contains("search_schema"));
    assert_eq!(
        step(4)["fix"]["told"],
        "The agent was told to correct the arguments of its call."
    );
    // check_sql: the SQL and the verdict are kept, with the fix inside a
    // successful answer.
    assert_eq!(step(5)["sql"], json!(read));
    assert_eq!(
        (step(5)["verdict"].clone(), step(5)["fix"].clone()),
        (json!("allow"), Value::Null)
    );
    assert_eq!(step(6)["sql"], json!(blocked));
    assert_eq!(
        (step(6)["outcome"].clone(), step(6)["verdict"].clone()),
        (json!("ok"), json!("deny"))
    );
    assert_eq!(step(6)["fix"]["action"], "stop");
    assert_eq!(step(6)["fix"]["told"], "The agent was told to stop.");
    // run_query: the rows are counted, never kept, and the step points at
    // the history row of this very query.
    assert_eq!(step(7)["verdict"], "allow");
    assert_eq!(step(7)["row_count"], 3);
    assert_eq!(step(7)["sql_truncated"], false);
    for n in [7, 8, 9] {
        let history: (String, Option<Uuid>, String) =
            sqlx::query_as("SELECT sql,agent_id,status FROM query_history WHERE id=$1")
                .bind(
                    step(n)["history_id"]
                        .as_str()
                        .unwrap()
                        .parse::<Uuid>()
                        .unwrap(),
                )
                .fetch_one(&f.db)
                .await
                .unwrap();
        assert_eq!(json!(history.0), step(n)["sql"], "step {n}");
        assert_eq!(history.1, Some(agent));
        assert_eq!(history.2, if n == 7 { "ok" } else { "blocked" });
    }
    assert_eq!(
        (step(8)["outcome"].clone(), step(8)["verdict"].clone()),
        (json!("query_denied"), json!("deny"))
    );
    assert_eq!(step(8)["fix"]["action"], "stop");
    assert_eq!(
        (step(9)["outcome"].clone(), step(9)["verdict"].clone()),
        (json!("approval_required"), json!("requires_approval"))
    );
    assert_eq!(step(9)["fix"]["action"], "propose_write");
    assert_eq!(
        step(9)["fix"]["told"],
        "The agent was told to ask a person for this write."
    );
    // The write tools point at the approval request.
    assert_eq!(step(10)["verdict"], "requires_approval");
    for n in [10, 11, 12] {
        assert_eq!(step(n)["approval_id"], approval, "step {n}");
        assert_eq!(step(n)["outcome"], "ok");
    }
    assert_eq!(step(13)["outcome"], "result_expired");
    assert_eq!(step(13)["fix"]["action"], "rewrite_sql");
    assert_eq!(step(14)["outcome"], "validation");
    assert_eq!(step(14)["sql"], "SELECT 1");
    assert_eq!(step(14)["task"], "Check with more");
    assert_eq!(step(14)["fix"]["action"], "fix_arguments");
    assert_eq!(
        (step(15)["outcome"].clone(), step(15)["task"].clone()),
        (json!("validation"), Value::Null)
    );
    // Steps hold SQL text, never result rows: no value of a row is in them.
    let text = all.to_string();
    assert!(
        !text.contains("note-1") && !text.contains("hidden.example"),
        "{text}"
    );
    // The marker reads only what is new, and a limit says that more waits.
    let new = f.steps(agent, session, "?after=13").await;
    assert_eq!(new["items"].as_array().unwrap().len(), 2);
    assert_eq!(new["items"][0]["n"], 14);
    assert_eq!(new["after"], 15);
    let none = f.steps(agent, session, "?after=15").await;
    assert_eq!(
        (none["items"].clone(), none["after"].clone()),
        (json!([]), json!(15))
    );
    let part = f.steps(agent, session, "?limit=5").await;
    assert_eq!(part["items"].as_array().unwrap().len(), 5);
    assert_eq!(
        (part["after"].clone(), part["more"].clone()),
        (json!(5), json!(true))
    );
    for bad in ["?after=-1", "?limit=0", "?limit=501", "?after=x"] {
        let (s, _) = f
            .request(
                "GET",
                &format!(
                    "/agents/{agent}/sessions/{}/steps{bad}",
                    session["id"].as_str().unwrap()
                ),
                &f.owner_cookie,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    // The audit event of each call that reached a tool is still written.
    let mut events = 0i64;
    for _ in 0..1200 {
        events = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE action='agent.tool' AND target_id=$1",
        )
        .bind(agent)
        .fetch_one(&f.db)
        .await
        .unwrap();
        if events >= 13 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(events, 13, "one event per call that reached a tool");

    // A flood: calls above the rate are refused before any tool runs. They
    // are steps too, but only so many in a minute.
    let (flood, _, flood_token) = f.agent("Flood", "read").await;
    let mut limited = 0;
    for _ in 0..180 {
        let (failed, v) = tool(&f, &flood_token, "list_databases", json!({"task":"Again"})).await;
        if failed {
            assert_eq!(v["error"]["code"], "rate_limited", "{v}");
            limited += 1;
        }
    }
    assert_eq!(limited, 60);
    f.written(flood, 150).await;
    // Give a step beyond the bound the time to be written, if one were queued.
    tokio::time::sleep(Duration::from_millis(300)).await;
    f.written(flood, 150).await;
    let session = &f.sessions(flood).await[0];
    assert_eq!(
        (session["steps"].clone(), session["refusals"].clone()),
        (json!(150), json!(30))
    );
    let last = f.steps(flood, session, "?after=149").await;
    assert_eq!(last["items"][0]["outcome"], "rate_limited");
    assert_eq!(last["items"][0]["fix"]["action"], "retry_later");
    assert_eq!(last["items"][0]["task"], "Again");
    f.close().await;
}

fn crafted(agent: Uuid, token: Uuid, at: chrono::DateTime<chrono::Utc>, outcome: &str) -> Step {
    Step {
        id: Uuid::new_v4(),
        agent_id: agent,
        token_id: token,
        tool: "list_databases".into(),
        task: Some(format!("At {}", at.format("%H:%M:%S"))),
        database: None,
        sql: None,
        sql_truncated: false,
        verdict: None,
        outcome: outcome.into(),
        fix: None,
        row_count: None,
        elapsed_ms: 1,
        history_id: None,
        approval_id: None,
        at,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_ends_after_the_gap_and_two_nodes_agree_on_it() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let gap = steps::SESSION_GAP;
    assert_eq!(gap, Duration::from_secs(1800));
    // The gap, with times written into the steps: no clock has to pass.
    let (agent, token_id, _) = f.agent("Gap", "read").await;
    use chrono::Timelike;
    let start = (chrono::Utc::now() - chrono::Duration::hours(6))
        .with_nanosecond(0)
        .unwrap();
    let minutes = |m: i64| start + chrono::Duration::minutes(m);
    let batch = [
        crafted(agent, token_id, minutes(0), "ok"),
        crafted(agent, token_id, minutes(29), "forbidden"),
        // Exactly the gap: still the same session.
        crafted(agent, token_id, minutes(59), "ok"),
        // One second more than the gap: a new session.
        crafted(
            agent,
            token_id,
            minutes(89) + chrono::Duration::seconds(1),
            "ok",
        ),
    ];
    assert_eq!(steps::persist(&f.db, &batch, gap).await.unwrap(), 4);
    // A batch that is tried again writes nothing twice.
    assert_eq!(steps::persist(&f.db, &batch, gap).await.unwrap(), 0);
    // The next batch continues the open session, also from another call.
    let more = [
        crafted(agent, token_id, minutes(100), "ok"),
        crafted(agent, token_id, minutes(200), "ok"),
    ];
    assert_eq!(steps::persist(&f.db, &more, gap).await.unwrap(), 2);
    let sessions = f.sessions(agent).await;
    let shape: Vec<(i64, i64, bool)> = sessions
        .iter()
        .map(|s| {
            (
                s["steps"].as_i64().unwrap(),
                s["refusals"].as_i64().unwrap(),
                s["active"].as_bool().unwrap(),
            )
        })
        .collect();
    // Newest first: one step after the long silence, two before it, three first.
    assert_eq!(shape, [(1, 0, false), (2, 0, false), (3, 1, false)]);
    let time = |value: &Value| {
        value
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
    };
    assert_eq!(time(&sessions[2]["started_at"]), minutes(0));
    assert_eq!(time(&sessions[2]["last_step_at"]), minutes(59));
    assert_eq!(sessions[2]["first_task"], batch[0].task.clone().unwrap());
    // The gap is a parameter of the writer: a shorter one cuts sooner.
    let (short, short_token, _) = f.agent("Short gap", "read").await;
    let quick = [
        crafted(short, short_token, minutes(0), "ok"),
        crafted(short, short_token, minutes(2), "ok"),
    ];
    steps::persist(&f.db, &quick, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(f.sessions(short).await.len(), 2);
    // A step whose agent or token is gone, or whose token belongs to another
    // agent, is skipped and does not fail the batch.
    let stray = [
        crafted(Uuid::new_v4(), Uuid::new_v4(), minutes(1), "ok"),
        crafted(agent, short_token, minutes(1), "ok"),
        crafted(short, short_token, minutes(3), "ok"),
    ];
    assert_eq!(steps::persist(&f.db, &stray, gap).await.unwrap(), 1);

    // Through the door: a call, a silence longer than the gap, a call.
    let (agent, _, token) = f.agent("Door", "read").await;
    let (failed, _) = tool(&f, &token, "list_databases", json!({"task":"First visit"})).await;
    assert!(!failed);
    f.written(agent, 1).await;
    sqlx::query(
        "UPDATE agent_sessions SET started_at=started_at-interval '31 minutes',
         last_step_at=last_step_at-interval '31 minutes' WHERE agent_id=$1",
    )
    .bind(agent)
    .execute(&f.db)
    .await
    .unwrap();
    let (failed, _) = tool(&f, &token, "list_databases", json!({"task":"Second visit"})).await;
    assert!(!failed);
    f.written(agent, 2).await;
    let sessions = f.sessions(agent).await;
    assert_eq!(sessions.len(), 2, "{sessions:?}");
    assert_eq!(sessions[0]["first_task"], "Second visit");
    assert_eq!(
        (sessions[0]["active"].clone(), sessions[1]["active"].clone()),
        (json!(true), json!(false))
    );

    // Two nodes: the calls of one token alternate between them, and many
    // arrive at once. Every node gives them the same session, and the steps
    // are numbered once each.
    let (second, other) = f.node().await;
    let (agent, token_id, token) = f.agent("Two nodes", "read").await;
    let mut calls = Vec::new();
    for n in 0..40 {
        let app = if n % 2 == 0 {
            f.app.clone()
        } else {
            other.clone()
        };
        let token = token.clone();
        calls.push(tokio::spawn(async move {
            tool_at(
                &app,
                &token,
                "list_databases",
                json!({"task":format!("Call {n}")}),
            )
            .await
        }));
    }
    for call in calls {
        let (failed, v) = call.await.unwrap();
        assert!(!failed, "{v}");
    }
    f.written(agent, 40).await;
    // And both writers at the very same moment, for a token with no session yet.
    let (fresh, fresh_token, _) = f.agent("Fresh", "read").await;
    let now = chrono::Utc::now();
    let left: Vec<Step> = (0..50)
        .map(|_| crafted(fresh, fresh_token, now, "ok"))
        .collect();
    let right: Vec<Step> = (0..50)
        .map(|_| crafted(fresh, fresh_token, now, "ok"))
        .collect();
    let (a, b) = tokio::join!(
        steps::persist(&f.state.db, &left, gap),
        steps::persist(&second.db, &right, gap)
    );
    assert_eq!((a.unwrap(), b.unwrap()), (50, 50));
    for (agent, token_id, expected) in [(agent, token_id, 40), (fresh, fresh_token, 100)] {
        let sessions = f.sessions(agent).await;
        assert_eq!(sessions.len(), 1, "one session on both nodes: {sessions:?}");
        assert_eq!(sessions[0]["steps"], expected);
        assert_eq!(sessions[0]["token"]["id"], json!(token_id));
        let numbers: Vec<i32> =
            sqlx::query_scalar("SELECT n FROM agent_steps WHERE session_id=$1 ORDER BY n")
                .bind(sessions[0]["id"].as_str().unwrap().parse::<Uuid>().unwrap())
                .fetch_all(&f.db)
                .await
                .unwrap();
        assert_eq!(numbers, (1..=expected).collect::<Vec<i32>>());
    }
    // Another token of the same agent has a session of its own.
    let (_, token_b) = f.token(agent).await;
    let (failed, _) = tool(
        &f,
        &token_b,
        "list_databases",
        json!({"task":"Other token"}),
    )
    .await;
    assert!(!failed);
    f.written(agent, 41).await;
    assert_eq!(f.sessions(agent).await.len(), 2);

    // Old steps are pruned, and then the sessions that have none left.
    sqlx::query("UPDATE agent_steps SET created_at=created_at-interval '40 days' WHERE session_id IN (SELECT id FROM agent_sessions WHERE agent_id=$1)")
        .bind(fresh).execute(&f.db).await.unwrap();
    sqlx::query(
        "UPDATE agent_sessions SET last_step_at=last_step_at-interval '40 days' WHERE agent_id=$1",
    )
    .bind(fresh)
    .execute(&f.db)
    .await
    .unwrap();
    steps::prune(&f.db, 30).await.unwrap();
    assert_eq!(f.sessions(fresh).await.len(), 0);
    assert_eq!(f.sessions(agent).await.len(), 2, "younger steps stay");
    // The token's next call starts a new session after the prune.
    let later = [crafted(fresh, fresh_token, chrono::Utc::now(), "ok")];
    assert_eq!(steps::persist(&f.db, &later, gap).await.unwrap(), 1);
    assert_eq!(f.sessions(fresh).await[0]["steps"], 1);
    // Deleting an agent deletes its sessions and steps with it.
    let (s, _) = f
        .request("DELETE", &format!("/agents/{fresh}"), &f.owner_cookie, None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_sessions WHERE agent_id=$1")
        .bind(fresh)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_owner_and_administrators_read_sessions_and_an_agent_never_does() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (agent, _, token) = f.agent("Watched", "read").await;
    let (failed, _) = tool(&f, &token, "list_databases", json!({"task":"Look around"})).await;
    assert!(!failed);
    f.written(agent, 1).await;
    let session = f.sessions(agent).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let list = format!("/agents/{agent}/sessions");
    let one = format!("/agents/{agent}/sessions/{session}/steps");
    // The owner and an organization administrator read both.
    for cookie in [&f.owner_cookie, &f.admin_cookie] {
        for path in [&list, &one] {
            let (s, v) = f.request("GET", path, cookie, None).await;
            assert_eq!(s, StatusCode::OK, "{path} {v}");
        }
    }
    // Another member, also one who administers the same database, sees
    // nothing: not the list, not the steps, as for the agent itself.
    for cookie in [&f.other_cookie, &f.reader_cookie] {
        for path in [&list, &one, &format!("/agents/{agent}")] {
            let (s, v) = f.request("GET", path, cookie, None).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{path} {v}");
        }
    }
    // An agent token is not a session: the people's API refuses it, alone
    // and next to a cookie-less request, and the agent door has no such tool.
    for path in [&list, &one] {
        let (s, _) = call(&f.app, "GET", path, "", None, Some(&token)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
    }
    let listed = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    let (_, v) = call(&f.app, "POST", "/mcp", "", Some(listed), Some(&token)).await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 9, "{names:?}");
    assert!(names.contains(&"fetch_rows"));
    assert!(!names
        .iter()
        .any(|name| name.contains("session") || name.contains("step")));
    // A session is read only under its own agent.
    let (mine, _, _) = f.agent("Mine", "read").await;
    let (s, _) = f
        .request(
            "GET",
            &format!("/agents/{mine}/sessions/{session}/steps"),
            &f.owner_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for bad in [
        format!("/agents/{agent}/sessions/{}/steps", Uuid::new_v4()),
        format!("/agents/{}/sessions", Uuid::new_v4()),
    ] {
        let (s, _) = f.request("GET", &bad, &f.owner_cookie, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{bad}");
    }
    let (s, _) = f
        .request(
            "GET",
            &format!("/agents/{agent}/sessions/x/steps"),
            &f.owner_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // The list is paged, newest first.
    let (paged, paged_token, _) = f.agent("Paged", "read").await;
    let start = chrono::Utc::now() - chrono::Duration::days(2);
    let old: Vec<Step> = (0..5)
        .map(|n| crafted(paged, paged_token, start + chrono::Duration::hours(n), "ok"))
        .collect();
    steps::persist(&f.db, &old, steps::SESSION_GAP)
        .await
        .unwrap();
    let (s, first) = f
        .request(
            "GET",
            &format!("/agents/{paged}/sessions?limit=2"),
            &f.owner_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let mut seen: Vec<Value> = first["items"].as_array().unwrap().clone();
    let mut cursor = first["next_cursor"].clone();
    while let Some(next) = cursor.as_str() {
        let (_, page) = f
            .request(
                "GET",
                &format!("/agents/{paged}/sessions?limit=2&cursor={next}"),
                &f.owner_cookie,
                None,
            )
            .await;
        seen.extend(page["items"].as_array().unwrap().iter().cloned());
        cursor = page["next_cursor"].clone();
    }
    let started: Vec<&str> = seen
        .iter()
        .map(|s| s["started_at"].as_str().unwrap())
        .collect();
    assert_eq!(started.len(), 5);
    let mut sorted = started.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(started, sorted, "newest first");
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_rows_hands_out_exactly_the_rows_of_one_run() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (agent, _, token) = f.agent("Pager", "read").await;
    let db = json!(f.cluster);
    let table = &f.table;
    let sql = format!("SELECT id,email,note FROM {table} ORDER BY id");
    // The table has 250 rows and the policy lets one query fetch 120.
    let (failed, first) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read all notes","database":db,"sql":sql,"max_rows":50}),
    )
    .await;
    assert!(!failed, "{first}");
    assert_eq!(first["row_count"], 50);
    assert_eq!(first["truncated"], true);
    assert_eq!(first["rows_left"], 70);
    assert_eq!(f.queries(agent).await, 1);
    let mut got = ids(&first["rows"]);
    let mut pages = vec![first.clone()];
    let mut cursor = first["next_cursor"].as_str().unwrap().to_owned();
    let mut sizes = vec![30, 1000];
    while !cursor.is_empty() {
        let (failed, page) = tool(
            &f,
            &token,
            "fetch_rows",
            json!({"task":"Read the next notes","cursor":cursor,"max_rows":sizes.remove(0)}),
        )
        .await;
        assert!(!failed, "{page}");
        // A cursor works once.
        assert_expired(
            &tool(
                &f,
                &token,
                "fetch_rows",
                json!({"task":"Again","cursor":cursor}),
            )
            .await,
        );
        got.extend(ids(&page["rows"]));
        cursor = page["next_cursor"].as_str().unwrap_or_default().to_owned();
        pages.push(page);
    }
    // Exactly the 120 rows the one query fetched: in order, no repeat, no gap.
    assert_eq!(got, (1..=120).collect::<Vec<i64>>());
    assert_eq!(
        pages
            .iter()
            .map(|p| p["row_count"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        [50, 30, 40]
    );
    assert_eq!(pages[1]["rows_left"], 40);
    // The last page has no cursor; it still says that the database had more
    // rows than the policy lets one query fetch.
    let last = pages.last().unwrap();
    assert!(
        last.get("next_cursor").is_none() && last.get("rows_left").is_none(),
        "{last}"
    );
    assert_eq!(last["truncated"], true);
    for page in &pages {
        // The same shape on every page, and the protected column masked.
        assert_eq!(page["query_id"], first["query_id"]);
        assert_eq!(page["columns"], first["columns"]);
        // What ran is said once, with the query; the pages do not repeat it.
        assert_eq!(
            page.get("ran_as").is_some(),
            page["rows"][0][0] == 1,
            "{page}"
        );
        assert_eq!(page["columns"][1]["masked"], true);
        for row in page["rows"].as_array().unwrap() {
            assert!(
                !row[1].as_str().unwrap().contains("hidden.example"),
                "{row}"
            );
            assert!(row[2].as_str().unwrap().starts_with("note-"));
        }
        assert!(!page.to_string().contains("hidden.example"));
    }
    // Nothing ran for the pages: one history row, one query from the budget.
    assert_eq!(f.queries(agent).await, 1);
    assert_eq!(f.state.held.usage(), (0, 0));
    // A result that fits in one answer has no cursor and is not truncated.
    let (_, small) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read a few","database":db,"sql":format!("SELECT id FROM {table} WHERE id<=5")}),
    )
    .await;
    assert_eq!(
        (small["row_count"].clone(), small["truncated"].clone()),
        (json!(5), json!(false))
    );
    assert!(small.get("next_cursor").is_none(), "{small}");
    // The pages are steps and audit events like other calls, with the
    // database and the history row of the query they belong to.
    f.written(agent, 6).await;
    let session = &f.sessions(agent).await[0];
    let listed = f.steps(agent, session, "").await;
    let fetched: Vec<&Value> = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["tool"] == "fetch_rows" && s["outcome"] == "ok")
        .collect();
    assert_eq!(fetched.len(), 2);
    for step in fetched {
        assert_eq!(step["database"], db);
        assert_eq!(step["history_id"], listed["items"][0]["history_id"]);
        assert_eq!(step["sql"], Value::Null);
    }
    assert_eq!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["row_count"].as_i64())
            .collect::<Vec<_>>(),
        [Some(50), Some(30), None, Some(40), None, Some(5)]
    );
    let mut events = 0i64;
    for _ in 0..1200 {
        events = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE action='agent.tool' AND target_id=$1
             AND details->>'tool'='fetch_rows' AND details->>'outcome'='ok'
             AND details->>'database'=$2",
        )
        .bind(agent)
        .bind(f.cluster.to_string())
        .fetch_one(&f.db)
        .await
        .unwrap();
        if events >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(events, 2);

    // A cursor is bound to the agent and to the token that ran the query.
    let run = |token: String| {
        let (db, sql, app) = (db.clone(), sql.clone(), f.app.clone());
        async move {
            let (failed, v) = tool_at(
                &app,
                &token,
                "run_query",
                json!({"task":"Read all notes","database":db,"sql":sql,"max_rows":10}),
            )
            .await;
            assert!(!failed, "{v}");
            v["next_cursor"].as_str().unwrap().to_owned()
        }
    };
    let cursor = run(token.clone()).await;
    let (_, _, stranger) = f.agent("Stranger", "read").await;
    let (_, sibling) = f.token(agent).await;
    for foreign in [&stranger, &sibling] {
        assert_expired(
            &tool(
                &f,
                foreign,
                "fetch_rows",
                json!({"task":"Take them","cursor":cursor}),
            )
            .await,
        );
    }
    // Garbage of every kind gets the same answer.
    for garbage in [
        "rows_",
        "rows_AAAA",
        "x",
        &cursor[..cursor.len() - 1],
        &format!("{cursor}A"),
    ] {
        assert_expired(
            &tool(
                &f,
                &token,
                "fetch_rows",
                json!({"task":"Guess","cursor":garbage}),
            )
            .await,
        );
    }
    // The owner of the cursor can still use it after all that.
    let (failed, page) = tool(
        &f,
        &token,
        "fetch_rows",
        json!({"task":"Go on","cursor":cursor}),
    )
    .await;
    assert!(!failed, "{page}");
    assert_eq!(ids(&page["rows"]), (11..=110).collect::<Vec<i64>>());
    // A cursor that nobody used for five minutes is gone.
    let next = page["next_cursor"].as_str().unwrap();
    assert_eq!(
        f.state
            .held
            .sweep(Instant::now() + held::IDLE - Duration::from_secs(5)),
        0
    );
    assert_eq!(
        f.state
            .held
            .sweep(Instant::now() + held::IDLE + Duration::from_secs(1)),
        1
    );
    assert_expired(
        &tool(
            &f,
            &token,
            "fetch_rows",
            json!({"task":"Too late","cursor":next}),
        )
        .await,
    );
    // Arguments are checked like those of any tool.
    for arguments in [
        json!({"task":"No cursor"}),
        json!({"task":"With a database","cursor":"x","database":db}),
    ] {
        let (failed, v) = tool(&f, &token, "fetch_rows", arguments).await;
        assert!(failed && v["error"]["code"] == "validation", "{v}");
    }
    // Zero rows is refused by both tools, as their schema says, and the
    // refusal does not use up the cursor. More than the most is cut to it.
    let cursor = run(token.clone()).await;
    for (name, arguments) in [
        (
            "fetch_rows",
            json!({"task":"Zero rows","cursor":cursor,"max_rows":0}),
        ),
        (
            "run_query",
            json!({"task":"Zero rows","database":db,"sql":sql,"max_rows":0}),
        ),
    ] {
        let (failed, v) = tool(&f, &token, name, arguments).await;
        assert!(failed, "{name} {v}");
        assert_eq!(v["error"]["code"], "validation", "{name} {v}");
        assert_eq!(v["error"]["message"], "`max_rows` must be 1 or more");
        assert_eq!(v["error"]["fix"]["action"], "fix_arguments");
    }
    let (failed, v) = tool(
        &f,
        &token,
        "fetch_rows",
        json!({"task":"All the rest","cursor":cursor,"max_rows":1000000}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(ids(&v["rows"]), (11..=120).collect::<Vec<i64>>());
    // The pages count toward the calls of a minute, and take nothing from
    // the hourly budget: a pager with a budget of two queries reads on.
    let (frugal, _, frugal_token) = f.agent("Frugal", "read").await;
    let (s, _) = f
        .request(
            "PATCH",
            &format!("/agents/{frugal}"),
            &f.owner_cookie,
            Some(json!({"hourly_query_budget":1})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let mut cursor = run(frugal_token.clone()).await;
    for _ in 0..100 {
        let (failed, v) = tool(
            &f,
            &frugal_token,
            "fetch_rows",
            json!({"task":"One row at a time","cursor":cursor,"max_rows":1}),
        )
        .await;
        assert!(!failed, "{v}");
        assert_eq!(v["row_count"], 1);
        cursor = v["next_cursor"].as_str().unwrap().to_owned();
    }
    for _ in 0..19 {
        let (failed, v) = tool(&f, &frugal_token, "list_databases", json!({"task":"Look"})).await;
        assert!(!failed, "{v}");
    }
    // The 121st call of the minute is refused, whichever tool it is.
    let (failed, v) = tool(
        &f,
        &frugal_token,
        "fetch_rows",
        json!({"task":"One row at a time","cursor":cursor,"max_rows":1}),
    )
    .await;
    assert!(failed && v["error"]["code"] == "rate_limited", "{v}");
    assert_eq!(f.queries(frugal).await, 1);
    let (failed, v) = tool(
        &f,
        &frugal_token,
        "run_query",
        json!({"task":"One more query","database":db,"sql":"SELECT 1"}),
    )
    .await;
    assert!(failed && v["error"]["code"] == "rate_limited", "{v}");
    f.close().await;
}

/// `fetch_rows` on MySQL: the fixture's database is pointed at the MySQL
/// test server, and the same paging as on PostgreSQL must hold there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_rows_pages_a_mysql_result_like_a_postgres_one() {
    let Ok(mysql_url) = std::env::var("VISP_GATE_TEST_MYSQL_URL") else {
        eprintln!("skipped: VISP_GATE_TEST_MYSQL_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mysql = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(2)
        .connect(&mysql_url)
        .await
        .unwrap();
    // The fixture's PostgreSQL table name is unique to this test.
    let table = &f.table;
    let body = async {
        for sql in [
        format!(
            "CREATE TABLE {table}(id INT PRIMARY KEY, email VARCHAR(100), note TEXT NOT NULL,
             amount DECIMAL(10,2), big BIGINT UNSIGNED, made DATETIME, raw VARBINARY(8))"
        ),
        format!(
            "INSERT INTO {table} WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<250)
             SELECT i, CONCAT('person',i,'@hidden.example'), CONCAT('note-',i),
             IF(i%7=0, NULL, i*1.25), 18446744073709551615-i,
             TIMESTAMP('2026-01-01 00:00:00') + INTERVAL i MINUTE, UNHEX(LPAD(HEX(i),4,'0'))
             FROM n"
        ),
    ] {
        sqlx::query(&sql).execute(&mysql).await.unwrap();
    }
        let at = url::Url::parse(&mysql_url).unwrap();
        sqlx::query(
        "UPDATE clusters SET engine='mysql',host=$2,port=$3,database=$4,username=$5,password_enc=$6
         WHERE id=$1",
    )
    .bind(f.cluster)
    .bind(at.host_str().unwrap())
    .bind(i32::from(at.port().unwrap_or(3306)))
    .bind(at.path().trim_start_matches('/'))
    .bind(at.username())
    .bind(
        Crypto::new(&[4; 32])
            .encrypt(f.cluster, at.password().unwrap_or(""))
            .unwrap(),
    )
    .execute(&f.db)
    .await
    .unwrap();

        let (agent, token_id, token) = f.agent("MySQL pager", "read").await;
        let db = json!(f.cluster);
        let sql = format!("SELECT id,email,note,amount,big,made,raw FROM {table} ORDER BY id");
        // The table has 250 rows and the policy lets one query fetch 120.
        let run = |token: String, rows: usize| {
            let (db, sql, app) = (db.clone(), sql.clone(), f.app.clone());
            async move {
                let (failed, v) = tool_at(
                    &app,
                    &token,
                    "run_query",
                    json!({"task":"Read all notes","database":db,"sql":sql,"max_rows":rows}),
                )
                .await;
                assert!(!failed, "{v}");
                v
            }
        };
        let first = run(token.clone(), 50).await;
        assert_eq!(first["row_count"], 50, "{first}");
        assert_eq!(first["truncated"], true);
        assert_eq!(first["rows_left"], 70);
        let mut cursor = first["next_cursor"].as_str().unwrap().to_owned();
        // Another agent cannot take the cursor, and trying leaves it to its owner.
        let (_, _, stranger) = f.agent("Stranger", "read").await;
        assert_expired(
            &tool(
                &f,
                &stranger,
                "fetch_rows",
                json!({"task":"Take them","cursor":cursor}),
            )
            .await,
        );
        assert_eq!(f.state.held.usage().0, 1);
        let mut got = ids(&first["rows"]);
        let mut pages = vec![first.clone()];
        let mut sizes = vec![30, 1000];
        while !cursor.is_empty() {
            let (failed, page) = tool(
                &f,
                &token,
                "fetch_rows",
                json!({"task":"Read the next notes","cursor":cursor,"max_rows":sizes.remove(0)}),
            )
            .await;
            assert!(!failed, "{page}");
            got.extend(ids(&page["rows"]));
            cursor = page["next_cursor"].as_str().unwrap_or_default().to_owned();
            pages.push(page);
        }
        // Exactly the 120 rows the one query fetched: in order, no repeat, no gap.
        assert_eq!(got, (1..=120).collect::<Vec<i64>>());
        assert_eq!(
            pages
                .iter()
                .map(|p| p["row_count"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            [50, 30, 40]
        );
        let last = pages.last().unwrap();
        assert!(
            last.get("next_cursor").is_none() && last.get("rows_left").is_none(),
            "{last}"
        );
        assert_eq!(last["truncated"], true);
        assert_eq!(f.state.held.usage(), (0, 0));
        // Every page as the first: the same columns, the protected column
        // masked, and each MySQL type decoded the same way on every row.
        assert_eq!(first["rows"][0][1], "••••••", "{first}");
        for page in &pages {
            assert_eq!(page["query_id"], first["query_id"]);
            assert_eq!(page["columns"], first["columns"]);
            assert_eq!(page["columns"][1]["masked"], true, "{page}");
            assert!(!page.to_string().contains("hidden.example"), "{page}");
            for row in page["rows"].as_array().unwrap() {
                use base64::Engine;
                let id = row[0].as_i64().unwrap();
                let amount = if id % 7 == 0 {
                    Value::Null
                } else {
                    json!(format!("{}.{:02}", id * 125 / 100, id * 125 % 100))
                };
                let raw = base64::engine::general_purpose::STANDARD
                    .encode(u16::try_from(id).unwrap().to_be_bytes());
                assert_eq!(
                    row,
                    &json!([
                        id,
                        "••••••",
                        format!("note-{id}"),
                        amount,
                        (u64::MAX - u64::try_from(id).unwrap()).to_string(),
                        format!("2026-01-01T{:02}:{:02}:00", id / 60, id % 60),
                        format!("base64:{raw}"),
                    ])
                );
            }
        }
        // Nothing ran for the pages.
        assert_eq!(f.queries(agent).await, 1);

        // A revoked token's rows are dropped, and its sibling cannot take them.
        let (_, sibling) = f.token(agent).await;
        let revoked = run(token.clone(), 10).await["next_cursor"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(f.state.held.usage().0, 1);
        let (s, _) = f
            .request(
                "DELETE",
                &format!("/agents/{agent}/tokens/{token_id}"),
                &f.owner_cookie,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        assert_eq!(f.state.held.usage(), (0, 0));
        let (s, _) = call(
            &f.app,
            "POST",
            "/mcp",
            "",
            Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"fetch_rows","arguments":{"task":"Go on","cursor":revoked}}})),
            Some(&token),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_expired(
            &tool(
                &f,
                &sibling,
                "fetch_rows",
                json!({"task":"Go on","cursor":revoked}),
            )
            .await,
        );
    };
    // Drop the table and close the fixture even when an assertion failed,
    // then re-raise the failure.
    let outcome = AssertUnwindSafe(body).catch_unwind().await;
    sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
        .execute(&mysql)
        .await
        .unwrap();
    mysql.close().await;
    f.close().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_rows_end_with_a_pause_a_revoke_a_change_and_the_memory_caps() {
    // One held result of this test's rows takes about 17 KiB.
    let Some(mut f) = Fixture::with(|config| {
        config.held_results_max_bytes = 80 * 1024;
        config.held_results_agent_max_bytes = 50 * 1024;
    })
    .await
    else {
        return;
    };
    let (second, other) = f.node().await;
    let db = json!(f.cluster);
    let sql = format!("SELECT id,email,note FROM {} ORDER BY id", f.table);
    let run_at = |app: Router, token: String, rows: usize| {
        let (db, sql) = (db.clone(), sql.clone());
        async move {
            let (failed, v) = tool_at(
                &app,
                &token,
                "run_query",
                json!({"task":"Read all notes","database":db,"sql":sql,"max_rows":rows}),
            )
            .await;
            assert!(!failed, "{v}");
            v
        }
    };
    let fetch = |token: String, cursor: String| {
        let app = f.app.clone();
        async move {
            tool_at(
                &app,
                &token,
                "fetch_rows",
                json!({"task":"Go on","cursor":cursor}),
            )
            .await
        }
    };
    let cursor_of = |v: &Value| v["next_cursor"].as_str().unwrap().to_owned();
    let (agent, token_id, token) = f.agent("Held", "read").await;
    let patch = |body: Value| {
        let (app, cookie) = (f.app.clone(), f.owner_cookie.clone());
        async move {
            let (s, v) = call(
                &app,
                "PATCH",
                &format!("/agents/{agent}"),
                &cookie,
                Some(body),
                None,
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{v}");
        }
    };

    // Pause: the rows are dropped at once, and a resume does not bring them back.
    let cursor = cursor_of(&run_at(f.app.clone(), token.clone(), 10).await);
    assert_eq!(f.state.held.usage().0, 1);
    patch(json!({"paused":true})).await;
    assert_eq!(f.state.held.usage(), (0, 0));
    patch(json!({"paused":false})).await;
    assert_expired(&fetch(token.clone(), cursor).await);

    // The same on a node that did not hear of the pause: the rows stay in
    // its memory, but the agent's mark moved, so they are refused there too.
    let cursor = cursor_of(&run_at(other.clone(), token.clone(), 10).await);
    assert_eq!(second.held.usage().0, 1);
    patch(json!({"paused":true})).await;
    assert_eq!(second.held.usage().0, 1, "the other node was not told");
    let (s, _) = call(
        &other,
        "POST",
        "/mcp",
        "",
        Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})),
        Some(&token),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "a paused agent is refused everywhere"
    );
    patch(json!({"paused":false})).await;
    assert_expired(
        &tool_at(
            &other,
            &token,
            "fetch_rows",
            json!({"task":"Go on","cursor":cursor}),
        )
        .await,
    );
    assert_eq!(second.held.usage(), (0, 0));
    // A cursor of one node is unknown on another: the same stable code.
    let cursor = cursor_of(&run_at(other.clone(), token.clone(), 10).await);
    assert_expired(&fetch(token.clone(), cursor.clone()).await);
    let (failed, v) = tool_at(
        &other,
        &token,
        "fetch_rows",
        json!({"task":"Go on","cursor":cursor}),
    )
    .await;
    assert!(
        !failed,
        "the node that holds the rows still serves them: {v}"
    );

    // A change of the agent drops what was held for it.
    let cursor = cursor_of(&run_at(f.app.clone(), token.clone(), 10).await);
    patch(json!({"description":"Now with a description"})).await;
    assert_eq!(f.state.held.usage(), (0, 0));
    assert_expired(&fetch(token.clone(), cursor).await);

    // A policy change drops the database's rows here, and the mark refuses
    // them on the node that was not told.
    let here = cursor_of(&run_at(f.app.clone(), token.clone(), 10).await);
    let there = cursor_of(&run_at(other.clone(), token.clone(), 10).await);
    f.policy(|policy| policy.masked_columns = vec!["email".into(), "note".into()])
        .await;
    assert_eq!(f.state.held.usage(), (0, 0));
    assert_expired(&fetch(token.clone(), here).await);
    assert_eq!(second.held.usage().0, 2);
    assert_expired(
        &tool_at(
            &other,
            &token,
            "fetch_rows",
            json!({"task":"Go on","cursor":there}),
        )
        .await,
    );
    // The query run again is masked by the new policy.
    let again = run_at(f.app.clone(), token.clone(), 10).await;
    assert_eq!(again["columns"][2]["masked"], true);
    let (_, page) = fetch(token.clone(), cursor_of(&again)).await;
    assert!(!page.to_string().contains("note-"), "{page}");
    f.policy(|_| {}).await;

    // Access that ends is checked on every page: the agent loses the
    // database, and its held rows with it.
    let cursor = cursor_of(&run_at(f.app.clone(), token.clone(), 10).await);
    sqlx::query("UPDATE grants SET expires_at=now()-interval '1 minute' WHERE user_id=$1")
        .bind(f.owner)
        .execute(&f.db)
        .await
        .unwrap();
    let (failed, v) = fetch(token.clone(), cursor.clone()).await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "forbidden", "{v}");
    assert_eq!(v["error"]["fix"]["action"], "choose_database");
    sqlx::query("UPDATE grants SET expires_at=now()+interval '1 hour' WHERE user_id=$1")
        .bind(f.owner)
        .execute(&f.db)
        .await
        .unwrap();
    assert_expired(&fetch(token.clone(), cursor).await);

    // A revoked token: its rows are dropped, those of another token stay.
    let (_, sibling) = f.token(agent).await;
    let revoked = cursor_of(&run_at(f.app.clone(), token.clone(), 10).await);
    let kept = cursor_of(&run_at(f.app.clone(), sibling.clone(), 10).await);
    assert_eq!(f.state.held.usage().0, 2);
    let (s, _) = f
        .request(
            "DELETE",
            &format!("/agents/{agent}/tokens/{token_id}"),
            &f.owner_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.state.held.usage().0, 1);
    let (s, _) = call(
        &f.app,
        "POST",
        "/mcp",
        "",
        Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_expired(&fetch(sibling.clone(), revoked).await);
    let (failed, v) = fetch(sibling.clone(), kept).await;
    assert!(!failed, "{v}");
    // Deleting the agent drops the rest.
    assert_eq!(f.state.held.usage().0, 1);
    let (s, _) = f
        .request("DELETE", &format!("/agents/{agent}"), &f.owner_cookie, None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.state.held.usage(), (0, 0));

    // Memory. A result takes about 17 KiB here; an agent may hold 50 KiB and
    // the node 80 KiB.
    let (_, _, a) = f.agent("First", "read").await;
    let (_, _, b) = f.agent("Second", "read").await;
    let (_, _, c) = f.agent("Third", "read").await;
    let first = cursor_of(&run_at(f.app.clone(), a.clone(), 10).await);
    let one = f.state.held.usage().1;
    assert!((15_000..25_000).contains(&one), "{one}");
    let second_of_a = cursor_of(&run_at(f.app.clone(), a.clone(), 10).await);
    // The agent's third result drops its oldest.
    let third_of_a = cursor_of(&run_at(f.app.clone(), a.clone(), 10).await);
    assert_eq!(f.state.held.usage(), (2, one * 2));
    assert_expired(&fetch(a.clone(), first).await);
    // Other agents fill the node; then the oldest of anyone makes room.
    let of_b = cursor_of(&run_at(f.app.clone(), b.clone(), 10).await);
    cursor_of(&run_at(f.app.clone(), b.clone(), 10).await);
    assert_eq!(f.state.held.usage(), (4, one * 4));
    cursor_of(&run_at(f.app.clone(), c.clone(), 10).await);
    let (results, bytes) = f.state.held.usage();
    assert!(results == 4 && bytes <= 80 * 1024, "{results} {bytes}");
    assert_expired(&fetch(a.clone(), second_of_a).await);
    for (token, cursor) in [(a.clone(), third_of_a), (b.clone(), of_b)] {
        let (failed, v) = fetch(token, cursor).await;
        assert!(!failed, "{v}");
    }
    // A result that alone is larger than the agent's cap is not held: the
    // answer is truncated and has no cursor, as before there was a cursor.
    sqlx::query(&format!("UPDATE {} SET note=repeat('n',1000)", f.table))
        .execute(&f.target)
        .await
        .unwrap();
    let big = run_at(f.app.clone(), c.clone(), 10).await;
    assert_eq!(
        (big["row_count"].clone(), big["truncated"].clone()),
        (json!(10), json!(true))
    );
    assert!(
        big.get("next_cursor").is_none() && big.get("rows_left").is_none(),
        "{big}"
    );
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_page_obeys_the_answer_size_and_one_row_too_large_is_an_error() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (_, _, token) = f.agent("Wide", "read").await;
    let db = json!(f.cluster);
    f.policy(|policy| policy.masked_columns = vec![]).await;
    sqlx::query(&format!(
        "UPDATE {} SET note=repeat('n',300000) WHERE id<=7",
        f.table
    ))
    .execute(&f.target)
    .await
    .unwrap();
    let sql = format!("SELECT id,note FROM {} WHERE id<=8 ORDER BY id", f.table);
    let (failed, first) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read wide notes","database":db,"sql":sql}),
    )
    .await;
    assert!(!failed, "{}", first["error"]);
    // Three rows of 300 KiB fit in about one megabyte; the fourth does not.
    let mut got = ids(&first["rows"]);
    assert_eq!(got, [1, 2, 3]);
    assert_eq!(first["rows_left"], 5);
    let mut cursor = first["next_cursor"].as_str().unwrap().to_owned();
    loop {
        let (failed, page) = tool(
            &f,
            &token,
            "fetch_rows",
            json!({"task":"Go on","cursor":cursor}),
        )
        .await;
        assert!(!failed, "{}", page["error"]);
        let rows = page["rows"].as_array().unwrap();
        let bytes: usize = rows.iter().map(|row| row.to_string().len()).sum();
        assert!(bytes <= 1024 * 1024 && !rows.is_empty(), "{bytes}");
        got.extend(ids(&page["rows"]));
        match page["next_cursor"].as_str() {
            Some(next) => cursor = next.to_owned(),
            None => break,
        }
    }
    assert_eq!(got, (1..=8).collect::<Vec<i64>>());
    // A row that alone is larger than an answer ends the paging with an error.
    sqlx::query(&format!(
        "UPDATE {} SET note=repeat('n',1100000) WHERE id=2",
        f.table
    ))
    .execute(&f.target)
    .await
    .unwrap();
    let sql = format!(
        "SELECT id,note FROM {} WHERE id IN (1,2,9) ORDER BY id",
        f.table
    );
    let (failed, first) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read wide notes","database":db,"sql":sql}),
    )
    .await;
    assert!(!failed, "{}", first["error"]);
    assert_eq!(ids(&first["rows"]), [1]);
    let cursor = first["next_cursor"].as_str().unwrap();
    let (failed, v) = tool(
        &f,
        &token,
        "fetch_rows",
        json!({"task":"Go on","cursor":cursor}),
    )
    .await;
    assert!(
        failed && v["error"]["code"] == "result_too_large",
        "{}",
        v["error"]
    );
    assert_eq!(f.state.held.usage(), (0, 0));
    let sql = format!("SELECT id,note FROM {} WHERE id=2", f.table);
    let (failed, v) = tool(
        &f,
        &token,
        "run_query",
        json!({"task":"Read one","database":db,"sql":sql}),
    )
    .await;
    assert!(
        failed && v["error"]["code"] == "result_too_large",
        "{}",
        v["error"]
    );
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_analyze_answer_carries_a_preflight_for_each_state_and_access_level() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    // Writes need approval on this database, as in production.
    f.policy(|policy| policy.require_approval_for_writes = true)
        .await;
    let table = &f.table;
    let check = |cookie: String, sql: String| {
        let (app, path) = (f.app.clone(), format!("/clusters/{}/analyze", f.cluster));
        async move {
            let (s, v) = call(&app, "POST", &path, &cookie, Some(json!({"sql":sql})), None).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            v
        }
    };
    let cookies = [
        ("read", f.reader_cookie.clone()),
        ("write", f.writer_cookie.clone()),
        ("admin", f.admin_cookie.clone()),
    ];
    // Safe, for every level: run. The analysis keeps every field it had.
    for (level, cookie) in &cookies {
        let v = check(cookie.clone(), format!("SELECT id,note FROM {table}")).await;
        for field in [
            "verdict",
            "risk",
            "statements",
            "rewritten_sql",
            "issues",
            "suggestions",
        ] {
            assert!(v.get(field).is_some(), "{field} {v}");
        }
        assert!(v.get("row_cap").is_none(), "{v}");
        assert_eq!(v["verdict"], "allow");
        let p = &v["preflight"];
        assert_eq!(
            (p["state"].clone(), p["action"].clone(), p["label"].clone()),
            (json!("safe"), json!("run"), json!("Run")),
            "{level}"
        );
        assert_eq!(p["hint"], "This statement only reads data.");
        assert!(p.get("code").is_none() && p.get("fix").is_none(), "{p}");
        // The guard's change, exactly: the policy allows 120 rows.
        assert_eq!(p["guard_change"]["clause"], "LIMIT 121");
        assert!(p["guard_change"].get("replaces").is_none());
        assert_eq!(
            p["guard_change"]["text"],
            "The guard adds LIMIT 121: the policy allows 120 rows, and one more row shows whether there are more."
        );
        assert!(v["rewritten_sql"].as_str().unwrap().ends_with("LIMIT 121"));
        let lowered = check(cookie.clone(), format!("SELECT id FROM {table} LIMIT 500")).await;
        assert_eq!(
            lowered["preflight"]["guard_change"]["replaces"],
            "LIMIT 500"
        );
        let within = check(cookie.clone(), format!("SELECT id FROM {table} LIMIT 5")).await;
        assert!(within["preflight"].get("guard_change").is_none());
    }
    // A write: a person with write access asks for approval; a person with
    // read access cannot, and is told who can.
    let write = format!("UPDATE {table} SET note='x' WHERE id=1");
    for (level, cookie) in &cookies {
        let v = check(cookie.clone(), write.clone()).await;
        let p = &v["preflight"];
        if *level == "read" {
            assert_eq!(v["verdict"], "deny");
            assert_eq!(
                (p["state"].clone(), p["action"].clone()),
                (json!("blocked"), json!("ask_admin"))
            );
            assert_eq!(p["code"], "insufficient_access");
            assert_eq!(p["label"], "Ask for write access");
            assert!(
                p["hint"]
                    .as_str()
                    .unwrap()
                    .contains("A person with write access can ask for this change"),
                "{p}"
            );
        } else {
            assert_eq!(v["verdict"], "requires_approval");
            assert_eq!(
                (p["state"].clone(), p["action"].clone(), p["label"].clone()),
                (
                    json!("needs_approval"),
                    json!("request_approval"),
                    json!("Request approval")
                ),
                "{level}"
            );
            assert_eq!(p["code"], "approval_required");
            assert_eq!(
                p["hint"],
                "This statement changes data, so another person must approve it before it runs."
            );
        }
        assert!(p.get("guard_change").is_none());
    }
    // Blocked by the policy: only an administrator can help, and the
    // administrator is told that it is theirs to change.
    let vault = format!("SELECT * FROM {}", f.vault);
    for (level, cookie) in &cookies {
        let p = check(cookie.clone(), vault.clone()).await["preflight"].clone();
        assert_eq!(
            (p["state"].clone(), p["code"].clone()),
            (json!("blocked"), json!("blocked_table"))
        );
        let (action, label) = if *level == "admin" {
            ("change_policy", "Change the policy")
        } else {
            ("ask_admin", "Ask an administrator")
        };
        assert_eq!(
            (p["action"].clone(), p["label"].clone()),
            (json!(action), json!(label)),
            "{level}"
        );
    }
    // Blocked, repaired by hand; and blocked with the guard's own fix, which
    // one step applies and which then passes the check.
    let p = check(f.reader_cookie.clone(), "SELECT pg_sleep(1)".into()).await["preflight"].clone();
    assert_eq!(
        (p["state"].clone(), p["action"].clone(), p["label"].clone()),
        (json!("blocked"), json!("edit_sql"), json!("Edit the SQL"))
    );
    assert_eq!(p["code"], "dangerous_function");
    let two = check(
        f.reader_cookie.clone(),
        format!("SELECT id FROM {table} WHERE id=1; SELECT 2"),
    )
    .await;
    let p = &two["preflight"];
    assert_eq!(
        (p["state"].clone(), p["action"].clone()),
        (json!("blocked"), json!("apply_fix"))
    );
    assert_eq!(
        (p["label"].clone(), p["code"].clone()),
        (
            json!("Keep the first statement"),
            json!("multiple_statements")
        )
    );
    assert_eq!(p["fix"]["action"], "replace");
    let fixed = check(
        f.reader_cookie.clone(),
        p["fix"]["sql"].as_str().unwrap().to_owned(),
    )
    .await;
    assert_eq!(fixed["preflight"]["state"], "safe");
    // No hint for a person names an agent's tool.
    for sql in [
        vault,
        write,
        "SELEC".into(),
        "SELECT 1; SELECT pg_sleep(1)".into(),
    ] {
        let hint = check(f.reader_cookie.clone(), sql).await["preflight"]["hint"]
            .as_str()
            .unwrap()
            .to_owned();
        for word in ["propose_write", "check_sql", "your owner", "search_schema"] {
            assert!(!hint.contains(word), "{hint}");
        }
    }
    // A statement that masking refuses is denied with no advice about
    // speed: the bar must not offer "Add LIMIT 100" for a block it does not
    // resolve. The guard alone would allow this one and advise a LIMIT.
    for (level, cookie) in &cookies {
        let v = check(cookie.clone(), format!("SELECT md5(email) FROM {table}")).await;
        assert_eq!(
            (v["verdict"].clone(), v["suggestions"].clone()),
            (json!("deny"), json!([])),
            "{level}"
        );
        assert_eq!(v["rewritten_sql"], Value::Null);
        let p = &v["preflight"];
        assert_eq!(
            (p["state"].clone(), p["action"].clone(), p["code"].clone()),
            (
                json!("blocked"),
                json!("edit_sql"),
                json!("masked_data_transformation")
            ),
            "{level}"
        );
        assert!(
            p.get("fix").is_none() && p.get("guard_change").is_none(),
            "{p}"
        );
        // Keeping the first of several statements is offered only when that
        // statement passes the masking check too.
        let v = check(
            cookie.clone(),
            format!("SELECT md5(email) FROM {table}; SELECT 2"),
        )
        .await;
        assert_eq!(
            (v["verdict"].clone(), v["suggestions"].clone()),
            (json!("deny"), json!([])),
            "{level}"
        );
        let p = &v["preflight"];
        assert_eq!(
            (p["state"].clone(), p["action"].clone()),
            (json!("blocked"), json!("edit_sql")),
            "{p}"
        );
        assert!(p.get("fix").is_none(), "{p}");
    }
    // A read that locks rows: the guard asks for approval, and an approval
    // request for a read is refused. The bar says to take the clause out;
    // it never offers a request that cannot be made.
    let locking = format!("SELECT id FROM {table} WHERE id=1 FOR UPDATE");
    for (level, cookie) in &cookies {
        let v = check(cookie.clone(), locking.clone()).await;
        let p = &v["preflight"];
        assert_eq!(
            (
                p["state"].clone(),
                p["action"].clone(),
                p["label"].clone(),
                p["code"].clone()
            ),
            (
                json!("blocked"),
                json!("edit_sql"),
                json!("Edit the SQL"),
                json!("locking_read")
            ),
            "{level}"
        );
        assert_eq!(
            p["hint"],
            "This statement locks rows. Remove the locking clause (FOR UPDATE / FOR SHARE) to run it as a read."
        );
        if *level != "read" {
            assert_eq!(v["verdict"], "requires_approval");
            let (s, refused) = call(
                &f.app,
                "POST",
                "/approvals",
                cookie,
                Some(json!({"cluster_id":f.cluster,"sql":locking,"reason":"Lock one row"})),
                None,
            )
            .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{refused}");
        }
    }
    // The agent is told the same, by check_sql and by run_query, and is not
    // sent to propose_write with a statement that tool refuses.
    let (_, _, locker) = f.agent("Locker", "write").await;
    let (failed, v) = tool(
        &f,
        &locker,
        "check_sql",
        json!({"task":"Check a lock","database":f.cluster,"sql":locking}),
    )
    .await;
    assert!(!failed, "{v}");
    assert_eq!(v["verdict"], "requires_approval");
    let agent_hint = "This statement locks rows, so it does not run as a read, and it changes no data, so it cannot be proposed as a write. Remove the locking clause (FOR UPDATE or FOR SHARE) and run it again.";
    assert_eq!(v["fix"], json!({"action":"rewrite_sql","hint":agent_hint}));
    let (failed, v) = tool(
        &f,
        &locker,
        "run_query",
        json!({"task":"Lock a row","database":f.cluster,"sql":locking}),
    )
    .await;
    assert!(failed, "{v}");
    assert_eq!(v["error"]["code"], "approval_required");
    assert_eq!(
        v["error"]["fix"],
        json!({"action":"rewrite_sql","hint":agent_hint})
    );
    // A write still sends the agent to propose_write.
    let (_, v) = tool(
        &f,
        &locker,
        "check_sql",
        json!({"task":"Check a write","database":f.cluster,"sql":format!("UPDATE {table} SET note='x' WHERE id=1")}),
    )
    .await;
    assert_eq!(v["fix"]["action"], "propose_write");
    // With a cost limit in the policy, the safe sentence says that the cost
    // is checked when the statement runs. The state stays "safe".
    f.policy(|policy| {
        policy.require_approval_for_writes = true;
        policy.max_cost = Some(1_000_000_000.0);
    })
    .await;
    let v = check(
        f.reader_cookie.clone(),
        format!("SELECT id FROM {table} LIMIT 5"),
    )
    .await;
    assert_eq!(
        v["preflight"],
        json!({"state":"safe","action":"run","label":"Run",
            "hint":"This statement only reads data. Its cost is checked against this database's limit when it runs."})
    );
    f.policy(|policy| policy.require_approval_for_writes = true)
        .await;
    // An agent's check_sql is unchanged by the console's fix: a refused
    // statement comes with `fix` and no suggestions.
    let (_, _, token) = f.agent("Checker", "read").await;
    let (_, v) = tool(
        &f,
        &token,
        "check_sql",
        json!({"task":"Check two","database":f.cluster,"sql":format!("SELECT id FROM {table} WHERE id=1; SELECT 2")}),
    )
    .await;
    assert_eq!(
        (v["verdict"].clone(), v["suggestions"].clone()),
        (json!("deny"), json!([]))
    );
    assert_eq!(v["fix"]["action"], "rewrite_sql");
    assert!(v.get("preflight").is_none());
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_call_cannot_make_a_step_large() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (agent, token_id, token) = f.agent("Loud", "read").await;
    // An argument name of a megabyte and a half, which no tool takes. The
    // refusal names it, and the refusal is what a step keeps as the fix.
    let name = "n".repeat(1_500_000);
    for _ in 0..35 {
        let (failed, v) = tool(
            &f,
            &token,
            "check_sql",
            json!({"task":"Send a long name","database":f.cluster,"sql":"SELECT 1",name.as_str():1}),
        )
        .await;
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "validation");
        // The answer says only the beginning of the name.
        let message = v["error"]["message"].as_str().unwrap();
        assert_eq!(
            message,
            format!("`{}…` is not an argument of this tool", "n".repeat(64))
        );
        assert_eq!(v["error"]["fix"]["hint"], message);
        assert!(v.to_string().len() < 1000, "{}", v.to_string().len());
    }
    // Thirty of them are steps (the bound for one minute), and all of them
    // together take a few kilobytes, in the table and in the answer.
    f.written(agent, 30).await;
    let stored: i64 = sqlx::query_scalar(
        "SELECT sum(pg_column_size(p.*))::int8 FROM agent_steps p JOIN agent_sessions s
         ON s.id=p.session_id WHERE s.agent_id=$1",
    )
    .bind(agent)
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert!(stored < 30 * 600, "{stored} bytes for 30 steps");
    let session = &f.sessions(agent).await[0];
    let listed = f.steps(agent, session, "").await;
    assert_eq!(listed["items"].as_array().unwrap().len(), 30);
    assert!(
        listed.to_string().len() < 30 * 1000,
        "{}",
        listed.to_string().len()
    );
    assert_eq!(listed["items"][0]["fix"]["action"], "fix_arguments");
    // Whatever path a text takes into a step, the writer cuts it: a step
    // made with a megabyte in every text is stored within the limits.
    let huge = "é".repeat(500_000);
    let mut step = crafted(agent, token_id, chrono::Utc::now(), &huge);
    step.tool = huge.clone();
    step.task = Some(huge.clone());
    step.sql = Some(huge.clone());
    step.fix = Some((huge.clone(), huge.clone()));
    assert_eq!(
        steps::persist(&f.db, &[step], steps::SESSION_GAP)
            .await
            .unwrap(),
        1
    );
    let sizes: (i32, i32, i32, i32, i32, i32, bool) = sqlx::query_as(
        "SELECT octet_length(tool),octet_length(task),octet_length(sql),octet_length(outcome),
           octet_length(fix_action),octet_length(fix_hint),sql_truncated
         FROM agent_steps WHERE session_id=$1 ORDER BY n DESC LIMIT 1",
    )
    .bind(session["id"].as_str().unwrap().parse::<Uuid>().unwrap())
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert!(sizes.0 <= 64 && sizes.3 <= 64 && sizes.4 <= 64, "{sizes:?}");
    assert!(
        sizes.1 <= 2000 && sizes.5 <= 1024 && sizes.2 <= 16 * 1024,
        "{sizes:?}"
    );
    assert!(sizes.6);
    let last = f.steps(agent, session, "?after=30").await;
    assert!(
        last.to_string().len() < 40 * 1024,
        "{}",
        last.to_string().len()
    );
    f.close().await;
}

// ---- Limits that hold across nodes ----

/// Backends of the target that wait for a lock on the table.
async fn lock_waiters(target: &sqlx::PgPool, table: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE relation=$1::text::regclass AND NOT granted",
    )
    .bind(table)
    .fetch_one(target)
    .await
    .unwrap()
}
/// Wait until this many backends wait for a lock on the table.
async fn until_waiting(target: &sqlx::PgPool, table: &str, count: i64) {
    let mut found = 0;
    for _ in 0..400 {
        found = lock_waiters(target, table).await;
        if found == count {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(found, count, "backends waiting for the lock");
}
/// Who holds the agent's turn to propose, if anyone.
async fn proposal_holder(db: &sqlx::PgPool, agent: Uuid) -> Option<Uuid> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT proposal_holder FROM agent_limits WHERE agent_id=$1",
    )
    .bind(agent)
    .fetch_optional(db)
    .await
    .unwrap()
    .flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_share_one_call_rate() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let (_, other) = f.node().await;
    let nodes = [f.app.clone(), other];
    let (agent, _, token) = f.agent("Busy", "read").await;
    // 125 calls at once over both nodes: 120 in the minute for the agent,
    // not 120 for each node.
    let calls = (0..125).map(|n| {
        let (app, token) = (nodes[n % 2].clone(), token.clone());
        async move { tool_at(&app, &token, "list_databases", json!({"task":"Flood"})).await }
    });
    let results = futures::future::join_all(calls).await;
    let limited: Vec<&Value> = results
        .iter()
        .filter(|(failed, _)| *failed)
        .map(|(_, v)| v)
        .collect();
    assert_eq!(limited.len(), 5, "{limited:?}");
    assert!(limited.iter().all(|v| v["error"]["code"] == "rate_limited"
        && v["error"]["message"] == "Too many tool calls in one minute"
        && v["error"]["fix"]["action"] == "retry_later"
        && v["error"]["fix"]["retry_after_seconds"] == 60));
    // Each node refuses the next call, whichever node took the earlier ones.
    for node in &nodes {
        let (failed, v) = tool_at(node, &token, "list_databases", json!({"task":"More"})).await;
        assert!(failed && v["error"]["code"] == "rate_limited", "{v}");
    }
    // Another agent has its own minute.
    let (_, _, calm) = f.agent("Calm", "read").await;
    let (failed, v) = tool_at(&nodes[1], &calm, "list_databases", json!({"task":"Look"})).await;
    assert!(!failed, "{v}");
    // The count is one row of the agent, deleted with the agent.
    let rows = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM agent_limits WHERE agent_id=$1")
            .bind(agent)
            .fetch_one(&f.db)
            .await
            .unwrap()
    };
    assert_eq!(rows().await, 1);
    let (s, _) = f
        .request("DELETE", &format!("/agents/{agent}"), &f.owner_cookie, None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(rows().await, 0);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_share_the_streak_of_refused_queries() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let (_, other) = f.node().await;
    let nodes = [f.app.clone(), other];
    let db = json!(f.cluster);
    let vault = format!("SELECT * FROM {}", f.vault);
    let refused =
        |n: usize| json!({"task":"Try the vault","database":db,"sql":format!("{vault} -- {n}")});
    let good = json!({"task":"A good query","database":db,"sql":"SELECT 1"});
    // Five refusals over both nodes stop the agent on both.
    let (agent, _, token) = f.agent("Prober", "read").await;
    for n in 0..5 {
        let (failed, v) = tool_at(&nodes[n % 2], &token, "run_query", refused(n)).await;
        assert!(failed);
        assert_eq!(v["error"]["code"], "query_denied", "{v}");
    }
    let before = f.queries(agent).await;
    for node in &nodes {
        let (failed, v) = tool_at(node, &token, "run_query", good.clone()).await;
        assert!(failed);
        assert_eq!(v["error"]["code"], "too_many_denials", "{v}");
        assert_eq!(v["error"]["message"], "Too many refused queries in a row");
        assert_eq!(v["error"]["fix"]["action"], "stop");
        assert_eq!(v["error"]["fix"]["retry_after_seconds"], 600);
    }
    assert_eq!(f.queries(agent).await, before, "a stopped call ran");
    // Parallel refused calls over both nodes cannot all slip past the
    // breaker: five get the guard's answer, the rest are stopped.
    let (_, _, racer) = f.agent("Racer", "read").await;
    let calls = (0..20).map(|n| {
        let (app, token, arguments) = (nodes[n % 2].clone(), racer.clone(), refused(n));
        async move { tool_at(&app, &token, "run_query", arguments).await }
    });
    let results = futures::future::join_all(calls).await;
    let count = |code: &str| {
        results
            .iter()
            .filter(|(_, v)| v["error"]["code"] == code)
            .count()
    };
    assert_eq!((count("query_denied"), count("too_many_denials")), (5, 15));
    // A success on one node ends the streak on both.
    let (_, _, careful) = f.agent("Careful", "read").await;
    for round in 0..2 {
        for n in 0..4 {
            let (failed, v) = tool_at(
                &nodes[n % 2],
                &careful,
                "run_query",
                refused(round * 10 + n),
            )
            .await;
            assert!(failed);
            assert_eq!(v["error"]["code"], "query_denied", "{v}");
        }
        let (failed, v) = tool_at(&nodes[1 - round], &careful, "run_query", good.clone()).await;
        assert!(!failed, "{v}");
    }
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_give_an_agent_one_proposal_at_a_time_and_share_its_stop() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let (_, other) = f.node().await;
    let nodes = [f.app.clone(), other];
    // A lock on the target table holds a proposal's read check as long as
    // the test needs.
    f.policy(|policy| policy.lock_timeout_ms = 30_000).await;
    let (agent, _, token) = f.agent("Writer", "write").await;
    let db = json!(f.cluster);
    let table = f.table.clone();
    let write = |id: i32| {
        json!({"task":"Fix a note","database":db,
            "sql":format!("UPDATE {table} SET note='fixed' WHERE id={id}")})
    };
    let propose = |node: usize, arguments: Value| {
        let (app, token) = (nodes[node].clone(), token.clone());
        tokio::spawn(async move { tool_at(&app, &token, "propose_write", arguments).await })
    };
    let mut lock = f.target.begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *lock)
        .await
        .unwrap();
    // A proposal on the first node is in its read check, and holds the turn.
    let first = propose(0, write(1));
    until_waiting(&f.target, &table, 1).await;
    assert!(proposal_holder(&f.db, agent).await.is_some());
    // A second proposal on the other node waits for its turn, as it would
    // on one node: it does not reach the database.
    let second = propose(1, write(2));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!second.is_finished());
    assert_eq!(lock_waiters(&f.target, &table).await, 1);
    lock.commit().await.unwrap();
    for task in [first, second] {
        let (failed, v) = task.await.unwrap();
        assert!(!failed, "{v}");
        assert_eq!(v["status"], "pending", "{v}");
    }
    assert_eq!(proposal_holder(&f.db, agent).await, None);
    // A proposal that is cancelled while it holds the turn gives it back at
    // once, not when its lease lapses.
    let mut lock = f.target.begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *lock)
        .await
        .unwrap();
    let cancelled = propose(1, write(3));
    until_waiting(&f.target, &table, 1).await;
    assert!(proposal_holder(&f.db, agent).await.is_some());
    cancelled.abort();
    let mut held = true;
    for _ in 0..200 {
        held = proposal_holder(&f.db, agent).await.is_some();
        if !held {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(!held, "the cancelled proposal kept its turn");
    lock.commit().await.unwrap();
    // Five refused proposals over both nodes stop the agent on both, for
    // the time left from the refusal that reached the limit.
    let blocked = json!({"task":"Probe","database":db,
        "sql":format!("UPDATE {} SET word='x' WHERE id=1", f.vault)});
    for n in 0..5 {
        let (failed, v) = propose(n % 2, blocked.clone()).await.unwrap();
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "query_denied", "{v}");
    }
    for node in [1, 0] {
        let (failed, v) = propose(node, write(4)).await.unwrap();
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "too_many_denials", "{v}");
        assert_eq!(
            v["error"]["message"],
            "Too many refused write requests in a row"
        );
        assert_eq!(v["error"]["fix"]["action"], "stop", "{v}");
        let wait = v["error"]["fix"]["retry_after_seconds"].as_u64().unwrap();
        assert!((590..=600).contains(&wait), "{v}");
    }
    let approvals: i64 = sqlx::query_scalar("SELECT count(*) FROM approvals WHERE agent_id=$1")
        .bind(agent)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(approvals, 2);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turn_left_by_a_crashed_node_does_not_block_the_agent() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (agent, _, token) = f.agent("Survivor", "write").await;
    let db = json!(f.cluster);
    let write = json!({"task":"Fix a note","database":db,
        "sql":format!("UPDATE {} SET note='fixed' WHERE id=1", f.table)});
    // A node took both turns of the agent and crashed: its leases have ended.
    let crashed = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_limits(agent_id,query_holder,query_until,proposal_holder,proposal_until)
         VALUES ($1,$2,now()-interval '1 second',$2,now()-interval '1 second')",
    )
    .bind(agent)
    .bind(crashed)
    .execute(&f.db)
    .await
    .unwrap();
    let quick = Duration::from_secs(5);
    let (failed, v) = tokio::time::timeout(
        quick,
        tool(
            &f,
            &token,
            "run_query",
            json!({"task":"Read","database":db,"sql":"SELECT 1"}),
        ),
    )
    .await
    .unwrap();
    assert!(!failed, "{v}");
    let (failed, v) = tokio::time::timeout(quick, tool(&f, &token, "propose_write", write.clone()))
        .await
        .unwrap();
    assert!(!failed, "{v}");
    let holders: (Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT query_holder,proposal_holder FROM agent_limits WHERE agent_id=$1")
            .bind(agent)
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(holders, (None, None));
    // A turn whose lease has not ended is waited for, until it lapses.
    sqlx::query(
        "UPDATE agent_limits SET proposal_holder=$2,proposal_until=now()+interval '2 seconds'
         WHERE agent_id=$1",
    )
    .bind(agent)
    .bind(crashed)
    .execute(&f.db)
    .await
    .unwrap();
    let started = Instant::now();
    let (failed, v) = tool(&f, &token, "propose_write", write).await;
    assert!(!failed, "{v}");
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proposal_that_lost_its_turn_is_not_stored() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let (_, other) = f.node().await;
    let nodes = [f.app.clone(), other];
    f.policy(|policy| policy.lock_timeout_ms = 30_000).await;
    let (agent, _, token) = f.agent("Writer", "write").await;
    let db = json!(f.cluster);
    let table = f.table.clone();
    let write = |id: i32| {
        json!({"task":"Fix a note","database":db,
            "sql":format!("UPDATE {table} SET note='fixed' WHERE id={id}")})
    };
    let propose = |node: usize, arguments: Value| {
        let (app, token) = (nodes[node].clone(), token.clone());
        tokio::spawn(async move { tool_at(&app, &token, "propose_write", arguments).await })
    };
    // Nine requests wait for a person: room for one more.
    for id in 0..9 {
        let (failed, v) = propose(id as usize % 2, write(id)).await.unwrap();
        assert!(!failed, "{v}");
    }
    let mut lock = f.target.begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *lock)
        .await
        .unwrap();
    // The first node's proposal is in its read check when its lease ends,
    // and the other node's proposal takes the turn and starts its own.
    let first = propose(0, write(20));
    until_waiting(&f.target, &table, 1).await;
    let lost = proposal_holder(&f.db, agent).await.unwrap();
    sqlx::query(
        "UPDATE agent_limits SET proposal_until=now()-interval '1 second' WHERE agent_id=$1",
    )
    .bind(agent)
    .execute(&f.db)
    .await
    .unwrap();
    let second = propose(1, write(21));
    until_waiting(&f.target, &table, 2).await;
    assert_ne!(proposal_holder(&f.db, agent).await, Some(lost));
    lock.commit().await.unwrap();
    let (first, second) = (first.await.unwrap(), second.await.unwrap());
    // The call that lost its turn is refused with an error that exists
    // today; the one that holds it is stored.
    assert!(first.0, "{}", first.1);
    assert_eq!(first.1["error"]["code"], "internal", "{}", first.1);
    assert_eq!(
        first.1["error"]["fix"]["action"], "retry_later",
        "{}",
        first.1
    );
    assert!(!second.0, "{}", second.1);
    let open: i64 =
        sqlx::query_scalar("SELECT count(*) FROM approvals WHERE agent_id=$1 AND status='pending'")
            .bind(agent)
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(open, 10, "at most the limit of open requests is stored");
    // The limit holds for the next proposal on either node.
    for node in [0, 1] {
        let (failed, v) = propose(node, write(30)).await.unwrap();
        assert!(failed, "{v}");
        assert_eq!(v["error"]["code"], "too_many_open_requests", "{v}");
    }
    f.close().await;
}
