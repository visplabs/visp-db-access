#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The audit hash chain against a real PostgreSQL: the order rows are sealed
//! in, what holds sealing back, two nodes, every kind of tampering, a change
//! of the master key, the migration, the batched writer, the status event of
//! the agent login, the two endpoints and the offline command.
//!
//! Other tests use the same PostgreSQL instance at the same time, and a
//! transaction of theirs can hold sealing back for a moment, exactly as the
//! design says. So a test never expects a row to be sealed at once: it seals
//! until the row is, and gives up after two minutes.
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use clap::Parser;
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;
use vda_server::{
    app::{router, AppState},
    audit::{persist, persist_on, Event},
    audit_chain,
    chain::{self, Checkpoint, Kind, Outcome, Status, Step},
    config::Cli,
    crypto::Crypto,
};

const KEY: [u8; 32] = [4; 32];

struct Fixture {
    db: sqlx::PgPool,
    root: sqlx::PgPool,
    url: String,
    schema: String,
    state: AppState,
    writer: tokio::task::JoinHandle<()>,
    app: Router,
    admin: Uuid,
    member: Uuid,
    admin_cookie: String,
    member_cookie: String,
}
async fn pool(url: &str, schema: &str, size: u32) -> sqlx::PgPool {
    let path = format!("SET search_path TO {schema},public");
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(size)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |c, _| {
            let path = path.clone();
            Box::pin(async move {
                sqlx::query(&path).execute(&mut *c).await?;
                sqlx::query("SET TIME ZONE 'UTC'").execute(c).await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap()
}
impl Fixture {
    /// A schema of its own; `None` (the test is skipped) without a database.
    async fn bare() -> Option<(sqlx::PgPool, sqlx::PgPool, String, String)> {
        let Ok(url) = std::env::var("VDA_TEST_DATABASE_URL") else {
            eprintln!("skipped: VDA_TEST_DATABASE_URL is not set");
            return None;
        };
        let root = sqlx::PgPool::connect(&url).await.unwrap();
        let schema = format!("vda_chain_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&root)
            .await
            .unwrap();
        let db = pool(&url, &schema, 24).await;
        Some((db, root, url, schema))
    }
    async fn new() -> Option<Self> {
        let (db, root, url, schema) = Self::bare().await?;
        vda_server::db::migrate(&db).await.unwrap();
        let (state, writer) = Self::node(&db, KEY).await;
        let (admin, member) = (Uuid::new_v4(), Uuid::new_v4());
        for (id, email, role) in [
            (admin, "admin@chain.example", "admin"),
            (member, "member@chain.example", "member"),
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
        let admin_cookie = Self::session(&db, admin).await;
        let member_cookie = Self::session(&db, member).await;
        let app = router(state.clone());
        Some(Self {
            db,
            root,
            url,
            schema,
            state,
            writer,
            app,
            admin,
            member,
            admin_cookie,
            member_cookie,
        })
    }
    /// A node: its own state and caches on the shared metadata store.
    async fn node(db: &sqlx::PgPool, key: [u8; 32]) -> (AppState, tokio::task::JoinHandle<()>) {
        let mut config = Cli::parse_from(["test"]).config;
        config.allow_private_targets = true;
        AppState::new(db.clone(), config, Crypto::new(&key), None)
            .await
            .unwrap()
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
        let mut req = Request::builder()
            .method(method)
            .uri(format!("/api/v1{path}"))
            .header("cookie", cookie)
            .header("x-requested-with", "vda");
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
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 40 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
    fn crypto(&self) -> &Crypto {
        &self.state.core.crypto
    }
    /// Write `count` events, one transaction each, with content that differs.
    async fn events(&self, count: usize) -> Vec<Uuid> {
        let mut ids = Vec::new();
        for n in 0..count {
            let event = event(&format!("test.event.{n}"), Some(self.admin), n);
            persist(&self.db, &event).await.unwrap();
            ids.push(event.id);
        }
        ids
    }
    async fn close(self) {
        self.state.core.tasks.close();
        self.state.core.tasks.wait().await;
        self.state.stop.cancel();
        self.writer.await.unwrap();
        self.state.core.pools.close().await;
        self.db.close().await;
        drop_schema(&self.root, &self.schema).await;
        self.root.close().await;
    }
}
async fn drop_schema(root: &sqlx::PgPool, schema: &str) {
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(root)
        .await
        .unwrap();
}
fn event(action: &str, actor: Option<Uuid>, n: usize) -> Event {
    Event {
        id: Uuid::new_v4(),
        actor_id: actor,
        action: action.into(),
        target_type: (!n.is_multiple_of(3)).then(|| "cluster".to_owned()),
        target_id: (n % 3 == 1).then(Uuid::new_v4),
        ip: n.is_multiple_of(2).then(|| "10.1.2.3".parse().unwrap()),
        details: json!({"n": n, "status": 200, "note": "café ☕", "nested": {"b": [1, 2], "a": null}}),
        created_at: chrono::Utc::now(),
    }
}
/// How many audit rows have no link.
async fn unsealed(db: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_log a WHERE NOT EXISTS
         (SELECT 1 FROM audit_chain c WHERE c.audit_id=a.id)",
    )
    .fetch_one(db)
    .await
    .unwrap()
}
async fn is_sealed(db: &sqlx::PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_chain WHERE audit_id=$1)")
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap()
}
/// Seal until `done` says so. Another test's open transaction may hold
/// sealing back for a while; that is the design, so wait for it.
async fn seal_until<F, Fut>(db: &sqlx::PgPool, crypto: &Crypto, done: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        chain::seal(db, crypto, 500).await.unwrap();
        if done().await {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "rows were not sealed in two minutes"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
/// Seal everything, and return the keys of the links before which a run
/// of the sealer began with another key.
async fn sealing_began(db: &sqlx::PgPool, crypto: &Crypto) -> Vec<String> {
    let start = std::time::Instant::now();
    let mut began = Vec::new();
    loop {
        let sealed = chain::seal(db, crypto, 500).await.unwrap().unwrap();
        began.extend(sealed.previous_key);
        if unsealed(db).await == 0 {
            return began;
        }
        assert!(start.elapsed() < Duration::from_secs(120), "not sealed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn seal_all(db: &sqlx::PgPool, crypto: &Crypto) {
    seal_until(db, crypto, || async {
        // A row that waits behind the sealed part would wait for ever:
        // the sealer went past a transaction that was still open.
        let outcome = verify_all(db, crypto).await;
        assert!(
            outcome.problem.is_none() || outcome.key_id != crypto.chain_key_id(),
            "the chain broke while sealing: {outcome:?}"
        );
        unsealed(db).await == 0
    })
    .await;
}
async fn head_position(db: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(max(position),0) FROM audit_chain")
        .fetch_one(db)
        .await
        .unwrap()
}
async fn verify_all(db: &sqlx::PgPool, crypto: &Crypto) -> Outcome {
    let end = head_position(db).await;
    chain::verify(&mut db.acquire().await.unwrap(), crypto, 1, end)
        .await
        .unwrap()
}
/// The chain is sound as a structure: positions 1..n with no gap, every
/// audit row linked exactly once, links in the order (txid, seq) of their
/// rows, and every link verifies.
async fn assert_sound(db: &sqlx::PgPool, crypto: &Crypto) -> i64 {
    let (links, low, high, rows): (i64, Option<i64>, Option<i64>, i64) = sqlx::query_as(
        "SELECT count(*),min(position),max(position),count(DISTINCT audit_id) FROM audit_chain",
    )
    .fetch_one(db)
    .await
    .unwrap();
    assert_eq!(rows, links, "an audit row has two links");
    if links > 0 {
        assert_eq!((low, high), (Some(1), Some(links)), "positions have a gap");
    }
    // The order of the links is the order of the rows, compared in SQL with
    // the database's own comparison of transaction IDs.
    let disorder: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (
           SELECT c.position,
                  row_number() OVER (ORDER BY a.txid,a.seq) AS place
           FROM audit_chain c JOIN audit_log a ON a.id=c.audit_id) o
         WHERE o.position<>o.place",
    )
    .fetch_one(db)
    .await
    .unwrap();
    assert_eq!(disorder, 0, "links are not in (txid, seq) order");
    let outcome = verify_all(db, crypto).await;
    assert_eq!(outcome.status, Status::Intact, "{outcome:?}");
    assert_eq!((outcome.links, outcome.verified), (links, links));
    links
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rows_written_from_many_connections_are_sealed_once_in_order_without_gaps() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    // Sixteen writers on their own connections: single rows, several rows
    // in one transaction, and transactions that roll back (they leave gaps
    // in `seq`). Two sealers run all the while, with small batches.
    let writers: Vec<_> = (0..16usize)
        .map(|writer| {
            let (db, admin) = (f.db.clone(), f.admin);
            tokio::spawn(async move {
                let mut kept = Vec::new();
                for n in 0..40usize {
                    match (writer + n) % 4 {
                        0 => {
                            let mut tx = db.begin().await.unwrap();
                            for part in 0..3 {
                                let event = event("many.grouped", Some(admin), n * 3 + part);
                                persist_on(&mut tx, &event).await.unwrap();
                                kept.push(event.id);
                            }
                            // Stay open while others commit with later
                            // transaction IDs.
                            tokio::time::sleep(Duration::from_millis(5 + (n % 20) as u64)).await;
                            tx.commit().await.unwrap();
                        }
                        1 => {
                            let mut tx = db.begin().await.unwrap();
                            let event = event("many.rolled_back", Some(admin), n);
                            persist_on(&mut tx, &event).await.unwrap();
                            tx.rollback().await.unwrap();
                        }
                        _ => {
                            let event = event("many.single", None, n);
                            persist(&db, &event).await.unwrap();
                            kept.push(event.id);
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                    }
                }
                kept
            })
        })
        .collect();
    let stop = tokio_util::sync::CancellationToken::new();
    // One sealer takes everything it may, as often as it can, so that it
    // is always right behind the writers; the other takes a few rows at a
    // time and gets in its way.
    let sealers: Vec<_> = [500, 7]
        .into_iter()
        .map(|batch| {
            let (db, crypto, stop) = (f.db.clone(), f.crypto().clone(), stop.clone());
            tokio::spawn(async move {
                let mut sealed = 0;
                while !stop.is_cancelled() {
                    if let Some(done) = chain::seal(&db, &crypto, batch).await.unwrap() {
                        sealed += done.rows;
                    }
                    tokio::task::yield_now().await;
                }
                sealed
            })
        })
        .collect();
    let mut kept = Vec::new();
    for writer in writers {
        kept.extend(writer.await.unwrap());
    }
    seal_all(&f.db, f.crypto()).await;
    stop.cancel();
    let mut by_sealers = 0;
    for sealer in sealers {
        by_sealers += sealer.await.unwrap();
    }
    assert!(by_sealers > 0, "the concurrent sealers sealed nothing");
    let links = assert_sound(&f.db, f.crypto()).await;
    assert_eq!(links as usize, kept.len());
    let rolled_back: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action='many.rolled_back'")
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(rolled_back, 0);
    for id in kept {
        assert!(is_sealed(&f.db, id).await);
    }
    // `seq` has gaps where transactions rolled back; `position` has none.
    let (seqs, span): (i64, i64) =
        sqlx::query_as("SELECT count(*),max(seq)-min(seq)+1 FROM audit_log")
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert!(span > seqs, "expected gaps in seq: {seqs} rows over {span}");
    // The rows of one transaction stay together and in the order written.
    let split: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (
           SELECT a.txid,max(c.position)-min(c.position)+1 AS span,count(*) AS rows
           FROM audit_chain c JOIN audit_log a ON a.id=c.audit_id GROUP BY a.txid) t
         WHERE t.span<>t.rows",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(split, 0);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_transaction_holds_sealing_back_and_releases_it() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(3).await;
    seal_all(&f.db, f.crypto()).await;
    // A transaction inserts an audit row and stays open.
    let mut open = f.db.begin().await.unwrap();
    let held = event("held.open", Some(f.admin), 0);
    persist_on(&mut open, &held).await.unwrap();
    // Rows committed after it began to write must wait for it: it may still
    // commit a row that sorts before them.
    let later = f.events(4).await;
    let before = head_position(&f.db).await;
    for _ in 0..40 {
        let sealed = chain::seal(&f.db, f.crypto(), 500).await.unwrap().unwrap();
        assert_eq!(sealed.rows, 0, "sealed past an open transaction");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(head_position(&f.db).await, before);
    for id in &later {
        assert!(!is_sealed(&f.db, *id).await);
    }
    // The delay is visible.
    let mut connection = f.db.acquire().await.unwrap();
    let head = chain::head(&mut connection).await.unwrap();
    let backlog = chain::backlog(&mut connection, head.as_ref())
        .await
        .unwrap();
    assert_eq!(backlog.unsealed, 4, "{backlog:?}");
    assert!(
        backlog.oldest_unsealed_seconds.unwrap() >= 1.0,
        "{backlog:?}"
    );
    drop(connection);
    // It commits: its row and the later rows are sealed, its row first.
    open.commit().await.unwrap();
    seal_all(&f.db, f.crypto()).await;
    let position = |id: Uuid| {
        let db = f.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT position FROM audit_chain WHERE audit_id=$1")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    let first = position(held.id).await;
    assert_eq!(first, before + 1);
    for (index, id) in later.iter().enumerate() {
        assert_eq!(position(*id).await, first + 1 + index as i64);
    }
    // A transaction that rolls back releases the rows behind it as well,
    // and leaves no row and no gap in the positions.
    let mut open = f.db.begin().await.unwrap();
    let gone = event("held.rolled_back", Some(f.admin), 1);
    persist_on(&mut open, &gone).await.unwrap();
    let after = f.events(2).await;
    assert_eq!(
        chain::seal(&f.db, f.crypto(), 500)
            .await
            .unwrap()
            .unwrap()
            .rows,
        0
    );
    open.rollback().await.unwrap();
    seal_all(&f.db, f.crypto()).await;
    assert!(!is_sealed(&f.db, gone.id).await);
    assert!(is_sealed(&f.db, after[1]).await);
    // A transaction that is open but has written nothing has no transaction
    // ID yet, and holds nothing back. When it writes, it gets an ID above
    // every row already sealed, so its row sorts after them.
    let mut idle = f.db.begin().await.unwrap();
    sqlx::query("SELECT count(*) FROM audit_log")
        .execute(&mut *idle)
        .await
        .unwrap();
    let ahead = f.events(1).await;
    seal_until(&f.db, f.crypto(), || is_sealed(&f.db, ahead[0])).await;
    let late = event("held.late", Some(f.admin), 2);
    persist_on(&mut idle, &late).await.unwrap();
    idle.commit().await.unwrap();
    seal_all(&f.db, f.crypto()).await;
    assert!(position(late.id).await > position(ahead[0]).await);
    assert_sound(&f.db, f.crypto()).await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_never_fork_the_chain() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    // A second node with its own pool, state and caches.
    let other_db = pool(&f.url, &f.schema, 8).await;
    let (other, other_writer) = Fixture::node(&other_db, KEY).await;
    // Both nodes run the real tick while rows are written through both.
    let writing: Vec<_> = [f.db.clone(), other_db.clone()]
        .into_iter()
        .map(|db| {
            tokio::spawn(async move {
                for n in 0..150 {
                    persist(&db, &event("fork.event", None, n)).await.unwrap();
                }
            })
        })
        .collect();
    let stop = tokio_util::sync::CancellationToken::new();
    let ticking: Vec<_> = [f.state.clone(), other.clone()]
        .into_iter()
        .map(|state| {
            let stop = stop.clone();
            tokio::spawn(async move {
                let mut sealed = 0;
                while !stop.is_cancelled() {
                    sealed += audit_chain::seal(&state, 3).await.unwrap();
                }
                sealed
            })
        })
        .collect();
    for task in writing {
        task.await.unwrap();
    }
    seal_all(&f.db, f.crypto()).await;
    stop.cancel();
    let mut shares = Vec::new();
    for task in ticking {
        shares.push(task.await.unwrap());
    }
    assert_eq!(assert_sound(&f.db, f.crypto()).await, 300);
    assert_eq!(shares.iter().sum::<u64>(), 300, "{shares:?}");
    // While one session seals, the other gets nothing to do: it does not
    // wait and does not read the head.
    let mut holder = f.db.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext(current_schema()))")
        .bind(chain::SEAL_LOCK)
        .execute(&mut *holder)
        .await
        .unwrap();
    f.events(2).await;
    assert_eq!(chain::seal(&other_db, f.crypto(), 500).await.unwrap(), None);
    holder.rollback().await.unwrap();
    seal_all(&other_db, f.crypto()).await;
    // And without the lock: two sessions that both read the same head and
    // both append to it cannot both commit. The second waits for the first
    // and is then refused by the primary key on `position`.
    let end = head_position(&f.db).await;
    let append =
        "INSERT INTO audit_chain(position,audit_id,txid,seq,key_id,segment_start,prev_hash,hash)
                  VALUES ($1,$2,'1',$3,'k',$1,$4,$4)";
    let mut one = f.db.begin().await.unwrap();
    sqlx::query(append)
        .bind(end + 1)
        .bind(Uuid::new_v4())
        .bind(1i64)
        .bind(chain::GENESIS)
        .execute(&mut *one)
        .await
        .unwrap();
    let racing = {
        let db = other_db.clone();
        tokio::spawn(async move {
            let mut two = db.begin().await.unwrap();
            let result = sqlx::query(append)
                .bind(end + 1)
                .bind(Uuid::new_v4())
                .bind(2i64)
                .bind(chain::GENESIS)
                .execute(&mut *two)
                .await;
            (result, two.commit().await)
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!racing.is_finished(), "the second append did not wait");
    one.commit().await.unwrap();
    let (result, _) = racing.await.unwrap();
    let error = result.unwrap_err();
    assert!(
        error
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation()),
        "{error}"
    );
    assert_eq!(head_position(&f.db).await, end + 1);
    other.stop.cancel();
    other_writer.await.unwrap();
    other_db.close().await;
    f.close().await;
}

/// The links of a sealed chain: position, audit row, transaction ID, seq.
async fn links(db: &sqlx::PgPool) -> Vec<(i64, Uuid, String, i64)> {
    sqlx::query_as("SELECT position,audit_id,txid::text,seq FROM audit_chain ORDER BY position")
        .fetch_all(db)
        .await
        .unwrap()
}
/// Do what someone with full access to the database could do, then check
/// the chain, then undo it. Everything happens in one transaction that is
/// rolled back, so every case starts from the same intact chain.
async fn after(
    f: &Fixture,
    crypto: &Crypto,
    expect: Option<&Checkpoint>,
    statements: &[String],
) -> (Outcome, Option<chain::Problem>, i64) {
    let mut connection = f.db.acquire().await.unwrap();
    sqlx::query("BEGIN")
        .execute(&mut *connection)
        .await
        .unwrap();
    // The append-only triggers do not stop an owner of the tables.
    for sql in [
        "DROP TRIGGER audit_immutable ON audit_log",
        "DROP TRIGGER audit_chain_immutable ON audit_chain",
        "ALTER TABLE audit_chain DROP CONSTRAINT audit_chain_position_check",
        "ALTER TABLE audit_chain DROP CONSTRAINT audit_chain_segment_check",
    ] {
        sqlx::query(sql).execute(&mut *connection).await.unwrap();
    }
    for sql in statements {
        sqlx::raw_sql(sql)
            .execute(&mut *connection)
            .await
            .unwrap_or_else(|error| panic!("{sql}: {error}"));
    }
    let end: i64 = sqlx::query_scalar("SELECT COALESCE(max(position),0) FROM audit_chain")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    let outcome = chain::verify(&mut connection, crypto, 1, end)
        .await
        .unwrap();
    let lost = match expect {
        Some(expect) => chain::check_checkpoint(&mut connection, expect)
            .await
            .unwrap(),
        None => None,
    };
    let head = chain::head(&mut connection).await.unwrap();
    let waiting = chain::backlog(&mut connection, head.as_ref())
        .await
        .unwrap()
        .unsealed;
    sqlx::query("ROLLBACK")
        .execute(&mut *connection)
        .await
        .unwrap();
    (outcome, lost, waiting)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_kind_of_tampering_is_found_with_its_kind_and_position() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(12).await;
    seal_all(&f.db, f.crypto()).await;
    assert_eq!(assert_sound(&f.db, f.crypto()).await, 12);
    let chain_links = links(&f.db).await;
    let head = chain::head(&mut f.db.acquire().await.unwrap())
        .await
        .unwrap()
        .unwrap();
    let saved = Checkpoint {
        position: head.position,
        hash: head.hash.clone(),
        key_id: Some(head.key_id.clone()),
    };
    // Position 5 holds event 4: it has an address, a target type and a
    // target, so every column has a value to change.
    let (position, id, txid, seq) = chain_links[4].clone();
    assert_eq!(position, 5);
    let check = |statements: Vec<String>| {
        let (f, saved) = (&f, &saved);
        async move { after(f, f.crypto(), Some(saved), &statements).await }
    };
    // Nothing changed: intact, and the checkpoint holds.
    let (outcome, lost, waiting) = check(vec![]).await;
    assert_eq!(outcome.status, Status::Intact);
    assert_eq!((outcome.links, lost, waiting), (12, None, 0));

    // A change of any column of a sealed row.
    let other = f.member;
    for (column, change) in [
        ("actor_id", format!("actor_id='{other}'")),
        ("actor_id to null", "actor_id=NULL".to_owned()),
        ("action", "action=action||'x'".to_owned()),
        ("action case", "action=upper(action)".to_owned()),
        ("target_type", "target_type='agent'".to_owned()),
        ("target_type to null", "target_type=NULL".to_owned()),
        ("target_id", format!("target_id='{other}'")),
        ("target_id to null", "target_id=NULL".to_owned()),
        ("ip", "ip='10.1.2.4'".to_owned()),
        ("ip mask", "ip='10.1.2.3/24'".to_owned()),
        ("ip to null", "ip=NULL".to_owned()),
        (
            "details value",
            "details=jsonb_set(details,'{status}','201')".to_owned(),
        ),
        (
            "details added key",
            "details=details||'{\"x\":1}'".to_owned(),
        ),
        ("details removed key", "details=details-'note'".to_owned()),
        (
            "details nested",
            "details=jsonb_set(details,'{nested,b,0}','9')".to_owned(),
        ),
        (
            "details type",
            "details=jsonb_set(details,'{status}','\"200\"')".to_owned(),
        ),
        (
            "created_at",
            "created_at=created_at+interval '1 microsecond'".to_owned(),
        ),
        ("created_at infinity", "created_at='infinity'".to_owned()),
        ("seq", "seq=seq+100000".to_owned()),
        ("txid", "txid='1'".to_owned()),
        (
            "txid later",
            "txid=(txid::text::bigint+100000)::text::xid8".to_owned(),
        ),
    ] {
        let (outcome, _, _) = check(vec![format!(
            "UPDATE audit_log SET {change} WHERE id='{id}'"
        )])
        .await;
        let found = outcome
            .problem
            .unwrap_or_else(|| panic!("{column}: no problem"));
        assert_eq!(outcome.status, Status::Broken, "{column}");
        assert_eq!(
            (found.kind, found.position, found.audit_id, found.seq),
            (Kind::RowChanged, 5, Some(id), Some(seq)),
            "{column}"
        );
        // What comes before the change is still counted as good.
        assert_eq!((outcome.links, outcome.to_position), (4, 4), "{column}");
    }
    // A new ID is a deleted row and a row that was put in; the missing row
    // is at the link, so it comes first.
    let (outcome, _, _) = check(vec![format!(
        "UPDATE audit_log SET id=gen_random_uuid() WHERE id='{id}'"
    )])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::RowMissing, 5));

    // Only the order of the keys of `details`, or the spelling of a number
    // in it, is not a change: `jsonb` does not keep either.
    let (outcome, _, _) = check(vec![format!(
        "UPDATE audit_log SET details='{{\"status\": 2e2, \"nested\": {{\"a\": null, \"b\": [1.0, 2]}},
          \"note\": \"caf\\u00e9 \\u2615\", \"n\": 4.00}}'::jsonb WHERE id='{id}'"
    )])
    .await;
    assert_eq!(outcome.status, Status::Intact, "{outcome:?}");
    assert_eq!(outcome.verified, 12);

    // A deleted row: its link stays and says so.
    let (outcome, _, _) = check(vec![format!("DELETE FROM audit_log WHERE id='{id}'")]).await;
    let found = outcome.problem.unwrap();
    assert_eq!(
        (found.kind, found.position, found.audit_id, found.seq),
        (Kind::RowMissing, 5, Some(id), Some(seq))
    );
    // A deleted row and its link: the positions have a gap.
    let both = vec![
        format!("DELETE FROM audit_log WHERE id='{id}'"),
        "DELETE FROM audit_chain WHERE position=5".to_owned(),
    ];
    let (outcome, _, _) = check(both.clone()).await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 5));
    assert_eq!(outcome.links, 4);
    // ... and the gap closed by numbering the later links again: the link
    // now at 5 names a link before it that is not the link at 4.
    let mut renumbered = both.clone();
    renumbered.push("UPDATE audit_chain SET position=-position WHERE position>5".to_owned());
    renumbered.push("UPDATE audit_chain SET position=-position-1 WHERE position<0".to_owned());
    let (outcome, _, _) = check(renumbered).await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 5));
    // The first row and its link.
    let (outcome, _, _) = check(vec![
        format!("DELETE FROM audit_log WHERE id='{}'", chain_links[0].1),
        "DELETE FROM audit_chain WHERE position=1".to_owned(),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 1));

    // The end removed, rows and links: what is left verifies, because
    // nothing in the database says there was more. A checkpoint saved
    // outside does.
    let tail = vec![
        "DELETE FROM audit_log WHERE id IN (SELECT audit_id FROM audit_chain WHERE position>9)"
            .to_owned(),
        "DELETE FROM audit_chain WHERE position>9".to_owned(),
    ];
    let (outcome, lost, waiting) = check(tail.clone()).await;
    assert_eq!(outcome.status, Status::Intact);
    assert_eq!((outcome.links, waiting), (9, 0));
    let lost = lost.unwrap();
    assert_eq!((lost.kind, lost.position), (Kind::ChainTruncated, 10));
    // Only the last links removed: the rows look as if they waited to be
    // sealed, and would be sealed again. The checkpoint still says no.
    let (outcome, lost, waiting) = check(tail.into_iter().skip(1).collect()).await;
    assert_eq!((outcome.status, waiting), (Status::Intact, 3));
    assert_eq!(lost.unwrap().kind, Kind::ChainTruncated);
    // A checkpoint with a hash that was never in the chain.
    let wrong = Checkpoint {
        position: 12,
        hash: chain::GENESIS.to_owned(),
        key_id: None,
    };
    let (_, lost, _) = after(&f, f.crypto(), Some(&wrong), &[]).await;
    assert_eq!(lost.unwrap().kind, Kind::CheckpointMismatch);
    // The right hash under the name of another key.
    let renamed = Checkpoint {
        key_id: Some("0123456789abcdef".to_owned()),
        ..saved.clone()
    };
    let (_, lost, _) = after(&f, f.crypto(), Some(&renamed), &[]).await;
    let lost = lost.unwrap();
    assert_eq!((lost.kind, lost.position), (Kind::CheckpointMismatch, 12));
    assert!(lost.message.contains("relabelled"), "{}", lost.message);
    // A checkpoint that was saved without the key's name still holds.
    let unnamed = Checkpoint {
        key_id: None,
        ..saved.clone()
    };
    assert_eq!(after(&f, f.crypto(), Some(&unnamed), &[]).await.1, None);

    // Two links exchanged.
    let (outcome, _, _) = check(vec![
        "UPDATE audit_chain SET position=-5 WHERE position=5".to_owned(),
        "UPDATE audit_chain SET position=5 WHERE position=6".to_owned(),
        "UPDATE audit_chain SET position=6 WHERE position=-5".to_owned(),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 5));
    // Two rows exchanged in the order, links and all: every link still
    // names the link before it by the stored value, so it is the hash, made
    // over the position, that fails.
    let (outcome, _, _) = check(vec![
        "UPDATE audit_chain SET position=-5 WHERE position=5".to_owned(),
        "UPDATE audit_chain SET position=5 WHERE position=6".to_owned(),
        "UPDATE audit_chain SET position=6 WHERE position=-5".to_owned(),
        "UPDATE audit_chain a SET prev_hash=b.prev_hash FROM
           (SELECT position,prev_hash FROM audit_chain WHERE position IN (5,6)) b
         WHERE a.position IN (5,6) AND a.position<>b.position"
            .to_owned(),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!(found.position, 5, "{found:?}");
    assert!(matches!(found.kind, Kind::ChainBroken | Kind::RowChanged));
    // A link changed: its hash, the hash it names, the place it claims.
    for (what, change, kind) in [
        ("hash", "hash=md5('a')||md5('b')", Kind::RowChanged),
        ("hash not hex", "hash='x'", Kind::RowChanged),
        (
            "prev_hash",
            "prev_hash=md5('a')||md5('b')",
            Kind::ChainBroken,
        ),
        ("seq", "seq=seq+100000", Kind::RowChanged),
        ("seq back", "seq=0", Kind::RowChanged),
        ("txid", "txid='1'", Kind::ChainBroken),
        ("audit_id", "audit_id=gen_random_uuid()", Kind::RowMissing),
        // The start of the run is inside the hash.
        ("segment_start", "segment_start=5", Kind::RowChanged),
        ("segment_start back", "segment_start=0", Kind::RowChanged),
        // The name of the key is not; the run it stands in gives it away.
        ("key_id", "key_id='aaaaaaaaaaaaaaaa'", Kind::ChainBroken),
    ] {
        let (outcome, _, _) = check(vec![format!(
            "UPDATE audit_chain SET {change} WHERE position=5"
        )])
        .await;
        let found = outcome.problem.unwrap_or_else(|| panic!("{what}"));
        assert_eq!((found.kind, found.position), (kind, 5), "{what}");
    }

    // A row put in behind the sealed frontier, dated back: it sorts just
    // before the row at 5 and has no link.
    let forged = Uuid::new_v4();
    let (outcome, _, _) = check(vec![format!(
        "INSERT INTO audit_log(id,action,details,created_at,seq,txid)
         VALUES ('{forged}','forged.event','{{}}',now()-interval '1 day',-5,'{txid}')"
    )])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!(
        (found.kind, found.position, found.audit_id, found.seq),
        (Kind::RowInserted, 5, Some(forged), Some(-5))
    );
    assert_eq!(outcome.status, Status::Broken);
    // The rows before the place where it sorts are still good.
    assert_eq!((outcome.links, outcome.to_position), (4, 4));
    // ... before every sealed row.
    let (outcome, _, _) = check(vec![format!(
        "INSERT INTO audit_log(id,action,seq,txid) VALUES ('{forged}','forged.event',-5,'0')"
    )])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::RowInserted, 1));
    // A row put in with a transaction ID far ahead is never sealed and
    // breaks nothing; it shows as a row that waits, for ever.
    let (outcome, _, waiting) = check(vec![format!(
        "INSERT INTO audit_log(id,action,seq,txid)
         VALUES ('{forged}','forged.event',-5,'4611686018427387904')"
    )])
    .await;
    assert_eq!((outcome.status, waiting), (Status::Intact, 1));

    // The whole chain thrown away and made again by someone without the
    // master key: with the real key's name, the first link does not verify.
    let thief = Crypto::new(&[9; 32]);
    let mut prev = chain::GENESIS.to_owned();
    let mut rebuilt = vec!["DELETE FROM audit_chain".to_owned()];
    let mut relabelled = rebuilt.clone();
    let rows: Vec<chain::Row> = sqlx::query_as(&format!(
        "SELECT {} FROM audit_log a ORDER BY a.txid,a.seq",
        chain::ROW_COLUMNS
    ))
    .fetch_all(&f.db)
    .await
    .unwrap();
    for (index, row) in rows.iter().enumerate() {
        let position = index as i64 + 1;
        let hash =
            chain::link_hash(&thief, position, 1, &prev, &chain::canonical_row(row)).unwrap();
        for (script, key_id) in [
            (&mut rebuilt, f.crypto().chain_key_id()),
            (&mut relabelled, thief.chain_key_id()),
        ] {
            script.push(format!(
                "INSERT INTO audit_chain(position,audit_id,txid,seq,key_id,segment_start,prev_hash,hash)
                 VALUES ({position},'{}','{}',{},'{key_id}',1,'{prev}','{hash}')",
                row.id, row.txid, row.seq
            ));
        }
        prev = hash;
    }
    let (outcome, lost, _) = check(rebuilt).await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::RowChanged, 1));
    assert_eq!(lost.unwrap().kind, Kind::CheckpointMismatch);
    // ... and under the thief's own key name it is never called intact:
    // nothing in it is verified.
    let (outcome, lost, _) = check(relabelled).await;
    assert_eq!(outcome.status, Status::Partial);
    assert_eq!((outcome.links, outcome.verified), (12, 0));
    assert_eq!(
        outcome.unverifiable,
        [chain::Segment {
            key_id: thief.chain_key_id(),
            first_position: 1,
            last_position: 12
        }]
    );
    assert_eq!(lost.unwrap().kind, Kind::CheckpointMismatch);

    // After all of that the real chain is as it was.
    assert_eq!(assert_sound(&f.db, f.crypto()).await, 12);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_master_key_cannot_verify_old_links_and_starts_a_segment_bound_to_them() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(6).await;
    seal_all(&f.db, f.crypto()).await;
    let old = f.crypto().clone();
    let new = Crypto::new(&[5; 32]);
    // With another key nothing is verified, and nothing is called intact.
    let outcome = verify_all(&f.db, &new).await;
    assert_eq!(outcome.status, Status::Partial);
    assert_eq!((outcome.links, outcome.verified), (6, 0));
    assert_eq!(outcome.key_id, new.chain_key_id());
    assert_eq!(outcome.unverifiable[0].key_id, old.chain_key_id());
    assert_eq!(
        (
            outcome.unverifiable[0].first_position,
            outcome.unverifiable[0].last_position
        ),
        (1, 6)
    );
    // The gateway now runs with the new key: sealing goes on in a new
    // segment, and says that it began one.
    f.events(4).await;
    assert_eq!(sealing_began(&f.db, &new).await, [old.chain_key_id()]);
    f.events(1).await;
    assert!(sealing_began(&f.db, &new).await.is_empty());
    let key_ids: Vec<String> =
        sqlx::query_scalar("SELECT key_id FROM audit_chain ORDER BY position")
            .fetch_all(&f.db)
            .await
            .unwrap();
    assert_eq!(key_ids[..6], vec![old.chain_key_id(); 6]);
    assert_eq!(key_ids[6..], vec![new.chain_key_id(); 5]);
    // The first link of the new segment is made over the last hash of the
    // old one.
    let (last_old, first_prev): (String, String) = sqlx::query_as(
        "SELECT (SELECT hash FROM audit_chain WHERE position=6),
                (SELECT prev_hash FROM audit_chain WHERE position=7)",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(last_old, first_prev);
    // Each key verifies its own segment and reports the other.
    let with_new = verify_all(&f.db, &new).await;
    assert_eq!(with_new.status, Status::Partial);
    assert_eq!((with_new.links, with_new.verified), (11, 5));
    assert_eq!(with_new.unverifiable.len(), 1);
    let with_old = verify_all(&f.db, &old).await;
    assert_eq!(with_old.status, Status::Partial);
    assert_eq!((with_old.links, with_old.verified), (11, 6));
    assert_eq!(
        (
            with_old.unverifiable[0].first_position,
            with_old.unverifiable[0].last_position
        ),
        (7, 11)
    );
    // A second change of key: two segments that the third key cannot verify.
    f.events(1).await;
    let third = Crypto::new(&[6; 32]);
    assert_eq!(sealing_began(&f.db, &third).await, [new.chain_key_id()]);
    let outcome = verify_all(&f.db, &third).await;
    assert_eq!(outcome.unverifiable.len(), 2, "{outcome:?}");
    assert_eq!(outcome.verified, 1);
    // What the new key can still see in the old segment: its structure. A
    // deleted row, a deleted link, and the end of the old segment changed.
    let old_links = links(&f.db).await;
    for (statements, kind, position) in [
        (
            vec![format!(
                "DELETE FROM audit_log WHERE id='{}'",
                old_links[2].1
            )],
            Kind::RowMissing,
            3,
        ),
        (
            vec!["DELETE FROM audit_chain WHERE position=3".to_owned()],
            Kind::ChainBroken,
            3,
        ),
        (
            // The last hash of the old segment: the new segment's first
            // link was made over the real one.
            vec!["UPDATE audit_chain SET hash=md5('a')||md5('b') WHERE position=6".to_owned()],
            Kind::ChainBroken,
            7,
        ),
    ] {
        let (outcome, _, _) = after(&f, &new, None, &statements).await;
        let found = outcome.problem.unwrap();
        assert_eq!((found.kind, found.position), (kind, position));
    }
    // What it cannot see: a change inside an old row. Only the old key
    // finds it. This is why an old key is kept, offline, after a change.
    let change = vec![format!(
        "UPDATE audit_log SET action='changed' WHERE id='{}'",
        old_links[2].1
    )];
    let (outcome, _, _) = after(&f, &new, None, &change).await;
    assert_eq!(outcome.status, Status::Partial);
    let (outcome, _, _) = after(&f, &old, None, &change).await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::RowChanged, 3));
    // A link of the current key relabelled as another key's, to hide a
    // change in its row, does not pass as a link that cannot be verified:
    // it stands in a run of links of the current key.
    let relabel = |extra: &str| {
        vec![
            format!("UPDATE audit_chain SET key_id='someone'{extra} WHERE position=8"),
            format!(
                "UPDATE audit_log SET action='changed' WHERE id='{}'",
                old_links[7].1
            ),
        ]
    };
    let (outcome, _, _) = after(&f, &new, None, &relabel("")).await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 8));
    // ... and with its stored start made to fit, the link after it does not.
    let (outcome, _, _) = after(&f, &new, None, &relabel(",segment_start=8")).await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 9));
    assert!(found.message.contains("relabelled"), "{}", found.message);
    // The first key comes back: A, B, C, A. Every run names its own start,
    // and each key verifies its runs and finds nothing wrong in the others.
    f.events(2).await;
    assert_eq!(sealing_began(&f.db, &old).await, [third.chain_key_id()]);
    let starts: Vec<i64> =
        sqlx::query_scalar("SELECT segment_start FROM audit_chain ORDER BY position")
            .fetch_all(&f.db)
            .await
            .unwrap();
    assert_eq!(starts, [1, 1, 1, 1, 1, 1, 7, 7, 7, 7, 7, 12, 13, 13]);
    for (key, verified, segments) in [(&old, 8, 2), (&new, 5, 3), (&third, 1, 3)] {
        let outcome = verify_all(&f.db, key).await;
        assert_eq!(outcome.problem, None, "{outcome:?}");
        assert_eq!(outcome.status, Status::Partial);
        assert_eq!((outcome.links, outcome.verified), (14, verified));
        assert_eq!(outcome.unverifiable.len(), segments, "{outcome:?}");
        // Bounded checks that begin at every position pass as well.
        for from in 1..=14 {
            let part = chain::verify(&mut f.db.acquire().await.unwrap(), key, from, 14)
                .await
                .unwrap();
            assert_eq!(part.problem, None, "from {from}: {part:?}");
            assert_eq!(part.links, 15 - from);
        }
    }
    f.close().await;
}

/// Someone with the database changes a sealed row and tries to make its
/// link pass for one that another master key sealed, so that the check says
/// "cannot be verified" and not "changed".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relabelling_a_link_as_another_keys_does_not_hide_a_changed_row() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(12).await;
    seal_all(&f.db, f.crypto()).await;
    assert_eq!(assert_sound(&f.db, f.crypto()).await, 12);
    let chain_links = links(&f.db).await;
    let head = chain::head(&mut f.db.acquire().await.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.segment_start, 1);
    let saved = Checkpoint {
        position: head.position,
        hash: head.hash.clone(),
        key_id: Some(head.key_id.clone()),
    };
    let other = "0123456789abcdef";
    let change = format!(
        "UPDATE audit_log SET action='changed' WHERE id='{}'",
        chain_links[4].1
    );
    let attack = |statements: Vec<String>| {
        let (f, saved) = (&f, &saved);
        async move { after(f, f.crypto(), Some(saved), &statements).await }
    };
    // (a) The row at 5 is changed and only its link is relabelled. The
    // link claims a run that began at 1 behind a link of another key.
    let (outcome, _, _) = attack(vec![
        change.clone(),
        format!("UPDATE audit_chain SET key_id='{other}' WHERE position=5"),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!(outcome.status, Status::Broken);
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 5));
    assert!(found.message.contains("relabelled"), "{}", found.message);
    // The stored start of the relabelled link made to fit: it is checked
    // as stored for a link of another key, so that link passes as "cannot
    // be verified". The link after it does not: its hash proves that its
    // run began at 1, and the link before it is not of its key.
    let (outcome, _, _) = attack(vec![
        change.clone(),
        format!("UPDATE audit_chain SET key_id='{other}',segment_start=5 WHERE position=5"),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!(outcome.status, Status::Broken);
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 6));
    assert!(
        found.message.contains("relabelled") && found.message.contains("position 1"),
        "{}",
        found.message
    );
    assert_eq!((outcome.links, outcome.verified), (5, 4));
    // The start of the link after it cannot be made to fit: it is hashed.
    let (outcome, _, _) = attack(vec![
        change.clone(),
        format!("UPDATE audit_chain SET key_id='{other}',segment_start=5 WHERE position=5"),
        "UPDATE audit_chain SET segment_start=6 WHERE position>=6".to_owned(),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::RowChanged, 6));
    // (b) The whole start of the run relabelled, up to and with the
    // changed row, as one run of another key.
    let (outcome, _, _) = attack(vec![
        change.clone(),
        format!("UPDATE audit_chain SET key_id='{other}' WHERE position<=5"),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!(outcome.status, Status::Broken);
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 6));
    assert_eq!((outcome.links, outcome.verified), (5, 0));
    // ... and a relabelled stretch in the middle that does not hold the
    // changed row's neighbours: the same.
    let (outcome, _, _) = attack(vec![
        change.clone(),
        format!("UPDATE audit_chain SET key_id='{other}',segment_start=3 WHERE position BETWEEN 3 AND 7"),
    ])
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 8));
    // What is left: every link of the current key from the changed row to
    // the head relabelled. No link of the key is left behind it to object,
    // so the check says "cannot be verified", like a chain whose end was
    // cut off says "intact". A checkpoint from outside names the key of
    // the head, and that no longer fits.
    let to_the_head = vec![
        change.clone(),
        format!("UPDATE audit_chain SET key_id='{other}',segment_start=5 WHERE position>=5"),
    ];
    let (outcome, lost, _) = attack(to_the_head.clone()).await;
    assert_eq!(outcome.status, Status::Partial);
    assert_eq!((outcome.links, outcome.verified), (12, 4));
    let lost = lost.unwrap();
    assert_eq!((lost.kind, lost.position), (Kind::CheckpointMismatch, 12));
    assert!(lost.message.contains("relabelled"), "{}", lost.message);
    // A checkpoint that was saved without the key's name does not see it.
    let unnamed = Checkpoint {
        key_id: None,
        ..saved.clone()
    };
    assert_eq!(
        after(&f, f.crypto(), Some(&unnamed), &to_the_head).await.1,
        None
    );
    // (d) On the intact chain, a bounded check that begins inside the run
    // passes, through the function and through the endpoint.
    for from in 1..=12 {
        let part = chain::verify(&mut f.db.acquire().await.unwrap(), f.crypto(), from, 12)
            .await
            .unwrap();
        assert_eq!(part.status, Status::Intact, "from {from}: {part:?}");
        assert_eq!((part.links, part.verified), (13 - from, 13 - from));
    }
    for (body, from, to) in [
        (json!({"from_position": 7, "limit": 3}), 7, 9),
        (json!({"limit": 5}), 8, 12),
        (json!({"from_position": 12}), 12, 12),
    ] {
        let (s, v) = f
            .request("POST", "/audit/verify", &f.admin_cookie, Some(body.clone()))
            .await;
        assert_eq!(s, StatusCode::OK, "{body} {v}");
        assert_eq!(v["status"], "intact", "{body} {v}");
        assert_eq!(
            (v["from_position"].clone(), v["to_position"].clone()),
            (json!(from), json!(to)),
            "{body}"
        );
        assert_eq!(v["verified"], v["links"]);
    }
    // A bounded check behind a relabelled link, committed this time, is
    // refused by the endpoint as well.
    sqlx::raw_sql(&format!(
        "ALTER TABLE audit_log DISABLE TRIGGER audit_immutable;
         ALTER TABLE audit_chain DISABLE TRIGGER audit_chain_immutable;
         {change};
         UPDATE audit_chain SET key_id='{other}',segment_start=5 WHERE position=5;
         ALTER TABLE audit_log ENABLE TRIGGER audit_immutable;
         ALTER TABLE audit_chain ENABLE TRIGGER audit_chain_immutable;"
    ))
    .execute(&f.db)
    .await
    .unwrap();
    let (s, v) = f
        .request(
            "POST",
            "/audit/verify",
            &f.admin_cookie,
            Some(json!({"from_position": 6, "limit": 3})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "broken", "{v}");
    assert_eq!(v["problem"]["kind"], "chain_broken");
    assert_eq!(v["problem"]["position"], 6);
    // One that begins further on sees only links that follow each other;
    // the whole walk, which the background check makes, finds it.
    let (_, v) = f
        .request(
            "POST",
            "/audit/verify",
            &f.admin_cookie,
            Some(json!({"from_position": 7, "limit": 3})),
        )
        .await;
    assert_eq!(v["status"], "intact", "{v}");
    let Step::Finished { outcome, .. } = chain::verify_step(&f.db, f.crypto(), 100, 0.0)
        .await
        .unwrap()
    else {
        panic!("the pass did not end");
    };
    let found = outcome.problem.unwrap();
    assert_eq!((found.kind, found.position), (Kind::ChainBroken, 6));
    f.close().await;
}

/// The audit list is ordered by time. A row can be given a time that is
/// not a time; the list must still be read to its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_audit_list_pages_past_rows_whose_time_is_not_a_time() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(5).await;
    sqlx::query(
        "INSERT INTO audit_log(id,action,created_at) VALUES
         (gen_random_uuid(),'odd.time','infinity'),
         (gen_random_uuid(),'odd.time','infinity'),
         (gen_random_uuid(),'odd.time','infinity'),
         (gen_random_uuid(),'odd.time','-infinity'),
         (gen_random_uuid(),'odd.time','-infinity'),
         (gen_random_uuid(),'odd.time','294276-12-31 23:59:59.999999+00'),
         (gen_random_uuid(),'odd.time','4713-01-01 00:00:00+00 BC')",
    )
    .execute(&f.db)
    .await
    .unwrap();
    let expected: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM audit_log ORDER BY created_at DESC,id DESC")
            .fetch_all(&f.db)
            .await
            .unwrap();
    assert_eq!(expected.len(), 12);
    // Every page size puts another row at the end of a page.
    for limit in 1..=6 {
        let mut seen: Vec<Uuid> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let path = match &cursor {
                Some(cursor) => format!("/audit?limit={limit}&cursor={cursor}"),
                None => format!("/audit?limit={limit}"),
            };
            let (s, v) = f.request("GET", &path, &f.admin_cookie, None).await;
            assert_eq!(s, StatusCode::OK, "{path}: {v}");
            let items = v["items"].as_array().unwrap();
            assert!(items.len() <= limit && !items.is_empty(), "{path}");
            seen.extend(
                items
                    .iter()
                    .map(|item| item["id"].as_str().unwrap().parse::<Uuid>().unwrap()),
            );
            match v["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
            assert!(seen.len() <= expected.len(), "the list does not end");
        }
        assert_eq!(seen, expected, "limit {limit}");
    }
    // The same with a filter, which the boundary row need not match.
    let (s, v) = f
        .request(
            "GET",
            "/audit?action=odd.time&limit=3",
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = f
        .request(
            "GET",
            &format!(
                "/audit?action=odd.time&limit=10&cursor={}",
                v["next_cursor"].as_str().unwrap()
            ),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 4);
    assert_eq!(v["next_cursor"], Value::Null);
    // A row with such a time is shown with it, as text.
    let (_, v) = f
        .request("GET", "/audit?limit=1", &f.admin_cookie, None)
        .await;
    assert_eq!(v["items"][0]["created_at"], "infinity");
    // A cursor is checked: not base64, not an ID, an ID that is not there.
    let unknown = URL_SAFE_NO_PAD.encode(Uuid::new_v4().to_string());
    for cursor in [
        "!",
        &URL_SAFE_NO_PAD.encode("not an id"),
        &URL_SAFE_NO_PAD.encode("infinity|"),
        &unknown,
        &"A".repeat(300),
    ] {
        let (s, v) = f
            .request(
                "GET",
                &format!("/audit?cursor={cursor}"),
                &f.admin_cookie,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{cursor}: {v}");
        assert_eq!(v["error"]["message"], "Invalid cursor");
    }
    // A cursor in the earlier form, a time and the ID, is still read.
    let old = URL_SAFE_NO_PAD.encode(format!("2026-01-01T00:00:00+00:00|{}", expected[2]));
    let (s, v) = f
        .request(
            "GET",
            &format!("/audit?limit=2&cursor={old}"),
            &f.admin_cookie,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"][0]["id"], json!(expected[3]));
    f.close().await;
}

/// A node remembers which key sealed the head it saw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_notices_when_the_head_it_remembers_names_another_key() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let ids = f.events(6).await;
    seal_all(&f.db, f.crypto()).await;
    audit_chain::cycle(&f.state).await.unwrap();
    assert_eq!(f.state.audit_chain.lost(), None);
    // A row is changed, and every link from it to the head is relabelled
    // as another key's. Nothing in the chain itself shows that.
    sqlx::raw_sql(&format!(
        "ALTER TABLE audit_log DISABLE TRIGGER audit_immutable;
         ALTER TABLE audit_chain DISABLE TRIGGER audit_chain_immutable;
         UPDATE audit_log SET action='changed' WHERE id='{}';
         UPDATE audit_chain SET key_id='aaaaaaaaaaaaaaaa',segment_start=4 WHERE position>=4;
         ALTER TABLE audit_log ENABLE TRIGGER audit_immutable;
         ALTER TABLE audit_chain ENABLE TRIGGER audit_chain_immutable;",
        ids[3]
    ))
    .execute(&f.db)
    .await
    .unwrap();
    let outcome = verify_all(&f.db, f.crypto()).await;
    assert_eq!(
        (outcome.status, outcome.problem.clone()),
        (Status::Partial, None)
    );
    // The node that saw the head under its own key says so.
    audit_chain::cycle(&f.state).await.unwrap();
    let lost = f.state.audit_chain.lost().unwrap();
    assert_eq!((lost.kind, lost.position), (Kind::CheckpointMismatch, 6));
    assert!(lost.message.contains("relabelled"), "{}", lost.message);
    let (_, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(v["verification"]["status"], "broken", "{v}");
    assert_eq!(v["verification"]["problem"]["kind"], "checkpoint_mismatch");
    // New rows are sealed on top, in a new run of the node's key, and the
    // node keeps saying it.
    f.events(2).await;
    seal_all(&f.db, f.crypto()).await;
    audit_chain::cycle(&f.state).await.unwrap();
    assert_eq!(
        f.state.audit_chain.lost().unwrap().kind,
        Kind::CheckpointMismatch
    );
    let starts: Vec<i64> =
        sqlx::query_scalar("SELECT segment_start FROM audit_chain WHERE position>6")
            .fetch_all(&f.db)
            .await
            .unwrap();
    assert_eq!(starts, [7, 7]);
    // A node that started later has only the logs to go by.
    let (late, late_writer) = Fixture::node(&f.db, KEY).await;
    audit_chain::cycle(&late).await.unwrap();
    assert_eq!(late.audit_chain.lost(), None);
    late.stop.cancel();
    late_writer.await.unwrap();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_background_check_walks_in_slices_stores_its_result_and_finds_a_change() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let ids = f.events(25).await;
    seal_all(&f.db, f.crypto()).await;
    // Nothing has been checked yet.
    let (s, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["verification"]["status"], "pending", "{v}");
    assert_eq!(
        (v["sealed"].clone(), v["unsealed"].clone()),
        (json!(25), json!(0))
    );
    assert_eq!(v["head"]["position"], 25);
    assert_eq!(v["key_id"], f.crypto().chain_key_id());
    assert_eq!(v["head"]["key_id"], v["key_id"]);
    // A pass in slices of ten.
    let step = || chain::verify_step(&f.db, f.crypto(), 10, 3600.0);
    assert_eq!(
        step().await.unwrap(),
        Step::Checked {
            links: 10,
            position: 10
        }
    );
    let (_, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(v["verification"]["status"], "pending");
    assert_eq!(v["verification"]["running"]["position"], 10);
    assert_eq!(
        step().await.unwrap(),
        Step::Checked {
            links: 10,
            position: 20
        }
    );
    // Rows sealed while the pass runs are part of it.
    f.events(2).await;
    seal_all(&f.db, f.crypto()).await;
    let Step::Finished { links, outcome } = step().await.unwrap() else {
        panic!("the pass did not end");
    };
    assert_eq!(links, 7);
    assert_eq!(outcome.status, Status::Intact);
    assert_eq!(
        (outcome.from_position, outcome.to_position, outcome.links),
        (1, 27, 27)
    );
    // The next pass is not due for an hour.
    assert_eq!(step().await.unwrap(), Step::Idle);
    let (_, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(v["verification"]["status"], "intact", "{v}");
    assert_eq!(v["verification"]["links"], 27);
    assert_eq!(v["verification"]["verified"], 27);
    assert_eq!(v["verification"]["problem"], Value::Null);
    assert_eq!(v["verification"]["running"], Value::Null);
    assert!(v["verification"]["checked_at"].is_string());
    // While another session checks, this one leaves it alone.
    let mut holder = f.db.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext(current_schema()))")
        .bind(chain::VERIFY_LOCK)
        .execute(&mut *holder)
        .await
        .unwrap();
    assert_eq!(
        chain::verify_step(&f.db, f.crypto(), 10, 0.0)
            .await
            .unwrap(),
        Step::Idle
    );
    holder.rollback().await.unwrap();
    // Someone with the database changes an old row. Nobody asks; the next
    // pass finds it, stores it, and the gateway says so.
    let mut attacker = f.db.acquire().await.unwrap();
    sqlx::raw_sql(&format!(
        "ALTER TABLE audit_log DISABLE TRIGGER audit_immutable;
         UPDATE audit_log SET action='query.execute' WHERE id='{}';
         ALTER TABLE audit_log ENABLE TRIGGER audit_immutable;",
        ids[6]
    ))
    .execute(&mut *attacker)
    .await
    .unwrap();
    drop(attacker);
    let Step::Finished { outcome, .. } = chain::verify_step(&f.db, f.crypto(), 10, 0.0)
        .await
        .unwrap()
    else {
        panic!("the pass did not stop at the change");
    };
    let found = outcome.problem.clone().unwrap();
    assert_eq!((found.kind, found.position), (Kind::RowChanged, 7));
    assert_eq!(found.audit_id, Some(ids[6]));
    let (_, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(v["verification"]["status"], "broken", "{v}");
    assert_eq!(v["verification"]["problem"]["kind"], "row_changed");
    assert_eq!(v["verification"]["problem"]["position"], 7);
    assert_eq!(v["verification"]["problem"]["audit_id"], json!(ids[6]));
    // The check changed nothing: the row is as the attacker left it and
    // the chain has the same links.
    let action: String = sqlx::query_scalar("SELECT action FROM audit_log WHERE id=$1")
        .bind(ids[6])
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(action, "query.execute");
    assert_eq!(head_position(&f.db).await, 27);
    // "Verify now" over the newest links does not reach the change; a
    // range that covers it does.
    let (s, v) = f
        .request(
            "POST",
            "/audit/verify",
            &f.admin_cookie,
            Some(json!({"limit": 10})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "intact");
    assert_eq!(
        (v["from_position"].clone(), v["to_position"].clone()),
        (json!(18), json!(27))
    );
    assert_eq!(v["links"], 10);
    let (s, v) = f
        .request(
            "POST",
            "/audit/verify",
            &f.admin_cookie,
            Some(json!({"from_position": 1, "limit": 10})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "broken");
    assert_eq!(v["problem"]["kind"], "row_changed");
    assert_eq!(v["problem"]["position"], 7);
    assert_eq!(v["head"]["position"], 27);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_integrity_endpoints_are_for_organization_administrators_and_are_audited() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(3).await;
    seal_all(&f.db, f.crypto()).await;
    // Not for a member, not without a session, and the answer names nothing.
    for (method, path, body) in [
        ("GET", "/audit/integrity", None),
        ("POST", "/audit/verify", Some(json!({}))),
    ] {
        let (s, v) = f
            .request(method, path, &f.member_cookie, body.clone())
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {path}");
        assert!(v.get("head").is_none() && v.get("status").is_none());
        let (s, _) = f.request(method, path, "", body).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    let (s, _) = f
        .request("GET", "/audit/verify", &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    // A check is recorded with who asked, from where, what and the result.
    let (s, v) = f
        .request("POST", "/audit/verify", &f.admin_cookie, Some(json!({})))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "intact");
    assert_eq!(v["key_id"], f.crypto().chain_key_id());
    assert_eq!(v["unverifiable"], json!([]));
    assert_eq!(v["problem"], Value::Null);
    let (actor, ip, target_type, details): (Option<Uuid>, Option<String>, Option<String>, Value) =
        sqlx::query_as(
            "SELECT actor_id,host(ip),target_type,details FROM audit_log WHERE action='audit.verify'",
        )
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(actor, Some(f.admin));
    assert_eq!(ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(target_type.as_deref(), Some("audit"));
    assert_eq!(
        details,
        json!({"from_position": 1, "to_position": 3, "status": "intact", "problem": null})
    );
    // The handler's own event is the only one: the request middleware adds
    // its row only for a call that fails.
    let generic = || async {
        // The queue writer is asynchronous; give it a moment.
        let mut rows: Vec<(String, Value)> = Vec::new();
        for _ in 0..100 {
            rows = sqlx::query_as(
                "SELECT action,details FROM audit_log WHERE action LIKE 'POST %' ORDER BY seq",
            )
            .fetch_all(&f.db)
            .await
            .unwrap();
            if !rows.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        rows
    };
    generic().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        generic().await,
        [(
            "POST /api/v1/audit/verify".to_owned(),
            json!({"status": 403})
        )]
    );
    // Bounds.
    for body in [
        json!({"limit": 0}),
        json!({"limit": 10001}),
        json!({"from_position": 0}),
        json!({"from_position": -1}),
        json!({"limit": "ten"}),
        json!({"other": 1}),
    ] {
        let (s, v) = f
            .request("POST", "/audit/verify", &f.admin_cookie, Some(body.clone()))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} {v}");
    }
    // A range past the head is empty, not an error.
    let (s, v) = f
        .request(
            "POST",
            "/audit/verify",
            &f.admin_cookie,
            Some(json!({"from_position": 1000})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["status"].clone(), v["links"].clone()),
        (json!("intact"), json!(0))
    );
    // Six checks a minute on a node, then 429. Refused calls are not checks.
    let mut refused = None;
    for _ in 0..audit_chain::VERIFIES_PER_MINUTE {
        let (s, v) = f
            .request("POST", "/audit/verify", &f.admin_cookie, Some(json!({})))
            .await;
        if s != StatusCode::OK {
            refused = Some((s, v));
            break;
        }
    }
    let (s, v) = refused.expect("the limit was never reached");
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_eq!(v["error"]["code"], "rate_limited");
    assert_eq!(v["error"]["details"]["retry_after_seconds"], 60);
    let checks: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action='audit.verify'")
            .fetch_one(&f.db)
            .await
            .unwrap();
    assert_eq!(checks, i64::from(audit_chain::VERIFIES_PER_MINUTE));
    // The list says for each event whether it is sealed, and its number.
    seal_all(&f.db, f.crypto()).await;
    let waiting = f.events(1).await;
    let mut open = f.db.begin().await.unwrap();
    persist_on(&mut open, &event("held.open", None, 0))
        .await
        .unwrap();
    let after_open = f.events(1).await;
    let (s, v) = f
        .request("GET", "/audit?limit=200", &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let items = v["items"].as_array().unwrap();
    let find = |id: Uuid| {
        items
            .iter()
            .find(|item| item["id"] == json!(id))
            .unwrap()
            .clone()
    };
    assert_eq!(find(after_open[0])["sealed"], false);
    assert!(
        find(after_open[0])["seq"].as_i64().unwrap() > find(waiting[0])["seq"].as_i64().unwrap()
    );
    let sealed_before: Vec<&Value> = items
        .iter()
        .filter(|item| item["action"] == "audit.verify")
        .collect();
    assert!(sealed_before.iter().all(|item| item["sealed"] == true));
    for item in items {
        assert!(
            item["seq"].is_i64() && item["sealed"].is_boolean(),
            "{item}"
        );
        // Nothing of the chain's inside is in the list.
        for secret in ["hash", "txid", "key_id", "prev_hash"] {
            assert!(item.get(secret).is_none(), "{item}");
        }
    }
    let (_, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert!(v["unsealed"].as_i64().unwrap() >= 1, "{v}");
    assert!(v["oldest_unsealed_at"].is_string(), "{v}");
    assert!(v["oldest_unsealed_seconds"].is_number(), "{v}");
    open.rollback().await.unwrap();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_remembers_the_head_and_notices_when_the_end_is_removed() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(8).await;
    seal_all(&f.db, f.crypto()).await;
    // A tick remembers the head, and runs a pass that finds nothing.
    audit_chain::cycle(&f.state).await.unwrap();
    assert_eq!(f.state.audit_chain.lost(), None);
    let (_, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(v["verification"]["status"], "intact", "{v}");
    // The last three rows and their links are removed. The chain that is
    // left is a valid, shorter chain.
    sqlx::raw_sql(
        "ALTER TABLE audit_log DISABLE TRIGGER audit_immutable;
         ALTER TABLE audit_chain DISABLE TRIGGER audit_chain_immutable;
         DELETE FROM audit_log WHERE id IN (SELECT audit_id FROM audit_chain WHERE position>5);
         DELETE FROM audit_chain WHERE position>5;
         ALTER TABLE audit_log ENABLE TRIGGER audit_immutable;
         ALTER TABLE audit_chain ENABLE TRIGGER audit_chain_immutable;",
    )
    .execute(&f.db)
    .await
    .unwrap();
    assert_eq!(verify_all(&f.db, f.crypto()).await.status, Status::Intact);
    // The node that saw the longer chain says so, and keeps saying so while
    // new rows are sealed on top of the shorter one.
    audit_chain::cycle(&f.state).await.unwrap();
    let lost = f.state.audit_chain.lost().unwrap();
    assert_eq!((lost.kind, lost.position), (Kind::ChainTruncated, 6));
    f.events(5).await;
    seal_all(&f.db, f.crypto()).await;
    audit_chain::cycle(&f.state).await.unwrap();
    let lost = f.state.audit_chain.lost().unwrap();
    assert_eq!(lost.kind, Kind::ChainTruncated);
    let (_, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(v["verification"]["status"], "broken", "{v}");
    assert_eq!(v["verification"]["problem"]["kind"], "chain_truncated");
    // A node that started later never saw the longer chain. Only a
    // checkpoint from the logs can tell it.
    let (late, late_writer) = Fixture::node(&f.db, KEY).await;
    audit_chain::cycle(&late).await.unwrap();
    assert_eq!(late.audit_chain.lost(), None);
    late.stop.cancel();
    late_writer.await.unwrap();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rows_the_gateway_would_never_write_do_not_stop_sealing_or_the_check() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(2).await;
    // Someone with the database inserts rows with values that no gateway
    // writes: times that are not times, the last time there is, JSON nested
    // deeper than the canonical form goes, a number with four hundred
    // digits, text in every script, and a transaction ID that never comes.
    let deep = format!("{}1{}", "[".repeat(300), "]".repeat(300));
    sqlx::query(
        r#"INSERT INTO audit_log(id,action,target_type,ip,details,created_at) VALUES
         (gen_random_uuid(),'odd.infinity',NULL,NULL,'{}','infinity'),
         (gen_random_uuid(),'odd.minus_infinity','','::/0','[]','-infinity'),
         (gen_random_uuid(),'odd.last_time',NULL,'255.255.255.255','null','294276-12-31 23:59:59.999999+00'),
         (gen_random_uuid(),'odd.first_time',NULL,'::1','""','4713-01-01 00:00:00+00 BC'),
         (gen_random_uuid(),'odd.deep',NULL,NULL,$1::jsonb,now()),
         (gen_random_uuid(),'odd.number',NULL,NULL,'{"n": 1e400, "m": -1e-400}',now()),
         (gen_random_uuid(),E'odd.text \x07 \u202e ünï ☃ 😀',E'a\tb',NULL,
          '{"k": "\u00e9\n\u0001", "": [true, false]}',now())"#,
    )
    .bind(&deep)
    .execute(&f.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO audit_log(id,action,details,created_at,txid) VALUES
         (gen_random_uuid(),'odd.never','{}','infinity','4611686018427387904')",
    )
    .execute(&f.db)
    .await
    .unwrap();
    let odd: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'odd.%'")
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(odd, 8);
    // Every part of the tick still works, and what can be sealed is.
    let start = std::time::Instant::now();
    loop {
        audit_chain::cycle(&f.state).await.unwrap();
        if unsealed(&f.db).await == 1 {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(120), "not sealed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let outcome = verify_all(&f.db, f.crypto()).await;
    assert_eq!(outcome.status, Status::Intact, "{outcome:?}");
    assert_eq!(outcome.links, 2 + odd - 1);
    // The row that is never sealed shows as waiting, with no age to give.
    let (s, v) = f
        .request("GET", "/audit/integrity", &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["unsealed"], 1, "{v}");
    assert_eq!(v["oldest_unsealed_at"], Value::Null);
    assert_eq!(v["oldest_unsealed_seconds"], Value::Null);
    assert_ne!(v["verification"]["status"], "broken", "{v}");
    // The list still answers. Details that this server cannot read as
    // JSON are given as their text, not as an error for the whole page.
    let (s, v) = f
        .request("GET", "/audit?limit=200", &f.admin_cookie, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 10);
    let details = |action: &str| {
        items
            .iter()
            .find(|item| item["action"].as_str().unwrap().starts_with(action))
            .unwrap()["details"]
            .clone()
    };
    assert!(details("odd.deep").as_str().unwrap().starts_with("[[[["));
    assert!(details("odd.number")
        .as_str()
        .unwrap()
        .contains("\"n\": 1000000"));
    assert_eq!(
        details("odd.text"),
        json!({"k": "é\n\u{1}", "": [true, false]})
    );
    assert_eq!(details("test.event.0")["status"], 200);
    // The offline check reads the same rows.
    let mut out = Vec::new();
    let url = format!(
        "{}{}options=-c%20search_path%3D{}",
        f.url,
        if f.url.contains('?') { '&' } else { '?' },
        f.schema
    );
    let code = audit_chain::verify_offline(&url, f.crypto(), None, &mut out)
        .await
        .unwrap();
    let out = String::from_utf8(out).unwrap();
    assert_eq!(code, audit_chain::EXIT_INTACT, "{out}");
    assert!(out.contains("unsealed: 1 audit rows wait"), "{out}");
    // A change to one of these rows is found like any other.
    let changed: Uuid = sqlx::query_scalar("SELECT id FROM audit_log WHERE action='odd.deep'")
        .fetch_one(&f.db)
        .await
        .unwrap();
    let (outcome, _, _) = after(
        &f,
        f.crypto(),
        None,
        &[format!(
            "UPDATE audit_log SET details=jsonb_set(details,'{{0}}','2') WHERE id='{changed}'"
        )],
    )
    .await;
    let found = outcome.problem.unwrap();
    assert_eq!(found.kind, Kind::RowChanged);
    assert_eq!(found.audit_id, Some(changed));
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_seals_survives_database_errors_and_stops_cleanly() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let worker = tokio::spawn(audit_chain::worker(f.state.clone()));
    let first = f.events(5).await;
    // The worker seals on its own, every two seconds.
    let wait = |id: Uuid| {
        let db = f.db.clone();
        async move {
            let start = std::time::Instant::now();
            while !is_sealed(&db, id).await {
                assert!(start.elapsed() < Duration::from_secs(120), "not sealed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    wait(first[4]).await;
    // The chain is away for a few ticks: every tick fails. The worker keeps
    // going and seals again when it is back.
    sqlx::query("ALTER TABLE audit_chain RENAME TO audit_chain_away")
        .execute(&f.db)
        .await
        .unwrap();
    let second = f.events(5).await;
    tokio::time::sleep(audit_chain::TICK * 2 + Duration::from_millis(500)).await;
    assert!(!worker.is_finished(), "the worker stopped on an error");
    sqlx::query("ALTER TABLE audit_chain_away RENAME TO audit_chain")
        .execute(&f.db)
        .await
        .unwrap();
    wait(second[4]).await;
    assert_sound(&f.db, f.crypto()).await;
    // It ran the background check as well.
    let stored = chain::verification(&mut f.db.acquire().await.unwrap())
        .await
        .unwrap();
    assert_eq!(stored.result.unwrap().status, Status::Intact);
    // It stops when the gateway does, and the last step leaves the head in
    // place: nothing half written.
    f.state.stop.cancel();
    tokio::time::timeout(Duration::from_secs(20), worker)
        .await
        .expect("the worker did not stop")
        .unwrap();
    let last = event("at.shutdown", None, 0);
    persist(&f.db, &last).await.unwrap();
    let start = std::time::Instant::now();
    while !is_sealed(&f.db, last.id).await {
        audit_chain::finish(&f.state).await;
        assert!(start.elapsed() < Duration::from_secs(120), "not sealed");
    }
    assert_sound(&f.db, f.crypto()).await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_batch_writer_keeps_every_event_under_load_and_at_shutdown() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    // Eight producers and a full queue: the writer takes what waits, up to
    // a batch, and writes it in one statement.
    let total = 6000usize;
    let producers: Vec<_> = (0..8usize)
        .map(|producer| {
            let (sender, admin) = (f.state.audit_sender.clone(), f.admin);
            tokio::spawn(async move {
                let mut ids = Vec::new();
                for n in 0..total / 8 {
                    let event = event("load.event", Some(admin), producer * 1000 + n);
                    sender.send(event.clone()).await.unwrap();
                    // The same event sent twice is written once.
                    if n % 50 == 0 {
                        sender.send(event.clone()).await.unwrap();
                    }
                    ids.push(event.id);
                }
                ids
            })
        })
        .collect();
    // One event that the database will never take is in the middle of it.
    let mut poison = event("bad\u{0}", Some(f.admin), 0);
    f.state.audit_sender.send(poison.clone()).await.unwrap();
    let mut ids = Vec::new();
    for producer in producers {
        ids.extend(producer.await.unwrap());
    }
    let written = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_log WHERE action='load.event'")
            .fetch_one(&f.db)
            .await
            .unwrap()
    };
    let start = std::time::Instant::now();
    while written().await < total as i64 {
        assert!(start.elapsed() < Duration::from_secs(120), "events lost");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(written().await, total as i64);
    let distinct: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE id=ANY($1)")
        .bind(&ids)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(distinct, total as i64);
    let bad: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE id=$1")
        .bind(poison.id)
        .fetch_one(&f.db)
        .await
        .unwrap();
    assert_eq!(bad, 0);
    // The writer really batched: far fewer transactions than rows.
    let (transactions, largest): (i64, i64) = sqlx::query_as(
        "SELECT count(*),max(rows) FROM
         (SELECT count(*) AS rows FROM audit_log WHERE action='load.event' GROUP BY txid) t",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert!(
        transactions < total as i64 / 4,
        "{transactions} transactions"
    );
    assert!(
        largest <= vda_server::audit::BATCH as i64 && largest > 1,
        "{largest}"
    );
    // The events of one batch keep the order they were queued in.
    let disorder: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (
           SELECT (details->>'n')::int AS n,
                  lag((details->>'n')::int) OVER (PARTITION BY (details->>'n')::int/1000 ORDER BY txid,seq) AS before
           FROM audit_log WHERE action='load.event') o WHERE o.before>=o.n",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert_eq!(disorder, 0);
    // At shutdown what is queued is written before the writer ends, the
    // event behind a refused one included.
    let mut queued = Vec::new();
    for n in 0..1000 {
        let event = event("shutdown.event", None, n);
        f.state.audit_sender.try_send(event.clone()).unwrap();
        queued.push(event.id);
        if n == 700 {
            poison.id = Uuid::new_v4();
            f.state.audit_sender.try_send(poison.clone()).unwrap();
        }
    }
    f.state.stop.cancel();
    let Fixture {
        db,
        root,
        schema,
        state,
        writer,
        ..
    } = f;
    tokio::time::timeout(Duration::from_secs(30), writer)
        .await
        .expect("the writer did not end")
        .unwrap();
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE id=ANY($1)")
        .bind(&queued)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(kept, 1000);
    // And all of it is sealed like any other row.
    seal_all(&db, &state.core.crypto).await;
    assert_eq!(
        assert_sound(&db, &state.core.crypto).await,
        total as i64 + 1000
    );
    db.close().await;
    drop_schema(&root, &schema).await;
    root.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_migration_orders_the_rows_that_were_there_and_they_are_sealed() {
    let Some((db, root, _, schema)) = Fixture::bare().await else {
        return;
    };
    // The schema as it was before the chain.
    let mut before = sqlx::migrate::Migrator::new(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations"
    )))
    .await
    .unwrap();
    let old: Vec<_> = before
        .iter()
        .filter(|migration| migration.version <= 10)
        .cloned()
        .collect();
    assert_eq!(old.len(), 10);
    before.migrations = std::borrow::Cow::Owned(old);
    before.run(&db).await.unwrap();
    let rows: i64 = std::env::var("VDA_TEST_MIGRATION_ROWS")
        .ok()
        .and_then(|rows| rows.parse().ok())
        .unwrap_or(3000);
    // Rows as an old version wrote them: random IDs, times from several
    // nodes that do not agree, some equal to the microsecond.
    sqlx::query(
        "INSERT INTO audit_log(id,action,target_type,ip,details,created_at)
         SELECT gen_random_uuid(),'old.event.'||(n%7),CASE WHEN n%2=0 THEN 'cluster' END,
                CASE WHEN n%3=0 THEN '10.0.0.1'::inet END,jsonb_build_object('n',n,'status',200),
                '2026-01-01'::timestamptz+((n/3)*interval '1 second')+((n%5)*interval '1 microsecond')
         FROM generate_series(1,$1) n",
    )
    .bind(rows)
    .execute(&db)
    .await
    .unwrap();
    let start = std::time::Instant::now();
    vda_server::db::migrate(&db).await.unwrap();
    let migrated = start.elapsed();
    // Every old row has a number, in the order the list showed them, and
    // the transaction that sorts before all others.
    let (count, low, high, zero): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),min(seq),max(seq),count(*) FILTER (WHERE txid='0') FROM audit_log",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!((count, low, high, zero), (rows, 1, rows, rows));
    let disorder: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT seq,row_number() OVER (ORDER BY created_at,id) AS place
         FROM audit_log) o WHERE o.seq<>o.place",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(disorder, 0);
    // The trigger is on again, on both tables.
    for sql in [
        "UPDATE audit_log SET action='x'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
        "UPDATE audit_chain SET hash='x'",
        "DELETE FROM audit_chain",
        "TRUNCATE audit_chain",
    ] {
        let error = sqlx::query(sql).execute(&db).await.unwrap_err().to_string();
        assert!(error.contains("append-only"), "{sql}: {error}");
    }
    // A new row continues the numbers and carries its transaction.
    let crypto = Crypto::new(&KEY);
    let fresh = event("new.event", None, 0);
    persist(&db, &fresh).await.unwrap();
    let (seq, txid): (i64, String) =
        sqlx::query_as("SELECT seq,txid::text FROM audit_log WHERE id=$1")
            .bind(fresh.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(seq, rows + 1);
    assert!(txid.parse::<u64>().unwrap() > 2);
    // The old rows are sealed first, in their order, then the new one.
    let start = std::time::Instant::now();
    seal_until(&db, &crypto, || async { head_position(&db).await >= rows }).await;
    let sealing = start.elapsed();
    seal_all(&db, &crypto).await;
    let start = std::time::Instant::now();
    assert_eq!(assert_sound(&db, &crypto).await, rows + 1);
    let checking = start.elapsed();
    let last: Uuid = sqlx::query_scalar("SELECT audit_id FROM audit_chain WHERE position=$1")
        .bind(rows + 1)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(last, fresh.id);
    eprintln!(
        "migration of {rows} rows: {:.2} s; sealing them: {:.2} s ({:.0} rows/s); checking twice in SQL and once by hash: {:.2} s",
        migrated.as_secs_f64(),
        sealing.as_secs_f64(),
        rows as f64 / sealing.as_secs_f64(),
        checking.as_secs_f64(),
    );
    db.close().await;
    drop_schema(&root, &schema).await;
    root.close().await;
}

/// Not a test of behaviour: it measures. Run it alone with
/// `cargo test -p vda-server --release --test audit_chain measure -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run by hand"]
async fn measure_the_writer_the_sealer_and_the_check() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let count = 4096usize;
    let batch = |action: &'static str| -> Vec<Event> {
        (0..count).map(|n| event(action, None, n)).collect()
    };
    let rows = |action: &'static str| {
        let db = f.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_log WHERE action=$1")
                .bind(action)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    // Before: the writer took one event and wrote it, then the next. That
    // loop is `persist` once for each event of a full queue.
    let events = batch("measure.one_by_one");
    let start = std::time::Instant::now();
    for event in &events {
        persist(&f.db, event).await.unwrap();
    }
    let one_by_one = start.elapsed();
    // After: a full queue through the writer.
    let events = batch("measure.batched");
    for event in events {
        f.state.audit_sender.try_send(event).unwrap();
    }
    let start = std::time::Instant::now();
    while rows("measure.batched").await < count as i64 {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let batched = start.elapsed();
    eprintln!(
        "writer, {count} events: one by one {:.0} rows/s ({:.2} s); batched {:.0} rows/s ({:.2} s)",
        count as f64 / one_by_one.as_secs_f64(),
        one_by_one.as_secs_f64(),
        count as f64 / batched.as_secs_f64(),
        batched.as_secs_f64(),
    );
    // Sealing and checking a larger log.
    let more: i64 = 100_000;
    sqlx::query(
        "INSERT INTO audit_log(id,actor_id,action,target_type,target_id,ip,details)
         SELECT gen_random_uuid(),$2,'query.execute','cluster',gen_random_uuid(),'10.0.0.1',
                jsonb_build_object('query_id',gen_random_uuid(),'history_id',gen_random_uuid(),
                                   'status','running','agent_id',NULL)
         FROM generate_series(1,$1) n",
    )
    .bind(more)
    .bind(f.admin)
    .execute(&f.db)
    .await
    .unwrap();
    let total = more + 2 * count as i64;
    let start = std::time::Instant::now();
    seal_until(&f.db, f.crypto(), || async {
        head_position(&f.db).await >= total
    })
    .await;
    let sealing = start.elapsed();
    let start = std::time::Instant::now();
    let outcome = verify_all(&f.db, f.crypto()).await;
    let checking = start.elapsed();
    assert_eq!(outcome.status, Status::Intact);
    eprintln!(
        "sealing {total} rows in batches of 500: {:.0} rows/s ({:.2} s); checking them: {:.0} links/s ({:.2} s)",
        total as f64 / sealing.as_secs_f64(),
        sealing.as_secs_f64(),
        total as f64 / checking.as_secs_f64(),
        checking.as_secs_f64(),
    );
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_offline_check_reads_only_and_its_exit_code_says_what_it_found() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.events(9).await;
    seal_all(&f.db, f.crypto()).await;
    let head = chain::head(&mut f.db.acquire().await.unwrap())
        .await
        .unwrap()
        .unwrap();
    let key = |bytes: [u8; 32]| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };
    let url = |schema: &str| {
        let separator = if f.url.contains('?') { '&' } else { '?' };
        format!("{}{separator}options=-c%20search_path%3D{schema}", f.url)
    };
    let run = |schema: &str, master: [u8; 32], arguments: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_visp-db-access"))
            .arg("verify-audit")
            .args(arguments)
            .env("VDA_DATABASE_URL", url(schema))
            .env("VDA_MASTER_KEY", key(master))
            .env_remove("VDA_BOOTSTRAP_ADMIN_EMAIL")
            .env_remove("VDA_BOOTSTRAP_ADMIN_PASSWORD")
            .output()
            .unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    // Everything the command could have written to.
    let fingerprint = || async {
        sqlx::query_scalar::<_, String>(
            "SELECT md5(
               (SELECT string_agg(a::text,'|' ORDER BY a.id) FROM audit_log a)||
               (SELECT string_agg(c::text,'|' ORDER BY c.position) FROM audit_chain c)||
               (SELECT string_agg(v::text,'|') FROM audit_verification v)||
               (SELECT string_agg(m::text,'|' ORDER BY m.version) FROM _sqlx_migrations m)||
               (SELECT count(*)::text FROM pg_tables WHERE schemaname=current_schema()))",
        )
        .fetch_one(&f.db)
        .await
        .unwrap()
    };
    let before = fingerprint().await;
    let (code, out, err) = run(&f.schema, KEY, &[]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(out.contains("result: INTACT"), "{out}");
    assert!(
        out.contains(&format!(
            "head: position=9 hash={} key_id={}",
            head.hash, head.key_id
        )),
        "{out}"
    );
    assert!(out.contains("checked: 9 links, 9 verified"), "{out}");
    // A saved checkpoint that still holds.
    let position = head.position.to_string();
    let (code, out, err) = run(
        &f.schema,
        KEY,
        &["--expect-position", &position, "--expect-hash", &head.hash],
    );
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(
        out.contains("checkpoint: position=9 is in the chain"),
        "{out}"
    );
    // With the name of the key that sealed it.
    let (code, out, err) = run(
        &f.schema,
        KEY,
        &[
            "--expect-position",
            &position,
            "--expect-hash",
            &head.hash,
            "--expect-key-id",
            &head.key_id,
        ],
    );
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(
        out.contains("checkpoint: position=9 is in the chain with that hash and key"),
        "{out}"
    );
    // The right hash under another key's name: the link was relabelled.
    let (code, out, _) = run(
        &f.schema,
        KEY,
        &[
            "--expect-position",
            &position,
            "--expect-hash",
            &head.hash,
            "--expect-key-id",
            "0123456789abcdef",
        ],
    );
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("kind=checkpoint_mismatch position=9"), "{out}");
    assert!(out.contains("relabelled"), "{out}");
    assert!(out.contains("result: BROKEN"), "{out}");
    // The name of a key alone is not a checkpoint.
    let (code, _, err) = run(&f.schema, KEY, &["--expect-key-id", &head.key_id]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("--expect-position"), "{err}");
    // One that does not.
    let (code, out, _) = run(
        &f.schema,
        KEY,
        &["--expect-position", "9", "--expect-hash", chain::GENESIS],
    );
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("kind=checkpoint_mismatch position=9"), "{out}");
    assert!(out.contains("result: BROKEN"), "{out}");
    let (code, out, _) = run(
        &f.schema,
        KEY,
        &["--expect-position", "12", "--expect-hash", &head.hash],
    );
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("kind=chain_truncated position=10"), "{out}");
    // Half a checkpoint is refused before anything is read, as a wrong
    // command line and not as a verdict.
    let (code, _, err) = run(&f.schema, KEY, &["--expect-position", "9"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("--expect-hash"), "{err}");
    // Another master key: nothing is wrong, nothing is verified, and the
    // exit code is not 0.
    let (code, out, _) = run(&f.schema, [5; 32], &[]);
    assert_eq!(code, Some(4), "{out}");
    assert!(out.contains("checked: 9 links, 0 verified"), "{out}");
    assert!(
        out.contains("not verifiable with this key: positions 1-9"),
        "{out}"
    );
    assert!(out.contains("result: NOT FULLY VERIFIED"), "{out}");
    // No key, or no database: an error, not a verdict.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_visp-db-access"))
        .arg("verify-audit")
        .env("VDA_DATABASE_URL", url(&f.schema))
        .env_remove("VDA_MASTER_KEY")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    // None of that wrote anything, or migrated.
    assert_eq!(fingerprint().await, before);
    // A database that was never migrated is left exactly as it is.
    let empty = format!("vda_chain_empty_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {empty}"))
        .execute(&f.root)
        .await
        .unwrap();
    let (code, out, err) = run(&empty, KEY, &[]);
    assert_eq!(code, Some(1), "{out}{err}");
    assert!(err.contains("no audit chain yet"), "{err}");
    let tables: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_tables WHERE schemaname=$1")
        .bind(&empty)
        .fetch_one(&f.root)
        .await
        .unwrap();
    assert_eq!(tables, 0);
    drop_schema(&f.root, &empty).await;
    // A row waits behind an open transaction: reported, and not a break.
    let mut open = f.db.begin().await.unwrap();
    persist_on(&mut open, &event("held.open", None, 0))
        .await
        .unwrap();
    f.events(2).await;
    let (code, out, _) = run(&f.schema, KEY, &[]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("unsealed: 2 audit rows wait"), "{out}");
    open.rollback().await.unwrap();
    seal_all(&f.db, f.crypto()).await;
    // Someone changes a sealed row.
    let changed: Uuid = sqlx::query_scalar("SELECT audit_id FROM audit_chain WHERE position=4")
        .fetch_one(&f.db)
        .await
        .unwrap();
    sqlx::raw_sql(&format!(
        "ALTER TABLE audit_log DISABLE TRIGGER audit_immutable;
         UPDATE audit_log SET ip='10.9.9.9' WHERE id='{changed}';
         ALTER TABLE audit_log ENABLE TRIGGER audit_immutable;"
    ))
    .execute(&f.db)
    .await
    .unwrap();
    let before = fingerprint().await;
    let (code, out, err) = run(&f.schema, KEY, &[]);
    assert_eq!(code, Some(3), "{out}{err}");
    assert!(
        out.contains(&format!(
            "problem: kind=row_changed position=4 audit_id={changed}"
        )),
        "{out}"
    );
    assert!(out.contains("result: BROKEN"), "{out}");
    assert!(out.contains("checked: 3 links, 3 verified"), "{out}");
    assert_eq!(fingerprint().await, before);
    // The master key is in neither stream.
    assert!(!out.contains(&key(KEY)) && !err.contains(&key(KEY)));
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_of_the_agent_login_status_is_recorded_once_across_two_nodes() {
    let Ok(target_url) = std::env::var("VDA_TEST_POSTGRES_URL") else {
        eprintln!("skipped: VDA_TEST_POSTGRES_URL is not set");
        return;
    };
    let Some(f) = Fixture::new().await else {
        return;
    };
    // The database administrator: a database of its own and a login that
    // can connect and read nothing.
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let (database, role) = (format!("chain_db_{suffix}"), format!("vda_agent_{suffix}"));
    let server = sqlx::PgPool::connect(&target_url).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&server)
        .await
        .unwrap();
    let (base_url, _) = target_url.rsplit_once('/').unwrap();
    let dba = sqlx::PgPool::connect(&format!("{base_url}/{database}"))
        .await
        .unwrap();
    let run = |sql: String| {
        let dba = dba.clone();
        async move {
            sqlx::raw_sql(&sql).execute(&dba).await.unwrap();
        }
    };
    run(format!(
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;
         CREATE TABLE public.notes(id integer, body text);
         CREATE TABLE public.vault(id integer, secret text);
         CREATE ROLE {role} LOGIN PASSWORD 'first-pw';
         GRANT SELECT ON public.notes TO {role};"
    ))
    .await;
    // The cluster and its policy, written as the fixture of the other
    // tests does.
    let opts = server.connect_options();
    let password = target_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('@'))
        .and_then(|(user, _)| user.split_once(':'))
        .map_or("", |(_, password)| password);
    let (project, cluster) = (Uuid::new_v4(), Uuid::new_v4());
    sqlx::query("INSERT INTO projects(id,name) VALUES ($1,'Project')")
        .bind(project)
        .execute(&f.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO clusters(id,project_id,name,engine,provider,region,environment,host,port,database,username,password_enc,tls_mode)
        VALUES ($1,$2,'Cluster','postgres','onprem','local','development',$3,$4,$5,$6,$7,'disable')")
        .bind(cluster).bind(project).bind(opts.get_host()).bind(i32::from(opts.get_port()))
        .bind(&database).bind(opts.get_username())
        .bind(f.crypto().encrypt(cluster, password).unwrap()).execute(&f.db).await.unwrap();
    let mut policy = vda_server::policy::Policy::for_environment("development");
    policy.blocked_tables = vec!["public.vault".into()];
    sqlx::query("INSERT INTO cluster_policies(cluster_id,policy) VALUES ($1,$2)")
        .bind(cluster)
        .bind(json!(policy))
        .execute(&f.db)
        .await
        .unwrap();
    // A second node on the same metadata store.
    let other_db = pool(&f.url, &f.schema, 8).await;
    let (other, other_writer) = Fixture::node(&other_db, KEY).await;
    let statuses = || async {
        sqlx::query_as::<_, (Option<Uuid>, Option<String>, Option<Uuid>, Value)>(
            "SELECT actor_id,target_type,target_id,details FROM audit_log
             WHERE action='agent_login.status' ORDER BY txid,seq",
        )
        .fetch_all(&f.db)
        .await
        .unwrap()
    };
    let changes = || async {
        statuses()
            .await
            .into_iter()
            .map(|(_, _, _, details)| {
                format!(
                    "{}>{}",
                    details["from"].as_str().unwrap(),
                    details["to"].as_str().unwrap()
                )
            })
            .collect::<Vec<_>>()
    };
    // Both nodes check the cluster again and again, at the same time, as
    // they do when agents query through both.
    let check_on_both = || async {
        let record = vda_server::db::cluster(&f.db, cluster).await.unwrap();
        let mut tasks = Vec::new();
        for core in [f.state.core.clone(), other.core.clone()] {
            // What the database allows changed without the gateway knowing.
            core.pools.invalidate(record.id).await;
            for _ in 0..6 {
                let (core, record, policy) = (core.clone(), record.clone(), policy.clone());
                tasks.push(tokio::spawn(async move {
                    vda_core::judge::check(&core, &record, &policy)
                        .await
                        .map(|(status, _)| status)
                }));
            }
        }
        let mut seen = Vec::new();
        for task in tasks {
            seen.push(task.await.unwrap().unwrap());
        }
        seen.sort();
        seen.dedup();
        seen
    };
    // The login is set with a wrong password: the check in the request
    // fails. One change, from unchecked to error, with nobody as its actor
    // and the cluster as its target.
    let path = format!("/clusters/{cluster}/agent-login");
    let (s, v) = f
        .request(
            "PUT",
            &path,
            &f.admin_cookie,
            Some(json!({"username": role, "password": "wrong-pw"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(changes().await, ["unchecked>error"]);
    let (actor, target_type, target_id, details) = statuses().await.remove(0);
    assert_eq!(actor, None);
    assert_eq!(target_type.as_deref(), Some("cluster"));
    assert_eq!(target_id, Some(cluster));
    assert_eq!(details, json!({"from": "unchecked", "to": "error"}));
    // Twelve more checks on two nodes find the same: no new event.
    assert_eq!(check_on_both().await, ["error"]);
    assert_eq!(changes().await, ["unchecked>error"]);
    // The administrator gives the role that password. The twelve checks
    // all pass, and the change is written once.
    run(format!("ALTER ROLE {role} PASSWORD 'wrong-pw'")).await;
    assert_eq!(check_on_both().await, ["ok"]);
    assert_eq!(changes().await, ["unchecked>error", "error>ok"]);
    assert_eq!(check_on_both().await, ["ok"]);
    assert_eq!(changes().await, ["unchecked>error", "error>ok"]);
    // The login gets a grant on a table the policy blocks: drift, once.
    run(format!("GRANT SELECT ON public.vault TO {role}")).await;
    assert_eq!(check_on_both().await, ["drift"]);
    assert_eq!(check_on_both().await, ["drift"]);
    assert_eq!(changes().await, ["unchecked>error", "error>ok", "ok>drift"]);
    // Repaired: ok again, once.
    run(format!("REVOKE SELECT ON public.vault FROM {role}")).await;
    assert_eq!(check_on_both().await, ["ok"]);
    assert_eq!(
        changes().await,
        ["unchecked>error", "error>ok", "ok>drift", "drift>ok"]
    );
    // Setting the login again makes it unchecked, and the check in the
    // same request makes it ok: two changes, each once.
    let (s, v) = f
        .request(
            "PUT",
            &path,
            &f.admin_cookie,
            Some(json!({"username": role, "password": "wrong-pw"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "ok", "{v}");
    assert_eq!(
        changes().await[4..],
        ["ok>unchecked".to_owned(), "unchecked>ok".to_owned()]
    );
    // No finding, object name or password is in the events.
    let text: String = sqlx::query_scalar(
        "SELECT string_agg(details::text,'') FROM audit_log WHERE action='agent_login.status'",
    )
    .fetch_one(&f.db)
    .await
    .unwrap();
    assert!(
        !text.contains("vault") && !text.contains("wrong-pw"),
        "{text}"
    );
    // The events are audit rows like any other: sealed and verified.
    seal_all(&f.db, f.crypto()).await;
    assert_sound(&f.db, f.crypto()).await;
    other.core.pools.close().await;
    other.stop.cancel();
    other_writer.await.unwrap();
    other_db.close().await;
    f.close().await;
    dba.close().await;
    sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&server)
        .await
        .unwrap();
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&server)
        .await
        .unwrap();
    server.close().await;
}
