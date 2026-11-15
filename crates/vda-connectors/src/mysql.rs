//! MySQL guarded transactions and diagnostics.
use crate::{
    cancel::{self, GuardedConnection},
    decode,
    limits::{self, Results},
    tls, ConnectionSpec, ConnectorError, ExecLimits, HealthReport, PoolOptions, QueryResult,
};
use futures::TryStreamExt;
use sqlx::{mysql::MySqlPoolOptions, Executor, MySqlConnection, MySqlPool, Row};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::Instant,
};
use tokio_util::sync::CancellationToken;

/// Session variables that change on their own, or that `setup` overwrites
/// before every statement, so they are excluded from the session comparison.
const VOLATILE: &str = "'timestamp', 'statement_id', 'pseudo_thread_id', 'rand_seed1', \
     'rand_seed2', 'warning_count', 'error_count', 'sql_mode', 'time_zone', \
     'max_execution_time', 'max_statement_time', 'innodb_lock_wait_timeout', 'lock_wait_timeout'";

/// One text-protocol round trip: release every `GET_LOCK` lock, then list the session
/// identity (database, user, active roles) and every non-volatile session variable,
/// plus user variables when `user_variables` is set and the server exposes them.
fn probe(mariadb: bool, user_variables: bool) -> String {
    let (session, user) = if mariadb {
        (
            "information_schema.SESSION_VARIABLES",
            "SELECT CONCAT('@', VARIABLE_NAME), CONCAT(VARIABLE_TYPE, ':', VARIABLE_VALUE) \
             FROM information_schema.USER_VARIABLES",
        )
    } else {
        (
            "performance_schema.session_variables",
            "SELECT CONCAT('@', VARIABLE_NAME), VARIABLE_VALUE \
             FROM performance_schema.user_variables_by_thread WHERE THREAD_ID = \
             (SELECT THREAD_ID FROM performance_schema.threads WHERE PROCESSLIST_ID = CONNECTION_ID())",
        )
    };
    // `/*!80000 ... */` runs on MySQL 8+ and every MariaDB (versions 10+), never on 5.7.
    let mut sql = format!(
        "DO RELEASE_ALL_LOCKS(); \
         SELECT '~database', DATABASE() UNION ALL SELECT '~user', CURRENT_USER() \
         /*!80000 UNION ALL SELECT '~role', CURRENT_ROLE() */ \
         UNION ALL SELECT CONCAT('$', LOWER(VARIABLE_NAME)), VARIABLE_VALUE FROM {session} \
         WHERE LOWER(VARIABLE_NAME) NOT IN ({VOLATILE})"
    );
    if user_variables {
        sql.push_str(" UNION ALL ");
        sql.push_str(user);
    }
    sql
}

type SessionState = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
enum Baseline {
    /// The probe that worked on connect and the state it saw then.
    Verified { probe: String, state: SessionState },
    /// The server cannot list its session state: never reuse a connection.
    Unverifiable,
}

/// The session state of a freshly configured connection, shared by a pool.
///
/// MySQL has `COM_RESET_CONNECTION`, but SQLx 0.8 cannot send it. Instead a
/// released connection is compared with a fresh one and closed on any difference:
/// role, database, session or user variables changed by a stored function or SET.
/// Every connection of a pool logs in as the same account, so one baseline serves
/// all; each new connection refreshes it.
#[derive(Default)]
struct SessionCheck {
    baseline: Mutex<Option<Arc<Baseline>>>,
    warned: AtomicBool,
}
impl SessionCheck {
    async fn capture(&self, connection: &mut MySqlConnection) -> Result<(), sqlx::Error> {
        let row = connection.fetch_one("SELECT VERSION()").await?;
        let mariadb = row
            .try_get_unchecked::<Vec<u8>, _>(0)?
            .windows(7)
            .any(|window| window == b"MariaDB");
        let mut baseline = Baseline::Unverifiable;
        for user_variables in [true, false] {
            let probe = probe(mariadb, user_variables);
            match session_state(connection, &probe).await {
                Ok(state) => {
                    if !user_variables {
                        self.warn_once(
                            "user variables are not visible to this account, so a stored \
                             function that sets one is not detected; grant SELECT on \
                             performance_schema.user_variables_by_thread and \
                             performance_schema.threads to verify them",
                        );
                    }
                    baseline = Baseline::Verified { probe, state };
                    break;
                }
                // Missing tables, functions or privileges: try a narrower probe.
                Err(sqlx::Error::Database(_)) => {}
                Err(error) => return Err(error),
            }
        }
        if matches!(baseline, Baseline::Unverifiable) {
            self.warn_once(
                "session state cannot be listed (needs RELEASE_ALL_LOCKS and readable \
                 session variables); connections are closed after every use",
            );
        }
        *self.baseline.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(baseline));
        Ok(())
    }

    /// `Ok(true)` only when the released session matches a fresh one.
    async fn verify(&self, connection: &mut MySqlConnection) -> Result<bool, sqlx::Error> {
        let baseline = self
            .baseline
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(Baseline::Verified { probe, state }) = baseline.as_deref() else {
            return Ok(false);
        };
        let current = session_state(connection, probe).await?;
        if &current == state {
            return Ok(true);
        }
        let changed: Vec<_> = current
            .keys()
            .chain(state.keys())
            .filter(|key| current.get(*key) != state.get(*key))
            .map(|key| String::from_utf8_lossy(key).into_owned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .take(8)
            .collect();
        tracing::warn!(
            ?changed,
            "MySQL session state changed during a request; closing the connection"
        );
        Ok(false)
    }

    fn warn_once(&self, message: &str) {
        if !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!("MySQL session reset: {message}");
        }
    }
}
async fn session_state(
    connection: &mut MySqlConnection,
    probe: &str,
) -> Result<SessionState, sqlx::Error> {
    // Text protocol: values arrive as bytes whatever the column types unify to.
    connection
        .fetch_all(probe)
        .await?
        .iter()
        .map(|row| Ok((row.try_get_unchecked(0)?, row.try_get_unchecked(1)?)))
        .collect()
}

/// State no probe can see on every server: temporary tables (reads cannot create
/// them inside READ ONLY transactions, writes can) and user variables named in the
/// SQL. A `@` anywhere, even in a literal, costs at most one reconnect.
fn reusable_after(sql: &str, write: bool) -> bool {
    !write && !sql.contains('@')
}

pub(crate) fn pool(spec: &ConnectionSpec, options: PoolOptions) -> MySqlPool {
    let application = spec.application_name.clone();
    let check = Arc::new(SessionCheck::default());
    let released = check.clone();
    MySqlPoolOptions::new()
        .max_connections(options.max_connections)
        .min_connections(0)
        .acquire_timeout(options.acquire_timeout.min(options.connect_timeout))
        .idle_timeout(options.idle_timeout)
        .test_before_acquire(true)
        .after_connect(move |connection, _| {
            let application = application.clone();
            let check = check.clone();
            Box::pin(async move {
                match sqlx::query("SET SESSION transaction_read_only = ON")
                    .persistent(false)
                    .execute(&mut *connection)
                    .await
                {
                    Err(sqlx::Error::Database(error))
                        if error
                            .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                            .is_some_and(|error| error.number() == 1193) =>
                    {
                        sqlx::query("SET SESSION tx_read_only = ON")
                            .persistent(false)
                            .execute(&mut *connection)
                            .await?;
                    }
                    Err(error) => return Err(error),
                    Ok(_) => {}
                }
                sqlx::query("SET @vda_application_name = ?")
                    .bind(application)
                    .persistent(false)
                    .execute(&mut *connection)
                    .await?;
                check.capture(connection).await
            })
        })
        // Every connection the pool would reuse passes through here; a difference
        // from a fresh session, an error or a timeout closes it instead.
        .after_release(move |connection, _| {
            let check = released.clone();
            Box::pin(async move { cancel::bounded_reset(check.verify(connection)).await })
        })
        .connect_lazy_with(tls::mysql(spec))
}
async fn command(connection: &mut MySqlConnection, sql: &str) -> Result<(), ConnectorError> {
    // START TRANSACTION READ ONLY/WRITE is unsupported by MySQL's prepared
    // statement protocol. These commands are trusted, internally generated SQL.
    connection.execute(sql).await.map_err(cancel::error)?;
    Ok(())
}
async fn set_statement_timeout(
    connection: &mut MySqlConnection,
    timeout: std::time::Duration,
) -> Result<(), ConnectorError> {
    let sql = format!(
        "SET SESSION max_execution_time = {}",
        limits::millis(timeout)
    );
    match connection.execute(sql.as_str()).await {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(error))
            if error
                .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .is_some_and(|error| error.number() == 1193) =>
        {
            // MariaDB uses seconds (including fractions) and also bounds writes.
            let millis = limits::millis(timeout);
            command(
                connection,
                &format!(
                    "SET SESSION max_statement_time = {}.{:03}",
                    millis / 1000,
                    millis % 1000
                ),
            )
            .await
        }
        Err(error) => Err(cancel::error(error)),
    }
}
async fn setup(
    connection: &mut MySqlConnection,
    limits: &ExecLimits,
    write: bool,
) -> Result<(), ConnectorError> {
    // Match the guard's MySQL lexer regardless of server defaults. UTC keeps
    // TIMESTAMP decoding stable; ANSI_QUOTES/NO_BACKSLASH_ESCAPES alter syntax.
    command(
        connection,
        "SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'",
    )
    .await?;
    command(connection, "SET SESSION time_zone = '+00:00'").await?;
    set_statement_timeout(connection, limits.statement_timeout).await?;
    for sql in [
        format!(
            "SET SESSION innodb_lock_wait_timeout = {}",
            limits::seconds(limits.lock_timeout)
        ),
        format!(
            "SET SESSION lock_wait_timeout = {}",
            limits::seconds(limits.lock_timeout)
        ),
    ] {
        command(connection, &sql).await?;
    }
    command(
        connection,
        if write {
            "START TRANSACTION READ WRITE"
        } else {
            "START TRANSACTION READ ONLY"
        },
    )
    .await
}
pub(crate) async fn execute(
    pool: &MySqlPool,
    sql: &str,
    limits: &ExecLimits,
    write_cap: Option<u64>,
    token: CancellationToken,
) -> Result<QueryResult, ConnectorError> {
    let start = Instant::now();
    let timeout = limits::hard_timeout(limits);
    let acquired = cancel::race(
        async { pool.acquire().await.map_err(cancel::error) },
        &token,
        timeout,
    )
    .await?;
    let mut connection = GuardedConnection::new(acquired);
    let id = AtomicU64::new(0);
    let operation = async {
        let backend: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
            .persistent(false)
            .fetch_one(&mut *connection)
            .await
            .map_err(cancel::error)?;
        id.store(backend, Ordering::Relaxed);
        let cancel_pool = pool.clone();
        connection.on_discard(move || {
            // Aborting/dropping the execution future must stop work server-side
            // too; SQLx graceful TLS close can otherwise hold the sole pool slot.
            // Dropping outside a runtime (e.g. during shutdown) must not panic.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    cancel::mysql(&cancel_pool, backend).await;
                });
            }
        });
        setup(&mut connection, limits, write_cap.is_some()).await?;
        let result = if let Some(cap) = write_cap {
            write(&mut connection, sql, cap).await
        } else {
            read(&mut connection, sql, limits).await
        };
        match result {
            Ok(result) if result.truncated && write_cap.is_none() => Ok(result),
            Ok(result) => {
                command(
                    &mut connection,
                    if write_cap.is_some() {
                        "COMMIT"
                    } else {
                        "ROLLBACK"
                    },
                )
                .await?;
                finish(&mut connection, sql, write_cap.is_some());
                Ok(result)
            }
            Err(error) => {
                if command(&mut connection, "ROLLBACK").await.is_ok() {
                    finish(&mut connection, sql, write_cap.is_some());
                }
                Err(error)
            }
        }
    };
    let result = cancel::race(operation, &token, timeout.saturating_sub(start.elapsed())).await;
    if matches!(
        result,
        Err(ConnectorError::Cancelled | ConnectorError::Timeout)
    ) || matches!(&result, Ok(result) if result.truncated && write_cap.is_none())
    {
        connection.discard();
        connection.clear_discard_hook();
        let backend = id.load(Ordering::Relaxed);
        if backend != 0 {
            cancel::mysql(pool, backend).await;
        }
    }
    result.map(|mut result| {
        result.elapsed_ms = limits::elapsed(start);
        result
    })
}
/// After COMMIT/ROLLBACK succeeded: pool the connection, where `after_release`
/// verifies its session, or close it when it may hold unverifiable state.
fn finish(connection: &mut GuardedConnection<sqlx::MySql>, sql: &str, write: bool) {
    if reusable_after(sql, write) {
        connection.clean();
    } else {
        connection.retire();
    }
}
async fn read(
    connection: &mut MySqlConnection,
    sql: &str,
    limits: &ExecLimits,
) -> Result<QueryResult, ConnectorError> {
    let mut results = Results::new(limits);
    results.columns(decode::columns(
        connection
            .describe(sql)
            .await
            .map_err(cancel::error)?
            .columns(),
    ));
    let mut stream = sqlx::query(sql).persistent(false).fetch(&mut *connection);
    while let Some(row) = stream.try_next().await.map_err(cancel::error)? {
        if results.needs_columns() {
            results.columns(decode::mysql_columns(&row));
        }
        if !results.offer(|| decode::mysql(&row)) {
            break;
        }
    }
    Ok(results.finish(None))
}
async fn write(
    connection: &mut MySqlConnection,
    sql: &str,
    cap: u64,
) -> Result<QueryResult, ConnectorError> {
    let affected = sqlx::query(sql)
        .persistent(false)
        .execute(connection)
        .await
        .map_err(cancel::error)?
        .rows_affected();
    if affected > cap {
        return Err(ConnectorError::TooManyAffectedRows {
            actual: affected,
            limit: cap,
        });
    }
    Ok(QueryResult {
        columns: Vec::new(),
        rows: Vec::new(),
        row_count: 0,
        truncated: false,
        affected_rows: Some(affected),
        elapsed_ms: 0,
    })
}
pub(crate) fn cost(plan: &serde_json::Value) -> Option<f64> {
    let block = plan.get("query_block")?;
    let value = block
        .get("cost_info")
        .and_then(|info| info.get("query_cost"))
        .or_else(|| block.get("cost"))?;
    value
        .as_f64()
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
}
pub(crate) async fn explain(
    pool: &MySqlPool,
    sql: &str,
    limits: &ExecLimits,
) -> Result<Option<f64>, ConnectorError> {
    let mut budget = *limits;
    budget.max_rows = 1;
    budget.max_bytes = 4 * 1024 * 1024;
    let result = execute(
        pool,
        &format!("EXPLAIN FORMAT=JSON {sql}"),
        &budget,
        None,
        CancellationToken::new(),
    )
    .await?;
    let plan = result.rows.first().and_then(|row| row.first());
    Ok(plan.and_then(|value| {
        if let Some(text) = value.as_str() {
            serde_json::from_str(text).ok().as_ref().and_then(cost)
        } else {
            cost(value)
        }
    }))
}
pub(crate) async fn health(
    pool: &MySqlPool,
    report: &mut HealthReport,
) -> Result<(), ConnectorError> {
    let mut connection = GuardedConnection::new(pool.acquire().await.map_err(cancel::error)?);
    let start = Instant::now();
    sqlx::query("SELECT 1")
        .persistent(false)
        .execute(&mut *connection)
        .await
        .map_err(cancel::error)?;
    report.ok = true;
    report.latency_ms = Some(limits::elapsed(start));
    report.server_version = sqlx::query_scalar("SELECT VERSION()")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .ok();
    report.is_replica = sqlx::query_scalar::<_, i64>("SELECT @@global.read_only")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .ok()
        .map(|value| value != 0);
    let replica = match sqlx::query("SHOW REPLICA STATUS")
        .persistent(false)
        .fetch_optional(&mut *connection)
        .await
    {
        Ok(row) => Some(row.is_some()),
        Err(_) => sqlx::query("SHOW SLAVE STATUS")
            .persistent(false)
            .fetch_optional(&mut *connection)
            .await
            .ok()
            .map(|row| row.is_some()),
    };
    if replica == Some(true) {
        report.is_replica = Some(true);
    } else if report.is_replica.is_none() {
        report.is_replica = replica;
    }
    report.active_connections = sqlx::query("SHOW GLOBAL STATUS LIKE 'Threads_connected'")
        .persistent(false)
        .fetch_optional(&mut *connection)
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<String, _>(1).ok()?.parse().ok());
    report.max_connections = sqlx::query_scalar::<_, u64>("SELECT @@max_connections")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .ok()
        .and_then(|value| i64::try_from(value).ok());
    connection.clean();
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_probe_covers_locks_identity_and_variables() {
        for mariadb in [false, true] {
            let full = probe(mariadb, true);
            let narrow = probe(mariadb, false);
            for sql in [&full, &narrow] {
                assert!(sql.starts_with("DO RELEASE_ALL_LOCKS();"));
                for item in ["DATABASE()", "CURRENT_USER()", "CURRENT_ROLE()", VOLATILE] {
                    assert!(sql.contains(item), "{item} missing from {sql}");
                }
                // Only one statement after the lock release: a single result set.
                assert_eq!(sql.matches(';').count(), 1);
            }
            assert!(full.contains("USER_VARIABLES") || full.contains("user_variables_by_thread"));
            assert!(!narrow.contains("user_variables"));
            assert!(!narrow.contains("USER_VARIABLES"));
            let source = if mariadb {
                "information_schema.SESSION_VARIABLES"
            } else {
                "performance_schema.session_variables"
            };
            assert!(full.contains(source));
        }
        // Security-relevant variables are compared, never excluded as volatile.
        for name in [
            "transaction_read_only",
            "sql_select_limit",
            "character_set_results",
            "foreign_key_checks",
            "autocommit",
        ] {
            assert!(!VOLATILE.contains(&format!("'{name}'")));
        }
    }
    #[test]
    fn writes_and_user_variables_are_never_pooled() {
        assert!(reusable_after("SELECT 1", false));
        assert!(!reusable_after("SELECT 1", true));
        assert!(!reusable_after("SELECT @leak := 1", false));
        assert!(!reusable_after(
            "SELECT 1 FROM t WHERE email = 'a@b.c'",
            false
        ));
        assert!(!reusable_after("UPDATE t SET a = 1", true));
    }
    #[test]
    fn parses_real_explain_plan_shape() {
        let plan = serde_json::json!({"query_block":{"select_id":1,"cost_info":{"query_cost":"1.20"},"table":{"table_name":"users","access_type":"ALL","rows_examined_per_scan":2,"cost_info":{"read_cost":"1.00","eval_cost":"0.20"}}}});
        assert_eq!(cost(&plan), Some(1.2));
        assert_eq!(
            cost(&serde_json::json!({"query_block":{"cost_info":{"query_cost":4.25}}})),
            Some(4.25)
        );
        assert_eq!(
            cost(&serde_json::json!({"query_block":{"cost":0.0597548}})),
            Some(0.0597548)
        );
        assert_eq!(cost(&serde_json::json!({})), None);
        assert_eq!(
            cost(&serde_json::json!({"query_block":{"cost_info":{"query_cost":"NaN"}}})),
            None
        );
    }
}
