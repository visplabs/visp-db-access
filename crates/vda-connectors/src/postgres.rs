//! PostgreSQL guarded transactions and diagnostics.
use crate::{
    cancel::{self, GuardedConnection},
    decode,
    limits::{self, Results},
    tls, Column, ConnectionSpec, ConnectorError, ExecLimits, HealthReport, PoolOptions,
    QueryResult,
};
use futures::TryStreamExt;
use sqlx::Either;
use sqlx::{postgres::PgPoolOptions, Connection, Executor, PgConnection, PgPool, Statement};
use std::{
    sync::atomic::{AtomicI32, Ordering},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

/// Session settings applied after connecting and after every reset. `DISCARD ALL`
/// restores startup-packet values (`application_name`, `TimeZone`) but not these.
const SESSION_DEFAULTS: &str = "SET idle_in_transaction_session_timeout = '60s'; \
     SET default_transaction_read_only = on; SET TIME ZONE 'UTC'";

pub(crate) fn pool(spec: &ConnectionSpec, options: PoolOptions) -> PgPool {
    let application = spec.application_name.clone();
    PgPoolOptions::new()
        .max_connections(options.max_connections)
        .min_connections(0)
        // SQLx's acquire deadline includes establishing the connection and after_connect.
        .acquire_timeout(options.acquire_timeout.min(options.connect_timeout))
        .idle_timeout(options.idle_timeout)
        .test_before_acquire(true)
        .after_connect(move |connection, _| {
            let application = application.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('application_name', $1, false)")
                    .bind(application)
                    .persistent(false)
                    .execute(&mut *connection)
                    .await?;
                connection.execute(SESSION_DEFAULTS).await?;
                Ok(())
            })
        })
        // Every connection the pool would reuse passes through here; an error or
        // timeout closes it instead.
        .after_release(|connection, _| Box::pin(cancel::bounded_reset(reset(connection))))
        .connect_lazy_with(tls::postgres(spec))
}

/// Returns a released connection to its post-connect state.
///
/// `DISCARD ALL` is PostgreSQL's complete session reset: it releases session-level
/// advisory locks (which survive ROLLBACK), closes cursors, runs `UNLISTEN *`,
/// drops temporary tables and prepared statements, and resets every setting,
/// role and session authorization. It refuses to run inside a transaction block,
/// so a connection released mid-transaction is closed rather than reused.
async fn reset(connection: &mut PgConnection) -> Result<bool, sqlx::Error> {
    // Statements SQLx still tracks are about to disappear server-side; forget them
    // first so the cache can never name a deallocated statement (no round trip
    // when the cache is empty, as it is with this crate's zero-capacity cache).
    connection.clear_cached_statements().await?;
    connection.execute("DISCARD ALL").await?;
    connection.execute(SESSION_DEFAULTS).await?;
    Ok(true)
}

async fn setup(
    connection: &mut PgConnection,
    limits: &ExecLimits,
    write: bool,
) -> Result<(), ConnectorError> {
    command(
        connection,
        if write {
            "BEGIN TRANSACTION READ WRITE ISOLATION LEVEL READ COMMITTED"
        } else {
            "BEGIN TRANSACTION READ ONLY ISOLATION LEVEL READ COMMITTED"
        },
    )
    .await?;
    let settings = [
        (
            "statement_timeout",
            limits::millis(limits.statement_timeout),
        ),
        ("lock_timeout", limits::millis(limits.lock_timeout)),
        (
            "idle_in_transaction_session_timeout",
            limits::millis(limits.statement_timeout)
                .saturating_mul(2)
                .min(i32::MAX as u64),
        ),
    ];
    for (name, value) in settings {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(format!("{value}ms"))
            .persistent(false)
            .execute(&mut *connection)
            .await
            .map_err(cancel::error)?;
    }
    Ok(())
}
async fn command(connection: &mut PgConnection, sql: &str) -> Result<(), ConnectorError> {
    sqlx::query(sql)
        .persistent(false)
        .execute(connection)
        .await
        .map_err(cancel::error)?;
    Ok(())
}

pub(crate) async fn execute(
    pool: &PgPool,
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
    let pid = AtomicI32::new(0);
    let operation = async {
        let id: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .persistent(false)
            .fetch_one(&mut *connection)
            .await
            .map_err(cancel::error)?;
        pid.store(id, Ordering::Relaxed);
        setup(&mut connection, limits, write_cap.is_some()).await?;
        let result = if let Some(cap) = write_cap {
            write(&mut connection, sql, None, limits, cap).await
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
                // The pool's after_release reset clears session state before reuse.
                connection.clean();
                Ok(result)
            }
            Err(error) => {
                if command(&mut connection, "ROLLBACK").await.is_ok() {
                    connection.clean();
                }
                Err(error)
            }
        }
    };
    let remaining = timeout.saturating_sub(start.elapsed());
    let result = cancel::race(operation, &token, remaining).await;
    if matches!(
        result,
        Err(ConnectorError::Cancelled | ConnectorError::Timeout)
    ) || matches!(&result, Ok(result) if result.truncated && write_cap.is_none())
    {
        connection.discard();
        let id = pid.load(Ordering::Relaxed);
        if id != 0 {
            cancel::postgres(pool, id).await;
        }
        // Drop closes unfinished transactions; pool capacity stays reserved until close.
    }
    result.map(|mut result| {
        result.elapsed_ms = limits::elapsed(start);
        result
    })
}
/// Run `body` in a read-write transaction with the limits applied, then
/// commit or roll back. Cancellation and the deadline kill the statement on
/// the server, as for [`execute`].
async fn in_write_transaction<T>(
    pool: &PgPool,
    limits: &ExecLimits,
    token: CancellationToken,
    commit: bool,
    body: impl AsyncFnOnce(&mut PgConnection) -> Result<T, ConnectorError>,
) -> Result<T, ConnectorError> {
    let start = Instant::now();
    let timeout = limits::hard_timeout(limits);
    let acquired = cancel::race(
        async { pool.acquire().await.map_err(cancel::error) },
        &token,
        timeout,
    )
    .await?;
    let mut connection = GuardedConnection::new(acquired);
    let pid = AtomicI32::new(0);
    let operation = async {
        let id: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .persistent(false)
            .fetch_one(&mut *connection)
            .await
            .map_err(cancel::error)?;
        pid.store(id, Ordering::Relaxed);
        setup(&mut connection, limits, true).await?;
        match body(&mut connection).await {
            Ok(value) => {
                command(&mut connection, if commit { "COMMIT" } else { "ROLLBACK" }).await?;
                connection.clean();
                Ok(value)
            }
            Err(error) => {
                if command(&mut connection, "ROLLBACK").await.is_ok() {
                    connection.clean();
                }
                Err(error)
            }
        }
    };
    let remaining = timeout.saturating_sub(start.elapsed());
    let result = cancel::race(operation, &token, remaining).await;
    if matches!(
        result,
        Err(ConnectorError::Cancelled | ConnectorError::Timeout)
    ) {
        connection.discard();
        let id = pid.load(Ordering::Relaxed);
        if id != 0 {
            cancel::postgres(pool, id).await;
        }
    }
    result
}
/// Limits for reading the rows a write targets: all of them, up to one more
/// than the write may change, so a fingerprint covers every row.
fn target_limits(limits: &ExecLimits, cap: u64) -> ExecLimits {
    ExecLimits {
        max_rows: usize::try_from(cap.saturating_add(1)).unwrap_or(usize::MAX),
        ..*limits
    }
}
/// The keys and digests of the target rows, locked.
async fn target_keys(
    connection: &mut PgConnection,
    sql: &str,
    limits: &ExecLimits,
) -> Result<(Vec<String>, crate::Targets), ConnectorError> {
    let rows = read(connection, sql, limits).await?;
    let mut keys = Vec::with_capacity(rows.rows.len());
    let mut digests = Vec::with_capacity(rows.rows.len());
    for row in &rows.rows {
        let (Some(serde_json::Value::String(key)), Some(serde_json::Value::String(digest))) =
            (row.first(), row.get(1))
        else {
            return Err(ConnectorError::EffectChanged(
                "the rows it changes could not be identified".into(),
            ));
        };
        keys.push(key.clone());
        digests.push(digest.clone());
    }
    let targets = crate::Targets {
        count: keys.len() as u64,
        complete: !rows.truncated,
        fingerprint: crate::rows_fingerprint(&digests),
    };
    Ok((keys, targets))
}
/// Whether `table` is a plain or a partitioned table: only those have the
/// `tableoid` and `ctid` that name a row.
async fn has_row_keys(
    connection: &mut PgConnection,
    table: Option<&str>,
) -> Result<bool, ConnectorError> {
    let Some(table) = table else {
        return Ok(false);
    };
    let plain: Option<bool> = sqlx::query_scalar(
        "SELECT relkind IN ('r','p') FROM pg_catalog.pg_class WHERE oid = pg_catalog.to_regclass($1)",
    )
    .bind(table)
    .persistent(false)
    .fetch_optional(&mut *connection)
    .await
    .map_err(cancel::error)?;
    Ok(plain == Some(true))
}
/// Every function outside `pg_catalog` and `information_schema` that a
/// `SELECT` would call, as PostgreSQL itself resolves it: directly, through
/// attribute notation (`row.fn`), an operator, a cast, or a view (followed
/// through views of views). The `SELECT` is made into a temporary view in a
/// transaction that is rolled back; nothing in it runs.
pub(crate) async fn database_functions(
    pool: &PgPool,
    select: &str,
    target: Option<(&str, Option<&[String]>)>,
    limits: &ExecLimits,
    token: CancellationToken,
) -> Result<Vec<String>, ConnectorError> {
    // A value written to a column is cast to the column's type, which can
    // call a cast function the SELECT never shows. Any cast function into the
    // type of a written column (or its base or element type) counts.
    const CASTS: &str = "SELECT DISTINCT p.oid::regprocedure::text
      FROM pg_catalog.pg_attribute a
      JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
      JOIN pg_catalog.pg_cast c ON c.casttarget IN (t.oid, t.typbasetype, t.typelem)
      JOIN pg_catalog.pg_proc p ON p.oid = c.castfunc
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      WHERE a.attrelid = pg_catalog.to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped
        AND ($2::text[] IS NULL OR lower(a.attname) = ANY($2::text[]))
        AND n.nspname NOT IN ('pg_catalog', 'information_schema')";
    const DEPENDS: &str = "WITH RECURSIVE deps(classid, objid, depth) AS (
        SELECT 'pg_catalog.pg_class'::regclass::oid, 'pg_temp.vda_function_check'::regclass::oid, 0
        UNION
        SELECT d.refclassid, d.refobjid, deps.depth + 1
        FROM deps
        JOIN pg_catalog.pg_rewrite r
          ON deps.classid = 'pg_catalog.pg_class'::regclass AND r.ev_class = deps.objid
        JOIN pg_catalog.pg_depend d
          ON d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid = r.oid
        WHERE deps.depth < 32
      ), called(oid) AS (
        SELECT objid FROM deps WHERE classid = 'pg_catalog.pg_proc'::regclass
        UNION
        SELECT o.oprcode FROM deps JOIN pg_catalog.pg_operator o
          ON deps.classid = 'pg_catalog.pg_operator'::regclass AND o.oid = deps.objid
      )
      SELECT DISTINCT p.oid::regprocedure::text
      FROM called JOIN pg_catalog.pg_proc p ON p.oid = called.oid
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      ORDER BY 1";
    in_write_transaction(pool, limits, token, false, async |connection| {
        command(
            connection,
            &format!(
                "CREATE TEMP VIEW vda_function_check AS SELECT 1 FROM ({select}) AS vda_check"
            ),
        )
        .await?;
        let mut found: Vec<String> = sqlx::query_scalar(DEPENDS)
            .persistent(false)
            .fetch_all(&mut *connection)
            .await
            .map_err(cancel::error)?;
        if let Some((table, columns)) = target {
            // Deliberately blind to case on both sides: a column that differs
            // only by case is checked too. Checking an extra column is
            // harmless; missing one would let its cast function run in the
            // preview.
            let columns =
                columns.map(|columns| columns.iter().map(|c| c.to_lowercase()).collect::<Vec<_>>());
            let casts: Vec<String> = sqlx::query_scalar(CASTS)
                .bind(table)
                .bind(columns)
                .persistent(false)
                .fetch_all(&mut *connection)
                .await
                .map_err(cancel::error)?;
            found.extend(casts);
        }
        found.sort();
        found.dedup();
        Ok(found)
    })
    .await
}
pub(crate) async fn dry_run(
    pool: &PgPool,
    sql: crate::WriteSql<'_>,
    limits: &ExecLimits,
    cap: u64,
    token: CancellationToken,
) -> Result<crate::DryRun, ConnectorError> {
    let start = Instant::now();
    let target_limits = target_limits(limits, cap);
    // Never committed: a dry run changes nothing.
    in_write_transaction(pool, limits, token, false, async |connection| {
        let keyed = has_row_keys(connection, sql.table).await?;
        let targets = match sql.target_keys.filter(|_| keyed) {
            Some(keys) => Some(target_keys(connection, keys, &target_limits).await?.1),
            None => None,
        };
        let target = match sql.target_rows.filter(|_| keyed) {
            Some(rows) => Some(read(connection, rows, &target_limits).await?),
            None => None,
        };
        let mut written = write(connection, sql.write, None, limits, cap).await?;
        written.elapsed_ms = limits::elapsed(start);
        Ok(crate::DryRun {
            target,
            targets,
            written,
        })
    })
    .await
}
pub(crate) async fn bound_write(
    pool: &PgPool,
    sql: crate::WriteSql<'_>,
    expected: &crate::Expected,
    limits: &ExecLimits,
    cap: u64,
    token: CancellationToken,
) -> Result<QueryResult, ConnectorError> {
    let start = Instant::now();
    let target_limits = target_limits(limits, cap);
    let changed = |reason: &str| ConnectorError::EffectChanged(reason.into());
    in_write_transaction(pool, limits, token, true, async |connection| {
        // The target rows are read with FOR UPDATE: from here to the commit
        // nobody else can change them. The write is then limited to exactly
        // these rows, so a row that joins the target set later (through a
        // subquery or a new snapshot) is not written.
        let keyed = has_row_keys(connection, sql.table).await?;
        let (statement, keys) = match (sql.target_keys, sql.bound_write) {
            (Some(keys_sql), Some(bound)) if keyed => {
                let (keys, targets) = target_keys(connection, keys_sql, &target_limits).await?;
                if !targets.complete {
                    return Err(changed("it now targets more rows than may be changed"));
                }
                if expected
                    .rows_fingerprint
                    .as_ref()
                    .is_some_and(|fingerprint| *fingerprint != targets.fingerprint)
                {
                    return Err(changed(
                        "the rows it changes are not the rows that were approved",
                    ));
                }
                (bound, Some(keys))
            }
            _ if expected.rows_fingerprint.is_some() => {
                return Err(changed("the rows it changes can no longer be identified"));
            }
            _ => (sql.write, None),
        };
        let mut result = write(connection, statement, keys.as_deref(), limits, cap).await?;
        let affected = result.affected_rows.unwrap_or(0);
        if affected != expected.affected_rows {
            return Err(ConnectorError::EffectChanged(format!(
                "it changes {affected} rows, and {} were approved",
                expected.affected_rows
            )));
        }
        result.elapsed_ms = limits::elapsed(start);
        Ok(result)
    })
    .await
}
async fn describe(connection: &mut PgConnection, sql: &str) -> Result<Vec<Column>, ConnectorError> {
    Ok(decode::columns(
        connection
            .prepare(sql)
            .await
            .map_err(cancel::error)?
            .columns(),
    ))
}
async fn read(
    connection: &mut PgConnection,
    sql: &str,
    limits: &ExecLimits,
) -> Result<QueryResult, ConnectorError> {
    let mut results = Results::new(limits);
    results.columns(describe(connection, sql).await?);
    let mut stream = sqlx::query(sql).persistent(false).fetch(&mut *connection);
    while let Some(row) = stream.try_next().await.map_err(cancel::error)? {
        if results.needs_columns() {
            results.columns(decode::pg_columns(&row));
        }
        if !results.offer(|| decode::postgres(&row)) {
            break;
        }
    }
    Ok(results.finish(None))
}
#[allow(deprecated)]
async fn write(
    connection: &mut PgConnection,
    sql: &str,
    keys: Option<&[String]>,
    limits: &ExecLimits,
    cap: u64,
) -> Result<QueryResult, ConnectorError> {
    let mut results = Results::new(limits);
    results.columns(describe(connection, sql).await?);
    let mut affected = 0u64;
    // A bound write takes the locked row keys as `$1`.
    let mut query = sqlx::query(sql).persistent(false);
    if let Some(keys) = keys {
        query = query.bind(keys.to_vec());
    }
    // CommandComplete carries the true affected count even with RETURNING.
    let mut stream = query.fetch_many(&mut *connection);
    while let Some(item) = stream.try_next().await.map_err(cancel::error)? {
        match item {
            Either::Left(result) => {
                affected = affected.saturating_add(result.rows_affected());
                if affected > cap {
                    return Err(ConnectorError::TooManyAffectedRows {
                        actual: affected,
                        limit: cap,
                    });
                }
            }
            Either::Right(row) => {
                if results.needs_columns() {
                    results.columns(decode::pg_columns(&row));
                }
                results.offer(|| decode::postgres(&row));
            }
        }
    }
    Ok(results.finish(Some(affected)))
}

pub(crate) fn cost(plan: &serde_json::Value) -> Option<f64> {
    plan.get(0)?
        .get("Plan")?
        .get("Total Cost")?
        .as_f64()
        .filter(|v| v.is_finite() && *v >= 0.0)
}
pub(crate) async fn explain(
    pool: &PgPool,
    sql: &str,
    limits: &ExecLimits,
) -> Result<Option<f64>, ConnectorError> {
    let mut budget = *limits;
    budget.max_rows = 1;
    budget.max_bytes = 4 * 1024 * 1024;
    let result = execute(
        pool,
        &format!("EXPLAIN (FORMAT JSON) {sql}"),
        &budget,
        None,
        CancellationToken::new(),
    )
    .await?;
    Ok(result
        .rows
        .first()
        .and_then(|row| row.first())
        .and_then(cost))
}

pub(crate) async fn health(pool: &PgPool, report: &mut HealthReport) -> Result<(), ConnectorError> {
    let mut connection = GuardedConnection::new(pool.acquire().await.map_err(cancel::error)?);
    let start = Instant::now();
    sqlx::query("SELECT 1")
        .persistent(false)
        .execute(&mut *connection)
        .await
        .map_err(cancel::error)?;
    report.ok = true;
    report.latency_ms = Some(limits::elapsed(start));
    report.server_version = sqlx::query_scalar("SHOW server_version")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .ok();
    report.is_replica = sqlx::query_scalar("SELECT pg_is_in_recovery()")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .ok();
    report.active_connections = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .ok();
    report.max_connections = sqlx::query_scalar::<_, String>("SHOW max_connections")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .ok()
        .and_then(|value| value.parse().ok());
    connection.clean();
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_real_explain_plan_shape() {
        let plan = serde_json::json!([{"Plan":{"Node Type":"Seq Scan","Relation Name":"users","Alias":"users","Startup Cost":0.00,"Total Cost":18.10,"Plan Rows":810,"Plan Width":36}}]);
        assert_eq!(cost(&plan), Some(18.1));
        assert_eq!(cost(&serde_json::json!([])), None);
        assert_eq!(cost(&serde_json::json!([{"Plan":{"Total Cost":-1}}])), None);
    }
}
