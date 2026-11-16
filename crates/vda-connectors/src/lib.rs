//! Guarded execution against target databases (Postgres, MySQL).
//!
//! INTERFACE CONTRACT: the public types and `TargetPool` methods below are
//! consumed by `vda-server`. Keep them stable; add fields/methods only.
//! This crate does NOT decide whether SQL is safe — `vda-guard` does. It
//! enforces runtime limits: read-only transactions, timeouts, row/byte caps,
//! affected-row caps, and server-side cancellation.

mod cancel;
mod decode;
mod limits;
mod mysql;
mod postgres;
mod schema;
mod tls;

use std::time::Duration;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Database dialect and driver for a target endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// PostgreSQL target.
    Postgres,
    /// MySQL target.
    Mysql,
}

/// Transport encryption and server identity verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Use plaintext transport.
    Disable,
    /// Try TLS and permit fallback to plaintext.
    Prefer,
    /// Require TLS without CA or hostname verification.
    Require,
    /// Require TLS and validate the CA chain and hostname.
    VerifyFull,
}

/// Target credentials and transport settings; passwords remain secret in Debug output.
#[derive(Debug, Clone)]
pub struct ConnectionSpec {
    /// Target database driver.
    pub engine: Engine,
    /// DNS name or IP address of the target.
    pub host: String,
    /// Target TCP port.
    pub port: u16,
    /// Database selected on connection.
    pub database: String,
    /// Database login role.
    pub username: String,
    /// Database password; exposed only when constructing driver options.
    pub password: SecretString,
    /// Encryption and server identity policy.
    pub tls: TlsMode,
    /// Optional PEM CA bundle for `VerifyFull`.
    pub ca_cert_pem: Option<String>,
    /// PostgreSQL activity label; MySQL stores it in `@vda_application_name`.
    pub application_name: String,
}

/// Pool capacity and connection deadlines. Pools keep zero minimum idle connections.
#[derive(Debug, Clone, Copy)]
pub struct PoolOptions {
    /// Maximum checked-out and idle connections; must be positive.
    pub max_connections: u32,
    /// Maximum acquisition deadline, including connection setup.
    pub acquire_timeout: Duration,
    /// Connection setup deadline. SQLx uses the smaller of this and acquire_timeout
    /// for the whole acquisition, including queue wait and session initialization.
    pub connect_timeout: Duration,
    /// How long an unused connection may remain pooled.
    pub idle_timeout: Duration,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            max_connections: 5,
            acquire_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// Execution budgets applied independently of SQL safety analysis.
#[derive(Debug, Clone, Copy)]
pub struct ExecLimits {
    /// Server statement deadline; client deadline adds two seconds.
    pub statement_timeout: Duration,
    /// Maximum lock wait (rounded up to whole seconds for MySQL).
    pub lock_timeout: Duration,
    /// Stop reading after this many rows; `truncated = true` if more existed.
    pub max_rows: usize,
    /// Maximum serialized row-array bytes; the overflow row is discarded.
    pub max_bytes: usize,
}

/// Result column metadata reported by the database driver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Column {
    /// Database-reported name.
    pub name: String,
    /// Type name reported by the database.
    pub type_name: String,
}

/// Bounded query output and execution statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryResult {
    /// Ordered result columns, including metadata for empty results.
    pub columns: Vec<Column>,
    /// Values decoded to JSON. Unknown types fall back to their text form;
    /// binary → base64 string prefixed `base64:`.
    pub rows: Vec<Vec<serde_json::Value>>,
    /// Number of rows retained in this result.
    pub row_count: usize,
    /// Whether at least one output row was discarded due to a budget.
    pub truncated: bool,
    /// Full database affected count for writes; None for reads.
    pub affected_rows: Option<u64>,
    /// Wall-clock milliseconds, including acquisition and cleanup.
    pub elapsed_ms: u64,
}

/// Connectivity and best-effort diagnostic probes for a target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthReport {
    /// Whether the connectivity probe completed within its deadline.
    pub ok: bool,
    /// Measured SELECT 1 latency, excluding pool acquisition.
    pub latency_ms: Option<u64>,
    /// Server version when the sub-probe succeeds.
    pub server_version: Option<String>,
    /// Recovery or replica state, inferred from engine-specific probes.
    pub is_replica: Option<bool>,
    /// Current connection count, if visible to the login role.
    pub active_connections: Option<i64>,
    /// Configured server connection limit, when available.
    pub max_connections: Option<i64>,
    /// Connectivity or overall deadline failure.
    pub error: Option<String>,
}

/// Catalog object type supported by schema introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TableKind {
    /// Ordinary or partitioned table.
    Table,
    /// Logical view.
    View,
    /// PostgreSQL materialized view.
    MaterializedView,
}

/// Column definition from the target catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaColumn {
    /// Database-reported name.
    pub name: String,
    /// Catalog type spelling, including modifiers when available.
    pub data_type: String,
    /// Whether the catalog allows NULL in this column.
    pub nullable: bool,
    /// Whether this column participates in the primary key.
    pub is_primary_key: bool,
}

/// Table or view definition, including visible columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaTable {
    /// Database-reported name.
    pub name: String,
    /// Table, view or materialized view classification.
    pub kind: TableKind,
    /// Nonnegative catalog row estimate; None when unavailable.
    pub row_estimate: Option<i64>,
    /// Columns in catalog ordinal order.
    pub columns: Vec<SchemaColumn>,
}

/// Named schema and its deterministically ordered tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaInfo {
    /// Database-reported name.
    pub name: String,
    /// Tables ordered deterministically by name.
    pub tables: Vec<SchemaTable>,
}

/// User catalog, bounded to 5,000 tables and 100,000 columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaTree {
    /// Non-system schemas ordered deterministically by name.
    pub schemas: Vec<SchemaInfo>,
}

/// Stable connector failures consumed by the server query pipeline.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// Transport, authentication or invalid pool configuration.
    #[error("connection failed: {0}")]
    Connect(String),
    /// Query or decoding failure reported by the database.
    #[error("database error: {0}")]
    Database(String),
    /// Server or client execution deadline exceeded.
    #[error("query timed out")]
    Timeout,
    /// Cancellation token or server query interruption.
    #[error("query cancelled")]
    Cancelled,
    /// Write exceeded its affected-row budget and was rolled back.
    #[error("affected rows {actual} exceed limit {limit}; transaction rolled back")]
    TooManyAffectedRows { actual: u64, limit: u64 },
    /// A pool connection was unavailable before its deadline.
    #[error("pool exhausted")]
    PoolExhausted,
    /// An approved write would no longer have the effect that was approved:
    /// the rows it changes, or how many, are not what the dry run showed. The
    /// transaction was rolled back.
    #[error("effect changed since approval: {0}")]
    EffectChanged(String),
    /// The engine does not support this operation.
    #[error("not supported: {0}")]
    Unsupported(&'static str),
}

/// What a dry run of a write saw. Nothing was changed: the transaction was
/// rolled back.
#[derive(Debug, Clone)]
pub struct DryRun {
    /// The rows the write was going to change, as they were before it ran.
    pub target: Option<QueryResult>,
    /// The keys and digests of those rows.
    pub targets: Option<Targets>,
    /// What the write returned (its `RETURNING` rows) and its affected count.
    pub written: QueryResult,
}
/// The rows a write targets, by key and digest.
#[derive(Debug, Clone)]
pub struct Targets {
    /// How many target rows were read.
    pub count: u64,
    /// `false` when there were more than the write may change.
    pub complete: bool,
    /// A digest of the digests of every target row, in any order.
    pub fingerprint: String,
}
/// The SQL of one write and of its row plan, from the guard's write planner.
#[derive(Debug, Clone, Copy)]
pub struct WriteSql<'a> {
    /// The statement to run: for a dry run, with `RETURNING` added.
    pub write: &'a str,
    /// Selects and locks the target rows, for a preview.
    pub target_rows: Option<&'a str>,
    /// Selects and locks a key and a digest of each target row.
    pub target_keys: Option<&'a str>,
    /// The statement limited to the rows whose keys are bound as `$1`.
    pub bound_write: Option<&'a str>,
    /// The changed table. The row plan is used only when it is a plain or a
    /// partitioned table; a view gets the count alone.
    pub table: Option<&'a str>,
}
/// The effect that an approval was given for. An approved write runs only if
/// it still has this effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expected {
    /// How many rows the write changes.
    pub affected_rows: u64,
    /// A digest of the rows it changes, as they were at the dry run. `None`
    /// when only the count can be bound.
    pub rows_fingerprint: Option<String>,
}
/// A digest of a set of row digests that does not depend on their order.
pub fn rows_fingerprint(digests: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut lines: Vec<&String> = digests.iter().collect();
    lines.sort_unstable();
    let mut hasher = Sha256::new();
    for line in &lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A connection pool to one target endpoint (primary or replica).
///
/// Pools built by [`TargetPool::new_lazy`] reset or verify every session before
/// reuse (PostgreSQL `DISCARD ALL`; MySQL lock release plus a comparison with a
/// fresh session), so no request's session state reaches the next. Pools wrapped
/// directly in a variant do not get that reset.
#[derive(Debug, Clone)]
pub enum TargetPool {
    /// PostgreSQL driver pool.
    Postgres(sqlx::PgPool),
    /// MySQL driver pool.
    Mysql(sqlx::MySqlPool),
}

impl TargetPool {
    /// Lazily-connecting pool; does not fail if the DB is down.
    pub fn new_lazy(spec: &ConnectionSpec, opts: PoolOptions) -> Result<Self, ConnectorError> {
        if opts.max_connections == 0
            || opts.acquire_timeout.is_zero()
            || opts.connect_timeout.is_zero()
        {
            return Err(ConnectorError::Connect(
                "pool capacity and timeouts must be positive".into(),
            ));
        }
        Ok(match spec.engine {
            Engine::Postgres => Self::Postgres(postgres::pool(spec, opts)),
            Engine::Mysql => Self::Mysql(mysql::pool(spec, opts)),
        })
    }

    /// Database engine served by this pool.
    pub fn engine(&self) -> Engine {
        match self {
            Self::Postgres(_) => Engine::Postgres,
            Self::Mysql(_) => Engine::Mysql,
        }
    }

    /// Cheap probe: `SELECT 1` + version + replica flag + connection counts.
    /// Never returns Err; failures are reported in `HealthReport.error`.
    pub async fn health(&self) -> HealthReport {
        let mut report = empty_health();
        let probe = async {
            match self {
                Self::Postgres(pool) => postgres::health(pool, &mut report).await,
                Self::Mysql(pool) => mysql::health(pool, &mut report).await,
            }
        };
        match tokio::time::timeout(Duration::from_secs(5), probe).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                report.ok = false;
                report.error = Some(error.to_string());
            }
            Err(_) => {
                report.ok = false;
                report.error = Some("health probe timed out after 5 seconds".into());
            }
        }
        report
    }

    /// Estimated total cost from `EXPLAIN` (no execution). `None` if unavailable.
    pub async fn explain_cost(
        &self,
        sql: &str,
        limits: &ExecLimits,
    ) -> Result<Option<f64>, ConnectorError> {
        match self {
            Self::Postgres(pool) => postgres::explain(pool, sql, limits).await,
            Self::Mysql(pool) => mysql::explain(pool, sql, limits).await,
        }
    }

    /// Run a read-only statement in a READ ONLY transaction that is always rolled back.
    /// Cancelling `cancel` kills the query server-side and returns `Cancelled`.
    pub async fn execute_read(
        &self,
        sql: &str,
        limits: &ExecLimits,
        cancel: CancellationToken,
    ) -> Result<QueryResult, ConnectorError> {
        match self {
            Self::Postgres(pool) => postgres::execute(pool, sql, limits, None, cancel).await,
            Self::Mysql(pool) => mysql::execute(pool, sql, limits, None, cancel).await,
        }
    }

    /// Run a write and roll it back, to see its effect without changing
    /// anything. `target_sql` selects (and locks) the rows the write will
    /// change; it runs first, in the same transaction. PostgreSQL only.
    pub async fn dry_run_write(
        &self,
        sql: WriteSql<'_>,
        limits: &ExecLimits,
        max_affected_rows: u64,
        cancel: CancellationToken,
    ) -> Result<DryRun, ConnectorError> {
        match self {
            Self::Postgres(pool) => {
                postgres::dry_run(pool, sql, limits, max_affected_rows, cancel).await
            }
            Self::Mysql(_) => Err(ConnectorError::Unsupported("dry runs on MySQL")),
        }
    }

    /// Functions defined in the database that a `SELECT` would call, as the
    /// database resolves them. Nothing runs. PostgreSQL only; MySQL: none.
    /// `target` is the written table and its written columns (`None`: all),
    /// whose casts into their types count too.
    pub async fn database_functions(
        &self,
        select: &str,
        target: Option<(&str, Option<&[String]>)>,
        limits: &ExecLimits,
        cancel: CancellationToken,
    ) -> Result<Vec<String>, ConnectorError> {
        match self {
            Self::Postgres(pool) => {
                postgres::database_functions(pool, select, target, limits, cancel).await
            }
            Self::Mysql(_) => Ok(vec![]),
        }
    }

    /// Run an approved write only if it still has the approved effect: the
    /// same rows (when a fingerprint was taken) and the same count. With a
    /// row plan, the write changes only the target rows that were locked and
    /// checked. Otherwise roll back and return `EffectChanged`. PostgreSQL only.
    pub async fn execute_bound_write(
        &self,
        sql: WriteSql<'_>,
        expected: &Expected,
        limits: &ExecLimits,
        max_affected_rows: u64,
        cancel: CancellationToken,
    ) -> Result<QueryResult, ConnectorError> {
        match self {
            Self::Postgres(pool) => {
                postgres::bound_write(pool, sql, expected, limits, max_affected_rows, cancel).await
            }
            Self::Mysql(_) => Err(ConnectorError::Unsupported("bound writes on MySQL")),
        }
    }

    /// Run a write in a transaction; roll back if affected rows > `max_affected_rows`.
    /// PostgreSQL RETURNING rows obey the read budgets without losing affected counts.
    /// Callers must reject implicit-commit SQL and nontransactional MySQL table writes
    /// when rollback guarantees are required.
    pub async fn execute_write(
        &self,
        sql: &str,
        limits: &ExecLimits,
        max_affected_rows: u64,
        cancel: CancellationToken,
    ) -> Result<QueryResult, ConnectorError> {
        match self {
            Self::Postgres(pool) => {
                postgres::execute(pool, sql, limits, Some(max_affected_rows), cancel).await
            }
            Self::Mysql(pool) => {
                mysql::execute(pool, sql, limits, Some(max_affected_rows), cancel).await
            }
        }
    }

    /// Introspect user schemas (excludes system schemas); MySQL uses the current database.
    pub async fn schema(&self) -> Result<SchemaTree, ConnectorError> {
        schema::load(self).await
    }

    /// Close idle connections and wait for active connections to be released.
    pub async fn close(&self) {
        match self {
            Self::Postgres(p) => p.close().await,
            Self::Mysql(p) => p.close().await,
        }
    }
}

/// One-shot connection test with a fresh single-connection pool.
pub async fn test_connection(spec: &ConnectionSpec) -> HealthReport {
    let options = PoolOptions {
        max_connections: 1,
        acquire_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        ..PoolOptions::default()
    };
    match TargetPool::new_lazy(spec, options) {
        Ok(pool) => {
            let report = pool.health().await;
            pool.close().await;
            report
        }
        Err(error) => {
            let mut report = empty_health();
            report.error = Some(error.to_string());
            report
        }
    }
}

fn empty_health() -> HealthReport {
    HealthReport {
        ok: false,
        latency_ms: None,
        server_version: None,
        is_replica: None,
        active_connections: None,
        max_connections: None,
        error: None,
    }
}
