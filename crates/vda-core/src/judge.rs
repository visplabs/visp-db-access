//! The database is the judge.
//!
//! The SQL guard reads text and can be fooled by SQL it does not understand.
//! The target database cannot: it decides what a login may read. So agents'
//! queries run as a separate login that holds exactly the column grants the
//! cluster policy allows, and nothing else.
//!
//! The gateway never creates or changes that login. It writes a script for a
//! database administrator ([`script`]) and then verifies, as that login, what
//! the database really allows ([`verify`]). Anything readable or writable
//! beyond the policy is drift, and agents are refused until it is gone.
use crate::{error::ApiError, policy::Policy, records::ClusterRecord, Core};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vda_connectors::{ExecLimits, SchemaTree, TableKind, TargetPool};

/// How long a clean verification is trusted before it is run again. A schema
/// change on the target does not tell the gateway, so this bounds how long a
/// new, wrongly open object can stay unnoticed.
pub const TRUST_SECONDS: u64 = 300;

/// What a verification found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// `critical` stops agents; `warning` does not.
    pub severity: String,
    /// Stable machine code.
    pub code: String,
    /// The schema, table, column, function or role it is about.
    pub object: String,
    pub message: String,
}
fn critical(code: &str, object: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding {
        severity: "critical".into(),
        code: code.into(),
        object: object.into(),
        message: message.into(),
    }
}
fn warning(code: &str, object: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding {
        severity: "warning".into(),
        ..critical(code, object, message)
    }
}

/// Which tables share rows. A partition or an inheritance child holds rows of
/// its parent, and a query on a parent returns its children's rows. A child
/// with two parents shows its rows through both. So a rule about one table is
/// a rule about every table it is linked to, however far.
#[derive(Debug, Default, Clone)]
pub struct Family {
    /// The group of each linked `schema.table`, lower-case.
    group_of: BTreeMap<String, usize>,
    /// The members of each group.
    groups: Vec<Vec<String>>,
}
impl Family {
    /// Build from child-to-parent edges, each name as `schema.table`. The work
    /// is close to linear in the number of edges, so a table with thousands
    /// of partitions costs no more per partition than a small one.
    pub fn new(edges: &[(String, String)]) -> Self {
        let mut index: BTreeMap<String, usize> = BTreeMap::new();
        let mut names: Vec<String> = Vec::new();
        let mut parent: Vec<usize> = Vec::new();
        let mut id = |name: &str, names: &mut Vec<String>, parent: &mut Vec<usize>| {
            let name = name.to_lowercase();
            *index.entry(name.clone()).or_insert_with(|| {
                names.push(name);
                parent.push(parent.len());
                parent.len() - 1
            })
        };
        // Union-find: `root` follows links to the group's representative.
        fn root(parent: &mut [usize], mut node: usize) -> usize {
            while let Some(&above) = parent.get(node) {
                if above == node {
                    break;
                }
                // Point at the grandparent to keep later walks short.
                let next = parent.get(above).copied().unwrap_or(above);
                if let Some(slot) = parent.get_mut(node) {
                    *slot = next;
                }
                node = above;
            }
            node
        }
        for (child, above) in edges {
            let (a, b) = (
                id(child, &mut names, &mut parent),
                id(above, &mut names, &mut parent),
            );
            let (a, b) = (root(&mut parent, a), root(&mut parent, b));
            if let Some(slot) = parent.get_mut(a) {
                *slot = b;
            }
        }
        let mut slot_of: BTreeMap<usize, usize> = BTreeMap::new();
        let mut groups: Vec<Vec<String>> = Vec::new();
        let mut group_of = BTreeMap::new();
        for (node, name) in names.into_iter().enumerate() {
            let top = root(&mut parent, node);
            let slot = *slot_of.entry(top).or_insert_with(|| {
                groups.push(Vec::new());
                groups.len() - 1
            });
            if let Some(group) = groups.get_mut(slot) {
                group.push(name.clone());
            }
            group_of.insert(name, slot);
        }
        Self { group_of, groups }
    }
    /// Apply a policy to every family once. After this, the rule for a table
    /// is a lookup, however large its family is.
    fn rules<'a>(&'a self, policy: &'a Policy) -> Rules<'a> {
        Rules {
            family: self,
            policy,
            by_group: self
                .groups
                .iter()
                .map(|names| TableRule::new(policy, names))
                .collect(),
        }
    }
}
/// A policy applied to the families of one database.
struct Rules<'a> {
    family: &'a Family,
    policy: &'a Policy,
    by_group: Vec<TableRule>,
}
impl Rules<'_> {
    /// What the policy says about one table, taking its whole family into account.
    fn of(&self, schema: &str, table: &str) -> TableRule {
        let name = format!("{schema}.{table}").to_lowercase();
        self.family
            .group_of
            .get(&name)
            .and_then(|slot| self.by_group.get(*slot))
            .cloned()
            .unwrap_or_else(|| TableRule::new(self.policy, std::slice::from_ref(&name)))
    }
}
/// The policy for one table and its family.
#[derive(Debug, Clone)]
struct TableRule {
    blocked: bool,
    /// Column-name patterns that are protected on this table.
    protected: Vec<String>,
}
impl TableRule {
    /// The rule for a set of tables that share rows.
    fn new(policy: &Policy, names: &[String]) -> Self {
        let blocked = policy.blocked_tables.iter().any(|pattern| {
            names
                .iter()
                .any(|name| vda_guard::relation_matches(pattern, name))
        });
        // The column part of every protection pattern that applies here: all
        // unqualified ones, and qualified ones whose table part matches a member.
        let protected = policy
            .masked_columns
            .iter()
            .filter_map(|pattern| match pattern.rsplit_once('.') {
                None => Some(pattern.clone()),
                Some((owner, column)) => names
                    .iter()
                    .any(|name| vda_guard::relation_matches(owner, name))
                    .then(|| column.to_owned()),
            })
            .collect();
        Self { blocked, protected }
    }
    /// Whether the policy lets an agent read this column, were it a plain table.
    fn reads(&self, column: &str) -> bool {
        !self.blocked
            && !self
                .protected
                .iter()
                .any(|pattern| crate::masking::glob(pattern, column))
    }
}

/// Whether the policy lets an agent read this column of this object.
/// Only ordinary tables are readable: a view or a materialized view runs as
/// its owner or holds a copy, so it can show what the policy hides. A table is
/// closed when it or any table of its family is blocked, and a column is
/// closed when it is protected on any of them.
#[cfg(test)]
fn allowed(
    policy: &Policy,
    family: &Family,
    (schema, table, column): (&str, &str, &str),
    plain_table: bool,
) -> bool {
    plain_table && family.rules(policy).of(schema, table).reads(column)
}

/// Quote an identifier for PostgreSQL.
fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
/// A login name the script and the gateway accept: plain, lower-case, short.
pub fn valid_role(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !name.starts_with("pg_")
        // Names that PostgreSQL reserves, or that every server already has.
        && !matches!(
            name,
            "public"
                | "none"
                | "user"
                | "current_user"
                | "current_role"
                | "session_user"
                | "postgres"
                | "all"
        )
}

/// The SQL that a database administrator runs to create or repair the agent
/// login. It grants column by column, never a whole table, so a column added
/// later is closed until someone decides about it.
///
/// The script refuses to touch a login that is a superuser or owns anything:
/// its next step removes all that the login holds, and for a login that
/// people or an application use, that would be destructive.
pub fn script(
    role: &str,
    database: &str,
    schema: &SchemaTree,
    policy: &Policy,
    family: &Family,
) -> Result<String, ApiError> {
    if !valid_role(role) {
        return Err(ApiError::validation("Invalid login name"));
    }
    // `role` is now known to be plain; it needs no escaping in a literal.
    let (name, role) = (literal(role), ident(role));
    let mut out = vec![
        "-- visp-db-access: agent login for PostgreSQL.".to_owned(),
        "-- Run this as a database administrator, in the database named below.".to_owned(),
        "-- Use a NEW login name. The script stops if the login is a superuser or".to_owned(),
        "-- owns anything, because it removes everything the login holds here.".to_owned(),
        "-- It is safe to run again for the same agent login.".to_owned(),
        "-- Set the password afterwards with:  \\password ".to_owned() + &role,
        "-- Then enter that login in the gateway, which verifies the result.".to_owned(),
        "BEGIN;".to_owned(),
        "-- Stops with a division by zero when run in another database.".to_owned(),
        format!(
            "SELECT 1 / (current_database() = {})::int AS right_database;",
            escaped(database)
        ),
        format!(
            "DO $vda$ BEGIN IF EXISTS (SELECT FROM pg_catalog.pg_roles r WHERE r.rolname = {name} AND (r.rolsuper OR EXISTS (SELECT FROM pg_catalog.pg_shdepend d WHERE d.refclassid = 'pg_catalog.pg_authid'::regclass AND d.refobjid = r.oid AND d.deptype = 'o'))) THEN RAISE EXCEPTION 'The login % is a superuser or owns objects. Choose a new login name.', {name}; END IF; IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = {name}) THEN CREATE ROLE {role} LOGIN; END IF; END $vda$;"
        ),
        format!("ALTER ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;"),
        format!("ALTER ROLE {role} SET default_transaction_read_only = on;"),
        // Removes every privilege the login holds in this database, and only
        // those, in one statement. The check above made sure it owns nothing.
        format!("DROP OWNED BY {role};"),
        format!("GRANT CONNECT ON DATABASE {} TO {role};", ident(database)),
    ];
    let mut granted = 0usize;
    let rules = family.rules(policy);
    for group in &schema.schemas {
        let name = ident(&group.name);
        let mut grants = Vec::new();
        for table in &group.tables {
            // Only ordinary tables: a view runs as its owner, a copy holds
            // rows of its source, and either can show what the policy hides.
            if table.kind != TableKind::Table {
                continue;
            }
            let rule = rules.of(&group.name, &table.name);
            let columns: Vec<String> = table
                .columns
                .iter()
                .filter(|column| rule.reads(&column.name))
                .map(|column| ident(&column.name))
                .collect();
            if !columns.is_empty() {
                grants.push(format!(
                    "GRANT SELECT ({}) ON {name}.{} TO {role};",
                    columns.join(", "),
                    ident(&table.name)
                ));
            }
        }
        if !grants.is_empty() {
            granted += grants.len();
            out.push(format!("GRANT USAGE ON SCHEMA {name} TO {role};"));
            out.append(&mut grants);
        }
    }
    out.push("COMMIT;".to_owned());
    out.push(format!(
        "-- {granted} tables granted. Views, materialized views, blocked tables (with their"
    ));
    out.push(
        "-- partitions, parents and children) and protected columns are not granted.".to_owned(),
    );
    out.push("-- At most 5000 tables are read from the catalog; the rest stay closed.".to_owned());
    out.push(
        "-- A grant to PUBLIC is not removed by this script; the gateway's check reports"
            .to_owned(),
    );
    out.push("-- any that still opens something to the login.".to_owned());
    Ok(out.join("\n") + "\n")
}
/// A literal for text that is not ours. The escape form reads the same
/// whatever `standard_conforming_strings` is set to.
fn escaped(text: &str) -> String {
    format!("E'{}'", text.replace('\\', "\\\\").replace('\'', "''"))
}
fn literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

const ROLE_SQL: &str =
    "SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
 (SELECT count(*) FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid) AS memberships,
 COALESCE(pg_catalog.array_to_string(r.rolconfig, ','), '') AS settings,
 COALESCE((SELECT pg_catalog.string_agg(n.nspname, ', ') FROM pg_catalog.pg_namespace n
   WHERE pg_catalog.has_schema_privilege(n.oid, 'CREATE') AND n.nspname NOT LIKE 'pg\\_%'
   AND n.nspname <> 'information_schema'), '') AS creatable,
 pg_catalog.has_database_privilege(pg_catalog.current_database(), 'CREATE') AS database_create
 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
const COLUMN_SQL: &str = "SELECT n.nspname, c.relname, c.relkind::text, a.attname,
 pg_catalog.has_schema_privilege(n.oid, 'USAGE')
   AND pg_catalog.has_column_privilege(c.oid, a.attnum, 'SELECT') AS can_read,
 pg_catalog.has_any_column_privilege(c.oid, 'INSERT,UPDATE,REFERENCES')
   OR pg_catalog.has_table_privilege(c.oid, 'DELETE,TRUNCATE,TRIGGER') AS can_write,
 EXISTS (SELECT FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_class'::regclass
   AND d.objid = c.oid AND d.deptype = 'e') AS from_extension
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
 WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema')
 AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'
 ORDER BY n.nspname, c.relname, a.attnum";
// Every schema, and no test for USAGE on it: an aggregate or an operator can
// call a function in a schema that the login cannot otherwise use.
const DEFINER_SQL: &str = "SELECT DISTINCT n.nspname, p.proname FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
 WHERE p.prosecdef AND pg_catalog.has_function_privilege(p.oid, 'EXECUTE') ORDER BY 1, 2";
/// Child-to-parent links of partitions and inheritance.
const INHERIT_SQL: &str = "SELECT cn.nspname || '.' || c.relname, pn.nspname || '.' || p.relname
 FROM pg_catalog.pg_inherits i
 JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
 JOIN pg_catalog.pg_namespace cn ON cn.oid = c.relnamespace
 JOIN pg_catalog.pg_class p ON p.oid = i.inhparent
 JOIN pg_catalog.pg_namespace pn ON pn.oid = p.relnamespace
 WHERE c.relkind IN ('r','p','f') AND p.relkind IN ('r','p','f') ORDER BY 1, 2";
/// Ways around table grants that the column check does not see: system
/// tables that hold copies of table data or credentials, storage tables,
/// foreign servers, and built-in functions that read files or other servers.
const BYPASS_SQL: &str =
    "SELECT 'system_catalog_readable' AS code, n.nspname || '.' || c.relname AS object
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r','v','m','t') AND pg_catalog.has_schema_privilege(n.oid, 'USAGE')
 AND pg_catalog.has_any_column_privilege(c.oid, 'SELECT')
 AND ((n.nspname = 'pg_catalog' AND c.relname IN ('pg_statistic','pg_statistic_ext_data',
   'pg_authid','pg_shadow','pg_largeobject','pg_user_mapping'))
   OR n.nspname = 'pg_toast')
 UNION ALL
 SELECT 'system_catalog_readable', n.nspname || '.' || c.relname
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname IN ('pg_catalog','information_schema') AND c.oid >= 16384
 AND c.relkind IN ('r','p','v','m','f') AND pg_catalog.has_any_column_privilege(c.oid, 'SELECT')
 UNION ALL
 SELECT 'foreign_server', s.srvname::text FROM pg_catalog.pg_foreign_server s
 WHERE pg_catalog.has_server_privilege(s.oid, 'USAGE')
 UNION ALL
 SELECT DISTINCT 'dangerous_function', n.nspname || '.' ||
   CASE WHEN p.proname LIKE 'dblink%' THEN 'dblink functions' ELSE p.proname END
 FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
 WHERE pg_catalog.has_function_privilege(p.oid, 'EXECUTE')
 AND pg_catalog.has_schema_privilege(n.oid, 'USAGE')
 AND ((n.nspname = 'pg_catalog' AND p.proname IN ('pg_read_file','pg_read_binary_file',
   'pg_ls_dir','pg_ls_logdir','pg_ls_waldir','pg_stat_file','lo_import','lo_export'))
   OR p.proname LIKE 'dblink%')
 ORDER BY 1, 2";
/// Rows the check reads at most; a database with more columns fails the check
/// rather than pass with part of it unread.
const MAX_ROWS: usize = 200_000;

fn text(row: &[Value], index: usize) -> Result<&str, ApiError> {
    row.get(index)
        .and_then(Value::as_str)
        .ok_or_else(ApiError::internal)
}
fn flag(row: &[Value], index: usize) -> Result<bool, ApiError> {
    row.get(index)
        .and_then(Value::as_bool)
        .ok_or_else(ApiError::internal)
}

/// Ask the database, as the agent login, what that login can really do, and
/// compare it with the policy. The answer comes from the database's own
/// privilege functions, so it includes grants to PUBLIC, inherited rights and
/// anything else that text analysis could not see.
pub async fn verify(pool: &TargetPool, policy: &Policy) -> Result<Vec<Finding>, ApiError> {
    let limits = ExecLimits {
        statement_timeout: Duration::from_secs(15),
        lock_timeout: Duration::from_secs(1),
        max_rows: MAX_ROWS,
        max_bytes: 64 * 1024 * 1024,
    };
    let mut findings = Vec::new();
    let role = pool
        .execute_read(ROLE_SQL, &limits, CancellationToken::new())
        .await?;
    let row = role.rows.first().ok_or_else(ApiError::internal)?;
    for (index, power) in [
        (0, "is a superuser"),
        (1, "can create roles"),
        (2, "can create databases"),
        (3, "can start replication"),
        (4, "bypasses row-level security"),
    ] {
        if flag(row, index)? {
            findings.push(critical(
                "role_too_powerful",
                "login",
                format!("The agent login {power}."),
            ));
        }
    }
    if row.get(5).and_then(Value::as_i64) != Some(0) {
        findings.push(critical(
            "role_too_powerful",
            "login",
            "The agent login is a member of another role and takes on its rights.",
        ));
    }
    // The role's own setting: the gateway's sessions set theirs, so the session
    // value says nothing about what another client of this login would get.
    if !text(row, 6)?.contains("default_transaction_read_only=on") {
        findings.push(warning(
            "not_read_only",
            "login",
            "The agent login's sessions are not read-only by default.",
        ));
    }
    let creatable = text(row, 7)?;
    if !creatable.is_empty() {
        findings.push(critical(
            "can_create",
            creatable,
            "The agent login can create objects in these schemas. PostgreSQL 14 and older let everyone create in `public`. REVOKE CREATE ON SCHEMA public FROM PUBLIC closes it; first grant CREATE to the roles that need it.",
        ));
    }
    if flag(row, 8)? {
        findings.push(critical(
            "can_create",
            "database",
            "The agent login can create schemas in this database.",
        ));
    }
    let columns = pool
        .execute_read(COLUMN_SQL, &limits, CancellationToken::new())
        .await?;
    if columns.truncated {
        return Err(too_large());
    }
    let family = inheritance(pool).await?;
    // One finding per table keeps a large drift readable.
    let mut extra: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut extension: BTreeMap<String, ()> = BTreeMap::new();
    let mut missing: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut writable: BTreeMap<String, ()> = BTreeMap::new();
    let rules = family.rules(policy);
    // Rows come ordered by table, so one rule serves all columns of a table.
    let mut current: Option<(String, TableRule)> = None;
    for row in &columns.rows {
        let (schema, table, kind, column) =
            (text(row, 0)?, text(row, 1)?, text(row, 2)?, text(row, 3)?);
        let object = format!("{schema}.{table}");
        if current.as_ref().is_none_or(|(name, _)| *name != object) {
            current = Some((object.clone(), rules.of(schema, table)));
        }
        let unnamed = current.as_ref().is_some_and(|(_, rule)| rule.reads(column));
        let expected = unnamed && matches!(kind, "r" | "p");
        match (flag(row, 4)?, expected) {
            // A view that an extension installed, such as its statistics view,
            // is not the application's data. It is reported, but it does not
            // close the cluster. That holds only when the policy has no rule
            // about it: a blocked or protected name is never waved through.
            (true, false) if flag(row, 6)? && unnamed => {
                extension.insert(object.clone(), ());
            }
            (true, false) => extra
                .entry(object.clone())
                .or_default()
                .push(column.to_owned()),
            (false, true) => missing
                .entry(object.clone())
                .or_default()
                .push(column.to_owned()),
            _ => {}
        }
        if flag(row, 5)? {
            writable.insert(object, ());
        }
    }
    for (object, columns) in extra {
        findings.push(critical(
            "readable_beyond_policy",
            object,
            format!(
                "The agent login can read columns that the policy hides: {}.",
                columns.join(", ")
            ),
        ));
    }
    let bypass = pool
        .execute_read(BYPASS_SQL, &limits, CancellationToken::new())
        .await?;
    for row in &bypass.rows {
        let (code, object) = (text(row, 0)?, text(row, 1)?);
        let message = match code {
            "system_catalog_readable" => "The agent login can read a system table that holds copies of table data or credentials, or an object that someone added to a system schema.",
            "foreign_server" => "The agent login can use a foreign server, which reads with another login's rights.",
            _ => "The agent login can run a function that reads files or connects to other servers. Revoke EXECUTE on it from PUBLIC and grant it to the roles that need it.",
        };
        findings.push(critical(code, object, message));
    }
    for (object, ()) in extension {
        findings.push(warning(
            "extension_object_readable",
            object,
            "The agent login can read an object that an extension installed. Revoke it from PUBLIC if it shows anything sensitive.",
        ));
    }
    for (object, ()) in writable {
        findings.push(critical(
            "can_write",
            object,
            "The agent login can change this table.",
        ));
    }
    let definers = pool
        .execute_read(DEFINER_SQL, &limits, CancellationToken::new())
        .await?;
    for row in &definers.rows {
        findings.push(critical(
            "definer_function",
            format!("{}.{}", text(row, 0)?, text(row, 1)?),
            "The agent login can run this function, which runs with its owner's rights and can read what the policy hides.",
        ));
    }
    for (object, columns) in missing {
        findings.push(warning(
            "not_granted",
            object,
            format!(
                "The policy allows these columns but the login cannot read them: {}.",
                columns.join(", ")
            ),
        ));
    }
    Ok(bounded(findings))
}
/// Keep the list a person can read and the row small. A very large catalog
/// can give thousands of findings of one kind; the first ones and a count say
/// as much. Critical findings come first, so they are the last to be cut.
fn bounded(mut findings: Vec<Finding>) -> Vec<Finding> {
    const KEEP: usize = 200;
    findings.sort_by_key(|finding| finding.severity != "critical");
    if findings.len() > KEEP {
        let (total, critical) = (
            findings.len(),
            findings.iter().filter(|f| f.severity == "critical").count(),
        );
        findings.truncate(KEEP);
        findings.push(warning(
            "more_findings",
            "check",
            format!("{total} findings in all, {critical} of them critical. The first {KEEP} are listed."),
        ));
    }
    findings
}

/// Read which tables share rows, through any login that can see the catalog.
pub async fn inheritance(pool: &TargetPool) -> Result<Family, ApiError> {
    let limits = ExecLimits {
        statement_timeout: Duration::from_secs(15),
        lock_timeout: Duration::from_secs(1),
        max_rows: MAX_ROWS,
        max_bytes: 64 * 1024 * 1024,
    };
    let links = pool
        .execute_read(INHERIT_SQL, &limits, CancellationToken::new())
        .await?;
    if links.truncated {
        return Err(too_large());
    }
    let mut edges = Vec::with_capacity(links.rows.len());
    for row in &links.rows {
        edges.push((text(row, 0)?.to_owned(), text(row, 1)?.to_owned()));
    }
    Ok(Family::new(&edges))
}
fn too_large() -> ApiError {
    ApiError::new(
        http::StatusCode::UNPROCESSABLE_ENTITY,
        "database_too_large",
        "The database has more tables or columns than the check can read",
    )
}

/// The stored agent login of a cluster.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentLogin {
    pub username: String,
    pub password_enc: String,
}
/// Load the agent login of a cluster, if one is set.
pub async fn login(pool: &sqlx::PgPool, cluster: Uuid) -> Result<Option<AgentLogin>, ApiError> {
    Ok(
        sqlx::query_as(
            "SELECT username,password_enc FROM cluster_agent_logins WHERE cluster_id=$1",
        )
        .bind(cluster)
        .fetch_optional(pool)
        .await?,
    )
}

/// The outcome of a check, as it is cached on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The database allows no more than the policy.
    Clean,
    /// The database allows more than the policy.
    Drift,
    /// The check could not run, for example the login could not connect.
    Failed,
}
/// How long a bad result is kept before the next agent query checks again.
/// Short, so a repair or a passing outage is noticed without anyone asking.
const RECHECK_SECONDS: u64 = 15;

/// Verify now and store the result against the cluster version it is for.
pub async fn check(
    core: &Core,
    cluster: &ClusterRecord,
    policy: &Policy,
) -> Result<(String, Vec<Finding>), ApiError> {
    let stored = login(&core.db, cluster.id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let pools = core.pools.get(core, cluster, policy).await?;
    let outcome = match pools.agent.as_ref() {
        _ if stored.password_enc.is_empty() => Err(ApiError::new(
            http::StatusCode::CONFLICT,
            "password_needed",
            "",
        )),
        Some(pool) => verify(&pool.primary, policy).await,
        None => {
            // The login is stored but its pools could not be built, perhaps
            // because of a passing fault. Build them again next time.
            core.pools.invalidate(cluster.id).await;
            Err(ApiError::internal())
        }
    };
    let (verdict, findings) = match outcome {
        // The cluster's endpoint changed. The old password must not go to the
        // new endpoint, and agents must not fall back to the cluster's login.
        Err(error) if error.code == "password_needed" => (
            Verdict::Drift,
            vec![critical(
                error.code,
                "login",
                "The cluster's connection endpoint changed. Enter the agent login's password again, or remove the agent login.",
            )],
        ),
        Ok(findings) if findings.iter().any(|f| f.severity == "critical") => {
            (Verdict::Drift, findings)
        }
        Ok(findings) => (Verdict::Clean, findings),
        Err(error) if error.code == "database_too_large" => (
            Verdict::Failed,
            vec![critical(
                error.code,
                "login",
                "The database has more tables or columns than the check can read.",
            )],
        ),
        Err(_) => (
            Verdict::Failed,
            vec![critical(
                "check_failed",
                "login",
                "The check could not run as the agent login. Verify its name, password and CONNECT right, and that the database is reachable.",
            )],
        ),
    };
    let status = match verdict {
        Verdict::Clean => "ok",
        Verdict::Drift => "drift",
        Verdict::Failed => "error",
    };
    store(&core.db, cluster, status, &findings).await?;
    core.judged
        .insert(
            (cluster.id, cluster.updated_at),
            (verdict, std::time::Instant::now()),
        )
        .await;
    Ok((status.to_owned(), findings))
}

/// Store the result of a check and, when the status is another one than
/// before, one `agent_login.status` audit event, in one transaction.
///
/// Every node checks on its own, and several may check the same cluster at
/// the same moment. The stored status is the shared truth: its row is locked
/// while it is compared and replaced, so the checks of one cluster store
/// their results one after another, and each compares with what the one
/// before it committed. A change is therefore recorded once, by the check
/// that made it, however many nodes saw it.
async fn store(
    db: &sqlx::PgPool,
    cluster: &ClusterRecord,
    status: &str,
    findings: &[Finding],
) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    let before: Option<String> = sqlx::query_scalar(
        "SELECT status FROM cluster_agent_logins WHERE cluster_id=$1 FOR UPDATE",
    )
    .bind(cluster.id)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE cluster_agent_logins SET status=$2,findings=$3,checked_at=now(),checked_version=$4
         WHERE cluster_id=$1",
    )
    .bind(cluster.id)
    .bind(status)
    .bind(serde_json::json!(findings))
    .bind(cluster.updated_at)
    .execute(&mut *tx)
    .await?;
    if let Some(before) = before.filter(|before| before != status) {
        status_changed(&mut tx, cluster.id, &before, status).await?;
    }
    tx.commit().await?;
    Ok(())
}
/// Record that the status of a cluster's agent login changed, on the
/// transaction that changes it. Nobody is the actor: a check found it. The
/// findings are not copied: they name database objects, and the current
/// ones are shown with the login.
pub async fn status_changed(
    connection: &mut sqlx::PgConnection,
    cluster: Uuid,
    from: &str,
    to: &str,
) -> Result<(), ApiError> {
    crate::audit::persist_on(
        connection,
        &crate::audit::Event {
            id: Uuid::new_v4(),
            actor_id: None,
            action: "agent_login.status".into(),
            target_type: Some("cluster".into()),
            target_id: Some(cluster),
            ip: None,
            details: serde_json::json!({"from": from, "to": to}),
            created_at: chrono::Utc::now(),
        },
    )
    .await?;
    Ok(())
}

/// Before an agent's query: when the cluster has an agent login, it must be
/// verified clean for this cluster version, and recently. Returns whether the
/// query runs as the agent login (`true`) or as the cluster's shared login.
pub async fn require(
    core: &Core,
    cluster: &ClusterRecord,
    policy: &Policy,
) -> Result<bool, ApiError> {
    if login(&core.db, cluster.id).await?.is_none() {
        return Ok(false);
    }
    let key = (cluster.id, cluster.updated_at);
    // A bad result is checked again soon; a clean one is trusted for longer.
    if let Some((verdict, at)) = core.judged.get(&key).await {
        if verdict != Verdict::Clean && at.elapsed() > Duration::from_secs(RECHECK_SECONDS) {
            core.judged.invalidate(&key).await;
        }
    }
    // Requests that arrive together share one check.
    let (verdict, _) = core
        .judged
        .try_get_with(key, async {
            let (status, _) = check(core, cluster, policy).await?;
            let verdict = match status.as_str() {
                "ok" => Verdict::Clean,
                "drift" => Verdict::Drift,
                _ => Verdict::Failed,
            };
            Ok::<_, ApiError>((verdict, std::time::Instant::now()))
        })
        .await
        .map_err(|error| (*error).clone())?;
    match verdict {
        Verdict::Clean => Ok(true),
        Verdict::Drift => Err(ApiError::new(
            http::StatusCode::CONFLICT,
            "database_setup_drift",
            "The agent login on this database needs repair by a person before agents can use it",
        )),
        Verdict::Failed => Err(ApiError::new(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "database_check_failed",
            "The agent login on this database could not be checked",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vda_connectors::{SchemaColumn, SchemaInfo, SchemaTable};

    fn table(name: &str, kind: TableKind, columns: &[&str]) -> SchemaTable {
        SchemaTable {
            name: name.into(),
            kind,
            row_estimate: None,
            columns: columns
                .iter()
                .map(|c| SchemaColumn {
                    name: (*c).into(),
                    data_type: "text".into(),
                    nullable: true,
                    is_primary_key: false,
                })
                .collect(),
        }
    }

    #[test]
    fn the_script_grants_columns_only_for_what_the_policy_allows() {
        let tree = SchemaTree {
            schemas: vec![
                SchemaInfo {
                    name: "public".into(),
                    tables: vec![
                        table("users", TableKind::Table, &["id", "email", "Odd \"name\""]),
                        table("vault", TableKind::Table, &["id", "api_key"]),
                        table("v_vault", TableKind::View, &["id", "api_key"]),
                        table("m_users", TableKind::MaterializedView, &["id"]),
                        table("all_masked", TableKind::Table, &["email"]),
                    ],
                },
                SchemaInfo {
                    name: "audit".into(),
                    tables: vec![table("log", TableKind::Table, &["id"])],
                },
            ],
        };
        let mut policy = Policy::for_environment("production");
        policy.masked_columns = vec!["email".into()];
        policy.blocked_tables = vec!["vault".into(), "audit.*".into()];
        let sql =
            script("vda_agent", "shop\"db", &tree, &policy, &Family::default()).unwrap_or_default();
        assert!(script("postgres", "db", &tree, &policy, &Family::default()).is_err());
        assert!(sql.contains(
            "GRANT SELECT (\"id\", \"Odd \"\"name\"\"\") ON \"public\".\"users\" TO \"vda_agent\";"
        ));
        assert!(sql.contains("GRANT CONNECT ON DATABASE \"shop\"\"db\" TO \"vda_agent\";"));
        assert!(sql.contains("GRANT USAGE ON SCHEMA \"public\" TO \"vda_agent\";"));
        // Nothing is granted on a blocked table, a view, a copy, or a protected column.
        for hidden in [
            "\"vault\"",
            "\"v_vault\"",
            "\"m_users\"",
            "\"all_masked\"",
            "\"email\"",
            "\"log\"",
        ] {
            assert!(
                !sql.lines()
                    .any(|l| l.starts_with("GRANT") && l.contains(hidden)),
                "{hidden} must not be granted"
            );
        }
        assert!(!sql.contains("GRANT USAGE ON SCHEMA \"audit\""));
        // What the login held before is removed first, in the whole database.
        let at = |needle: &str| sql.find(needle).unwrap_or(usize::MAX);
        assert!(at("DROP OWNED BY \"vda_agent\";") < at("GRANT"));
        assert!(
            !sql.contains("\"audit\""),
            "a schema that gets nothing is not touched"
        );
        assert!(
            sql.starts_with("-- ") && sql.contains("\nBEGIN;\n") && sql.contains("\nCOMMIT;\n")
        );
        assert!(
            !sql.contains("GRANT SELECT ON"),
            "never a whole-table grant"
        );
    }

    #[test]
    fn only_plain_safe_login_names_are_accepted() {
        for good in ["vda_agent", "_a1", "a"] {
            assert!(valid_role(good), "{good}");
        }
        for bad in [
            "",
            "1a",
            "Agent",
            "a-b",
            "a b",
            "a\"b",
            "pg_read_all_data",
            &"a".repeat(64),
            "postgres;",
            "postgres",
            "public",
            "current_user",
            "none",
        ] {
            assert!(!valid_role(bad), "{bad}");
        }
    }

    #[test]
    fn a_rule_about_one_table_covers_the_tables_that_share_its_rows() {
        let edge = |child: &str, parent: &str| (child.to_owned(), parent.to_owned());
        let family = Family::new(&[
            edge("public.orders_2024", "public.Orders"),
            edge("public.orders_2024_q1", "public.orders_2024"),
            edge("public.vip_people", "public.people"),
        ]);
        let mut policy = Policy::for_environment("production");
        let read = |policy: &Policy, table: &str, column: &str| {
            allowed(policy, &family, ("public", table, column), true)
        };
        assert!(read(&policy, "orders_2024_q1", "who"));
        // Blocking the parent closes every partition, however it is named.
        policy.blocked_tables = vec!["orders".into()];
        for table in ["orders", "orders_2024", "orders_2024_q1"] {
            assert!(!read(&policy, table, "who"), "{table}");
        }
        assert!(
            read(&policy, "people", "name"),
            "another family is not touched"
        );
        // Blocking a child closes its parent too: a query on the parent
        // returns the child's rows.
        policy.blocked_tables = vec!["vip_people".into()];
        assert!(!read(&policy, "people", "name"));
        // A child with two parents shows its rows through both. Blocking one
        // parent closes the other, and a column protected on one is protected
        // on the other.
        let two = Family::new(&[
            edge("public.kid", "public.pa"),
            edge("public.kid", "public.pb"),
        ]);
        let through = |policy: &Policy, table: &str, column: &str| {
            allowed(policy, &two, ("public", table, column), true)
        };
        policy.blocked_tables = vec!["pa".into()];
        for table in ["pa", "pb", "kid"] {
            assert!(!through(&policy, table, "tag"), "{table}");
        }
        policy.blocked_tables.clear();
        policy.masked_columns = vec!["pa.secret".into()];
        assert!(!through(&policy, "pb", "secret") && through(&policy, "pb", "id"));
        policy.masked_columns.clear();
        // A protected column is protected on every member, also by a
        // table-qualified pattern.
        policy.blocked_tables.clear();
        policy.masked_columns = vec!["orders.ssn".into()];
        for table in ["orders", "orders_2024", "orders_2024_q1"] {
            assert!(!read(&policy, table, "ssn"), "{table}");
            assert!(read(&policy, table, "who"), "{table}");
        }
        // The script follows the same rule.
        let tree = SchemaTree {
            schemas: vec![SchemaInfo {
                name: "public".into(),
                tables: vec![
                    table("orders_2024", TableKind::Table, &["id", "ssn"]),
                    table("people", TableKind::Table, &["id"]),
                ],
            }],
        };
        policy.blocked_tables = vec!["vip_people".into()];
        let sql = script("vda_agent", "db", &tree, &policy, &family).unwrap_or_default();
        assert!(sql.contains("GRANT SELECT (\"id\") ON \"public\".\"orders_2024\""));
        assert!(!sql.contains("\"people\""));
    }

    #[test]
    fn a_table_with_thousands_of_partitions_is_cheap_to_judge() {
        let edges: Vec<(String, String)> = (0..20_000)
            .map(|n| (format!("public.big_p{n}"), "public.big".to_owned()))
            .collect();
        let mut policy = Policy::for_environment("production");
        policy.blocked_tables = (0..20).map(|n| format!("nothing_{n}")).collect();
        policy.masked_columns = (0..20).map(|n| format!("big.secret_{n}")).collect();
        let started = std::time::Instant::now();
        let family = Family::new(&edges);
        let rules = family.rules(&policy);
        let mut readable = 0;
        for n in 0..20_000 {
            let rule = rules.of("public", &format!("big_p{n}"));
            for column in ["id", "a", "b", "c", "secret_3"] {
                readable += usize::from(rule.reads(column));
            }
        }
        assert_eq!(readable, 80_000, "four of five columns on every partition");
        // Quadratic work takes minutes here; this bound is loose on purpose.
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(family.groups.len(), 1);
    }
}
