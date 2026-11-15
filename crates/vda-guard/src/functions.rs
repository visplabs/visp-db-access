//! Function policy shared by scalar and table-valued calls.
use std::{collections::HashSet, sync::LazyLock};

use crate::{Dialect, Issue, Severity};

// Matching is on the lower-cased, unqualified function name, so schema
// qualification (`pg_catalog.ts_stat`), quoting (`"ts_stat"`) and case never
// bypass a rule. Exact names come first, then whole families by prefix, then
// extension schemas whose every routine is blocked when called qualified.
const POSTGRES_BLOCKED: &[&str] = &[
    // Sleeps and backend control.
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_log_backend_memory_contexts",
    // Server configuration, logs, WAL, backups and replication.
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    "pg_create_restore_point",
    "pg_switch_wal",
    "pg_switch_xlog",
    "pg_wal_replay_pause",
    "pg_wal_replay_resume",
    "pg_xlog_replay_pause",
    "pg_xlog_replay_resume",
    "pg_start_backup",
    "pg_stop_backup",
    "pg_backup_start",
    "pg_backup_stop",
    "pg_create_logical_replication_slot",
    "pg_create_physical_replication_slot",
    "pg_drop_replication_slot",
    "pg_copy_logical_replication_slot",
    "pg_copy_physical_replication_slot",
    "pg_replication_slot_advance",
    "pg_sync_replication_slots",
    "pg_logical_emit_message",
    "pg_log_standby_snapshot",
    "pg_export_snapshot",
    "pg_import_system_collations",
    // Server files (core and adminpack).
    "pg_read_file",
    "pg_read_binary_file",
    "pg_stat_file",
    "pg_ls_dir",
    "pg_file_write",
    "pg_file_unlink",
    "pg_file_rename",
    "pg_file_sync",
    "pg_file_read",
    "pg_file_length",
    "pg_logdir_ls",
    // Large objects live outside table policy and can touch server files.
    "lo_import",
    "lo_export",
    "lo_unlink",
    "lo_from_bytea",
    "lo_put",
    "lo_get",
    "lo_create",
    "lo_creat",
    "lo_open",
    "lo_close",
    "lo_truncate",
    "lo_truncate64",
    "lo_lseek",
    "lo_lseek64",
    "lo_tell",
    "lo_tell64",
    "loread",
    "lowrite",
    // Session state.
    "set_config",
    // SQL passed as text, and table data read by name from text.
    "ts_stat",
    "ts_rewrite",
    "connectby",
    "xpath_table",
    "query_export_to_s3",
    "table_import_from_s3",
    "schedule",
    "schedule_in_database",
    "unschedule",
    "alter_job",
    // Raw page reads bypass table policy; prewarming floods shared buffers.
    "get_raw_page",
    "pg_prewarm",
    // Network access.
    "http",
    "postgres_fdw_disconnect",
    "postgres_fdw_disconnect_all",
    // Statistics manipulation.
    "pg_set_relation_stats",
    "pg_clear_relation_stats",
    "pg_restore_relation_stats",
    "pg_set_attribute_stats",
    "pg_clear_attribute_stats",
    "pg_restore_attribute_stats",
    // Transaction ids, sequences and notifications change server state.
    "txid_current",
    "pg_current_xact_id",
    "nextval",
    "setval",
    "pg_notify",
];
const POSTGRES_BLOCKED_PREFIXES: &[&str] = &[
    // dblink, dblink_exec, dblink_connect_u, dblink_open, dblink_fetch, ...
    "dblink",
    // pg_advisory_lock, pg_advisory_xact_lock_shared, pg_advisory_unlock_all, ...
    "pg_advisory_",
    // pg_try_advisory_lock_shared, pg_try_advisory_xact_lock, ...
    "pg_try_advisory_",
    // query_to_xml, query_to_xmlschema, query_to_xml_and_xmlschema
    "query_to_xml",
    // cursor_to_xml, cursor_to_xmlschema
    "cursor_to_xml",
    // table_to_xml, table_to_xmlschema, table_to_xml_and_xmlschema
    "table_to_xml",
    // schema_to_xml, schema_to_xmlschema, schema_to_xml_and_xmlschema
    "schema_to_xml",
    // database_to_xml, database_to_xmlschema, database_to_xml_and_xmlschema
    "database_to_xml",
    // pg_ls_logdir, pg_ls_waldir, pg_ls_tmpdir, pg_ls_logicalsnapdir, ...
    "pg_ls_",
    // pg_logical_slot_get_changes, pg_logical_slot_peek_binary_changes, ...
    "pg_logical_slot_",
    // pg_replication_origin_create, _drop, _session_setup, _advance, ...
    "pg_replication_origin_",
    // pg_stat_reset, pg_stat_reset_shared, pg_stat_statements_reset, ...
    "pg_stat_reset",
    "pg_stat_statements_reset",
    // pg_walinspect: pg_get_wal_records_info, pg_get_wal_block_info, ...
    "pg_get_wal_",
    // tablefunc: crosstab, crosstab2, crosstab3, crosstab4
    "crosstab",
    // pg_background_launch, pg_background_result, pg_background_detach
    "pg_background_",
    // pgsql-http and pg_net: http_get, http_post, http_delete, ...
    "http_",
    // Only valid in binary-upgrade mode; never needed through the gateway.
    "binary_upgrade_",
];
const POSTGRES_BLOCKED_SCHEMAS: &[&str] =
    &["cron", "aws_s3", "aws_lambda", "azure_storage", "utl_file"];
const MYSQL_BLOCKED: &[&str] = &[
    "sleep",
    "benchmark",
    "load_file",
    "get_lock",
    "release_lock",
    "release_all_locks",
    "is_free_lock",
    "is_used_lock",
    "master_pos_wait",
    "source_pos_wait",
    "master_gtid_wait",
    "wait_for_executed_gtid_set",
    "wait_until_sql_thread_after_gtids",
    "wsrep_sync_wait_upto_gtid",
    "sys_exec",
    "sys_eval",
    "sys_get",
    "sys_set",
    "sys_bineval",
    "lib_mysqludf_sys_info",
    "mroonga_command",
    "service_get_read_locks",
    "service_get_write_locks",
    "service_release_locks",
    "set_firewall_mode",
    "mysql_firewall_flush_status",
];
const MYSQL_BLOCKED_PREFIXES: &[&str] = &[
    // version_tokens_set, version_tokens_lock_exclusive, ...
    "version_tokens_",
    // keyring_key_fetch, keyring_key_store, keyring_key_remove, ...
    "keyring_key_",
    // audit_log_filter_set_filter, audit_log_read, audit_log_rotate, ...
    "audit_log_",
    // MariaDB Spider: spider_direct_sql, spider_bg_direct_sql, ...
    "spider_",
    // firewall_group_register, firewall_group_enlist, ...
    "firewall_group_",
    // group_replication_set_as_primary, ...
    "group_replication_",
    "asynchronous_connection_failover_",
];
const MYSQL_BLOCKED_SCHEMAS: &[&str] = &["sys"];
const POSTGRES_WARNED: &[&str] = &["generate_series"];
const MYSQL_WARNED: &[&str] = &["uuid_short"];
static PG_BLOCK: LazyLock<HashSet<&str>> =
    LazyLock::new(|| POSTGRES_BLOCKED.iter().copied().collect());
static MY_BLOCK: LazyLock<HashSet<&str>> =
    LazyLock::new(|| MYSQL_BLOCKED.iter().copied().collect());
static PG_WARN: LazyLock<HashSet<&str>> =
    LazyLock::new(|| POSTGRES_WARNED.iter().copied().collect());
static MY_WARN: LazyLock<HashSet<&str>> = LazyLock::new(|| MYSQL_WARNED.iter().copied().collect());

struct Rules {
    names: &'static HashSet<&'static str>,
    prefixes: &'static [&'static str],
    schemas: &'static [&'static str],
}

fn rules(dialect: Dialect) -> Rules {
    match dialect {
        Dialect::Postgres => Rules {
            names: &PG_BLOCK,
            prefixes: POSTGRES_BLOCKED_PREFIXES,
            schemas: POSTGRES_BLOCKED_SCHEMAS,
        },
        Dialect::MySql => Rules {
            names: &MY_BLOCK,
            prefixes: MYSQL_BLOCKED_PREFIXES,
            schemas: MYSQL_BLOCKED_SCHEMAS,
        },
    }
}

/// `name` is the lower-cased, dot-joined function name as written.
fn blocked(name: &str, dialect: Dialect) -> bool {
    let rules = rules(dialect);
    let last = name.rsplit('.').next().unwrap_or(name);
    rules.names.contains(last)
        || rules.prefixes.iter().any(|p| last.starts_with(p))
        || name
            .split('.')
            .rev()
            .skip(1)
            .any(|schema| rules.schemas.contains(&schema))
}

pub(crate) fn inspect(name: &str, dialect: Dialect) -> Option<Issue> {
    let last = name.rsplit('.').next().unwrap_or(name);
    let warned = match dialect {
        Dialect::Postgres => &*PG_WARN,
        Dialect::MySql => &*MY_WARN,
    };
    if blocked(name, dialect) {
        Some(Issue::new(Severity::Block, "dangerous_function", format!("Function {name} can change database state, access files, acquire locks, or disrupt production. Remove this call.")))
    } else if warned.contains(last) {
        let (code, message) = if last == "generate_series" {
            ("unbounded_generator", format!("Function {name} can generate a large number of rows. Bound its arguments and use a LIMIT."))
        } else {
            ("stateful_function", format!("Function {name} allocates identifiers and changes server state. Use a deterministic expression if possible."))
        };
        Some(Issue::new(Severity::Warning, code, message))
    } else {
        None
    }
}

pub(crate) fn is_aggregate(name: &str) -> bool {
    matches!(
        name.rsplit('.').next(),
        Some(
            "count"
                | "sum"
                | "avg"
                | "min"
                | "max"
                | "bool_and"
                | "bool_or"
                | "every"
                | "array_agg"
                | "string_agg"
                | "json_agg"
                | "jsonb_agg"
                | "group_concat"
        )
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    fn denied(sql: &str, dialect: Dialect) -> bool {
        let policy = crate::GuardPolicy {
            max_rows: 10,
            allow_writes: true,
            require_approval_for_writes: false,
            allow_ddl: true,
            blocked_tables: vec![],
        };
        let a = crate::analyze(sql, dialect, crate::AccessLevel::Admin, &policy);
        a.verdict == crate::Verdict::Deny && a.issues.iter().any(|i| i.code == "dangerous_function")
    }

    #[test]
    fn every_listed_function_is_enforced() {
        for (dialect, names, prefixes, schemas) in [
            (
                Dialect::Postgres,
                POSTGRES_BLOCKED,
                POSTGRES_BLOCKED_PREFIXES,
                POSTGRES_BLOCKED_SCHEMAS,
            ),
            (
                Dialect::MySql,
                MYSQL_BLOCKED,
                MYSQL_BLOCKED_PREFIXES,
                MYSQL_BLOCKED_SCHEMAS,
            ),
        ] {
            for name in names.iter().chain(prefixes) {
                let mut forms = vec![
                    format!("SELECT {name}()"),
                    format!("SELECT {}()", name.to_uppercase()),
                    format!("SELECT some_schema.{name}()"),
                ];
                if dialect == Dialect::Postgres {
                    forms.push(format!("SELECT * FROM {name}() AS t"));
                    forms.push(format!("SELECT pg_catalog.\"{name}\"()"));
                }
                for sql in forms {
                    assert!(denied(&sql, dialect), "{sql}");
                }
            }
            for schema in schemas {
                let sql = format!("SELECT {schema}.anything()");
                assert!(denied(&sql, dialect), "{sql}");
            }
        }
    }

    #[test]
    fn similar_names_are_not_blocked() {
        for (dialect, name) in [
            (Dialect::Postgres, "ts_stats"),
            (Dialect::Postgres, "my_set_config"),
            (Dialect::Postgres, "net.total"),
            (Dialect::Postgres, "network_http"),
            (Dialect::MySql, "sleepy"),
            (Dialect::MySql, "my_get_lock"),
        ] {
            assert!(!blocked(name, dialect), "{name}");
        }
        // A blocked schema only matters as a qualifier, not as a function name.
        assert!(!blocked("cron", Dialect::Postgres));
        assert!(!blocked("sys", Dialect::MySql));
    }
}
