//! libFuzzer target: the guard must never panic, must be deterministic, and
//! must never return SQL to run for a statement it denied.
//!
//! Run with `cargo +nightly fuzz run analyze` from `crates/vda-guard`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vda_guard::{analyze, AccessLevel, Dialect, GuardPolicy, Verdict};

fuzz_target!(|sql: &str| {
    let policy = GuardPolicy {
        max_rows: 100,
        allow_writes: true,
        require_approval_for_writes: true,
        allow_ddl: false,
        blocked_tables: vec!["public.users".into(), "audit.*".into()],
    };
    for dialect in [Dialect::Postgres, Dialect::MySql] {
        for level in [AccessLevel::Read, AccessLevel::Admin] {
            let first = analyze(sql, dialect, level, &policy);
            let second = analyze(sql, dialect, level, &policy);
            assert_eq!(first.verdict, second.verdict);
            assert_eq!(first.rewritten_sql, second.rewritten_sql);
            if first.verdict == Verdict::Deny {
                assert!(first.rewritten_sql.is_none());
                assert!(!first.issues.is_empty());
            }
        }
    }
});
