//! The guard invariants shared by the mutation test and the libFuzzer target
//! in `fuzz/`: no panic, the same answer twice, and no SQL to run for a
//! statement the guard denied.

use vda_guard::{analyze, AccessLevel, Dialect, GuardPolicy, Verdict};

pub fn check(sql: &str) {
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
            assert_eq!(
                first.verdict, second.verdict,
                "verdict is not deterministic for {sql:?}"
            );
            assert_eq!(
                first.rewritten_sql, second.rewritten_sql,
                "rewrite is not deterministic for {sql:?}"
            );
            if first.verdict == Verdict::Deny {
                assert!(
                    first.rewritten_sql.is_none(),
                    "denied statement still has SQL to run: {sql:?}"
                );
                assert!(!first.issues.is_empty(), "denied without a reason: {sql:?}");
            }
        }
    }
}
