//! Seeded mutation test: the guard must never panic, must be deterministic,
//! and must never hand back SQL to run for a statement it denied.
//!
//! This is the stable-toolchain companion of the libFuzzer target in
//! `fuzz/`. It runs on every `cargo test`; the fuzz target runs on a schedule.

use vda_guard::{analyze, AccessLevel, Dialect, GuardPolicy, Verdict};

const SEEDS: &[&str] = &[
    "SELECT id, name FROM users WHERE id = 42 ORDER BY id LIMIT 10",
    "SELECT * FROM ONLY (users) u JOIN orders o ON o.user_id = u.id",
    "WITH t AS (SELECT 1 AS n) SELECT n FROM t UNION ALL SELECT 2",
    "EXPLAIN (ANALYSE true, VERBOSE) DELETE FROM orders WHERE id = 1",
    "UPDATE users SET name = 'O''Brien' WHERE id = 1 RETURNING *",
    "INSERT INTO t (a, b) VALUES (1, 'x'), (2, NULL) ON CONFLICT DO NOTHING",
    "SELECT pg_catalog.\"ts_stat\"('select 1') /* c */ -- tail",
    "SELECT `a`.`b` FROM `db`.`t` WHERE x = @v := 1 # mysql",
    "SELECT * FROM users, LATERAL (VALUES (email)) v(e)",
    "DELETE FROM a USING b WHERE a.id = b.id; SELECT 1;",
    "SELECT $$dollar ' quoted$$, E'\\x41', U&'\\0041', x'ff', 1e9, .5",
    "MERGE INTO ONLY t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
    "SHOW CREATE TABLE users; SET ROLE admin; CALL p(1); DO $$ BEGIN END $$",
    "SELECT CASE WHEN a THEN (SELECT max(b) FROM t2) ELSE NULL END FROM t1",
];

/// Fragments spliced into seeds: the syntax attackers lean on.
const FRAGMENTS: &[&str] = &[
    "ONLY",
    "(",
    ")",
    "'",
    "\"",
    "`",
    ";",
    "--",
    "/*",
    "*/",
    "$$",
    ".",
    "*",
    ",",
    "@",
    "\\",
    "\0",
    "\n",
    " ",
    "ANALYSE",
    "LATERAL",
    "public.",
    "pg_catalog.",
    "ts_stat(",
    "users",
    "é",
    "\u{202e}",
    "0x",
    "UNION",
    "INTO",
    "RETURNING",
    "E'",
    "U&'",
    "::",
];

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % (bound.max(1) as u64)).unwrap_or(0)
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items.get(self.below(items.len())).copied().unwrap_or("")
    }
}

/// A char boundary at or below a random offset.
fn boundary(text: &str, rng: &mut Rng) -> usize {
    let mut at = rng.below(text.len() + 1);
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn mutate(rng: &mut Rng) -> String {
    let mut sql = rng.pick(SEEDS).to_owned();
    for _ in 0..=rng.below(6) {
        let at = boundary(&sql, rng);
        match rng.below(6) {
            0 => sql.insert_str(at, rng.pick(FRAGMENTS)),
            1 => sql.truncate(at),
            2 => {
                let end = boundary(&sql, rng);
                let (from, to) = (at.min(end), at.max(end));
                sql.replace_range(from..to, "");
            }
            3 => {
                let other = rng.pick(SEEDS);
                let cut = boundary(other, rng);
                sql.insert_str(at, other.get(cut..).unwrap_or(""));
            }
            4 => sql = sql.to_uppercase(),
            _ => {
                let end = boundary(&sql, rng);
                let (from, to) = (at.min(end), at.max(end));
                let copy = sql.get(from..to).unwrap_or("").to_owned();
                sql.insert_str(to, &copy);
            }
        }
    }
    sql
}

fn check(sql: &str) {
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

#[test]
fn guard_survives_mutated_sql() {
    for seed in SEEDS {
        check(seed);
    }
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        check(&mutate(&mut rng));
    }
}
