//! libFuzzer target: the guard must never panic, must be deterministic, and
//! must never return SQL to run for a statement it denied.
//!
//! Run with `cargo +nightly fuzz run analyze` from `crates/vda-guard`.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/invariants.rs"]
mod invariants;

fuzz_target!(|sql: &str| invariants::check(sql));
