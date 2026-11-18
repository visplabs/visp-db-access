//! Write previews: run a write in a transaction that is always rolled back,
//! and show what it would change.
//!
//! A preview is shown to people (the requester and the reviewer). It masks
//! protected columns by name, and it also hides a new value that is computed
//! from a protected column, so that a write cannot be used to read one. The
//! digest that binds an approval to the rows it changes is never shown.
use crate::masking::{self, Column};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vda_connectors::{DryRun, Expected};
use vda_guard::{Source, StatementKind, WritePlan};

/// Rows shown in a preview at most, before and after.
pub const SAMPLE_ROWS: usize = 20;
const HIDDEN: &str = "••••••";

/// A few rows of a preview, already masked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RowSample {
    pub columns: Vec<String>,
    /// Columns whose values are not shown.
    pub hidden: Vec<String>,
    /// The hidden columns that the policy protects (a subset of `hidden`).
    /// The others are new values computed from something that may not be
    /// shown. Absent from previews stored before this field existed.
    #[serde(default)]
    pub masked: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// How many rows there were in all.
    pub total: usize,
}
/// What a write would do, seen by running it and rolling it back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Preview {
    /// `false` when the write could not be previewed; `reason` says why.
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<StatementKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_rows: Option<u64>,
    /// The rows it changes, as they are now (`UPDATE`, `DELETE`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<RowSample>,
    /// The rows as the write leaves them (`INSERT`, `UPDATE`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<RowSample>,
    /// Whether the approval is bound to the exact rows (`rows`) or only to
    /// how many there are (`count`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_to: Option<String>,
    /// The columns the statement writes (`UPDATE`, and `INSERT` with a
    /// column list of written-out values). Left out when not known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<Vec<String>>,
    pub notes: Vec<String>,
    /// The effect an approval is bound to. Never sent to a client: the digest
    /// covers protected values.
    #[serde(skip)]
    pub binding: Option<Expected>,
}
impl Preview {
    /// A write that is not previewed, and why.
    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            supported: false,
            reason: Some(reason.into()),
            ..Self::default()
        }
    }
}

fn sample(
    mut result: vda_connectors::QueryResult,
    patterns: &[String],
    tables: &[String],
    also_hidden: &dyn Fn(&str) -> bool,
) -> RowSample {
    let total = result.rows.len();
    let columns: Vec<Column> = masking::apply(&mut result, patterns, tables);
    let mut hidden = Vec::new();
    let mut masked = Vec::new();
    for (index, column) in columns.iter().enumerate() {
        if column.masked {
            masked.push(column.name.clone());
        }
        if column.masked || also_hidden(&column.name) {
            hidden.push(column.name.clone());
            for row in &mut result.rows {
                if let Some(value) = row.get_mut(index) {
                    *value = Value::String(HIDDEN.into());
                }
            }
        }
    }
    result.rows.truncate(SAMPLE_ROWS);
    RowSample {
        columns: columns.into_iter().map(|column| column.name).collect(),
        hidden,
        masked,
        rows: result.rows,
        total,
    }
}

/// Build the preview from a dry run. `tables` are the relations the guard
/// found in the statement; `patterns` the policy's protected columns.
pub fn build(
    run: DryRun,
    plan: Option<&WritePlan>,
    patterns: &[String],
    tables: &[String],
) -> Preview {
    let affected = run.written.affected_rows.unwrap_or(0);
    let mut notes = Vec::new();
    let Some(plan) = plan else {
        notes.push(
            "This statement is previewed by its row count only: it is not a single plain INSERT, UPDATE or DELETE."
                .into(),
        );
        return Preview {
            supported: true,
            affected_rows: Some(affected),
            bound_to: Some("count".into()),
            notes,
            binding: Some(Expected {
                affected_rows: affected,
                rows_fingerprint: None,
            }),
            ..Preview::default()
        };
    };
    // The rows it changes must be exactly the rows it targets; otherwise the
    // digest would bind the wrong thing, and only the count is bound. The
    // write is still limited to the target rows when it runs.
    let fingerprint = run.targets.as_ref().and_then(|targets| {
        (targets.complete && targets.count == affected).then(|| targets.fingerprint.clone())
    });
    if plan.target_keys.is_some() && run.targets.is_none() {
        notes.push(
            "The target is not a plain table (for example a view), so the approval is bound to the count of changed rows only."
                .into(),
        );
    } else if plan.target_keys.is_some() && fingerprint.is_none() {
        notes.push(
            "The changed rows could not be matched one to one with the rows it targets, so the approval is bound to their count only."
                .into(),
        );
    }
    let before = run
        .target
        .map(|target| sample(target, patterns, tables, &|_| false));
    // A new value is shown only when it is written out in the statement or
    // computed from columns of the target that are not protected. A name that
    // is not a column of the target (a whole-row reference such as `t::text`,
    // or a column of another table) could carry anything, so it hides the value.
    let known: Vec<String> = run
        .written
        .columns
        .iter()
        .map(|column| column.name.to_lowercase())
        .collect();
    let derived_hidden = |column: &str| -> bool {
        match &plan.assigned {
            None => true,
            Some(assigned) => assigned
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(column))
                .any(|(_, source)| match source {
                    Source::Opaque => true,
                    Source::Columns(sources) => sources.iter().any(|source| {
                        !known.contains(&source.to_lowercase())
                            || patterns
                                .iter()
                                .any(|pattern| masking::matches_column(pattern, source, tables))
                    }),
                }),
        }
    };
    let after = (plan.returning_all.is_some() && !run.written.columns.is_empty())
        .then(|| sample(run.written, patterns, tables, &derived_hidden));
    if plan.returning && plan.kind != StatementKind::Delete {
        notes.push(
            "The new values are not shown: the statement has its own RETURNING clause.".into(),
        );
    }
    if after.as_ref().is_some_and(|after| !after.hidden.is_empty()) {
        notes.push(
            "Some new values are not shown: they are protected, or computed from a protected column or another query."
                .into(),
        );
    }
    Preview {
        supported: true,
        reason: None,
        kind: Some(plan.kind),
        target: Some(plan.target.clone()),
        affected_rows: Some(affected),
        before,
        after,
        bound_to: Some(
            if fingerprint.is_some() {
                "rows"
            } else {
                "count"
            }
            .into(),
        ),
        written: written_columns(plan),
        notes,
        binding: Some(Expected {
            affected_rows: affected,
            rows_fingerprint: fingerprint,
        }),
    }
}

/// The columns an `UPDATE` or `INSERT` writes, when the plan names them.
fn written_columns(plan: &WritePlan) -> Option<Vec<String>> {
    if !matches!(plan.kind, StatementKind::Update | StatementKind::Insert) {
        return None;
    }
    plan.assigned
        .as_ref()
        .map(|assigned| assigned.iter().map(|(name, _)| name.clone()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vda_connectors::{Column as Col, QueryResult};

    fn result(columns: &[&str], rows: Vec<Vec<Value>>, affected: Option<u64>) -> QueryResult {
        QueryResult {
            columns: columns
                .iter()
                .map(|name| Col {
                    name: (*name).into(),
                    type_name: "text".into(),
                })
                .collect(),
            row_count: rows.len(),
            rows,
            truncated: false,
            affected_rows: affected,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn a_preview_never_shows_a_protected_value_or_one_computed_from_it() {
        let plan = vda_guard::write_plan(
            "UPDATE users SET name = email, note = 'checked', city = upper(city) WHERE id = 1",
            vda_guard::Dialect::Postgres,
        );
        let before = result(
            &["id", "name", "email", "note", "city"],
            vec![vec![
                json!(1),
                json!("Ada"),
                json!("ada@x.test"),
                json!(null),
                json!("oslo"),
            ]],
            None,
        );
        let after = result(
            &["id", "name", "email", "note", "city"],
            vec![vec![
                json!(1),
                json!("ada@x.test"),
                json!("ada@x.test"),
                json!("checked"),
                json!("OSLO"),
            ]],
            Some(1),
        );
        let preview = build(
            DryRun {
                target: Some(before),
                targets: Some(targets(1)),
                written: after,
            },
            plan.as_ref(),
            &["email".into()],
            &["users".into()],
        );
        let text = serde_json::to_string(&preview).unwrap_or_default();
        assert!(!text.contains("ada@x.test"), "{text}");
        let after = preview.after.as_ref().map(|a| a.hidden.clone());
        assert_eq!(after, Some(vec!["name".to_string(), "email".to_string()]));
        // Only the protected column is masked; `name` is hidden because it
        // is computed from it.
        let masked = preview.after.as_ref().map(|a| a.masked.clone());
        assert_eq!(masked, Some(vec!["email".to_string()]));
        assert!(text.contains("OSLO") && text.contains("checked"));
        assert_eq!(
            preview.written,
            Some(vec!["name".into(), "note".into(), "city".into()])
        );
        assert_eq!(preview.bound_to.as_deref(), Some("rows"));
        assert!(!text.contains("fingerprint") && !text.contains("binding"));
        let binding = preview.binding.unwrap_or(Expected {
            affected_rows: 0,
            rows_fingerprint: None,
        });
        assert_eq!(binding.affected_rows, 1);
        assert!(binding.rows_fingerprint.is_some());
    }

    fn targets(count: u64) -> vda_connectors::Targets {
        vda_connectors::Targets {
            count,
            complete: true,
            fingerprint: "f".into(),
        }
    }

    #[test]
    fn a_name_that_is_not_a_column_of_the_target_hides_the_new_value() {
        // `t::text` is the whole row, protected columns included.
        let plan = vda_guard::write_plan(
            "UPDATE t SET note = t::text WHERE id = 1",
            vda_guard::Dialect::Postgres,
        );
        let written = result(
            &["id", "email", "note"],
            vec![vec![json!(1), json!("a@x.test"), json!("(1,a@x.test,)")]],
            Some(1),
        );
        let preview = build(
            DryRun {
                target: None,
                targets: Some(targets(1)),
                written,
            },
            plan.as_ref(),
            &["email".into()],
            &["t".into()],
        );
        let text = serde_json::to_string(&preview).unwrap_or_default();
        assert!(!text.contains("a@x.test"), "{text}");
    }

    #[test]
    fn rows_that_do_not_match_the_count_are_bound_by_count_only() {
        let plan = vda_guard::write_plan(
            "UPDATE t SET a = 1 FROM u WHERE t.id = u.t_id",
            vda_guard::Dialect::Postgres,
        );
        let target = result(&["id", "a"], vec![vec![json!(1), json!(0)]; 2], None);
        let written = result(&["id", "a"], vec![vec![json!(1), json!(1)]], Some(1));
        let preview = build(
            DryRun {
                target: Some(target),
                targets: Some(targets(2)),
                written,
            },
            plan.as_ref(),
            &[],
            &["t".into(), "u".into()],
        );
        assert_eq!(preview.bound_to.as_deref(), Some("count"));
        assert_eq!(preview.binding.and_then(|b| b.rows_fingerprint), None);
        assert_eq!(preview.notes.len(), 1);
    }

    #[test]
    fn copies_from_another_query_are_hidden_and_samples_are_short() {
        let plan = vda_guard::write_plan(
            "INSERT INTO t (a) SELECT secret FROM vault",
            vda_guard::Dialect::Postgres,
        );
        let written = result(&["a"], vec![vec![json!("s")]; 50], Some(50));
        let preview = build(
            DryRun {
                target: None,
                targets: None,
                written,
            },
            plan.as_ref(),
            &[],
            &["t".into(), "vault".into()],
        );
        let after = preview.after.unwrap_or_else(|| RowSample {
            columns: vec![],
            hidden: vec![],
            masked: vec![],
            rows: vec![],
            total: 0,
        });
        assert_eq!((after.total, after.rows.len()), (50, SAMPLE_ROWS));
        assert_eq!(after.hidden, vec!["a".to_string()]);
        assert!(after.masked.is_empty(), "copied, not protected");
        assert!(after.rows.iter().all(|row| row == &vec![json!(HIDDEN)]));
    }

    #[test]
    fn an_insert_marks_a_protected_column_as_masked() {
        let plan = vda_guard::write_plan(
            "INSERT INTO users (id, email) VALUES (1, 'a@x.test')",
            vda_guard::Dialect::Postgres,
        );
        let preview = build(
            DryRun {
                target: None,
                targets: None,
                written: result(
                    &["id", "email"],
                    vec![vec![json!(1), json!("a@x.test")]],
                    Some(1),
                ),
            },
            plan.as_ref(),
            &["email".into()],
            &["users".into()],
        );
        let after = preview.after.map(|after| (after.hidden, after.masked));
        assert_eq!(
            after,
            Some((vec!["email".to_string()], vec!["email".to_string()]))
        );
        assert_eq!(preview.written, Some(vec!["id".into(), "email".into()]));
        // A stored preview from before `masked` existed still reads.
        let old: Result<RowSample, _> =
            serde_json::from_value(json!({"columns": [], "hidden": [], "rows": [], "total": 0}));
        assert!(old.is_ok_and(|old| old.masked.is_empty()));
    }

    #[test]
    fn a_preview_names_the_written_columns_only_when_they_are_known() {
        let preview = |sql: &str, columns: &[&str]| {
            let plan = vda_guard::write_plan(sql, vda_guard::Dialect::Postgres);
            build(
                DryRun {
                    target: None,
                    targets: None,
                    written: result(columns, vec![vec![json!(1); columns.len()]], Some(1)),
                },
                plan.as_ref(),
                &[],
                &["t".into()],
            )
        };
        let insert = preview("INSERT INTO t (a, b) VALUES (1, 2)", &["id", "a", "b"]);
        assert_eq!(insert.written, Some(vec!["a".into(), "b".into()]));
        let text = serde_json::to_string(&insert).unwrap_or_default();
        assert!(text.contains(r#""written":["a","b"]"#), "{text}");
        // Not known: no column list, or a source that is a query.
        assert_eq!(preview("INSERT INTO t VALUES (1)", &["a"]).written, None);
        let copied = preview("INSERT INTO t (a) SELECT a FROM u", &["a"]);
        assert_eq!(copied.written, None);
        let text = serde_json::to_string(&copied).unwrap_or_default();
        assert!(!text.contains("written"), "{text}");
        // A DELETE writes no column.
        assert_eq!(preview("DELETE FROM t WHERE id = 1", &["a"]).written, None);
        // Its own RETURNING leaves no after sample, and a note says why.
        let returning = preview("UPDATE t SET a = 1 WHERE id = 1 RETURNING id", &["id"]);
        assert!(returning.after.is_none());
        assert!(returning
            .notes
            .iter()
            .any(|note| note.contains("own RETURNING")));
    }
}
