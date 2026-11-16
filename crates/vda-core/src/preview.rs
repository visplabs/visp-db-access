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
    for (index, column) in columns.iter().enumerate() {
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
        notes,
        binding: Some(Expected {
            affected_rows: affected,
            rows_fingerprint: fingerprint,
        }),
    }
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
        assert!(text.contains("OSLO") && text.contains("checked"));
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
            rows: vec![],
            total: 0,
        });
        assert_eq!((after.total, after.rows.len()), (50, SAMPLE_ROWS));
        assert_eq!(after.hidden, vec!["a".to_string()]);
        assert!(after.rows.iter().all(|row| row == &vec![json!(HIDDEN)]));
    }
}
