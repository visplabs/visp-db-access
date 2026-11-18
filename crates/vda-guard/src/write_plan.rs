//! A plan for previewing a write: which rows it will change, and how to see
//! the rows it produces, without changing anything.
//!
//! The gateway runs the plan inside a transaction that it always rolls back.
//! Only plain PostgreSQL `INSERT`, `UPDATE` and `DELETE` statements get a row
//! plan; anything else is previewed by its affected-row count alone.
use crate::{parse, Dialect, StatementKind};
use sqlparser::ast::{
    visit_expressions, AssignmentTarget, Expr, FromTable, Ident, ObjectName, SetExpr, Statement,
    TableFactor, TableObject, TableWithJoins, UpdateTableFromKind,
};
use std::ops::ControlFlow;

/// Where an assigned value comes from, for deciding whether a preview may show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Built from these column names only (an empty list: literals only).
    Columns(Vec<String>),
    /// Could read anything: a subquery, or a value that cannot be traced.
    Opaque,
}

/// How to preview one write statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritePlan {
    pub kind: StatementKind,
    /// The changed table, as written in the statement.
    pub target: String,
    /// A `SELECT` of the rows that an `UPDATE` or `DELETE` will change, as they
    /// are now, locking them (`FOR UPDATE`). `None` for an `INSERT`.
    pub target_rows: Option<String>,
    /// The statement with `RETURNING *` added, so the rows it produces can be
    /// shown. `None` when it already has a `RETURNING` clause, or is a `DELETE`
    /// (the target rows are what it removes).
    pub returning_all: Option<String>,
    /// For each column the statement sets, where its new value comes from.
    /// `None`: not known per column; treat every new value as opaque.
    pub assigned: Option<Vec<(String, Source)>>,
    /// A `SELECT` of a key and a digest of each target row, locking them. The
    /// key is `tableoid:ctid`; the digest covers the whole row as text.
    pub target_keys: Option<String>,
    /// The statement limited to the rows whose keys are bound as `$1`
    /// (`text[]`): an approved write then changes only the locked rows.
    pub bound_write: Option<String>,
    /// The statement has its own `RETURNING` clause.
    pub returning: bool,
    /// A read that touches every table and column the statement reads, and
    /// evaluates every new value. An agent must be allowed to run it as a
    /// read before its write is tried.
    pub read_check: Option<String>,
}

/// `tableoid:ctid` names one row of a table, also in a partitioned table.
fn row_key(reference: &Ident) -> String {
    format!("({reference}.tableoid::text || ':' || {reference}.ctid::text)")
}
fn target_keys(reference: &Ident, from: &[String], selection: Option<&Expr>) -> String {
    format!(
        "SELECT {}, encode(sha256(convert_to(ROW({reference}.*)::text, 'UTF8')), 'hex') FROM {}{} FOR UPDATE OF {reference}",
        row_key(reference),
        from.join(", "),
        selection
            .map(|selection| format!(" WHERE {selection}"))
            .unwrap_or_default(),
    )
}
/// The selection, with `AND <row key> = ANY(<keys>)` added.
fn bounded(reference: &Ident, selection: Option<&Expr>) -> Option<Expr> {
    let condition = format!("{} = ANY($1::text[])", row_key(reference));
    let dialect = sqlparser::dialect::PostgreSqlDialect {};
    let condition = sqlparser::parser::Parser::new(&dialect)
        .try_with_sql(&condition)
        .ok()?
        .parse_expr()
        .ok()?;
    Some(match selection {
        Some(selection) => Expr::BinaryOp {
            left: Box::new(Expr::Nested(Box::new(selection.clone()))),
            op: sqlparser::ast::BinaryOperator::And,
            right: Box::new(condition),
        },
        None => condition,
    })
}
fn is_default(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(ident) if ident.quote_style.is_none() && ident.value.eq_ignore_ascii_case("default"))
}

/// A column name as PostgreSQL stores it: an unquoted identifier is folded
/// to lower case, a quoted one is kept exactly. `SET NAME = …` writes `name`;
/// `SET "Name" = …` writes `Name`.
fn column_name(ident: &Ident) -> String {
    if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_lowercase()
    }
}
fn last(name: &ObjectName) -> Option<String> {
    name.0
        .last()
        .and_then(|part| part.as_ident())
        .map(column_name)
}
/// The column that an assignment changes: `SET addr.street = …` changes `addr`.
fn first(name: &ObjectName) -> Option<String> {
    name.0
        .first()
        .and_then(|part| part.as_ident())
        .map(column_name)
}
/// The only plain table of a `FROM` item, with the name a query uses for it.
fn plain(table: &TableWithJoins) -> Option<(String, Ident)> {
    if !table.joins.is_empty() {
        return None;
    }
    match &table.relation {
        TableFactor::Table {
            name,
            alias,
            args: None,
            with_hints,
            version: None,
            partitions,
            ..
        } if with_hints.is_empty() && partitions.is_empty() => {
            // `ONLY t` is read by the parser as a table named `only`.
            let first = name.0.first()?.as_ident()?;
            if first.quote_style.is_none() && first.value.eq_ignore_ascii_case("only") {
                return None;
            }
            let reference = match alias {
                Some(alias) if alias.columns.is_empty() => alias.name.clone(),
                Some(_) => return None,
                None => name.0.last()?.as_ident()?.clone(),
            };
            Some((name.to_string(), reference))
        }
        _ => None,
    }
}
/// A function called with `*` or `t.*` among its arguments.
fn has_wildcard(function: &sqlparser::ast::Function) -> bool {
    use sqlparser::ast::{FunctionArg, FunctionArgExpr, FunctionArguments};
    let FunctionArguments::List(list) = &function.args else {
        return false;
    };
    list.args.iter().any(|arg| {
        let value = match arg {
            FunctionArg::Unnamed(value) => value,
            FunctionArg::Named { arg, .. } | FunctionArg::ExprNamed { arg, .. } => arg,
        };
        matches!(
            value,
            FunctionArgExpr::Wildcard | FunctionArgExpr::QualifiedWildcard(_)
        )
    })
}
/// The column names an expression reads, or `Opaque` for a subquery.
fn sources(expr: &Expr) -> Source {
    let mut columns = Vec::new();
    let opaque = visit_expressions(expr, |expr| {
        match expr {
            Expr::Identifier(ident) => columns.push(column_name(ident)),
            Expr::CompoundIdentifier(parts) => {
                if let Some(part) = parts.last() {
                    columns.push(column_name(part));
                }
            }
            // A subquery, or a whole row (`t.*`, `*`): could carry anything.
            Expr::Subquery(_)
            | Expr::Exists { .. }
            | Expr::InSubquery { .. }
            | Expr::Wildcard(_)
            | Expr::QualifiedWildcard(..) => {
                return ControlFlow::Break(());
            }
            Expr::Function(function) if has_wildcard(function) => {
                return ControlFlow::Break(());
            }
            _ => {}
        }
        ControlFlow::Continue(())
    })
    .is_break();
    if opaque {
        Source::Opaque
    } else {
        Source::Columns(columns)
    }
}

/// A preview plan for one PostgreSQL write, or `None` when the statement is
/// not a single plain `INSERT`, `UPDATE` or `DELETE`.
pub fn write_plan(sql: &str, dialect: Dialect) -> Option<WritePlan> {
    if dialect != Dialect::Postgres {
        return None;
    }
    let mut parsed = parse::parse(sql, dialect).ok()?;
    if parsed.statements.len() != 1 || !parsed.lock_syntax.is_empty() {
        return None;
    }
    let mut statement = parsed.statements.pop()?;
    // `$1` is the list of row keys in a bound write; the statement may not
    // have parameters of its own.
    let parameters = visit_expressions(&statement, |expr| match expr {
        Expr::Value(value) if matches!(value.value, sqlparser::ast::Value::Placeholder(_)) => {
            ControlFlow::Break(())
        }
        _ => ControlFlow::Continue(()),
    });
    if parameters.is_break() {
        return None;
    }
    match &mut statement {
        Statement::Update(update) => {
            if update.or.is_some()
                || update.limit.is_some()
                || !update.order_by.is_empty()
                || update.output.is_some()
            {
                return None;
            }
            let (target, reference) = plain(&update.table)?;
            let mut from = vec![update.table.to_string()];
            match &update.from {
                None => {}
                Some(UpdateTableFromKind::AfterSet(tables)) => {
                    from.extend(tables.iter().map(ToString::to_string));
                }
                Some(UpdateTableFromKind::BeforeSet(_)) => return None,
            }
            let assigned = update
                .assignments
                .iter()
                .map(|assignment| match &assignment.target {
                    AssignmentTarget::ColumnName(name) => {
                        Some((first(name)?, sources(&assignment.value)))
                    }
                    AssignmentTarget::Tuple(_) => None,
                })
                .collect::<Option<Vec<_>>>();
            let target_rows = format!(
                "SELECT {reference}.* FROM {}{} FOR UPDATE OF {reference}",
                from.join(", "),
                update
                    .selection
                    .as_ref()
                    .map(|selection| format!(" WHERE {selection}"))
                    .unwrap_or_default(),
            );
            let selection = update.selection.clone();
            let values: Vec<String> = update
                .assignments
                .iter()
                .filter(|assignment| !is_default(&assignment.value))
                .map(|assignment| assignment.value.to_string())
                .chain(std::iter::once("1".to_owned()))
                .collect();
            let tuple = update
                .assignments
                .iter()
                .any(|assignment| matches!(assignment.target, AssignmentTarget::Tuple(_)));
            let read_check = (!tuple).then(|| {
                format!(
                    "SELECT {} FROM {}{}",
                    values.join(", "),
                    from.join(", "),
                    selection
                        .as_ref()
                        .map(|selection| format!(" WHERE {selection}"))
                        .unwrap_or_default(),
                )
            });
            let keys = target_keys(&reference, &from, selection.as_ref());
            let has_returning = update.returning.is_some();
            update.selection = Some(bounded(&reference, selection.as_ref())?);
            let bound_write = statement.to_string();
            if let Statement::Update(update) = &mut statement {
                update.selection = selection;
            }
            // Only the target's own columns: a joined table's columns would
            // come back under the same names.
            let returning =
                (!has_returning).then(|| format!("{statement} RETURNING {reference}.*"));
            Some(WritePlan {
                kind: StatementKind::Update,
                target,
                target_rows: Some(target_rows),
                returning_all: returning,
                assigned,
                target_keys: Some(keys),
                bound_write: Some(bound_write),
                returning: has_returning,
                read_check,
            })
        }
        Statement::Delete(delete) => {
            if !delete.tables.is_empty()
                || delete.limit.is_some()
                || !delete.order_by.is_empty()
                || delete.output.is_some()
            {
                return None;
            }
            let FromTable::WithFromKeyword(tables) = &delete.from else {
                return None;
            };
            let [table] = tables.as_slice() else {
                return None;
            };
            let (target, reference) = plain(table)?;
            let mut from = vec![table.to_string()];
            if let Some(using) = &delete.using {
                from.extend(using.iter().map(ToString::to_string));
            }
            let selection = delete.selection.clone();
            let filter = selection
                .as_ref()
                .map(|selection| format!(" WHERE {selection}"))
                .unwrap_or_default();
            let target_rows = format!(
                "SELECT {reference}.* FROM {}{filter} FOR UPDATE OF {reference}",
                from.join(", "),
            );
            let read_check = format!("SELECT 1 FROM {}{filter}", from.join(", "));
            let keys = target_keys(&reference, &from, selection.as_ref());
            let has_returning = delete.returning.is_some();
            delete.selection = Some(bounded(&reference, selection.as_ref())?);
            Some(WritePlan {
                kind: StatementKind::Delete,
                target,
                target_rows: Some(target_rows),
                returning_all: None,
                assigned: Some(vec![]),
                target_keys: Some(keys),
                bound_write: Some(statement.to_string()),
                returning: has_returning,
                read_check: Some(read_check),
            })
        }
        Statement::Insert(insert) => {
            let TableObject::TableName(name) = &insert.table else {
                return None;
            };
            if insert.or.is_some() || insert.output.is_some() || insert.on.is_some() {
                return None;
            }
            let target = name.to_string();
            // Values that are written out in the statement are known to the
            // requester already. Anything read from a table is opaque.
            let assigned = match insert.source.as_deref() {
                Some(query) if !insert.columns.is_empty() && query.with.is_none() => {
                    match query.body.as_ref() {
                        SetExpr::Values(values) => {
                            let mut assigned = Vec::new();
                            for (index, column) in insert.columns.iter().enumerate() {
                                let mut source = Source::Columns(vec![]);
                                for row in &values.rows {
                                    if let Some(expr) = row.get(index) {
                                        if sources(expr) != Source::Columns(vec![]) {
                                            source = Source::Opaque;
                                        }
                                    }
                                }
                                assigned.push((last(column)?, source));
                            }
                            Some(assigned)
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            let read_check = Some(match insert.source.as_deref() {
                // Every source column is read, so no part of the source can be
                // dropped by the planner before its permissions are checked.
                Some(query) => format!("SELECT vda_source.* FROM ({query}) AS vda_source"),
                None => "SELECT 1".to_owned(),
            });
            let has_returning = insert.returning.is_some();
            let returning = (!has_returning).then(|| format!("{statement} RETURNING *"));
            Some(WritePlan {
                kind: StatementKind::Insert,
                target,
                target_rows: None,
                returning_all: returning,
                assigned,
                target_keys: None,
                bound_write: None,
                returning: has_returning,
                read_check,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn plan(sql: &str) -> WritePlan {
        write_plan(sql, Dialect::Postgres).unwrap_or_else(|| panic!("no plan for {sql}"))
    }

    #[test]
    fn update_and_delete_plans_select_and_lock_the_rows_they_change() {
        let p = plan("UPDATE public.users u SET name = upper(u.name), note = 'x' WHERE u.id = 1");
        assert_eq!(p.kind, StatementKind::Update);
        assert_eq!(
            p.target_rows.as_deref(),
            Some("SELECT u.* FROM public.users u WHERE u.id = 1 FOR UPDATE OF u")
        );
        assert_eq!(
            p.returning_all.as_deref(),
            Some("UPDATE public.users u SET name = upper(u.name), note = 'x' WHERE u.id = 1 RETURNING u.*")
        );
        assert_eq!(
            p.target_keys.as_deref(),
            Some("SELECT (u.tableoid::text || ':' || u.ctid::text), encode(sha256(convert_to(ROW(u.*)::text, 'UTF8')), 'hex') FROM public.users u WHERE u.id = 1 FOR UPDATE OF u")
        );
        assert_eq!(
            p.bound_write.as_deref(),
            Some("UPDATE public.users u SET name = upper(u.name), note = 'x' WHERE (u.id = 1) AND (u.tableoid::TEXT || ':' || u.ctid::TEXT) = ANY($1::TEXT[])")
        );
        assert_eq!(
            p.read_check.as_deref(),
            Some("SELECT upper(u.name), 'x', 1 FROM public.users u WHERE u.id = 1")
        );
        assert_eq!(
            p.assigned,
            Some(vec![
                ("name".into(), Source::Columns(vec!["name".into()])),
                ("note".into(), Source::Columns(vec![])),
            ])
        );
        let p = plan("UPDATE orders SET total = o2.total FROM orders o2 WHERE orders.id = o2.id RETURNING id");
        assert_eq!(
            p.target_rows.as_deref(),
            Some("SELECT orders.* FROM orders, orders o2 WHERE orders.id = o2.id FOR UPDATE OF orders")
        );
        assert_eq!(p.returning_all, None, "its own RETURNING is kept");
        let p = plan("UPDATE t SET a = (SELECT secret FROM vault LIMIT 1)");
        assert_eq!(p.assigned, Some(vec![("a".into(), Source::Opaque)]));
        assert_eq!(
            p.read_check.as_deref(),
            Some("SELECT (SELECT secret FROM vault LIMIT 1), 1 FROM t")
        );
        let p = plan("UPDATE t SET addr.street = email, b = DEFAULT WHERE id = 1");
        assert_eq!(
            p.assigned,
            Some(vec![
                ("addr".into(), Source::Columns(vec!["email".into()])),
                ("b".into(), Source::Columns(vec!["default".into()])),
            ])
        );
        assert_eq!(
            p.read_check.as_deref(),
            Some("SELECT email, 1 FROM t WHERE id = 1")
        );
        assert_eq!(
            write_plan("UPDATE t SET a = 1 WHERE id = $1", Dialect::Postgres),
            None
        );
        for sql in [
            "UPDATE t SET a = concat(t.*) WHERE id = 1",
            "UPDATE t SET a = (t.*)::text WHERE id = 1",
            "UPDATE t SET a = json_build_array(t.*)::text WHERE id = 1",
        ] {
            assert_eq!(
                plan(sql).assigned,
                Some(vec![("a".into(), Source::Opaque)]),
                "{sql}"
            );
        }
        assert!(plan("DELETE FROM t WHERE id = 1 RETURNING id").returning);
        assert!(!plan("DELETE FROM t WHERE id = 1").returning);
        let p = plan("DELETE FROM \"Odd\".\"T\" USING other WHERE \"T\".id = other.id");
        assert_eq!(
            p.target_rows.as_deref(),
            Some("SELECT \"T\".* FROM \"Odd\".\"T\", other WHERE \"T\".id = other.id FOR UPDATE OF \"T\"")
        );
        assert_eq!(p.returning_all, None);
        assert_eq!(
            p.read_check.as_deref(),
            Some("SELECT 1 FROM \"Odd\".\"T\", other WHERE \"T\".id = other.id")
        );
        assert!(p
            .bound_write
            .is_some_and(|sql| sql.ends_with("= ANY($1::TEXT[])")));
    }

    #[test]
    fn inserts_say_which_values_were_written_out() {
        let p = plan("INSERT INTO t (a, b) VALUES (1, 'x'), (2, now())");
        assert_eq!(p.target_rows, None);
        assert_eq!(
            p.returning_all.as_deref(),
            Some("INSERT INTO t (a, b) VALUES (1, 'x'), (2, now()) RETURNING *")
        );
        assert_eq!(
            p.read_check.as_deref(),
            Some("SELECT vda_source.* FROM (VALUES (1, 'x'), (2, now())) AS vda_source")
        );
        assert_eq!(
            p.assigned,
            Some(vec![
                ("a".into(), Source::Columns(vec![])),
                ("b".into(), Source::Columns(vec![])),
            ])
        );
        let p = plan("INSERT INTO t (a) SELECT email FROM users");
        assert_eq!(p.assigned, None, "copied from a table: opaque");
        assert_eq!(plan("INSERT INTO t VALUES (1)").assigned, None);
    }

    #[test]
    fn other_shapes_get_no_row_plan() {
        for sql in [
            "WITH x AS (SELECT 1) UPDATE t SET a = 1",
            "UPDATE t SET a = 1; DELETE FROM t",
            "UPDATE ONLY t SET a = 1",
            "DELETE FROM ONLY t",
            "UPDATE t JOIN u ON t.id = u.id SET t.a = 1",
            "UPDATE t x(a) SET a = 1",
            "INSERT INTO t VALUES (1) ON CONFLICT DO NOTHING",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
            "SELECT 1",
            "not sql",
        ] {
            assert_eq!(write_plan(sql, Dialect::Postgres), None, "{sql}");
        }
        assert_eq!(write_plan("UPDATE t SET a = 1", Dialect::MySql), None);
    }

    #[test]
    fn column_names_are_the_names_postgres_uses() {
        let names = |sql: &str| {
            plan(sql)
                .assigned
                .unwrap_or_default()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>()
        };
        assert_eq!(names("UPDATE t SET NAME = 1 WHERE id = 1"), ["name"]);
        assert_eq!(names("UPDATE t SET \"Name\" = 1 WHERE id = 1"), ["Name"]);
        assert_eq!(names("INSERT INTO t (A, \"B\") VALUES (1, 2)"), ["a", "B"]);
        // A swap writes `code` however it is spelled, and reads `code`.
        let p = plan("UPDATE swap_t SET CODE = 3 - code, qty = qty WHERE code IN (1, 2)");
        assert_eq!(
            p.assigned,
            Some(vec![
                ("code".into(), Source::Columns(vec!["code".into()])),
                ("qty".into(), Source::Columns(vec!["qty".into()])),
            ])
        );
        let p = plan("UPDATE t SET note = T.\"Secret\" || Email WHERE id = 1");
        assert_eq!(
            p.assigned,
            Some(vec![(
                "note".into(),
                Source::Columns(vec!["Secret".into(), "email".into()])
            )])
        );
    }
}
