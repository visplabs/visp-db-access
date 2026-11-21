//! Enforce the outer result cap while retaining the original offset.
use crate::RowCap;
use sqlparser::ast::{Expr, LimitClause, Query, Statement, Value};

pub(crate) fn has_limit(query: &Query) -> bool {
    query.fetch.is_some()
        || match &query.limit_clause {
            Some(LimitClause::OffsetCommaLimit { .. }) => true,
            Some(LimitClause::LimitOffset { limit, .. }) => limit.is_some(),
            None => false,
        }
}

pub(crate) fn number(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse().ok(),
            _ => None,
        },
        Expr::Nested(inner) => number(inner),
        _ => None,
    }
}

/// The row limit of a query as its SQL text says it: the `LIMIT` clause
/// without its `OFFSET`, or else the `FETCH` clause. Empty when it has neither.
fn limit_text(query: &Query) -> String {
    let limit = match &query.limit_clause {
        Some(LimitClause::OffsetCommaLimit { offset, limit }) => {
            Some(format!("LIMIT {offset}, {limit}"))
        }
        Some(LimitClause::LimitOffset { limit, .. }) => {
            limit.as_ref().map(|limit| format!("LIMIT {limit}"))
        }
        None => None,
    };
    limit
        .or_else(|| query.fetch.as_ref().map(|fetch| fetch.to_string()))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The statement with the row cap enforced, and what the cap changed.
pub(crate) fn cap(statement: &Statement, max_rows: u64) -> (String, Option<RowCap>) {
    let mut statement = statement.clone();
    let mut change = None;
    if let Statement::Query(query) = &mut statement {
        let written = limit_text(query);
        let limited = has_limit(query);
        let sentinel =
            Expr::Value(Value::Number((u128::from(max_rows) + 1).to_string(), false).into());
        if let Some(fetch) = &mut query.fetch {
            let quantity = fetch.quantity.as_ref().map_or(Some(1), number);
            if fetch.percent || fetch.with_ties || quantity.is_none_or(|n| n > max_rows) {
                fetch.quantity = Some(sentinel.clone());
                fetch.percent = false;
                fetch.with_ties = false;
            }
        }
        match &mut query.limit_clause {
            Some(LimitClause::OffsetCommaLimit { limit, .. }) => {
                if number(limit).is_none_or(|n| n > max_rows) {
                    *limit = sentinel;
                }
            }
            Some(LimitClause::LimitOffset { limit, .. }) => {
                if (limit.is_some() || query.fetch.is_none())
                    && limit.as_ref().and_then(number).is_none_or(|n| n > max_rows)
                {
                    *limit = Some(sentinel);
                }
            }
            None if query.fetch.is_none() => {
                query.limit_clause = Some(LimitClause::LimitOffset {
                    limit: Some(sentinel),
                    offset: None,
                    limit_by: vec![],
                });
            }
            None => {}
        }
        let runs = limit_text(query);
        if runs != written {
            change = Some(RowCap {
                clause: runs,
                replaces: limited.then_some(written),
            });
        }
    }
    (statement.to_string(), change)
}
