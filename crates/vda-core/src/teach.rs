//! Teaching errors: every refusal says what to do next, in one small object.
//!
//! The same `Fix` serves an agent (so it can correct itself instead of
//! guessing again) and a person in the console.
use crate::error::ApiError;
use serde::Serialize;
use serde_json::Value;

/// The next step after a refusal. `action` is a stable machine word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fix {
    /// One of: `rewrite_sql`, `fix_arguments`, `choose_database`, `ask_owner`,
    /// `propose_write`, `retry_later`, `stop`.
    pub action: &'static str,
    /// What to change, in one or two plain sentences.
    pub hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}
impl Fix {
    fn new(action: &'static str, hint: impl Into<String>) -> Self {
        Self {
            action,
            hint: hint.into(),
            retry_after_seconds: None,
        }
    }
}

/// The fix for one guard or masking issue code.
pub fn for_issue(code: &str, message: &str) -> Fix {
    let (action, hint) = match code {
        "parse_error" | "empty_query" => (
            "rewrite_sql",
            "The SQL does not parse. Send one complete statement in this database's dialect.",
        ),
        "multiple_statements" => (
            "rewrite_sql",
            "Send one statement per call. Split the work into separate calls.",
        ),
        "statement_not_allowed" | "unsupported_syntax" | "select_into" | "locking_read"
        | "optimizer_hint" | "executable_comment" => (
            "rewrite_sql",
            "This kind of statement or clause is not accepted. Use a plain SELECT without locking clauses, hints or special comments.",
        ),
        "dangerous_function" | "stateful_function" | "unbounded_generator" => (
            "rewrite_sql",
            "A function in this query is not accepted. Remove it and use plain columns, filters and aggregates.",
        ),
        "sensitive_catalog" => (
            "rewrite_sql",
            "This system catalog holds credentials or internals. Use search_schema and describe_table to learn the structure.",
        ),
        "masked_data_serialization" | "masked_data_transformation" => (
            "rewrite_sql",
            "The query would move a protected column through a function or a whole-row expression. Select the columns you need by name and leave protected columns untouched.",
        ),
        "query_too_large" => ("rewrite_sql", "The SQL text is too long. Send a shorter statement."),
        "explain_analyze_write" | "explain_analyze_executes" | "data_modifying_cte" => (
            "rewrite_sql",
            "This statement would change data while it looks like a read. Use a plain SELECT, or EXPLAIN without ANALYZE.",
        ),
        "write_without_where" | "tautological_where" | "unbounded_insert_select" => (
            "rewrite_sql",
            "A write must name the rows it changes. Add a WHERE clause that selects only those rows.",
        ),
        "blocked_table" => (
            "stop",
            "This table is not available here. Do not try other spellings of it. Tell your owner if you need it.",
        ),
        "insufficient_access" => (
            "ask_owner",
            "Your access level does not allow this statement. Ask your owner; do not retry.",
        ),
        "writes_disabled" | "ddl_disabled" => (
            "stop",
            "This database does not accept this kind of change from anyone. Do not retry.",
        ),
        _ => ("rewrite_sql", message),
    };
    Fix::new(action, hint)
}

/// Of several blocking issues, the one whose fix is the hardest stop wins:
/// `stop`, then `ask_owner`, then the rest in the guard's order. Otherwise an
/// agent is told to repair one thing and is then refused for another.
pub fn strongest<'a>(issues: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Fix> {
    let rank = |fix: &Fix| match fix.action {
        "stop" => 0,
        "ask_owner" => 1,
        _ => 2,
    };
    // `min_by_key` keeps the first of equals, which is the guard's own order.
    issues
        .into_iter()
        .map(|(code, message)| for_issue(code, message))
        .min_by_key(rank)
}

/// The fix for a refused request. A guard refusal carries its analysis in
/// `details`; the first blocking issue there decides the fix.
pub fn for_error(error: &ApiError) -> Fix {
    let blocking = error
        .details
        .get("issues")
        .and_then(Value::as_array)
        .map(|issues| {
            issues.iter().filter_map(|issue| {
                (issue.get("severity")?.as_str()? == "block").then_some((
                    issue.get("code")?.as_str()?,
                    issue.get("message")?.as_str()?,
                ))
            })
        })
        .and_then(strongest);
    match (error.code, blocking) {
        ("query_denied", Some(fix)) => fix,
        ("query_denied", None) => Fix::new(
            "rewrite_sql",
            "The guard refused this statement. Call check_sql to see why before you run it.",
        ),
        ("approval_required", _) => Fix::new(
            "propose_write",
            "This statement changes data, and an agent cannot change data on its own. Call propose_write with the same SQL and say why in `task`; a person decides.",
        ),
        ("effect_changed", _) => Fix::new(
            "propose_write",
            "The data changed after the approval, so the write did not run. Check the rows again, then call propose_write again if the change is still needed.",
        ),
        ("outcome_unknown", _) => Fix::new(
            "stop",
            "Nobody knows whether the write ran. Do not ask for it again; tell your owner.",
        ),
        ("write_failed", _) => Fix::new(
            "ask_owner",
            "The write failed when it ran, and the request is used up. Tell your owner; they can see why. Ask again only if they agree.",
        ),
        ("approval_not_found", _) => Fix::new(
            "fix_arguments",
            "No request of yours has this id. Use the approval_id that propose_write gave, or call get_approval without approval_id to list your open requests.",
        ),
        ("insufficient_access", _) => Fix::new(
            "ask_owner",
            "Your access level does not allow writes on this database. Ask your owner; do not retry.",
        ),
        ("conflict", _) => Fix::new(
            "stop",
            "The request is not in a state that allows this. Call get_approval to see its state; do not retry.",
        ),
        ("unsupported_write", _) => Fix::new("rewrite_sql", error.message.clone()),
        ("too_many_open_requests", _) => Fix::new(
            "retry_later",
            "Too many of your writes wait for a person. `error.details.requests` lists them. Wait for a decision, or withdraw one you no longer need.",
        ),
        ("cost_exceeded", _) => Fix::new(
            "rewrite_sql",
            "The query is too expensive. Add filters on indexed columns, select fewer rows, or aggregate less.",
        ),
        ("result_too_large", _) => Fix::new(
            "rewrite_sql",
            "Select fewer columns, or shorten the long ones with substring or left.",
        ),
        ("table_not_found", _) => Fix::new(
            "fix_arguments",
            "No table has this name here. Call search_schema to find the exact name, then use `schema.table`.",
        ),
        ("network_denied", _) => Fix::new(
            "stop",
            "This database does not accept requests from your network address. Do not retry. Tell your owner.",
        ),
        ("forbidden" | "not_found", _) => Fix::new(
            "choose_database",
            "You cannot reach this database or object. Call list_databases and use an id from that list.",
        ),
        ("validation", _) => Fix::new("fix_arguments", error.message.clone()),
        ("rate_limited", _) => Fix {
            retry_after_seconds: error.details.get("retry_after_seconds").and_then(Value::as_u64),
            ..Fix::new("retry_later", "You are calling too fast. Wait, then go on at a slower pace.")
        },
        ("busy", _) => Fix {
            retry_after_seconds: Some(5),
            ..Fix::new("retry_later", "The database is busy. Wait, then send the same call once.")
        },
        ("budget_exceeded", _) => Fix {
            retry_after_seconds: error.details.get("retry_after_seconds").and_then(Value::as_u64),
            ..Fix::new(
                "retry_later",
                "You have used your hourly query budget. Wait, or ask your owner to raise it.",
            )
        },
        ("too_many_denials", _) => Fix {
            retry_after_seconds: error.details.get("retry_after_seconds").and_then(Value::as_u64),
            ..if error.details.get("tool").and_then(Value::as_str) == Some("propose_write") {
                Fix::new(
                    "stop",
                    "Several write requests in a row were refused. Stop, and tell your owner what you asked for and what was refused.",
                )
            } else {
                Fix::new(
                    "stop",
                    "Several queries in a row were refused. Stop, and tell your owner what you tried and what was refused.",
                )
            }
        },
        ("upstream", _) => match (error.kind, error.message.as_str()) {
            (crate::error::ErrorKind::Cancelled, _) => Fix::new(
                "stop",
                "The query was cancelled by a person, or your access ended while it ran. Do not run it again. Tell your owner.",
            ),
            (crate::error::ErrorKind::Database, message)
                if message.contains("permission denied") || message.contains("masked data") =>
            {
                Fix::new(
                    "rewrite_sql",
                    "The database does not let you read a table or column in this query. Call describe_table, name the columns you need instead of `*`, and leave out the ones marked protected.",
                )
            }
            (crate::error::ErrorKind::Database, _) => Fix::new(
                "rewrite_sql",
                "The database reported an error. Check names and types with describe_table, then correct the SQL.",
            ),
            (_, "Query timed out") => Fix::new(
                "rewrite_sql",
                "The query ran too long. Add filters on indexed columns, select fewer rows, or aggregate less.",
            ),
            (_, "Affected row limit exceeded; transaction rolled back") => Fix::new(
                "rewrite_sql",
                "The statement touches more rows than this database allows at once. Narrow it.",
            ),
            _ => Fix {
                retry_after_seconds: Some(30),
                ..Fix::new("retry_later", "The database could not be reached. Try once more later.")
            },
        },
        ("database_setup_drift", _) => Fix::new(
            "ask_owner",
            "This database is closed to agents until a person repairs its setup. Tell your owner.",
        ),
        ("database_check_failed", _) => Fix {
            retry_after_seconds: Some(30),
            ..Fix::new(
                "retry_later",
                "The gateway could not check this database's setup. Try once more later; if it stays, tell your owner.",
            )
        },
        ("credentials_unreadable", _) => Fix::new(
            "ask_owner",
            "The gateway cannot open this database. Waiting does not help. Tell your owner.",
        ),
        ("unauthenticated", _) => {
            Fix::new("stop", "Your token is not valid any more. Ask your owner for a new one.")
        }
        _ => Fix {
            retry_after_seconds: Some(30),
            ..Fix::new("retry_later", "The gateway could not finish this call. Try once more later.")
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use serde_json::json;

    #[test]
    fn a_refusal_always_names_one_next_step() {
        let denied = |issues: Value| {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "query_denied", "denied")
                .details(json!({"issues":issues}))
        };
        // The first blocking issue decides; advice-level issues do not.
        let fix = for_error(&denied(json!([
            {"severity":"warning","code":"select_star","message":"advice"},
            {"severity":"block","code":"blocked_table","message":"users is blocked"},
            {"severity":"block","code":"parse_error","message":"later"},
        ])));
        assert_eq!(fix.action, "stop");
        // An unknown code still gives a usable answer: the guard's own words.
        let fix = for_error(&denied(json!([
            {"severity":"block","code":"brand_new_rule","message":"Do it differently."}
        ])));
        assert_eq!(
            (fix.action, fix.hint.as_str()),
            ("rewrite_sql", "Do it differently.")
        );
        assert_eq!(for_error(&denied(json!([]))).action, "rewrite_sql");
        // A hard stop outranks a repair: repairing would only reach the next refusal.
        let fix = for_error(&denied(json!([
            {"severity":"block","code":"write_without_where","message":"add where"},
            {"severity":"block","code":"insufficient_access","message":"read only"},
        ])));
        assert_eq!(fix.action, "ask_owner");
        let mut cancelled = ApiError::new(StatusCode::BAD_GATEWAY, "upstream", "Query cancelled");
        cancelled.kind = crate::error::ErrorKind::Cancelled;
        assert_eq!(for_error(&cancelled).action, "stop");
        let mut database = ApiError::new(
            StatusCode::BAD_GATEWAY,
            "upstream",
            "column x does not exist",
        );
        database.kind = crate::error::ErrorKind::Database;
        assert_eq!(for_error(&database).action, "rewrite_sql");
        for (message, action) in [
            ("Query timed out", "rewrite_sql"),
            ("Target database unavailable", "retry_later"),
        ] {
            let error = ApiError::new(StatusCode::BAD_GATEWAY, "upstream", message);
            assert_eq!(for_error(&error).action, action, "{message}");
        }
        for (code, action) in [
            ("approval_required", "propose_write"),
            ("effect_changed", "propose_write"),
            ("outcome_unknown", "stop"),
            ("write_failed", "ask_owner"),
            ("approval_not_found", "fix_arguments"),
            ("insufficient_access", "ask_owner"),
            ("conflict", "stop"),
            ("too_many_open_requests", "retry_later"),
            ("unsupported_write", "rewrite_sql"),
            ("cost_exceeded", "rewrite_sql"),
            ("forbidden", "choose_database"),
            ("not_found", "choose_database"),
            ("table_not_found", "fix_arguments"),
            ("result_too_large", "rewrite_sql"),
            ("network_denied", "stop"),
            ("rate_limited", "retry_later"),
            ("credentials_unreadable", "ask_owner"),
            ("database_setup_drift", "ask_owner"),
            ("database_check_failed", "retry_later"),
            ("validation", "fix_arguments"),
            ("busy", "retry_later"),
            ("unauthenticated", "stop"),
            ("internal", "retry_later"),
            ("something_new", "retry_later"),
        ] {
            let fix = for_error(&ApiError::new(StatusCode::BAD_REQUEST, code, "why"));
            assert_eq!(fix.action, action, "{code}");
            assert!(!fix.hint.is_empty());
        }
        let limited = ApiError::new(StatusCode::TOO_MANY_REQUESTS, "budget_exceeded", "x")
            .details(json!({"retry_after_seconds":120}));
        assert_eq!(for_error(&limited).retry_after_seconds, Some(120));
        // A stop on write requests talks about write requests.
        let stopped = |details: Value| {
            for_error(
                &ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too_many_denials", "x")
                    .details(details),
            )
        };
        let fix = stopped(json!({"retry_after_seconds":42,"tool":"propose_write"}));
        assert_eq!((fix.action, fix.retry_after_seconds), ("stop", Some(42)));
        assert!(fix.hint.contains("write requests"), "{}", fix.hint);
        assert!(stopped(json!({})).hint.contains("queries"));
        // The wire shape leaves out an absent wait.
        assert_eq!(
            json!(for_issue("multiple_statements", "")),
            json!({"action":"rewrite_sql","hint":"Send one statement per call. Split the work into separate calls."})
        );
    }
}
