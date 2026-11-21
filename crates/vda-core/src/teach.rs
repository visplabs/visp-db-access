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

/// What a person is told about a read that takes row locks. Such a statement
/// cannot run as a read, and an approval is for a change of data, so the one
/// way on is to take the locking clause out.
const LOCKING_READ: &str = "This statement locks rows. Remove the locking clause (FOR UPDATE / FOR SHARE) to run it as a read.";
/// The same for an agent, which would otherwise be sent to `propose_write`
/// with a statement that tool cannot take.
const LOCKING_READ_AGENT: &str = "This statement locks rows, so it does not run as a read, and it changes no data, so it cannot be proposed as a write. Remove the locking clause (FOR UPDATE or FOR SHARE) and run it again.";

/// What one guard or masking issue code teaches: the next step, and the
/// words for it. An agent and a person get the same step from this one table;
/// only the wording differs, because a person has no tools to call and an
/// agent has no console.
struct Lesson {
    action: &'static str,
    agent: &'static str,
    person: &'static str,
}

/// The lesson for a known issue code. An unknown code has none: the guard's
/// own message is then the hint, for both readers.
fn lesson(code: &str) -> Option<Lesson> {
    let (action, agent, person) = match code {
        "parse_error" | "empty_query" => (
            "rewrite_sql",
            "The SQL does not parse. Send one complete statement in this database's dialect.",
            "The SQL does not parse. Write one complete statement in this database's dialect.",
        ),
        "multiple_statements" => (
            "rewrite_sql",
            "Send one statement per call. Split the work into separate calls.",
            "Only one statement runs at a time. Keep one statement in the editor and run the others after it.",
        ),
        "locking_read" => (
            "rewrite_sql",
            "This kind of statement or clause is not accepted. Use a plain SELECT without locking clauses, hints or special comments.",
            LOCKING_READ,
        ),
        "statement_not_allowed" | "unsupported_syntax" | "select_into" | "optimizer_hint"
        | "executable_comment" => (
            "rewrite_sql",
            "This kind of statement or clause is not accepted. Use a plain SELECT without locking clauses, hints or special comments.",
            "This kind of statement or clause does not run through the gateway. Use a plain statement without locking clauses, hints or special comments.",
        ),
        "dangerous_function" | "stateful_function" | "unbounded_generator" => (
            "rewrite_sql",
            "A function in this query is not accepted. Remove it and use plain columns, filters and aggregates.",
            "A function in this statement is not allowed here. Remove it and use plain columns, filters and aggregates.",
        ),
        "sensitive_catalog" => (
            "rewrite_sql",
            "This system catalog holds credentials or internals. Use search_schema and describe_table to learn the structure.",
            "This system catalog holds credentials or internals. Use the schema panel to see the structure.",
        ),
        "masked_data_serialization" | "masked_data_transformation" => (
            "rewrite_sql",
            "The query would move a protected column through a function or a whole-row expression. Select the columns you need by name and leave protected columns untouched.",
            "The statement would move a protected column through a function or a whole-row expression, so it could not be masked. Select the columns you need by name and leave protected columns as they are.",
        ),
        "query_too_large" => (
            "rewrite_sql",
            "The SQL text is too long. Send a shorter statement.",
            "The SQL text is too long. Shorten the statement.",
        ),
        "explain_analyze_write" | "explain_analyze_executes" | "data_modifying_cte" => (
            "rewrite_sql",
            "This statement would change data while it looks like a read. Use a plain SELECT, or EXPLAIN without ANALYZE.",
            "This statement would change data while it looks like a read. Use a plain SELECT, or EXPLAIN without ANALYZE.",
        ),
        "write_without_where" | "tautological_where" | "unbounded_insert_select" => (
            "rewrite_sql",
            "A write must name the rows it changes. Add a WHERE clause that selects only those rows.",
            "A write must name the rows it changes. Add a WHERE clause that selects only those rows.",
        ),
        "blocked_table" => (
            "stop",
            "This table is not available here. Do not try other spellings of it. Tell your owner if you need it.",
            "This database's policy blocks a table in this statement.",
        ),
        "insufficient_access" => (
            "ask_owner",
            "Your access level does not allow this statement. Ask your owner; do not retry.",
            "Your access to this database does not allow this statement.",
        ),
        "writes_disabled" | "ddl_disabled" => (
            "stop",
            "This database does not accept this kind of change from anyone. Do not retry.",
            "This database's policy does not allow this kind of change, for anyone.",
        ),
        _ => return None,
    };
    Some(Lesson {
        action,
        agent,
        person,
    })
}

/// The fix for one guard or masking issue code.
pub fn for_issue(code: &str, message: &str) -> Fix {
    match lesson(code) {
        Some(lesson) => Fix::new(lesson.action, lesson.agent),
        None => Fix::new("rewrite_sql", message),
    }
}

/// How hard a fix stops its reader: `stop`, then `ask_owner`, then the rest.
fn rank(action: &str) -> u8 {
    match action {
        "stop" => 0,
        "ask_owner" => 1,
        _ => 2,
    }
}

/// Of several blocking issues, the one that decides the fix, as
/// `(code, message)`: the hardest stop, and among equals the guard's first.
fn deciding<'a>(
    issues: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<(&'a str, &'a str)> {
    // `min_by_key` keeps the first of equals, which is the guard's own order.
    issues
        .into_iter()
        .min_by_key(|(code, message)| rank(for_issue(code, message).action))
}

/// Of several blocking issues, the one whose fix is the hardest stop wins:
/// `stop`, then `ask_owner`, then the rest in the guard's order. Otherwise an
/// agent is told to repair one thing and is then refused for another.
pub fn strongest<'a>(issues: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Fix> {
    deciding(issues).map(|(code, message)| for_issue(code, message))
}

/// What an agent was told to do, said for a person who reads its trail.
/// One sentence for each `action` word of a [`Fix`].
pub fn told(action: &str) -> &'static str {
    match action {
        "rewrite_sql" => "The agent was told to change its SQL.",
        "fix_arguments" => "The agent was told to correct the arguments of its call.",
        "choose_database" => "The agent was told to use a database from its list.",
        "ask_owner" => "The agent was told to ask its owner.",
        "propose_write" => "The agent was told to ask a person for this write.",
        "retry_later" => "The agent was told to wait and try again.",
        "stop" => "The agent was told to stop.",
        _ => "The agent was told what to do next.",
    }
}

/// The guard's change to the row limit, said for a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardChange {
    /// The limit as it runs, such as `LIMIT 1001`.
    pub clause: String,
    /// The limit as it was written, when the guard lowered one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    /// One sentence that says what the guard does and why.
    pub text: String,
}

/// What a person can do with a statement before running it: the state of the
/// check, why, and the one next step. Made from the same lessons as an
/// agent's [`Fix`], worded for a person at the console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Preflight {
    /// One of: `safe`, `needs_approval`, `blocked`.
    pub state: &'static str,
    /// One of: `run`, `request_approval`, `apply_fix` (a button each), and
    /// `edit_sql`, `ask_admin`, `change_policy` (no button: read `hint`).
    pub action: &'static str,
    /// The next step in a few words: the button's text when there is one.
    pub label: String,
    /// Why, in one or two plain sentences.
    pub hint: String,
    /// The code that decided a state other than `safe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// With `apply_fix`: the edit that resolves the block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<vda_guard::Fix>,
    /// What the guard adds to the SQL that runs, when it adds something.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_change: Option<GuardChange>,
}

/// The number of a plain `LIMIT n`, and nothing for any other form.
fn plain_limit(clause: &str) -> Option<u64> {
    clause.strip_prefix("LIMIT ")?.parse().ok()
}
fn guard_change(cap: &vda_guard::RowCap, max_rows: u64) -> GuardChange {
    let why =
        format!("the policy allows {max_rows} rows, and one more row shows whether there are more");
    let text = match &cap.replaces {
        // "Lowers" is said only when both are plain numbers and it is true.
        Some(written)
            if plain_limit(written)
                .zip(plain_limit(&cap.clause))
                .is_some_and(|(before, after)| after < before) =>
        {
            format!("The guard lowers {written} to {}: {why}.", cap.clause)
        }
        Some(written) => format!("The guard replaces {written} with {}: {why}.", cap.clause),
        None => format!("The guard adds {}: {why}.", cap.clause),
    };
    GuardChange {
        clause: cap.clause.clone(),
        replaces: cap.replaces.clone(),
        text,
    }
}

/// What kind of change a statement makes, for a sentence: "changes data".
fn effect(analysis: &vda_guard::Analysis) -> &'static str {
    use vda_guard::StatementKind;
    let kinds = || analysis.statements.iter().map(|statement| statement.kind);
    if kinds().any(|kind| kind == StatementKind::Ddl) {
        "changes the schema"
    } else {
        "changes data"
    }
}

/// Who can help when the person cannot go on alone, as the action word, the
/// label and a sentence.
fn who_can_help(
    action: &str,
    level: vda_guard::AccessLevel,
    schema: bool,
) -> (&'static str, &'static str, &'static str) {
    use vda_guard::AccessLevel;
    match (action, level, schema) {
        // The policy decides. An administrator of the database is the one
        // who can change it; say so to the person who is one.
        ("stop", AccessLevel::Admin, _) => (
            "change_policy",
            "Change the policy",
            "You administer this database: change its policy if this should run.",
        ),
        ("stop", _, _) => (
            "ask_admin",
            "Ask an administrator",
            "Only an administrator of this database can change its policy.",
        ),
        (_, _, true) => (
            "ask_admin",
            "Ask an administrator",
            "Only an administrator of this database can ask for a schema change.",
        ),
        (_, AccessLevel::Read, false) => (
            "ask_admin",
            "Ask for write access",
            "A person with write access can ask for this change, or an administrator of this database can give you write access.",
        ),
        _ => (
            "ask_admin",
            "Ask an administrator",
            "An administrator of this database can change your access.",
        ),
    }
}

/// What the pre-flight answer depends on beside the analysis: the person
/// who asks, and the policy of the database.
#[derive(Debug, Clone, Copy)]
pub struct Asker {
    /// The person's access to the database.
    pub level: vda_guard::AccessLevel,
    /// The policy's row cap, for the sentence about the guard's change.
    pub max_rows: u64,
    /// The policy has a cost limit, which is checked when a read runs.
    pub cost_limit: bool,
}

/// The pre-flight answer for a person: the state of the check, one sentence
/// of why, and exactly one next step. A person who may not ask for an
/// approval is told who can.
pub fn preflight(analysis: &vda_guard::Analysis, asker: Asker) -> Preflight {
    use vda_guard::{AccessLevel, Severity, StatementKind, Verdict};
    let Asker {
        level, max_rows, ..
    } = asker;
    let change = analysis
        .row_cap
        .as_ref()
        .map(|cap| guard_change(cap, max_rows));
    let schema = analysis
        .statements
        .iter()
        .any(|statement| statement.kind == StatementKind::Ddl);
    let step = |state, action, label: &str, hint: String, code: Option<&str>| Preflight {
        state,
        action,
        label: label.to_owned(),
        hint,
        code: code.map(str::to_owned),
        fix: None,
        guard_change: None,
    };
    match analysis.verdict {
        Verdict::Allow => Preflight {
            guard_change: change,
            ..step(
                "safe",
                "run",
                "Run",
                if analysis.is_read_only() && asker.cost_limit {
                    // The check runs nothing, so it cannot know the cost yet.
                    "This statement only reads data. Its cost is checked against this database's limit when it runs.".to_owned()
                } else if analysis.is_read_only() {
                    "This statement only reads data.".to_owned()
                } else {
                    format!(
                        "This statement {}, and this database's policy lets it run without approval.",
                        effect(analysis)
                    )
                },
                None,
            )
        },
        // A read that takes row locks. An approval is for a change of data,
        // and a request for this one would be refused, so the next step is
        // to take the locking clause out, whatever the person's level.
        Verdict::RequiresApproval if analysis.is_read_only() => step(
            "blocked",
            "edit_sql",
            "Edit the SQL",
            LOCKING_READ.to_owned(),
            Some("locking_read"),
        ),
        // Asking for approval needs write access. The guard refuses a
        // reader's write before this point; this arm keeps the rule if that
        // ever changes.
        Verdict::RequiresApproval if level == AccessLevel::Read => {
            let (action, label, who) = who_can_help("ask_owner", level, schema);
            step(
                "blocked",
                action,
                label,
                format!(
                    "This statement {} and needs approval, and your read access does not let you ask for it. {who}",
                    effect(analysis)
                ),
                Some("insufficient_access"),
            )
        }
        Verdict::RequiresApproval => step(
            "needs_approval",
            "request_approval",
            "Request approval",
            format!(
                "This statement {}, so another person must approve it before it runs.",
                effect(analysis)
            ),
            Some("approval_required"),
        ),
        Verdict::Deny => {
            let blocking = analysis
                .issues
                .iter()
                .filter(|issue| issue.severity == Severity::Block)
                .map(|issue| (issue.code.as_str(), issue.message.as_str()));
            let Some((code, message)) = deciding(blocking) else {
                return step(
                    "blocked",
                    "edit_sql",
                    "Edit the SQL",
                    "The guard refused this statement. Change it, and the check runs again."
                        .to_owned(),
                    Some("query_denied"),
                );
            };
            let lesson = lesson(code);
            let action = lesson
                .as_ref()
                .map_or("rewrite_sql", |lesson| lesson.action);
            let words = lesson.as_ref().map_or(message, |lesson| lesson.person);
            if action != "rewrite_sql" {
                let (action, label, who) = who_can_help(action, level, schema);
                return step(
                    "blocked",
                    action,
                    label,
                    format!("{words} {who}"),
                    Some(code),
                );
            }
            // A fix from the guard resolves the block in one step. Only a
            // suggestion that carries the code of the block is such a fix:
            // advice about speed never is.
            let fix = analysis
                .suggestions
                .iter()
                .filter(|suggestion| suggestion.code == code)
                .find_map(|suggestion| Some((suggestion, suggestion.fix.as_ref()?)));
            match fix {
                Some((suggestion, fix)) => Preflight {
                    fix: Some(fix.clone()),
                    ..step(
                        "blocked",
                        "apply_fix",
                        &fix.label,
                        suggestion.message.clone(),
                        Some(code),
                    )
                },
                None => step(
                    "blocked",
                    "edit_sql",
                    "Edit the SQL",
                    words.to_owned(),
                    Some(code),
                ),
            }
        }
    }
}

/// Whether the analysis in an error's details has statements and all of them
/// only read. Such a statement needs approval only because it locks rows.
fn reads_only(details: &Value) -> bool {
    details
        .get("statements")
        .and_then(Value::as_array)
        .is_some_and(|statements| {
            !statements.is_empty()
                && statements.iter().all(|statement| {
                    matches!(
                        statement.get("kind").and_then(Value::as_str),
                        Some("select" | "explain" | "show")
                    )
                })
        })
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
        ("approval_required", _) if reads_only(&error.details) => {
            Fix::new("rewrite_sql", LOCKING_READ_AGENT)
        }
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
        ("result_expired", _) => Fix::new(
            "rewrite_sql",
            "These rows are not held any more. Call run_query again, with a narrower question: add filters, select fewer columns or aggregate, so that the answer needs fewer pages.",
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
    #![allow(clippy::unwrap_used)]
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
            ("result_expired", "rewrite_sql"),
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

    /// Every issue code the guard and the masking check can give.
    const ISSUE_CODES: [&str; 27] = [
        "parse_error",
        "empty_query",
        "multiple_statements",
        "statement_not_allowed",
        "unsupported_syntax",
        "select_into",
        "locking_read",
        "optimizer_hint",
        "executable_comment",
        "dangerous_function",
        "stateful_function",
        "unbounded_generator",
        "sensitive_catalog",
        "masked_data_serialization",
        "masked_data_transformation",
        "query_too_large",
        "explain_analyze_write",
        "explain_analyze_executes",
        "data_modifying_cte",
        "write_without_where",
        "tautological_where",
        "unbounded_insert_select",
        "blocked_table",
        "insufficient_access",
        "writes_disabled",
        "ddl_disabled",
        "file_write",
    ];
    const AGENT_ACTIONS: [&str; 7] = [
        "rewrite_sql",
        "fix_arguments",
        "choose_database",
        "ask_owner",
        "propose_write",
        "retry_later",
        "stop",
    ];
    /// Words that only make sense to an agent. A person has no tools to call
    /// and no owner to ask.
    const AGENT_WORDS: [&str; 9] = [
        "check_sql",
        "run_query",
        "propose_write",
        "search_schema",
        "describe_table",
        "list_databases",
        "your owner",
        "per call",
        "Call ",
    ];

    fn denied(issues: &[(&str, &str)]) -> vda_guard::Analysis {
        let mut analysis = vda_guard::analyze(
            "SELEC",
            vda_guard::Dialect::Postgres,
            vda_guard::AccessLevel::Read,
            &guard_policy(),
        );
        analysis.issues = issues
            .iter()
            .map(|(code, message)| vda_guard::Issue {
                severity: vda_guard::Severity::Block,
                code: (*code).to_owned(),
                message: (*message).to_owned(),
            })
            .collect();
        analysis
    }
    fn guard_policy() -> vda_guard::GuardPolicy {
        vda_guard::GuardPolicy {
            max_rows: 1000,
            allow_writes: true,
            require_approval_for_writes: true,
            allow_ddl: false,
            blocked_tables: vec!["vault".into()],
        }
    }
    fn asker(level: vda_guard::AccessLevel) -> Asker {
        Asker {
            level,
            max_rows: 1000,
            cost_limit: false,
        }
    }
    fn check(sql: &str, level: vda_guard::AccessLevel) -> Preflight {
        let analysis =
            vda_guard::analyze(sql, vda_guard::Dialect::Postgres, level, &guard_policy());
        preflight(&analysis, asker(level))
    }

    #[test]
    fn every_issue_code_has_one_next_step_for_an_agent_and_for_a_person() {
        use vda_guard::AccessLevel::{Admin, Read, Write};
        for code in ISSUE_CODES {
            let fix = for_issue(code, "The guard's own words.");
            assert!(AGENT_ACTIONS.contains(&fix.action), "{code}");
            assert!(!fix.hint.is_empty(), "{code}");
            assert!(!told(fix.action).is_empty());
            for level in [Read, Write, Admin] {
                let shown = preflight(&denied(&[(code, "The guard's own words.")]), asker(level));
                assert_eq!(shown.state, "blocked", "{code}");
                assert_eq!(shown.code.as_deref(), Some(code));
                // The person's step follows from the agent's: a repair is an
                // edit, and a stop or a question goes to an administrator.
                let expected: &[&str] = match fix.action {
                    "rewrite_sql" => &["edit_sql"],
                    "stop" if level == Admin => &["change_policy"],
                    _ => &["ask_admin"],
                };
                assert!(
                    expected.contains(&shown.action),
                    "{code} {level:?} {shown:?}"
                );
                assert!(!shown.label.is_empty() && !shown.hint.is_empty(), "{code}");
                assert!(shown.fix.is_none(), "{code}");
                for word in AGENT_WORDS {
                    assert!(
                        !shown.hint.contains(word),
                        "{code}: {:?} has {word:?}",
                        shown.hint
                    );
                }
            }
        }
        // Each action word of a fix is said in plain words for a person.
        let said: std::collections::HashSet<_> = AGENT_ACTIONS.iter().map(|a| told(a)).collect();
        assert_eq!(said.len(), AGENT_ACTIONS.len());
        assert!(!said.contains(told("something_new")));
        // An unknown code still gives the guard's own words to both readers.
        assert_eq!(
            preflight(
                &denied(&[("brand_new_rule", "Do it differently.")]),
                asker(Read)
            )
            .hint,
            "Do it differently."
        );
        // A held result that is gone sends the agent back to run_query.
        let gone = for_error(&ApiError::new(StatusCode::GONE, "result_expired", "x"));
        assert_eq!(gone.action, "rewrite_sql");
        assert!(gone.hint.contains("run_query") && gone.hint.contains("narrower"));
    }

    #[test]
    fn the_preflight_names_the_state_the_reason_and_one_step() {
        use vda_guard::AccessLevel::{Admin, Read, Write};
        // Safe: run, and the guard's change is said exactly.
        let safe = check("SELECT id FROM users", Read);
        assert_eq!(
            (safe.state, safe.action, safe.label.as_str()),
            ("safe", "run", "Run")
        );
        assert_eq!(safe.code, None);
        let change = safe.guard_change.unwrap();
        assert_eq!(
            (change.clause.as_str(), change.replaces),
            ("LIMIT 1001", None)
        );
        assert_eq!(
            change.text,
            "The guard adds LIMIT 1001: the policy allows 1000 rows, and one more row shows whether there are more."
        );
        let lowered = check("SELECT id FROM users LIMIT 5000", Read)
            .guard_change
            .unwrap();
        assert!(
            lowered
                .text
                .starts_with("The guard lowers LIMIT 5000 to LIMIT 1001:"),
            "{lowered:?}"
        );
        assert_eq!(
            check("SELECT id FROM users LIMIT 5", Read).guard_change,
            None
        );
        // Needs approval: a person with write access asks for it.
        let write = "UPDATE users SET name = 'a' WHERE id = 1";
        for level in [Write, Admin] {
            let shown = check(write, level);
            assert_eq!(
                (shown.state, shown.action, shown.label.as_str()),
                ("needs_approval", "request_approval", "Request approval")
            );
            assert_eq!(shown.code.as_deref(), Some("approval_required"));
            assert!(shown.hint.contains("changes data"), "{}", shown.hint);
        }
        // A person with read access cannot ask: the answer says who can.
        let reader = check(write, Read);
        assert_eq!((reader.state, reader.action), ("blocked", "ask_admin"));
        assert_eq!(reader.code.as_deref(), Some("insufficient_access"));
        assert!(
            reader.hint.contains("A person with write access can ask"),
            "{}",
            reader.hint
        );
        // The same holds if the guard ever lets a reader's write through to approval.
        let mut passed =
            vda_guard::analyze(write, vda_guard::Dialect::Postgres, Write, &guard_policy());
        assert_eq!(passed.verdict, vda_guard::Verdict::RequiresApproval);
        passed.row_cap = None;
        let reader = preflight(&passed, asker(Read));
        assert_eq!((reader.state, reader.action), ("blocked", "ask_admin"));
        assert!(
            reader.hint.contains("A person with write access can ask"),
            "{}",
            reader.hint
        );
        // A schema change needs an administrator, also for a writer.
        let ddl = check("CREATE TABLE t(id int)", Write);
        assert_eq!((ddl.state, ddl.action), ("blocked", "ask_admin"));
        assert!(ddl.hint.contains("administrator"), "{}", ddl.hint);
        // Blocked by policy: only an administrator can help, and an
        // administrator is told that it is their call.
        let blocked = check("SELECT * FROM vault", Read);
        assert_eq!((blocked.state, blocked.action), ("blocked", "ask_admin"));
        assert_eq!(blocked.code.as_deref(), Some("blocked_table"));
        assert!(
            blocked.hint.contains("Only an administrator"),
            "{}",
            blocked.hint
        );
        let admin = check("SELECT * FROM vault", Admin);
        assert_eq!(
            (admin.action, admin.label.as_str()),
            ("change_policy", "Change the policy")
        );
        // Blocked with a repair by hand.
        let edit = check("SELECT pg_sleep(1)", Read);
        assert_eq!(
            (edit.state, edit.action, edit.label.as_str()),
            ("blocked", "edit_sql", "Edit the SQL")
        );
        assert_eq!(edit.fix, None);
        // Blocked with a fix from the guard: one step applies it.
        let fixable = check("SELECT id FROM users WHERE id = 1; SELECT 2", Read);
        assert_eq!((fixable.state, fixable.action), ("blocked", "apply_fix"));
        assert_eq!(fixable.label, "Keep the first statement");
        assert_eq!(fixable.code.as_deref(), Some("multiple_statements"));
        let fix = fixable.fix.unwrap();
        assert_eq!(check(&fix.sql, Read).state, "safe");
        // A write that this database runs without approval is safe, and says so.
        let mut open = guard_policy();
        open.require_approval_for_writes = false;
        let analysis = vda_guard::analyze(write, vda_guard::Dialect::Postgres, Write, &open);
        let shown = preflight(&analysis, asker(Write));
        assert_eq!((shown.state, shown.action), ("safe", "run"));
        assert!(shown.hint.contains("without approval"), "{}", shown.hint);
        // The wire shape leaves out what is absent.
        assert_eq!(
            json!(check("SELECT id FROM users LIMIT 5", Read)),
            json!({"state":"safe","action":"run","label":"Run","hint":"This statement only reads data."})
        );
    }

    #[test]
    fn a_read_that_locks_rows_is_sent_to_an_edit_and_never_to_an_approval() {
        use vda_guard::AccessLevel::{Admin, Read, Write};
        let sql = "SELECT id FROM users WHERE id = 1 FOR UPDATE";
        // The guard asks for approval when a writer locks rows, and an
        // approval request for a read is refused. The person is told to
        // take the clause out, at every level.
        for level in [Write, Admin] {
            let analysis =
                vda_guard::analyze(sql, vda_guard::Dialect::Postgres, level, &guard_policy());
            assert_eq!(analysis.verdict, vda_guard::Verdict::RequiresApproval);
            let shown = preflight(&analysis, asker(level));
            assert_eq!(
                (shown.state, shown.action, shown.label.as_str()),
                ("blocked", "edit_sql", "Edit the SQL")
            );
            assert_eq!(shown.code.as_deref(), Some("locking_read"));
            assert_eq!(
                shown.hint,
                "This statement locks rows. Remove the locking clause (FOR UPDATE / FOR SHARE) to run it as a read."
            );
            assert_eq!(shown.fix, None);
            // The agent's fix for the same refusal is an edit too, not a
            // proposal that propose_write would refuse.
            let refused =
                ApiError::new(StatusCode::CONFLICT, "approval_required", "x").details(&analysis);
            let fix = for_error(&refused);
            assert_eq!(fix.action, "rewrite_sql");
            assert!(fix.hint.contains("FOR UPDATE") && !fix.hint.contains("Call propose_write"));
        }
        let reader = check(sql, Read);
        assert_eq!((reader.state, reader.action), ("blocked", "edit_sql"));
        assert_eq!(reader.code.as_deref(), Some("locking_read"));
        assert!(reader.hint.starts_with("This statement locks rows."));
        // A write that needs approval still sends the agent to propose_write,
        // with or without the analysis in the details.
        let write = vda_guard::analyze(
            "UPDATE users SET name = 'a' WHERE id = 1",
            vda_guard::Dialect::Postgres,
            Write,
            &guard_policy(),
        );
        let refused = ApiError::new(StatusCode::CONFLICT, "approval_required", "x");
        assert_eq!(for_error(&refused).action, "propose_write");
        assert_eq!(for_error(&refused.details(&write)).action, "propose_write");
    }

    #[test]
    fn only_a_fix_for_the_block_is_offered_and_advice_about_speed_never_is() {
        use vda_guard::AccessLevel::Read;
        // A statement that masking refuses: the guard alone allows it and
        // advises a LIMIT. After the masking check it is denied and carries
        // no advice, so the bar has nothing to apply.
        let sql = "SELECT md5(email) FROM users";
        let mut analysis =
            vda_guard::analyze(sql, vda_guard::Dialect::Postgres, Read, &guard_policy());
        assert!(analysis
            .suggestions
            .iter()
            .any(|suggestion| suggestion.code == "add_limit" && suggestion.fix.is_some()));
        assert!(analysis.row_cap.is_some());
        crate::masking::harden_analysis(
            &mut analysis,
            &["email".to_owned()],
            sql,
            vda_guard::Dialect::Postgres,
        );
        assert_eq!(analysis.verdict, vda_guard::Verdict::Deny);
        assert!(
            analysis.suggestions.is_empty(),
            "{:?}",
            analysis.suggestions
        );
        assert_eq!(analysis.row_cap, None);
        let shown = preflight(&analysis, asker(Read));
        assert_eq!((shown.state, shown.action), ("blocked", "edit_sql"));
        assert_eq!(shown.code.as_deref(), Some("masked_data_transformation"));
        assert_eq!((shown.fix, shown.guard_change), (None, None));
        // Even if a denied analysis held advice with a fix, it is not used:
        // only a suggestion with the code of the block is a fix for it.
        let mut stray = denied(&[("dangerous_function", "x")]);
        stray.suggestions = vec![vda_guard::Suggestion {
            code: "add_limit".into(),
            message: "advice".into(),
            fix: Some(vda_guard::Fix {
                label: "Add LIMIT 100".into(),
                sql: "SELECT 1 LIMIT 100".into(),
                action: vda_guard::FixAction::Replace,
            }),
        }];
        let shown = preflight(&stray, asker(Read));
        assert_eq!((shown.action, shown.fix), ("edit_sql", None));
    }

    #[test]
    fn the_safe_sentence_names_the_cost_check_and_the_change_says_what_is_true() {
        use vda_guard::AccessLevel::Read;
        let analysis = vda_guard::analyze(
            "SELECT id FROM users",
            vda_guard::Dialect::Postgres,
            Read,
            &guard_policy(),
        );
        let costed = preflight(
            &analysis,
            Asker {
                cost_limit: true,
                ..asker(Read)
            },
        );
        assert_eq!((costed.state, costed.action), ("safe", "run"));
        assert_eq!(
            costed.hint,
            "This statement only reads data. Its cost is checked against this database's limit when it runs."
        );
        assert_eq!(
            preflight(&analysis, asker(Read)).hint,
            "This statement only reads data."
        );
        // "Lowers" only for two plain numbers where the new one is smaller.
        let text = |sql: &str, dialect| {
            let analysis = vda_guard::analyze(sql, dialect, Read, &guard_policy());
            preflight(&analysis, asker(Read)).guard_change.unwrap().text
        };
        let pg = vda_guard::Dialect::Postgres;
        assert!(text("SELECT id FROM users LIMIT 5000", pg)
            .starts_with("The guard lowers LIMIT 5000 to LIMIT 1001:"));
        assert!(text(
            "SELECT id FROM users LIMIT 10, 5000",
            vda_guard::Dialect::MySql
        )
        .starts_with("The guard replaces LIMIT 10, 5000 with LIMIT 10, 1001:"));
        let fetch = text("SELECT id FROM users FETCH FIRST 50 PERCENT ROWS ONLY", pg);
        assert!(
            fetch.starts_with("The guard replaces ") && !fetch.contains("lowers"),
            "{fetch}"
        );
        let all = text("SELECT id FROM users LIMIT ALL", pg);
        assert!(!all.contains("lowers"), "{all}");
    }
}
