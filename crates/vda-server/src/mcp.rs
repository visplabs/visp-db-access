//! The agent door: a Model Context Protocol endpoint over plain HTTP POST.
//!
//! Each request is one JSON-RPC message and each answer is one JSON object, so
//! the endpoint keeps no session and works behind any load balancer. A tool
//! never does more than `vda-core` allows the agent's `Actor`.
use crate::{app::AppState, error::ApiError, network::ClientIp};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use uuid::Uuid;
use vda_core::{agents::AgentIdentity, query::QueryInput, records::ClusterRecord};
use vda_guard::AccessLevel;

/// Protocol revisions this endpoint speaks, newest first.
const VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// Refused queries in a row before the agent is told to stop.
const DENIAL_LIMIT: u32 = 5;
/// How long the stop lasts; also the window in which refusals are counted.
pub(crate) const DENIAL_WINDOW_SECONDS: u64 = 600;
const DEFAULT_ROWS: usize = 100;
const MAX_ROWS: usize = 1000;
/// Rows of one result, as JSON text, never exceed this. The result is sent
/// twice (text and structured), so the answer stays near two megabytes.
const MAX_RESULT_BYTES: usize = 1024 * 1024;
/// Tool calls per agent per minute, all tools together. It keeps one agent
/// from flooding the gateway and from burying its own audit trail.
const CALLS_PER_MINUTE: u32 = 120;

const INSTRUCTIONS: &str = "This server gives guarded access to production databases. \
Call list_databases first. Use search_schema and describe_table to learn the structure. \
Call check_sql before run_query when you are not sure a statement is accepted. \
Every call needs a `task`: one sentence that says what you are doing and why. \
You can read data; you cannot change it on your own. \
When a call is refused, read `error.fix` and do what it says. Do not retry a refused statement unchanged.";

fn rpc_result(id: &Value, result: Value) -> Response {
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}
fn rpc_error(status: StatusCode, id: &Value, code: i32, message: &str) -> Response {
    (
        status,
        Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})),
    )
        .into_response()
}

/// Handle one JSON-RPC message from an authenticated agent.
pub(crate) async fn handle(
    State(state): State<AppState>,
    Extension(identity): Extension<AgentIdentity>,
    Extension(ip): Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // A browser sends Origin; an agent does not. Refusing it stops a web page
    // from driving this endpoint through a person's network position.
    if headers.contains_key(header::ORIGIN) {
        return ApiError::forbidden().into_response();
    }
    if let Some(version) = headers.get("mcp-protocol-version") {
        if !version.to_str().is_ok_and(|v| VERSIONS.contains(&v)) {
            return ApiError::validation("Unsupported MCP-Protocol-Version").into_response();
        }
    }
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return rpc_error(StatusCode::BAD_REQUEST, &Value::Null, -32700, "Parse error");
    };
    let invalid = |why: &str| rpc_error(StatusCode::BAD_REQUEST, &Value::Null, -32600, why);
    if crate::sanitation::json(&message).is_err() {
        return invalid("Text contains prohibited control characters");
    }
    let Some(object) = message.as_object() else {
        return invalid("Send one JSON-RPC message per request; batches are not accepted");
    };
    let method = object.get("method").and_then(Value::as_str);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid("jsonrpc must be \"2.0\"");
    }
    let id = match object.get("id") {
        // A notification, or a response to a request this server never sends.
        None => return StatusCode::ACCEPTED.into_response(),
        // An integer that fits is echoed exactly; a float or a huge number would not be.
        Some(id) if id.is_string() || id.is_i64() || id.is_u64() => id.clone(),
        Some(_) => return invalid("id must be a string or an integer"),
    };
    let Some(method) = method else {
        return invalid("method is required");
    };
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str);
            let version = asked
                .filter(|v| VERSIONS.contains(v))
                .unwrap_or(VERSIONS[0]);
            rpc_result(
                &id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "visp-db-access", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": INSTRUCTIONS,
                }),
            )
        }
        "ping" => rpc_result(&id, json!({})),
        "tools/list" => rpc_result(&id, json!({"tools": tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str);
            let Some(name) = name.filter(|name| TOOL_NAMES.contains(name)) else {
                return rpc_error(StatusCode::OK, &id, -32602, "Unknown tool");
            };
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let outcome = call(&state, &identity, ip.0, name, arguments).await;
            rpc_result(&id, tool_result(outcome))
        }
        _ => rpc_error(StatusCode::OK, &id, -32601, "Method not found"),
    }
}

/// Shape a tool outcome. A refusal is a normal result with `isError`, so the
/// model reads it and can act on `fix`; it is not a protocol failure.
fn tool_result(outcome: Result<Value, ApiError>) -> Value {
    let (payload, failed) = match outcome {
        Ok(value) => (value, false),
        Err(error) => {
            // A failure inside the gateway is not the agent's to diagnose, and
            // its text can name internals. The code and the fix are enough.
            let message = if error.status.is_server_error() && error.code != "upstream" {
                "The gateway could not complete this call".to_owned()
            } else {
                error.message.clone()
            };
            (
                json!({"error": {
                    "code": error.code,
                    "message": message,
                    "fix": vda_core::teach::for_error(&error),
                }}),
                true,
            )
        }
    };
    json!({
        "content": [{"type": "text", "text": payload.to_string()}],
        "structuredContent": payload,
        "isError": failed,
    })
}

const TOOL_NAMES: [&str; 8] = [
    "list_databases",
    "search_schema",
    "describe_table",
    "check_sql",
    "run_query",
    "propose_write",
    "get_approval",
    "withdraw",
];

fn tools() -> Value {
    let task = json!({"type":"string","minLength":1,"maxLength":500,
        "description":"One sentence: what you are doing and why. It is kept in the audit record."});
    let database = json!({"type":"string","format":"uuid",
        "description":"A database id from list_databases."});
    let approval_id = json!({"type":"string","format":"uuid",
        "description":"The approval_id that propose_write gave."});
    let tool = |name: &str, description: &str, properties: Value, required: &[&str]| {
        json!({
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": false,
            },
        })
    };
    json!([
        tool(
            "list_databases",
            "List the databases you can reach right now, with your access level on each.",
            json!({"task": task}),
            &["task"],
        ),
        tool(
            "search_schema",
            "Find tables and columns whose name contains a word.",
            json!({"task": task, "database": database,
                "query": {"type":"string","minLength":1,"maxLength":100,
                    "description":"Part of a table or column name."},
                "limit": {"type":"integer","minimum":1,"maximum":50,"default":20}}),
            &["task", "database", "query"],
        ),
        tool(
            "describe_table",
            "Show the columns of one table: name, type, nullable, primary key, and whether the value is protected.",
            json!({"task": task, "database": database,
                "table": {"type":"string","minLength":1,"maxLength":200,
                    "description":"A table name, as `schema.table` or `table`."}}),
            &["task", "database", "table"],
        ),
        tool(
            "check_sql",
            "Ask the guard what it would do with a statement, without running it.",
            json!({"task": task, "database": database,
                "sql": {"type":"string","minLength":1,"description":"One SQL statement."}}),
            &["task", "database", "sql"],
        ),
        tool(
            "run_query",
            "Run one guarded read-only statement and return its rows. Protected values come back masked.",
            json!({"task": task, "database": database,
                "sql": {"type":"string","minLength":1,"description":"One SQL statement."},
                "max_rows": {"type":"integer","minimum":1,"maximum":MAX_ROWS,"default":DEFAULT_ROWS}}),
            &["task", "database", "sql"],
        ),
        tool(
            "propose_write",
            "Ask for a write (one INSERT, UPDATE or DELETE, without RETURNING). Nothing runs now. \
             A person tries it and rolls it back to see its effect, a person who is not your owner approves it, and a person runs it. \
             It runs only if it still changes the same rows. Your `task` is the reason the approver reads. \
             Call get_approval later to see the outcome.",
            json!({"task": task, "database": database,
                "sql": {"type":"string","minLength":1,"description":"One INSERT, UPDATE or DELETE statement."}}),
            &["task", "database", "sql"],
        ),
        tool(
            "get_approval",
            "Read the state of a write you asked for: pending, approved, rejected, executed, failed, expired or withdrawn.",
            json!({"task": task, "approval_id": approval_id}),
            &["task", "approval_id"],
        ),
        tool(
            "withdraw",
            "Withdraw a write you asked for, if it has not run.",
            json!({"task": task, "approval_id": approval_id}),
            &["task", "approval_id"],
        ),
    ])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    task: String,
    database: Option<Uuid>,
    query: Option<String>,
    limit: Option<usize>,
    table: Option<String>,
    sql: Option<String>,
    max_rows: Option<usize>,
    approval_id: Option<Uuid>,
}
/// The argument names each tool takes, as its input schema says.
fn accepted(tool: &str) -> &'static [&'static str] {
    match tool {
        "search_schema" => &["task", "database", "query", "limit"],
        "describe_table" => &["task", "database", "table"],
        "check_sql" => &["task", "database", "sql"],
        "run_query" => &["task", "database", "sql", "max_rows"],
        "propose_write" => &["task", "database", "sql"],
        "get_approval" | "withdraw" => &["task", "approval_id"],
        _ => &["task"],
    }
}
fn required<T>(value: Option<T>, name: &str) -> Result<T, ApiError> {
    value.ok_or_else(|| ApiError::validation(format!("`{name}` is required for this tool")))
}

/// Run one tool for an agent, then record that it was called and why.
async fn call(
    state: &AppState,
    identity: &AgentIdentity,
    ip: std::net::IpAddr,
    tool: &str,
    arguments: Value,
) -> Result<Value, ApiError> {
    let calls = state
        .agent_calls
        .get_with(identity.agent_id, async { Default::default() })
        .await
        .fetch_add(1, Ordering::Relaxed);
    if calls >= CALLS_PER_MINUTE {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many tool calls in one minute",
        )
        .details(json!({"retry_after_seconds": 60})));
    }
    let unknown = arguments.as_object().and_then(|given| {
        given
            .keys()
            .find(|name| !accepted(tool).contains(&name.as_str()))
    });
    if let Some(name) = unknown {
        return Err(ApiError::validation(format!(
            "`{name}` is not an argument of this tool"
        )));
    }
    let arguments: Arguments = serde_json::from_value(arguments)
        .map_err(|_| ApiError::validation("Arguments do not match the tool's input schema"))?;
    vda_core::query::validate_task(&arguments.task)?;
    let database = arguments.database;
    let task = arguments.task.trim().to_owned();
    let outcome = run_tool(state, identity, ip, tool, arguments).await;
    // Queries are in query history with their task. This event covers every
    // tool, so a person can read an agent's whole trail in one place.
    let event = crate::audit::Event {
        id: Uuid::new_v4(),
        actor_id: Some(identity.actor.user_id),
        action: "agent.tool".into(),
        target_type: Some("agent".into()),
        target_id: Some(identity.agent_id),
        ip: Some(ip),
        details: json!({
            "tool": tool,
            "task": task,
            "database": database,
            "outcome": outcome.as_ref().err().map_or("ok", |error| error.code),
        }),
        created_at: chrono::Utc::now(),
    };
    // Wait for room in the queue, as the session API does for its events. The
    // call rate above keeps one agent from filling it.
    let queued = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        state.audit_sender.send(event),
    )
    .await;
    if !matches!(queued, Ok(Ok(()))) {
        metrics::counter!("vda_agent_tool_events_dropped_total").increment(1);
        tracing::error!(agent_id = %identity.agent_id, tool, "agent tool event dropped: audit queue full");
    }
    outcome
}

async fn run_tool(
    state: &AppState,
    identity: &AgentIdentity,
    ip: std::net::IpAddr,
    tool: &str,
    arguments: Arguments,
) -> Result<Value, ApiError> {
    let actor = &identity.actor;
    match tool {
        "list_databases" => {
            return Ok(json!({"databases": crate::agents::reachable_now(state, actor, ip).await?}));
        }
        "get_approval" => {
            let id = required(arguments.approval_id, "approval_id")?;
            return crate::approvals::status_for_agent(state, identity, id).await;
        }
        "withdraw" => {
            let id = required(arguments.approval_id, "approval_id")?;
            return crate::approvals::withdraw_for_agent(state, identity, id, ip).await;
        }
        _ => {}
    }
    let database = required(arguments.database, "database")?;
    match tool {
        "search_schema" => {
            let query = required(arguments.query, "query")?.trim().to_lowercase();
            if query.is_empty() || query.chars().count() > 100 {
                return Err(ApiError::validation(
                    "`query` must contain 1..=100 characters",
                ));
            }
            let limit = arguments.limit.unwrap_or(20).clamp(1, 50);
            let (cluster, policy) = visible(state, identity, database, ip).await?;
            let schema = crate::clusters::load_schema(state, &cluster, &policy, false).await?;
            let mut matches = Vec::new();
            let mut more = false;
            for (qualified, table) in tables(&schema, &policy.blocked_tables) {
                let columns: Vec<&str> = table
                    .columns
                    .iter()
                    .map(|c| c.name.as_str())
                    .filter(|name| name.to_lowercase().contains(&query))
                    .collect();
                if !qualified.to_lowercase().contains(&query) && columns.is_empty() {
                    continue;
                }
                if matches.len() == limit {
                    more = true;
                    break;
                }
                matches.push(json!({"table": qualified, "kind": table.kind,
                    "row_estimate": table.row_estimate, "matching_columns": columns}));
            }
            Ok(json!({"tables": matches, "more": more}))
        }
        "describe_table" => {
            let wanted = required(arguments.table, "table")?.trim().to_lowercase();
            let (cluster, policy) = visible(state, identity, database, ip).await?;
            let schema = crate::clusters::load_schema(state, &cluster, &policy, false).await?;
            let mut found = tables(&schema, &policy.blocked_tables).filter(|(qualified, table)| {
                qualified.to_lowercase() == wanted || table.name.to_lowercase() == wanted
            });
            let Some((qualified, table)) = found.next() else {
                // A blocked table and a missing table look the same.
                return Err(ApiError::new(
                    StatusCode::NOT_FOUND,
                    "table_not_found",
                    "No such table",
                ));
            };
            if found.next().is_some() {
                return Err(ApiError::validation(
                    "More than one schema has a table with this name; use `schema.table`",
                ));
            }
            let scope = [qualified.to_lowercase()];
            let columns: Vec<Value> = table
                .columns
                .iter()
                .map(|column| {
                    let protected = policy.masked_columns.iter().any(|pattern| {
                        crate::masking::matches_column(pattern, &column.name, &scope)
                    });
                    json!({"name": column.name, "type": column.data_type,
                        "nullable": column.nullable, "primary_key": column.is_primary_key,
                        "protected": protected})
                })
                .collect();
            Ok(json!({"table": qualified, "kind": table.kind,
                "row_estimate": table.row_estimate, "columns": columns}))
        }
        "check_sql" => {
            let sql = required(arguments.sql, "sql")?;
            visible(state, identity, database, ip).await?;
            let analysis = vda_core::query::analyze(&state.core, actor, database, &sql, ip).await?;
            let blocking = analysis
                .issues
                .iter()
                .filter(|issue| issue.severity == vda_guard::Severity::Block)
                .map(|issue| (issue.code.as_str(), issue.message.as_str()));
            // The same fix that run_query would give for this statement.
            let fix = match analysis.verdict {
                vda_guard::Verdict::Allow => None,
                vda_guard::Verdict::Deny => vda_core::teach::strongest(blocking),
                vda_guard::Verdict::RequiresApproval => Some(vda_core::teach::for_error(
                    &ApiError::new(StatusCode::CONFLICT, "approval_required", ""),
                )),
            };
            Ok(json!({"verdict": analysis.verdict, "risk": analysis.risk,
                "issues": analysis.issues, "will_run_as": analysis.rewritten_sql,
                "suggestions": analysis.suggestions, "fix": fix}))
        }
        "run_query" => {
            let sql = required(arguments.sql, "sql")?;
            let rows = arguments
                .max_rows
                .unwrap_or(DEFAULT_ROWS)
                .clamp(1, MAX_ROWS);
            let input = |sql: String| QueryInput {
                sql,
                query_id: None,
                task: Some(arguments.task.clone()),
            };
            let counted = |code: &str| {
                matches!(
                    code,
                    "query_denied"
                        | "approval_required"
                        | "forbidden"
                        | "not_found"
                        | "cost_exceeded"
                )
            };
            // The streak of refusals is kept under a lock per agent. The guard's
            // decision needs no database I/O, so it is taken while the lock is
            // held: parallel calls then cannot all slip past a count that none
            // of them has added to yet. A statement that the guard accepts
            // runs after the lock is released, so good queries run in parallel.
            let streak = state
                .agent_denials
                .get_with(identity.agent_id, async { Default::default() })
                .await;
            let mut refused = streak.lock().await;
            if *refused >= DENIAL_LIMIT {
                return Err(ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too_many_denials",
                    "Too many refused queries in a row",
                )
                .details(json!({"retry_after_seconds": DENIAL_WINDOW_SECONDS})));
            }
            // A database that the agent cannot reach is a refusal too.
            if let Err(error) = visible(state, identity, database, ip).await {
                if counted(error.code) {
                    *refused += 1;
                }
                return Err(error);
            }
            let accepted = vda_core::query::analyze(&state.core, actor, database, &sql, ip)
                .await
                .is_ok_and(|analysis| analysis.verdict == vda_guard::Verdict::Allow);
            let result = if accepted {
                drop(refused);
                let result =
                    vda_core::query::run(&state.core, actor, database, input(sql), ip, false).await;
                if let Err(error) = &result {
                    if counted(error.code) {
                        *streak.lock().await += 1;
                    }
                }
                result
            } else {
                // The pipeline records the refused attempt; it does no target I/O.
                let result =
                    vda_core::query::run(&state.core, actor, database, input(sql), ip, false).await;
                if result.as_ref().is_err_and(|error| counted(error.code)) {
                    *refused += 1;
                }
                drop(refused);
                result
            };
            // A success ends the streak.
            let mut result = result?;
            state.agent_denials.invalidate(&identity.agent_id).await;
            let mut truncated = result.truncated || result.rows.len() > rows;
            result.rows.truncate(rows);
            let mut bytes = 0;
            let fits = result
                .rows
                .iter()
                .take_while(|row| {
                    bytes += serde_json::to_string(row).map_or(usize::MAX, |text| text.len());
                    bytes <= MAX_RESULT_BYTES
                })
                .count();
            if fits < result.rows.len() {
                result.rows.truncate(fits);
                truncated = true;
            }
            if result.rows.is_empty() && fits == 0 && truncated && bytes > MAX_RESULT_BYTES {
                // Not even one row fits. An empty answer would look like no data.
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "result_too_large",
                    "One row of this result is larger than a tool answer can hold",
                ));
            }
            Ok(
                json!({"query_id": result.query_id, "columns": result.columns,
                "rows": result.rows, "row_count": result.rows.len(), "truncated": truncated,
                "ran_as": result.executed_sql, "elapsed_ms": result.elapsed_ms}),
            )
        }
        "propose_write" => {
            let sql = required(arguments.sql, "sql")?;
            // One proposal of an agent at a time, under the same lock and
            // streak as run_query: each one costs a dry run, and a refused or
            // failed one counts toward the loop breaker.
            // Its own streak: a successful read does not reset it.
            let streak = state
                .agent_proposals
                .get_with(identity.agent_id, async { Default::default() })
                .await;
            let mut refused = streak.lock().await;
            if *refused >= DENIAL_LIMIT {
                return Err(ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too_many_denials",
                    "Too many refused or failed write requests in a row",
                )
                .details(json!({"retry_after_seconds": DENIAL_WINDOW_SECONDS})));
            }
            let result = match visible(state, identity, database, ip).await {
                Ok(_) => {
                    crate::approvals::propose_for_agent(
                        state,
                        identity,
                        database,
                        sql,
                        arguments.task,
                        ip,
                    )
                    .await
                }
                Err(error) => Err(error),
            };
            match &result {
                Ok(_) => *refused = 0,
                Err(error)
                    if !matches!(
                        error.code,
                        "rate_limited" | "too_many_open_requests" | "busy" | "internal"
                    ) =>
                {
                    *refused += 1;
                }
                Err(_) => {}
            }
            result
        }
        _ => Err(ApiError::internal()),
    }
}

/// The cluster and policy for a tool, after the same access and network
/// checks that a query gets. A refusal for the network address has its own
/// code, so the agent is not sent back to pick another database in vain.
async fn visible(
    state: &AppState,
    identity: &AgentIdentity,
    database: Uuid,
    ip: std::net::IpAddr,
) -> Result<(ClusterRecord, vda_core::policy::Policy), ApiError> {
    let (cluster, _) = vda_core::access::require_level_effective(
        &state.db,
        &identity.actor,
        database,
        AccessLevel::Read,
    )
    .await?;
    let policy = crate::db::policy(&state.db, cluster.id).await?;
    if !crate::network::allowed(ip, &crate::network::parse_cidrs(&policy.allowed_cidrs)?) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "network_denied",
            "This database does not accept requests from your network address",
        ));
    }
    Ok((cluster, policy))
}

/// Tables that the policy does not block, with their `schema.table` name.
fn tables<'a>(
    schema: &'a vda_connectors::SchemaTree,
    blocked: &'a [String],
) -> impl Iterator<Item = (String, &'a vda_connectors::SchemaTable)> {
    schema.schemas.iter().flat_map(move |group| {
        group.tables.iter().filter_map(move |table| {
            let qualified = format!("{}.{}", group.name, table.name);
            let hidden = blocked
                .iter()
                .any(|pattern| vda_guard::relation_matches(pattern, &qualified.to_lowercase()));
            (!hidden).then_some((qualified, table))
        })
    })
}
