# HTTP API contract (v1)

This file is the contract between `crates/vda-server` and `web/`. Change it
only deliberately and update both sides.

Conventions

- Base path `/api/v1`. JSON bodies, `snake_case` fields. IDs are UUID strings.
  Timestamps are RFC 3339 strings (UTC).
- Auth: HttpOnly cookie `vda_session` set by login. Mutating requests must send
  header `X-Requested-With: vda` (CSRF guard); server rejects otherwise (403).
- Errors: non-2xx with `{"error": {"code": "string", "message": "string", "details": any|null}}`.
  Common codes: `unauthenticated` 401, `forbidden` 403, `not_found` 404,
  `validation` 400, `conflict` 409, `approval_required` 409, `query_denied` 422,
  `cost_exceeded` 422, `rate_limited` 429, `busy` 429, `upstream` 502, `internal` 500.
- Paginated lists (grants, approvals, history, audit): `{"items": [...], "next_cursor": "string|null"}`;
  query `?limit=50&cursor=...`. Cursors are opaque and URL-safe, ordered by creation time
  and ID descending. Other lists return `{items: [...]}`.
- JSON strings and object keys reject NUL and other C0 controls with 400 `validation`
  (`Text contains prohibited control characters`); tab, newline and carriage return are allowed.
- 429 `busy` means the cluster's query slots are occupied; 429 `rate_limited` means
  login/password work is throttled. Wait before retrying; mutations are never automatically retried.

## Shared types

```ts
type OrgRole = "admin" | "member";
type AccessLevel = "read" | "write" | "admin";
type Engine = "postgres" | "mysql";
type Provider = "aws" | "gcp" | "azure" | "onprem" | "other";
type Environment = "production" | "staging" | "development";
type TlsMode = "disable" | "prefer" | "require" | "verify_full";
type HealthStatus = "healthy" | "degraded" | "down" | "unknown";
type Verdict = "allow" | "requires_approval" | "deny";
type Severity = "info" | "warning" | "block";
type Risk = "low" | "medium" | "high" | "critical";
type StatementKind =
  | "select"
  | "explain"
  | "show"
  | "insert"
  | "update"
  | "delete"
  | "merge"
  | "ddl"
  | "dcl"
  | "transaction"
  | "utility"
  | "other";

interface User {
  id: string;
  email: string;
  name: string;
  org_role: OrgRole;
  disabled: boolean;
  created_at: string;
  last_login_at: string | null;
}

interface Project {
  id: string;
  name: string;
  description: string;
  cluster_count: number;
  created_at: string;
}

interface Health {
  status: HealthStatus;
  latency_ms: number | null;
  server_version: string | null;
  is_replica: boolean | null;
  active_connections: number | null;
  max_connections: number | null;
  error: string | null;
  checked_at: string | null;
}

interface Cluster {
  id: string;
  project_id: string;
  name: string;
  engine: Engine;
  provider: Provider;
  region: string;
  environment: Environment;
  host: string;
  port: number;
  database: string;
  username: string;
  tls_mode: TlsMode;
  replica_host: string | null;
  replica_port: number | null;
  tags: Record<string, string>;
  health: Health;
  my_access: AccessLevel | null; // effective level of the caller
  created_at: string;
  updated_at: string;
}
// password is write-only: accepted on create/update, never returned.

interface Policy {
  max_rows: number; // default 1000 (prod) / 5000 (non-prod)
  statement_timeout_ms: number; // default 15000 (prod) / 60000
  lock_timeout_ms: number; // default 2000
  max_cost: number | null; // EXPLAIN total cost gate for reads
  max_concurrent_queries: number; // per node, default 4
  allow_writes: boolean; // default false in production
  require_approval_for_writes: boolean; // default true
  max_affected_rows: number; // default 1000
  allow_ddl: boolean; // default false
  route_reads_to_replica: boolean; // default true
  masked_columns: string[]; // patterns: "email", "users.ssn", "*.password*"
  blocked_tables: string[]; // patterns: "secrets.*", "audit_trail"
  allowed_cidrs: string[]; // empty = only org-level rule applies
}

interface Issue {
  severity: Severity;
  code: string;
  message: string;
}
interface StatementAnalysis {
  kind: StatementKind;
  sql: string;
  tables: string[];
  functions: string[];
  risk: Risk;
  issues: Issue[];
  has_where: boolean;
  has_limit: boolean;
}
interface Analysis {
  verdict: Verdict;
  risk: Risk;
  statements: StatementAnalysis[];
  rewritten_sql: string | null;
  issues: Issue[];
  suggestions: Suggestion[]; // advisory only; never change the verdict; empty when denied
} // issues = flattened, incl. top-level

interface Suggestion {
  code: string; // see the analyze endpoint for the list
  message: string;
  fix?: Fix;
}
interface Fix {
  label: string;
  sql: string; // never executed by the server; the console applies it
  action: "replace" | "new_tab"; // replace the editor text, or open alongside it
}

interface Column {
  name: string;
  type_name: string;
  masked: boolean;
}
interface QueryResult {
  query_id: string;
  columns: Column[];
  rows: unknown[][];
  row_count: number;
  truncated: boolean;
  affected_rows: number | null;
  elapsed_ms: number;
  executed_sql: string;
  routed_to: "primary" | "replica";
  analysis: Analysis;
}

interface HistoryEntry {
  id: string;
  cluster_id: string;
  cluster_name: string;
  user_id: string;
  user_email: string;
  sql: string;
  verdict: Verdict;
  status: "running" | "unknown" | "ok" | "blocked" | "error" | "cancelled";
  row_count: number | null;
  elapsed_ms: number | null;
  error: string | null;
  created_at: string;
  ip: string | null;
  agent_id: string | null; // the agent that ran it for user_id; null for a person's own query
  task: string | null; // what the caller said the query is for
}

interface Approval {
  id: string;
  cluster_id: string;
  cluster_name: string;
  requester: { id: string; email: string; name: string };
  sql: string;
  reason: string;
  analysis: Analysis;
  status:
    | "pending"
    | "approved"
    | "rejected"
    | "executing"
    | "executed"
    | "failed"
    | "expired";
  error: string | null;
  sql_truncated: boolean;
  reviewer: { id: string; email: string; name: string } | null;
  review_note: string | null;
  result: QueryResult | null;
  created_at: string;
  reviewed_at: string | null;
  executed_at: string | null;
  expires_at: string;
}

interface Grant {
  id: string;
  user: { id: string; email: string; name: string };
  scope: "project" | "cluster";
  scope_id: string;
  scope_name: string;
  level: AccessLevel;
  expires_at: string | null;
  created_at: string;
  created_by: string | null;
}

interface AuditEvent {
  id: string;
  actor: { id: string; email: string } | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  details: unknown;
  created_at: string;
}

interface SchemaTree {
  schemas: {
    name: string;
    tables: {
      name: string;
      kind: "table" | "view" | "materialized_view";
      row_estimate: number | null;
      columns: {
        name: string;
        data_type: string;
        nullable: boolean;
        is_primary_key: boolean;
      }[];
    }[];
  }[];
}
```

## Endpoints

### System (no session auth, no `/api/v1` prefix)

- `GET /healthz` → `200 "ok"` — process alive.
- `GET /readyz` → `200` when metadata DB reachable, else `503`.
- `GET /metrics` → Prometheus text with `Authorization: Bearer <VDA_METRICS_TOKEN>`;
  403 if the token is absent, incorrect, or metrics access is not configured.

### Auth

- `POST /auth/login` `{email, password}` → `{user: User}` + cookie. 401 on bad creds (generic message). Rate-limited per IP and per IP+email.
  Ten failed attempts temporarily lock the email for 15 minutes across all source IPs.
  A locked or disabled account returns the same generic 401 as incorrect credentials,
  including for nonexistent accounts; clients must not infer account existence.
- `POST /auth/logout` → `204`.
- `GET /auth/me` → `{user: User}`.
- `POST /auth/change-password` `{current_password, new_password}` → `204`.

### Overview

- `GET /overview` → `{clusters_total, healthy, degraded, down, unknown,
queries_24h, blocked_24h, errors_24h, pending_approvals,
recent_queries: HistoryEntry[] (≤10), unhealthy_clusters: Cluster[]}`
  (scoped to clusters the caller can access).

### Users

- `GET /users` → `{items: User[]}` (org admin)
- `GET /users/lookup?q=` → `{items: {id, email, name}[]}` (org admin, or an unexpired
  admin grant on at least one existing project/cluster). Case-insensitive literal substring
  search in name/email; trimmed query must contain 2–254 Unicode characters (400 `validation`
  otherwise). Disabled users are excluded. At most 20 results, ordered by name, email, ID.
  Password hashes, organization roles, and account state are never included.
- `POST /users` `{email, name, password, org_role}` → `User` (org admin)
- `PATCH /users/:id` `{name?, org_role?, disabled?, password?}` → `User` (org admin)
- `DELETE /users/:id` → `204` (org admin; soft: disables + revokes sessions)

### Projects

- `GET /projects` → `{items: Project[]}` (projects with ≥1 accessible cluster, or all for admin)
- `POST /projects` `{name, description}` → `Project` (admin)
- `PATCH /projects/:id` `{name?, description?}` → `Project` (admin)
- `DELETE /projects/:id` → `204` (admin; 409 if it still has clusters)

### Clusters

- `GET /clusters?project_id=&environment=&engine=&q=` → `{items: Cluster[]}` (only accessible)
- `POST /clusters` `{project_id, name, engine, provider, region, environment, host, port,
database, username, password, tls_mode, replica_host?, replica_port?, tags?}` → `Cluster` (admin).
  Creates default policy for the environment.
- `GET /clusters/:id` → `Cluster`
- `PATCH /clusters/:id` (same fields, all optional; `password` optional) → `Cluster` (admin / cluster admin).
  Changing engine, host, port, database, username, TLS mode, replica host or replica port
  requires explicitly resupplying `password`. Otherwise 400 `validation`:
  `Changing the connection endpoint requires re-entering the password`.
  Moving a cluster to a different project requires organization administration.
- `DELETE /clusters/:id` → `204` (org admin)
- `POST /clusters/test-connection` `{engine, host, port, database, username, password?, tls_mode, cluster_id?}`
  → `Health` (if `password` omitted and `cluster_id` given, use stored password only when all endpoint fields match the stored connection; otherwise
  the same password re-entry validation applies). Org admin only.
- `GET /clusters/:id/health?hours=24` → `{current: Health, history: {status, latency_ms, checked_at}[]}`
- `POST /clusters/:id/health/check` → `Health` (run now; cluster admin)
- `GET /clusters/:id/schema` → `SchemaTree` (read; cached 5 min server-side, `?refresh=true` bypasses)

### Policy & access

- `GET /clusters/:id/policy` → `Policy` (read)
- `PUT /clusters/:id/policy` `Policy` → `Policy` (cluster admin)
- `GET /clusters/:id/grants` → `{items: Grant[]}` (includes project-level grants that apply) (cluster admin)
- `GET /grants?scope=&scope_id=&user_id=&limit=50&cursor=` → `{items: Grant[], next_cursor}`.
  Org admins see all grants, including projects with no clusters and expired grants.
  Project admins see grants on their project and its clusters. Cluster admins see grants
  on their cluster, not grants on the parent project or unrelated scopes. Administrative
  authority must be unexpired; users with no administered scope receive 403. Optional
  filters are exact matches; `scope` is `project` or `cluster`. `limit` must be 1–200.
  Invalid scope/UUID/cursor/limit returns 400 `validation`.
- `POST /grants` `{user_id, scope, scope_id, level, expires_at?}` → `Grant` (org admin, or admin on scope)
- `DELETE /grants/:id` → `204` (org admin, or admin on the grant's scope).
  Scoped admins cannot grant to themselves or delegate access beyond the expiry of
  their own administrative authority.

### Queries

- `POST /clusters/:id/analyze` `{sql}` → `Analysis` (read). Cheap; UI calls it debounced while typing.
  `suggestions` are advisory performance hints: `select_star`, `add_limit`
  (with a sample-`LIMIT` fix), `order_by_random`, `large_offset`,
  `function_on_column`, `leading_wildcard`, `not_in_subquery`, `large_in_list`
  and `preview_write` (a `SELECT COUNT(*)` of the rows an `UPDATE`/`DELETE`
  would touch, opened in a new tab). They never change the verdict or the
  executed SQL.
  `masked_data_serialization` is a blocking issue for whole-row/JSON serialization
  touching masked data; select individual columns so masking can be applied.
  MySQL executable comments (`/*!...*/`, `/*M!...*/`) are always denied with
  `executable_comment`; optimizer hints are blocked with `optimizer_hint` because
  hints can override execution limits. Session assignments and maintenance commands
  are blocked. The connector pins SQL mode to `STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION`
  (backslash escapes enabled, ANSI_QUOTES disabled) and UTC for each execution.
  SELECT rewriting re-escapes literal backslashes; mode-dependent statement boundaries
  are rejected. Rewritten outer SELECT/FETCH limits use `max_rows + 1` when imposing/capping a
  policy limit to detect truncation. Smaller explicit limits are preserved. Display
  `rewritten_sql` verbatim; only `max_rows` rows are returned.
- `POST /clusters/:id/query` `{sql, query_id?, task?}` → `QueryResult`.
  `query_id` (client-generated UUID) lets the client cancel before the response arrives.
  Errors: `query_denied` 422 (`details: Analysis`), `approval_required` 409 (`details: Analysis`),
  `cost_exceeded` 422 (`details: {cost, max_cost}`), `busy` 429, `upstream` 502 (`message` = DB error).
- `POST /queries/:query_id/cancel` → `204` (own queries; admins any).
- `GET /history?cluster_id=&user_id=&status=&limit=&cursor=` → `{items: HistoryEntry[], next_cursor}`.
  Members see only their own; org admins see all. `limit` must be 1–200.
  `running` is durably recorded before target execution. Abandoned executions become
  `unknown` after recovery; this does not imply success or rollback. History `id` is a
  fresh identity for each attempt and is distinct from the cancellation `query_id`.

### Approvals

- `POST /approvals` `{cluster_id, sql, reason}` → `Approval` (write level; re-analyzed server-side; 422 if `deny`)
- `GET /approvals?status=&cluster_id=&mine=true&limit=50&cursor=` → `{items: Approval[], next_cursor: string | null}`.
  Org admins see all, scoped admins see requests on administered clusters, and other
  members see their own requests. Detail/review/execution also check current access.
  Keyset pagination orders by creation time and ID descending; `limit` must be 1–100.
  List items set `result` to null, truncate `sql` to 2,000 characters, and set
  `sql_truncated` to true when truncated. `GET /approvals/:id` returns full SQL
  and result, with `sql_truncated: false`. `executing` claims are never expired;
  abandoned claims become `failed` with an `error` after the statement timeout
  plus five minutes. Failed executions remain consumed and cannot be replayed.
- `GET /approvals/:id` → `Approval`
- `POST /approvals/:id/approve` `{note?}` → `Approval` (cluster admin, ≠ requester)
- `POST /approvals/:id/reject` `{note}` → `Approval`
- `POST /approvals/:id/execute` → `Approval` with `result` (requester or approver; once; approval valid 24h)

### Agents

An agent is a non-human caller that acts for one person, its owner. Its access
is the owner's access at request time, narrowed to `cluster_ids` and capped at
`max_level`. It is never wider. When the owner loses a grant, the agent loses it
on its next request.

Pausing or deleting an agent, revoking a token, and disabling the owner all take
effect at once: new requests get 401, and the queries that the agent is running
on the node that handled the change are cancelled. On other nodes a running query
ends at its statement timeout. Three events also revoke every token of the owner's agents: a disable, a password
change (by an org admin or by the owner at `POST /auth/change-password`), and a
change of organization role. Only a real change counts; sending the same role
again, or a rename, revokes nothing. Enabling the account again does not bring
the tokens back. The audit event carries `agent_tokens_revoked`.

A pause is not a lock: the owner can resume an agent that an org admin paused.
For a stop that the owner cannot undo, delete the agent or disable the owner.

`Agent` is `{id, name, description, max_level: "read"|"write", paused, hourly_query_budget,
owner: {id, email, name}, cluster_ids: uuid[], tokens: AgentToken[], created_at, updated_at}`.
`hourly_query_budget` (1–100000, default 300) is how many queries the agent can start in one
hour. Refused attempts count too. Only the owner can change it.
`AgentToken` is `{id, hint, created_at, expires_at, revoked_at, last_used_at}`; `hint` is the
last four characters of the token. A token digest is never returned.

- `GET /agents?limit=50&cursor=` → `{items: Agent[], next_cursor}`. The caller's own agents;
  an org admin sees every agent.
- `POST /agents` `{name, description?, max_level? = "read", cluster_ids, hourly_query_budget? = 300}` → `Agent`. The caller
  becomes the owner. `name` is trimmed, then must be 1–100 characters with no invisible, blank or
  direction-changing characters (a plain space is fine; joiners and the emoji selector are
  allowed only after a non-ASCII character), and unique per owner without regard to case (409 `conflict`).
  `cluster_ids` holds 1–100 clusters, each one the caller can access now (400 `validation`
  otherwise). At most 50 agents per owner (409).
- `GET /agents/:id` → `Agent` (owner or org admin; 404 for everyone else).
- `PATCH /agents/:id` `{name?, description?, max_level?, cluster_ids?, hourly_query_budget?, paused?}` → `Agent`.
  The owner can change every field. An org admin who is not the owner can change only
  `paused` (403 `forbidden` if any other field is present). A body with no field is 400.
  A body that asks for the state the agent already has returns the agent and writes nothing.
- `DELETE /agents/:id` → `204` (owner or org admin). Deletes its tokens. Query history
  stays, without the link to the agent.
- `POST /agents/:id/tokens` `{expires_in_days? = 30}` → `{id, token, hint, expires_at}` (owner
  only). A JSON body is required; send `{}` for the default. `token` is `vda_agent_` followed
  by 43 characters. It is returned once and cannot be read again. Lifetime is 1–90 days. At
  most 5 active tokens per agent (409).
- `DELETE /agents/:id/tokens/:token_id` → `204` (owner or org admin). Repeating it is harmless.

Agent rules in the query pipeline:

- A write by an agent always needs approval, even when the cluster policy lets people
  write without one. Analysis says so too: its verdict is `requires_approval`.
- An agent has no organization powers, even when its owner is an org admin.
- An agent can cancel only the queries that it started. Its owner can cancel them too.
- Query history has `agent_id` (null for a person's own query); `user_id` and `user_email`
  hold the owner. `query.execute` audit details also carry `agent_id`.

### Agent login (the database is the judge)

The SQL guard reads text, and text can hide what a statement really does: a view over a
blocked table, a function that returns a protected column. The target database cannot be
fooled that way. So a PostgreSQL cluster can have a second login, the _agent login_, that
agents' queries run as. It holds `SELECT` on the columns that the cluster policy allows,
and nothing else:

- no grant on a blocked table, on a protected (masked) column, or on any view or
  materialized view;
- a rule about a table also covers every table that shares rows with it: its partitions,
  its parents and children by inheritance, and the other parents of a shared child, however
  far the links go. Blocking any of them closes all of them, and a protected column is
  protected on all of them;
- grants are per column, never per table, so a column added later is closed until the
  script is run again;
- its sessions are read-only, and it has no role memberships and no create rights.

The gateway never creates or changes this login. It writes a script; a database
administrator reads it, runs it and sets a password. The gateway then connects as that
login and asks the database what the login can really do. Anything beyond the policy is
_drift_, and agents are refused on that cluster (`database_setup_drift`, 409) until a check
finds it gone. People's queries always use the cluster's own login and are not affected.

All endpoints need admin access to the cluster. PostgreSQL only (400 for MySQL), except
`DELETE`, which works for any cluster.

- `GET /clusters/:id/agent-login` → `AgentLogin`:
  `{configured: false}` or
  `{configured: true, username, status, findings, checked_at, stale, needs_password}`.
  `status` is `unchecked`, `ok`, `drift` (a critical finding) or `error` (the check could not
  run, for example a wrong password). `stale` is true when the cluster or its policy changed
  after the last check; the next agent query checks again before it runs.
  `findings` is `[{severity: "critical"|"warning", code, object, message}]`:

  | Code                                 | Severity | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                       |
  | ------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `readable_beyond_policy`             | critical | The login can read a column that the policy hides, or a view. Includes grants to `PUBLIC`, and partitions, parents and children of a blocked table.                                                                                                                                                                                                                                                                                           |
  | `can_write`                          | critical | The login can change a table.                                                                                                                                                                                                                                                                                                                                                                                                                 |
  | `can_create`                         | critical | The login can create objects in a schema, or schemas in the database.                                                                                                                                                                                                                                                                                                                                                                         |
  | `definer_function`                   | critical | The login can run a `SECURITY DEFINER` function, which reads with its owner's rights. Every schema counts, also one the login cannot use, because an aggregate or an operator can call the function. Revoke `EXECUTE` on it from `PUBLIC`.                                                                                                                                                                                                    |
  | `system_catalog_readable`            | critical | The login can read `pg_statistic`, `pg_statistic_ext_data`, `pg_authid`, `pg_shadow`, `pg_largeobject`, `pg_user_mapping`, or a table in `pg_toast`: these hold copies of table data or credentials. Also any table or view that someone added to `pg_catalog` or `information_schema`.                                                                                                                                                       |
  | `foreign_server`                     | critical | The login can use a foreign server, which reads with another login's rights.                                                                                                                                                                                                                                                                                                                                                                  |
  | `dangerous_function`                 | critical | The login can run a function that reads files or connects to other servers: `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_ls_logdir`, `pg_ls_waldir`, `pg_stat_file`, `lo_import`, `lo_export`, or the `dblink` functions (one finding for all of them). Installing `dblink` gives them to `PUBLIC`; revoke `EXECUTE` from `PUBLIC` and grant it to the roles that need it.                                                         |
  | `role_too_powerful`                  | critical | Superuser, create role or database, replication, bypass row security, or member of another role.                                                                                                                                                                                                                                                                                                                                              |
  | `check_failed`, `database_too_large` | critical | The check could not run as the login, or the database has more columns than it reads (about 200,000). Status `error`.                                                                                                                                                                                                                                                                                                                         |
  | `not_read_only`                      | warning  | The login's sessions are not read-only by default.                                                                                                                                                                                                                                                                                                                                                                                            |
  | `password_needed`                    | critical | The cluster's endpoint changed and the stored password was cleared. Enter it again, or remove the login.                                                                                                                                                                                                                                                                                                                                      |
  | `extension_object_readable`          | warning  | The login can read a view or table that an extension installed, such as `pg_stat_statements`, and that the policy has no rule about. Revoke it from `PUBLIC` if it shows anything sensitive. An extension's object that the policy blocks or protects is `readable_beyond_policy`; a broad protection pattern, such as `*name*`, can match a column of an extension's view and so close the cluster until that view is revoked from `PUBLIC`. |
  | `not_granted`                        | warning  | The policy allows a column that the login cannot read. Agents get a permission error for it.                                                                                                                                                                                                                                                                                                                                                  |

- `GET /clusters/:id/agent-login/script?username=` → `text/plain`: the SQL to run as a database
  administrator. `username` defaults to the stored login, or `vda_agent`; it cannot be the
  cluster's own login. The script is made from the current catalog and policy and contains no
  secret. **Use a new login name, and one name per database.** The script removes every
  privilege the login holds in that database, and its rights on other databases and
  tablespaces of the same server such as `CONNECT` (`DROP OWNED BY`), and then grants the
  exact list, so it is safe to run again
  for the agent login, and it stops without changing anything when the login is a superuser
  or owns any object, or when it is run in another database. It reads at most 5,000 tables
  from the catalog; tables beyond that stay closed. It does not remove grants to `PUBLIC`;
  the check reports them.
- `PUT /clusters/:id/agent-login` `{username, password}` → `AgentLogin`. Stores the login
  (the password encrypted, like the cluster's own) and checks it at once. `username` is 1–63
  lower-case letters, digits or `_`, not a reserved name, and must differ from the cluster's
  own login.
- `POST /clusters/:id/agent-login/check` → `AgentLogin`. Checks now.
- `DELETE /clusters/:id/agent-login` → `204`. Agents use the cluster's own login again.

When the check runs. A clean result is trusted for five minutes on the node that made it,
then repeated before the next agent query. A bad result (`drift` or `error`) is repeated
after fifteen seconds, so a repair is noticed without anyone asking; `POST …/check` does it
at once on the node that handles it. A policy change makes the result stale at once. So a
stricter policy closes the cluster to agents until the script has been run again; a looser
policy leaves it working, with `not_granted` warnings. While the check cannot run, agents
get `database_check_failed` (503) with a `retry_later` fix.

When the cluster's connection endpoint changes (engine, host, port, database, login, TLS
mode, replica), the stored agent password is cleared, and `cluster.update` records
`agent_login_password_cleared`. A stored password is only ever sent to the endpoint it was
entered for. The login itself stays, with `needs_password: true`, so agents are refused
(`database_setup_drift`, finding `password_needed`) and never fall back to the cluster's own
login. Enter the password again with `PUT`, or remove the login on purpose with `DELETE`.

Limits. State them to whoever relies on this:

- **Names and definitions stay visible.** The PostgreSQL catalog shows every login the
  names of tables and columns, column defaults, check constraints, comments, the source of
  views and functions, index definitions, partition bounds and row-count estimates (also of
  a partial index, which is a count behind its condition), also for blocked tables.
  Only the rows are closed. Do not put secrets in those places.
- **The policy works on names.** A generated column, or a copy of a protected column under
  another name, is a different column to the policy and is granted. So is a field inside a
  composite or JSON column: protect the whole column. Blocking one partition closes its
  parent and all its sibling partitions too. A view is never
  granted, so an agent cannot read through any view.
- **One login for all agents of a cluster.** They can see each other's running statements
  in `pg_stat_activity`. Set `CONNECTION LIMIT` on the login to cover the gateway's pools:
  five connections per pool, for the primary and the replica, on each gateway node (the
  script sets 16).
- **Between checks.** A new object that is open to `PUBLIC` can be readable for up to five
  minutes. The same holds for a granted table that is attached as a partition of a blocked
  table. The gateway's own name-based checks still apply in that time. A partition that is
  detached from a blocked table becomes an ordinary table; block it by name if it must stay
  closed.
- **What the check does not cover:** sequences, large-object grants, the `TEMPORARY` right
  on the database, and built-in functions other than those listed above. The guard's
  function list is the only layer for these. A read-only setting made with
  `ALTER ROLE … IN DATABASE` is not seen by `not_read_only`. Only the primary is checked; a physical
  replica has the same grants, a logical replica may not.
- **Row-level security policies.** PostgreSQL does not check column grants for a column
  that a policy uses. A policy on a protected column is a yes-or-no test of that column, and
  a policy function that prints its argument sends the value to the login as a notice or an
  error. Do not write such functions on tables that agents can read.
- **Other clues.** Timing and error messages can still tell an attacker something, and
  allowed columns can still be combined across many queries.
- **Large catalogs.** At most 200 findings are listed, critical ones first, with a
  `more_findings` note that gives the totals.
- **PostgreSQL 14 and older** let everyone create in schema `public`, which the check
  reports as `can_create`. `REVOKE CREATE ON SCHEMA public FROM PUBLIC` closes it, and also
  takes that right from every role that had it only through `PUBLIC`; grant it to them
  first.
- **MySQL** has no agent login yet.

### Agent door (bearer token, no session)

These endpoints take `Authorization: Bearer <agent token>` and never a session cookie.
The scheme name is `Bearer`, with that exact case. The session API above never accepts
an agent token. The network allowlist applies. The `X-Requested-With` header is not
needed on the endpoints listed here. Every authentication failure is the same `401 unauthenticated`: unknown,
malformed, expired or revoked token, paused agent, disabled owner.

- `GET /agent/whoami` → `{agent: {id, name, max_level}, owner: {email},
clusters: [{id, name, engine, provider, region, environment, level, enforced_by}]}`.
  `enforced_by` is `database` when the cluster has an agent login, else `gateway`. `clusters` lists
  only what the agent can reach now, with its effective `level`.

- `POST /mcp` — the Model Context Protocol endpoint (Streamable HTTP, without sessions and
  without server-sent events). The body is one JSON-RPC 2.0 message; the answer is one JSON
  object. Protocol versions `2025-06-18`, `2025-03-26` and `2024-11-05` are accepted; an
  unknown `MCP-Protocol-Version` header is 400. A request with an `Origin` header is 403,
  because a browser must not drive this endpoint. `GET` is 405.

  | Method                           | Answer                                                               |
  | -------------------------------- | -------------------------------------------------------------------- |
  | `initialize`                     | `{protocolVersion, capabilities: {tools}, serverInfo, instructions}` |
  | `ping`                           | `{}`                                                                 |
  | `tools/list`                     | `{tools: [{name, description, inputSchema}]}`                        |
  | `tools/call` `{name, arguments}` | `{content: [{type: "text", text}], structuredContent, isError}`      |
  | a message with no `id`           | `202`, no body                                                       |

  Protocol errors use JSON-RPC codes: `-32700` (not JSON, 400), `-32600` (not one valid
  message, or a batch, 400), `-32601` (unknown method), `-32602` (unknown tool). `id` must
  be a string or an integer.

  Tools. Every tool takes `task`: one line of 1–500 visible characters that says what the
  agent is doing and why. A tool accepts only the arguments in its own row below.

  | Tool             | Arguments                              | Result                                                                                   |
  | ---------------- | -------------------------------------- | ---------------------------------------------------------------------------------------- |
  | `list_databases` | `task`                                 | `{databases: [{id, name, engine, provider, region, environment, level, enforced_by}]}`   |
  | `search_schema`  | `task, database, query, limit? = 20`   | `{tables: [{table, kind, row_estimate, matching_columns}], more}`                        |
  | `describe_table` | `task, database, table`                | `{table, kind, row_estimate, columns: [{name, type, nullable, primary_key, protected}]}` |
  | `check_sql`      | `task, database, sql`                  | `{verdict, risk, issues, will_run_as, suggestions, fix}`; nothing runs                   |
  | `run_query`      | `task, database, sql, max_rows? = 100` | `{query_id, columns, rows, row_count, truncated, ran_as, elapsed_ms}`                    |

  `database` is an `id` from `list_databases`. Tables that the cluster policy blocks are
  left out of `search_schema`, and `describe_table` answers `table_not_found` for them, the
  same as for a table that does not exist. This is a filter on names in the gateway. When the
  cluster has an agent login (`enforced_by: "database"`), the database also refuses to read
  them, whatever the statement looks like. `check_sql` still answers `blocked_table` for a
  blocked name, so the block list is not a secret from the agent. `run_query` goes through the same pipeline as a
  person's query (guard, policy, masking, cost gate, audit) and stores `task` in query
  history. It returns at most `max_rows` rows (1000 at most) and at most about one megabyte
  of row data; `truncated` says when rows were left out. The request can run as long as a
  person's query (610 s ceiling); the statement timeout of the cluster policy applies.

  A refused tool call is a normal result with `isError: true` and
  `structuredContent: {error: {code, message, fix}}`. `fix` is
  `{action, hint, retry_after_seconds?}`. `action` is one of `rewrite_sql`, `fix_arguments`,
  `choose_database`, `ask_owner`, `retry_later`, `stop`. When a statement has several
  blocking issues, the hardest stop decides the fix. A failure inside the gateway (5xx
  other than `upstream`) has a generic message. Error codes are those of the query API,
  plus:
  - `table_not_found` (404): `describe_table` found no such table.
  - `database_setup_drift` (409): the cluster's agent login allows more than the policy. The
    fix is `ask_owner`.
  - `database_check_failed` (503): the agent login could not be checked. The fix is
    `retry_later`.
  - `result_too_large` (422): one row alone is larger than about one megabyte.
  - `network_denied` (403): the cluster's own network policy excludes the agent's address.
    Such a cluster is also left out of `list_databases`.
  - `rate_limited` (429): more than 120 tool calls by one agent in one minute, all tools
    together, counted on one node.
  - `budget_exceeded` (429): the hourly query budget is used; `fix.retry_after_seconds` says
    how long to wait. The budget is exact also under parallel calls, and a refusal for the
    budget records nothing.
  - `too_many_denials` (429): five `run_query` calls in a row were refused (`query_denied`,
    `approval_required`, `forbidden`, `not_found`, `cost_exceeded`). The agent is stopped for up to ten
    minutes from the first refusal, on the node that counted them; the other tools still
    work. A successful `run_query` resets the count. Parallel calls that the guard or the
    access check refuses cannot pass the limit. Statements that the guard accepts run in
    parallel, so several of them can reach the cost gate at once and each be refused there;
    the budget still bounds them.

  Each tool call whose arguments parse is recorded as an `agent.tool` audit event:
  `{tool, task, database, outcome}`, under the owner, with the agent as the target. These
  events go through the same bounded queue as other audit events; if the queue stays full
  for 250 ms the event is dropped, logged, and counted in the metric
  `vda_agent_tool_events_dropped_total`. Queries are not affected: their history row and
  `query.execute` event are written in a transaction before the query runs.

### Audit

- `GET /audit?action=&actor_id=&limit=&cursor=` → `{items: AuditEvent[], next_cursor}` (org admin).
  `action` is an exact match; `limit` must be 1–200. `query.execute` durably records
  every authorized query attempt before target I/O, including blocked attempts;
  details contain `{query_id, history_id, status}` with initial `running`/`blocked`
  status. Final outcome is in history. Approval actions include `approval.create`,
  `approval.approve`, `approval.reject`, `approval.execute` (claim), `approval.executed`,
  and `approval.failed`. Administrative actions use `*.create`, `*.update`, `*.delete`. The agent login of a cluster writes `agent_login.set` (`{username}`) and
  `agent_login.remove`. Agent actions are
  `agent.create` (`{owner_id, name, max_level, cluster_ids, hourly_query_budget}`), `agent.update` (each changed
  field as `{from, to}`, except `description`, which is only marked `"changed"`; a change of name, level or clusters is always its own event, also
  when the same request pauses or resumes), `agent.pause`, `agent.resume`, `agent.delete`
  (`{owner_id, name}`), `agent.token_create` (`{token_id, hint, expires_at}`) and
  `agent.token_revoke` (`{token_id}`). A token is never written to the audit log.

### Settings

- `GET /settings/network` → `{allowed_cidrs: string[], trust_proxy_headers: boolean}` (admin)
- `PUT /settings/network` same → same. Server refuses a change that would lock out the caller's current IP (400 `validation`).

### Cloud discovery (org admin only)

Discovery finds databases in cloud accounts and proposes them for import. It
never creates clusters on its own (import needs DB credentials) and only uses
read-only cloud APIs. AWS credentials are never stored: the gateway uses its
own ambient identity (IRSA / ECS task role / instance profile / env) and,
per source, optionally assumes a role in the target account.

```ts
type DiscoveryProvider = "aws";
type ResourceStatus = "new" | "imported" | "ignored" | "gone";
type Drift =
  "endpoint_changed" | "replica_changed" | "deleted" | "engine_changed";

interface DiscoverySource {
  id: string;
  provider: DiscoveryProvider;
  name: string;
  role_arn: string | null; // arn:aws:iam::<12 digits>:role/<path/name>
  external_id_set: boolean; // external_id is write-only
  regions: string[]; // e.g. ["us-east-1","eu-west-1"], 1..=20
  default_project_id: string | null;
  environment_tag_keys: string[]; // default ["environment","env","stage"]
  scan_interval_minutes: number; // 5..=1440, default 60
  enabled: boolean;
  last_scan: ScanRun | null;
  last_test: {
    ok: boolean;
    account_id: string | null;
    identity_arn: string | null;
    tested_at: string;
  } | null;
  created_at: string;
  updated_at: string;
}

interface ScanRun {
  id: string;
  source_id: string;
  status: "running" | "succeeded" | "partial" | "failed";
  started_at: string;
  finished_at: string | null;
  found: number;
  new: number;
  gone: number;
  changed: number;
  errors: { region: string | null; message: string }[];
}

interface DiscoveredResource {
  id: string;
  source_id: string;
  source_name: string;
  provider: DiscoveryProvider;
  kind: "rds_instance" | "aurora_cluster";
  arn: string;
  identifier: string;
  account_id: string;
  region: string;
  engine: Engine; // postgres | mysql (aurora-*/mariadb mapped)
  engine_detail: string; // raw, e.g. "aurora-postgresql"
  engine_version: string;
  host: string;
  port: number;
  replica_host: string | null; // Aurora reader endpoint or first read replica
  replica_port: number | null;
  database: string | null; // DBName if set
  status_detail: string; // AWS status, e.g. "available"
  publicly_accessible: boolean;
  encrypted: boolean;
  multi_az: boolean;
  iam_auth_enabled: boolean;
  vpc_id: string | null;
  tags: Record<string, string>;
  suggested_environment: Environment; // from environment_tag_keys, else name heuristics, else "production"
  status: ResourceStatus;
  cluster_id: string | null; // set when imported
  drift: Drift[]; // vs the imported cluster's current config
  first_seen_at: string;
  last_seen_at: string;
}
```

- `GET /discovery/sources` → `{items: DiscoverySource[]}`
- `POST /discovery/sources` `{provider, name, role_arn?, external_id?, regions, default_project_id?, environment_tag_keys?, scan_interval_minutes?, enabled?}` → `DiscoverySource`
- `PATCH /discovery/sources/:id` (same fields, optional; `external_id: null` clears) → `DiscoverySource`
- `DELETE /discovery/sources/:id` → `204` (its resources are deleted; imported clusters are kept)
- `POST /discovery/sources/test` (same body as create) → the connection test report below.
  Tests an unsaved draft without creating a source or storing its external ID.
  A server-generated summary is retained for 10 minutes in a bounded, actor-scoped
  cache and persisted in `last_test` when that actor saves the matching role,
  external ID and regions through create/update. Tests are optional before saving.
- `POST /discovery/sources/:id/test` → `{ok: boolean, account_id: string | null, identity_arn: string | null, regions: {region: string, ok: boolean, error: string | null}[]}`
  (STS GetCallerIdentity after assume-role + a 1-item DescribeDBInstances per region).
  Both success and failure summaries persist in `last_test`; timeouts return an
  `ok: false` report. Editing role/external ID/regions clears stale verification
  unless a matching draft test exists. A test completing after an edit does not
  overwrite the edited source's summary. Summaries contain no credentials.
- `POST /discovery/sources/:id/scan` → `ScanRun` (runs now, synchronously, ≤ 60 s; 409 `conflict` if a scan for this source is already running)
- `GET /discovery/sources/:id/runs?limit=&cursor=` → `{items: ScanRun[], next_cursor}`
- `GET /discovery/resources?source_id=&status=&engine=&region=&q=&limit=&cursor=` → `{items: DiscoveredResource[], next_cursor}`;
  response also includes `counts: {new, imported, ignored, gone}` for the filter minus `status`.
- `POST /discovery/resources/:id/import` `{project_id, name, environment, database, username, password, tls_mode}`
  → `Cluster`. Host/port/engine/provider(`aws`)/region/replica/tags come from the resource;
  same validation as `POST /clusters` (SSRF guard, credential encryption, default policy).
  409 if already imported. Default `tls_mode` in UI: `verify_full`.
- `POST /discovery/resources/:id/ignore` → `DiscoveredResource`; `POST /discovery/resources/:id/unignore` → `DiscoveredResource`
- `POST /discovery/resources/:id/sync` → `Cluster` (imported only): applies discovered host/port/replica to the
  cluster. Requires `password` in body if the endpoint changed (same rule as `PATCH /clusters/:id`).

Overview adds `discovery: {new: number, gone: number, drifted: number} | null` (null for non-admins).
