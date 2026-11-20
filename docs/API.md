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
    | "expired"
    | "withdrawn";
  error: string | null;
  error_code: string | null; // the stored code of the error that stopped the write, e.g. "effect_changed"
  sql_truncated: boolean;
  agent: { id: string | null; name: string } | null; // the agent that asked, for its owner
  preview: Preview | null; // null in lists
  receipt: Receipt | null; // null in lists and until the write has run
  reviewer: { id: string; email: string; name: string } | null;
  review_note: string | null;
  result: QueryResult | null;
  created_at: string;
  reviewed_at: string | null;
  executed_at: string | null;
  expires_at: string;
}

// What a write would do, seen in a dry run. Fields that have no value are
// left out, not null: `reason` only when `supported` is false; `kind`,
// `target`, `before`, `after` and `bound_to` only when known.
interface Preview {
  supported: boolean; // false for MySQL
  reason?: string;
  kind?: StatementKind;
  target?: string; // the table it writes
  affected_rows?: number;
  before?: RowSample; // the rows it changes, as they are now (UPDATE, DELETE)
  after?: RowSample; // the rows as it leaves them (INSERT, UPDATE)
  bound_to?: "rows" | "count";
  written?: string[]; // the columns it writes, named as PostgreSQL names them (UPDATE, INSERT with a column list of values); left out when not known
  notes: string[]; // what the preview could not show
}

interface RowSample {
  columns: string[];
  hidden: string[]; // columns whose values are not shown
  masked: string[]; // the hidden columns that the policy protects (absent on previews stored before it existed)
  rows: unknown[][]; // at most 20
  total: number; // how many rows there were in all
}

// The signed record of a write that ran. The people in it are `{id, email}`.
interface Receipt {
  version: number;
  approval_id: string;
  cluster: { id: string; name: string; engine: "postgres" | "mysql" };
  sql: string;
  reason: string;
  requested_by: { id: string; email: string };
  agent: { id: string | null; name: string } | null;
  approved_by: { id: string; email: string };
  review_note: string | null;
  executed_by: { id: string; email: string };
  requested_at: string;
  approved_at: string;
  executed_at: string;
  previewed_rows: number | null; // null without a preview
  affected_rows: number | null;
  bound_to: "rows" | "count" | null; // null when nothing was bound
  key_id: string;
  digest: string;
  signature: string;
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

- `POST /approvals` `{cluster_id, sql, reason}` → `Approval` (write level; re-analyzed server-side; 422 if `deny`;
  400 for a read-only statement; 422 `unsupported_write` for a write inside `WITH`). The
  write is first tried in a dry run (see below); a write that fails in the dry run is
  refused with the same error and is not stored.
- `GET /approvals?status=&cluster_id=&mine=true&limit=50&cursor=` → `{items: Approval[], next_cursor: string | null}`.
  Org admins see all, scoped admins see requests on administered clusters, and other
  members see their own requests. Detail/review/execution also check current access.
  Keyset pagination orders by creation time and ID descending; `limit` must be 1–100.
  List items set `result`, `preview` and `receipt` to null, truncate `sql` to 2,000 characters, and set
  `sql_truncated` to true when truncated. `GET /approvals/:id` returns full SQL
  and result, with `sql_truncated: false`. `executing` claims are never expired;
  abandoned claims become `failed` with an `error` after the statement timeout
  plus five minutes. Failed executions remain consumed and cannot be replayed.
- `GET /approvals/:id` → `Approval`
- `POST /approvals/:id/preview` → `Approval` (requester or cluster admin). For a pending
  request without a preview, that is an agent's request: runs the dry run once, as the
  caller, and binds the approval to it; else 409. A preview runs the agent's statement
  and rolls it back, so read the SQL first. It is refused while the agent is paused or
  deleted (409), and when the statement calls a function defined in the database rather
  than a built-in one (422 `unsupported_write`), because the preview would run that
  function. The database itself reports what the statement calls (from a temporary view
  of its expressions in a transaction that is rolled back): direct calls, attribute
  notation (`row.fn`), operators, casts, functions inside views it reads, and cast
  functions into the types of the columns it writes. Not checked, and run in the
  preview: triggers (also those fired by foreign-key actions), column defaults,
  generated columns, CHECK and domain constraints, expression and partial indexes,
  row-security policies, and foreign tables on the target. The cluster's login needs
  the `TEMP` privilege for this check; without it, previews of agent requests fail.
- `POST /approvals/:id/approve` `{note?, run?}` → `Approval` (cluster admin, ≠ requester;
  for an agent's request, 409 until it has a preview). With
  `run: true` the request is approved and then run at once, as `execute` does.
- `POST /approvals/:id/reject` `{note}` → `Approval` (`run: true` is 400)
- `POST /approvals/:id/execute` → `Approval` with `result` (requester or approver; once; approval valid 24h)
- `POST /approvals/:id/withdraw` → `Approval` (requester only; `pending` or `approved` →
  `withdrawn`; else 409)
- `GET /approvals/:id/receipt` → `{receipt, valid, digest_matches, signed_with_current_key}`
  (same visibility as the request; 404 until the write has run)

`Approval` also has `agent: {id, name} | null` (the agent that asked, for its owner, who is
the `requester`; `id` is null once the agent is deleted), `preview: Preview | null`,
`receipt: Receipt | null` and `error_code: string | null`, the code of the error that
stopped the write as it was stored (for example `effect_changed`, `outcome_unknown` or
`upstream`; null for a request that has not failed). People see the stored code; an agent
reads one of three normalized codes from `get_approval`. Status is one of
`pending`, `approved`, `rejected`, `executing`, `executed`, `failed`, `expired`, `withdrawn`.

**Dry run and preview (PostgreSQL).** When a person makes a request (for an agent's
request: when a person calls `preview`), the write runs in a
read-write transaction on the primary that is always rolled back. First the rows that the
write targets are read with `SELECT … FOR UPDATE OF <table>`, then the write runs with
`RETURNING <table>.*` (`RETURNING *` for an `INSERT`). `Preview` (see Shared types)
is `{supported, reason, kind, target, affected_rows, before, after, bound_to, notes}`,
without the fields that have no value. `before` and `after` are `RowSample`s,
`{columns, hidden, rows, total}`, with at most 20 rows. Protected
columns are masked by name, and a new value that is computed from a protected column or
from a subquery is hidden. So is a new value computed from any name that is not a column
of the target, or from a whole row (`t::text`, `concat(t.*)`, `(t.*)::text`). For an `UPDATE`,
`after` has the target's own columns only. `notes` says what the preview could not show.

**Binding.** The approval is bound to the effect of the dry run. At execution the target
rows are read again under `FOR UPDATE`, each with its key (`tableoid` and `ctid`) and a
digest of the whole row as text. With `bound_to: "rows"` the digests must be the same as
in the dry run (the digest is never sent to clients). The write is then limited to
exactly the locked rows (their keys are a query parameter), so a row that would join the
target set later (through a subquery, a volatile function or a new snapshot) is not
written. With `bound_to: "count"` the number of changed rows must be the same. This is
the case when the target rows and the changed rows did not match one to one, for a
target that is not a plain or partitioned table (a view), and for a statement the
planner does not cover (such as `UPDATE ONLY`, `ON CONFLICT`, or a statement with
parameters). A planned statement on a table is still limited to the locked rows. Otherwise the
transaction is rolled back and the request becomes `failed` with `409 effect_changed`.

**MySQL.** There is no dry run: `supported: false`, and nothing is bound beyond the
statement itself.

**Limits of the dry run.** A dry run runs the statement on the primary before anyone
approves it, and then rolls it back. What cannot be rolled back still happens: sequences
advance, and functions and triggers that act outside the transaction (for example
`dblink`, or `setval` in a user function) do so. `NOTIFY` is not sent. Target rows stay
locked while it runs. A person who can request writes can learn whether rows match a
condition from the count. An agent's write is never tried until a person starts its
preview (see `propose_write`).

**Receipt.** A write that runs leaves a receipt (`Receipt` in Shared types):
`{version, approval_id, cluster: {id, name, engine}, sql, reason, requested_by, agent,
approved_by, review_note, executed_by, requested_at, approved_at, executed_at,
previewed_rows, affected_rows, bound_to, key_id, digest, signature}`, where
`requested_by`, `approved_by` and `executed_by` are `{id, email}`. `digest` is the SHA-256 of the
receipt without `digest` and `signature`, as compact JSON with the keys of every object
sorted. `signature` is an
HMAC-SHA256 of the digest with a key derived from the master key; `key_id` names that
key without revealing it. `valid` is true when the digest and the signature match and the
receipt belongs to this request (same `approval_id`, `sql` and cluster, status
`executed`). `digest_matches` is true when the receipt's content matches its own digest;
that needs no key, so a changed record shows also when it claims another key.
`signed_with_current_key` is false when the receipt names another key. That
may be a receipt signed before the master key changed, or one that was changed
and given another key id: a key id proves nothing, so such a receipt is not
verified and must be treated as unproven. The receipt proves who asked, who approved and what ran; it is not a
backup and has no undo script.

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

  | Tool             | Arguments                              | Result                                                                                                      |
  | ---------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
  | `list_databases` | `task`                                 | `{databases: [{id, name, engine, provider, region, environment, level, enforced_by}]}`                      |
  | `search_schema`  | `task, database, query, limit? = 20`   | `{tables: [{table, kind, row_estimate, matching_columns}], more}`                                           |
  | `describe_table` | `task, database, table`                | `{table, kind, row_estimate, columns: [{name, type, nullable, primary_key, protected}]}`                    |
  | `check_sql`      | `task, database, sql`                  | `{verdict, risk, issues, will_run_as, suggestions, fix}`; nothing runs                                      |
  | `run_query`      | `task, database, sql, max_rows? = 100` | `{query_id, columns, rows, row_count, truncated, ran_as, elapsed_ms}`                                       |
  | `propose_write`  | `task, database, sql`                  | `{approval_id, status, previewed, …}`; nothing runs                                                         |
  | `get_approval`   | `task, approval_id?`                   | `{approval_id, status, previewed, review_note, executed_rows, error_code, error, fix?, …}`, or `{requests}` |
  | `withdraw`       | `task, approval_id`                    | the same as `get_approval`, with `status: "withdrawn"`                                                      |

  `propose_write` opens an approval request for the agent's owner, with `task` as the
  reason. The agent needs write level (its own limit and its owner's access). An agent
  that can read the database but not write it gets `403 insufficient_access` (fix
  `ask_owner`); a database it cannot reach at all is `403 forbidden` or `404 not_found`
  (fix `choose_database`), as for the other tools. On PostgreSQL it takes one plain
  `INSERT`, `UPDATE` or `DELETE`; `WITH`, `ONLY`, `ON CONFLICT`, `RETURNING`, parameters,
  joins in the target and tuple assignments (`SET (a, b) = …`) are `422 unsupported_write`.

  Nothing of an agent's write runs before a person looks at it. First, a read that
  touches everything the statement reads and computes runs as the agent's own read. For
  an `UPDATE` it is `SELECT <new values> FROM <tables> WHERE <condition>`; for an
  `INSERT` it reads every column of its source. The guard, the database as the judge, the
  budget and query history all apply, in a read-only transaction. If the agent may not
  read it, the proposal is refused with that read's error. Otherwise the request is
  stored with no preview. A person starts its dry run with
  `POST /approvals/:id/preview`; it cannot be approved before that. (A dry run runs as
  the cluster's own login. SQL can tell a read-only check from a dry run, so a dry run
  started by an agent could act, or show a count, beyond what the agent's reads allow.)

  A person who is not the owner approves the request, and a person runs it. An agent's
  request does not run if the agent was paused or deleted after it asked.

  The agent never sees rows, and sees no counts before its write has run: `get_approval`
  shows the status, `previewed`, the reviewer's note and, after execution,
  `executed_rows`. While a request has not failed, `error_code` and `error` are null and
  there is no `fix`. When the write failed at execution, the agent reads one of three
  outcomes, each with a fixed sentence in `error` and a fix:

  | `error_code`      | `error`                                                          | `fix.action`    |
  | ----------------- | ---------------------------------------------------------------- | --------------- |
  | `effect_changed`  | "The data changed after the approval, so the write was not run." | `propose_write` |
  | `outcome_unknown` | "Nobody knows whether the write ran. Your owner can see more."   | `stop`          |
  | `write_failed`    | "The write failed when it ran. Your owner can see why."          | `ask_owner`     |

  `outcome_unknown` means the node that ran the write was lost. `write_failed` covers
  every other failure, also an old failed request with no stored code; the request is
  used up. A failed write is never told to retry later, to choose another database or to
  rewrite its SQL. People see the full text in `Approval.error`, which can hold counts
  from the dry run and database messages; the agent never does. The original error code
  is kept with the request (`approvals.error_code`).

  `get_approval` without `approval_id` returns
  `{requests: [{approval_id, database, status, task, created_at, expires_at}]}`: the
  agent's own open requests (`pending`, `approved` or `executing`, and not expired),
  newest first, at most 20, so an agent that lost an id can find it. `database` is the
  cluster id. Requests expire 24 hours after they are made. Each call of `get_approval`
  writes an audit event; poll no more than about once a minute.

  Limits per agent: one proposal at a time (per node). Five refused proposals in a row
  give `429 too_many_denials` for ten minutes from the refusal that made five; calls
  during the stop do not make it longer, and `fix.retry_after_seconds` is the time
  left. A refusal is a proposal that ends in `query_denied`, `unsupported_write`,
  `forbidden`, `not_found`, `insufficient_access` or `cost_exceeded`, or in `upstream`
  when the database refused the statement itself: its own error, `Query timed out`, or
  the affected-row limit. An `upstream` error because the database cannot be reached
  (fix `retry_later`) does not count, nor does a cancelled query. Other errors
  (`validation`, `budget_exceeded`, `rate_limited`, `too_many_open_requests`, `busy`,
  `internal`, `network_denied`, …) do not count either. An accepted proposal resets the
  count; a successful read does not. The count is kept on the node that made it and is
  dropped after ten minutes without a proposal. At most 10 requests waiting
  (`429 too_many_open_requests`, with the open requests in `error.details`) and 30 in an
  hour, withdrawn ones included (`429 rate_limited`). A task may use all 500 characters:
  the read check records it after a prefix, cut to fit.
  `get_approval` and `withdraw` work only on the agent's own requests; any other id is
  `404 approval_not_found`.

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
  `choose_database`, `ask_owner`, `propose_write`, `retry_later`, `stop`. A write that needs
  approval (`approval_required`) and a write whose data changed after the approval
  (`effect_changed`) have the fix `propose_write`. When a statement has several
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
  - `unsupported_write` (422): a write that cannot be previewed and bound this way. The
    fix is `rewrite_sql`.
  - `insufficient_access` (403): `propose_write` on a database where the agent can read
    but not write. The fix is `ask_owner`.
  - `too_many_open_requests` (429): ten of the agent's writes wait for a person.
    `error.details` is `{limit, requests}`, with `requests` as `get_approval` lists them
    without an id; it is the only error whose `details` an agent sees. The fix is
    `retry_later`.
  - `too_many_denials` (429): five `run_query` calls in a row were refused (`query_denied`,
    `forbidden`, `not_found`, `cost_exceeded`; `approval_required` is not a refusal here,
    because its fix sends the agent to `propose_write`). The agent is stopped for up to
    ten minutes from the first refusal, on the node that counted them; the other tools
    still work. A successful `run_query` resets the count. Parallel calls that the guard
    or the access check refuses cannot pass the limit. Statements that the guard accepts
    run in parallel, so several of them can reach the cost gate at once and each be
    refused there; the budget still bounds them. Five refused `propose_write` calls stop
    that tool for ten minutes; see its limits above.

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
  status. Final outcome is in history. Approval actions are `approval.create`,
  `approval.preview` (`{affected_rows, bound_to}`), `approval.approve`, `approval.reject`,
  `approval.withdraw` (`{agent_id}`), `approval.execute` (claim), `approval.executed`,
  `approval.failed` (`{code}`) and `approval.expire`. Two of them have no actor and no
  IP address, because no person caused them: `approval.expire`, written once when a
  request runs out of time, and `approval.failed` with
  `{code: "outcome_unknown", recovered: true}`, written once when a node that had claimed
  a write is lost. Notice settings write `settings.notices` (the saved fields, the host
  of the address, `url_changed` and `dropped_notices`), `settings.notices.secret` (`{rotated}`) and
  `settings.notices.test` (`{delivered, status, error}`); the address and the secret are
  never written to the audit log. Administrative actions use `*.create`, `*.update`, `*.delete`. The agent login of a cluster writes `agent_login.set` (`{username}`) and
  `agent_login.remove`. Agent actions are
  `agent.create` (`{owner_id, name, max_level, cluster_ids, hourly_query_budget}`), `agent.update` (each changed
  field as `{from, to}`, except `description`, which is only marked `"changed"`; a change of name, level or clusters is always its own event, also
  when the same request pauses or resumes), `agent.pause`, `agent.resume`, `agent.delete`
  (`{owner_id, name}`), `agent.token_create` (`{token_id, hint, expires_at}`) and
  `agent.token_revoke` (`{token_id}`). A token is never written to the audit log.

### Settings

- `GET /settings/network` → `{allowed_cidrs: string[], trust_proxy_headers: boolean}` (admin)
- `PUT /settings/network` same → same. Server refuses a change that would lock out the caller's current IP (400 `validation`).

#### Notices to approvers (org admin only)

The gateway can tell approvers that a request waits, through one outbound webhook. A
notice is written in the transaction that changes the request and is sent afterwards
by a worker; no request handler waits for the receiver.

```ts
type NoticeEvent =
  | "approval.created" // a person or an agent asked for a write
  | "approval.previewed" // a person ran the dry run of an agent's request
  | "approval.approved"
  | "approval.rejected"
  | "approval.withdrawn"
  | "approval.executed" // the approved write ran
  | "approval.failed" // it did not run, or nobody knows whether it ran
  | "approval.expired";

interface NoticeSettings {
  enabled: boolean; // default false
  format: "webhook" | "slack"; // default "webhook"
  url_set: boolean; // the address itself is write-only
  url_host: string | null; // its host, to recognize it by
  secret_set: boolean;
  events: NoticeEvent[]; // default ["approval.created"]
  include_reason: boolean; // default false
  include_row_count: boolean; // default false
  links: boolean; // VDA_PUBLIC_URL is set, so notices link to the request
  delivery: {
    pending: number; // notices that wait or are being retried
    dead: number; // notices that were given up
    last_success_at: string | null;
    last_error: string | null; // a failure class, see below
    last_error_at: string | null;
  };
}
```

- `GET /settings/notices` → `NoticeSettings`.
- `PUT /settings/notices` → `NoticeSettings`. The body has `enabled`, `format`,
  `events`, `include_reason`, `include_row_count` and, to change the address, `url`.
  Unknown fields are refused. `url` left out or `null` keeps the stored address; `""`
  removes it. An address must be `https`, without a user name, password or fragment,
  at most 2048 bytes, and must not be an address inside the network (see
  [the security model](SECURITY-MODEL.md)). Plain `http` is accepted only to loopback,
  and only with `VDA_ALLOW_PRIVATE_TARGETS`. A host name is not resolved when it is
  saved; it is resolved and checked for every delivery. Turning notices on needs an
  address, at least one event and, for the `webhook` format, a signing secret (400
  `validation` otherwise).

  A change applies to the next state change on every node: the settings are read in the
  transaction that writes a notice. The notices that still wait are made to agree with
  the change, in the same transaction:

  | Change                                     | Notices that wait                         |
  | ------------------------------------------ | ----------------------------------------- |
  | notices turned off, or the address removed | dropped (`notices_off`)                   |
  | another address                            | dropped (`address_changed`)               |
  | another format                             | dropped (`format_changed`)                |
  | an event deselected                        | those of that event dropped (`event_off`) |
  | `include_reason` turned off                | `reason` removed from them                |
  | `include_row_count` turned off             | `affected_rows` removed from them         |

  A dropped notice is never sent: it was written for the settings of its moment. The
  same address sent again is not a change. The audit event `settings.notices` has the
  count as `dropped_notices`. A notice that was already on its way to the old receiver
  when the settings changed is in that count; if that receiver takes it, it is then
  recorded as delivered (and counted in `vda_notices_sent_total` as well), and if not,
  it stays dropped and is not tried again.

- `POST /settings/notices/secret` → `{secret, rotated}`. Makes a new signing secret
  (`vda_whsec_` and 32 random bytes in URL-safe base64) and returns it this one time.
  A secret that was set before stops working at once; notices that wait are signed
  with the new one.
- `POST /settings/notices/test` → `{delivered, status, error}`: a boolean, the HTTP
  status or `null`, and the failure class or `null`. Sends a test notice now to the
  stored address, in the stored format. It never returns a part of the receiver's
  answer. 400 `validation` when there is no address, or no secret for the `webhook`
  format. At most five test notices a minute are sent, for all administrators
  together; after that the answer is 429 `rate_limited` with
  `details.retry_after_seconds`. The count is kept per node. The test notice has
  `event: "notice.test"` and is about no request.

All four answer 409 `settings_unreadable` while the stored settings cannot be read by
this version (a newer version wrote a value it does not know, for example during a
rolling upgrade). In that state the gateway does not treat notices as off: it writes
and sends none, drops none, and does not overwrite the stored value; approvals keep
working.

Failure classes, in `error` and `delivery.last_error`: `http_<status>` (any status
that is not 2xx; a redirect is not followed), `connect`, `tls`, `timeout`,
`not_deliverable` (the host name does not resolve, or resolves to an address a notice
may not go to; one class for both, so the answer does not tell which names exist
inside the network), `protocol`, `invalid_url`, `config` (the stored address or secret
cannot be decrypted), and the four reasons a waiting notice is dropped (table above).

**What is sent.** With `format: "webhook"`, a `POST` with this JSON body:

```ts
interface Notice {
  version: 1;
  event: NoticeEvent | "notice.test";
  time: string; // RFC 3339 with milliseconds, UTC: when the state changed
  // The place of this notice in the order they were written. For one request, a
  // larger number is a later state. Not consecutive; absent from a test notice.
  sequence?: number;
  approval_id: string;
  status: Approval["status"]; // after the change
  cluster: string; // its name
  environment: string;
  engine: "postgres" | "mysql";
  // The display name of the person who asked, which is an email address where
  // names are emails. For an agent's request it is the agent's owner.
  requester: string;
  agent: string | null; // the agent's name when an agent asked
  url?: string; // link to the request; only when VDA_PUBLIC_URL is set
  error_code?: string | null; // only for approval.failed, e.g. "effect_changed"
  reason?: string; // only with include_reason; one line, at most 500 characters
  affected_rows?: number; // only with include_row_count, and when known
}
```

A notice never holds the SQL, a row, a preview, a result or the text of a database
error. `reason` is free text written by a person or an agent, and `affected_rows` is the
count from the dry run (from the run itself after `approval.executed`); both are off
unless switched on. An agent's request has no count until a person previews it. A test
notice has only `version`, `event`, `time` and, when known, `url`.

Names (`cluster`, `environment`, `engine`, `requester`, `agent`) and the reason are
sent as one plain line each: control characters and line breaks become a space, runs
of spaces collapse, characters that change the direction of text are removed, and a
name is cut at 200 characters.

| Header            | Value                                                      |
| ----------------- | ---------------------------------------------------------- |
| `X-VDA-Event`     | the event name                                             |
| `X-VDA-Delivery`  | the notice's id; the same on every attempt                 |
| `X-VDA-Timestamp` | Unix seconds when this attempt was signed                  |
| `X-VDA-Signature` | `v1=` + hex HMAC-SHA256 of `<timestamp>.<delivery>.<body>` |
| `Content-Type`    | `application/json`                                         |
| `User-Agent`      | `vda-notices/1`                                            |

The key of the HMAC is the secret exactly as it was shown, prefix included, as UTF-8
bytes. The message is the `X-VDA-Timestamp` value, a dot, the `X-VDA-Delivery` value,
a dot, and the raw bytes of the body. `v1` names this scheme; a later scheme will have
another prefix. A receiver must: compute the signature over the bytes it received (not
over re-encoded JSON), compare in constant time, refuse a timestamp that is more than
five minutes from its own clock, and remember recent `X-VDA-Delivery` values to drop a
repeat. Because the delivery id is signed, a captured notice cannot be replayed under
another id.

```python
import hashlib, hmac, time

seen = {}  # delivery id -> when it was seen; use a shared store in production


def verify(secret: str, headers, body: bytes) -> bool:
    """True for a notice that is genuine, recent and new. Never raises,
    whatever the three headers hold.

    `headers` is the request's header mapping (its `get` ignores case in the
    usual web frameworks); `body` is the raw request body, as bytes."""
    timestamp = headers.get("X-VDA-Timestamp") or ""
    delivery = headers.get("X-VDA-Delivery") or ""
    given = headers.get("X-VDA-Signature") or ""
    # Unix seconds have 10 digits. A longer number is not a time, and a very
    # long one cannot be compared with the clock at all.
    if not (timestamp.isascii() and timestamp.isdigit() and len(timestamp) <= 12):
        return False
    # The real values are ASCII; anything else could fail to encode below.
    if not (delivery and delivery.isascii() and given.isascii()):
        return False
    now = time.time()
    if abs(now - int(timestamp)) > 300:
        return False
    signed = timestamp.encode() + b"." + delivery.encode() + b"." + body
    expected = "v1=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode(), given.encode()):
        return False
    # Only a verified delivery is remembered, and only for the time window.
    for old in [key for key, at in seen.items() if now - at > 600]:
        del seen[old]
    if delivery in seen:
        return False
    seen[delivery] = now
    return True
```

With `format: "slack"`, the body is a Slack incoming-webhook message, `{text, blocks}`:
one sentence about the event, the link when there is one, and, with the switches, the
reason and the row count. Every value is one plain line (as above) and the characters
`&`, `<` and `>` are escaped in it, so a name or a reason cannot make a mention, a
link or a second line. The sentence is cut to stay under Slack's 3000-character limit
for a section; the link is never cut. Slack does not check signatures, so no `X-VDA-*`
header is sent; the address itself is the secret.

**Delivery.** A 2xx answer is a delivery. Anything else is tried again: six attempts
in about an hour (after 30 s, 90 s, 4.5 min, 13.5 min and 40.5 min, each moved by up
to 20%), then the notice is given up. Delivered notices are removed after 7 days and
given-up ones after 30. The gateway counts `vda_notices_sent_total`,
`vda_notices_retried_total` and `vda_notices_dead_total`.

**Order.** The notices of one request are delivered in the order they were written:
a notice is not sent while an earlier notice of the same request still waits, also
while that earlier one is being retried. If the earlier one is given up, the later
ones go. Notices of different requests are sent side by side and can arrive in any
order. Delivery is at least once: a receiver can get the same `X-VDA-Delivery` again
after a later notice of the same request (a node that stopped before it recorded a
delivery sends it again). A receiver that needs the latest state keeps the largest
`sequence` it has seen for an `approval_id` and ignores smaller ones.

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
