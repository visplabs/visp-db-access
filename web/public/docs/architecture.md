# Architecture

A self-hosted gateway that lets engineers query production databases **safely**:
every statement is parsed, checked against the caller's access level and the
cluster's policy, rewritten with hard limits, executed inside a guarded
transaction, masked, and audited. Engineers never see credentials.

## Goals

1. **Safe by construction** — read-only by default; writes need an explicit
   grant, a policy that allows them, and (by default) a second person's approval.
2. **No production harm** — statement/lock timeouts, row and byte caps, cost
   gate via `EXPLAIN`, per-cluster concurrency limits, read-replica routing,
   server-side cancellation.
3. **One app for every database** — PostgreSQL and MySQL (including MariaDB,
   RDS, Aurora, Cloud SQL, Azure Database, AlloyDB and self-hosted); the engine
   layer is an enum so more engines can be added.
4. **Easy to deploy and scale** — one static binary with the UI embedded;
   stateless app nodes; all state in a Postgres metadata store; health checks
   leader-elected via advisory lock so N replicas don't multiply load.
5. **Strict Rust** — `unsafe_code = "forbid"`, no `unwrap`/`expect`/`panic` in
   non-test code (workspace lints).

For the threat model and limits, see [Security model](SECURITY-MODEL.md).

## Components

```
            ┌──────────────── browser (React SPA, embedded) ───────────────┐
            │  console · schema explorer · approvals · audit · admin       │
            └──────────────────────────────┬───────────────────────────────┘
                                           │ HTTPS, session cookie
┌──────────────────────────────────────────▼───────────────────────────────────┐
│ vda-server (axum)                                                            │
│  network gate (CIDR allowlist) → auth (session) → RBAC (grants)              │
│  → query pipeline (vda-core, shared by every door into the gateway):         │
│      vda-guard::analyze  → cost gate (EXPLAIN) → concurrency permit          │
│      → vda-connectors::execute_* (guarded txn) → masking → audit/history     │
│  approvals · policies · clusters/projects · users · health scheduler         │
│  secrets (AES-256-GCM) · metrics (/metrics) · /healthz /readyz               │
└───────────┬─────────────────────────────────────────────┬────────────────────┘
            │ sqlx (metadata)                             │ sqlx pools per cluster
     ┌──────▼──────┐                          ┌───────────▼──────────────────┐
     │ Postgres    │                          │ target DBs (AWS/GCP/Azure/…) │
     │ metadata    │                          │ primary + optional replica   │
     └─────────────┘                          └──────────────────────────────┘
```

### crates/vda-guard (pure, no I/O)

SQL safety engine built on `sqlparser`. Input: SQL text, dialect, caller access
level, policy. Output: per-statement classification, referenced tables and
functions, issues (with severity + stable code), risk level, overall verdict
(`allow` / `requires_approval` / `deny`), and a rewritten SQL with an enforced
`LIMIT`. Walks the **whole AST** (CTEs, subqueries, set operations) so a
`WITH x AS (DELETE …) SELECT …` is a write, not a read.

### crates/vda-connectors (I/O to target DBs)

`TargetPool` enum over sqlx Postgres/MySQL pools. Executes reads in a
`READ ONLY` transaction with `SET LOCAL statement_timeout / lock_timeout`
(MySQL: `SET SESSION TRANSACTION READ ONLY`, `max_execution_time`,
`innodb_lock_wait_timeout`), streams rows and stops at the row/byte cap, always
rolls back. Writes run in a transaction that is rolled back if affected rows
exceed the cap. Cancellation kills the query server-side
(`pg_cancel_backend` / `KILL QUERY`). Also: health probe, `EXPLAIN` cost,
schema introspection, connection test.

### crates/vda-discovery (cloud inventory)

A `Provider` trait (`test`, `scan`) returning normalized database records. The
AWS implementation is described [below](#cloud-discovery-aws-rds--aurora).

### crates/vda-core (the query pipeline)

Everything that decides and runs a query, with no router and no request
handlers: effective access from grants, the cluster policy, the guard call,
masking, the cost gate, target pools and the concurrency permit, cancellation,
and the durable audit intent. A caller builds an `Actor` (who is asking) and
calls `query::analyze` or `query::run`. The web console is the first caller;
any other door into the gateway uses the same functions, so the rules cannot
differ between them.

An `Actor` can carry an agent scope. Access is then the owner's access, narrowed
to the agent's clusters and capped at its level (`access::narrow`). `agents`
resolves a bearer token to such an actor; only the token's SHA-256 digest is
stored.

`teach` turns any refusal into one `fix` object: a stable action word and a
plain hint. Each issue code has one lesson there, with the words for an agent
and the words for a person side by side. `teach::preflight` makes the
console's pre-flight answer from the same lessons, the verdict and the
person's access level: a state, one sentence and one next step. So the bar
next to the Run button and the `fix` an agent reads cannot disagree. The
agent door (`vda-server/src/mcp.rs`) is a Model Context Protocol endpoint over
plain HTTP POST with nine tools. It keeps no session, so it works behind any
load balancer. Each tool calls the same `vda-core` functions as the console,
with the agent's `Actor`.

`judge` makes the target database the last word for agents. A PostgreSQL
cluster can have an agent login with column grants for exactly what the policy
allows. `judge::script` writes the SQL for a database administrator;
`judge::verify` connects as that login and asks PostgreSQL's own privilege
functions what it can do; `judge::require` refuses an agent's query when the
answer is more than the policy. The gateway holds no administrative power on
the target. The text guard stays as the fast first check.

### crates/vda-server (binary `visp-db-access`)

axum HTTP API + embedded SPA. Metadata in Postgres (sqlx migrations). Owns
authn/z, pool cache, policies, approvals, audit, health and discovery
schedulers, notices to approvers, metrics.

`steps` is the gateway's own record of what agents do, and `held` keeps the
rows that `fetch_rows` hands out; both are described
[below](#agent-steps-sessions-and-held-rows).

### web/ (React + TypeScript + Vite)

Built to `web/dist`, embedded into the server binary with `rust-embed`.

## Data model (metadata store)

- `users` (id, email, name, password_hash argon2id, org_role admin|member, disabled)
- `sessions` (token_hash sha256, user_id, expires_at, ip, user_agent)
- `projects` (id, name, description)
- `clusters` (id, project_id, name, engine, provider, region, environment,
  host, port, database, username, password_enc, tls_mode, replica_host,
  replica_port, tags jsonb)
- `cluster_policies` (cluster_id PK, policy jsonb)
- `grants` (id, user_id, scope project|cluster, scope_id, level read|write|admin,
  expires_at, created_by)
- `approvals` (id, cluster_id, requester_id, sql, reason, analysis jsonb,
  status pending|approved|rejected|executing|executed|failed|expired,
  reviewer_id, review_note,
  result jsonb, timestamps)
- `query_history` (id, cluster_id, user_id, sql, verdict,
  status running|unknown|ok|blocked|error|cancelled,
  row_count, elapsed_ms, error, created_at)
- `health_checks` (cluster_id, status, latency_ms, server_version, is_replica,
  details jsonb, checked_at) — retained 7 days
- `agent_sessions` (id, agent_id, token_id, started_at, last_step_at, steps,
  refusals, first_task) — a run of calls of one agent token
- `agent_session_heads` (token_id PK, session_id) — the session a token is in;
  the row that the writer of steps locks
- `agent_steps` (session_id, n, id, tool, task, cluster_id, sql, sql_truncated,
  verdict, outcome, fix_action, fix_hint, row_count, elapsed_ms, history_id,
  approval_id, created_at) — one tool call; SQL text, never rows; retained 30
  days by default
- `audit_log` (id, actor_id, action, target_type, target_id, ip, details jsonb, created_at,
  seq, txid) — append-only; `txid` is the inserting transaction, `seq` a sequence number
- `audit_chain` (position, audit_id, txid, seq, key_id, segment_start, prev_hash, hash,
  sealed_at)
  — append-only; one link per sealed audit row, in the order `(txid, seq)`
- `audit_verification` (one row: where the background check is and what its last
  pass found)
- `settings` (key, value jsonb) — org network policy, notice settings
- `notices` (id, seq, approval_id, event, payload jsonb,
  status pending|sent|dead, attempts, next_attempt_at, last_error,
  last_attempt_at, created_at, sent_at)
  — the outbox of notices to approvers; sent rows kept 7 days, dead rows 30
- `discovery_sources`, `discovery_runs`, `discovered_resources` — AWS sources,
  scan history and inventory (see below)

## Access model

- Org role `admin`: manage everything, implicit `admin` on every cluster.
- Grants on a **project** (all its clusters) or a **cluster**; effective level
  = max of unexpired grants. Levels:
  - `read` — SELECT / EXPLAIN / SHOW under policy limits.
  - `write` — may submit DML; executed only if policy `allow_writes`, and via
    approval if `require_approval_for_writes` (default true in production).
  - `admin` — manage cluster policy and grants; DDL only if policy `allow_ddl`,
    always via approval.
- Four-eyes: an approver can never approve their own request.
- Grants can expire (just-in-time access).

## Query pipeline (`POST /api/v1/clusters/:id/query`)

1. Network gate: client IP ∈ org CIDRs ∩ cluster CIDRs (if set).
2. Session → user → effective access level (403 if none).
3. `vda_guard::analyze(sql, dialect, level, policy)`.
   - `deny` → 422, recorded as `blocked` in history + audit.
   - `requires_approval` → 409 `approval_required` (UI offers "Request approval").
4. Reads: optional cost gate (`EXPLAIN`, compare to `policy.max_cost`).
5. Acquire per-cluster semaphore permit (`max_concurrent_queries`), 429 if saturated
   after a short wait.
6. Route to replica if `route_reads_to_replica` and a replica is configured & healthy.
7. Execute with limits; cancellable via `POST /api/v1/queries/:query_id/cancel`.
8. Apply column masking; record history + audit; return result.

## Audit hash chain (sealer and verifier)

The audit log is written from many connections and nodes with no lock: inside
the transaction of a change, and by the queue writer in batches. The chain is
built afterwards, so writers never wait for it.

- **Order.** `audit_log.txid` defaults to `pg_current_xact_id()` and `seq` to a
  sequence. The chain order is `(txid, seq)`. A row may be sealed when
  `txid < pg_snapshot_xmin(pg_current_snapshot())`: every transaction with a
  lower ID has ended, so no row that sorts before it can still be committed.
  The rows below that limit are read in the same statement that takes the
  snapshot. The cost is a delay while any transaction on the PostgreSQL
  instance stays open with an ID.
- **Sealer** (`vda_core::chain::seal`). One transaction per batch: take an
  advisory lock for the transaction, read the head, read the next rows in
  order, compute `hash = HMAC(chain key, label ‖ position ‖ segment start ‖ prev hash ‖ row)`
  and insert the links. The append is atomic with the head it read. Two
  sealers cannot extend the same head: the lock keeps them apart, and the
  primary key on `position` would refuse the second commit.
- **Verifier** (`vda_core::chain::verify`). Walks links in order with their
  rows and reports the first problem and its position: a changed row, a
  missing row, a missing or moved link, or a row without a link among sealed
  rows. Links of another key are checked for structure and reported as not
  verified. The key's name on a link is a label outside the hash, so each
  link carries inside its hash the position where the run of links of its
  key began (`segment_start`): a link that verifies but does not follow a
  link of its key, without being the start of its run, proves that a link
  before it was relabelled. It only reads. The same function serves the background check, the
  `POST /audit/verify` endpoint and the `verify-audit` command.
- **Worker** (`vda-server/src/audit_chain.rs`). Every node ticks every two
  seconds: seal, refresh the gauges, check that the head it remembers is still
  in the chain, take the next slice of the background pass (progress and result
  are stored in `audit_verification`, so any node continues it), and log the
  head as `audit_checkpoint`. It stops with the gateway; a tick that fails is
  logged and tried again.

## Notices to approvers (outbox and worker)

Approvers learn that a request waits through one outbound webhook
(`crates/vda-server/src/notices/`).

- **Outbox.** Every state change of a request (`created`, `previewed`,
  `approved`, `rejected`, `withdrawn`, `executed`, `failed`, `expired`) calls
  `notices::enqueue` on the transaction that makes the change. It reads the
  notice settings on that transaction (one row by its key, never a cache), so
  a change of the settings on one node applies to the next state change on
  every node. When notices are on and the event is selected, it builds the neutral payload from a
  fixed list of columns (no SQL, preview, result or error text) and inserts a
  `notices` row. The row commits or rolls back with the state change; nothing
  is sent in a request handler.
- **One place for expiry and recovery.** A request expires in
  `approvals::expire_due`, and a write that a lost node left running is failed
  in `approvals::fail_abandoned`. Lists, single reads, the agent door and the
  scheduler all call these. Each locks the due rows in id order and writes one
  audit row and one notice per request that it changed, so concurrent callers
  never write twice.
- **Worker.** Every node runs `notices::worker`. Every five seconds it claims
  up to eight due rows with `FOR UPDATE SKIP LOCKED` and, in the same
  statement, moves their next attempt one minute ahead. That lease keeps two
  nodes from sending the same notice at once without holding a transaction
  open during a request. It sends four at a time, then marks each row `sent`,
  schedules the next attempt (30 s × 3ⁿ ± 20%, six attempts in about an hour)
  or marks it `dead`. Delivery is at least once.
- **Order.** Each row has a `seq` from one sequence. A row can be claimed only
  when no row of the same request with a smaller `seq` is still `pending`, so
  a notice that is on the wire or waiting for a retry holds back the later
  notices of its request, and requests do not hold each other back. The
  webhook body carries `seq` as `sequence`.
- **Cost of a claim.** A claim reads the due rows in the order of the
  partial index `notices_due(next_attempt_at, seq)` and asks for each, with
  one probe of `notices_waiting(approval_id, seq)`, whether an earlier row of
  its request still waits; it stops at eight. So that it reads about eight
  rows however many wait, a row behind a waiting one is not left due: when
  an attempt fails, the later rows of the request get the time of its next
  attempt, and a row written behind one that waits longer than a lease
  starts with that time. That time only saves reading; the rule above
  decides what may be sent.
- **Settings and the outbox agree.** A change of the settings locks the
  `notices` settings row, stores the new value and, in the same transaction,
  drops or edits the rows that still wait (`notices::api::clean_outbox`). A
  state change that writes a row and a worker that claims rows hold that row
  shared while they do, so each happens wholly before a change or wholly
  after it. A value that this version cannot parse means "unknown": nothing
  is written, sent or dropped, and the API answers 409.
- **Sender.** `notices::send` makes one HTTP/1.1 request on a connection it
  opens itself (hyper's connection API over tokio-rustls), to an address it
  resolved and checked. There is no client pool, redirect handling or proxy
  support to configure away. See [the security model](SECURITY-MODEL.md).
- **Shutdown.** The worker stops after the HTTP server and the schedulers
  (`main.rs`), gives requests on the wire five seconds, and leaves the rest in
  the outbox.

## Agent steps, sessions and held rows

**Steps and sessions** (`vda-server/src/steps.rs`). The agent door keeps no
session and the agent sends nothing extra, so the gateway makes its own.

- **On the call path.** `mcp::call` times the call, runs it, and hands one
  `Step` to `Recorder::record`, which is a `try_send` into a queue of 4,096.
  It never waits and never fails the call; a full queue drops the step and
  counts it. A call that is refused before a tool runs is recorded too, at
  most 30 per agent in a minute.
- **Writer.** One task per node takes up to 256 steps, waiting at most a
  quarter of a second for more, and writes them in one transaction
  (`steps::persist`): hold the agents' rows (`FOR KEY SHARE`),
  make sure each token has a row in `agent_session_heads`, lock those rows in
  id order, and only then read each token's session. A step continues the
  session when it arrived no more than 30 minutes after the session's last
  step; otherwise it starts a new one. The steps get the numbers after the
  session's count. The lock is taken in a statement of its own, because a
  statement that waits for a lock goes on with the snapshot it began with.
- **Why two nodes agree.** A session is decided while the token's head row is
  locked, from what is committed. The second writer waits, then sees the
  first one's session and count. The order agents → heads is the order in
  which a delete of an agent takes them, so the two cannot deadlock.
- **Reading.** `GET /agents/:id/sessions` and `…/steps?after=n` serve the
  console, which asks every three seconds for the steps after the last one
  it has while the session is going on and the page is visible. There are no
  server-sent events.
- **Pruning** is part of the leader's maintenance cycle, like health history:
  5,000 old steps and 500 empty sessions per pass.

**Held rows** (`vda-server/src/held.rs`). `run_query` fetches up to the
policy's row cap and masks the rows; one answer holds fewer. The rest stays
in a map in the node's memory, keyed by the SHA-256 of a random cursor, with
the agent, the token, and the `updated_at` of the agent and of the cluster as
they were. `fetch_rows` takes the entry out, checks those marks and the
agent's access again, hands out a page and puts the rest back under a new
cursor. Nothing is written anywhere, and no database is asked again. The map
is bounded in bytes for the node and for each agent, oldest first, and a
sweep every 30 seconds drops what was not used for five minutes. The two
marks are how a pause or a policy change on one node ends the rows held on
another: they are compared on every page, with values that
`agents::authenticate` and the access check read anyway.

## Scaling & deployment

- Stateless nodes behind any L7 load balancer; sessions in Postgres.
- Health scheduler runs on whichever node holds `pg_try_advisory_lock`.
- The notice worker runs on every node; rows are claimed with `SKIP LOCKED`.
- The audit chain worker runs on every node; sealing and the background check
  are each done by one node at a time, under an advisory lock.
- The writer of agent steps runs on every node; sessions are decided in the
  metadata database, under a row lock per token.
- Rows held for `fetch_rows` are in the memory of the node that ran the
  query. A page that reaches another node gets `result_expired`; route an
  agent's calls to one node to avoid that (see
  [Deployment](DEPLOYMENT.md#agents-on-several-nodes)).
- Per-node pool cache (moka, idle eviction); pool sizes are small by default
  (`max_connections=5` per cluster per node) to protect production.
- Deploy: Docker image (distroless), docker-compose for single host, Helm chart
  for Kubernetes.

## Cloud discovery (AWS RDS / Aurora)

`crates/vda-discovery` defines a `Provider` trait (`test`, `scan`) returning
normalized `DiscoveredDb` records; the AWS implementation uses `aws-config`
(default credential chain) + `aws-sdk-sts` (AssumeRole with external ID,
session name `visp-db-access`, 1 h) + `aws-sdk-rds` (`DescribeDBInstances`,
`DescribeDBClusters`, paginated, regions scanned concurrently with a small
bound). The server stores sources, scan runs and discovered resources; the
leader node (same advisory-lock pattern as health checks) runs due scans.
Scans upsert by ARN, mark unseen resources `gone`, and compute drift against
imported clusters. Import is always an explicit admin action because
database credentials are required; discovered endpoints pass the same SSRF
guard as manual clusters.

Minimal IAM policy for the gateway identity / assumed role:
`rds:DescribeDBInstances`, `rds:DescribeDBClusters` (+ `sts:AssumeRole` on the
gateway identity for cross-account roles). No write permissions are used.

Setup and operations are covered in [AWS discovery](DISCOVERY.md).

## Roadmap

RDS IAM authentication; GCP Cloud SQL and Azure discovery; OIDC/SAML SSO and
SCIM; group grants; just-in-time access requests; saved queries; distributed
query cancellation; durable audit delivery and SIEM export;
classification-driven masking; MongoDB and SQL Server engines; SSH/bastion
tunnels.
