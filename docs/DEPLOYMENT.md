# Deployment and operations

visp-gate ships as one binary (`visp-gate`) with the web console
embedded. Nodes are stateless; all state lives in a PostgreSQL metadata
database. Run as many replicas as you need behind any HTTP load balancer.

## Configuration

All settings are environment variables (each also has a matching CLI flag).
The binary does not load `.env` files itself; see [.env.example](../.env.example)
and [deploy/config.env.example](../deploy/config.env.example).

| Variable                                 | Default        | Purpose                                                                                                                                                                                               |
| ---------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VISP_GATE_DATABASE_URL`                 | required       | PostgreSQL metadata URL, version 14 or newer. Migration privileges are needed on first start.                                                                                                         |
| `VISP_GATE_MASTER_KEY`                   | required       | Standard-base64 32-byte key that encrypts stored credentials. The keys that sign receipts and seal the audit log are derived from it. Generate with `openssl rand -base64 32` or `visp-gate gen-key`. |
| `VISP_GATE_BIND`                         | `0.0.0.0:8080` | Listening address.                                                                                                                                                                                    |
| `VISP_GATE_METADATA_POOL_SIZE`           | `20`           | Metadata connections per node (1–200). Health and discovery schedulers each use one more.                                                                                                             |
| `VISP_GATE_BOOTSTRAP_ADMIN_EMAIL`        | unset          | First administrator, created only when no users exist. Set with the password.                                                                                                                         |
| `VISP_GATE_BOOTSTRAP_ADMIN_PASSWORD`     | unset          | First administrator's password, at least 12 bytes.                                                                                                                                                    |
| `VISP_GATE_ADMIN_PASSWORD`               | unset          | Password for the `create-admin` command.                                                                                                                                                              |
| `VISP_GATE_COOKIE_SECURE`                | `true`         | Secure session cookie and HSTS. Set `false` only for local plain-HTTP development (a startup warning is logged).                                                                                      |
| `VISP_GATE_ALLOWED_CIDRS`                | empty          | Comma-separated client allowlist; intersected with the allowlist set in the console. Empty allows all.                                                                                                |
| `VISP_GATE_TRUST_PROXY_HEADERS`          | `false`        | Use `X-Forwarded-For` for client attribution.                                                                                                                                                         |
| `VISP_GATE_TRUSTED_PROXIES`              | empty          | Comma-separated CIDRs of your proxies. With forwarding on and no list, only the direct peer is trusted. `VISP_GATE_TRUSTED_PROXY_CIDRS` is accepted as an alias.                                      |
| `VISP_GATE_ALLOW_PRIVATE_TARGETS`        | `false`        | Allow loopback database targets (development). RFC 1918 targets are always allowed. For notices it also allows a webhook on a private address, and plain `http` to loopback.                          |
| `VISP_GATE_METRICS_TOKEN`                | unset          | When set, `/metrics` requires `Authorization: Bearer <token>`.                                                                                                                                        |
| `VISP_GATE_PUBLIC_URL`                   | unset          | The address people open the console at, such as `https://gate.example.com`: an `http(s)` origin with no path. Notices link to the request only when it is set.                                        |
| `VISP_GATE_AGENT_STEPS_RETENTION_DAYS`   | `30`           | Days the record of agent steps and sessions is kept (1–3650). Steps hold the SQL text of agent calls.                                                                                                 |
| `VISP_GATE_HELD_RESULTS_MAX_BYTES`       | `268435456`    | Memory, in bytes, that one node may use for rows it holds for `fetch_rows`, for all agents together. `0` holds nothing: agents then get no cursor and narrow their queries.                           |
| `VISP_GATE_HELD_RESULTS_AGENT_MAX_BYTES` | `67108864`     | The same bound for the rows held for one agent. Not more than the bound for the node.                                                                                                                 |
| `VISP_GATE_LOG_FORMAT`                   | `text`         | `text` or `json`.                                                                                                                                                                                     |
| `RUST_LOG`                               | `info`         | Log filter.                                                                                                                                                                                           |

Back up the master key together with the metadata database. Stored credentials
can't be decrypted with a different key; if the key is lost, re-enter each
cluster's password in its settings. The audit hash chain protects the audit
log from people who have the database but not this key, so do not store the
key in the database or where its administrators can read it.

### Policy defaults

Each cluster has a safety policy, editable in the console. Defaults depend on
the environment:

|                      | Production | Other environments         |
| -------------------- | ---------- | -------------------------- |
| Maximum result rows  | 1,000      | 5,000                      |
| Statement timeout    | 15 s       | 60 s                       |
| Writes               | Blocked    | Allowed with a write grant |
| Writes need approval | Yes        | Yes                        |
| DDL                  | Blocked    | Blocked                    |

Both use a 2-second lock timeout, four concurrent queries per node, a
1,000-row affected-row cap and read-replica routing. Hard upper bounds are
100,000 rows, 10-minute timeouts and 32 MiB of result data.

## Commands

```sh
visp-gate serve          # default; applies migrations, then serves
visp-gate migrate        # apply metadata migrations only
visp-gate gen-key        # print a new master key
visp-gate verify-audit   # check the audit hash chain; reads only
VISP_GATE_ADMIN_PASSWORD=… visp-gate create-admin --email you@example.com --name "Your Name"
```

Startup applies migrations and creates the bootstrap admin only if there are no
users, under an advisory lock so concurrent replicas don't race.

## Docker

Each release publishes an image to
`ghcr.io/visplabs/visp-gate:<version>`, plus a Linux x86_64 binary on the
[releases page](https://github.com/visplabs/visp-gate/releases). The image
builds the console and the Rust binary in separate stages and runs as a
non-root user on a distroless base.

```sh
docker pull ghcr.io/visplabs/visp-gate:0.2.0
docker build -t visp-gate .     # or build from source
docker compose up --build            # gateway + metadata Postgres
docker compose --profile demo up     # plus demo PostgreSQL and MySQL targets
```

`docker compose` needs `VISP_GATE_MASTER_KEY` and `VISP_GATE_BOOTSTRAP_ADMIN_PASSWORD` in
the environment. The `demo` profile only starts two databases with sample
shop data; you add them as clusters yourself, with **TLS mode** `disable`
(they have no certificate the gateway can verify) and an environment other
than production if you want to try writes:

| Engine     | Host            | Port | Database | User   | Password          |
| ---------- | --------------- | ---- | -------- | ------ | ----------------- |
| PostgreSQL | `demo-postgres` | 5432 | `shop`   | `demo` | `demo-local-only` |
| MySQL      | `demo-mysql`    | 3306 | `shop`   | `demo` | `demo-local-only` |

For a demo that sets itself up, with an agent and a policy, use
`deploy/demo/docker-compose.yml` instead: see [Demo](DEMO.md). It is for a
look at the product only.

## Kubernetes (Helm)

`deploy/helm/visp-gate` provides a two-replica Deployment, Service,
optional TLS Ingress, HorizontalPodAutoscaler and PodDisruptionBudget. Provide
an existing Secret with `database-url` and `master-key`, and optionally
`bootstrap-admin-email` and `bootstrap-admin-password`.

```sh
helm upgrade --install visp-gate deploy/helm/visp-gate \
  --set existingSecret=visp-gate-secrets
```

The chart uses the published image for its version; set `image.repository`
and `image.tag` to run your own build.

For AWS discovery on EKS, see [IRSA setup](DISCOVERY.md#eks-irsa).

## Health and metrics

- `/healthz` reports process liveness; `/readyz` checks the metadata database
  with a short deadline.
- `/metrics` exports Prometheus request counters, query durations, blocked
  queries and pool gauges. Restrict it at your ingress or set
  `VISP_GATE_METRICS_TOKEN`.
- Cluster health probes run every 30 seconds on one node (elected through a
  PostgreSQL advisory lock), with up to 16 probes in parallel. Health history is
  kept for seven days.
- Notices to approvers are delivered by a worker on every node, which looks
  for due notices every five seconds. `vda_notices_sent_total`,
  `vda_notices_retried_total` and `vda_notices_dead_total` count deliveries,
  failed attempts that will be tried again, and notices that were given up.
  A rising `vda_notices_dead_total` means that the receiver has been failing
  for about an hour; Settings → Notices shows the last error.
- "Send test" is limited to five test notices a minute on each node, for all
  administrators together. Behind a load balancer the total is five times the
  number of nodes.
- Agent steps: `vda_agent_steps_dropped_total` counts steps that were not
  recorded because the queue was full or the metadata database refused them;
  it should stay at zero. `vda_agent_steps_suppressed_total` counts calls
  refused before a tool ran beyond 30 per agent in a minute, which are left
  out on purpose. `vda_agent_step_writer_batch_steps` is the size of the
  batches written.
- Held rows: `vda_held_results` and `vda_held_result_bytes` are what one node
  holds now; `vda_held_results_dropped_total{reason}` counts results dropped
  as `expired`, for `memory`, as `too_large` to hold, because something
  `changed`, because the agent lost its `access` to the database, or because
  the agent or the gateway `stopped`. Many `memory`
  drops mean that agents page through more than the node may hold: raise
  `VISP_GATE_HELD_RESULTS_MAX_BYTES` or lower the policies' `max_rows`.

## Agents on several nodes

The agent door keeps no session, so any node can answer any call. Two things
are kept per node:

- **Rows held for `fetch_rows`.** When a query fetched more rows than one
  answer holds, the rest stays in the memory of the node that ran it, for
  five minutes after the last page. They are never written to the metadata
  database or to disk, so a restart drops them. A `fetch_rows` call that
  reaches another node gets the error `result_expired`, and the agent is
  told to run the query again with a narrower question. Nothing is lost and
  nothing leaks, but the agent pays one more query. To avoid it, route the
  calls of one agent to one node: hash on the `Authorization` header (the
  bearer token) at the load balancer, or use the balancer's source-address
  affinity when each agent has its own address. Affinity is an optimization
  only; do not rely on it for correctness.
- **Limits.** The 120 tool calls a minute, the stop after five refusals and
  the 30 recorded refused calls a minute are counted on each node. Behind a
  balancer without affinity an agent can reach each limit once per node.

What is the same on every node: an agent's access, pause and tokens; its
hourly query budget; and its sessions. The steps of one token are in one
session whichever nodes they went through, because the session is decided in
the metadata database.

Size the memory for held rows with `VISP_GATE_HELD_RESULTS_MAX_BYTES` (per node,
default 256 MiB) and `VISP_GATE_HELD_RESULTS_AGENT_MAX_BYTES` (per agent, default
64 MiB). One held result is at most what one query may fetch: the policy's
`max_rows`, and never more than 32 MiB of row data as the database sent it;
held as JSON values it can take about twice that. A result that is larger
than the agent's bound is not held, and the agent is told to narrow its
query, as before `fetch_rows` existed.

The record of agent steps grows by one row per tool call: at most 150 a
minute per agent and node (120 calls, and 30 calls refused before a tool
ran), each at most about 20 KiB. Steps older than `VISP_GATE_AGENT_STEPS_RETENTION_DAYS`
are deleted by the node that runs health checks, 5,000 per half minute.

## Audit hash chain

Every audit row is sealed into a keyed hash chain, so that a change made in
the database behind the gateway's back shows. What it proves and what it does
not is in the [security model](SECURITY-MODEL.md#a-tamper-evident-audit-log);
the bytes are in the [API reference](API.md#the-audit-hash-chain).

**How it runs.** Every node has a worker that ticks every two seconds. One
node at a time seals (an advisory lock held for the length of one
transaction), in batches of 500 rows and at most 20,000 rows a tick. One node
at a time takes the next step of the background check: 5,000 links a tick,
and a new pass over the whole chain a minute after the last one began. The
check only reads. Nothing needs to be configured.

**Upgrading.** Migration `0011_audit_chain` adds two columns to `audit_log`
and numbers the rows that are there, in one transaction; on a laptop it took
about two seconds for 200,000 rows. The old rows are then sealed in the
background at about 10,000 rows a second, and show as waiting until then.
Older nodes can keep writing during a rolling upgrade: the new columns have
defaults.

**Checkpoints.** A node writes the head of the chain to its log when it
starts, at most every five minutes after that when the head has moved, and
when it shuts down:

```text
INFO vda_server::audit_chain: audit_checkpoint position=48211 hash=5f0c…9a1e key_id=4a1886b932e8ae81
```

`GET /api/v1/audit/integrity` returns the same three values as `head`. Keep
these lines in a log store that the administrators of the metadata database
cannot change. They are the only proof of how long the chain was and which
key sealed its end: without them, someone who removes the newest rows and
their links leaves a shorter chain that verifies, and someone who writes
another key's name on every link from a changed row to the head leaves a
chain that only says "cannot be verified".

**Checking offline.**

```sh
VISP_GATE_DATABASE_URL=… VISP_GATE_MASTER_KEY=… visp-gate verify-audit
VISP_GATE_DATABASE_URL=… VISP_GATE_MASTER_KEY=… visp-gate verify-audit \
  --expect-position 48211 --expect-hash 5f0c…9a1e --expect-key-id 4a1886b932e8ae81
```

The command reads the whole chain and every row it seals in one read-only
snapshot. It does not migrate and writes nothing, so it can run against a
replica or a restored backup, with a read-only database role. With a
checkpoint it also checks that the chain still holds that link: the same hash
at that position and, with `--expect-key-id`, under the same key's name. Give
all three values of the log line; the key's name is optional only so that a
checkpoint noted without it can still be used. On a laptop it checks about
80,000 rows a second. Its exit code:

| Code | Meaning                                                                                                       |
| ---- | ------------------------------------------------------------------------------------------------------------- |
| 0    | Intact: every link verified with this master key (and the checkpoint, if given, is in the chain).             |
| 1    | No verdict: the database could not be reached, the key is missing, or the database has no chain yet.          |
| 2    | Wrong command line.                                                                                           |
| 3    | Broken. The output names the first problem: its kind, the link's position and the audit row.                  |
| 4    | Nothing is wrong, but some links were sealed with another master key and could not be verified with this one. |

Rows that wait to be sealed are reported and are not an error.

**Metrics to alert on.**

| Metric                                    | Alert when                                                                                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `vda_audit_chain_broken`                  | It is 1. The background check, or this node's memory of the head, found a problem. The log has an `audit_chain_break` error with the kind. |
| `vda_audit_chain_oldest_unsealed_seconds` | It stays above a minute or two. Something holds sealing back; rows written meanwhile are not protected.                                    |
| `vda_audit_chain_unverifiable_links`      | It is above 0 and you did not change the master key.                                                                                       |
| `vda_audit_chain_last_pass_age_seconds`   | It keeps growing well past the time a pass takes (about 7 minutes for each million rows). The background check is not running.             |
| `vda_audit_chain_errors_total`            | It keeps rising. Ticks of the worker fail, usually because the database is away.                                                           |

Also exported: `vda_audit_chain_head_position`, `vda_audit_chain_unsealed_rows`,
`vda_audit_chain_sealed_total`, `vda_audit_chain_verified_links_total`,
`vda_audit_chain_passes_total`, `vda_audit_chain_breaks_total` and
`vda_audit_writer_batch_events` (how many queued events one statement wrote).
The gauges are set by every node from the database, so any node can be
scraped.

**When sealing falls behind.** A row is sealed once no transaction with a
lower ID is still open. Look for the oldest open transaction on the
PostgreSQL instance of the metadata database, in any of its databases:

```sql
SELECT pid, datname, usename, state, xact_start, left(query, 80)
FROM pg_stat_activity WHERE backend_xid IS NOT NULL ORDER BY xact_start LIMIT 5;
SELECT gid, prepared, owner, database FROM pg_prepared_xacts ORDER BY prepared;
```

A session that sits `idle in transaction` after a write, a long data load and
a forgotten prepared transaction are the usual causes. Give the metadata
database its own instance, or set `idle_in_transaction_session_timeout`, if
this happens often. Read-only transactions do not hold sealing back.

**When the chain is reported broken.**

1. Do not repair anything in the database. Take a copy of it as it is.
2. Run `verify-audit` against the copy, with the newest checkpoint from your
   log store. The output names the first problem. Rows before that position
   still match the chain; treat that row and everything after it as unproven.
3. Compare the unproven rows with a backup from before the problem, and with
   the query history, which is a separate table.
4. Find out who had access to the metadata database. Treat the master key as
   exposed if the break is `checkpoint_mismatch` because of another hash
   while the links verify: only the key makes links that verify. A
   `checkpoint_mismatch` because the link names another key means links were
   relabelled to hide a change in a row; so does `chain_broken` with
   "relabelled" in its message, and the rows from the start of the run it
   names are the ones to compare.
5. The gateway keeps sealing new rows onto the chain, and keeps reporting the
   break; that is intended. There is no command that resets the chain.

Restoring the metadata database from a backup removes the rows written since
the backup. Nodes that were running report `chain_truncated`, correctly; they
stop after a restart.

**Changing the master key.** The chain key is derived from the master key.
After a change, the gateway logs once that the chain continues with another
key, new links form a new segment, and the old links are reported as not
verifiable (`partial`, exit code 4). Before the change, run `verify-audit`
with the old key and save its head as a checkpoint. Keep the old key offline:
only it can prove that the old rows were not changed. All nodes must run with
the same master key; two keys at once make the segments alternate.

**Rate limit.** "Verify now" (`POST /audit/verify`) is limited to six checks
a minute on each node, for all administrators together.

## Operations notes

- Shutdown is graceful: active queries are cancelled, HTTP requests and queued
  history drain, what can be sealed is sealed and the head of the audit chain
  is logged, pools close and the scheduler lock is released.
- Each node keeps small per-cluster connection pools (up to five connections per
  endpoint). Budget target connections across replicas accordingly.
- Concurrency limits, cancellation and login throttling are per node. Use
  load-balancer affinity so a cancel request reaches the node running the query.
- Runtime network settings are cached for 30 seconds and schema trees for five
  minutes. Notice settings are not cached: a change applies to the next state
  change on every node.
- Notices need outbound HTTPS from the gateway to the webhook's host, and to
  nothing else. The gateway uses the public certificate authorities built into
  the binary; it reads no proxy and no trust store from the environment, so a
  receiver behind a private authority or an outbound proxy cannot be used.
- During a rolling upgrade to a version that stores notice settings an older
  node cannot read, the older nodes pause notices (they write and send none
  and log this once a minute) and answer 409 on the notice settings. The
  outbox is kept and the upgraded nodes deliver it; a state change handled
  by an older node in that time writes no notice.
- At shutdown the notice worker gives the requests on the wire five seconds.
  A notice that was not sent stays in the outbox and is sent by any node.
