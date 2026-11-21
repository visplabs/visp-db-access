# Security model

visp-db-access sits between people, AI agents and production databases. This
document describes what it guarantees, how, and where its limits are. The
[threat model](THREAT-MODEL.md) looks at the same system from the attacker's
side: who can attack it, what the gate does about each attack, and what is
left over. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What a query goes through

1. **Network gate.** The client IP must be in the organization allowlist and,
   if set, the cluster's allowlist. Forwarded headers are honored only from
   explicitly trusted proxy networks.
2. **Session and access.** Sessions are random tokens stored as SHA-256 digests;
   state-changing requests require a CSRF header. The caller's effective level
   (`read`, `write`, `admin`) is the highest unexpired grant on the cluster or
   its project; organization admins have `admin` everywhere.
3. **Analysis.** `vda-guard` parses the whole statement and classifies every
   nested statement, function and table. The verdict is `allow`,
   `requires_approval` or `deny`. Unsupported SQL fails closed.
4. **Intent recording.** Full SQL, identity, verdict and client IP are committed
   to history before any target I/O. If that write fails, the query is refused.
5. **Limits.** An optional `EXPLAIN` cost gate, a per-cluster concurrency
   permit, and statement, lock, row, byte and affected-row limits.
6. **Guarded execution.** Reads run in a read-only transaction that is always
   rolled back. Writes roll back if they exceed the affected-row cap.
7. **Masking and audit.** Matching columns are masked; the final status is
   recorded synchronously.

## Access and approvals

- Writes require a `write` grant, a policy with `allow_writes`, and by default a
  second person's approval. DDL requires `allow_ddl` and always requires
  approval. Production defaults block writes and DDL entirely.
- A reviewer can never approve their own request. Approvals expire after
  24 hours and are executed through an atomic single-use claim; both the
  requester's and the reviewer's grants are re-checked at execution time.
- Grants can expire, which supports just-in-time access.

## Credentials

- Target database passwords are encrypted with AES-256-GCM under
  `VDA_MASTER_KEY`, authenticated against their cluster's UUID. They are
  write-only in the API and never shown in the console.
- Changing any connection endpoint field requires re-entering the password,
  including connection tests that would otherwise reuse stored credentials.
- User passwords are hashed with Argon2id. Accounts lock for a period after
  ten failed sign-ins within 15 minutes, alongside per-IP throttling.
- AWS discovery stores no AWS keys; see [AWS discovery](DISCOVERY.md).

## SQL guard

The guard walks the full AST, so writes hidden in CTEs, subqueries, set
operations or `EXPLAIN ANALYZE` are classified as writes. It blocks dangerous
functions (sleeps, file access, locks, `dblink`, …), sensitive catalogs,
row-locking reads without the right access, writes without a `WHERE` clause,
and configured blocked tables. On MySQL it also denies executable comments
(`/*! … */`, `/*M! … */`), optimizer hints, session assignments and
maintenance statements, and pins the SQL mode so statement boundaries can't
shift. Permitted `SELECT`s get an outer `LIMIT max_rows + 1` so truncation is
detectable.

The guard does not resolve search paths, inspect user-defined function bodies,
or estimate plans. Database privileges remain the primary control: give
visp-db-access the least-privileged database roles that fit each cluster.

## Masking

Masking is defense in depth, not a substitute for database grants and
restricted views. It applies to returned column names (including
table-qualified patterns when the query references the table), so aliases and
computed expressions can still bypass it. Queries touching potentially masked
tables can't serialize rows through JSON functions, row constructors or
whole-row references, and their upstream error messages are hidden in responses
and history. The same rules cover `RETURNING` on writes, including inside
data-modifying CTEs: renamed or derived masked columns and whole-row returns
are denied.

## Network and targets

- Use TLS at the ingress and to targets, with `verify_full` for hostname
  verification.
- Target addresses are checked when a pool is created and at every health
  check. Metadata, link-local and zero-network addresses, the Azure platform
  address `168.63.129.16`, and every IPv6 form of a prohibited IPv4 address
  (mapped, compatible, translated `::ffff:0:a.b.c.d`, NAT64 including
  local-use `64:ff9b:1::a.b.c.d`, 6to4) are always blocked.
  Loopback targets require `VDA_ALLOW_PRIVATE_TARGETS`.
- The database driver can't separate the connected IP from the TLS hostname, so
  a DNS change between validation and connection remains a rebinding risk.
  Enforce outbound firewall rules as well.
- `/metrics` uses the same network gate as the API and, when
  `VDA_METRICS_TOKEN` is set, requires `Authorization: Bearer <token>`.

## Notices to approvers

A notice tells approvers that a request waits. It is the one place where the
gateway sends something to an address outside it, so it is built to say little
and to reach nothing inside the network. Notices are off until an organization
administrator turns them on.

**What a notice contains.** The event, the time, the request's id and state,
the cluster's name, environment and engine, the display name of the person who
asked, the agent's name when an agent asked, a link when `VDA_PUBLIC_URL` is
set, and the error code of a failed write. Never the SQL, a row, a preview, a
result or the text of a database error: the code that builds a notice has no
access to them. Two fields are off by default, each with its own switch: the
request's reason (free text from a person or an agent, cut at 500 characters)
and the number of rows the write changes. Turn them on only if the receiver
may hold what a reason can contain.

Two of the fields that are always sent name people and software. `requester`
is the display name of the person who asked; where display names are email
addresses, the receiver gets an email address. `agent` is the name its owner
gave the agent. Choose a receiver that may hold both, and treat its channel as
one that shows who works on which database.

The settings are read in the transaction that writes a notice, on every node,
so turning a switch off (or notices off) applies to the very next state change
everywhere, and to the notices that still wait (see below).

Names and the reason come from people and agents, so each is sent as one
plain line: control characters and line breaks become a space, characters
that change the direction of text are removed, and a name is cut at 200
characters. In the Slack format `&`, `<` and `>` are escaped as well, and the
sentence is kept under Slack's limit for a section. A name or a reason cannot
make a mention, a link or a second line.

**Where it goes.** To one address, set by an organization administrator and
stored encrypted with the master key. The API and the console show only that
an address is set and its host. A notice is written for the settings of its
moment: for one receiver, one format, and the private fields that were on
then. When the settings change, the notices that still wait are made to agree
in the same transaction. They are dropped when notices are turned off or the
address or the format changes, so a notice written for one receiver never
reaches another; those of a deselected event are dropped; and a private field
that is switched off is removed from them. The settings row is locked while
this happens, and a state change or a worker that writes or claims a notice
holds the same row shared, so no notice slips past the change.

**What the sender refuses.** The address must be `https` (plain `http` only
to loopback, and only with `VDA_ALLOW_PRIVATE_TARGETS`), with no user name or
password. For every delivery the gateway resolves the host once and refuses
the delivery unless every address of the answer is public. For IPv4 that
excludes loopback, RFC 1918, carrier-grade NAT, link-local and metadata
addresses, documentation, benchmark, relay and reserved ranges, and the Azure
platform address `168.63.129.16`. A plain IPv6 address must be global unicast
(`2000::/3`) and outside the blocks set aside in it (`2001::/23`, which holds
Teredo, benchmarking and ORCHID; documentation `2001:db8::/32` and
`3fff::/20`; `5f00::/16`), so unique-local, site-local, link-local and every
other non-global address is refused. An IPv6 address that stands for an IPv4
one (mapped `::ffff:a.b.c.d`, compatible, translated `::ffff:0:a.b.c.d`,
NAT64, 6to4) is judged by that IPv4 address. All of this holds however the
address is written (`2130706433`, `0x7f.1`). The gateway then connects to an
address it checked, so a second DNS answer cannot move the request, and checks
the certificate against the host name. It follows no redirect, uses no proxy
from the environment, gives up after ten seconds (five to connect), and reads
at most a few kilobytes of the answer, of which it keeps only the status code.
`VDA_ALLOW_PRIVATE_TARGETS` lifts the private ranges for local development;
metadata and link-local addresses stay refused. Enforce outbound firewall
rules as well.

**What the test endpoint tells.** `POST /settings/notices/test` reports a
status code or a failure class for the stored address. An organization
administrator can therefore learn whether a public host answers on a port; it
gives no content. For a host name there is one class, `not_deliverable`,
whether the name does not resolve or resolves to an address inside the
network, so the answer does not tell which internal names exist. (An address
typed as an IP literal is refused when it is saved, with a clear message: the
administrator already knows it.) A node sends at most five test notices a
minute, for all administrators together (429 after that), so it is a slow
probe at best. The limit is kept per node, not across nodes.

**What the receiver must check.** In the `webhook` format every notice is
signed: `X-VDA-Signature` is `v1=` and the HMAC-SHA256 of
`<timestamp>.<delivery id>.<body>` under a secret that the gateway made and
showed once. A receiver must check the signature over the raw body in constant
time, refuse a timestamp more than five minutes from its clock, and drop a
repeated `X-VDA-Delivery`. The delivery id is part of what is signed, so a
captured notice cannot be sent again under another id to get past that check.
The secret is stored encrypted and is never returned again, logged or audited;
rotate it if it may have leaked. The Slack format is not signed: there the
address is the secret.

**Order.** The notices of one request are delivered in the order they were
written, and each carries a `sequence` that grows with every notice. A channel
therefore does not end on "waits for approval" for a request that was since
approved or run because of a retry. The limits: delivery is at least once, so
a repeat of an earlier notice can follow a later one, and notices of
different requests are not ordered against each other.

**Settings that cannot be read.** If the stored settings were written by a
newer version and this one cannot read them, it does not act as if notices
were off. It writes and sends no notice, drops none, refuses to change the
settings (409), and logs the fact once a minute. Approvals keep working.

**What a notice is not.** It is not an approval and carries no authority. The
link leads to the console, where the approver signs in and the usual rules
apply. A lost notice changes nothing about the request; the console is always
the source of truth.

## Agent steps, sessions and held rows

**What is stored about an agent's calls.** The gateway keeps one row per tool
call of an agent, a _step_, and groups the steps of one token into sessions
(a run of calls with no gap longer than 30 minutes). A step holds: the tool,
the task the agent gave, the database, the SQL text when the tool takes SQL
(cut at 16 KiB), the guard's verdict, the outcome code, the fix the agent was
given (the action word and the hint), how many rows the answer held, how long
the call took, and the id of the query history row or the approval request.
Every text of a step is cut to a fixed size when it is written (a step is at
most about 20 KiB), so an agent cannot make the record large with what it
sends. It never holds a result row or a value from one: protected values cannot
reach it. SQL text can itself hold a literal that a person or an agent typed;
that is true of query history as well.

**Who can read it.** The agent's owner and organization administrators, with
`GET /agents/:id/sessions` and `…/steps`: the same rule as for the agent
itself, and "not found" for everyone else, also for a person who administers
the same database. An agent cannot read steps: the agent door has no tool for
them, and the API for people refuses an agent token. A step names a database
by its id only; the console shows a name only for a database the reader can
see.

**How long.** Steps older than `VDA_AGENT_STEPS_RETENTION_DAYS` (default 30)
are deleted. Deleting an agent deletes its sessions and steps at once; the
`agent.tool` audit events and query history stay.

**Not the audit trail.** Steps are written through a queue that drops them
when it is full, and they are not part of the audit hash chain: someone who
can write to the metadata database can change or delete them unseen. What an
agent did is proved by the `agent.tool` audit events and by query history,
which are written as before. Use the steps to understand a session, and the
audit log to prove one.

**Held rows.** `fetch_rows` gives an agent the rows that one `run_query`
fetched and one answer could not hold. It gives no new access:

- The rows are those the query fetched, never more than the policy's cap for
  one query, already masked as the policy was when the query ran. Nothing is
  run or read again for a page.
- They are held in the memory of the node that ran the query, never in the
  metadata database and never on disk, and within byte bounds for the node
  and for each agent. A cursor is refused from five minutes after the last
  use; the memory is freed by a sweep up to 30 seconds after that.
- The cursor is 32 random bytes, usable once, and bound to the agent and to
  the token that ran the query. Only its SHA-256 digest is kept. Another
  agent, another token of the same agent, a used cursor and a guess all get
  the same answer, `result_expired`, which says nothing about whether such a
  cursor ever existed.
- The rows end when the agent's rights do. A pause, a change or a delete of
  the agent, a revoked token, a disabled owner, and a change of the cluster's
  policy (masking included), endpoint or agent login drop them on the node
  that handles the change. On other nodes they are refused on the next page:
  a held result carries the `updated_at` of the agent and of the cluster,
  and both are compared, and the access and network checks of a query are
  repeated, on every page, with the check that the token is still valid.
  Until then the rows stay in that node's memory until the sweep after five
  minutes without use.
- A person with a memory dump of a node can read held rows, as they can read
  a result that is being sent. Set `VDA_HELD_RESULTS_MAX_BYTES=0` to hold
  nothing.

## Audit

Security-relevant changes and their audit records share a metadata transaction.
Query intent and final status are written synchronously. Auxiliary events go
through a bounded 4,096-event queue that waits at most 250 ms per event and may
lose events in a crash; permanent failures log structured `audit_dead_letter`
records. The queue is written in batches of up to 256 events, one statement
each; a batch that the database refuses is written again event by event, so
one bad event does not take the others with it. Records left `running` after
a crash become `unknown` after the maximum statement timeout plus five minutes.

### A tamper-evident audit log

A trigger makes `audit_log` append-only for the gateway's own database role.
It does not stop someone who owns the tables: they can drop the trigger and
change, delete or reorder rows. The hash chain makes that visible.

Every audit row gets a link in `audit_chain`, and each link holds
`HMAC-SHA256` over the row's content, the link's number and the hash of the
link before it, with a key derived from the master key
([API](API.md#the-audit-hash-chain) has the exact bytes). The chain is checked
in three ways: all the time in the background, on request from the Audit
screen, and offline with `visp-db-access verify-audit`
([Deployment](DEPLOYMENT.md#audit-hash-chain)).

**What it detects.** Done by someone who has the metadata database but not
the master key:

- a change to any column of a sealed row, or to its link (`row_changed`);
- a deleted row (`row_missing`), or a deleted, moved or added link
  (`chain_broken`);
- a link relabelled as another key's while a later link of the real key
  remains (`chain_broken`);
- a row put in among sealed rows, for example dated back (`row_inserted`);
- the whole chain thrown away and made again: without the key no link
  verifies.

The check reports the first problem and its position. Rows before that
position still match the chain.

**What it does not detect.** These are limits of the design, not bugs:

- **Someone who has the master key** can make a chain that verifies for any
  content. The key is the root of trust; keep it away from the database.
- **A row that is not sealed yet.** A row is sealed a few seconds after it is
  written, and later when a transaction stays open (below). Until then it can
  be changed or deleted without a trace.
- **A false row that is written the normal way.** The chain proves that a
  sealed row was not changed afterwards. It does not prove who wrote it:
  someone who can insert into `audit_log` can add a row with any actor, and
  it is sealed like any other.
- **The end of the chain cut off.** A chain that lost its newest rows and
  links is a shorter chain that verifies. Only something outside the database
  knows that it was longer: each node remembers the last head it saw and
  reports `chain_truncated` if that link is gone, and each node writes the
  head to its log as `audit_checkpoint`. A log store that the database's
  administrator cannot change is what proves the end. Without it, the newest
  rows are protected only while a node that saw them keeps running.
- **Rows sealed with another master key.** After a key change the old links
  cannot be made again with the new key. Their structure is still checked (no
  missing row, no missing or moved link, and the last old hash is bound by the
  first new link), but a change inside an old row is found only with the old
  key. Such links are reported as `partial`, never as `intact`.
- **Every link of the current key relabelled, from a changed row to the
  head.** The name of the key on a link (`key_id`) is a label outside the
  hash, so someone could change a sealed row and write another key's name on
  its link, to turn "changed" into "cannot be verified". Inside a run of
  links this does not work: each link carries, inside its hash, the position
  where the run of links of its key began, and the first link of the real
  key after the relabelled ones still names the old start while the link
  before it is no longer of its key. That is `chain_broken`, whether one link
  was relabelled, a stretch in the middle, or the whole start of the run. It
  fails only when no link of the current key is left after the relabelled
  ones, that is when every link from the changed row to the head is
  relabelled. This is the same class as cutting the end off, and the same
  thing catches it: the checkpoint carries the `key_id` of the head, a node
  remembers it, and a link that is at the checkpoint's position under
  another key's name is `checkpoint_mismatch`. Without a checkpoint from
  outside it shows only as `partial`. So a `partial` result that no key
  change explains is an alarm, and `vda_audit_chain_unverifiable_links`
  above zero is the metric for it.
- **The stored result of the background check** is a row in the same
  database, written for the console and the other nodes. It is not evidence.
  The chain, the logs and a run of `verify-audit` are.

**The sealing delay.** Rows are written from many connections and nodes with
no lock, so they have no order until they are sealed. The order is the ID of
the inserting transaction, then a sequence number, and a row is sealed only
when every transaction with a lower ID has ended. A transaction that stays
open with an ID assigned, in any database of the same PostgreSQL instance,
therefore holds sealing back for every row written after it. The delay is
shown on the Audit screen and exported as
`vda_audit_chain_oldest_unsealed_seconds`. A row with a forged, far-off
transaction ID is never sealed and shows as a row that waits for ever.

## Known limits

- Concurrency limits, cancellation and login throttling are per node. Use
  load-balancer affinity so cancellation reaches the executing node.
- Approval execution claims stay consumed after a crash; a claim stuck in
  `executing` becomes `failed` with an unknown-outcome message rather than
  replaying.
- The audit hash chain detects changes by someone without the master key,
  and not before a row is sealed. Its end needs a checkpoint kept outside the
  database. See [Audit](#a-tamper-evident-audit-log).
- A notice travels to a third party (the webhook's host). Its names (cluster,
  requester, agent) are metadata that the receiver will hold. The notice
  sender trusts the public certificate authorities only, and a notice can
  arrive twice or, after six failed attempts in about an hour, not at all.
- The record of agent steps is not tamper-evident and can lose steps under
  load; it stores the SQL text of agent calls for 30 days by default. Rows
  held for `fetch_rows` and the limits on an agent's calls are per node; see
  [Agent steps, sessions and held rows](#agent-steps-sessions-and-held-rows).
- MySQL's `max_execution_time` covers only `SELECT`; writes rely on the client
  deadline and lock timeouts. Rollback requires transactional storage (InnoDB),
  MySQL DDL commits implicitly, and a connection lost during `COMMIT` leaves the
  outcome uncertain.
