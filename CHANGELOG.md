# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Before 1.0, minor releases may
change the API and storage schema; migrations run automatically at startup.

## [Unreleased]

## [0.2.0] - 2026-11-22

### Added

- Notices to approvers: an outbound webhook, signed or in Slack's format, that
  says a request waits. Off by default; set up under Settings → Notices. A
  notice never holds SQL, rows or database errors. New optional setting
  `VISP_GATE_PUBLIC_URL` adds a link to the request. Migration `0010_notices`.
- Audit events `approval.expire` and, for a write that a lost node left
  running, `approval.failed` with `outcome_unknown`.
- A tamper-evident audit log. Every audit row is sealed into a keyed hash
  chain a few seconds after it is written. A row that is changed, deleted or
  put in afterwards, by someone who has the database but not the master key,
  is found by a background check, by "Verify now" on the Audit screen
  (`GET /audit/integrity`, `POST /audit/verify`) and by the new offline
  command `visp-gate verify-audit`. A link that is relabelled as another
  master key's, to hide a changed row, breaks the chain as well. The head of
  the chain is logged as `audit_checkpoint` (position, hash and key) to keep
  outside the database, and `verify-audit --expect-position … --expect-hash …
--expect-key-id …` checks a saved one. Audit events gain `seq` and
  `sealed`. New metrics `vda_audit_chain_*`. Migration `0011_audit_chain`
  numbers the existing rows; they are sealed in the background. The metadata
  database must be PostgreSQL 14 or newer.
- Audit event `agent_login.status` (`{from, to}`) when the check of a
  cluster's agent login changes its status, written once per change however
  many nodes check.
- A pre-flight bar in the console, always visible next to the Run button: the
  state of the safety check (Safe to run, Needs approval, Blocked), one
  sentence of why, and one next step: run, open the approval request, apply
  the guard's fix, or read who can help. It names exactly what the guard adds
  to the SQL, such as `LIMIT 1001`. The server makes it: the answer of
  `POST /clusters/:id/analyze` gains the field `preflight`, from the same
  lessons that give agents their `fix`, with the caller's access level. Every
  existing field of the answer is unchanged.
- The guard offers a fix for one kind of blocked statement: several
  statements that would each pass alone ("Keep the first statement").
- Agent sessions. The gateway records each tool call of an agent as a step
  (tool, task, SQL text, verdict, outcome, the fix it was given, never result
  rows) and groups the steps of one token into sessions. The owner and
  administrators read them on the agent's screen, where a session that is
  going on updates by itself and "Pause agent" is one click away, and with
  `GET /agents/:id/sessions` and `…/sessions/:id/steps?after=`. Steps are
  kept 30 days (`VISP_GATE_AGENT_STEPS_RETENTION_DAYS`). Migration
  `0012_agent_sessions`. New metrics `vda_agent_steps_*`.
- Agent tool `fetch_rows`: pages through the rows that one `run_query`
  already fetched and masked. `run_query` adds `next_cursor` and `rows_left`
  when its answer could not hold all rows. Nothing runs again and no query
  is taken from the budget. The rows are held in the node's memory only, for
  five minutes, within `VISP_GATE_HELD_RESULTS_MAX_BYTES` and
  `VISP_GATE_HELD_RESULTS_AGENT_MAX_BYTES`. New error code `result_expired`. New
  metrics `vda_held_results*`.

- A five-minute demo. Run this command from the repository root:

  `docker compose -f deploy/demo/docker-compose.yml up --build`

  It starts the gateway, a demo database and an agent that is ready to
  use it, with demo-only passwords and a master key made at the first start,
  on `127.0.0.1` only. `scripts/demo-seed.sh` sets it up through the public
  API. `scripts/demo-agent.sh` plays an agent at the agent door, prints each
  step, and exits non-zero when the gate does not behave as the demo says.
  `docs/DEMO.md` has the steps. `make demo` now starts this demo.

- A threat model (`docs/THREAT-MODEL.md`): the actors, the trust boundaries,
  and for each threat what the gate does, where the code or a test shows it,
  and what remains; with a list of what the gate does not protect against.
- A comparison of approaches (`docs/COMPARISON.md`): direct credentials, a
  read-only role, a generic SQL tool server, an access tool for people, and
  this gate, with when another approach is the better choice.
- The Helm chart and `docker-compose.yml` pass
  `VISP_GATE_AGENT_STEPS_RETENTION_DAYS`, `VISP_GATE_HELD_RESULTS_MAX_BYTES` and
  `VISP_GATE_HELD_RESULTS_AGENT_MAX_BYTES` (chart values
  `config.agentStepsRetentionDays`, `config.heldResultsMaxBytes` and
  `config.heldResultsAgentMaxBytes`).
- A `.dockerignore`, so that an image built in a working copy does not take
  in local build output or `node_modules`.

### Changed

- The product is now named visp-gate. The program, the Docker image and the
  Helm chart (`deploy/helm/visp-gate`) are `visp-gate`, and every setting
  starts with `VISP_GATE_` in place of `VDA_`, for example
  `VISP_GATE_MASTER_KEY`. The earlier names are not read any more. The notice
  headers are `X-Visp-Gate-*` in place of `X-VDA-*`, and the notice user agent
  is `visp-gate-notices/1`.
- The demo starts from the released image
  (`docker compose -f deploy/demo/docker-compose.yml up`). It builds the
  gateway from the checkout when the image cannot be pulled, or with
  `--build`.
- The audit queue is written in batches of up to 256 events in one statement
  instead of one event at a time, so many agents at full rate no longer fill
  it. Retries, dead letters and the drain at shutdown are as before.
- `GET /audit` pages on the last event of a page, not on its time, so an
  audit row with a time that is not a finite time no longer makes a page
  fail. The cursor stays an opaque string.
- The Audit screen shows the details the gateway records. It no longer looks
  for query SQL in an audit event: that is in History.
- The Run button moved from the editor toolbar into the pre-flight bar under
  the editor, and the safety panel no longer repeats the verdict in the
  console. When only an administrator can help, the bar has no button.
- Deleting an agent also deletes its sessions and steps.
- The README leads with the agent safety gate: what it is, the demo, the
  agent tools and the safety layers. Its screenshots show the current
  console, with two new ones: an agent's session and the preview of a write.
  The details of the `demo` profile of `docker-compose.yml` moved to
  `docs/DEPLOYMENT.md`.

## [0.1.0] - 2026-10-10

First public release.

### Added

- Whole-statement SQL analysis for PostgreSQL and MySQL (including MariaDB and
  managed variants), covering CTEs, subqueries and nested writes. Unsupported
  SQL fails closed.
- Read-only access by default; writes need a grant, a permitting policy and,
  by default, four-eyes approval. DDL always needs approval. Approvals expire
  after 24 hours and are claimed once at execution.
- Production protection: statement and lock timeouts, row, byte and
  affected-row caps, an optional `EXPLAIN` cost gate, per-cluster concurrency
  limits, read-replica routing and server-side cancellation.
- Advisory performance suggestions (`SELECT *`, unbounded reads,
  leading-wildcard `LIKE`, non-sargable filters, large `OFFSET`s and `IN`
  lists) with one-click fixes. Suggestions never change the verdict.
- Column masking, including DML `RETURNING`; expiring project and cluster
  grants; organization and cluster network allowlists; an append-only audit
  log with full query history.
- CSV and JSON result export with spreadsheet formula escaping.
- AWS discovery of RDS and Aurora across accounts and regions, with
  credential-verified import and drift detection.
- A single Rust binary with the React console embedded, a PostgreSQL metadata
  store, a distroless Docker image and a Helm chart.

[Unreleased]: https://github.com/visplabs/visp-gate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/visplabs/visp-gate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/visplabs/visp-gate/releases/tag/v0.1.0
