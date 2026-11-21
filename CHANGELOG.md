# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Before 1.0, minor releases may
change the API and storage schema; migrations run automatically at startup.

## [Unreleased]

### Added

- Notices to approvers: an outbound webhook, signed or in Slack's format, that
  says a request waits. Off by default; set up under Settings → Notices. A
  notice never holds SQL, rows or database errors. New optional setting
  `VDA_PUBLIC_URL` adds a link to the request. Migration `0010_notices`.
- Audit events `approval.expire` and, for a write that a lost node left
  running, `approval.failed` with `outcome_unknown`.
- A tamper-evident audit log. Every audit row is sealed into a keyed hash
  chain a few seconds after it is written. A row that is changed, deleted or
  put in afterwards, by someone who has the database but not the master key,
  is found by a background check, by "Verify now" on the Audit screen
  (`GET /audit/integrity`, `POST /audit/verify`) and by the new offline
  command `visp-db-access verify-audit`. A link that is relabelled as another
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

### Changed

- The audit queue is written in batches of up to 256 events in one statement
  instead of one event at a time, so many agents at full rate no longer fill
  it. Retries, dead letters and the drain at shutdown are as before.
- `GET /audit` pages on the last event of a page, not on its time, so an
  audit row with a time that is not a finite time no longer makes a page
  fail. The cursor stays an opaque string.
- The Audit screen shows the details the gateway records. It no longer looks
  for query SQL in an audit event: that is in History.

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

[Unreleased]: https://github.com/djkeshawa/visp-db-access/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/djkeshawa/visp-db-access/releases/tag/v0.1.0
