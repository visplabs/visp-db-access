# visp-gate

**Let AI agents query production. Writes wait for a human.**

A self-hosted gate between AI agents (over MCP) and your PostgreSQL or MySQL
databases. Agents read through a SQL guard with masking and limits. Every
write an agent asks for keeps a human in the loop: it waits until a second
person has seen what it changes.

[![CI](https://img.shields.io/github/actions/workflow/status/visplabs/visp-gate/ci.yml?branch=main&label=CI)](https://github.com/visplabs/visp-gate/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/github/license/visplabs/visp-gate)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/visplabs/visp-gate)](https://github.com/visplabs/visp-gate/releases)
[![Container image](https://img.shields.io/badge/image-ghcr.io%2Fvisplabs%2Fvisp--gate-blue)](https://github.com/visplabs/visp-gate/pkgs/container/visp-gate)

<!-- HERO: replace with docs/images/hero.gif after the redesign -->

![An agent's UPDATE waiting for approval: the two rows it changes, before and after](docs/images/approval-preview.png)

## Quickstart

You need Docker with Compose 2.20 or newer. The demo uses made-up data and
demo-only passwords, on `127.0.0.1` only.

```sh
git clone https://github.com/visplabs/visp-gate.git && cd visp-gate
docker compose -f deploy/demo/docker-compose.yml up
```

When it prints "The gate is running", watch a scripted agent from a second
terminal:

```sh
docker compose -f deploy/demo/docker-compose.yml run --rm agent --follow
```

You see a statement blocked with a hint, a masked column, and an `UPDATE`
that waits. Open <http://localhost:8080/approvals> as `reviewer@example.com`
(password `demo-reviewer-local-only`), preview the write, read the three rows
it changes, and approve it. The agent prints "changed 3 rows". The
[demo guide](docs/DEMO.md) has every step.

### Connect your own agent

The gate is an MCP server (Streamable HTTP) at `/api/v1/mcp` that takes an
agent token. The demo prints one; in your own installation, create one under
**Agents → Connect an agent** in the console. No database password appears
in any MCP config.

Claude Code:

```sh
claude mcp add --transport http visp-gate http://localhost:8080/api/v1/mcp \
  --header "Authorization: Bearer vda_agent_…"
```

Cursor (`.cursor/mcp.json`) and other clients that take a URL and headers:

```json
{
  "mcpServers": {
    "visp-gate": {
      "url": "http://localhost:8080/api/v1/mcp",
      "headers": { "Authorization": "Bearer vda_agent_…" }
    }
  }
}
```

## Why not just a read-only role?

Use one: a read-only role or read-only replica is enforced by the database,
and the gate sits on top of it. On its own, a role does not:

- **keep personal data out of the model's context.** The gate masks
  protected columns and hides blocked tables.
- **stop runaway queries.** The gate adds a row cap, timeouts, a call rate
  and an hourly query budget.
- **say which agent ran what, and why.** Every query is kept in history
  with the agent, its owner and its task. An audit event for each query and
  tool call is sealed into a hash chain; the SQL text itself is not.
- **let an agent prepare a change.** An agent proposes a write; a person
  sees the affected rows and approves it.

## What an agent can and cannot do

Nine tools, none of them "run any SQL". An agent never holds a database
password and never does more than its owner can, on the databases its owner
chose: a small blast radius by design.

| Tool             | What it does                                                      |
| ---------------- | ----------------------------------------------------------------- |
| `list_databases` | The databases this agent can reach, and its level on each         |
| `search_schema`  | Find tables and columns by name; blocked tables are left out      |
| `describe_table` | The columns of a table, with the masked ones marked               |
| `check_sql`      | Ask whether a statement would be allowed, without running it      |
| `run_query`      | Run one guarded read; masked columns come back as `••••••`        |
| `fetch_rows`     | Read the next rows of a result; nothing runs again                |
| `propose_write`  | Ask a person for one `INSERT`, `UPDATE` or `DELETE`; nothing runs |
| `get_approval`   | Follow a request: pending, approved, executed, rejected           |
| `withdraw`       | Take a request back                                               |

## Safety layers

- **SQL guard.** Parses the whole statement, CTEs included; refuses what it
  does not understand.
- **Limits.** Row cap, statement and lock timeouts, a byte cap, and a call
  rate and hourly budget per agent.
- **Masking and blocked tables**, per database. On PostgreSQL an optional
  agent login makes the database itself refuse what the policy hides.
- **Refusals that teach.** Each refusal tells the agent what to do next; five
  in a row stop it for up to ten minutes.
- **Four-eyes approval for every agent write.** On PostgreSQL a rolled-back
  dry run shows the rows before and after, the write runs only on those rows,
  and it leaves a signed receipt.
- **Pause and record.** Pausing an agent refuses its next call and cancels
  its running queries on that node. Every query is recorded with the agent's
  task.

Limits: the gate caps the blast radius of a prompt-injected agent; it does
not detect injection, and an agent with its own credentials goes around it.
Read the [threat model](docs/THREAT-MODEL.md).

## Compared with other tools

As of 2026-11-25; the [comparison](docs/COMPARISON.md) has more rows and
where each tool is stronger.

|                                      | Human approval of agent writes | Row-level preview of a write  | Nothing paywalled                 |
| ------------------------------------ | ------------------------------ | ----------------------------- | --------------------------------- |
| [Bytebase](https://www.bytebase.com) | Yes, change review             | No, SQL review                | No: MIT core + enterprise edition |
| [Kviklet](https://kviklet.dev)       | Yes, four-eyes review          | Dry run; row diff not checked | No: MCP server is enterprise-only |
| [hoop.dev](https://hoop.dev)         | Yes                            | No                            | No: approvals are enterprise-only |
| DBHub, Postgres MCP Pro              | Not checked                    | No                            | Yes (MIT)                         |
| visp-gate                            | Yes, by someone not the owner  | Yes, on PostgreSQL            | Yes (Apache-2.0)                  |

## Screenshots

| An agent's session, call by call                | The console's safety check before a query runs            |
| ----------------------------------------------- | --------------------------------------------------------- |
| ![Agent session](docs/images/agent-session.png) | ![Console with the safety check](docs/images/console.png) |

## Install

One binary with the console built in. State lives in a PostgreSQL metadata
database (14 or newer). Keep the 32-byte master key in a secret manager and
back it up with that database.

```sh
docker run -p 8080:8080 \
  -e VISP_GATE_DATABASE_URL='postgres://…' \
  -e VISP_GATE_MASTER_KEY \
  -e VISP_GATE_BOOTSTRAP_ADMIN_EMAIL=you@example.com \
  -e VISP_GATE_BOOTSTRAP_ADMIN_PASSWORD \
  ghcr.io/visplabs/visp-gate:0.2.1 serve
```

Kubernetes, with the chart in this repository:

```sh
helm upgrade --install visp-gate deploy/helm/visp-gate \
  --set existingSecret=visp-gate-secrets
```

Put TLS in front, then add a database under **Clusters → Add cluster**.
[Deployment](docs/DEPLOYMENT.md) has the details.

## Documentation

| Topic                                    |                                                        |
| ---------------------------------------- | ------------------------------------------------------ |
| [Demo](docs/DEMO.md)                     | The demo, step by step, and connecting an MCP client   |
| [Threat model](docs/THREAT-MODEL.md)     | What the gate protects against, and what it does not   |
| [Security model](docs/SECURITY-MODEL.md) | Guarantees, layers and known limits                    |
| [Comparison](docs/COMPARISON.md)         | Other approaches and named tools, and when to use them |
| [HTTP API](docs/API.md)                  | The v1 API, the MCP endpoint and its tools             |
| [Architecture](docs/ARCHITECTURE.md)     | Components, data model and query pipeline              |
| [Deployment](docs/DEPLOYMENT.md)         | Configuration, Docker, Helm, health and metrics        |
| [AWS discovery](docs/DISCOVERY.md)       | Finding and importing RDS and Aurora databases         |
| [Development](docs/DEVELOPMENT.md)       | Local setup, tests and smoke tests                     |

## Status and roadmap

Pre-1.0: the API and storage schema may change between releases. It
supports PostgreSQL and MySQL (with MariaDB, RDS, Aurora, Cloud SQL and Azure
Database). MySQL writes are approved without a row preview.

Planned: OIDC/SAML single sign-on, just-in-time access requests, SIEM export,
RDS IAM authentication, and more engines and clouds. See the
[changelog](CHANGELOG.md).

## Community and security

Questions and bugs go to [issues](https://github.com/visplabs/visp-gate/issues).
Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as
[SECURITY.md](SECURITY.md) describes.

## License

<!-- OWNER: confirm this promise before launch -->

[Apache License 2.0](LICENSE). Nothing is held back for a paid edition. See
[NOTICE](NOTICE) for attributions.
