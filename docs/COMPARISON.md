# How this compares with other approaches

There are several ways to let an AI agent work with a production database.
This page first compares approaches, then [named tools](#named-tools), as of
one date. Products change, and a claim about one can be out of date the day
after it is written: check any product you consider against the rows of the
tables.

The five approaches:

- **A. Direct credentials.** The agent gets a connection string for a login
  that people or services also use.
- **B. A read-only role or a read replica.** The agent gets its own login
  that can only read, often on a replica.
- **C. A generic SQL tool server.** A small server gives the agent a tool
  such as "run this SQL", over the Model Context Protocol or a similar
  interface, and holds the connection string itself.
- **D. An access tool built for people.** A database proxy, a bastion or an
  access-management product that gives engineers sessions, with approval of
  access and a record of the session.
- **E. This gate.** visp-gate between the agent and the database.

## The table

"Yes" means the approach gives you the property by its nature. "You build it"
means it is possible and the work is yours. "Varies" means some tools of this
kind do it and some do not.

| Property                                         | A. Direct credentials     | B. Read-only role or replica         | C. Generic SQL tool server   | D. Access tool for people             | E. This gate                                                                                                     |
| ------------------------------------------------ | ------------------------- | ------------------------------------ | ---------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| The agent cannot write on its own                | No                        | Yes, enforced by the database        | Varies; often a setting      | Varies; by the login it hands out     | Yes. Every write by an agent needs a person.                                                                     |
| A cap on rows per query                          | No                        | No                                   | Varies                       | Rarely                                | Yes: the guard adds a limit, and execution stops at the cap                                                      |
| Time, lock and concurrency limits                | Only what the role has    | Only what the role has               | Varies                       | Varies                                | Yes, per database; concurrency is counted on each node                                                           |
| Column masking                                   | You build it, with views  | You build it, with views or grants   | Rarely                       | Varies                                | Yes, by column name. Read [its limits](THREAT-MODEL.md#a-prompt-injected-agent).                                 |
| Blocked tables                                   | You build it, with grants | Yes, with grants                     | Varies                       | Varies                                | Yes, by name; a view can leak without the agent login. With an agent login the database enforces it (PostgreSQL) |
| A refusal the agent can act on                   | A database error          | A database error                     | Usually the database's error | Usually a denied session              | Yes: each refusal has an action word and a hint                                                                  |
| A person approves each write, with a row preview | No                        | No writes at all                     | Rarely                       | Approval of access, not of each write | Yes on PostgreSQL: a dry run shows the rows; the write is bound to them                                          |
| A stop that takes effect at once                 | Change the password       | Change the password or drop the role | Stop the server              | Usually: end the session              | Yes: pause the agent; its running queries are cancelled on that node                                             |
| Identity and record per agent                    | No, a shared login        | Per role, if each agent has its own  | Varies                       | Per person; agents are rarely known   | Yes: each agent has an owner, tokens, sessions, a task for every call                                            |
| Evidence that the record was not changed         | No                        | No                                   | No                           | Varies                                | A keyed hash chain over the audit log. Read [its limits](SECURITY-MODEL.md).                                     |
| The agent never holds a database password        | No                        | No                                   | Yes                          | Varies                                | Yes                                                                                                              |
| Enforced by the database, not by reading SQL     | Yes                       | Yes                                  | No                           | Varies                                | Partly: with the agent login on PostgreSQL; else the guard reads SQL                                             |
| Works with any SQL the database accepts          | Yes                       | Yes, for reads                       | Yes                          | Yes                                   | No. SQL that the guard does not understand is refused.                                                           |
| Effort to run                                    | None                      | Low: a role, perhaps a replica       | Low: one process             | Medium to high                        | Medium: one service and a PostgreSQL metadata database                                                           |
| Cost                                             | None                      | The replica, if you add one          | Usually free                 | Varies; many are paid                 | Free and self-hosted. You run and update it.                                                                     |

## What you give up with this gate

- **One more service in the path.** If the gateway is down, agents cannot
  reach the database through it, and every query passes its checks first.
- **Less SQL.** The guard refuses what it cannot parse or does not support,
  and some safe statements with it. Functions defined in your database are
  not inspected, and on PostgreSQL a write by an agent that calls one cannot
  be approved.
- **A second place to keep secrets.** The gateway stores database logins,
  encrypted under a master key that you must protect and back up.
- **People's time.** Each write by an agent waits for a person to preview and
  approve it. That is the point, and it is a cost.
- **A young project.** It is before 1.0 and has no single sign-on yet.
  PostgreSQL has the full feature set; MySQL has no row preview and no
  agent login.

## When you do not need this

- The agent works on a development database, a copy with no personal data,
  or a dataset that is public anyway.
- The agent only reads, every column it can reach is fine to read, and load
  on the database does not matter. A read-only role on a replica (B) is
  simpler and is enforced by the database itself.
- A person reads and runs every statement the agent writes. Then the person
  is the gate.

## When another approach is the better choice

- **You need a hard guarantee and only reads.** Use a read-only role with
  grants on exactly the tables and columns that are allowed (B). Database
  grants are stronger than any rule that reads SQL text. This gate can sit
  on top; it cannot replace them.
- **Your problem is people, not agents.** If you need single sign-on,
  session recording and access requests for engineers across many kinds of
  systems, an access tool built for people (D) covers more ground.
- **You need a database that this gate does not speak to.** It supports
  PostgreSQL and MySQL, with their managed variants.
- **The agent needs SQL that the guard refuses**, such as procedural code or
  special syntax of an extension. A narrow role (B) and a tool server (C)
  let it through; you then carry the risk in the role's grants.
- **You cannot run one more service.** A read-only role costs nothing to
  operate.

The approaches combine. A read-only role or a narrow agent login in the
database (B), this gate in front of it (E), and no other credentials in the
agent's reach, is the setup the [threat model](THREAT-MODEL.md) assumes.

## Named tools

As of 2026-11-25. These facts come from each project's repository and
documentation on that date; stars and licenses are from the GitHub API.
"Not checked" means we did not verify the cell; it is not a "No". If a cell
is wrong, please [open an issue](https://github.com/visplabs/visp-gate/issues).

| Property                                   | Read-only role (B)                 | [Bytebase](https://github.com/bytebase/bytebase)                    | [Kviklet](https://github.com/kviklet/kviklet)                       | [hoop.dev](https://github.com/hoophq/hoop)             | [Teleport](https://github.com/gravitational/teleport) | [DBHub](https://github.com/bytebase/dbhub) / [Postgres MCP Pro](https://github.com/crystaldba/postgres-mcp) | visp-gate                                                                      |
| ------------------------------------------ | ---------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| What it is                                 | A database login                   | Database change review, for people and agents                       | Four-eyes SQL review, with an MCP server                            | An access gateway for agents and people                | Zero-trust access to many systems; MCP access         | MCP servers that give an agent SQL tools                                                                    | A gate between agents (MCP) and PostgreSQL or MySQL                            |
| License, and what is paywalled             | Part of the database               | MIT core; an enterprise edition; a cap of 20 users on the free plan | MIT except marked parts; the MCP server is enterprise-only          | MIT; approvals and the AI analyzer are enterprise-only | AGPL-3.0                                              | MIT                                                                                                         | Apache-2.0; nothing paywalled                                                  |
| A person approves each write by an agent   | No writes at all                   | Yes: SQL-review checks, then an approval flow                       | Yes: requests reviewed like pull requests; an edit resets approvals | Yes: an Approve decision per action (enterprise)       | Not checked                                           | Not checked; Postgres MCP Pro has a restricted read-only mode                                               | Yes, by a person who is not the agent's owner                                  |
| The approver sees the rows a write changes | No                                 | No: the review is of the SQL text                                   | A dry run (run, then roll back); a row diff is not checked          | No: the review is of the SQL text                      | Not checked                                           | No                                                                                                          | Yes on PostgreSQL: before and after, and the write is bound to them            |
| Column masking                             | You build it, with views or grants | Not checked                                                         | Not checked                                                         | Yes: a Mask decision per action                        | Not checked                                           | Not checked                                                                                                 | Yes, by column name; see [its limits](THREAT-MODEL.md#a-prompt-injected-agent) |
| Errors written for the agent to act on     | A database error                   | Not advertised                                                      | Not advertised                                                      | Not advertised                                         | Not advertised                                        | Not advertised                                                                                              | Yes: an action word and a hint in each refusal                                 |
| Audit                                      | Database logs, per role            | One activity timeline per change; audit log not checked             | Not checked                                                         | Not checked                                            | Logs every allowed and denied LLM access              | DBHub's Workbench traces recent requests                                                                    | Each call with agent, owner and task; audit log in a keyed hash chain          |
| GitHub stars                               | -                                  | 14.7k                                                               | 636                                                                 | 866                                                    | 21.1k                                                 | 4.0k / 3.5k                                                                                                 | -                                                                              |

Where they are stronger:

- **Bytebase** is the mature choice for schema migrations and change review
  across many database engines, with SSO and a large user base. Its DBHub MCP
  server is featured in Claude Code's documentation.
- **Teleport** covers far more than databases, with single sign-on, at a
  scale this project has not been tested at.
- **hoop.dev** gates both people and agents, with a decision per action:
  run, mask, approve or block.
- **Kviklet** has a simple pull-request-like review for people, and a dry
  run that executes a statement and rolls it back before anyone approves it.
- **DBHub and Postgres MCP Pro** are one small process with nothing else to
  run. For an agent on a development database or a read-only replica they are
  enough.
- **A read-only role** is enforced by the database itself and costs nothing.

visp-gate supports PostgreSQL and MySQL only, has no single sign-on yet, and
is a young project. Its row-level preview works on PostgreSQL only.
