# How this compares with other approaches

There are several ways to let an AI agent work with a production database.
This page compares approaches, not products: products change, and a claim
about one can be out of date the day after it is written. Check any product
you consider against the rows of the table.

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
- **E. This gate.** visp-db-access between the agent and the database.

## The table

"Yes" means the approach gives you the property by its nature. "You build it"
means it is possible and the work is yours. "Varies" means some tools of this
kind do it and some do not.

| Property                                              | A. Direct credentials     | B. Read-only role or replica         | C. Generic SQL tool server   | D. Access tool for people             | E. This gate                                                                                                     |
| ----------------------------------------------------- | ------------------------- | ------------------------------------ | ---------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| The agent cannot write on its own                     | No                        | Yes, enforced by the database        | Varies; often a setting      | Varies; by the login it hands out     | Yes. Every write by an agent needs a person.                                                                     |
| A cap on rows per query                               | No                        | No                                   | Varies                       | Rarely                                | Yes: the guard adds a limit, and execution stops at the cap                                                      |
| Time, lock and concurrency limits                     | Only what the role has    | Only what the role has               | Varies                       | Varies                                | Yes, per database; concurrency is counted on each node                                                           |
| Column masking                                        | You build it, with views  | You build it, with views or grants   | Rarely                       | Varies                                | Yes, by column name. Read [its limits](THREAT-MODEL.md#a-prompt-injected-agent).                                 |
| Blocked tables                                        | You build it, with grants | Yes, with grants                     | Varies                       | Varies                                | Yes, by name; a view can leak without the agent login. With an agent login the database enforces it (PostgreSQL) |
| A refusal the agent can act on                        | A database error          | A database error                     | Usually the database's error | Usually a denied session              | Yes: each refusal has an action word and a hint                                                                  |
| A person approves each write, with a measured preview | No                        | No writes at all                     | Rarely                       | Approval of access, not of each write | Yes on PostgreSQL: a dry run shows the rows; the write is bound to them                                          |
| A stop that takes effect at once                      | Change the password       | Change the password or drop the role | Stop the server              | Usually: end the session              | Yes: pause the agent; its running queries are cancelled on that node                                             |
| Identity and record per agent                         | No, a shared login        | Per role, if each agent has its own  | Varies                       | Per person; agents are rarely known   | Yes: each agent has an owner, tokens, sessions, a task for every call                                            |
| Evidence that the record was not changed              | No                        | No                                   | No                           | Varies                                | A keyed hash chain over the audit log. Read [its limits](SECURITY-MODEL.md).                                     |
| The agent never holds a database password             | No                        | No                                   | Yes                          | Varies                                | Yes                                                                                                              |
| Enforced by the database, not by reading SQL          | Yes                       | Yes                                  | No                           | Varies                                | Partly: with the agent login on PostgreSQL; else the guard reads SQL                                             |
| Works with any SQL the database accepts               | Yes                       | Yes, for reads                       | Yes                          | Yes                                   | No. SQL that the guard does not understand is refused.                                                           |
| Effort to run                                         | None                      | Low: a role, perhaps a replica       | Low: one process             | Medium to high                        | Medium: one service and a PostgreSQL metadata database                                                           |
| Cost                                                  | None                      | The replica, if you add one          | Usually free                 | Varies; many are paid                 | Free and self-hosted. You run and update it.                                                                     |

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
  PostgreSQL has the full feature set; MySQL has no measured preview and no
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
