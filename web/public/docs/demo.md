# Demo

One command starts the gateway, a demo database and an agent that is ready to
use it. In about five minutes, once the images are downloaded, you see:

- **A blocked statement.** The agent sends an `UPDATE` with no `WHERE`, or
  reads a blocked table, and is refused with a hint it can act on.
- **A masked column.** The agent reads customers and gets `email` and `phone`
  as `••••••`.
- **A write that waits for a person.** The agent asks to cancel three orders.
  Nothing runs until you, as a second person, preview it and see the exact
  three rows before and after.
- **The receipt.** After you approve, the write runs on those rows only, and
  you get a signed receipt and a record of the calls the agent made.

**Demo only.** The demo uses well-known passwords, plain HTTP and made-up shop
data, and it listens on `127.0.0.1` only. Do not put real data behind it. For a
real installation see [Deployment](deployment.md).

You need Docker with Compose 2.20 or newer and a clone of this repository.
Nothing else: the scripted agent runs in a container.

How long it takes:

- **The first start downloads the released gateway image** and two database
  images. How long that takes depends on your connection.
- If the released image cannot be downloaded, or if you add `--build`, the
  gateway is built from your checkout. On a 16-core laptop that took about
  eight minutes, five of them the Rust build, and it needs several gigabytes
  of free disk space.
- Every later start takes about 15 seconds.
- The walkthrough below takes about five minutes.

## 1. Start

From the root of the repository:

```sh
docker compose -f deploy/demo/docker-compose.yml up
```

The command stays in the foreground. It shows the output of one step only, the
one that sets the demo up through the gateway's public API. When that step is
done you see:

```text
The gate is running. Three things to do:

1. Watch an agent work through the gate (it takes a few seconds):
   …
2. Open the console:  http://localhost:8080
   …
3. Connect your own agent instead of the script. …
```

Leave it running and open a second terminal for the next steps. (To run it
in the background, add `-d`, and read the output of the setup step with
`docker compose -f deploy/demo/docker-compose.yml logs seed`.) If port 8080
is taken, choose another one and use it in every command of this page:

```sh
VISP_GATE_DEMO_PORT=18480 docker compose -f deploy/demo/docker-compose.yml up
```

What the setup step made:

| Thing      | Value                                                                     |
| ---------- | ------------------------------------------------------------------------- |
| Database   | `shop-production`: PostgreSQL with customers, products, orders and cards  |
| Row cap    | 50 rows a query                                                           |
| Protected  | The columns `email` and `phone` are masked                                |
| Blocked    | The table `payment_cards`                                                 |
| Writes     | Allowed, and each one needs a second person's approval                    |
| Agent      | `demo-agent`, owned by `admin@example.com`, with a token valid for 7 days |
| Two people | `admin@example.com` owns the agent; `reviewer@example.com` approves       |

The gateway connects to the database as `shop_gate`, a login that can read and
change the shop tables and owns nothing. The agent never sees that login or
its password.

## 2. Watch an agent work through the gate

```sh
docker compose -f deploy/demo/docker-compose.yml run --rm agent --follow
```

This plays an agent over the real Model Context Protocol (MCP) endpoint at
`/api/v1/mcp`, with the agent's token. It prints each call and
what came back, and it stops with an error if the gate does not behave as
this page says. What to look for:

| Step | The agent does                                   | The gate answers                                                                                            |
| ---- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| 1    | Connects and lists the tools                     | Nine tools. None of them is "run any SQL".                                                                  |
| 2    | `list_databases`                                 | One database, with the level `write`. Nothing else exists for this agent.                                   |
| 3    | `search_schema` for "customer"                   | `customers` and `orders`. `payment_cards` has a `customer_id` column too, and is not listed: it is blocked. |
| 4    | `describe_table customers`                       | `email` and `phone` are marked as protected, before the agent reads a row.                                  |
| 5    | `check_sql` with `UPDATE orders SET status = …`  | `deny`, and a fix: `rewrite_sql`, "Add a WHERE clause that selects only those rows." Nothing ran.           |
| 6    | `run_query` on `customers`                       | Rows, with `email` and `phone` as `••••••`. `ran_as` shows the SQL that ran, with the guard's `LIMIT 51`.   |
| 7    | `fetch_rows` with the cursor of step 6           | The next rows of the same result, masked the same way. No second query runs.                                |
| 8    | `run_query` on `payment_cards`                   | Refused: `query_denied`. The fix is `stop`: the agent is told not to try other spellings.                   |
| 9    | `run_query` with an `UPDATE` that has a `WHERE`  | Refused: `approval_required`. The fix is `propose_write`. An agent cannot change data on its own.           |
| 10   | `propose_write` with the same `UPDATE`           | A request with the status `pending`. Nothing was written. The agent saw no row and no count.                |
| 11   | `get_approval`, then waits because of `--follow` | `pending` until you decide.                                                                                 |

The cap of 50 rows shows in step 6: the guard adds `LIMIT 51`, one row more
than the policy allows, so that the gateway can tell the agent that there are
more rows. The answer holds 5 rows because the agent asked for 5, and 45 more
wait for `fetch_rows`.

## 3. Be the person who decides

Open <http://localhost:8080/approvals> and sign in:

|          |                            |
| -------- | -------------------------- |
| Email    | `reviewer@example.com`     |
| Password | `demo-reviewer-local-only` |

Sign in as the reviewer, not as the administrator: the administrator owns the
agent, and the owner of an agent cannot approve its writes.

1. Click **Review** on the request "Demo: cancel the 3 pending orders …". It
   says "Asked by agent demo-agent for Administrator". **Approve** is disabled:
   nobody has tried the write yet.
2. Click **Preview**, read the SQL in the dialog, and click **Confirm**. The
   gateway now runs the write on the database inside a transaction, measures
   it, and rolls it back.
3. Read **What changes**: "Changes 3 rows in orders. It will run only on these
   exact rows.", with the three rows before and after.
4. Click **Approve and run** and confirm. Or type a note and click **Reject**.

After **Approve and run** the request shows a **Receipt** with "Signature
valid" and "3 rows previewed, 3 rows changed". In the terminal of step 2 the
agent prints the outcome:

```text
   status    executed  (a person has previewed it)
   changed   3 rows
   ✓ a person approved and ran the write; the agent learns the count and nothing else
```

## 4. Read the record

Still in the console, as the reviewer:

- **Overview** shows each agent with its live session, and what the gate did
  in the last 24 hours: how many statements it allowed, how many requests are
  held for a person, and how many it blocked.
- **Agents → demo-agent**, then open the newest session. Every call of step 2
  is a step: the tool, the task the agent gave, the SQL, the guard's answer
  and, for a refusal, the fix the agent read. No result row is stored there.
- **History** shows the queries that ran, with the agent's task.
- **Audit log** shows who did what, and "Chain intact". Click **Verify now**
  to check the hash chain again.

## 5. Stop the agent

On **Agents → demo-agent**, click **Pause agent**. Then run the agent again:

```sh
docker compose -f deploy/demo/docker-compose.yml run --rm agent
```

It fails at its first call: the gateway answers `401` to a paused agent, and
a query that the agent was running would be cancelled. Click **Resume agent**
to let it work again.

## Connect a real MCP client

Any client that speaks MCP over Streamable HTTP can use the gate in place of
the script. It needs three values: the URL `http://localhost:8080/api/v1/mcp`,
the header name `Authorization` and the value `Bearer ` followed by the agent
token that the setup step printed. No database password goes into the
client's configuration.

In your own installation, **Agents → Connect an agent** in the console makes
the agent and its token, gives the same command or block for your client, and
shows the agent's first calls as they arrive.

Claude Code:

```sh
claude mcp add --transport http visp-gate http://localhost:8080/api/v1/mcp \
  --header "Authorization: Bearer vda_agent_…"
```

Cursor (`.cursor/mcp.json` in a project, or `~/.cursor/mcp.json`) and other
clients that take a JSON block:

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

The setup step prints both of these with the demo's URL and token filled in
(step 3 of its output). To print them again, with the same token:

```sh
docker compose -f deploy/demo/docker-compose.yml run --rm seed
```

Then ask your agent, for example:

- "Which customers have the most pending orders?"
- "Show me the email addresses of the first ten customers." It gets `••••••`.
- "Read the payment cards." It is refused and told to stop.
- "Cancel the pending orders of customer 7." It must ask you, in **Approvals**.

Watch what it does under **Agents → demo-agent** while it works.

The MCP endpoint refuses a request that carries an `Origin` header, so a client
that runs inside a web page cannot use it. The tools and their answers are in
the [API reference](api.md#agent-door-bearer-token-no-session).

## Tear down

Press Ctrl+C in the first terminal, then remove the containers, the data and
the demo's master key:

```sh
docker compose -f deploy/demo/docker-compose.yml down -v
```

## What the demo leaves out

The demo shows the gate with its simplest setup. A real installation should
read these first:

- **The database as the judge.** Here the block on `payment_cards` and the
  masking of `email` are rules in the gateway, which reads SQL text
  (`enforced by the gateway` in step 2). On PostgreSQL you can add a second
  login for agents that holds grants for exactly what the policy allows, so
  the database itself refuses the rest. See
  [Agent login](api.md#agent-login-the-database-is-the-judge).
- **What masking does not stop.** A filter on a protected column still works:
  `SELECT count(*) FROM customers WHERE email LIKE 'a%'` returns a count. An
  agent can learn about a value by asking questions about it. The agent login
  closes this, and so does blocking the table. See the
  [threat model](threat-model.md).
- **TLS.** The demo speaks plain HTTP to the browser and to the database.
- **Notices.** A webhook can tell approvers that a request waits; it is off.
- **MySQL.** The gate works with MySQL too, without the row preview.

## Without Docker

The two scripts work against any running gateway, for example the one that
`scripts/dev-local.sh` starts (see [Development](development.md)). They need
`bash`, `curl` and `jq`.

```sh
# Set up: needs the administrator's password and a database with the shop
# data (deploy/demo/postgres.sql, then deploy/demo/postgres-gate.sql).
VISP_GATE_DEMO_URL=http://127.0.0.1:8080 \
VISP_GATE_DEMO_ADMIN_EMAIL=admin@local.test VISP_GATE_DEMO_ADMIN_PASSWORD=… \
VISP_GATE_DEMO_REVIEWER_PASSWORD=… \
VISP_GATE_DEMO_TARGET_HOST=127.0.0.1 VISP_GATE_DEMO_TARGET_PORT=55432 \
VISP_GATE_DEMO_TARGET_USER=shop_gate VISP_GATE_DEMO_TARGET_PASSWORD=… \
VISP_GATE_DEMO_TOKEN_FILE=/tmp/demo-agent-token \
  scripts/demo-seed.sh

# The agent.
VISP_GATE_DEMO_URL=http://127.0.0.1:8080 VISP_GATE_AGENT_TOKEN_FILE=/tmp/demo-agent-token \
  scripts/demo-agent.sh --follow
```

`scripts/demo-agent.sh` exits with 0 when every step behaved as described, 1
when one did not, and 2 for a wrong command line or a missing token.

## If something goes wrong

- **The setup step says the gateway did not become ready.** Read the
  gateway's log: `docker compose -f deploy/demo/docker-compose.yml logs gateway`.
- **"port is already allocated".** Set `VISP_GATE_DEMO_PORT` as shown in step 1.
- **The agent is refused with `too_many_denials`.** Five refused queries in a
  row stop an agent for up to ten minutes. That is the gate working. Wait, or
  restart the gateway: `docker compose -f deploy/demo/docker-compose.yml restart gateway`.
- **The agent is refused with 401.** The agent is paused, or the demo was
  removed and started again while an old token was in use. Run the `seed`
  step again; it makes a new token when the old one no longer works.
