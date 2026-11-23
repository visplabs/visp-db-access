-- The limits of one agent at the agent door, shared by every node. Each node
-- kept them in its own memory before, so an agent that a load balancer sent
-- to several nodes got each limit once per node. One row per agent, written
-- by its calls and deleted with it. The maintenance cycle deletes rows whose
-- windows and turns have all ended.
CREATE TABLE agent_limits (
 agent_id uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
 -- Tool calls in the minute that began at `calls_since`.
 calls integer NOT NULL DEFAULT 0,
 calls_since timestamptz,
 -- run_query: refused queries in a row, in the ten minutes that began at
 -- `denials_since`. A successful query ends the streak.
 denials integer NOT NULL DEFAULT 0,
 denials_since timestamptz,
 -- propose_write: refused proposals in a row and when they reached the
 -- limit. A streak is forgotten ten minutes after the last proposal began.
 proposals_refused integer NOT NULL DEFAULT 0,
 proposals_stopped_at timestamptz,
 proposals_seen_at timestamptz,
 -- Turns: one guard decision of run_query, and one proposal, at a time. A
 -- turn is a lease: the call that holds it and when the lease ends. The
 -- holder renews it while it works, so a node that crashed loses it soon.
 query_holder uuid,
 query_until timestamptz,
 proposal_holder uuid,
 proposal_until timestamptz
);
