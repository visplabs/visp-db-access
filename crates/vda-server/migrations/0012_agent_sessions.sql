-- What agents did at the agent door, step by step, for the people who answer
-- for them. The agent door keeps no session, so the gateway makes its own: a
-- session is a run of calls of one agent token with no gap longer than 30
-- minutes. Steps hold SQL text, never result rows.
CREATE TABLE agent_sessions (
 id uuid PRIMARY KEY,
 agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
 token_id uuid NOT NULL REFERENCES agent_tokens(id) ON DELETE CASCADE,
 started_at timestamptz NOT NULL, last_step_at timestamptz NOT NULL,
 steps integer NOT NULL DEFAULT 0, refusals integer NOT NULL DEFAULT 0,
 first_task text
);
CREATE INDEX agent_sessions_page ON agent_sessions(agent_id,started_at DESC,id DESC);
CREATE INDEX agent_sessions_token ON agent_sessions(token_id);
CREATE INDEX agent_sessions_last ON agent_sessions(last_step_at);
-- The session a token is in. The writer of steps locks this row, so every
-- node gives the calls of one token the same session and numbers its steps
-- without a gap.
CREATE TABLE agent_session_heads (
 token_id uuid PRIMARY KEY REFERENCES agent_tokens(id) ON DELETE CASCADE,
 session_id uuid REFERENCES agent_sessions(id) ON DELETE SET NULL
);
CREATE INDEX agent_session_heads_session ON agent_session_heads(session_id);
-- One row per tool call. `n` counts the steps of a session from 1, in the
-- order they were written; the console asks for the steps after a number.
-- `cluster_id`, `history_id` and `approval_id` are plain ids: the step stays
-- when the thing it points to is deleted.
CREATE TABLE agent_steps (
 session_id uuid NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
 n integer NOT NULL,
 id uuid NOT NULL UNIQUE,
 tool text NOT NULL, task text, cluster_id uuid,
 sql text, sql_truncated boolean NOT NULL DEFAULT false,
 verdict text CHECK(verdict IN ('allow','requires_approval','deny')),
 outcome text NOT NULL,
 fix_action text, fix_hint text,
 row_count integer, elapsed_ms integer NOT NULL,
 history_id uuid, approval_id uuid,
 created_at timestamptz NOT NULL,
 PRIMARY KEY(session_id,n)
);
CREATE INDEX agent_steps_time ON agent_steps(created_at);
