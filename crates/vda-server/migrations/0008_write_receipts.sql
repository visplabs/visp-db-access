-- Safe writes: every approval request carries a dry run of its write, and the
-- approval is bound to the effect the dry run saw. An executed write leaves a
-- signed receipt. Agents can ask for writes; a person approves and runs them.
ALTER TABLE approvals DROP CONSTRAINT approvals_status_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_status_check CHECK(status IN
 ('pending','approved','rejected','executing','executed','failed','expired','withdrawn'));
-- What the dry run showed (masked rows, counts, notes); shown to people.
ALTER TABLE approvals ADD COLUMN preview jsonb;
-- The effect the approval is bound to, with a digest of the target rows.
-- Never sent to a client.
ALTER TABLE approvals ADD COLUMN binding jsonb;
-- An agent that asked for the write, for its owner (the requester). The name
-- is kept so the request still says who asked after the agent is deleted.
ALTER TABLE approvals ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE SET NULL;
ALTER TABLE approvals ADD COLUMN agent_name text;
ALTER TABLE approvals ADD COLUMN executed_by uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE approvals ADD COLUMN receipt jsonb;
CREATE INDEX approvals_agent ON approvals(agent_id,created_at DESC) WHERE agent_id IS NOT NULL;
