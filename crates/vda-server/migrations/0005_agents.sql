-- An agent is a non-human caller that always acts for one human owner.
-- Its access is the owner's access, narrowed to a list of clusters and a
-- maximum level. It is never wider than what the owner has at request time.
CREATE TABLE agents (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL, description text NOT NULL DEFAULT '',
 max_level text NOT NULL DEFAULT 'read' CHECK(max_level IN ('read','write')),
 paused boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agents_owner_name ON agents(owner_id,lower(name));
CREATE INDEX agents_page ON agents(created_at DESC,id DESC);
CREATE TABLE agent_clusters (
 agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
 cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
 PRIMARY KEY(agent_id,cluster_id)
);
CREATE INDEX agent_clusters_cluster ON agent_clusters(cluster_id);
-- Only the SHA-256 digest of a token is stored. The hint is its last four
-- characters, so a person can tell tokens apart.
CREATE TABLE agent_tokens (
 id uuid PRIMARY KEY, agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
 token_hash bytea NOT NULL UNIQUE, hint text NOT NULL,
 created_by uuid REFERENCES users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 revoked_at timestamptz, last_used_at timestamptz
);
CREATE INDEX agent_tokens_agent ON agent_tokens(agent_id);
-- History keeps which agent ran a query. The user columns hold its owner.
ALTER TABLE query_history ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE SET NULL;
CREATE INDEX history_agent_time ON query_history(agent_id,created_at DESC,id DESC) WHERE agent_id IS NOT NULL;
