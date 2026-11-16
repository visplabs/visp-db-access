-- The database is the judge: a separate, least-privilege login on the target
-- database that agents' queries run as. A database administrator creates it
-- from a script that the gateway writes; the gateway only verifies it.
CREATE TABLE cluster_agent_logins (
 cluster_id uuid PRIMARY KEY REFERENCES clusters(id) ON DELETE CASCADE,
 username text NOT NULL, password_enc text NOT NULL,
 -- The result of the last verification, and the cluster version it was for.
 status text NOT NULL DEFAULT 'unchecked' CHECK(status IN ('unchecked','ok','drift','error')),
 findings jsonb NOT NULL DEFAULT '[]', checked_at timestamptz, checked_version timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
