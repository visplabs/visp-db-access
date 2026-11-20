-- A tamper-evident audit log.
--
-- The append-only trigger stops the gateway's own role from changing a row,
-- but whoever can drop the trigger can change, delete or reorder rows and
-- leave no trace. From here on every audit row is sealed into a keyed hash
-- chain: a change to a sealed row, a deleted row or a reordered row no
-- longer matches the chain, and the chain cannot be rebuilt without the
-- master key.
--
-- Writers are not serialized. Rows are inserted as before, from many
-- connections and nodes, and a sealer puts them into one order afterwards.
-- That order is (txid, seq):
--   txid  the transaction that inserted the row. Transaction IDs only grow.
--   seq   a sequence number, to order the rows of one transaction.
-- A row may be sealed when every transaction with a smaller or equal ID has
-- ended, that is when txid is below the oldest transaction still running
-- (pg_snapshot_xmin). No transaction that commits later can then add a row
-- that sorts before it. `seq` has gaps after a rollback; a gap means nothing.
CREATE SEQUENCE audit_log_seq_seq;
ALTER TABLE audit_log ADD COLUMN seq bigint, ADD COLUMN txid xid8;
-- Rows from before the chain keep the order they were listed in, and
-- transaction 0, which sorts before every real transaction. The trigger is
-- off for this one statement, inside the migration's transaction, so no
-- other session ever sees the table without it.
ALTER TABLE audit_log DISABLE TRIGGER audit_immutable;
UPDATE audit_log a SET seq=o.seq, txid='0'
  FROM (SELECT id, row_number() OVER (ORDER BY created_at,id) AS seq FROM audit_log) o
 WHERE o.id=a.id;
ALTER TABLE audit_log ENABLE TRIGGER audit_immutable;
SELECT setval('audit_log_seq_seq', COALESCE((SELECT max(seq) FROM audit_log),0)+1, false);
ALTER TABLE audit_log
  ALTER COLUMN seq SET DEFAULT nextval('audit_log_seq_seq'), ALTER COLUMN seq SET NOT NULL,
  ALTER COLUMN txid SET DEFAULT pg_current_xact_id(), ALTER COLUMN txid SET NOT NULL;
ALTER SEQUENCE audit_log_seq_seq OWNED BY audit_log.seq;
CREATE UNIQUE INDEX audit_chain_order ON audit_log(txid,seq);

-- One link per sealed audit row. `position` has no gaps and is given by the
-- sealer. `audit_id` deliberately references nothing: when an audit row is
-- deleted its link must stay, and show that a row is missing. `txid` and
-- `seq` repeat the place of the row in the order, so a missing row can still
-- be placed and a row added behind the sealed part can be found.
-- `segment_start` is the position of the first link of the unbroken run of
-- links that were sealed with this link's key. It is inside the hash, so a
-- link that verifies says where its run began; a link in that run that now
-- names another key was relabelled.
-- hash = HMAC-SHA256(chain key, label || position || segment_start ||
-- prev_hash || row), in hex; docs/API.md has the exact bytes.
CREATE TABLE audit_chain (
 position bigint PRIMARY KEY CONSTRAINT audit_chain_position_check CHECK(position>0),
 audit_id uuid NOT NULL UNIQUE,
 txid xid8 NOT NULL, seq bigint NOT NULL,
 key_id text NOT NULL,
 segment_start bigint NOT NULL,
 prev_hash text NOT NULL, hash text NOT NULL,
 sealed_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT audit_chain_segment_check CHECK(segment_start>0 AND segment_start<=position)
);
CREATE FUNCTION audit_chain_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_chain is append-only'; END $$;
CREATE TRIGGER audit_chain_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_chain
  FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_append_only();

-- Where the background check of the chain is, and what its last full pass
-- found. One row. It is a convenience for the console and for the other
-- nodes, not evidence: the chain itself and the checkpoints in the logs are.
CREATE TABLE audit_verification (
 id boolean PRIMARY KEY DEFAULT true CHECK(id),
 -- The pass that is running: the last position it checked, when it began,
 -- and what it has counted so far.
 position bigint NOT NULL DEFAULT 0,
 pass_started_at timestamptz,
 progress jsonb NOT NULL DEFAULT '{}',
 -- The last pass that reached the head or found a problem.
 result jsonb,
 finished_at timestamptz
);
INSERT INTO audit_verification DEFAULT VALUES;
