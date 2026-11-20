-- Notices to approvers. A row is written in the transaction that changes an
-- approval, and a worker on every node delivers it to one webhook. The
-- payload never holds SQL, rows, previews or database error text.
CREATE TABLE notices (
 id uuid PRIMARY KEY,
 -- The order in which notices were written. The notices of one request are
 -- delivered in this order, and a receiver gets it as `sequence`.
 seq bigserial NOT NULL,
 approval_id uuid NOT NULL REFERENCES approvals(id) ON DELETE CASCADE,
 event text NOT NULL,
 payload jsonb NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sent','dead')),
 attempts integer NOT NULL DEFAULT 0,
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 -- A short class such as `http_500` or `connect`; never response content.
 last_error text,
 last_attempt_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 sent_at timestamptz
);
-- What is due, in the order a worker claims it, and how many wait.
CREATE INDEX notices_due ON notices(next_attempt_at,seq) WHERE status='pending';
-- Whether an earlier notice of the same request still waits: one probe for
-- each notice a claim looks at, however many were already delivered.
CREATE INDEX notices_waiting ON notices(approval_id,seq) WHERE status='pending';
-- All notices of a request, and the cascade from approvals.
CREATE INDEX notices_request ON notices(approval_id,seq);
-- The delivery status and the retention of delivered and given-up notices.
CREATE INDEX notices_sent ON notices(sent_at) WHERE status='sent';
CREATE INDEX notices_dead ON notices(last_attempt_at) WHERE status='dead';
CREATE INDEX notices_failed ON notices(last_attempt_at DESC) WHERE last_error IS NOT NULL;
-- The webhook address and the signing secret are stored encrypted.
INSERT INTO settings(key,value) VALUES ('notices',
 '{"enabled":false,"format":"webhook","url_enc":null,"url_host":null,"secret_enc":null,
   "events":["approval.created"],"include_reason":false,"include_row_count":false}');
