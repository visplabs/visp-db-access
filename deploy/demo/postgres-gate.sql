-- Extra objects for the agent safety gate demo (deploy/demo/docker-compose.yml).
-- DEMO ONLY: made-up data and a well-known password. Runs after postgres.sql.
-- A table that the demo policy blocks for everyone who comes through the gate.
CREATE TABLE payment_cards (id bigint PRIMARY KEY, customer_id bigint NOT NULL REFERENCES customers(id), brand text NOT NULL, last4 text NOT NULL, vault_ref text NOT NULL);
INSERT INTO payment_cards SELECT n,n,CASE WHEN n%2=0 THEN 'visa' ELSE 'mastercard' END,lpad((n%10000)::text,4,'0'),'demo-vault-ref-'||n FROM generate_series(1,3000) n;
-- The login the gateway connects with: rights on the data only. It owns
-- nothing and is not a superuser. TEMPORARY is needed for the check that the
-- gateway makes before a person previews an agent's write.
CREATE ROLE shop_gate LOGIN PASSWORD 'demo-local-only';
GRANT CONNECT, TEMPORARY ON DATABASE shop TO shop_gate;
GRANT USAGE ON SCHEMA public TO shop_gate;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO shop_gate;
