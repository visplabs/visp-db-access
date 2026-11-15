-- A limit on how many queries an agent can start in one hour. Blocked
-- attempts count too, so a loop of refused queries also runs out.
ALTER TABLE agents ADD COLUMN hourly_query_budget integer NOT NULL DEFAULT 300
 CHECK(hourly_query_budget BETWEEN 1 AND 100000);
-- What the caller said the query is for. An agent must always say.
ALTER TABLE query_history ADD COLUMN task text;
