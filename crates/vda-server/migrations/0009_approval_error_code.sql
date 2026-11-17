-- The code of the error that stopped an approved write, such as
-- `effect_changed`. An agent reads its outcome from this code; the text in
-- `error` can hold counts and database messages and is for people only.
ALTER TABLE approvals ADD COLUMN error_code text;
UPDATE approvals SET error_code='effect_changed'
 WHERE status='failed' AND error LIKE 'The data changed after the approval%';
UPDATE approvals SET error_code='outcome_unknown'
 WHERE status='failed' AND error='execution outcome unknown (node crashed or lost)';
