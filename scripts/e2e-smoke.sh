#!/usr/bin/env bash
# Exercises a running gateway and seeded demo target; leaves uniquely named API fixtures.
set -euo pipefail
umask 077
for tool in curl jq; do command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 1; }; done
base_url=${VISP_GATE_SMOKE_BASE_URL:-http://127.0.0.1:8080}
admin_email=${VISP_GATE_SMOKE_ADMIN_EMAIL:-admin@local.test}
admin_password=${VISP_GATE_SMOKE_ADMIN_PASSWORD:-local-admin-password}
target_host=${VISP_GATE_SMOKE_TARGET_HOST:-127.0.0.1}
target_port=${VISP_GATE_SMOKE_TARGET_PORT:-55432}
target_db=${VISP_GATE_SMOKE_TARGET_DATABASE:-shop}
reader=${VISP_GATE_SMOKE_READER:-shop_reader}
reader_password=${VISP_GATE_SMOKE_READER_PASSWORD:-shop_reader_pw}
writer=${VISP_GATE_SMOKE_WRITER:-shop_writer}
writer_password=${VISP_GATE_SMOKE_WRITER_PASSWORD:-shop_writer_pw}
run_id="$(date +%s)-$$"
work_dir=$(mktemp -d)
cleanup() {
  if [[ -n ${mysql_request_pid:-} ]] && kill -0 "$mysql_request_pid" 2>/dev/null; then
    curl --silent --show-error --max-time 5 --request POST --header 'X-Requested-With: vda' \
      --cookie "$admin_jar" "$base_url/api/v1/queries/${mysql_cancel_id:-}/cancel" >/dev/null 2>&1 || true
    kill "$mysql_request_pid" 2>/dev/null || true
    wait "$mysql_request_pid" 2>/dev/null || true
  fi
  if [[ -n ${discovery_fixture_backup:-} ]]; then
    cat -- "$discovery_fixture_backup" > "$VISP_GATE_DISCOVERY_FAKE_FIXTURE"
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
admin_jar="$work_dir/admin.cookies"
reviewer_jar="$work_dir/reviewer.cookies"
member_jar="$work_dir/member.cookies"
response="$work_dir/response.json"

call() {
  local method=$1 path=$2 expected=$3 jar=$4 body=${5-}
  local -a args=(--silent --show-error --max-time 90 --request "$method"
    --header 'X-Requested-With: vda' --cookie "$jar" --cookie-jar "$jar"
    --output "$response" --write-out '%{http_code}')
  if [[ -n $body ]]; then args+=(--header 'Content-Type: application/json' --data-binary @-); fi
  local status
  status=$(curl "${args[@]}" "$base_url/api/v1$path" <<< "$body")
  if [[ $status != "$expected" ]]; then
    printf 'FAIL %s %s: expected %s, received %s\n' "$method" "$path" "$expected" "$status" >&2
    cat "$response" >&2
    exit 1
  fi
}
check() {
  if ! jq --exit-status "$1" "$response" >/dev/null; then
    printf 'FAIL response assertion: %s\n' "$1" >&2; cat "$response" >&2; exit 1
  fi
}
pass() { printf 'PASS %s\n' "$1"; }
login_body=$(jq -n --arg email "$admin_email" --arg password "$admin_password" '{email:$email,password:$password}')
call POST /auth/login 200 "$admin_jar" "$login_body"
check '.user.org_role == "admin" and (.user | has("password_hash") | not)'
admin_id=$(jq -r '.user.id' "$response")
pass login

call POST /projects 200 "$admin_jar" "$(jq -n --arg name "Smoke $run_id" '{name:$name,description:"Real API smoke test"}')"
project_id=$(jq -er '.id' "$response")
cluster_body=$(jq -n --arg project "$project_id" --arg host "$target_host" --argjson port "$target_port" --arg database "$target_db" --arg username "$reader" --arg password "$reader_password" '{project_id:$project,name:"Smoke reader",engine:"postgres",provider:"onprem",region:"local",environment:"development",host:$host,port:$port,database:$database,username:$username,password:$password,tls_mode:"disable"}')
call POST /clusters 200 "$admin_jar" "$cluster_body"
cluster_id=$(jq -er '.id' "$response")
check 'has("password") == false and has("password_enc") == false'
pass 'project and least-privileged reader cluster'

call POST /clusters/test-connection 200 "$admin_jar" "$(jq --arg id "$cluster_id" 'del(.project_id,.name,.provider,.region,.environment,.password) + {cluster_id:$id}' <<< "$cluster_body")"
check '.status == "healthy"'
call POST "/clusters/$cluster_id/health/check" 200 "$admin_jar"
check '.status == "healthy"'
call GET "/clusters/$cluster_id/health" 200 "$admin_jar"
check '.current.status == "healthy" and (.history | length) > 0'
call GET "/clusters/$cluster_id/schema" 200 "$admin_jar"
check '[.schemas[].tables[].name] | index("products") != null'
pass 'connection, health and schema'

call GET "/clusters/$cluster_id/policy" 200 "$admin_jar"
policy=$(jq '.max_rows=2 | .max_cost=null | .allow_writes=true | .require_approval_for_writes=true | .masked_columns=["email"]' "$response")
call PUT "/clusters/$cluster_id/policy" 200 "$admin_jar" "$policy"
read_body='{"sql":"SELECT id,name,email FROM customers ORDER BY id"}'
call POST "/clusters/$cluster_id/analyze" 200 "$admin_jar" "$read_body"
check '.verdict == "allow" and (.rewritten_sql | contains("LIMIT 3"))'
call POST "/clusters/$cluster_id/query" 200 "$admin_jar" "$read_body"
check '.row_count == 2 and .truncated == true and .rows[0][2] == "••••••" and .routed_to == "primary"'
read_query_id=$(jq -er '.query_id' "$response")
pass 'SELECT, masking and max_rows+1 truncation'
call POST "/clusters/$cluster_id/query" 422 "$admin_jar" '{"sql":"DELETE FROM products"}'
check '.error.code == "query_denied"'
call POST "/clusters/$cluster_id/analyze" 200 "$admin_jar" '{"sql":"SELECT row_to_json(customers) FROM customers"}'
check '.verdict == "deny" and ([.issues[].code] | index("masked_data_serialization") != null)'
call PATCH "/clusters/$cluster_id" 400 "$admin_jar" '{"host":"localhost"}'
check '.error.code == "validation" and (.error.message | contains("re-entering the password"))'
call POST /projects 400 "$admin_jar" '{"name":"bad\u0000","description":"control regression"}'
check '.error.code == "validation"'
pass 'blocked DELETE, serialization guard and input/endpoint validation'

# Separate scoped approver and writer users exercise lookup and RBAC as well as four-eyes.
reviewer_email="smoke-reviewer-$run_id@local.test"
member_email="smoke-member-$run_id@local.test"
user_password="smoke-password-$run_id"
for account in reviewer member; do
  if [[ $account == reviewer ]]; then email=$reviewer_email; else email=$member_email; fi
  call POST /users 200 "$admin_jar" "$(jq -n --arg email "$email" --arg name "Smoke $account $run_id" --arg password "$user_password" '{email:$email,name:$name,password:$password,org_role:"member"}')"
  if [[ $account == reviewer ]]; then reviewer_id=$(jq -er '.id' "$response"); else member_id=$(jq -er '.id' "$response"); fi
 done
call POST /grants 200 "$admin_jar" "$(jq -n --arg user "$reviewer_id" --arg project "$project_id" '{user_id:$user,scope:"project",scope_id:$project,level:"admin"}')"
call POST /grants 200 "$admin_jar" "$(jq -n --arg user "$member_id" --arg project "$project_id" '{user_id:$user,scope:"project",scope_id:$project,level:"write"}')"
call POST /auth/login 200 "$reviewer_jar" "$(jq -n --arg email "$reviewer_email" --arg password "$user_password" '{email:$email,password:$password}')"
call POST /auth/login 200 "$member_jar" "$(jq -n --arg email "$member_email" --arg password "$user_password" '{email:$email,password:$password}')"
call GET "/users/lookup?q=smoke-member-$run_id" 200 "$reviewer_jar"
check "(.items | length) == 1 and .items[0].id == \"$member_id\" and (.items[0] | keys | length) == 3"
call GET /users 403 "$reviewer_jar"
call GET "/grants?scope=project&scope_id=$project_id&limit=1" 200 "$reviewer_jar"
check '(.items | length) == 1 and .next_cursor != null'
cursor=$(jq -r '.next_cursor | @uri' "$response")
first_grant_id=$(jq -r '.items[0].id' "$response")
call GET "/grants?scope=project&scope_id=$project_id&limit=1&cursor=$cursor" 200 "$reviewer_jar"
check "(.items | length) == 1 and .items[0].id != \"$first_grant_id\" and .next_cursor == null"
call GET /grants 403 "$member_jar"
pass 'scoped grant pagination and minimal user lookup'

# Notices to approvers. Notices stay off and nothing leaves this machine: when
# the gateway runs on loopback, the test notice goes to the gateway's own
# /healthz, which answers a POST with 405. That is a real round trip.
notice_settings() {
  jq -n --arg url "$1" --argjson enabled "$2" '{enabled:$enabled,format:"webhook",events:["approval.created"],include_reason:false,include_row_count:false} + (if $url == "keep" then {} else {url:$url} end)'
}
call GET /settings/notices 200 "$admin_jar"
check '.enabled == false and .url_set == false and (has("url") or has("secret") | not)'
call GET /settings/notices 403 "$reviewer_jar"
call PUT /settings/notices 403 "$member_jar" "$(notice_settings keep false)"
call PUT /settings/notices 400 "$admin_jar" "$(notice_settings keep true)"
call PUT /settings/notices 400 "$admin_jar" "$(notice_settings 'https://169.254.169.254/latest/meta-data/' false)"
call PUT /settings/notices 400 "$admin_jar" "$(notice_settings 'https://user:pw@hooks.example.com/x' false)"
call POST /settings/notices/secret 200 "$admin_jar"
check '(.secret | startswith("vda_whsec_")) and (.secret | length) == 53'
if [[ $base_url =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$ ]]; then
  call PUT /settings/notices 200 "$admin_jar" "$(notice_settings "$base_url/healthz" false)"
  check '.url_set == true and .secret_set == true and (has("url") or has("secret") | not)'
  call POST /settings/notices/test 200 "$admin_jar"
  check '.delivered == false and .status == 405 and .error == "http_405"'
  pass 'notice settings, write-only address and secret, and a test round trip'
else
  call PUT /settings/notices 200 "$admin_jar" "$(notice_settings 'https://hooks.example.com/smoke' false)"
  check '.url_set == true and .url_host == "hooks.example.com" and (has("url") or has("secret") | not)'
  pass 'notice settings, write-only address and secret (no test notice: the gateway is not on loopback)'
fi
call PUT /settings/notices 200 "$admin_jar" "$(notice_settings '' false)"
check '.enabled == false and .url_set == false'

# A write that the SELECT-only role cannot run fails in its dry run, when it is
# requested, and no request is stored.
call GET "/approvals?cluster_id=$cluster_id&limit=100" 200 "$reviewer_jar"
approvals_before=$(jq -r '.items | length' "$response")
call POST /approvals 502 "$member_jar" "$(jq -n --arg cluster "$cluster_id" '{cluster_id:$cluster,sql:"UPDATE products SET price=price WHERE id=1",reason:"Smoke: reader cannot write"}')"
check '.error.code == "upstream"'
call GET "/approvals?cluster_id=$cluster_id&limit=100" 200 "$reviewer_jar"
check "(.items | length) == $approvals_before"
pass 'reader write rejected by its dry run and not stored'

# Rotate explicitly to the write role; a SELECT-only role must never apply a write.
call PATCH "/clusters/$cluster_id" 200 "$admin_jar" "$(jq -n --arg username "$writer" --arg password "$writer_password" '{username:$username,password:$password}')"
write_sql='UPDATE products SET price=price WHERE id=1'
write_body=$(jq -n --arg sql "$write_sql" '{sql:$sql}')
call POST "/clusters/$cluster_id/query" 409 "$member_jar" "$write_body"
check '.error.code == "approval_required"'
# A second request makes a list of two for the paging checks.
call POST /approvals 200 "$member_jar" "$(jq -n --arg cluster "$cluster_id" --arg sql "$write_sql" '{cluster_id:$cluster,sql:$sql,reason:"Smoke: second request"}')"
check '.preview.supported == true and .preview.affected_rows == 1 and .preview.bound_to == "rows"'
second_approval_id=$(jq -er '.id' "$response")
# SQL over the summary bound proves that the detail endpoint retains the full query.
long_sql="$write_sql /* $(printf '%2100s' '' | tr ' ' x) */"
call POST /approvals 200 "$member_jar" "$(jq -n --arg cluster "$cluster_id" --arg sql "$long_sql" '{cluster_id:$cluster,sql:$sql,reason:"Smoke: verify four-eyes write"}')"
approval_id=$(jq -er '.id' "$response")
call GET "/approvals?cluster_id=$cluster_id&limit=1" 200 "$reviewer_jar"
check '.items[0].sql_truncated == true and .items[0].result == null and (.items[0].sql | length) == 2000'
check '.next_cursor != null'
approval_cursor=$(jq -r '.next_cursor | @uri' "$response")
call GET "/approvals?cluster_id=$cluster_id&limit=1&cursor=$approval_cursor" 200 "$reviewer_jar"
check ".items[0].id == \"$second_approval_id\" and .next_cursor == null"

call GET "/approvals/$approval_id" 200 "$reviewer_jar"
check '.sql_truncated == false and (.sql | length) > 2000'
call POST "/approvals/$approval_id/approve" 403 "$member_jar" '{}'
call POST "/approvals/$approval_id/approve" 200 "$reviewer_jar" '{"note":"Verified one-row predicate"}'
check '.status == "approved"'
call POST "/approvals/$approval_id/execute" 200 "$member_jar"
check '.status == "executed" and .error == null and .result.affected_rows == 1 and .receipt.bound_to == "rows"'
write_query_id=$(jq -er '.result.query_id' "$response")
call GET "/approvals/$approval_id/receipt" 200 "$member_jar"
check '.valid == true'
call POST "/approvals/$approval_id/execute" 409 "$member_jar"
pass 'write approval, second-user review, execution and replay rejection'

call GET "/history?cluster_id=$cluster_id&limit=200" 200 "$admin_jar"
check '([.items[] | select(.status == "ok" and (.sql | startswith("SELECT id,name,email")))] | length) == 1 and ([.items[] | select(.status == "ok" and (.sql | startswith("UPDATE products")) and ((.task // "") | startswith("Dry run") | not))] | length) == 1 and ([.items[] | select(.status == "blocked")] | length) >= 1'
# Audit uses actor IDs to avoid unrelated fixture activity; intent and completion must persist.
call GET "/audit?actor_id=$admin_id&limit=200" 200 "$admin_jar"
check "([.items[] | select(.action == \"query.execute\" and .details.query_id == \"$read_query_id\" and .details.status == \"running\")] | length) == 1 and ([.items[] | select(.action == \"query.execute\" and .target_id == \"$cluster_id\" and .details.status == \"blocked\")] | length) >= 1"
call GET "/audit?actor_id=$member_id&limit=200" 200 "$admin_jar"
check "([.items[].action] | index(\"approval.create\") != null) and ([.items[].action] | index(\"approval.executed\") != null) and ([.items[] | select(.action == \"query.execute\" and .details.query_id == \"$write_query_id\") ] | length) == 1"
call GET "/audit?actor_id=$reviewer_id&limit=200" 200 "$admin_jar"
check '[.items[].action] | index("approval.approve") != null'
pass 'history and durable audit'
# An agent at the agent door. Its calls are the steps of one session that
# people can read, and fetch_rows hands out the rows that one run_query
# fetched: the policy lets a query fetch two rows, and each answer holds one.
call POST /agents 200 "$admin_jar" "$(jq -n --arg name "Smoke agent $run_id" --arg cluster "$cluster_id" '{name:$name,cluster_ids:[$cluster]}')"
agent_id=$(jq -er '.id' "$response")
call POST "/agents/$agent_id/tokens" 200 "$admin_jar" '{"expires_in_days":1}'
agent_token=$(jq -er '.token' "$response")
# Call one tool; the answer's structured content is left in $response.
tool() {
  local name=$1 arguments=$2 status
  status=$(jq -n --arg name "$name" --argjson arguments "$arguments" \
    '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$name,arguments:$arguments}}' |
    curl --silent --show-error --max-time 90 --request POST \
      --header 'Content-Type: application/json' --header "Authorization: Bearer $agent_token" \
      --output "$response.raw" --write-out '%{http_code}' --data-binary @- "$base_url/api/v1/mcp")
  if [[ $status != 200 ]]; then
    printf 'FAIL tool %s: HTTP %s\n' "$name" "$status" >&2; cat "$response.raw" >&2; exit 1
  fi
  jq '.result.structuredContent + {is_error: .result.isError}' "$response.raw" > "$response"
}
database=$(jq -n --arg id "$cluster_id" '$id')
agent_sql='SELECT id,name,email FROM customers ORDER BY id'
tool list_databases '{"task":"Smoke: see what I can reach"}'
check ".is_error == false and ([.databases[].id] | index($database) != null)"
tool check_sql "$(jq -n --argjson database "$database" --arg sql "$agent_sql" '{task:"Smoke: check the read",database:$database,sql:$sql}')"
check '.is_error == false and .verdict == "allow" and .fix == null'
tool run_query "$(jq -n --argjson database "$database" --arg sql "$agent_sql" '{task:"Smoke: read two customers",database:$database,sql:$sql,max_rows:1}')"
check '.is_error == false and .row_count == 1 and .truncated == true and .rows_left == 1 and (.next_cursor | startswith("rows_")) and .rows[0][2] == "••••••"'
first_row_id=$(jq -er '.rows[0][0]' "$response")
agent_query_id=$(jq -er '.query_id' "$response")
cursor=$(jq -er '.next_cursor' "$response")
tool fetch_rows "$(jq -n --arg cursor "$cursor" '{task:"Smoke: read the second customer",cursor:$cursor}')"
check ".is_error == false and .row_count == 1 and .rows[0][0] != $first_row_id and .rows[0][2] == \"••••••\" and .query_id == \"$agent_query_id\" and .truncated == true and (has(\"next_cursor\") | not)"
# A cursor works once; a used one and a made-up one get the same answer.
for used in "$cursor" 'rows_made-up'; do
  tool fetch_rows "$(jq -n --arg cursor "$used" '{task:"Smoke: a cursor that is gone",cursor:$cursor}')"
  check '.is_error == true and .error.code == "result_expired" and .error.fix.action == "rewrite_sql"'
done
pass 'agent tools, masked rows and one fetch_rows page with no second query'

# The steps are written by a queue; give the writer a moment.
session_id=
for _ in $(seq 1 60); do
  call GET "/agents/$agent_id/sessions" 200 "$admin_jar"
  if jq --exit-status '(.items | length) == 1 and .items[0].steps == 6' "$response" >/dev/null; then
    session_id=$(jq -er '.items[0].id' "$response"); break
  fi
  sleep 0.5
done
if [[ -z $session_id ]]; then printf 'FAIL the agent session did not show six steps in 30 seconds\n' >&2; cat "$response" >&2; exit 1; fi
check '.items[0].refusals == 2 and .items[0].active == true and .items[0].first_task == "Smoke: see what I can reach" and .next_cursor == null'
call GET "/agents/$agent_id/sessions/$session_id/steps" 200 "$admin_jar"
check '[.items[].tool] == ["list_databases","check_sql","run_query","fetch_rows","fetch_rows","fetch_rows"] and [.items[].n] == [1,2,3,4,5,6] and .after == 6 and .more == false'
check '[.items[].outcome] == ["ok","ok","ok","ok","result_expired","result_expired"] and [.items[].row_count] == [null,null,1,1,null,null]'
check ".items[1].verdict == \"allow\" and .items[2].sql == \"$agent_sql\" and .items[3].sql == null and .items[3].history_id == .items[2].history_id and (.items[4].fix.told | startswith(\"The agent was told\"))"
check '(tostring | contains("••••••") | not) and ([.items[] | has("rows")] | any | not)'
step_history_id=$(jq -er '.items[2].history_id' "$response")
call GET "/agents/$agent_id/sessions/$session_id/steps?after=5" 200 "$admin_jar"
check '(.items | length) == 1 and .items[0].n == 6'
# One query in history for the run and its page, linked from the step.
call GET "/history?cluster_id=$cluster_id&limit=200" 200 "$admin_jar"
check "([.items[] | select(.agent_id == \"$agent_id\")] | length) == 1 and ([.items[] | select(.id == \"$step_history_id\" and .agent_id == \"$agent_id\" and .status == \"ok\")] | length) == 1"
# Only the owner and administrators read an agent's sessions; an agent token
# is refused by the API for people.
call GET "/agents/$agent_id/sessions" 404 "$member_jar"
call GET "/agents/$agent_id/sessions/$session_id/steps" 404 "$reviewer_jar"
status=$(curl --silent --max-time 30 --output /dev/null --write-out '%{http_code}' \
  --header 'X-Requested-With: vda' --header "Authorization: Bearer $agent_token" \
  "$base_url/api/v1/agents/$agent_id/sessions")
if [[ $status != 401 ]]; then printf 'FAIL an agent token read the session API: HTTP %s\n' "$status" >&2; exit 1; fi
# Pausing the agent refuses its token at once.
call PATCH "/agents/$agent_id" 200 "$admin_jar" '{"paused":true}'
status=$(curl --silent --max-time 30 --output /dev/null --write-out '%{http_code}' --request POST \
  --header 'Content-Type: application/json' --header "Authorization: Bearer $agent_token" \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"ping"}' "$base_url/api/v1/mcp")
if [[ $status != 401 ]]; then printf 'FAIL a paused agent was not refused: HTTP %s\n' "$status" >&2; exit 1; fi
pass 'agent session with six steps, links to history, visibility and pause'

# The pre-flight answer of the console's check, for each state.
call POST "/clusters/$cluster_id/analyze" 200 "$admin_jar" "$read_body"
check '.verdict == "allow" and .preflight.state == "safe" and .preflight.action == "run" and .preflight.guard_change.clause == "LIMIT 3"'
call POST "/clusters/$cluster_id/analyze" 200 "$member_jar" "$write_body"
check '.verdict == "requires_approval" and .preflight.state == "needs_approval" and .preflight.action == "request_approval"'
call POST "/clusters/$cluster_id/analyze" 200 "$admin_jar" '{"sql":"SELECT 1; SELECT 2"}'
check '.verdict == "deny" and .preflight.state == "blocked" and .preflight.action == "apply_fix" and .preflight.fix.sql == "SELECT 1"'
pass 'pre-flight states: safe with the guard change, needs approval, blocked with a fix'
if [[ -n ${VISP_GATE_SMOKE_MYSQL_HOST:-} ]]; then
  # shellcheck source=/dev/null
  source "$(dirname -- "${BASH_SOURCE[0]}")/mysql-smoke.sh"
else
  printf 'SKIP MySQL: VISP_GATE_SMOKE_MYSQL_HOST is unset.\n'
fi
if [[ -n ${VISP_GATE_DISCOVERY_FAKE_FIXTURE:-} ]]; then
  # The running fake provider must use this same writable temporary fixture.
  # shellcheck source=/dev/null
  source "$(dirname -- "${BASH_SOURCE[0]}")/discovery-smoke.sh"
else
  printf 'SKIP discovery: VISP_GATE_DISCOVERY_FAKE_FIXTURE is unset.\n'
fi
# The audit hash chain. Everything this run wrote is sealed within a few ticks
# of the sealer (it waits for transactions that are still open), every event
# of this run is marked sealed, and a check of the newest links finds them
# intact. The check is itself recorded, and only an administrator may ask.
sealed=false
for _ in $(seq 1 90); do
  call GET /audit/integrity 200 "$admin_jar"
  if jq --exit-status '.unsealed == 0 and .sealed > 0 and .head.position == .sealed and (.head.hash | test("^[0-9a-f]{64}$")) and .head.key_id == .key_id' "$response" >/dev/null; then sealed=true; break; fi
  sleep 1
done
if [[ $sealed != true ]]; then printf 'FAIL audit rows were not sealed in 90 seconds\n' >&2; cat "$response" >&2; exit 1; fi
check '.verification.status != "broken" and .verification.problem == null'
sealed_rows=$(jq -er '.sealed' "$response")
call GET "/audit?actor_id=$admin_id&limit=200" 200 "$admin_jar"
check '(.items | length) > 0 and ([.items[] | select(.sealed != true or (.seq | type) != "number")] | length) == 0'
call POST /audit/verify 200 "$admin_jar" '{"limit":10000}'
check ".status == \"intact\" and .problem == null and .unverifiable == [] and .links > 0 and .verified == .links and .to_position == $sealed_rows and .head.position == $sealed_rows"
call GET "/audit?action=audit.verify&actor_id=$admin_id&limit=5" 200 "$admin_jar"
check "(.items | length) >= 1 and .items[0].details.status == \"intact\" and .items[0].details.to_position == $sealed_rows and .items[0].details.problem == null"
call GET /audit/integrity 403 "$member_jar"
call POST /audit/verify 403 "$member_jar" '{}'
pass "audit chain intact: $sealed_rows rows sealed and verified"
for jar in "$admin_jar" "$reviewer_jar" "$member_jar"; do call POST /auth/logout 204 "$jar"; done
printf 'SMOKE OK: login → project → cluster → connection → health → schema → analyze → SELECT → blocked DELETE → approval → review → execute → history/audit → agent session and fetch_rows → pre-flight → audit chain\n'
printf 'Fixtures retained: project=%s cluster=%s approval=%s agent=%s\n' "$project_id" "$cluster_id" "$approval_id" "$agent_id"
