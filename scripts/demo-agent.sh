#!/usr/bin/env bash
# Plays an AI agent at the gateway's agent door (Model Context Protocol over
# HTTP) and prints each step. It is the scripted agent of the five-minute demo
# (docs/DEMO.md), and it is a test too: it exits non-zero when a step does not
# behave as the demo says.
#
#   docker compose -f deploy/demo/docker-compose.yml run --rm agent [--follow]
#   VISP_GATE_AGENT_TOKEN=… VISP_GATE_DEMO_URL=http://127.0.0.1:8080 scripts/demo-agent.sh [--follow]
#
# --follow  after the write is asked for, wait until a person has approved and
#           run it, or rejected it, in the console, and print the outcome.
#
# It expects the demo's database and policy (scripts/demo-seed.sh): the shop
# data, a cap of 50 rows a query, `email` and `phone` protected, the table
# `payment_cards` blocked, and writes that need an approval.
set -euo pipefail
umask 077
for tool in curl jq; do command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 1; }; done

follow=false
for argument in "$@"; do
  case $argument in
    --follow) follow=true ;;
    -h | --help) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'Unknown argument: %s (try --help)\n' "$argument" >&2; exit 2 ;;
  esac
done

base_url=${VISP_GATE_DEMO_URL:-http://127.0.0.1:8080}
public_url=${VISP_GATE_DEMO_PUBLIC_URL:-$base_url}
database_name=${VISP_GATE_DEMO_DATABASE:-shop-production}
follow_seconds=${VISP_GATE_DEMO_FOLLOW_SECONDS:-900}
token=${VISP_GATE_AGENT_TOKEN:-}
if [[ -z $token && -n ${VISP_GATE_AGENT_TOKEN_FILE:-} && -r ${VISP_GATE_AGENT_TOKEN_FILE:-} ]]; then
  token=$(head -n 1 -- "$VISP_GATE_AGENT_TOKEN_FILE")
fi
if [[ -z $token ]]; then
  printf 'No agent token. Set VISP_GATE_AGENT_TOKEN, or VISP_GATE_AGENT_TOKEN_FILE to a file that holds one.\n' >&2
  exit 2
fi

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
raw="$work_dir/raw.json"
answer="$work_dir/answer.json"
: > "$answer"

if [[ -t 1 ]]; then bold=$'\033[1m'; dim=$'\033[2m'; green=$'\033[32m'; red=$'\033[31m'; plain=$'\033[0m'
else bold=''; dim=''; green=''; red=''; plain=''; fi
step_number=0
step() { step_number=$((step_number + 1)); printf '\n%s%d. %s%s\n' "$bold" "$step_number" "$1" "$plain"; }
line() { printf '   %-9s %s\n' "$1" "$2"; }
note() { printf '   %s%s%s\n' "$dim" "$1" "$plain"; }
good() { printf '   %s✓ %s%s\n' "$green" "$1" "$plain"; }
broken() {
  printf '\n%s✗ NOT AS THE DEMO SAYS: %s%s\n' "$red" "$1" "$plain" >&2
  if [[ -s $answer ]]; then printf 'The last answer was:\n' >&2; jq . "$answer" >&2 || cat "$answer" >&2; fi
  exit 1
}
# A claim about the last answer: a jq condition, what it means, and any
# further arguments for jq (such as --arg name value).
claim() {
  local condition=$1 meaning=$2
  shift 2
  jq --exit-status "$@" "$condition" "$answer" >/dev/null 2>&1 || broken "$meaning"
}
value() { jq -r "$1" "$answer"; }

# One JSON-RPC message to the agent door. The whole answer is left in $raw.
rpc() {
  local method=$1 params=$2 status
  status=$(jq -n --arg method "$method" --argjson params "$params" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}' |
    curl --silent --show-error --max-time 120 --request POST \
      --header 'Content-Type: application/json' --header 'Accept: application/json' \
      --header "Authorization: Bearer $token" \
      --output "$raw" --write-out '%{http_code}' --data-binary @- "$base_url/api/v1/mcp") ||
    broken "the gateway at $base_url did not answer"
  if [[ $status == 401 ]]; then
    printf '\n%sThe gateway refused the agent (401).%s The agent is paused, or its token is wrong, expired or revoked.\n' "$red" "$plain" >&2
    printf 'Resume the agent in the console, or run the demo'"'"'s seed step again for a new token.\n' >&2
    exit 1
  fi
  if [[ $status != 200 ]]; then cp -- "$raw" "$answer"; broken "$method: HTTP $status"; fi
}
# Call one tool. A refusal is an answer too: the structured content, with
# `is_error`, is left in $answer.
tool() {
  rpc tools/call "$(jq -n --arg name "$1" --argjson arguments "$2" '{name:$name,arguments:$arguments}')"
  jq '.result.structuredContent + {is_error: .result.isError}' "$raw" > "$answer"
}
# The rows of an answer as an aligned table; protected columns are marked.
table() {
  jq -r '
    (.columns | map(.name + (if .masked then " (protected)" else "" end))) as $head
    | ([$head] + (.rows | map(map(if . == null then "null" elif type == "string" then . else tojson end)))) as $all
    | ([range(0; $head | length)] | map(. as $i | $all | map(.[$i] | length) | max)) as $width
    | $all[]
    | [range(0; length) as $i | .[$i] + (" " * ($width[$i] - (.[$i] | length)) // "")]
    | "      " + join("  ")' "$answer"
}

printf '%sAn agent at the gate%s  %s%s/api/v1/mcp%s\n' "$bold" "$plain" "$dim" "$base_url" "$plain"

step 'Connect and read the list of tools'
rpc initialize '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo-agent","version":"1"}}'
jq '.result' "$raw" > "$answer"
claim '.serverInfo.name == "visp-gate" and (.instructions | length) > 0' 'the server did not introduce itself'
line server "$(value '.serverInfo.name + " " + .serverInfo.version + ", protocol " + .protocolVersion')"
rpc tools/list '{}'
jq '.result' "$raw" > "$answer"
claim '[.tools[].name] == ["list_databases","search_schema","describe_table","check_sql","run_query","fetch_rows","propose_write","get_approval","withdraw"]' \
  'the agent door does not offer the nine tools'
line tools "$(value '[.tools[].name] | join(", ")')"
good 'nine tools, and none of them is "run any SQL"'

step 'list_databases: what can I reach?'
tool list_databases '{"task":"Demo: find the shop database"}'
claim '.is_error == false and (.databases | length) >= 1' 'the agent reaches no database'
database=$(jq -r --arg name "$database_name" '([.databases[] | select(.name == $name)][0] // .databases[0]).id' "$answer")
jq -r --arg id "$database" '.databases[] | select(.id == $id)
  | "   database  \(.name)  (\(.engine), \(.environment))\n   level     \(.level)\n   enforced  by the \(.enforced_by)"' "$answer"
# shellcheck disable=SC2016 # $id is a jq variable, not a shell one
claim '[.databases[] | select(.id == $id)][0].level == "write"' \
  'the agent should have write level on the demo database' --arg id "$database"
good 'the agent sees only the databases its owner gave it'
db=$(jq -n --arg id "$database" '$id')

step 'search_schema: where is customer data?'
tool search_schema "$(jq -n --argjson database "$db" '{task:"Demo: find tables about customers",database:$database,query:"customer"}')"
claim '.is_error == false and ([.tables[].table] | index("public.customers") != null)' 'search_schema did not find public.customers'
jq -r '.tables[] | "   \(.table)" + (if (.matching_columns | length) > 0 then "  (columns: " + (.matching_columns | join(", ")) + ")" else "" end)' "$answer"
claim '[.tables[].table | select(test("payment_cards"))] | length == 0' \
  'the blocked table payment_cards is listed, although it has a customer_id column and the policy blocks it'
good 'payment_cards has a customer_id column too, but the policy blocks it, so it is not listed'

step 'describe_table: which columns are protected?'
tool describe_table "$(jq -n --argjson database "$db" '{task:"Demo: read the columns of customers",database:$database,table:"customers"}')"
claim '.is_error == false' 'describe_table failed for customers'
jq -r '(.columns | map(.name | length) | max) as $width
  | .columns[] | "   " + .name + (" " * ($width - (.name | length)) // "") + "  " + .type + (if .protected then "  ← protected" else "" end)' "$answer"
claim '[.columns[] | select(.protected) | .name] | (index("email") != null and index("phone") != null)' \
  'email and phone should be marked as protected'
good 'the agent is told up front which values it will not see'

step 'check_sql: would this write be accepted? (nothing runs)'
careless="UPDATE orders SET status = 'cancelled'"
line sql "$careless"
tool check_sql "$(jq -n --argjson database "$db" --arg sql "$careless" '{task:"Demo: cancel stale orders",database:$database,sql:$sql}')"
claim '.is_error == false and .verdict == "deny"' 'a write with no WHERE clause should be refused'
line verdict "$(value '.verdict + "  (" + ([.issues[] | select(.severity == "block") | .code] | join(", ")) + ")"')"
claim '.fix.action == "rewrite_sql" and (.fix.hint | test("WHERE"))' 'the refusal should come with a fix that says to add a WHERE clause'
line fix "$(value '.fix.action + ": " + .fix.hint')"
good 'refused before anything ran, with a fix the agent can act on'

step 'run_query: read customers'
read_sql='SELECT id, name, email, phone FROM customers ORDER BY id'
line sql "$read_sql"
tool run_query "$(jq -n --argjson database "$db" --arg sql "$read_sql" '{task:"Demo: look at the first customers",database:$database,sql:$sql,max_rows:5}')"
claim '.is_error == false and .row_count == 5' 'the read should return five rows'
line ran_as "$(value '.ran_as')"
table
claim '.ran_as | test("LIMIT 51")' 'the guard should add LIMIT 51: the policy allows 50 rows, and one more shows whether there are more'
claim 'all(.rows[]; .[2] == "••••••" and .[3] == "••••••") and all(.rows[]; (.[1] | startswith("Customer ")))' \
  'email and phone should be masked, and name should not be'
claim '.truncated == true and .rows_left == 45 and (.next_cursor | startswith("rows_"))' \
  'the query should have fetched 50 rows: 5 in this answer and 45 held for fetch_rows'
line rows "$(value '"\(.row_count) in this answer, \(.rows_left) more held for fetch_rows, truncated: \(.truncated)"')"
good 'the guard added LIMIT 51 to the SQL, and the gate masked email and phone'
query_id=$(value '.query_id')
cursor=$(value '.next_cursor')

step 'fetch_rows: the next page of the same result (nothing runs again)'
tool fetch_rows "$(jq -n --arg cursor "$cursor" '{task:"Demo: read the next customers",cursor:$cursor,max_rows:5}')"
claim '.is_error == false and .row_count == 5' 'fetch_rows should return the next five rows'
table
claim '.rows[0][0] == 6 and all(.rows[]; .[2] == "••••••") and .rows_left == 40' \
  'the page should start at customer 6, be masked, and leave 40 rows'
# shellcheck disable=SC2016 # $id is a jq variable, not a shell one
claim '.query_id == $id' 'the page should belong to the query that ran before' --arg id "$query_id"
good 'rows 6 to 10 of the same query, masked the same way; no second query ran'

step 'run_query: try the blocked table'
blocked_sql='SELECT * FROM payment_cards LIMIT 5'
line sql "$blocked_sql"
tool run_query "$(jq -n --argjson database "$db" --arg sql "$blocked_sql" '{task:"Demo: look at payment cards",database:$database,sql:$sql}')"
claim '.is_error == true and .error.code == "query_denied"' 'a read of the blocked table should be refused'
line refused "$(value '.error.code + ": " + .error.message')"
claim '.error.fix.action == "stop"' 'the fix for a blocked table should be "stop"'
line fix "$(value '.error.fix.action + ": " + .error.fix.hint')"
good 'refused, and the agent is told to stop, not to try another spelling'

step 'run_query: find work to do, then try to write directly'
find_sql="SELECT customer_id, count(*) AS pending FROM orders WHERE status = 'pending' GROUP BY customer_id ORDER BY customer_id LIMIT 1"
tool run_query "$(jq -n --argjson database "$db" --arg sql "$find_sql" '{task:"Demo: find a customer with pending orders",database:$database,sql:$sql}')"
claim '.is_error == false and .row_count == 1' 'the demo data should hold a customer with pending orders'
customer=$(value '.rows[0][0]')
pending=$(value '.rows[0][1]')
[[ $customer =~ ^[0-9]+$ && $pending =~ ^[0-9]+$ ]] || broken 'the aggregate read should return two numbers'
note "customer $customer has $pending pending orders"
write_sql="UPDATE orders SET status = 'cancelled' WHERE customer_id = $customer AND status = 'pending'"
line sql "$write_sql"
tool run_query "$(jq -n --argjson database "$db" --arg sql "$write_sql" '{task:"Demo: cancel the pending orders of one customer",database:$database,sql:$sql}')"
claim '.is_error == true and .error.code == "approval_required"' 'a write through run_query should be refused with approval_required'
line refused "$(value '.error.code + ": " + .error.message')"
claim '.error.fix.action == "propose_write"' 'the fix for a write should send the agent to propose_write'
line fix "$(value '.error.fix.action + ": " + .error.fix.hint')"
good 'an agent cannot change data on its own, whatever its level'

step 'propose_write: ask a person for the write'
tool get_approval '{"task":"Demo: see whether earlier requests still wait"}'
claim '.is_error == false' 'get_approval should list the open requests'
for earlier in $(jq -r '.requests[] | select(.status == "pending" or .status == "approved") | .approval_id' "$answer"); do
  tool withdraw "$(jq -n --arg id "$earlier" '{task:"Demo: withdraw a request left from an earlier run",approval_id:$id}')"
  claim '.is_error == false and .status == "withdrawn"' 'an open request of an earlier run should be withdrawn'
  note "withdrew request $earlier, left from an earlier run"
done
reason="Demo: cancel the $pending pending orders of customer $customer, as their owner asked"
tool propose_write "$(jq -n --argjson database "$db" --arg sql "$write_sql" --arg task "$reason" '{task:$task,database:$database,sql:$sql}')"
claim '.is_error == false and .status == "pending" and .previewed == false and (.approval_id | length) == 36' \
  'propose_write should open a pending request that nobody has previewed yet'
approval=$(value '.approval_id')
line request "$approval"
line status "$(value '.status + ", previewed: " + (.previewed | tostring)')"
good 'the request waits for a person; nothing was written, and the agent saw no rows'

step 'get_approval: follow the request'
tool get_approval "$(jq -n --arg id "$approval" '{task:"Demo: see whether a person has decided",approval_id:$id}')"
claim '.is_error == false and .status == "pending" and .executed_rows == null' 'the request should still wait'
line status "$(value '.status')"

cat <<TEXT

${bold}Now it is your turn.${plain} Open $public_url/approvals and sign in as
reviewer@example.com (password: demo-reviewer-local-only). Open the request,
start its preview and read "What changes": the gateway tries the write on the
database, measures it and rolls it back. Then approve and run it, or reject it.
Agents → demo-agent shows the steps above as the gateway recorded them.
TEXT

if [[ $follow != true ]]; then
  printf '\nRun this again with --follow to see how the agent learns the outcome.\n'
  exit 0
fi

printf '\nWaiting for a person to decide (up to %s seconds; Ctrl+C stops waiting) …\n' "$follow_seconds"
waited=0
last=pending
while :; do
  tool get_approval "$(jq -n --arg id "$approval" '{task:"Demo: see whether a person has decided",approval_id:$id}')"
  claim '.is_error == false' 'get_approval failed while waiting'
  status=$(value '.status')
  if [[ $status != "$last" ]]; then line status "$status$(value 'if .previewed then "  (a person has previewed it)" else "" end')"; last=$status; fi
  case $status in
    executed)
      # shellcheck disable=SC2016 # $pending is a jq variable, not a shell one
      claim '.executed_rows == $pending' 'the write should have changed exactly the rows the agent counted' --argjson pending "$pending"
      line changed "$(value '.executed_rows') rows"
      good 'a person approved and ran the write; the agent learns the count and nothing else'
      exit 0 ;;
    rejected)
      line note "$(value '.review_note // "(none)"')"
      good 'a person rejected the write; nothing changed, and the agent reads why'
      exit 0 ;;
    pending | approved | executing) ;;
    *) broken "the request ended as \"$status\"" ;;
  esac
  if ((waited >= follow_seconds)); then
    printf '\nNobody decided in %s seconds. The request stays open for 24 hours.\n' "$follow_seconds"
    exit 0
  fi
  sleep 15
  waited=$((waited + 15))
done
