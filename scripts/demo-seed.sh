#!/usr/bin/env bash
# DEMO ONLY. Sets up the five-minute demo through the public API of a running
# gateway: a database, a policy, a second person who can approve, an agent and
# its token. Then prints what to do next. Safe to run again: it reuses what is
# there. It is the one-shot `seed` step of deploy/demo/docker-compose.yml; see
# docs/DEMO.md.
#
# WARNING: this script creates an organisation administrator
# (reviewer@example.com by default) with a password you give it. Point it only
# at a demo or test gateway, never at a real one.
set -euo pipefail
umask 077
for tool in curl jq; do command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 1; }; done

base_url=${VISP_GATE_DEMO_URL:-http://127.0.0.1:8080}
public_url=${VISP_GATE_DEMO_PUBLIC_URL:-$base_url}
admin_email=${VISP_GATE_DEMO_ADMIN_EMAIL:-admin@example.com}
admin_password=${VISP_GATE_DEMO_ADMIN_PASSWORD:?Set VISP_GATE_DEMO_ADMIN_PASSWORD to the bootstrap administrator password}
reviewer_email=${VISP_GATE_DEMO_REVIEWER_EMAIL:-reviewer@example.com}
reviewer_password=${VISP_GATE_DEMO_REVIEWER_PASSWORD:?Set VISP_GATE_DEMO_REVIEWER_PASSWORD to a password of 12 characters or more}
target_host=${VISP_GATE_DEMO_TARGET_HOST:-demo-postgres}
target_port=${VISP_GATE_DEMO_TARGET_PORT:-5432}
target_db=${VISP_GATE_DEMO_TARGET_DATABASE:-shop}
target_user=${VISP_GATE_DEMO_TARGET_USER:-shop_gate}
target_password=${VISP_GATE_DEMO_TARGET_PASSWORD:?Set VISP_GATE_DEMO_TARGET_PASSWORD to the password of the database login}
token_file=${VISP_GATE_DEMO_TOKEN_FILE:-}
project_name='Demo shop'
cluster_name='shop-production'
agent_name='demo-agent'

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
jar="$work_dir/admin.cookies"
response="$work_dir/response.json"

say() { printf '%s\n' "$*"; }
fail() { printf 'DEMO SEED FAILED: %s\n' "$*" >&2; [[ -s $response ]] && cat "$response" >&2; exit 1; }

# One call of the session API. The answer is left in $response.
call() {
  local method=$1 path=$2 expected=$3 body=${4-}
  local -a args=(--silent --show-error --max-time 60 --request "$method"
    --header 'X-Requested-With: vda' --cookie "$jar" --cookie-jar "$jar"
    --output "$response" --write-out '%{http_code}')
  if [[ -n $body ]]; then args+=(--header 'Content-Type: application/json' --data-binary @-); fi
  local status
  status=$(curl "${args[@]}" "$base_url/api/v1$path" <<< "$body") || fail "$method $path: no answer from $base_url"
  [[ $status == "$expected" ]] || fail "$method $path: expected HTTP $expected, received $status"
}

say 'Waiting for the gateway …'
ready=false
for _ in $(seq 1 120); do
  if curl --fail --silent --max-time 3 "$base_url/readyz" >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
[[ $ready == true ]] || fail "the gateway at $base_url did not become ready in two minutes; read its log with: docker compose -f deploy/demo/docker-compose.yml logs gateway"

call POST /auth/login 200 "$(jq -n --arg email "$admin_email" --arg password "$admin_password" '{email:$email,password:$password}')"
say "Signed in as $admin_email."

# The project and the database. The password of the database login is sent
# once, here; the gateway stores it encrypted and never returns it.
call GET /projects 200
project_id=$(jq -r --arg name "$project_name" '[.items[] | select(.name == $name)][0].id // empty' "$response")
if [[ -z $project_id ]]; then
  call POST /projects 200 "$(jq -n --arg name "$project_name" '{name:$name,description:"Made-up shop data for the five-minute demo"}')"
  project_id=$(jq -er '.id' "$response")
fi
call GET /clusters 200
cluster_id=$(jq -r --arg name "$cluster_name" '[.items[] | select(.name == $name)][0].id // empty' "$response")
new_cluster=false
if [[ -z $cluster_id ]]; then
  new_cluster=true
  call POST /clusters 200 "$(jq -n --arg project "$project_id" --arg name "$cluster_name" --arg host "$target_host" \
    --argjson port "$target_port" --arg database "$target_db" --arg username "$target_user" --arg password "$target_password" \
    '{project_id:$project,name:$name,engine:"postgres",provider:"other",region:"local",environment:"production",
      host:$host,port:$port,database:$database,username:$username,password:$password,tls_mode:"disable"}')"
  cluster_id=$(jq -er '.id' "$response")
fi
healthy=false
for _ in $(seq 1 30); do
  call POST "/clusters/$cluster_id/health/check" 200
  if jq --exit-status '.status == "healthy"' "$response" >/dev/null; then healthy=true; break; fi
  sleep 2
done
[[ $healthy == true ]] || fail "the gateway cannot reach the demo database at $target_host:$target_port"
say "Database \"$cluster_name\" is registered and healthy."

# The policy that the demo shows: a row cap, two protected columns, one
# blocked table, and writes that are allowed only with an approval. It is set
# once, with the database, so a later run keeps what you changed in the console.
if [[ $new_cluster == true ]]; then
  call GET "/clusters/$cluster_id/policy" 200
  policy=$(jq '.max_rows = 50 | .max_affected_rows = 100 | .allow_writes = true | .require_approval_for_writes = true
    | .allow_ddl = false | .masked_columns = ["email","phone"] | .blocked_tables = ["payment_cards"]' "$response")
  call PUT "/clusters/$cluster_id/policy" 200 "$policy"
  say 'Policy set: 50 rows a query, email and phone masked, payment_cards blocked, writes need an approval.'
else
  say 'The database was set up before; its policy is left as it is.'
fi

# A second person. The owner of an agent cannot approve its writes.
call GET /users 200
if ! jq --exit-status --arg email "$reviewer_email" '[.items[] | select(.email == $email)] | length > 0' "$response" >/dev/null; then
  call POST /users 200 "$(jq -n --arg email "$reviewer_email" --arg password "$reviewer_password" \
    '{email:$email,name:"Demo reviewer",password:$password,org_role:"admin"}')"
fi

# The agent. It acts for the administrator, on this one database, and may
# ask for writes. Its token is made once and kept where the scripted agent
# of the demo can read it.
call GET '/agents?limit=200' 200
agent_id=$(jq -r --arg name "$agent_name" --arg owner "$admin_email" \
  '[.items[] | select(.name == $name and .owner.email == $owner)][0].id // empty' "$response")
if [[ -z $agent_id ]]; then
  call POST /agents 200 "$(jq -n --arg name "$agent_name" --arg cluster "$cluster_id" \
    '{name:$name,description:"The scripted agent of the five-minute demo",max_level:"write",cluster_ids:[$cluster]}')"
  agent_id=$(jq -er '.id' "$response")
fi
token_works() {
  local status
  status=$(curl --silent --max-time 30 --output /dev/null --write-out '%{http_code}' \
    --header "Authorization: Bearer $1" "$base_url/api/v1/agent/whoami") || return 1
  [[ $status == 200 ]]
}
agent_token=
if [[ -n $token_file && -s $token_file ]]; then
  agent_token=$(head -n 1 -- "$token_file")
  token_works "$agent_token" || agent_token=
fi
if [[ -z $agent_token ]]; then
  # No usable token is at hand: revoke the old ones and make a new one.
  call GET "/agents/$agent_id" 200
  for token_id in $(jq -r '.tokens[] | select(.revoked_at == null) | .id' "$response"); do
    call DELETE "/agents/$agent_id/tokens/$token_id" 204
  done
  call POST "/agents/$agent_id/tokens" 200 '{"expires_in_days":7}'
  agent_token=$(jq -er '.token' "$response")
  token_works "$agent_token" || fail 'the new agent token was refused'
  if [[ -n $token_file ]]; then
    # Mode 0600: the demo `agent` container runs as root in the same image and
    # mounts this volume read-only, and root can read it. Remove the old file
    # first, so a re-run never keeps an older mode or owner.
    rm -f -- "$token_file"
    printf '%s\n' "$agent_token" > "$token_file"
    chmod 0600 -- "$token_file"
  fi
fi
call POST /auth/logout 204

# Passwords are shown only when they are the well-known demo defaults of
# deploy/demo/docker-compose.yml.
shown_admin_password='(the password you set)'
shown_reviewer_password='(the password you set)'
[[ $admin_password == demo-admin-local-only ]] && shown_admin_password=$admin_password
[[ $reviewer_password == demo-reviewer-local-only ]] && shown_reviewer_password=$reviewer_password
if [[ ${VISP_GATE_DEMO_URL:-} == http://gateway:8080 ]]; then
  agent_command='docker compose -f deploy/demo/docker-compose.yml run --rm agent'
else
  agent_command="VISP_GATE_DEMO_URL=$base_url VISP_GATE_AGENT_TOKEN_FILE=${token_file:-<token file>} bash scripts/demo-agent.sh"
fi

cat <<TEXT

================================================================================
  DEMO ONLY. Well-known passwords, plain HTTP, made-up data. Loopback only.
================================================================================
  This script made an organisation administrator, $reviewer_email.
  Point it only at a demo or test gateway.

The gate is running. Three things to do:

1. Watch an agent work through the gate (it takes a few seconds):

     $agent_command

2. Open the console:  $public_url

     Sign in as    $reviewer_email
     Password      $shown_reviewer_password

   Agents  →  $agent_name    shows every step the agent took.
   Approvals                 shows the write the agent asked for. Start its
                             preview, read "What changes", then approve or
                             reject it.

   The agent belongs to $admin_email (password: $shown_admin_password).
   The owner of an agent cannot approve its writes, so use the reviewer.

3. Connect your own agent instead of the script. Any MCP client that speaks
   Streamable HTTP works. Claude Code:

     claude mcp add --transport http visp-gate $public_url/api/v1/mcp --header "Authorization: Bearer $agent_token"

   Cursor (.cursor/mcp.json) and other clients that take a URL and headers:

     {
       "mcpServers": {
         "visp-gate": {
           "url": "$public_url/api/v1/mcp",
           "headers": { "Authorization": "Bearer $agent_token" }
         }
       }
     }

   This token is valid for 7 days, for this demo only.

Remove everything:  docker compose -f deploy/demo/docker-compose.yml down -v
Steps and what to look for: docs/DEMO.md
TEXT
