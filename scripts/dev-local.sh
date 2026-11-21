#!/usr/bin/env bash
# Local development only: binds loopback and permits loopback database targets.
set -euo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
export VISP_GATE_DATABASE_URL=${VISP_GATE_DATABASE_URL:-postgres://vda@127.0.0.1:55432/vda_meta}
export VISP_GATE_BIND=${VISP_GATE_BIND:-127.0.0.1:8080}
export VISP_GATE_COOKIE_SECURE=${VISP_GATE_COOKIE_SECURE:-false}
export VISP_GATE_ALLOW_PRIVATE_TARGETS=${VISP_GATE_ALLOW_PRIVATE_TARGETS:-true}
export VISP_GATE_BOOTSTRAP_ADMIN_EMAIL=${VISP_GATE_BOOTSTRAP_ADMIN_EMAIL:-admin@local.test}
export VISP_GATE_BOOTSTRAP_ADMIN_PASSWORD=${VISP_GATE_BOOTSTRAP_ADMIN_PASSWORD:-local-admin-password}

# Build the SPA before Rust compilation so rust-embed picks up current assets.
npm --prefix web run build
build_args=(-p vda-server)
if [[ -n ${VISP_GATE_DISCOVERY_FAKE_FIXTURE:-} ]]; then
  if [[ ! -r $VISP_GATE_DISCOVERY_FAKE_FIXTURE ]]; then
    printf 'Discovery fixture is not readable: %s\n' "$VISP_GATE_DISCOVERY_FAKE_FIXTURE" >&2
    exit 1
  fi
  build_args+=(--features fake-discovery)
  printf 'WARNING: enabling fake cloud discovery for local development.\n' >&2
fi
cargo build "${build_args[@]}"
server_bin="${CARGO_TARGET_DIR:-target}/debug/visp-gate"
if [[ -z ${VISP_GATE_MASTER_KEY:-} ]]; then
  # Keep a stable key across restarts; changing it makes stored credentials unreadable.
  # Outside build caches so cleaning target dirs never orphans stored credentials.
  key_dir="$repo_dir/.dev"
  mkdir -p -- "$key_dir"
  key_file="$key_dir/master-key"
  if [[ ! -s $key_file ]]; then
    "$server_bin" gen-key > "$key_file"
  fi
  export VISP_GATE_MASTER_KEY
  VISP_GATE_MASTER_KEY=$(cat -- "$key_file")
fi
printf 'Starting local gateway at %s (Ctrl+C to stop).\n' "$VISP_GATE_BIND"
exec "$server_bin" serve
