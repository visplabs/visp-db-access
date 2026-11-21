# Development

## Prerequisites

- Rust stable (1.91.1 or newer; see `rust-toolchain.toml`)
- Node.js 22.12 or newer and npm
- `curl` and `jq` for the smoke tests
- Linux x86_64 for the Docker-free database scripts below, or Docker for the
  alternatives

## Run the console without a backend

Mock mode serves the console with an in-memory API and demo data. No database,
server or AWS account is needed:

```sh
cd web
npm ci
npm run dev:mock
```

Sign in with `admin@visp.dev`, `reviewer@visp.dev` or `member@visp.dev`; the
password is `demo-password`. The mock includes ten clusters across three
projects, failed and degraded health, masked results, approvals in several
states and AWS discovery sources. Its SQL classifier is a simplified simulation;
the real server always re-analyzes queries. Mock code is excluded from
production builds.

## Run the full stack locally

The scripts below run PostgreSQL and MySQL as your user, without root or Docker.
Binaries and data live under `~/.local/share/` and survive reboots. They bind to
loopback only and use well-known local passwords — never reuse them elsewhere.

```sh
scripts/local-postgres.sh seed    # PostgreSQL 14 on 127.0.0.1:55432 with demo data
scripts/local-mysql.sh seed       # MySQL 8.4 on 127.0.0.1:33306 with demo data
scripts/local-mariadb.sh seed     # optional: MariaDB 11.4 on 127.0.0.1:33307
scripts/dev-local.sh              # builds the console and server, serves on :8080
```

`local-postgres.sh` downloads the Ubuntu PostgreSQL packages with
`apt-get download`; the MySQL and MariaDB scripts download the official generic
Linux archives. Each script supports `start`, `stop`, `status` and `seed`.

`dev-local.sh` applies migrations to the `vda_meta` metadata database, bootstraps
`admin@local.test` / `local-admin-password` on first run, allows loopback
targets and plain-HTTP cookies, and keeps a generated master key in
`.dev/master-key`. Keep that file while you keep the metadata: stored cluster
passwords can't be decrypted without it. Override any `VDA_*` variable to
change the defaults.

Demo database accounts:

| Account                                                        | Password         | Access                                           |
| -------------------------------------------------------------- | ---------------- | ------------------------------------------------ |
| `shop_reader`                                                  | `shop_reader_pw` | `SELECT` on `shop`                               |
| `shop_writer`                                                  | `shop_writer_pw` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `shop` |
| `vda` (Postgres, no password) / `vda` / `vda_local_pw` (MySQL) |                  | Local admin for tests                            |

In the console, add a cluster for `127.0.0.1:55432` (PostgreSQL) or
`127.0.0.1:33306` (MySQL), database `shop`, user `shop_reader`, with
environment `development` and TLS mode `disable`. The local databases have no
certificate the gateway can verify, so the default `verify full` fails the
connection test. Loopback
hosts work here only because `dev-local.sh` sets `VDA_ALLOW_PRIVATE_TARGETS`.

To work on the UI against the real server with hot reload, keep `dev-local.sh`
running and start `npm run dev` in `web/`; it proxies API requests to port 8080.

## Tests

### Rust

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --release -p vda-guard -- --ignored   # guard performance check
```

Tests that need a database skip themselves unless their URL is set. To run
everything against the local databases:

```sh
export VDA_TEST_DATABASE_URL=postgres://vda@127.0.0.1:55432/postgres
export VDA_TEST_POSTGRES_URL=postgres://vda@127.0.0.1:55432/postgres
export VDA_TEST_PG_URL=postgres://vda@127.0.0.1:55432/shop
export VDA_TEST_MYSQL_URL=mysql://vda:vda_local_pw@127.0.0.1:33306/shop
export VDA_TEST_MYSQL_PASSWORD=vda_local_pw
cargo test --workspace --all-features
```

Use disposable databases: tests create uniquely named schemas and tables and
drop them on success. Point `VDA_TEST_MYSQL_URL` at port 33307 to run the
connector tests against MariaDB. With Docker instead of the scripts, see
[connector tests](../crates/vda-connectors/tests/README.md).

### Web

```sh
cd web
npm run typecheck
npm run lint
npm run format:check
npm test              # unit tests (Vitest)
npx playwright install chromium   # once
npm run test:e2e      # browser tests against mock mode
npm run build         # fails if the initial JavaScript exceeds 250 KiB gzip
```

CI runs lint, the unit tests, the build and the browser tests (Chromium only)
on every push and pull request.

The browser tests include an accessibility scan (axe) of every route at desktop
and phone sizes in both themes. Screenshots they write go to the ignored
`web/screenshots/` directory.

### End-to-end smoke test

With `dev-local.sh` running, `scripts/e2e-smoke.sh` drives the real API: sign-in,
project and cluster setup, health and schema, masked and truncated reads, blocked
statements, scoped grants, the full approval lifecycle, history and audit, an
agent session with its steps and one `fetch_rows` page, the pre-flight answer,
and at its end that every audit row of the run is sealed and the hash chain is
intact. Set
`VDA_SMOKE_MYSQL_HOST=127.0.0.1` (and `VDA_SMOKE_MYSQL_PORT=33307` for MariaDB)
to add the MySQL section, and `VDA_DISCOVERY_FAKE_FIXTURE` to add discovery (see
[AWS discovery](DISCOVERY.md#developing-without-aws)). The script creates
uniquely named records and leaves them for inspection. All `VDA_SMOKE_*`
settings are listed at the top of the script.

### Demo walkthrough

`scripts/demo-seed.sh` and `scripts/demo-agent.sh` are the two steps of the
[five-minute demo](DEMO.md). The second one plays an agent at the agent door
and exits non-zero when the gate does not behave as the demo says, so it is
also a test of a running gateway from the outside:

```sh
docker compose -f deploy/demo/docker-compose.yml up --build -d
docker compose -f deploy/demo/docker-compose.yml wait seed
docker compose -f deploy/demo/docker-compose.yml run --rm agent
docker compose -f deploy/demo/docker-compose.yml down -v
```

## Useful scripts

| Command (in `web/`)                        | Purpose                                                                                                                                     |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run screenshots:readme`               | Regenerate `docs/images/` from a mock server on port 5179 (start it first: `npm run dev:mock -- --host 127.0.0.1 --port 5179 --strictPort`) |
| `npm run audit:ui`, `npm run audit:states` | Capture every route and state with axe reports (mock server on port 5175)                                                                   |

## Releasing

1. Set the new version in `Cargo.toml` (`workspace.package.version`),
   `web/package.json`, and `version`, `appVersion` and `image.tag` in the Helm
   chart, then run `cargo check` to update `Cargo.lock`.
2. Move the `Unreleased` entries in `CHANGELOG.md` under the new version and
   date, and update the comparison links at the bottom.
3. Commit, then tag and push: `git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0`.

The `Release` workflow checks that the tag matches these versions, publishes
the image to `ghcr.io/djkeshawa/visp-db-access`, and creates a GitHub release
with the changelog section and a Linux x86_64 binary.

## Conventions

- Rust: `unsafe_code` is forbidden and `unwrap`, `expect` and `panic!` are
  denied by workspace lints; tests opt out locally.
- The UI follows the [design system](DESIGN.md) and the
  [primitives](../web/src/components/ui/README.md); check new components in the
  development-only `/ui?kitchen-sink` route.
- `docs/API.md` is the authoritative API contract; update it together with the
  server and `web/src/api/types.ts`.

## Verification tools

CI runs every check below; run them locally before you push.

| Check                                       | Command                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Rust format and lint                        | `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests, attack corpus and mutation test | `cargo test --workspace`                                                                 |
| Vulnerable crates, licenses, crate sources  | `cargo deny check` (rules in `deny.toml`)                                                |
| Rust line coverage                          | `cargo llvm-cov --workspace --summary-only`                                              |
| Web lint, format, types                     | `npm run lint`, `npm run format:check`, `npm run typecheck` in `web/`                    |
| Web tests                                   | `npm test` and `npm run test:e2e` in `web/`                                              |
| Vulnerable npm packages                     | `npm audit --omit=dev` and `npm audit --audit-level=high` in `web/`                      |
| Workflow files, Dockerfile, shell scripts   | `actionlint`, `hadolint Dockerfile`, `shellcheck scripts/*.sh`                           |
| Committed secrets                           | `gitleaks git .`                                                                         |

The SQL guard also has a libFuzzer target that runs weekly in CI
(`.github/workflows/fuzz.yml`). To run it locally you need the nightly
toolchain and `cargo-fuzz`:

```sh
cd crates/vda-guard && cargo +nightly fuzz run analyze -- -max_total_time=600
```

An advisory may be ignored in `deny.toml` only with a written reason.
