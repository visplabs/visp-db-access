// Audit of build and test tooling: no high or critical finding may reach the
// tree unless every advisory behind it is an exception listed here. Packages
// that ship in the console are checked separately with `npm audit --omit=dev`,
// which has no exceptions.
//
// Fails closed: a refused finding, audit output that cannot be read, or an
// exception that no longer matches anything all exit non-zero.
import { spawnSync } from 'node:child_process';

// Each exception names the advisory, why it is accepted, and when it was
// added. Remove an entry as soon as a fixed release is available.
const ALLOWED = [
  {
    // Remove when a fixed picomatch is released (latest is 4.0.7, affected).
    id: 'GHSA-fc5q-39xc-vjpf',
    reason:
      'picomatch ReDoS with no fixed release; reaches us only through dev tooling (vite, vitest, tinyglobby, fdir, typescript-eslint) on trusted glob patterns',
    added: '2026-11-18',
  },
];

const GATED = new Set(['high', 'critical']);

function fail(message) {
  console.error(`audit:dev: ${message}`);
  process.exit(1);
}

function readAudit() {
  const run = spawnSync('npm', ['audit', '--json'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (run.error) fail(`could not run npm audit: ${run.error.message}`);
  let report;
  try {
    report = JSON.parse(run.stdout);
  } catch {
    fail(
      `npm audit output is not JSON (exit ${run.status}): ${run.stderr.trim()}`,
    );
  }
  if (
    !report ||
    report.error ||
    typeof report.vulnerabilities !== 'object' ||
    report.vulnerabilities === null
  ) {
    fail(
      `npm audit did not report vulnerabilities: ${JSON.stringify(report?.error ?? report)}`,
    );
  }
  return report.vulnerabilities;
}

// The advisory id: the GHSA id from its URL, else npm's own source number.
function advisoryId(via) {
  const fromUrl = typeof via.url === 'string' ? via.url.split('/').pop() : '';
  if (fromUrl) return fromUrl;
  if (via.source !== undefined) return `npm-${via.source}`;
  return null;
}

// The advisories at the root of a package's finding, following `via` through
// other vulnerable packages. Each root is {id, severity, name}.
function roots(vulnerabilities, name, seen = new Set()) {
  if (seen.has(name)) return [];
  seen.add(name);
  const entry = vulnerabilities[name];
  if (!entry || !Array.isArray(entry.via)) {
    fail(`cannot follow the finding for ${name}`);
  }
  return entry.via.flatMap((via) => {
    if (typeof via === 'string') return roots(vulnerabilities, via, seen);
    const id = advisoryId(via);
    if (!id) fail(`an advisory behind ${name} has no id`);
    return [{ id, severity: via.severity, name: via.name ?? name }];
  });
}

const vulnerabilities = readAudit();
const allowed = new Set(ALLOWED.map((entry) => entry.id));
const seenAdvisories = new Set();
const accepted = [];
const refused = [];

for (const [name, entry] of Object.entries(vulnerabilities)) {
  const behind = roots(vulnerabilities, name);
  for (const root of behind) seenAdvisories.add(root.id);
  if (!GATED.has(entry.severity)) continue;
  // Only high and critical advisories are gated, as `--audit-level=high`
  // did; a gated finding with no such advisory behind it is refused.
  const gated = behind.filter((root) => GATED.has(root.severity));
  const ids = [...new Set(gated.map((root) => root.id))];
  const blocked = ids.filter((id) => !allowed.has(id));
  if (ids.length > 0 && blocked.length === 0) {
    accepted.push(`${name} (${entry.severity}) via ${ids.join(', ')}`);
  } else {
    refused.push(
      `${name} (${entry.severity}) via ${blocked.length > 0 ? blocked.join(', ') : 'no identifiable high or critical advisory'}`,
    );
  }
}

for (const line of accepted) console.log(`allowed: ${line}`);
for (const line of refused) console.error(`refused: ${line}`);

const stale = ALLOWED.filter((entry) => !seenAdvisories.has(entry.id));
for (const entry of stale) {
  console.error(
    `stale exception: ${entry.id} (added ${entry.added}) no longer appears in npm audit; remove it from scripts/audit-dev.mjs`,
  );
}

if (refused.length > 0 || stale.length > 0) process.exit(1);
console.log(
  `audit:dev: ok (${accepted.length} finding(s) allowed by ${ALLOWED.length} exception(s))`,
);
