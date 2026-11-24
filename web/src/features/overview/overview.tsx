import { Link } from 'react-router-dom';
import { ArrowUpRight, ChevronRight, Radar } from 'lucide-react';
import type { Cluster } from '../../api/types';
import { useResource } from '../../lib/query';
import {
  EnvBadge,
  ErrorPanel,
  HealthBadge,
  Skeleton,
} from '../../components/ui';
import { VerdictChip } from '../../components/ui/verdict';
import { useUser } from '../auth/session';
import { SetupChecklist } from './setup';
import { MyWork, NeedsYou } from './my-work';
import { allowedCount, gateTiles, type Overview } from './model';
import { AgentActivity } from './agents';

const plural = (n: number, one: string, many = `${one}s`) =>
  `${n.toLocaleString('en')} ${n === 1 ? one : many}`;

function Heading() {
  return (
    <div className="page-heading ov-heading">
      <div>
        <h1>Workspace overview</h1>
        <p>What the gate did, and what needs you.</p>
      </div>
      <Link to="/console" className="button primary">
        Open console <ArrowUpRight size={16} aria-hidden />
      </Link>
    </div>
  );
}

/** What the gate did: one tile per verdict the API can count, each with
 * the time it covers. */
function GateTiles({ data }: { data: Overview }) {
  const tiles = gateTiles(data);
  const allowed = allowedCount(data);
  const total = data.queries_24h;
  return (
    <section className="ov-gate" aria-labelledby="ov-gate-title">
      <div className="ov-section-head">
        <h2 id="ov-gate-title">At the gate</h2>
        <span className="ov-count">
          {total
            ? `${plural(total, 'statement')} in the last 24 hours`
            : 'No statement reached the gate in 24 hours'}
        </span>
      </div>
      <ul className="ov-tiles">
        {tiles.map((tile) => (
          <li key={tile.verdict}>
            <Link
              className="ov-tile"
              to={tile.to}
              data-verdict={tile.verdict}
              data-zero={tile.count === 0 || undefined}
            >
              <span className="ov-tile-top">
                <VerdictChip verdict={tile.verdict} size="md" />
                <span className="ov-tile-window">
                  <span className="sr-only">, </span>
                  {tile.window}
                </span>
              </span>
              <span className="ov-tile-number">
                {tile.count.toLocaleString('en')}
              </span>
              <span className="ov-tile-meaning">{tile.meaning}</span>
              {tile.note && <span className="ov-tile-note">{tile.note}</span>}
            </Link>
          </li>
        ))}
      </ul>
      {total > 0 && (
        <div
          className="ov-split"
          role="img"
          aria-label={`Of ${total} statements in 24 hours: ${allowed} let through and did not fail, ${data.errors_24h} failed on the database, ${data.blocked_24h} stopped`}
        >
          {allowed > 0 && (
            <i
              data-verdict="allowed"
              style={{ flexGrow: allowed }}
              aria-hidden
            />
          )}
          {data.errors_24h > 0 && (
            <i
              data-verdict="failed"
              style={{ flexGrow: data.errors_24h }}
              aria-hidden
            />
          )}
          {data.blocked_24h > 0 && (
            <i
              data-verdict="blocked"
              style={{ flexGrow: data.blocked_24h }}
              aria-hidden
            />
          )}
        </div>
      )}
    </section>
  );
}

const SEVERITY: Record<string, number> = { down: 0, degraded: 1 };

/** Down and degraded databases, apart from the review list. */
function DatabaseHealth({ data }: { data: Overview }) {
  const troubled = data.unhealthy_clusters
    .filter((cluster) => cluster.health.status in SEVERITY)
    .sort(
      (a, b) =>
        (SEVERITY[a.health.status] ?? 2) - (SEVERITY[b.health.status] ?? 2),
    );
  return (
    <section className="ov-health" aria-labelledby="ov-health-title">
      <div className="ov-section-head">
        <h2 id="ov-health-title">Database health</h2>
        <Link to="/clusters" className="ov-head-link">
          All databases
        </Link>
      </div>
      {data.clusters_total > 0 && (
        <dl className="ov-health-counts">
          {(
            [
              ['healthy', 'Healthy', data.healthy],
              ['degraded', 'Degraded', data.degraded],
              ['down', 'Down', data.down],
              ['unknown', 'Not checked', data.unknown],
            ] as const
          ).map(([status, word, n]) => (
            <div key={status} data-status={status} data-zero={!n || undefined}>
              <dt>
                <span className={`status-dot ${status}`} aria-hidden />
                {word}
              </dt>
              <dd>{n}</dd>
            </div>
          ))}
        </dl>
      )}
      {data.clusters_total === 0 ? (
        <p className="ov-calm">No database is connected yet.</p>
      ) : troubled.length ? (
        <ul className="ov-health-list">
          {troubled.map((cluster: Cluster) => (
            <li key={cluster.id}>
              <Link to={`/clusters/${cluster.id}?tab=health`}>
                <strong className="ov-health-name">{cluster.name}</strong>
                <span className="ov-health-why">
                  <EnvBadge environment={cluster.environment} />
                  {cluster.health.error ?? 'Slow to answer'}
                </span>
                <HealthBadge
                  status={cluster.health.status}
                  latency={cluster.health.latency_ms}
                />
              </Link>
            </li>
          ))}
        </ul>
      ) : (
        <p className="ov-calm">
          All {plural(data.clusters_total, 'database')} answer the gate.
        </p>
      )}
    </section>
  );
}

function Discovery({ data }: { data: NonNullable<Overview['discovery']> }) {
  const changed = data.new + data.gone + data.drifted;
  return (
    <Link className="ov-discovery" to="/clusters?tab=discovered">
      <Radar size={16} aria-hidden />
      <span>
        <strong>Discovery</strong>
        <span>
          {changed
            ? `${data.new} new, ${data.gone} gone, ${data.drifted} drifted`
            : 'No new, gone or drifted resources'}
        </span>
      </span>
      <ChevronRight size={16} aria-hidden />
    </Link>
  );
}

export function OverviewPage() {
  const query = useResource<Overview>('/overview'),
    user = useUser();
  const admin = user?.org_role === 'admin';
  if (query.isPending || query.error)
    return (
      <>
        <Heading />
        {query.isPending ? (
          <Skeleton />
        ) : (
          <ErrorPanel error={query.error!} retry={() => void query.refetch()} />
        )}
      </>
    );
  const data = query.data;
  return (
    <div className="ov">
      <Heading />
      {admin && <SetupChecklist />}
      <AgentActivity />
      <GateTiles data={data} />
      <div className="ov-columns">
        <div className="ov-main">
          <NeedsYou />
          <MyWork />
        </div>
        <aside className="ov-side" aria-label="Databases">
          <DatabaseHealth data={data} />
          {admin && data.discovery && <Discovery data={data.discovery} />}
        </aside>
      </div>
    </div>
  );
}
