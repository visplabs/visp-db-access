import { ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';
import type { Cluster } from '../../api/types';
import { cloudLine } from '../../lib/cloud';
import { Badge, EnvBadge, HealthBadge, Tip } from './index';

/** Where a cluster runs. Plain text with no colour: colour is kept for risk. */
export function CloudLabel({
  cluster,
  engine = true,
}: {
  cluster: Pick<Cluster, 'provider' | 'region' | 'engine'>;
  /** Leave the engine out where the row already shows it. */
  engine?: boolean;
}) {
  return <span className="cloud-label">{cloudLine(cluster, engine)}</span>;
}

/** A single operational identity line, shared by cluster and query routes. */
export function ClusterHeading({
  cluster,
  children,
}: {
  cluster: Cluster;
  children?: ReactNode;
}) {
  return (
    <div className="cluster-heading-compact">
      <Tip text="All clusters">
        <Link
          className="button ghost icon"
          to="/clusters"
          aria-label="All clusters"
        >
          <ArrowLeft size={16} />
        </Link>
      </Tip>
      <h1>{cluster.name}</h1>
      <EnvBadge environment={cluster.environment} />
      <CloudLabel cluster={cluster} />
      <HealthBadge
        status={cluster.health.status}
        latency={cluster.health.latency_ms}
      />
      <span
        className="cluster-endpoint mono muted"
        title={`${cluster.host}:${cluster.port} / ${cluster.database}`}
      >
        {cluster.host}:{cluster.port}
      </span>
      <Badge>{`${cluster.my_access ?? 'No'} access`}</Badge>
      {children}
    </div>
  );
}
