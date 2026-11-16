import type { Cluster, Engine, Provider } from '../api/types';

/** Where a database runs, as a person would say it. */
export const cloudName: Record<Provider, string> = {
  aws: 'AWS',
  gcp: 'Google Cloud',
  azure: 'Azure',
  onprem: 'On-premises',
  other: 'Other',
};
export const engineName: Record<Engine, string> = {
  postgres: 'PostgreSQL',
  mysql: 'MySQL',
};
/** Cloud, region and engine in one line: "AWS · us-east-1 · PostgreSQL". */
export const cloudLine = (
  cluster: Pick<Cluster, 'provider' | 'region' | 'engine'>,
  engine = true,
): string =>
  [
    cloudName[cluster.provider],
    cluster.region,
    engine ? engineName[cluster.engine] : '',
  ]
    .filter(Boolean)
    .join(' · ');
