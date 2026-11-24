import type {
  Approval,
  AuditEvent,
  Cluster,
  Grant,
  HistoryEntry,
  Policy,
  Project,
  SchemaTree,
  User,
} from './types';
export const uuid = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const now = () => new Date().toISOString();
/** The demo's own agent. Jordan Lee runs it on the Commerce staging and
 * development databases; the seeded agent requests come from it. */
export const DEMO_AGENT = {
  id: uuid(900),
  name: 'support-assistant',
  description: 'Answers support tickets about orders and customer accounts.',
  /** Clusters by index: checkout-staging and commerce-dev. */
  clusters: [2, 3],
} as const;
/** History rows the demo agent ran, by index, with what it said they are for. */
const AGENT_ROWS: Record<number, string> = {
  2: 'Read the newest customers for the support summary',
  23: 'Count the open orders of a customer for ticket 4821',
  32: 'Check the account state before the anonymize request',
};
/** Rows whose outcome is not settled. They are from yesterday, so the last
 * 24 hours of the demo hold only finished runs. */
const OLD_ROWS: Record<number, number> = { 18: 25, 19: 26 };
export function defaultPolicy(environment: string): Policy {
  return {
    max_rows: environment === 'production' ? 1000 : 5000,
    statement_timeout_ms: environment === 'production' ? 15000 : 60000,
    lock_timeout_ms: 2000,
    max_cost: 100000,
    max_concurrent_queries: 4,
    allow_writes: environment !== 'production',
    require_approval_for_writes: true,
    max_affected_rows: 1000,
    allow_ddl: false,
    route_reads_to_replica: true,
    masked_columns: ['email', '*.password*', 'users.ssn'],
    blocked_tables: ['secrets.*'],
    allowed_cidrs: [],
  };
}
export const demoSchema: SchemaTree = {
  schemas: [
    {
      name: 'public',
      tables: [
        {
          name: 'users',
          kind: 'table',
          row_estimate: 248391,
          columns: [
            {
              name: 'id',
              data_type: 'uuid',
              nullable: false,
              is_primary_key: true,
            },
            {
              name: 'name',
              data_type: 'text',
              nullable: false,
              is_primary_key: false,
            },
            {
              name: 'email',
              data_type: 'text',
              nullable: false,
              is_primary_key: false,
            },
            {
              name: 'created_at',
              data_type: 'timestamptz',
              nullable: false,
              is_primary_key: false,
            },
          ],
        },
        {
          name: 'orders',
          kind: 'table',
          row_estimate: 1248902,
          columns: [
            {
              name: 'id',
              data_type: 'bigint',
              nullable: false,
              is_primary_key: true,
            },
            {
              name: 'user_id',
              data_type: 'uuid',
              nullable: false,
              is_primary_key: false,
            },
            {
              name: 'total',
              data_type: 'numeric',
              nullable: false,
              is_primary_key: false,
            },
            {
              name: 'metadata',
              data_type: 'jsonb',
              nullable: true,
              is_primary_key: false,
            },
          ],
        },
        {
          name: 'subscriptions',
          kind: 'table',
          row_estimate: 18234,
          columns: [
            {
              name: 'id',
              data_type: 'uuid',
              nullable: false,
              is_primary_key: true,
            },
            {
              name: 'status',
              data_type: 'text',
              nullable: false,
              is_primary_key: false,
            },
          ],
        },
      ],
    },
    {
      name: 'analytics',
      tables: [
        {
          name: 'daily_revenue',
          kind: 'view',
          row_estimate: 730,
          columns: [
            {
              name: 'day',
              data_type: 'date',
              nullable: false,
              is_primary_key: false,
            },
            {
              name: 'revenue',
              data_type: 'numeric',
              nullable: true,
              is_primary_key: false,
            },
          ],
        },
      ],
    },
  ],
};
export function fixtures() {
  const users: User[] = [
    {
      id: uuid(1),
      email: 'admin@visp.dev',
      name: 'Alex Morgan',
      org_role: 'admin',
      disabled: false,
      created_at: now(),
      last_login_at: now(),
    },
    {
      id: uuid(2),
      email: 'reviewer@visp.dev',
      name: 'Sam Chen',
      org_role: 'admin',
      disabled: false,
      created_at: now(),
      last_login_at: now(),
    },
    {
      id: uuid(3),
      email: 'member@visp.dev',
      name: 'Jordan Lee',
      org_role: 'member',
      disabled: false,
      created_at: now(),
      last_login_at: now(),
    },
  ];
  const projects: Project[] = ['Commerce', 'Platform', 'Data & analytics'].map(
    (name, i) => ({
      id: uuid(10 + i),
      name,
      description:
        [
          'Customer-facing services',
          'Internal infrastructure',
          'Reporting and warehouse',
        ][i] ?? '',
      cluster_count: i === 0 ? 4 : 3,
      created_at: now(),
    }),
  );
  const names = [
    'commerce-primary',
    'orders-replica',
    'checkout-staging',
    'commerce-dev',
    'identity-prod',
    'platform-staging',
    'local-services',
    'warehouse-prod',
    'events-staging',
    'analytics-dev',
  ];
  const clusters: Cluster[] = names.map((name, i) => ({
    id: uuid(100 + i),
    project_id: uuid(i < 4 ? 10 : i < 7 ? 11 : 12),
    name,
    engine: i % 3 === 0 ? 'mysql' : 'postgres',
    provider:
      (
        [
          'aws',
          'aws',
          'gcp',
          'onprem',
          'azure',
          'aws',
          'onprem',
          'gcp',
          'azure',
          'gcp',
        ] as const
      )[i] ?? 'aws',
    region:
      [
        'us-east-1',
        'us-east-1',
        'europe-west1',
        'local',
        'eastus',
        'eu-west-1',
        'local',
        'us-central1',
        'westeurope',
        'us-central1',
      ][i] ?? '',
    environment: name.includes('staging')
      ? 'staging'
      : name.includes('dev') || name.includes('local')
        ? 'development'
        : 'production',
    host: `${name}.internal.visp.dev`,
    port: i % 3 === 0 ? 3306 : 5432,
    database: i < 4 ? 'commerce' : i < 7 ? 'platform' : 'analytics',
    username: 'vda_gateway',
    tls_mode: 'verify_full',
    replica_host: i === 0 ? 'commerce-ro.internal.visp.dev' : null,
    replica_port: i === 0 ? 3306 : null,
    tags: { team: i < 4 ? 'commerce' : i < 7 ? 'platform' : 'data' },
    health: {
      status: i === 4 ? 'down' : i === 7 ? 'degraded' : 'healthy',
      latency_ms: i === 4 ? null : i === 7 ? 186 : 8 + i * 3,
      server_version: i % 3 === 0 ? 'MySQL 8.4.2' : 'PostgreSQL 17.3',
      is_replica: i === 1,
      active_connections: 12 + i * 4,
      max_connections: 200,
      error: i === 4 ? 'Connection timed out after 5000 ms' : null,
      checked_at: now(),
    },
    my_access: 'admin',
    created_at: now(),
    updated_at: now(),
  }));
  const history: HistoryEntry[] = Array.from({ length: 36 }, (_, i) => ({
    id: uuid(400 + i),
    cluster_id: clusters[i % 10]?.id ?? uuid(100),
    cluster_name: clusters[i % 10]?.name ?? '',
    user_id: users[i % 3]?.id ?? uuid(1),
    user_email: users[i % 3]?.email ?? '',
    sql:
      i % 7 === 0
        ? 'DELETE FROM users'
        : 'SELECT id, name, email FROM users ORDER BY created_at DESC LIMIT 100',
    verdict: i % 7 === 0 ? 'deny' : 'allow',
    status:
      i === 18
        ? 'running'
        : i === 19
          ? 'unknown'
          : i % 7 === 0
            ? 'blocked'
            : 'ok',
    row_count: i >= 18 || i % 7 === 0 ? null : 100,
    elapsed_ms: i >= 18 || i % 7 === 0 ? null : 21 + i * 2,
    error: i % 7 === 0 ? 'Writes without WHERE are blocked' : null,
    created_at: new Date(
      Date.now() - (OLD_ROWS[i] ? OLD_ROWS[i] * 3_600_000 : i * 640000),
    ).toISOString(),
    agent_id: AGENT_ROWS[i] ? DEMO_AGENT.id : null,
    task: AGENT_ROWS[i] ?? null,
  }));
  // Newest first, as the server lists them.
  history.sort((a, b) => b.created_at.localeCompare(a.created_at));
  const grants: Grant[] = users.map((user, i) => ({
    id: uuid(600 + i),
    user: { id: user.id, email: user.email, name: user.name },
    scope: 'project',
    scope_id: uuid(10),
    scope_name: 'Commerce',
    level: i === 2 ? 'write' : 'admin',
    expires_at: i === 2 ? new Date(Date.now() + 86400000).toISOString() : null,
    created_at: now(),
    created_by: uuid(1),
  }));
  const audit: AuditEvent[] = Array.from({ length: 120 }, (_, i) => {
    const row = history[i % history.length];
    return {
      id: uuid(700 + i),
      actor: {
        id: row?.user_id ?? uuid(1),
        email: row?.user_email ?? 'admin@visp.dev',
      },
      action: 'query.execute',
      target_type: 'cluster',
      target_id: row?.cluster_id ?? uuid(100),
      ip: '10.12.0.24',
      // What the gateway writes for a query: where to find it, not its SQL.
      details: {
        query_id: uuid(900 + i),
        history_id: row?.id ?? uuid(300),
        status: row?.status === 'blocked' ? 'blocked' : 'running',
        agent_id: null,
      },
      created_at: new Date(Date.now() - i * 300000).toISOString(),
      seq: 120 - i,
      sealed: true,
    };
  });
  const approvals: Approval[] = [];
  return { users, projects, clusters, history, grants, audit, approvals };
}
