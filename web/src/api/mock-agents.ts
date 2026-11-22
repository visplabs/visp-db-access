// In-memory agents and agent logins for the mock API. It follows docs/API.md
// closely enough for the screens and their tests; it is not a second gateway.
import type {
  Agent,
  AgentLogin,
  AgentSession,
  AgentStep,
  Cluster,
  SetupFinding,
  User,
} from './types';

type Fail = (code: string, message: string, status?: number) => never;
const TOKEN_PREFIX = 'vda_agent_';
const secret = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(43)), (byte) =>
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.charAt(
      byte % 64,
    ),
  ).join('');

/** What the server says to a person for each action word of a fix. */
const TOLD: Record<string, string> = {
  rewrite_sql: 'The agent was told to change its SQL.',
  fix_arguments: 'The agent was told to correct the arguments of its call.',
  choose_database: 'The agent was told to use a database from its list.',
  ask_owner: 'The agent was told to ask its owner.',
  propose_write: 'The agent was told to ask a person for this write.',
  retry_later: 'The agent was told to wait and try again.',
  stop: 'The agent was told to stop.',
};
const fix = (action: string, hint: string) => ({
  action,
  hint,
  told: TOLD[action] ?? 'The agent was told what to do next.',
});
type Draft = Pick<AgentStep, 'tool' | 'task'> & Partial<AgentStep>;
/** What a demo agent does, in order. The live session goes through `LIVE`
 * one step at a time while someone watches it. */
const PAST: Draft[] = [
  { tool: 'list_databases', task: 'See which databases I can use' },
  { tool: 'search_schema', task: 'Find the orders tables' },
  { tool: 'describe_table', task: 'Learn the columns of orders' },
  {
    tool: 'check_sql',
    task: 'Check the report query before I run it',
    sql: 'SELECT * FROM secrets.tokens',
    verdict: 'deny',
    fix: fix(
      'stop',
      'This table is not available here. Do not try other spellings of it. Tell your owner if you need it.',
    ),
  },
  {
    tool: 'run_query',
    task: 'Count the orders of last week for the weekly report',
    sql: "SELECT status, count(*) FROM orders WHERE created_at > now() - interval '7 days' GROUP BY status",
    verdict: 'allow',
    row_count: 4,
    history_id: 'history',
  },
  {
    tool: 'run_query',
    task: 'Close the stale orders',
    sql: "UPDATE orders SET status = 'closed' WHERE id = 4812",
    verdict: 'requires_approval',
    outcome: 'approval_required',
    fix: fix(
      'propose_write',
      'This statement changes data, and an agent cannot change data on its own. Call propose_write with the same SQL and say why in `task`; a person decides.',
    ),
  },
];
const LIVE: Draft[] = [
  { tool: 'list_databases', task: 'See which databases I can use' },
  {
    tool: 'check_sql',
    task: 'Check the customer query',
    sql: 'SELECT id, name, email FROM users ORDER BY created_at DESC',
    verdict: 'allow',
  },
  {
    tool: 'run_query',
    task: 'Read the newest customers for the support summary',
    sql: 'SELECT id, name, email FROM users ORDER BY created_at DESC',
    verdict: 'allow',
    row_count: 100,
    history_id: 'history',
  },
  {
    tool: 'fetch_rows',
    task: 'Read the next customers',
    row_count: 100,
    history_id: 'history',
  },
  {
    tool: 'run_query',
    task: 'Look up the API tokens',
    sql: 'SELECT * FROM secrets.tokens',
    verdict: 'deny',
    outcome: 'query_denied',
    fix: fix(
      'stop',
      'This table is not available here. Do not try other spellings of it. Tell your owner if you need it.',
    ),
  },
  {
    tool: 'propose_write',
    task: 'Correct the name of customer 42, as the ticket asks',
    sql: "UPDATE users SET name = 'Maya Patel' WHERE id = 42",
    verdict: 'requires_approval',
    approval_id: 'approval',
  },
  {
    tool: 'get_approval',
    task: 'See whether my request was decided',
    approval_id: 'approval',
  },
  {
    tool: 'fetch_rows',
    task: 'Read more customers',
    outcome: 'result_expired',
    fix: fix(
      'rewrite_sql',
      'These rows are not held any more. Call run_query again, with a narrower question: add filters, select fewer columns or aggregate, so that the answer needs fewer pages.',
    ),
  },
  { tool: 'search_schema', task: 'Find the invoice tables' },
  { tool: 'describe_table', task: 'Learn the columns of invoices' },
];
/** Steps of the live session that are there when it is first opened. */
const LIVE_START = 3;
/** The live session gets a step at most this often, while it is read. */
const LIVE_EVERY_MS = 1500;

export function createAgents(context: {
  clusters: () => Cluster[];
  access: (cluster: Cluster) => string | undefined;
  fail: Fail;
  audit: (action: string, type: string, id: string, details?: unknown) => void;
  now: () => string;
}) {
  const { fail, audit, now } = context;
  const agents: Agent[] = [];
  // Demo sessions of an agent that has a token: one that ended yesterday,
  // and one that is going on and gets a new step while someone reads it.
  type Trail = { session: AgentSession; steps: AgentStep[]; grown?: number };
  const trails = new Map<string, Trail[]>();
  const stepOf = (
    draft: Draft,
    agent: Agent,
    n: number,
    at: number,
  ): AgentStep => ({
    n,
    id: crypto.randomUUID(),
    database:
      draft.tool === 'list_databases' || draft.tool === 'get_approval'
        ? null
        : (agent.cluster_ids[0] ?? null),
    sql: null,
    sql_truncated: false,
    verdict: null,
    outcome: 'ok',
    fix: null,
    row_count: null,
    elapsed_ms: 12 + ((n * 37) % 180),
    created_at: new Date(at).toISOString(),
    ...draft,
    // The demo has no stored query or request behind a step; the ids are
    // made up, and the linked page says that it has no such item.
    history_id: draft.history_id ? crypto.randomUUID() : null,
    approval_id: draft.approval_id ? crypto.randomUUID() : null,
  });
  const summary = (
    agent: Agent,
    token: Agent['tokens'][number],
    steps: AgentStep[],
    active: boolean,
  ): AgentSession => ({
    id: crypto.randomUUID(),
    agent_id: agent.id,
    token: { id: token.id, hint: token.hint },
    started_at: steps[0]?.created_at ?? now(),
    last_step_at: steps.at(-1)?.created_at ?? now(),
    steps: steps.length,
    refusals: steps.filter((step) => step.outcome !== 'ok').length,
    first_task: steps[0]?.task ?? null,
    active,
  });
  const trailsOf = (agent: Agent): Trail[] => {
    const known = trails.get(agent.id);
    if (known) return known;
    const token = agent.tokens.at(-1);
    // An agent with no token has never called.
    if (!token) return [];
    const day = 26 * 3_600_000;
    const past = PAST.map((draft, index) =>
      stepOf(draft, agent, index + 1, Date.now() - day + index * 21_000),
    );
    const live = LIVE.slice(0, LIVE_START).map((draft, index) =>
      stepOf(draft, agent, index + 1, Date.now() - (LIVE_START - index) * 9000),
    );
    const made = [
      {
        session: summary(agent, token, live, true),
        steps: live,
      },
      { session: summary(agent, token, past, false), steps: past },
    ];
    trails.set(agent.id, made);
    return made;
  };
  /** The live session goes on while its agent may act and someone reads it. */
  const grow = (agent: Agent, trail: Trail) => {
    const time = Date.now();
    trail.grown ??= time;
    const live = agent.tokens.some(
      (token) =>
        !token.revoked_at && new Date(token.expires_at).getTime() > Date.now(),
    );
    const draft = LIVE[trail.steps.length];
    if (
      !trail.session.active ||
      agent.paused ||
      !live ||
      !draft ||
      time - trail.grown < LIVE_EVERY_MS
    )
      return;
    const step = stepOf(draft, agent, trail.steps.length + 1, time);
    trail.steps.push(step);
    trail.grown = time;
    trail.session.last_step_at = step.created_at;
    trail.session.steps = trail.steps.length;
    trail.session.refusals += step.outcome === 'ok' ? 0 : 1;
  };
  function sessions(
    agent: Agent,
    rest: string[],
    query: URLSearchParams,
  ): unknown {
    const all = trailsOf(agent);
    const [sessionId, sub] = rest;
    if (!sessionId) {
      const limit = Number(query.get('limit') ?? 50);
      if (!Number.isInteger(limit) || limit < 1 || limit > 200)
        fail('validation', 'Limit must be 1..=200');
      const start = Number(query.get('cursor') ?? 0);
      return {
        items: all.slice(start, start + limit).map((trail) => trail.session),
        next_cursor: start + limit < all.length ? String(start + limit) : null,
      };
    }
    const trail = all.find((item) => item.session.id === sessionId);
    if (!trail || sub !== 'steps')
      return fail('not_found', 'Resource not found', 404);
    const after = Number(query.get('after') ?? 0),
      limit = Number(query.get('limit') ?? 200);
    if (
      !Number.isInteger(after) ||
      after < 0 ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 500
    )
      fail('validation', '`after` must be 0 or more and `limit` 1..=500');
    // A metadata probe reads beyond the last step. Start the demo clock
    // when the first step page opens, even if the list was open for a while.
    if (after <= trail.session.steps) grow(agent, trail);
    const waiting = trail.steps.filter((step) => step.n > after);
    const items = waiting.slice(0, limit);
    return {
      session: trail.session,
      items,
      after: items.at(-1)?.n ?? after,
      more: waiting.length > limit,
    };
  }
  const logins = new Map<string, Extract<AgentLogin, { configured: true }>>();
  const reachable = (ids: unknown): string[] => {
    const list = Array.isArray(ids) ? [...new Set(ids.map(String))] : [];
    if (list.length === 0 || list.length > 100)
      fail('validation', 'An agent must have 1..=100 clusters');
    for (const id of list) {
      const cluster = context.clusters().find((c) => c.id === id);
      if (!cluster || !context.access(cluster))
        fail(
          'validation',
          'Every cluster must exist and be one that you can access',
        );
    }
    return list.sort((a, b) => a.localeCompare(b));
  };
  const named = (value: unknown, owner: string, except?: string): string => {
    const name = String(value ?? '').trim();
    if (!name || name.length > 100)
      fail('validation', 'Name must contain 1..=100 characters');
    if (
      agents.some(
        (a) =>
          a.owner.id === owner &&
          a.id !== except &&
          a.name.toLowerCase() === name.toLowerCase(),
      )
    )
      fail('conflict', 'Resource already exists', 409);
    return name;
  };
  const level = (value: unknown): 'read' | 'write' => {
    if (value !== 'read' && value !== 'write')
      fail('validation', 'Agent level must be read or write');
    return value as 'read' | 'write';
  };
  const budget = (value: unknown): number => {
    const number = Number(value);
    if (!Number.isInteger(number) || number < 1 || number > 100000)
      fail('validation', 'Hourly query budget must be 1..=100000');
    return number;
  };
  /** The agent, when the caller owns it (true) or administers it (false). */
  const find = (id: string, user: User): [Agent, boolean] => {
    const agent = agents.find((a) => a.id === id);
    if (!agent || (agent.owner.id !== user.id && user.org_role !== 'admin'))
      return fail('not_found', 'Resource not found', 404);
    return [agent, agent.owner.id === user.id];
  };
  function route(
    segments: string[],
    method: string,
    body: Record<string, unknown>,
    user: User,
    query: URLSearchParams,
  ): unknown {
    const [, id, sub, tokenId] = segments;
    if (!id) {
      if (method === 'GET') {
        const visible = agents.filter(
          (a) => user.org_role === 'admin' || a.owner.id === user.id,
        );
        // Pages, like the server: the cursor is the position in the list.
        const limit = Math.min(Number(query.get('limit') ?? 50), 200);
        const start = Number(query.get('cursor') ?? 0);
        return {
          items: visible.slice(start, start + limit),
          next_cursor:
            start + limit < visible.length ? String(start + limit) : null,
        };
      }
      if (agents.filter((a) => a.owner.id === user.id).length >= 50)
        fail('conflict', 'You have the maximum number of agents', 409);
      const agent: Agent = {
        id: crypto.randomUUID(),
        name: named(body.name, user.id),
        description: String(body.description ?? ''),
        max_level: level(body.max_level ?? 'read'),
        paused: false,
        hourly_query_budget: budget(body.hourly_query_budget ?? 300),
        owner: { id: user.id, email: user.email, name: user.name },
        cluster_ids: reachable(body.cluster_ids),
        tokens: [],
        created_at: now(),
        updated_at: now(),
      };
      agents.unshift(agent);
      audit('agent.create', 'agent', agent.id, { name: agent.name });
      return agent;
    }
    const [agent, owner] = find(id, user);
    if (sub === 'sessions') return sessions(agent, segments.slice(3), query);
    if (sub === 'tokens') {
      if (method === 'POST') {
        if (!owner) fail('forbidden', 'Access denied', 403);
        const days = Number(body.expires_in_days ?? 30);
        if (!Number.isInteger(days) || days < 1 || days > 90)
          fail('validation', 'Token lifetime must be 1..=90 days');
        const live = agent.tokens.filter(
          (t) => !t.revoked_at && new Date(t.expires_at).getTime() > Date.now(),
        );
        if (live.length >= 5)
          fail(
            'conflict',
            'This agent has the maximum number of active tokens; revoke one first',
            409,
          );
        const token = TOKEN_PREFIX + secret();
        const record = {
          id: crypto.randomUUID(),
          hint: token.slice(-4),
          created_at: now(),
          expires_at: new Date(Date.now() + days * 86_400_000).toISOString(),
          revoked_at: null,
          last_used_at: null,
        };
        agent.tokens.unshift(record);
        audit('agent.token_create', 'agent', agent.id, { token_id: record.id });
        return {
          id: record.id,
          token,
          hint: record.hint,
          expires_at: record.expires_at,
        };
      }
      const token = agent.tokens.find((t) => t.id === tokenId);
      if (!token) return fail('not_found', 'Resource not found', 404);
      token.revoked_at ??= now();
      audit('agent.token_revoke', 'agent', agent.id, { token_id: token.id });
      return undefined;
    }
    if (method === 'GET') return agent;
    if (method === 'DELETE') {
      trails.delete(agent.id);
      agents.splice(agents.indexOf(agent), 1);
      audit('agent.delete', 'agent', agent.id, { name: agent.name });
      return undefined;
    }
    const shape = [
      'name',
      'description',
      'max_level',
      'cluster_ids',
      'hourly_query_budget',
    ];
    const given = Object.keys(body).filter((key) => body[key] != null);
    if (given.length === 0) fail('validation', 'Nothing to change');
    if (!owner && given.some((key) => shape.includes(key)))
      fail('forbidden', 'Access denied', 403);
    if (body.name != null)
      agent.name = named(body.name, agent.owner.id, agent.id);
    if (body.description != null) agent.description = String(body.description);
    if (body.max_level != null) agent.max_level = level(body.max_level);
    if (body.cluster_ids != null)
      agent.cluster_ids = reachable(body.cluster_ids);
    if (body.hourly_query_budget != null)
      agent.hourly_query_budget = budget(body.hourly_query_budget);
    if (body.paused != null) agent.paused = body.paused === true;
    agent.updated_at = now();
    audit(
      body.paused == null
        ? 'agent.update'
        : agent.paused
          ? 'agent.pause'
          : 'agent.resume',
      'agent',
      agent.id,
    );
    return agent;
  }
  /** `/clusters/:id/agent-login…`, for a caller who administers the cluster. */
  function login(
    cluster: Cluster,
    rest: string[],
    method: string,
    body: Record<string, unknown>,
    query: URLSearchParams,
  ): unknown {
    const stored = logins.get(cluster.id);
    const view = (): AgentLogin =>
      logins.get(cluster.id) ?? { configured: false };
    const role = (value: string): string => {
      if (!/^[a-z_][a-z0-9_]{0,62}$/.test(value) || value.startsWith('pg_'))
        fail(
          'validation',
          'Login name must be 1..=63 characters: lower-case letters, digits and underscore, not starting with a digit or pg_',
        );
      if (value === cluster.username)
        fail(
          'validation',
          "The agent login must be a different login from the cluster's own",
        );
      return value;
    };
    if (method !== 'DELETE' && cluster.engine !== 'postgres')
      fail(
        'validation',
        'An agent login is supported for PostgreSQL clusters only',
      );
    if (rest[0] === 'script') {
      const name = role(
        query.get('username') ?? stored?.username ?? 'vda_agent',
      );
      return [
        '-- visp-gate: agent login for PostgreSQL.',
        '-- Run this as a database administrator, in the database named below.',
        'BEGIN;',
        `ALTER ROLE "${name}" SET default_transaction_read_only = on;`,
        `DROP OWNED BY "${name}";`,
        `GRANT CONNECT ON DATABASE "${cluster.database}" TO "${name}";`,
        `GRANT USAGE ON SCHEMA "public" TO "${name}";`,
        `GRANT SELECT ("id", "name", "created_at") ON "public"."users" TO "${name}";`,
        'COMMIT;',
        '',
      ].join('\n');
    }
    // The mock database is "too open" for a login named like this, so the
    // drift state can be seen and tested.
    const findings = (username: string): SetupFinding[] =>
      username.includes('drift')
        ? [
            {
              severity: 'critical',
              code: 'readable_beyond_policy',
              object: 'public.users',
              message:
                'The agent login can read columns that the policy hides: email.',
            },
            {
              severity: 'warning',
              code: 'not_granted',
              object: 'public.orders',
              message:
                'The policy allows these columns but the login cannot read them: id, total.',
            },
          ]
        : [];
    const check = (username: string) => {
      // A login named like this cannot connect: the check itself fails.
      const failed = username.includes('broken');
      const found: SetupFinding[] = failed
        ? [
            {
              severity: 'critical',
              code: 'check_failed',
              object: 'login',
              message:
                'The check could not run as the agent login. Verify its name, password and CONNECT right, and that the database is reachable.',
            },
          ]
        : findings(username);
      logins.set(cluster.id, {
        configured: true,
        username,
        status: failed
          ? 'error'
          : found.some((f) => f.severity === 'critical')
            ? 'drift'
            : 'ok',
        findings: found,
        checked_at: now(),
        stale: false,
        needs_password: false,
      });
    };
    if (rest[0] === 'check') {
      if (!stored) return fail('not_found', 'Resource not found', 404);
      if (stored.needs_password)
        logins.set(cluster.id, {
          ...stored,
          status: 'drift',
          stale: false,
          checked_at: now(),
          findings: [
            {
              severity: 'critical',
              code: 'password_needed',
              object: 'login',
              message:
                "The cluster's connection endpoint changed. Enter the agent login's password again, or remove the agent login.",
            },
          ],
        });
      else check(stored.username);
      return view();
    }
    if (method === 'PUT') {
      const username = role(String(body.username ?? ''));
      if (!body.password)
        fail('validation', 'Password must contain 1..=1024 bytes');
      check(username);
      audit('agent_login.set', 'agent_login', cluster.id, { username });
      return view();
    }
    if (method === 'DELETE') {
      if (!logins.delete(cluster.id))
        return fail('not_found', 'Resource not found', 404);
      audit('agent_login.remove', 'agent_login', cluster.id);
      return undefined;
    }
    return view();
  }
  /** The cluster's policy changed: the last check no longer says anything. */
  const policyChanged = (cluster: string) => {
    const stored = logins.get(cluster);
    if (stored) stored.stale = true;
  };
  /** The cluster's endpoint changed: the stored password is cleared. */
  const endpointChanged = (cluster: string) => {
    const stored = logins.get(cluster);
    if (stored)
      logins.set(cluster, {
        ...stored,
        status: 'unchecked',
        findings: [],
        checked_at: null,
        stale: true,
        needs_password: true,
      });
  };
  /** Whether a listed agent may act now; undefined for an unknown agent. */
  const active = (id: string) => {
    const agent = agents.find((a) => a.id === id);
    return agent ? !agent.paused : undefined;
  };
  return { route, login, policyChanged, endpointChanged, active };
}
