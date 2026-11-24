import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMockTransport } from '../src/api/mock';
import { requestText } from '../src/api/client';
import { cloudLine } from '../src/lib/cloud';
import type {
  Agent,
  AgentLogin,
  Cluster,
  NewAgentToken,
  User,
} from '../src/api/types';

const send = (method: string, body?: unknown): RequestInit => ({
  method,
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});
async function signIn(email = 'admin@visp.dev') {
  const api = createMockTransport({ delay: 0 });
  await api<{ user: User }>(
    '/auth/login',
    send('POST', { email, password: 'demo-password' }),
  );
  const { items } = await api<{ items: Cluster[] }>('/clusters');
  return { api, clusters: items };
}

describe('cloud label', () => {
  it('names the cloud, the region and the engine in one line', () => {
    const cluster = {
      provider: 'gcp',
      region: 'europe-west1',
      engine: 'postgres',
    } as const;
    expect(cloudLine(cluster)).toBe('Google Cloud · europe-west1 · PostgreSQL');
    expect(cloudLine(cluster, false)).toBe('Google Cloud · europe-west1');
    expect(cloudLine({ provider: 'onprem', region: '', engine: 'mysql' })).toBe(
      'On-premises · MySQL',
    );
  });
});

describe('mock agents follow the API contract', () => {
  it('creates, pages, limits and removes agents and tokens', async () => {
    const { api, clusters } = await signIn();
    const body = { name: 'reporter', cluster_ids: [clusters[0]!.id] };
    const agent = await api<Agent>('/agents', send('POST', body));
    expect(agent).toMatchObject({
      max_level: 'read',
      hourly_query_budget: 300,
      paused: false,
      tokens: [],
    });
    await expect(
      api('/agents', send('POST', { ...body, name: 'REPORTER' })),
    ).rejects.toMatchObject({ status: 409 });
    for (const bad of [
      { ...body, name: '' },
      { ...body, name: 'x', cluster_ids: [] },
      { ...body, name: 'x', cluster_ids: [crypto.randomUUID()] },
      { ...body, name: 'x', max_level: 'admin' },
      { ...body, name: 'x', hourly_query_budget: 0 },
    ])
      await expect(api('/agents', send('POST', bad))).rejects.toMatchObject({
        status: 400,
      });
    await expect(
      api(`/agents/${agent.id}`, send('PATCH', {})),
    ).rejects.toMatchObject({ status: 400 });
    // Five active tokens at most; the secret has the documented shape.
    const tokens: NewAgentToken[] = [];
    for (let i = 0; i < 5; i += 1)
      tokens.push(
        await api<NewAgentToken>(
          `/agents/${agent.id}/tokens`,
          send('POST', {}),
        ),
      );
    expect(tokens[0]!.token).toMatch(/^vda_agent_[\w-]{43}$/);
    expect(tokens[0]!.token.endsWith(tokens[0]!.hint)).toBe(true);
    await expect(
      api(`/agents/${agent.id}/tokens`, send('POST', {})),
    ).rejects.toMatchObject({ status: 409 });
    // The list never carries a secret.
    const listed = await api<{ items: Agent[] }>('/agents');
    expect(JSON.stringify(listed)).not.toContain(tokens[0]!.token);
    await api(`/agents/${agent.id}/tokens/${tokens[0]!.id}`, send('DELETE'));
    expect(
      (await api<Agent>(`/agents/${agent.id}`)).tokens.find(
        (t) => t.id === tokens[0]!.id,
      )?.revoked_at,
    ).not.toBeNull();
    // Pages: 3 agents, 2 per page.
    for (const name of ['second', 'third'])
      await api('/agents', send('POST', { ...body, name }));
    const first = await api<{ items: Agent[]; next_cursor: string | null }>(
      '/agents?limit=2',
    );
    expect(first.items).toHaveLength(2);
    const rest = await api<{ items: Agent[]; next_cursor: string | null }>(
      `/agents?limit=2&cursor=${first.next_cursor}`,
    );
    expect(rest).toMatchObject({ next_cursor: null });
    expect(rest.items).toHaveLength(1);
    await api(`/agents/${agent.id}`, send('DELETE'));
    await expect(api(`/agents/${agent.id}`)).rejects.toMatchObject({
      status: 404,
    });
  });

  it('lets only the owner shape an agent; an administrator may stop it', async () => {
    const { api, clusters } = await signIn();
    const users = await api<{ items: User[] }>('/users');
    const member = users.items.find((u) => u.org_role === 'member')!;
    // The member owns an agent on a cluster they can reach.
    await api(
      '/grants',
      send('POST', {
        user_id: member.id,
        scope: 'cluster',
        scope_id: clusters[0]!.id,
        level: 'read',
      }),
    );
    await api('/auth/logout', send('POST'));
    await api(
      '/auth/login',
      send('POST', { email: member.email, password: 'demo-password' }),
    );
    const agent = await api<Agent>(
      '/agents',
      send('POST', { name: 'mine', cluster_ids: [clusters[0]!.id] }),
    );
    await expect(
      api(
        '/agents',
        send('POST', { name: 'reach', cluster_ids: [clusters[5]!.id] }),
      ),
    ).rejects.toMatchObject({ status: 400 });
    await api('/auth/logout', send('POST'));
    await api(
      '/auth/login',
      send('POST', { email: 'admin@visp.dev', password: 'demo-password' }),
    );
    const path = `/agents/${agent.id}`;
    for (const shape of [
      { name: 'renamed' },
      { max_level: 'write' },
      { hourly_query_budget: 5 },
      { cluster_ids: [clusters[1]!.id] },
      { paused: true, description: 'x' },
    ])
      await expect(api(path, send('PATCH', shape))).rejects.toMatchObject({
        status: 403,
      });
    await expect(api(`${path}/tokens`, send('POST', {}))).rejects.toMatchObject(
      { status: 403 },
    );
    expect(
      await api<Agent>(path, send('PATCH', { paused: true })),
    ).toMatchObject({ paused: true, name: 'mine' });
  });

  it('shows each state of the agent login', async () => {
    const { api, clusters } = await signIn();
    const postgres = clusters.find((c) => c.engine === 'postgres')!;
    const mysql = clusters.find((c) => c.engine === 'mysql')!;
    const base = `/clusters/${postgres.id}/agent-login`;
    await expect(
      api(`/clusters/${mysql.id}/agent-login`),
    ).rejects.toMatchObject({ status: 400 });
    expect(await api<AgentLogin>(base)).toEqual({ configured: false });
    const script = await api<string>(`${base}/script?username=vda_agent`);
    expect(script).toContain('GRANT SELECT (');
    expect(script).not.toMatch(/password/i);
    for (const name of ['Bad', 'pg_monitor', postgres.username])
      await expect(
        api(base, send('PUT', { username: name, password: 'p' })),
      ).rejects.toMatchObject({ status: 400 });
    const put = (username: string) =>
      api<AgentLogin>(base, send('PUT', { username, password: 'p' }));
    expect(await put('vda_agent')).toMatchObject({
      status: 'ok',
      stale: false,
    });
    expect(await put('vda_drift')).toMatchObject({ status: 'drift' });
    expect(await put('vda_broken')).toMatchObject({
      status: 'error',
      findings: [{ code: 'check_failed' }],
    });
    await put('vda_agent');
    // A policy change makes the result stale; a check clears that.
    const policy = await api<Record<string, unknown>>(
      `/clusters/${postgres.id}/policy`,
    );
    await api(`/clusters/${postgres.id}/policy`, send('PUT', policy));
    expect(await api<AgentLogin>(base)).toMatchObject({
      status: 'ok',
      stale: true,
    });
    expect(await api<AgentLogin>(`${base}/check`, send('POST'))).toMatchObject({
      stale: false,
    });
    // An endpoint change clears the password and keeps the login.
    await api(
      `/clusters/${postgres.id}`,
      send('PATCH', { port: postgres.port + 1, password: 'cluster-pw' }),
    );
    expect(await api<AgentLogin>(base)).toMatchObject({
      configured: true,
      needs_password: true,
    });
    expect(await api<AgentLogin>(`${base}/check`, send('POST'))).toMatchObject({
      findings: [{ code: 'password_needed' }],
    });
    expect(await put('vda_agent')).toMatchObject({
      status: 'ok',
      needs_password: false,
    });
    await api(base, send('DELETE'));
    await expect(api(base, send('DELETE'))).rejects.toMatchObject({
      status: 404,
    });
  });
});

describe('requestText against a real server', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('sends the session and the CSRF header and returns the text', async () => {
    const fetch = vi.fn(
      async () => new Response('BEGIN;\nCOMMIT;\n', { status: 200 }),
    );
    vi.stubGlobal('fetch', fetch);
    expect(await requestText('/clusters/1/agent-login/script')).toBe(
      'BEGIN;\nCOMMIT;\n',
    );
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/v1/clusters/1/agent-login/script');
    expect(init.credentials).toBe('same-origin');
    expect(new Headers(init.headers).get('X-Requested-With')).toBe('vda');
  });
  it('turns an error envelope into an ApiError and reports a lost session', async () => {
    const events: string[] = [];
    vi.stubGlobal('window', {
      dispatchEvent: (event: Event) => events.push(event.type),
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              error: {
                code: 'unauthenticated',
                message: 'Sign in',
                details: null,
              },
            }),
            { status: 401 },
          ),
      ),
    );
    await expect(requestText('/x')).rejects.toMatchObject({
      code: 'unauthenticated',
      status: 401,
    });
    expect(events).toEqual(['vda:session-expired']);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network');
      }),
    );
    await expect(requestText('/x')).rejects.toThrow('network');
    expect(events).toEqual(['vda:session-expired', 'vda:unreachable']);
  });
});

describe('theme before first paint', () => {
  // public/theme.js runs before the bundle. It must decide exactly as
  // lib/theme.tsx does: dark unless light is stored; system follows the OS.
  const run = async (stored: string | null, osDark: boolean) => {
    const { readFileSync } = await import('node:fs');
    const source = readFileSync(
      new URL('../public/theme.js', import.meta.url),
      'utf8',
    );
    const document = { documentElement: { dataset: {} as { theme?: string } } };
    new Function('document', 'localStorage', 'matchMedia', source)(
      document,
      { getItem: () => stored },
      () => ({ matches: osDark }),
    );
    return document.documentElement.dataset.theme;
  };
  it('matches the rule of the theme provider', async () => {
    expect(await run(null, false)).toBe('dark');
    expect(await run('dark', false)).toBe('dark');
    expect(await run('garbage', false)).toBe('dark');
    expect(await run('light', true)).toBe('light');
    expect(await run('system', true)).toBe('dark');
    expect(await run('system', false)).toBe('light');
  });
  it('still sets a theme when storage is not available', async () => {
    const { readFileSync } = await import('node:fs');
    const source = readFileSync(
      new URL('../public/theme.js', import.meta.url),
      'utf8',
    );
    const document = { documentElement: { dataset: {} as { theme?: string } } };
    new Function('document', 'localStorage', 'matchMedia', source)(
      document,
      {
        getItem: () => {
          throw new Error('blocked');
        },
      },
      () => ({ matches: false }),
    );
    expect(document.documentElement.dataset.theme).toBe('dark');
  });
});

describe('connect an agent', () => {
  const token = `vda_agent_${'a'.repeat(43)}`;
  const url = 'https://gate.example.com/api/v1/mcp';
  it('prints a Claude Code command with the gate token, never a password', async () => {
    const { snippetFor } = await import('../src/features/agents/connect');
    expect(snippetFor('claude-code', token, url).text).toBe(
      `claude mcp add --transport http visp-gate ${url} --header "Authorization: Bearer ${token}"`,
    );
  });
  it('prints the Cursor file and the generic MCP config under visp-gate', async () => {
    const { snippetFor } = await import('../src/features/agents/connect');
    const cursor = snippetFor('cursor', token, url);
    expect(cursor.title).toBe('.cursor/mcp.json');
    expect(JSON.parse(cursor.text)).toEqual({
      mcpServers: {
        'visp-gate': { url, headers: { Authorization: `Bearer ${token}` } },
      },
    });
    expect(JSON.parse(snippetFor('other', token, url).text)).toEqual({
      mcpServers: {
        'visp-gate': {
          type: 'http',
          url,
          headers: { Authorization: `Bearer ${token}` },
        },
      },
    });
    for (const client of ['claude-code', 'cursor', 'other'] as const)
      expect(snippetFor(client, token, url).text).not.toMatch(
        /database-gateway|password/i,
      );
  });
  it('the mock agent first calls a little after its token is made', async () => {
    const api = createMockTransport({ delay: 0, firstCallMs: 150 });
    await api(
      '/auth/login',
      send('POST', { email: 'admin@visp.dev', password: 'demo-password' }),
    );
    const { items } = await api<{ items: Cluster[] }>('/clusters');
    const agent = await api<Agent>(
      '/agents',
      send('POST', { name: 'first-call', cluster_ids: [items[0]!.id] }),
    );
    const made = await api<NewAgentToken>(
      `/agents/${agent.id}/tokens`,
      send('POST', {}),
    );
    type Sessions = {
      items: { token: { id: string }; started_at: string; active: boolean }[];
    };
    const before = await api<Sessions>(`/agents/${agent.id}/sessions`);
    expect(before.items).toEqual([]);
    await new Promise((resolve) => setTimeout(resolve, 200));
    const after = await api<Sessions>(`/agents/${agent.id}/sessions`);
    const live = after.items.find((session) => session.active);
    expect(live?.token.id).toBe(made.id);
    // The session that the connect page shows began with that first call.
    const created = (await api<Agent>(`/agents/${agent.id}`)).tokens[0]!;
    expect(Date.parse(live!.started_at)).toBeGreaterThanOrEqual(
      Date.parse(created.created_at),
    );
  });
});
