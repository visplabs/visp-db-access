import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMockTransport } from '../src/api/mock';
import { analyzeDemo, preflightDemo } from '../src/api/mock-guard';
import { DEMO_AGENT, defaultPolicy } from '../src/api/fixtures';
import {
  checkStatus,
  gate,
  preflightOf,
  spoken,
  stateLabel,
} from '../src/lib/preflight';
import {
  answerText,
  approvalLink,
  earlierRange,
  firstMarker,
  historyLink,
  LIVE_INTERVAL_MS,
  markText,
  mergeSteps,
  PAST_ALL,
  pollEvery,
  prependSteps,
  sessionState,
  stepMark,
  toolText,
  WINDOW,
} from '../src/lib/sessions';
import type {
  Agent,
  AgentSession,
  AgentStep,
  AgentSteps,
  Checked,
  Cluster,
  NewAgentToken,
  Page,
  Preflight,
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
const policy = defaultPolicy('production');
const check = (sql: string, level: 'read' | 'write' | 'admin' | null) =>
  preflightDemo(analyzeDemo(sql, policy), level, policy);

/** The demo agent that the mock starts with; its token is days old. */
const DEMO = `/agents/${DEMO_AGENT.id}`;

describe('the mock pre-flight has the server shape', () => {
  it('names one state, one reason and one next step for each case', () => {
    expect(check('SELECT id FROM users', 'read')).toEqual({
      state: 'safe',
      action: 'run',
      label: 'Run',
      hint: "This statement only reads data. Its cost is checked against this database's limit when it runs.",
      guard_change: {
        clause: 'LIMIT 1001',
        text: 'The guard adds LIMIT 1001: the policy allows 1000 rows, and one more row shows whether there are more.',
      },
    });
    expect(
      check('SELECT id FROM users LIMIT 5000', 'read').guard_change,
    ).toMatchObject({ clause: 'LIMIT 1001', replaces: 'LIMIT 5000' });
    expect(
      check('SELECT id FROM users LIMIT 5', 'read').guard_change,
    ).toBeUndefined();
    const write = "UPDATE users SET name = 'x' WHERE id = 1";
    for (const level of ['write', 'admin'] as const)
      expect(check(write, level)).toMatchObject({
        state: 'needs_approval',
        action: 'request_approval',
        label: 'Request approval',
        code: 'approval_required',
      });
    // A person with read access cannot ask: the answer says who can.
    for (const level of ['read', null] as const) {
      const reader = check(write, level);
      expect(reader).toMatchObject({
        state: 'blocked',
        action: 'ask_admin',
        code: 'insufficient_access',
      });
      expect(reader.hint).toContain('A person with write access can ask');
    }
    expect(check('SELECT * FROM secrets.tokens', 'write')).toMatchObject({
      state: 'blocked',
      action: 'ask_admin',
      label: 'Ask an administrator',
      code: 'blocked_table',
    });
    expect(check('SELECT * FROM secrets.tokens', 'admin')).toMatchObject({
      action: 'change_policy',
      label: 'Change the policy',
    });
    expect(check('DELETE FROM users', 'admin')).toMatchObject({
      state: 'blocked',
      action: 'edit_sql',
      label: 'Edit the SQL',
      code: 'missing_where',
    });
    // Without a cost limit in the policy, nothing is said about cost.
    const free = { ...policy, max_cost: null };
    expect(
      preflightDemo(analyzeDemo('SELECT 1 LIMIT 1', free), 'read', free).hint,
    ).toBe('This statement only reads data.');
  });
  it('sends a read that locks rows to an edit, never to an approval', () => {
    const sql = 'SELECT id FROM users WHERE id = 1 FOR UPDATE';
    expect(analyzeDemo(sql, policy).verdict).toBe('requires_approval');
    for (const level of ['read', 'write', 'admin'] as const)
      expect(check(sql, level)).toEqual({
        state: 'blocked',
        action: 'edit_sql',
        label: 'Edit the SQL',
        hint: 'This statement locks rows. Remove the locking clause (FOR UPDATE / FOR SHARE) to run it as a read.',
        code: 'locking_read',
      });
    // The same when an older server sends the analysis alone.
    expect(
      preflightOf(analyzeDemo(sql, policy) as Checked, 'admin'),
    ).toMatchObject({
      state: 'blocked',
      action: 'edit_sql',
      code: 'locking_read',
    });
    // And the gate stays shut: no run, no request.
    const analysis = analyzeDemo(sql, policy);
    expect(
      gate({
        analysis,
        preflight: check(sql, 'admin'),
        status: 'ready',
        access: 'admin',
        busy: false,
      }),
    ).toEqual({ run: false, request: false, fix: false });
  });
  it('offers only a fix that carries the code of the block', () => {
    const denied = analyzeDemo('DELETE FROM users', policy);
    // Advice about speed on a refused statement is never the next step.
    denied.suggestions = [
      {
        code: 'add_limit',
        message: 'advice',
        fix: { label: 'Add LIMIT 100', sql: 'x', action: 'replace' },
      },
    ];
    const shown = preflightDemo(denied, 'admin', policy);
    expect(shown.action).toBe('edit_sql');
    expect(shown.fix).toBeUndefined();
  });
  it('offers the first statement as the fix for several acceptable ones', () => {
    const two = check('SELECT id FROM users WHERE id = 1; SELECT 2', 'read');
    expect(two).toMatchObject({
      state: 'blocked',
      action: 'apply_fix',
      label: 'Keep the first statement',
      code: 'multiple_statements',
      fix: { action: 'replace', sql: 'SELECT id FROM users WHERE id = 1' },
    });
    // The fix passes the check.
    expect(check(two.fix!.sql, 'read').state).toBe('safe');
    // When a statement is refused for its own reason there is no fix.
    for (const sql of [
      'SELECT 1; DELETE FROM users',
      'SELECT pg_sleep(1); SELECT 1',
    ]) {
      const shown = check(sql, 'admin');
      expect(shown.state).toBe('blocked');
      expect(shown.fix).toBeUndefined();
      expect(shown.action).not.toBe('apply_fix');
    }
  });
  it('is part of the analyze answer, with the caller level', async () => {
    const { api, clusters } = await signIn('member@visp.dev');
    const readable = clusters.find((c) => c.my_access === 'read');
    const writable = clusters.find(
      (c) => c.my_access === 'write' || c.my_access === 'admin',
    );
    const write = "UPDATE users SET name = 'x' WHERE id = 1";
    for (const [cluster, state] of [
      [readable, 'blocked'],
      [writable, 'needs_approval'],
    ] as const) {
      if (!cluster) continue;
      const answer = await api<Checked>(
        `/clusters/${cluster.id}/analyze`,
        send('POST', { sql: write }),
      );
      expect(answer.verdict).toBe('requires_approval');
      expect(answer.preflight?.state).toBe(state);
    }
    expect(readable ?? writable).toBeDefined();
  });
});

describe('pre-flight bar logic', () => {
  const analysis = (sql: string): Checked => {
    const result = analyzeDemo(sql, policy);
    return { ...result, preflight: preflightDemo(result, 'write', policy) };
  };
  it('says what the check is doing', () => {
    const base = {
      hasSql: true,
      fresh: false,
      failed: false,
      hasAnswer: false,
    };
    expect(checkStatus({ ...base, hasSql: false })).toBe('empty');
    expect(checkStatus(base)).toBe('checking');
    expect(checkStatus({ ...base, hasAnswer: true })).toBe('updating');
    expect(checkStatus({ ...base, failed: true, hasAnswer: true })).toBe(
      'failed',
    );
    expect(checkStatus({ ...base, fresh: true, hasAnswer: true })).toBe(
      'ready',
    );
  });
  it('opens the gate only for a settled answer that agrees with the verdict', () => {
    const safe = analysis('SELECT id FROM users');
    const open = {
      analysis: safe,
      preflight: safe.preflight,
      status: 'ready' as const,
      access: 'write' as const,
      busy: false,
    };
    expect(gate(open)).toEqual({ run: true, request: false, fix: false });
    // Never while the check runs, has failed, or a query is running.
    for (const status of ['checking', 'updating', 'failed', 'empty'] as const)
      expect(gate({ ...open, status }).run).toBe(false);
    expect(gate({ ...open, busy: true }).run).toBe(false);
    expect(gate({ ...open, analysis: undefined }).run).toBe(false);
    // A pre-flight that says "run" cannot open a verdict that does not.
    const denied = analysis('DELETE FROM users');
    expect(
      gate({ ...open, analysis: denied, preflight: safe.preflight }).run,
    ).toBe(false);
    expect(
      gate({ ...open, analysis: safe, preflight: denied.preflight }).run,
    ).toBe(false);
    // Approval: only with write access, and never as a run.
    const write = analysis("UPDATE users SET name = 'x' WHERE id = 1");
    const asking = { ...open, analysis: write, preflight: write.preflight };
    expect(gate(asking)).toEqual({ run: false, request: true, fix: false });
    expect(gate({ ...asking, access: 'read' }).request).toBe(false);
    expect(gate({ ...asking, access: null }).request).toBe(false);
    const two = analysis('SELECT 1; SELECT 2');
    expect(gate({ ...open, analysis: two, preflight: two.preflight })).toEqual({
      run: false,
      request: false,
      fix: true,
    });
  });
  it('derives a pre-flight for a server that sends none', () => {
    const bare = (sql: string) => analyzeDemo(sql, policy) as Checked;
    expect(preflightOf(undefined, 'admin')).toBeUndefined();
    expect(preflightOf(bare('SELECT 1'), 'read')).toMatchObject({
      state: 'safe',
      action: 'run',
    });
    const write = bare("UPDATE users SET name = 'x' WHERE id = 1");
    expect(preflightOf(write, 'write')).toMatchObject({
      state: 'needs_approval',
      action: 'request_approval',
    });
    for (const access of ['read', null] as const)
      expect(preflightOf(write, access)).toMatchObject({
        state: 'blocked',
        action: 'ask_admin',
      });
    const denied = preflightOf(bare('DELETE FROM users'), 'admin');
    expect(denied).toMatchObject({ state: 'blocked', action: 'edit_sql' });
    expect(denied?.hint).toBe('UPDATE and DELETE require a WHERE clause.');
    // The server's own answer is used as it is.
    const own: Preflight = {
      state: 'blocked',
      action: 'ask_admin',
      label: 'Ask an administrator',
      hint: 'Only an administrator can help.',
    };
    expect(preflightOf({ ...bare('SELECT 1'), preflight: own }, 'admin')).toBe(
      own,
    );
  });
  it('speaks the settled answer once, and nothing while it changes', () => {
    const safe = analysis('SELECT id FROM users').preflight;
    expect(spoken('ready', safe)).toBe(
      `Check passed. This statement only reads data. Its cost is checked against this database's limit when it runs. The guard adds LIMIT 1001: the policy allows 1000 rows, and one more row shows whether there are more.`,
    );
    for (const status of ['checking', 'updating', 'empty'] as const)
      expect(spoken(status, safe)).toBe('');
    expect(spoken('failed', safe)).toContain('failed');
    // The line never repeats the label that is on screen, so the label is
    // the one element with that text.
    for (const sql of [
      'SELECT 1',
      "UPDATE users SET name = 'x' WHERE id = 1",
      'DELETE FROM users',
    ]) {
      const shown = analysis(sql).preflight!;
      const line = spoken('ready', shown).toLowerCase();
      expect(line).not.toContain(stateLabel[shown.state].toLowerCase());
      expect(line.length).toBeGreaterThan(20);
    }
  });
});

describe('mock agent sessions follow the API contract', () => {
  afterEach(() => vi.useRealTimers());
  async function agentWithToken() {
    const { api, clusters } = await signIn();
    const agent = await api<Agent>(
      '/agents',
      send('POST', { name: 'watched', cluster_ids: [clusters[0]!.id] }),
    );
    const path = `/agents/${agent.id}`;
    return { api, agent, path, clusters };
  }
  it('has no session before the agent has a token, then pages them', async () => {
    const { api, path } = await agentWithToken();
    expect(await api<Page<AgentSession>>(`${path}/sessions`)).toEqual({
      items: [],
      next_cursor: null,
    });
    await api<NewAgentToken>(`${path}/tokens`, send('POST', {}));
    // A new agent has no past: one session, the one its first call began.
    const fresh = await api<Page<AgentSession>>(`${path}/sessions`);
    expect(fresh.items.map((session) => session.active)).toEqual([true]);
    // The demo agent's token is days old: newest first, the one that is
    // going on, then the one that ended yesterday.
    const list = await api<Page<AgentSession>>(`${DEMO}/sessions`);
    expect(list.items).toHaveLength(2);
    expect(list.items.map((session) => session.active)).toEqual([true, false]);
    expect(list.items[0]!.started_at > list.items[1]!.started_at).toBe(true);
    for (const session of [...fresh.items, ...list.items]) {
      expect(session.token.hint).toHaveLength(4);
      expect(session.steps).toBeGreaterThan(0);
      expect(session.first_task).toBeTruthy();
    }
    const first = await api<Page<AgentSession>>(`${DEMO}/sessions?limit=1`);
    expect(first.items).toHaveLength(1);
    expect(first.next_cursor).not.toBeNull();
    const rest = await api<Page<AgentSession>>(
      `${DEMO}/sessions?limit=1&cursor=${first.next_cursor}`,
    );
    expect(rest.items[0]!.id).toBe(list.items[1]!.id);
    expect(rest.next_cursor).toBeNull();
    await expect(api(`${path}/sessions?limit=0`)).rejects.toMatchObject({
      status: 400,
    });
  });
  it('reads steps after a marker, and the live session grows until a pause', async () => {
    vi.useFakeTimers({ now: Date.now(), toFake: ['Date'] });
    const { api, path, agent } = await agentWithToken();
    await api<NewAgentToken>(`${path}/tokens`, send('POST', {}));
    const [live] = (await api<Page<AgentSession>>(`${path}/sessions`)).items;
    const [, ended] = (await api<Page<AgentSession>>(`${DEMO}/sessions`)).items;
    const steps = (id: string, query = '') =>
      api<AgentSteps>(
        `${id === ended!.id ? DEMO : path}/sessions/${id}/steps${query}`,
      );
    // A session that is over never changes.
    const past = await steps(ended!.id);
    expect(past.items.map((step) => step.n)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(past).toMatchObject({ after: 6, more: false });
    expect(past.session.refusals).toBe(
      past.items.filter((step) => step.outcome !== 'ok').length,
    );
    expect(await steps(ended!.id, '?after=6')).toMatchObject({
      items: [],
      after: 6,
    });
    const part = await steps(ended!.id, '?after=2&limit=2');
    expect(part.items.map((step) => step.n)).toEqual([3, 4]);
    expect(part).toMatchObject({ after: 4, more: true });
    // Every step has the shape of the contract, and never rows.
    for (const step of past.items) {
      expect(Object.keys(step).sort((a, b) => a.localeCompare(b))).toEqual(
        [
          'approval_id',
          'created_at',
          'database',
          'elapsed_ms',
          'fix',
          'history_id',
          'id',
          'n',
          'outcome',
          'row_count',
          'sql',
          'sql_truncated',
          'task',
          'tool',
          'verdict',
        ].sort((a, b) => a.localeCompare(b)),
      );
      expect(step).not.toHaveProperty('rows');
      if (step.fix) expect(step.fix.told).toMatch(/^The agent was told /);
    }
    // The live one: three steps at first, one more per read after a moment.
    vi.advanceTimersByTime(3000);
    const probe = await steps(live!.id, `?after=${PAST_ALL}&limit=1`);
    expect(probe.session.steps).toBe(3);
    vi.advanceTimersByTime(3000);
    const first = await steps(live!.id);
    expect(first.items).toHaveLength(3);
    vi.advanceTimersByTime(2000);
    const second = await steps(live!.id, `?after=${first.after}`);
    expect(second.items.map((step) => step.n)).toEqual([4]);
    expect(second.session.steps).toBe(4);
    // Reading again at once adds nothing.
    expect((await steps(live!.id, '?after=4')).items).toEqual([]);
    // A paused agent makes no call: the session stops growing.
    await api(path, send('PATCH', { paused: true }));
    vi.advanceTimersByTime(5000);
    expect((await steps(live!.id, '?after=4')).items).toEqual([]);
    await api(path, send('PATCH', { paused: false }));
    vi.advanceTimersByTime(2000);
    expect((await steps(live!.id, '?after=4')).items).toHaveLength(1);
    for (const bad of ['?after=-1', '?limit=0', '?limit=501'])
      await expect(steps(live!.id, bad)).rejects.toMatchObject({ status: 400 });
    await expect(steps(crypto.randomUUID())).rejects.toMatchObject({
      status: 404,
    });
    // Another member cannot read them; the sessions go with the agent.
    const other = createMockTransport({ delay: 0 });
    await other(
      '/auth/login',
      send('POST', { email: 'member@visp.dev', password: 'demo-password' }),
    );
    await expect(other(`${path}/sessions`)).rejects.toMatchObject({
      status: 404,
    });
    await api(path, send('DELETE'));
    await expect(api(`${path}/sessions`)).rejects.toMatchObject({
      status: 404,
    });
    expect(agent.id).toBeTruthy();
  });
});

describe('session view logic', () => {
  const step = (over: Partial<AgentStep>): AgentStep => ({
    n: 1,
    id: 'a',
    tool: 'run_query',
    task: 'Read',
    database: 'db',
    sql: 'SELECT 1',
    sql_truncated: false,
    verdict: 'allow',
    outcome: 'ok',
    fix: null,
    row_count: 1,
    elapsed_ms: 5,
    history_id: null,
    approval_id: null,
    created_at: '2026-01-01T00:00:00Z',
    ...over,
  });
  const answer = (items: AgentStep[], after: number, more = false) =>
    ({
      session: { active: true } as AgentSession,
      items,
      after,
      more,
    }) satisfies AgentSteps;
  it('polls only a session that is going on, on a visible page', () => {
    expect(pollEvery({ active: true }, false)).toBe(LIVE_INTERVAL_MS);
    expect(pollEvery({ active: true }, true)).toBe(false);
    expect(pollEvery({ active: false }, false)).toBe(false);
    expect(pollEvery(undefined, false)).toBe(false);
    // A paused agent makes no call, so there is nothing to read.
    expect(pollEvery({ active: true }, false, true)).toBe(false);
    expect(pollEvery({ active: true }, false, false)).toBe(LIVE_INTERVAL_MS);
    expect(LIVE_INTERVAL_MS).toBeGreaterThanOrEqual(2000);
  });
  it('merges new steps once each, in order', () => {
    const first = mergeSteps(
      undefined,
      answer([step({ n: 1 }), step({ n: 2 })], 2),
    );
    expect(first.items.map((item) => item.n)).toEqual([1, 2]);
    // An answer that overlaps what is known adds only what is new.
    const second = mergeSteps(
      first,
      answer([step({ n: 2 }), step({ n: 3 })], 3, true),
    );
    expect(second.items.map((item) => item.n)).toEqual([1, 2, 3]);
    expect(second).toMatchObject({ after: 3, more: true });
    const third = mergeSteps(second, answer([], 3));
    expect(third.items).toHaveLength(3);
    expect(third.after).toBe(3);
  });
  it('opens a long session at its newest steps and adds earlier ones on request', () => {
    expect(firstMarker({ steps: 12 })).toBe(0);
    expect(firstMarker({ steps: WINDOW + 30 })).toBe(30);
    expect(earlierRange(30)).toEqual({ after: 0, limit: 30 });
    expect(earlierRange(WINDOW + 50)).toEqual({ after: 50, limit: WINDOW });
    const known = {
      ...mergeSteps(undefined, answer([step({ n: 31 }), step({ n: 32 })], 32)),
      from: 30,
    };
    const more = prependSteps(
      known,
      answer([step({ n: 29 }), step({ n: 30 }), step({ n: 31 })], 31),
    );
    expect(more.items.map((item) => item.n)).toEqual([29, 30, 31, 32]);
    expect(more.from).toBe(28);
    // The marker for new steps is not moved by reading old ones.
    expect(more.after).toBe(32);
    // An answer with nothing earlier means that nothing earlier remains:
    // the offer to show earlier steps goes away.
    expect(prependSteps(more, answer([], 0)).from).toBe(0);
    expect(prependSteps(more, answer([step({ n: 30 })], 30)).from).toBe(0);
  });
  it('asks for the session alone with a marker past every step', async () => {
    const { api } = await signIn();
    // The demo agent's session of yesterday.
    const ended = (await api<Page<AgentSession>>(`${DEMO}/sessions`)).items[1]!;
    const head = await api<AgentSteps>(
      `${DEMO}/sessions/${ended.id}/steps?after=${PAST_ALL}&limit=1`,
    );
    expect(head.items).toEqual([]);
    expect(head.session.steps).toBe(6);
    expect(head.more).toBe(false);
  });
  it('marks a step in words, not by colour', () => {
    expect(stepMark(step({}))).toBe('ok');
    expect(stepMark(step({ verdict: 'deny' }))).toBe('refused');
    expect(stepMark(step({ outcome: 'query_denied', verdict: 'deny' }))).toBe(
      'refused',
    );
    expect(
      stepMark(
        step({ outcome: 'approval_required', verdict: 'requires_approval' }),
      ),
    ).toBe('approval');
    expect(stepMark(step({ verdict: 'requires_approval' }))).toBe('approval');
    // A read that locks rows needs no person: the agent was told to edit it.
    const edit = { action: 'rewrite_sql', hint: 'x', told: 'y' };
    expect(stepMark(step({ verdict: 'requires_approval', fix: edit }))).toBe(
      'refused',
    );
    expect(
      stepMark(
        step({
          outcome: 'approval_required',
          verdict: 'requires_approval',
          fix: edit,
        }),
      ),
    ).toBe('refused');
    expect(
      answerText(
        step({
          outcome: 'approval_required',
          verdict: 'requires_approval',
          fix: { ...edit, told: 'The agent was told to change its SQL.' },
        }),
      ),
    ).toBe(
      'The statement locks rows, so it did not run. The agent was told to change its SQL.',
    );
    expect(stepMark(step({ outcome: 'rate_limited', verdict: null }))).toBe(
      'refused',
    );
    expect(stepMark(step({ outcome: 'upstream', verdict: 'allow' }))).toBe(
      'failed',
    );
    expect(Object.values(markText).every((text) => text.length > 2)).toBe(true);
    expect(Object.keys(toolText)).toHaveLength(9);
  });
  it('says the guard answer in plain words', () => {
    expect(answerText(step({ verdict: null }))).toBeNull();
    expect(answerText(step({}))).toBe('The guard accepted the statement.');
    const told = 'The agent was told to stop.';
    expect(
      answerText(
        step({
          outcome: 'query_denied',
          verdict: 'deny',
          fix: { action: 'stop', hint: 'x', told },
        }),
      ),
    ).toBe(`The guard refused the statement. ${told}`);
    expect(
      answerText(
        step({
          outcome: 'rate_limited',
          verdict: null,
          fix: {
            action: 'retry_later',
            hint: 'x',
            told: 'The agent was told to wait and try again.',
          },
        }),
      ),
    ).toBe(
      'The gateway refused the call. The agent was told to wait and try again.',
    );
    expect(
      answerText(
        step({
          verdict: 'deny',
          fix: { action: 'stop', hint: 'x', told },
        }),
      ),
    ).toBe(`The guard refused the statement. ${told}`);
  });
  it('links a step to its history entry and its approval', () => {
    expect(historyLink(step({}))).toBeNull();
    expect(historyLink(step({ history_id: 'h1' }))).toBe(
      '/history?cluster_id=db&entry=h1',
    );
    expect(historyLink(step({ history_id: 'h1', database: null }))).toBe(
      '/history?entry=h1',
    );
    expect(approvalLink(step({ approval_id: 'a1' }))).toBe(
      '/approvals?id=a1&tab=all',
    );
    expect(approvalLink(step({}))).toBeNull();
  });
  it('names the state of a session', () => {
    expect(sessionState({ active: true }, false)).toBe('Live');
    expect(sessionState({ active: true }, true)).toBe('Agent paused');
    expect(sessionState({ active: false }, true)).toBe('Ended');
  });
});
