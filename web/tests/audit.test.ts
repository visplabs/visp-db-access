import { afterEach, describe, it, expect, vi } from 'vitest';
import { createMockTransport } from '../src/api/mock';
import { SEAL_AFTER_MS, VERIFIES_PER_MINUTE } from '../src/api/mock-audit';
import {
  auditSummary,
  integrityView,
  problemPlace,
  sealingDelay,
  verificationText,
  verifyRefusal,
} from '../src/lib/audit';
import { ApiError } from '../src/api/errors';
import type {
  AuditEvent,
  AuditIntegrity,
  AuditVerification,
  Cluster,
} from '../src/api/types';

const send = (method: string, body?: unknown): RequestInit => ({
  method,
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});
async function setup(email = 'admin@visp.dev') {
  const api = createMockTransport({ delay: 0 });
  await api('/auth/login', send('POST', { email, password: 'demo-password' }));
  return api;
}
type Page = { items: AuditEvent[]; next_cursor: string | null };
const refusal = async (call: Promise<unknown>) =>
  call.then(
    () => null,
    (error: unknown) => error as ApiError,
  );
afterEach(() => vi.useRealTimers());

describe('audit chain contract', () => {
  it('lists every event with its number and whether it is sealed, and nothing of the chain', async () => {
    const api = await setup();
    const page = await api<Page>('/audit?limit=200');
    expect(page.items).toHaveLength(120);
    for (const event of page.items) {
      expect(Object.keys(event).sort()).toEqual([
        'action',
        'actor',
        'created_at',
        'details',
        'id',
        'ip',
        'sealed',
        'seq',
        'target_id',
        'target_type',
      ]);
      expect(event.sealed).toBe(true);
    }
    // Newest first; the numbers follow the order the events were written in.
    const numbers = page.items.map((event) => event.seq);
    expect(numbers).toEqual([...numbers].sort((a, b) => b - a));
    expect(new Set(numbers).size).toBe(120);
  });

  it('writes for a query what the gateway writes: where it is, not its SQL', async () => {
    const api = await setup();
    const { items } = await api<{ items: Cluster[] }>('/clusters');
    const cluster = items.find((c) => c.environment === 'development')!;
    await api(
      `/clusters/${cluster.id}/query`,
      send('POST', { sql: 'SELECT id FROM users LIMIT 5' }),
    );
    const page = await api<Page>('/audit?action=query.execute&limit=200');
    for (const event of page.items) {
      const details = event.details as Record<string, unknown>;
      expect(Object.keys(details).sort()).toEqual([
        'agent_id',
        'history_id',
        'query_id',
        'status',
      ]);
      expect(['running', 'blocked']).toContain(details.status);
      expect(JSON.stringify(details)).not.toMatch(/select|delete/i);
    }
    expect(page.items[0]!.target_id).toBe(cluster.id);
  });

  it('seals a new event a moment after it is written, and the head moves', async () => {
    // Only the clock is under the test's control; the mock's own waits run.
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() });
    const api = await setup();
    const before = await api<AuditIntegrity>('/audit/integrity');
    expect(before).toMatchObject({
      sealed: 120,
      unsealed: 0,
      oldest_unsealed_at: null,
      oldest_unsealed_seconds: null,
      verification: {
        status: 'intact',
        links: 120,
        verified: 120,
        unverifiable: [],
        problem: null,
        running: null,
      },
    });
    expect(before.head).toMatchObject({ position: 120 });
    expect(before.head!.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(before.key_id).toMatch(/^[0-9a-f]{16}$/);
    expect(before.head!.key_id).toBe(before.key_id);
    // A change writes an event; it waits.
    await api(
      '/settings/network',
      send('PUT', {
        allowed_cidrs: ['10.0.0.0/8'],
        trust_proxy_headers: false,
      }),
    );
    const waiting = await api<AuditIntegrity>('/audit/integrity');
    expect(waiting).toMatchObject({ sealed: 120, unsealed: 1 });
    expect(waiting.oldest_unsealed_at).not.toBeNull();
    expect(waiting.head).toEqual(before.head);
    const listed = (await api<Page>('/audit?limit=1')).items[0]!;
    expect(listed).toMatchObject({
      action: 'settings.network',
      sealed: false,
      seq: 121,
    });
    // After the sealer's tick it is in the chain.
    vi.setSystemTime(Date.now() + SEAL_AFTER_MS + 1);
    const after = await api<AuditIntegrity>('/audit/integrity');
    expect(after).toMatchObject({ sealed: 121, unsealed: 0 });
    expect(after.head!.position).toBe(121);
    expect(after.head!.hash).not.toBe(before.head!.hash);
    expect((await api<Page>('/audit?limit=1')).items[0]!.sealed).toBe(true);
  });

  it('checks a bounded range now, records the check, and limits how often', async () => {
    const api = await setup();
    const newest = await api<AuditVerification>(
      '/audit/verify',
      send('POST', {}),
    );
    expect(newest).toMatchObject({
      status: 'intact',
      from_position: 1,
      to_position: 120,
      links: 120,
      verified: 120,
      unverifiable: [],
      problem: null,
    });
    expect(newest.head!.position).toBe(120);
    const some = await api<AuditVerification>(
      '/audit/verify',
      send('POST', { limit: 10 }),
    );
    expect(some).toMatchObject({
      from_position: 111,
      to_position: 120,
      links: 10,
    });
    const range = await api<AuditVerification>(
      '/audit/verify',
      send('POST', { from_position: 5, limit: 3 }),
    );
    expect(range).toMatchObject({ from_position: 5, to_position: 7, links: 3 });
    // The check is itself an event, with who asked and what was found.
    const events = await api<Page>('/audit?action=audit.verify');
    expect(events.items).toHaveLength(3);
    expect(events.items.at(-1)).toMatchObject({
      actor: { email: 'admin@visp.dev' },
      target_type: 'audit',
      target_id: null,
      details: {
        from_position: 1,
        to_position: 120,
        status: 'intact',
        problem: null,
      },
    });
    // Bounds, before the limit is counted.
    for (const body of [
      { limit: 0 },
      { limit: 10001 },
      { limit: 1.5 },
      { from_position: 0 },
      { other: 1 },
    ]) {
      const error = await refusal(api('/audit/verify', send('POST', body)));
      expect(error?.status, JSON.stringify(body)).toBe(400);
    }
    for (let n = 3; n < VERIFIES_PER_MINUTE; n += 1)
      await api('/audit/verify', send('POST', {}));
    const error = await refusal(api('/audit/verify', send('POST', {})));
    expect(error).toMatchObject({
      status: 429,
      code: 'rate_limited',
      details: { retry_after_seconds: 60 },
    });
    expect(verifyRefusal(error)).toBe(
      'Too many checks. Try again in 60 seconds.',
    );
  });

  it('is for organization administrators only', async () => {
    const api = await setup('member@visp.dev');
    for (const call of [
      api('/audit/integrity'),
      api('/audit/verify', send('POST', {})),
      api('/audit'),
    ])
      expect((await refusal(call))?.status).toBe(403);
  });
});

const integrity = (
  change: Partial<AuditIntegrity> = {},
  verification: Partial<AuditIntegrity['verification']> = {},
): AuditIntegrity => ({
  head: {
    position: 1204,
    hash: 'ab'.repeat(32),
    key_id: '4a1886b932e8ae81',
    sealed_at: '2026-11-21T10:00:00Z',
  },
  key_id: '4a1886b932e8ae81',
  sealed: 1204,
  unsealed: 0,
  oldest_unsealed_at: null,
  oldest_unsealed_seconds: null,
  ...change,
  verification: {
    status: 'intact',
    checked_at: '2026-11-21T10:01:00Z',
    key_id: '4a1886b932e8ae81',
    links: 1204,
    verified: 1204,
    unverifiable: [],
    problem: null,
    running: null,
    ...verification,
  },
});

describe('audit screen wording', () => {
  it('says in one line that the chain is intact, how much is sealed and how much waits', () => {
    expect(integrityView(integrity())).toEqual({
      state: 'intact',
      headline: 'Chain intact up to',
      counts: '1,204 rows sealed · none waiting',
      notes: [],
      problem: null,
    });
    expect(
      integrityView(integrity({ unsealed: 3, oldest_unsealed_seconds: 2 }))
        .counts,
    ).toBe('1,204 rows sealed · 3 waiting');
    expect(integrityView(integrity({ sealed: 1 })).counts).toBe(
      '1 row sealed · none waiting',
    );
    expect(
      integrityView(integrity({}, { status: 'pending', checked_at: null })),
    ).toMatchObject({ state: 'pending', headline: 'Not checked yet' });
  });

  it('makes a long wait for sealing visible and says why', () => {
    const view = integrityView(
      integrity({ unsealed: 41, oldest_unsealed_seconds: 185 }),
    );
    expect(view.counts).toBe(
      '1,204 rows sealed · 41 waiting, the oldest for 3 minutes',
    );
    expect(view.notes).toHaveLength(1);
    expect(view.notes[0]).toContain('transaction');
    expect(sealingDelay(59)).toBeNull();
    expect(sealingDelay(null)).toBeNull();
    expect(sealingDelay(60)).toBe('1 minute');
    expect(sealingDelay(7300)).toBe('2 hours');
  });

  it('never calls rows intact that another key sealed', () => {
    const view = integrityView(
      integrity(
        {},
        {
          status: 'partial',
          verified: 1004,
          unverifiable: [
            { key_id: 'old', first_position: 1, last_position: 150 },
            { key_id: 'older', first_position: 151, last_position: 200 },
          ],
        },
      ),
    );
    expect(view.state).toBe('partial');
    expect(view.headline).not.toMatch(/^Chain intact/);
    expect(view.notes[0]).toContain(
      '200 rows of 1,204 were sealed with another master key',
    );
  });

  it('names the first problem, what it means and where it is, for every kind', () => {
    const kinds = [
      ['row_changed', 'A sealed event was changed'],
      ['row_missing', 'A sealed event was deleted'],
      ['row_inserted', 'An event was added after the fact'],
      ['chain_broken', 'The chain itself was changed'],
      ['chain_truncated', 'The end of the audit log was removed'],
      ['checkpoint_mismatch', 'The chain was rebuilt or relabelled'],
    ] as const;
    for (const [kind, title] of kinds) {
      const view = integrityView(
        integrity(
          {},
          {
            status: 'broken',
            problem: {
              kind,
              position: 1017,
              audit_id: '0a0a0a0a-0000-4000-8000-000000000001',
              seq: 1031,
              message: 'from the server',
            },
          },
        ),
      );
      expect(view.state).toBe('broken');
      expect(view.headline).toBe(
        'The audit log was changed outside the gateway',
      );
      expect(view.problem).toMatchObject({ kind, title, position: 1017 });
      expect(view.problem!.meaning.length).toBeGreaterThan(40);
      expect(problemPlace(view.problem!)).toBe(
        'First problem at chain position 1,017, event number 1,031.',
      );
    }
    // A kind this console does not know still shows the server's words.
    const unknown = integrityView(
      integrity(
        {},
        {
          status: 'broken',
          problem: {
            kind: 'something_new' as never,
            position: 2,
            audit_id: null,
            seq: null,
            message: 'A new kind of problem',
          },
        },
      ),
    );
    expect(unknown.problem).toMatchObject({ meaning: 'A new kind of problem' });
    expect(problemPlace(unknown.problem!)).toBe(
      'First problem at chain position 2.',
    );
  });

  it('says the result of a check in one sentence', () => {
    const result = (change: Partial<AuditVerification>): AuditVerification => ({
      status: 'intact',
      key_id: 'k',
      from_position: 205,
      to_position: 1204,
      links: 1000,
      verified: 1000,
      unverifiable: [],
      problem: null,
      head: null,
      ...change,
    });
    expect(verificationText(result({}))).toEqual({
      text: 'Checked the newest 1,000 rows (positions 205 to 1,204): intact.',
      bad: false,
    });
    expect(
      verificationText(result({ links: 0, verified: 0, to_position: 0 })),
    ).toEqual({
      text: 'Nothing is sealed yet, so there was nothing to check.',
      bad: false,
    });
    expect(
      verificationText(result({ status: 'partial', verified: 900 })).text,
    ).toContain('100 rows were sealed with another master key');
    expect(
      verificationText(
        result({
          status: 'broken',
          links: 12,
          to_position: 216,
          problem: {
            kind: 'row_missing',
            position: 217,
            audit_id: null,
            seq: 230,
            message: 'm',
          },
        }),
      ),
    ).toEqual({
      text: 'Checked positions 205 to 216: A sealed event was deleted. First problem at chain position 217, event number 230.',
      bad: true,
    });
    expect(verifyRefusal(new Error('The server is away'))).toBe(
      'The server is away',
    );
  });

  it('reads the details the gateway writes, and no SQL', () => {
    const summary = (action: string, details: unknown) =>
      auditSummary({ action, details });
    expect(
      summary('query.execute', {
        query_id: 'q',
        history_id: 'h',
        status: 'running',
        agent_id: null,
      }),
    ).toEqual({ text: 'Started · SQL and result are in History' });
    expect(
      summary('query.execute', { status: 'blocked', agent_id: 'a' }),
    ).toEqual({ text: 'Refused before it ran · by an agent', blocked: true });
    expect(
      summary('agent.tool', {
        tool: 'query',
        task: 'Count orders',
        database: 'orders',
        outcome: 'ok',
      }),
    ).toEqual({ text: 'query · ok · Count orders' });
    expect(
      summary('agent.tool', { tool: 'query', outcome: 'query_denied' })?.text,
    ).toBe('query · refused: query_denied');
    expect(summary('agent_login.status', { from: 'ok', to: 'drift' })).toEqual({
      text: 'In sync → Too open',
    });
    expect(
      summary('audit.verify', {
        from_position: 1,
        to_position: 1000,
        status: 'intact',
      }),
    ).toEqual({ text: 'Positions 1 to 1,000 · intact' });
    expect(summary('POST /api/v1/audit/verify', { status: 403 })).toEqual({
      text: 'Answered with HTTP 403',
    });
    // An action that speaks for itself, and details that are not an object.
    expect(summary('user.create', {})).toBeNull();
    expect(summary('cluster.update', ['name'])).toBeNull();
    expect(summary('query.execute', null)?.text).toContain('Started');
    // The old mock sent SQL here; the gateway never did, and it is not read.
    expect(
      summary('query.execute', { sql: 'DELETE FROM users', verdict: 'deny' }),
    ).toEqual({ text: 'Started · SQL and result are in History' });
  });
});
