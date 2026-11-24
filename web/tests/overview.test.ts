import { describe, expect, it } from 'vitest';
import {
  actorOfHistory,
  gateTiles,
  rankReviews,
  reviewable,
  runStatusText,
  type Overview,
} from '../src/features/overview/model';
import type { Approval, HistoryEntry, Risk } from '../src/api/types';

const overview = (fields: Partial<Overview> = {}): Overview => ({
  clusters_total: 3,
  healthy: 3,
  degraded: 0,
  down: 0,
  unknown: 0,
  queries_24h: 0,
  blocked_24h: 0,
  errors_24h: 0,
  pending_approvals: 0,
  discovery: null,
  recent_queries: [],
  unhealthy_clusters: [],
  ...fields,
});

describe('gate tiles', () => {
  it('has one tile per verdict the API can count, and no Masked tile', () => {
    const tiles = gateTiles(
      overview({ queries_24h: 36, blocked_24h: 6, pending_approvals: 7 }),
    );
    expect(tiles.map((tile) => [tile.verdict, tile.count, tile.to])).toEqual([
      ['allowed', 30, '/history?status=ok'],
      ['held', 7, '/approvals'],
      ['blocked', 6, '/history?status=blocked'],
    ]);
  });
  it('counts as Allowed only what did not fail, as the list it opens', () => {
    // The History list of status ok holds no failed run: neither does the
    // number on the tile.
    const [allowed] = gateTiles(
      overview({ queries_24h: 36, blocked_24h: 6, errors_24h: 2 }),
    );
    expect(allowed).toMatchObject({ count: 28, to: '/history?status=ok' });
    expect(allowed?.meaning).toBe('let through, and did not fail');
  });
  it('says the time each tile covers, and claims no tile holds another', () => {
    const tiles = gateTiles(
      overview({ queries_24h: 9, blocked_24h: 2, pending_approvals: 3 }),
    );
    expect(tiles.map((tile) => tile.window)).toEqual(['24 h', 'Now', '24 h']);
    for (const tile of tiles) expect(tile.meaning).not.toMatch(/includ/);
    expect(tiles[2]?.meaning).toBe('stopped by the guard');
  });
  it('words zeros as results, and one request as one', () => {
    expect(gateTiles(overview()).map((tile) => tile.meaning)).toEqual([
      'Nothing ran in 24 hours',
      'Nobody is waiting for a review',
      'Nothing blocked in 24 hours',
    ]);
    expect(gateTiles(overview({ pending_approvals: 1 }))[1]?.meaning).toBe(
      'request waits for a person',
    );
  });
  it('notes failures on the database under Allowed, only when there are some', () => {
    expect(gateTiles(overview({ queries_24h: 5 }))[0]?.note).toBeUndefined();
    expect(
      gateTiles(overview({ queries_24h: 5, errors_24h: 1 }))[0]?.note,
    ).toBe('1 more let through, then failed on the database');
    expect(
      gateTiles(overview({ queries_24h: 5, errors_24h: 3 }))[0]?.note,
    ).toBe('3 more let through, then failed on the database');
  });
  it('never shows a negative count', () => {
    expect(
      gateTiles(overview({ queries_24h: 1, blocked_24h: 2 }))[0]?.count,
    ).toBe(0);
    expect(
      gateTiles(overview({ queries_24h: 3, blocked_24h: 2, errors_24h: 2 }))[0]
        ?.count,
    ).toBe(0);
  });
});

const hour = 3_600_000;
const request = (
  id: string,
  risk: Risk,
  expiresIn: number,
  fields: Partial<Approval> = {},
) =>
  ({
    id,
    status: 'pending',
    cluster_id: 'c1',
    requester: { id: 'u2', email: 'b@x', name: 'B' },
    analysis: { risk },
    expires_at: new Date(Date.now() + expiresIn).toISOString(),
    ...fields,
  }) as Approval;

describe('needs you', () => {
  it('ranks the highest risk first, then the soonest expiry', () => {
    const ranked = rankReviews([
      request('low-soon', 'low', hour),
      request('high-late', 'high', 9 * hour),
      request('critical', 'critical', 20 * hour),
      request('high-soon', 'high', 2 * hour),
      request('medium', 'medium', hour),
    ]);
    expect(ranked.map((approval) => approval.id)).toEqual([
      'critical',
      'high-soon',
      'high-late',
      'medium',
      'low-soon',
    ]);
  });
  it('lists only pending, unexpired requests of others on clusters the person administers', () => {
    const now = Date.now();
    const items = [
      request('ok', 'low', hour),
      request('own', 'low', hour, {
        requester: { id: 'me', email: 'a@x', name: 'A' },
      }),
      request('expired', 'low', -hour),
      request('other-cluster', 'low', hour, { cluster_id: 'c2' }),
      request('done', 'low', hour, { status: 'approved' }),
    ];
    expect(
      reviewable(items, {
        userId: 'me',
        adminClusters: new Set(['c1']),
        now,
      }).map((approval) => approval.id),
    ).toEqual(['ok']);
  });
});

const entry = (fields: Partial<HistoryEntry>) =>
  ({
    user_id: 'u1',
    user_email: 'jordan@visp.dev',
    agent_id: null,
    ...fields,
  }) as HistoryEntry;

describe('who ran a query', () => {
  const agents = new Map([['a1', { name: 'support-assistant' }]]);
  it('names a person by email, or You', () => {
    expect(actorOfHistory(entry({}), { agents, me: { id: 'me' } })).toEqual({
      kind: 'human',
      name: 'jordan@visp.dev',
    });
    expect(
      actorOfHistory(entry({ user_id: 'me' }), { agents, me: { id: 'me' } }),
    ).toEqual({ kind: 'human', name: 'You' });
  });
  it('marks an agent and its owner, with the name when the caller can see it', () => {
    expect(
      actorOfHistory(entry({ agent_id: 'a1' }), { agents, me: { id: 'me' } }),
    ).toEqual({
      kind: 'agent',
      name: 'support-assistant',
      owner: 'jordan@visp.dev',
    });
    expect(
      actorOfHistory(entry({ agent_id: 'a9' }), { agents, me: null }),
    ).toEqual({ kind: 'agent', name: undefined, owner: 'jordan@visp.dev' });
  });
  it('treats a row from an older server without agent_id as a person', () => {
    const { agent_id: _, ...old } = entry({});
    void _;
    expect(actorOfHistory(old, { agents, me: null }).kind).toBe('human');
  });
  it('words a run that ended without a gate decision', () => {
    expect(runStatusText('error')).toBe('Failed');
    expect(runStatusText('cancelled')).toBe('Cancelled');
    expect(runStatusText('unknown')).toBe('Outcome unknown');
  });
});
