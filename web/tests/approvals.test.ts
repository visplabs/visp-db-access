import { describe, it, expect } from 'vitest';
import { createMockTransport } from '../src/api/mock';
import { TEXT } from '../src/api/mock-approvals';
import { MYSQL_REASON, previewWrite } from '../src/api/mock-preview';
import { defaultPolicy, fixtures, uuid } from '../src/api/fixtures';
import type {
  Approval,
  Cluster,
  Page,
  ReceiptCheck,
  User,
} from '../src/api/types';
import {
  agentLabel,
  awaitsAction,
  boundText,
  endedAt,
  matchRows,
  changeSummary,
  isEffectChanged,
  needsPreview,
  receiptState,
  receiptStateDetail,
  receiptStateText,
  resolveWritten,
  whatHappened,
  shortDigest,
} from '../src/lib/approval-presentation';

const post = (body?: unknown): RequestInit => ({
  method: 'POST',
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});
const AGENT_REQUEST = uuid(810),
  FUNCTION_REQUEST = uuid(811),
  DELETED_AGENT_REQUEST = uuid(812),
  EFFECT_CHANGED = uuid(813),
  WITHDRAWN = uuid(814),
  EXPIRED = uuid(815),
  SIGNED_EARLIER = uuid(817),
  MYSQL_PENDING = uuid(800),
  MYSQL_APPROVED = uuid(801);

async function as(email: string) {
  const api = createMockTransport({ delay: 0 });
  await api<{ user: User }>(
    '/auth/login',
    post({ email, password: 'demo-password' }),
  );
  return api;
}
const admin = () => as('admin@visp.dev'),
  owner = () => as('member@visp.dev');

describe('approval previews in the demo API', () => {
  it('gives a person’s request a preview when it is made', async () => {
    const api = await admin();
    const { items } = await api<{ items: Cluster[] }>('/clusters');
    const postgres = items.find((c) => c.name === 'checkout-staging')!;
    const mysql = items.find((c) => c.engine === 'mysql')!;
    const made = await api<Approval>(
      '/approvals',
      post({
        cluster_id: postgres.id,
        sql: "UPDATE users SET name = 'x' WHERE id IN (1, 2)",
        reason: 'Fix two names',
      }),
    );
    expect(made.agent).toBeNull();
    expect(made.preview).toMatchObject({
      supported: true,
      kind: 'update',
      target: 'users',
      affected_rows: 2,
      bound_to: 'rows',
      written: ['name'],
      // The email is masked in the new rows too, and the note says so.
      notes: [TEXT.someHidden],
    });
    expect(made.preview?.before?.hidden).toEqual(['email']);
    expect(made.preview?.after?.masked).toEqual(['email']);
    expect(made.preview?.after?.rows.map((row) => row[1])).toEqual(['x', 'x']);
    const onMysql = await api<Approval>(
      '/approvals',
      post({
        cluster_id: mysql.id,
        sql: "UPDATE users SET name = 'x' WHERE id = 1",
        reason: 'Fix a name',
      }),
    );
    expect(onMysql.preview).toEqual({
      supported: false,
      reason: MYSQL_REASON,
      notes: [],
    });
    // A list is light: no preview, receipt or result.
    const listed = await api<Page<Approval>>('/approvals?limit=100');
    expect(
      listed.items.every((a) => a.preview === null && a.receipt === null),
    ).toBe(true);
  });

  it('previews an agent’s request once, and approve waits for it', async () => {
    const api = await admin();
    const before = await api<Approval>(`/approvals/${AGENT_REQUEST}`);
    expect(before.agent).toEqual({ id: uuid(900), name: 'support-assistant' });
    expect(before.preview).toBeNull();
    await expect(
      api(`/approvals/${AGENT_REQUEST}/approve`, post({ note: '' })),
    ).rejects.toMatchObject({
      status: 409,
      message: TEXT.previewFirst(AGENT_REQUEST),
    });
    await expect(
      api(`/approvals/${AGENT_REQUEST}/approve`, post({ run: true })),
    ).rejects.toMatchObject({ status: 409 });
    const previewed = await api<Approval>(
      `/approvals/${AGENT_REQUEST}/preview`,
      post(),
    );
    expect(previewed.preview).toMatchObject({
      supported: true,
      affected_rows: 2,
      bound_to: 'rows',
    });
    await expect(
      api(`/approvals/${AGENT_REQUEST}/preview`, post()),
    ).rejects.toMatchObject({ status: 409, message: TEXT.previewTwice });
    expect(
      await api<Approval>(`/approvals/${AGENT_REQUEST}/approve`, post({})),
    ).toMatchObject({ status: 'approved', review_note: null });
  });

  it('refuses a preview that would run a database function, or for a deleted agent', async () => {
    const api = await admin();
    await expect(
      api(`/approvals/${FUNCTION_REQUEST}/preview`, post()),
    ).rejects.toMatchObject({
      status: 422,
      code: 'unsupported_write',
      message: TEXT.functions(['apply_discount(numeric)']),
    });
    const deleted = await api<Approval>(`/approvals/${DELETED_AGENT_REQUEST}`);
    expect(deleted.agent).toEqual({ id: null, name: 'nightly-cleanup' });
    await expect(
      api(`/approvals/${DELETED_AGENT_REQUEST}/preview`, post()),
    ).rejects.toMatchObject({ status: 409, message: TEXT.agentGone });
    // A person's request was previewed when it was made.
    await expect(
      api(`/approvals/${MYSQL_PENDING}/preview`, post()),
    ).rejects.toMatchObject({ status: 409, message: TEXT.previewTwice });
  });
});

describe('approve and run, withdraw and receipts in the demo API', () => {
  it('approves and runs at once, and leaves a valid receipt', async () => {
    const api = await admin();
    await api(`/approvals/${AGENT_REQUEST}/preview`, post());
    const ran = await api<Approval>(
      `/approvals/${AGENT_REQUEST}/approve`,
      post({ note: 'Checked the two accounts', run: true }),
    );
    expect(ran).toMatchObject({
      status: 'executed',
      result: { affected_rows: 2 },
      receipt: {
        approval_id: AGENT_REQUEST,
        agent: { id: uuid(900), name: 'support-assistant' },
        requested_by: { email: 'member@visp.dev' },
        approved_by: { email: 'admin@visp.dev' },
        executed_by: { email: 'admin@visp.dev' },
        review_note: 'Checked the two accounts',
        previewed_rows: 2,
        affected_rows: 2,
        bound_to: 'rows',
      },
    });
    expect(ran.receipt?.digest).toMatch(/^[0-9a-f]{64}$/);
    const check = await api<ReceiptCheck>(
      `/approvals/${AGENT_REQUEST}/receipt`,
    );
    expect(check).toMatchObject({
      valid: true,
      digest_matches: true,
      signed_with_current_key: true,
    });
    // The requester sees the same receipt.
    await api(
      '/auth/login',
      post({ email: 'member@visp.dev', password: 'demo-password' }),
    );
    expect(
      await api<ReceiptCheck>(`/approvals/${AGENT_REQUEST}/receipt`),
    ).toMatchObject({ valid: true });
    await expect(
      api(`/approvals/${AGENT_REQUEST}/execute`, post()),
    ).rejects.toMatchObject({ status: 409, message: TEXT.consumed });
  });

  it('has no receipt before a write ran, and an old one that cannot be checked', async () => {
    const api = await admin();
    await expect(
      api(`/approvals/${MYSQL_APPROVED}/receipt`),
    ).rejects.toMatchObject({ status: 404 });
    expect(
      await api<ReceiptCheck>(`/approvals/${SIGNED_EARLIER}/receipt`),
    ).toMatchObject({
      valid: false,
      digest_matches: true,
      signed_with_current_key: false,
    });
  });

  it('refuses what the server refuses when a request is made or run', async () => {
    const api = await admin();
    const { items } = await api<{ items: Cluster[] }>('/clusters');
    const staging = items.find((c) => c.name === 'checkout-staging')!;
    const make = (sql: string, reason = 'Because') =>
      api('/approvals', post({ cluster_id: staging.id, sql, reason }));
    await expect(make('SELECT * FROM users LIMIT 1')).rejects.toMatchObject({
      status: 400,
      message: TEXT.readOnly,
    });
    await expect(
      make("WITH x AS (UPDATE users SET name = 'a' WHERE id = 1) SELECT 1"),
    ).rejects.toMatchObject({
      status: 422,
      code: 'unsupported_write',
      message: TEXT.withWrite,
    });
    await expect(
      make("UPDATE users SET name = 'a' WHERE id = 1", ' '),
    ).rejects.toMatchObject({ status: 400, message: TEXT.input });
    await expect(make('DELETE FROM users')).rejects.toMatchObject({
      status: 422,
      message: TEXT.policy,
    });
    // Nobody approved it, so nobody can run it.
    await expect(
      api(`/approvals/${MYSQL_PENDING}/execute`, post()),
    ).rejects.toMatchObject({ status: 403 });
    const made = await api<Approval>(
      '/approvals',
      post({
        cluster_id: staging.id,
        sql: "UPDATE subscriptions SET status = 'x' WHERE id = 1",
        reason: 'Mine',
      }),
    );
    await expect(
      api(`/approvals/${made.id}/execute`, post()),
    ).rejects.toMatchObject({ status: 403, message: TEXT.denied });
    expect(made.preview?.written).toEqual(['status']);
  });
  it('refuses run with a rejection and a rejection without a note', async () => {
    const api = await admin();
    await expect(
      api(
        `/approvals/${MYSQL_PENDING}/reject`,
        post({ note: 'No', run: true }),
      ),
    ).rejects.toMatchObject({ status: 400, message: TEXT.rejectRun });
    await expect(
      api(`/approvals/${MYSQL_PENDING}/reject`, post({ note: ' ' })),
    ).rejects.toMatchObject({ status: 400, message: TEXT.note });
  });

  it('lets only the requester withdraw a pending or approved request', async () => {
    const reviewer = await admin();
    await expect(
      reviewer(`/approvals/${AGENT_REQUEST}/withdraw`, post()),
    ).rejects.toMatchObject({ status: 403 });
    const api = await owner();
    expect(
      await api<Approval>(`/approvals/${AGENT_REQUEST}/withdraw`, post()),
    ).toMatchObject({ status: 'withdrawn' });
    await expect(
      api(`/approvals/${AGENT_REQUEST}/withdraw`, post()),
    ).rejects.toMatchObject({ status: 409, message: TEXT.withdraw });
    await expect(
      api(`/approvals/${AGENT_REQUEST}/preview`, post()),
    ).rejects.toMatchObject({ status: 409, message: TEXT.previewTwice });
    // An approved request can be withdrawn too; it then cannot run.
    const self = await admin();
    expect(
      await self<Approval>(`/approvals/${MYSQL_APPROVED}/withdraw`, post()),
    ).toMatchObject({ status: 'withdrawn' });
    await expect(
      self(`/approvals/${MYSQL_APPROVED}/execute`, post()),
    ).rejects.toMatchObject({ status: 409 });
    await expect(
      self(`/approvals/${EXPIRED}/withdraw`, post()),
    ).rejects.toMatchObject({ status: 403 });
  });

  it('lists withdrawn, expired and failed requests under all and mine', async () => {
    const api = await admin();
    const all = await api<Page<Approval>>('/approvals?limit=100');
    const status = (id: string) => all.items.find((a) => a.id === id)?.status;
    expect(status(WITHDRAWN)).toBe('withdrawn');
    expect(status(EXPIRED)).toBe('expired');
    expect(status(EFFECT_CHANGED)).toBe('failed');
    expect(all.items.find((a) => a.id === EFFECT_CHANGED)?.error_code).toBe(
      'effect_changed',
    );
    expect(all.items.find((a) => a.id === WITHDRAWN)?.error_code).toBeNull();
    const mine = await api<Page<Approval>>('/approvals?mine=true&limit=100');
    expect(mine.items.map((a) => a.id)).toContain(WITHDRAWN);
    const withdrawn = await api<Page<Approval>>(
      '/approvals?status=withdrawn&limit=100',
    );
    expect(withdrawn.items.map((a) => a.id)).toEqual([WITHDRAWN]);
  });
});

describe('approval presentation', () => {
  const cluster = fixtures().clusters.find(
    (c) => c.name === 'checkout-staging',
  )!;
  const policy = defaultPolicy('staging');
  it('names the agent and its owner, also a deleted agent', () => {
    const requester = { id: '1', email: 'a@b', name: 'Jordan Lee' };
    expect(agentLabel({ agent: null, requester })).toBeNull();
    expect(agentLabel({ agent: { id: '9', name: 'bot' }, requester })).toBe(
      'Asked by agent bot for Jordan Lee',
    );
    expect(agentLabel({ agent: { id: null, name: 'bot' }, requester })).toBe(
      'Asked by agent bot (deleted) for Jordan Lee',
    );
  });
  it('says how a write is bound, in the tense of the request, and how many rows it changes', () => {
    expect(boundText('rows')).toBe('It will run only on these exact rows.');
    expect(boundText('count', 'approved')).toBe(
      'It will run only if it changes the same number of rows.',
    );
    expect(boundText('rows', 'executing')).toBe(
      'It runs only on these exact rows.',
    );
    expect(boundText('rows', 'executed')).toBe(
      'It was bound to these exact rows.',
    );
    expect(boundText('count', 'failed')).toBe(
      'It was bound to the number of rows it changes.',
    );
    expect(boundText(undefined, 'rejected')).toBe('Nothing was bound.');
    const preview = previewWrite(
      "DELETE FROM subscriptions WHERE id = 'a'",
      cluster,
      policy,
    );
    expect(changeSummary(preview)).toBe('Deletes 1 row');
    expect(preview.written).toBeUndefined();
    const insert = previewWrite(
      "INSERT INTO subscriptions (id, status) VALUES ('a', 'x'), ('b', 'y')",
      cluster,
      policy,
    );
    expect(changeSummary(insert)).toBe('Adds 2 rows');
    expect(insert.written).toEqual(['id', 'status']);
    // Without a column list nothing says which value is which: all hidden.
    const blind = previewWrite(
      "INSERT INTO subscriptions VALUES ('a', 'x')",
      cluster,
      policy,
    );
    expect(blind.written).toBeUndefined();
    expect(blind.after?.hidden).toEqual(['id', 'status']);
    expect(blind.notes).toEqual([TEXT.someHidden]);
  });
  describe('changed cells', () => {
    const sample = (
      columns: string[],
      hidden: string[],
      rows: unknown[][],
    ) => ({
      columns,
      hidden,
      rows,
      total: rows.length,
    });
    it('pairs rows by a shown, unique, unwritten key in any order', () => {
      const preview = previewWrite(
        "UPDATE users SET name = 'x' WHERE id IN (1, 2)",
        cluster,
        policy,
      );
      const match = matchRows(preview.before, preview.after, preview.written);
      expect(match.key).toBe('id');
      expect([...match.changed]).toEqual(['0:1', '1:1']);
      const reversed = {
        ...preview.after!,
        rows: [...preview.after!.rows].reverse(),
      };
      expect([
        ...matchRows(preview.before, reversed, preview.written).changed,
      ]).toEqual(['0:1', '1:1']);
    });
    it('marks nothing when the key is masked', () => {
      const before = sample(
        ['id', 'status'],
        ['id'],
        [
          ['••••••', 'on'],
          ['••••••', 'off'],
        ],
      );
      const after = sample(
        ['id', 'status'],
        ['id'],
        [
          ['••••••', 'off'],
          ['••••••', 'off'],
        ],
      );
      expect(matchRows(before, after, ['status'])).toEqual({
        changed: new Set(),
        key: null,
      });
    });
    it('marks nothing when the key repeats', () => {
      const before = sample(
        ['order_id', 'quantity'],
        [],
        [
          [7, 2],
          [7, 5],
        ],
      );
      const after = sample(
        ['order_id', 'quantity'],
        [],
        [
          [7, 0],
          [7, 5],
        ],
      );
      expect(matchRows(before, after, ['quantity']).key).toBeNull();
      expect(matchRows(before, after, ['quantity']).changed.size).toBe(0);
    });
    it('finds written columns however the SQL spelled them, or marks nothing', () => {
      expect(resolveWritten(['name'], ['id', 'name'])).toEqual({
        names: ['name'],
        complete: true,
      });
      // A backstop for a server that kept the spelling: one match without case.
      expect(resolveWritten(['NAME'], ['id', 'name'])).toEqual({
        names: ['name'],
        complete: true,
      });
      // Two columns differ only by case: no guess.
      expect(resolveWritten(['NAME'], ['name', 'Name']).complete).toBe(false);
      expect(resolveWritten(['missing'], ['id']).complete).toBe(false);
      // The swap case: `code` is written, so it is not a key.
      const before = sample(
        ['code', 'qty'],
        [],
        [
          [1, 10],
          [2, 20],
        ],
      );
      const after = sample(
        ['code', 'qty'],
        [],
        [
          [2, 10],
          [1, 20],
        ],
      );
      const swap = matchRows(before, after, ['CODE', 'qty']);
      expect(swap.key).toBeNull();
      expect(swap.changed.size).toBe(0);
      // A written name that is in no column: rows are not matchable.
      const keyed = sample(['id', 'name'], [], [[1, 'a']]),
        changed = sample(['id', 'name'], [], [[1, 'b']]);
      expect(matchRows(keyed, changed, ['nmae']).key).toBeNull();
      expect(matchRows(keyed, changed, ['NAME']).changed).toEqual(
        new Set(['0:1']),
      );
    });
    it('marks nothing without a key, a known write, or the whole sample', () => {
      const before = sample(['name'], [], [['a']]),
        after = sample(['name'], [], [['b']]);
      expect(matchRows(before, after, ['name']).key).toBeNull();
      const keyed = sample(['id', 'name'], [], [[1, 'a']]),
        changed = sample(['id', 'name'], [], [[1, 'b']]);
      expect(matchRows(keyed, changed, ['name']).changed).toEqual(
        new Set(['0:1']),
      );
      // The written columns are not known: the key could be one of them.
      expect(matchRows(keyed, changed, undefined).key).toBeNull();
      // A written key is no key: `SET id = id + 1` moves every row.
      expect(matchRows(keyed, changed, ['id', 'name']).key).toBeNull();
      // A cut sample cannot prove that a key is unique.
      expect(
        matchRows({ ...keyed, total: 40 }, { ...changed, total: 40 }, ['name'])
          .key,
      ).toBeNull();
    });
  });
  it('hides a value computed from a protected column, and says why values are missing', () => {
    const preview = previewWrite(
      'UPDATE users SET name = email WHERE id = 1',
      cluster,
      policy,
    );
    expect(preview.after?.hidden).toEqual(['name', 'email']);
    expect(preview.written).toEqual(['name']);
    expect(preview.notes).toEqual([TEXT.someHidden]);
    const returning = previewWrite(
      "UPDATE users SET name = 'x' WHERE id = 1 RETURNING id",
      cluster,
      policy,
    );
    expect(returning.after).toBeUndefined();
    expect(returning.notes).toEqual([
      'The new values are not shown: the statement has its own RETURNING clause.',
    ]);
    expect(
      previewWrite(
        "UPDATE ONLY users SET name = 'x' WHERE id = 1",
        cluster,
        policy,
      ),
    ).toMatchObject({ bound_to: 'count', notes: [expect.any(String)] });
  });
  it('tells a changed receipt from one that is not verified', () => {
    const approval = {
      id: 'a',
      sql: 'UPDATE t SET x = 1',
      cluster_id: 'c',
      status: 'executed' as const,
    };
    const receipt = {
      approval_id: 'a',
      sql: 'UPDATE t SET x = 1',
      cluster: { id: 'c', name: 'c', engine: 'postgres' as const },
    } as ReceiptCheck['receipt'];
    const state = (
      valid: boolean,
      digest_matches: boolean,
      signed_with_current_key: boolean,
      own = receipt,
    ) =>
      receiptStateText[
        receiptState(
          { valid, digest_matches, signed_with_current_key, receipt: own },
          approval,
        )
      ];
    expect(state(true, true, true)).toBe('Signature valid');
    expect(state(false, true, true)).toBe('Not valid: this record was changed');
    // Another key id proves nothing: not verified, never a calm word.
    expect(state(false, true, false)).toBe('Not verified');
    expect(
      receiptStateDetail[
        receiptState(
          {
            valid: false,
            digest_matches: true,
            signed_with_current_key: false,
            receipt,
          },
          approval,
        )
      ],
    ).toMatch(/Treat it as unproven\.$/);
    // A forged record that names another key is still a changed record.
    expect(state(false, false, false)).toBe(
      'Not valid: this record was changed',
    );
    // A receipt of another request is not valid here, whatever its key.
    expect(
      state(false, true, false, { ...receipt, sql: 'DELETE FROM t' }),
    ).toBe('Not valid: this record was changed');
    expect(shortDigest('a'.repeat(32) + 'b'.repeat(32))).toBe(
      'aaaaaaaa…bbbbbbbb',
    );
  });
  it('shows expiry only while a request can still run, else how it ended', () => {
    const times = {
      executed_at: '2026-11-11T10:00:00Z',
      reviewed_at: '2026-11-11T09:00:00Z',
      expires_at: '2026-11-12T08:00:00Z',
    };
    expect(awaitsAction({ status: 'pending' })).toBe(true);
    expect(awaitsAction({ status: 'approved' })).toBe(true);
    expect(awaitsAction({ status: 'executed' })).toBe(false);
    expect(endedAt({ status: 'executed', ...times })).toEqual({
      label: 'Ran',
      at: times.executed_at,
    });
    expect(endedAt({ status: 'failed', ...times })?.label).toBe('Failed');
    expect(endedAt({ status: 'rejected', ...times })).toEqual({
      label: 'Rejected',
      at: times.reviewed_at,
    });
    expect(endedAt({ status: 'expired', ...times })?.at).toBe(times.expires_at);
    expect(endedAt({ status: 'withdrawn', ...times })).toBeNull();
    expect(endedAt({ status: 'executing', ...times })).toBeNull();
    expect(
      endedAt({ status: 'failed', ...times, executed_at: null }),
    ).toBeNull();
  });
  it('says what happened to a request meanwhile', () => {
    const reviewer = { id: '2', email: 'r@x', name: 'Sam Chen' };
    expect(whatHappened({ status: 'rejected', reviewer, agent: null })).toBe(
      'This request was rejected by Sam Chen a moment ago.',
    );
    expect(
      whatHappened({ status: 'withdrawn', reviewer: null, agent: null }),
    ).toBe('This request was withdrawn by its requester.');
    expect(
      whatHappened({ status: 'pending', reviewer: null, agent: null }),
    ).toBeNull();
  });
  it('knows when a request needs a preview and when its data changed', () => {
    expect(needsPreview({ agent: { id: '1', name: 'a' }, preview: null })).toBe(
      true,
    );
    expect(needsPreview({ agent: null, preview: null })).toBe(false);
    expect(
      isEffectChanged({ status: 'failed', error_code: 'effect_changed' }),
    ).toBe(true);
    expect(isEffectChanged({ status: 'failed', error_code: 'upstream' })).toBe(
      false,
    );
    expect(isEffectChanged({ status: 'failed', error_code: null })).toBe(false);
  });
});
