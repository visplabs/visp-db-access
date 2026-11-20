import { describe, it, expect } from 'vitest';
import { createMockTransport } from '../src/api/mock';
import { noticeHost, TESTS_PER_MINUTE } from '../src/api/mock-notices';
import {
  addressProblem,
  applyEdits,
  failureText,
  testRefusal,
  waitingText,
} from '../src/features/admin/notices';
import { ApiError } from '../src/api/errors';
import type {
  Approval,
  Cluster,
  NoticeSecret,
  NoticeSettings,
  NoticeTest,
  NoticeUpdate,
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
const update = (change: Partial<NoticeUpdate> = {}): NoticeUpdate => ({
  enabled: false,
  format: 'webhook',
  events: ['approval.created'],
  include_reason: false,
  include_row_count: false,
  ...change,
});
const ADDRESS = 'https://hooks.example.com/services/T0/B0/private-token';

describe('notice settings contract', () => {
  it('starts off, with one event and no private field, and shows no address or secret', async () => {
    const api = await setup();
    const settings = await api<NoticeSettings>('/settings/notices');
    expect(settings).toEqual({
      enabled: false,
      format: 'webhook',
      url_set: false,
      url_host: null,
      secret_set: false,
      events: ['approval.created'],
      include_reason: false,
      include_row_count: false,
      links: false,
      delivery: {
        pending: 0,
        dead: 0,
        last_success_at: null,
        last_error: null,
        last_error_at: null,
      },
    });
  });
  it('is for organization administrators only', async () => {
    const api = await setup('member@visp.dev');
    for (const [path, init] of [
      ['/settings/notices', undefined],
      ['/settings/notices', send('PUT', update())],
      ['/settings/notices/secret', send('POST')],
      ['/settings/notices/test', send('POST')],
    ] as const)
      await expect(api(path, init)).rejects.toMatchObject({ status: 403 });
  });
  it('refuses to turn on without an address, an event or a secret, and refuses a bad address', async () => {
    const api = await setup();
    const put = (change: Partial<NoticeUpdate> | Record<string, unknown>) =>
      api<NoticeSettings>(
        '/settings/notices',
        send('PUT', { ...update(), ...change }),
      );
    for (const change of [
      { enabled: true },
      { enabled: true, url: ADDRESS },
      { enabled: true, url: ADDRESS, format: 'slack', events: [] },
      { events: ['approval.execute'] },
      { format: 'email' },
      { secret: 'mine' },
      { url: 'http://hooks.example.com/x' },
      { url: 'https://user:pw@hooks.example.com/x' },
      { url: 'https://hooks.example.com/x#frag' },
      { url: 'https://127.0.0.1/x' },
      { url: 'https://10.0.0.5/x' },
      { url: 'https://169.254.169.254/latest' },
      { url: 'https://localhost/x' },
      { url: 'https://[::1]/x' },
      { url: 'not a url' },
    ])
      await expect(put(change), JSON.stringify(change)).rejects.toMatchObject({
        status: 400,
        code: 'validation',
      });
    // A refused change changes nothing.
    expect((await api<NoticeSettings>('/settings/notices')).url_set).toBe(
      false,
    );
    await expect(
      api('/settings/notices/test', send('POST')),
    ).rejects.toMatchObject({ status: 400 });
  });
  it('keeps the address write-only, shows a new secret once, and orders the events', async () => {
    const api = await setup();
    const first = await api<NoticeSecret>(
      '/settings/notices/secret',
      send('POST'),
    );
    expect(first.rotated).toBe(false);
    expect(first.secret).toMatch(/^vda_whsec_[A-Za-z0-9_-]{43}$/);
    const saved = await api<NoticeSettings>(
      '/settings/notices',
      send(
        'PUT',
        update({
          enabled: true,
          url: ADDRESS,
          events: ['approval.failed', 'approval.created', 'approval.failed'],
          include_reason: true,
        }),
      ),
    );
    expect(saved).toMatchObject({
      enabled: true,
      url_set: true,
      url_host: 'hooks.example.com',
      secret_set: true,
      events: ['approval.created', 'approval.failed'],
      include_reason: true,
      include_row_count: false,
    });
    expect(saved).not.toHaveProperty('url');
    expect(saved).not.toHaveProperty('secret');
    // Leaving the address out keeps it; an empty one removes it.
    const kept = await api<NoticeSettings>(
      '/settings/notices',
      send('PUT', update({ enabled: true, format: 'slack' })),
    );
    expect(kept.url_host).toBe('hooks.example.com');
    const second = await api<NoticeSecret>(
      '/settings/notices/secret',
      send('POST'),
    );
    expect(second.rotated).toBe(true);
    expect(second.secret).not.toBe(first.secret);
    await expect(
      api('/settings/notices', send('PUT', update({ enabled: true, url: '' }))),
    ).rejects.toMatchObject({ status: 400 });
    const cleared = await api<NoticeSettings>(
      '/settings/notices',
      send('PUT', update({ url: '' })),
    );
    expect(cleared).toMatchObject({ url_set: false, url_host: null });
    // Nothing that was returned later, and nothing in the audit log, holds
    // the address or a secret.
    const audit = await api<{ items: { action: string }[] }>('/audit');
    expect(audit.items.map((event) => event.action)).toEqual(
      expect.arrayContaining(['settings.notices', 'settings.notices.secret']),
    );
    const later = JSON.stringify([audit, kept, cleared, saved]);
    for (const secret of [first.secret, second.secret, 'private-token'])
      expect(later).not.toContain(secret);
  });
  it('sends a test and reports the status or the class of the failure', async () => {
    const api = await setup();
    const put = (url: string) =>
      api<NoticeSettings>(
        '/settings/notices',
        send('PUT', update({ format: 'slack', url })),
      );
    const test = () => api<NoticeTest>('/settings/notices/test', send('POST'));
    await put(ADDRESS);
    expect(await test()).toEqual({ delivered: true, status: 200, error: null });
    await put('https://error.example.com/x');
    expect(await test()).toEqual({
      delivered: false,
      status: 500,
      error: 'http_500',
    });
    await put('https://down.example.com/x');
    expect(await test()).toEqual({
      delivered: false,
      status: null,
      error: 'connect',
    });
    // A test is not a notice: the delivery status does not change.
    const settings = await api<NoticeSettings>('/settings/notices');
    expect(settings.delivery).toMatchObject({ dead: 0, last_error: null });
    // A webhook cannot be tested without its secret.
    await api('/settings/notices', send('PUT', update()));
    await expect(test()).rejects.toMatchObject({ status: 400 });
  });
  it('sends only a few test notices a minute, for everyone together', async () => {
    const api = await setup();
    await api(
      '/settings/notices',
      send('PUT', update({ format: 'slack', url: ADDRESS })),
    );
    const test = () => api<NoticeTest>('/settings/notices/test', send('POST'));
    for (let sent = 0; sent < TESTS_PER_MINUTE; sent += 1)
      expect((await test()).delivered).toBe(true);
    await expect(test()).rejects.toMatchObject({
      status: 429,
      code: 'rate_limited',
      details: { retry_after_seconds: 60 },
    });
    // A refused test is not sent, so it leaves no audit event of a test.
    const audit = await api<{ items: { action: string }[] }>('/audit');
    expect(
      audit.items.filter((event) => event.action === 'settings.notices.test'),
    ).toHaveLength(TESTS_PER_MINUTE);
  });
  it('names its audit events as the gateway does', async () => {
    const api = await setup();
    await api('/settings/notices/secret', send('POST'));
    await api(
      '/settings/notices',
      send('PUT', update({ enabled: true, url: ADDRESS })),
    );
    await api('/settings/notices/test', send('POST'));
    await api(
      '/settings/network',
      send('PUT', {
        allowed_cidrs: ['10.0.0.0/8'],
        trust_proxy_headers: false,
      }),
    );
    const audit = await api<{
      items: { action: string; target_type: string; details: unknown }[];
    }>('/audit');
    const settings = audit.items.filter(
      (event) => event.target_type === 'settings',
    );
    expect(settings.map((event) => event.action)).toEqual([
      'settings.network',
      'settings.notices.test',
      'settings.notices',
      'settings.notices.secret',
    ]);
    expect(settings[1]!.details).toEqual({
      delivered: true,
      status: 200,
      error: null,
    });
    expect(Object.keys(settings[2]!.details as object).sort()).toEqual([
      'enabled',
      'events',
      'format',
      'include_reason',
      'include_row_count',
      'url_changed',
      'url_host',
    ]);
    expect(settings[3]!.details).toEqual({ rotated: false });
    expect(audit.items.map((event) => event.action)).not.toContain(
      'network.updated',
    );
  });
  it('writes a notice only for a selected event while notices are on', async () => {
    const api = await setup();
    const { items } = await api<{ items: Cluster[] }>('/clusters');
    const ask = () =>
      api<Approval>(
        '/approvals',
        send('POST', {
          cluster_id: items[0]!.id,
          sql: "UPDATE users SET name = 'x' WHERE id = 1",
          reason: 'Fix name',
        }),
      );
    const delivery = async () =>
      (await api<NoticeSettings>('/settings/notices')).delivery;
    await ask();
    expect((await delivery()).last_success_at).toBeNull();
    await api(
      '/settings/notices',
      send(
        'PUT',
        update({
          enabled: true,
          format: 'slack',
          url: ADDRESS,
          events: ['approval.withdrawn'],
        }),
      ),
    );
    const request = await ask();
    expect((await delivery()).last_success_at).toBeNull();
    await api(`/approvals/${request.id}/withdraw`, send('POST'));
    expect((await delivery()).last_success_at).not.toBeNull();
    // A receiver that is down: the notice is given up, with the class only.
    await api(
      '/settings/notices',
      send(
        'PUT',
        update({
          enabled: true,
          format: 'slack',
          url: 'https://down.example.com/x',
        }),
      ),
    );
    await ask();
    expect(await delivery()).toMatchObject({ dead: 1, last_error: 'connect' });
  });
});

describe('notice addresses and failures in the console', () => {
  it('names the host of an acceptable address and the reason for any other', () => {
    expect(noticeHost(ADDRESS)).toEqual({ host: 'hooks.example.com' });
    for (const bad of [
      'http://hooks.example.com/x',
      'https://user@hooks.example.com/x',
      'https://hooks.example.com/a b',
      'https://172.16.0.1/x',
      'https://192.168.1.1/x',
      'https://100.64.0.1/x',
      `https://hooks.example.com/${'a'.repeat(2048)}`,
    ])
      expect(noticeHost(bad), bad).toHaveProperty('error');
  });
  it('says before saving why an address would be refused', () => {
    expect(addressProblem(ADDRESS)).toBeNull();
    // Local development: the gateway decides.
    expect(addressProblem('http://127.0.0.1:9000/hook')).toBeNull();
    expect(addressProblem('http://hooks.example.com/x')).toContain('https://');
    expect(addressProblem('https://user:pw@hooks.example.com/x')).toContain(
      'user name',
    );
    expect(addressProblem('https://hooks.example.com/x#y')).toContain(
      'fragment',
    );
    expect(addressProblem('hooks.example.com')).toContain('not a valid URL');
  });
  it('keeps an edit for each event switch, so a save undoes nobody else', () => {
    const stored = (events: NoticeUpdate['events']) => ({
      ...update({ enabled: true, events }),
      url: '',
    });
    // "approved" is turned on and not saved.
    const edits = { events: { 'approval.approved': true } };
    expect(applyEdits(stored(['approval.created']), edits).events).toEqual([
      'approval.created',
      'approval.approved',
    ]);
    // Another administrator selects "expired"; the settings are read again.
    const later = applyEdits(
      stored(['approval.created', 'approval.expired']),
      edits,
    );
    expect(later.events).toEqual([
      'approval.created',
      'approval.approved',
      'approval.expired',
    ]);
    // A touched switch stays the person's, also when it was turned off.
    expect(
      applyEdits(stored(['approval.created', 'approval.expired']), {
        events: { 'approval.created': false },
      }).events,
    ).toEqual(['approval.expired']);
    // The other fields follow the store unless they were edited.
    expect(applyEdits(stored([]), {})).toEqual(stored([]));
    expect(applyEdits(stored([]), { format: 'slack' }).format).toBe('slack');
  });
  it('says what a save does to waiting notices, and only what is true', () => {
    const stored = { format: 'webhook' as const };
    const on = { enabled: true, format: 'webhook' as const };
    // Nothing that drops them: nothing is said.
    expect(waitingText(stored, on, '')).toBeNull();
    // Off, or another format: dropped, whatever is typed.
    for (const draft of [
      { ...on, enabled: false },
      { ...on, format: 'slack' as const },
    ])
      for (const url of ['', ADDRESS])
        expect(waitingText(stored, draft, url)).toMatch(
          /They are dropped, not sent\.$/,
        );
    // A typed address may be the one in use; the gateway keeps them then.
    const typed = waitingText(stored, on, ADDRESS);
    expect(typed).toContain('If the address you typed is not the one in use');
    expect(typed).toContain('If it is the same address, they are kept.');
    expect(typed).not.toContain('use now. They are dropped');
  });
  it('puts a failure class into words and never invents one', () => {
    expect(failureText(null)).toBe('None');
    expect(failureText('http_500')).toBe('The receiver answered 500.');
    expect(failureText('http_307')).toContain('Redirects are not followed');
    for (const code of [
      'connect',
      'tls',
      'timeout',
      'not_deliverable',
      'address_changed',
      'format_changed',
      'event_off',
      'protocol',
      'invalid_url',
      'config',
      'notices_off',
    ])
      expect(failureText(code)).not.toBe(code);
    expect(failureText('something_new')).toBe('something_new');
  });
  it('says in place why a test was not sent, with the wait', () => {
    expect(
      testRefusal(
        new ApiError(
          'rate_limited',
          'Too many test notices in one minute',
          429,
          {
            retry_after_seconds: 42,
          },
        ),
      ),
    ).toBe('Too many test notices. Try again in 42 seconds.');
    expect(testRefusal(new ApiError('rate_limited', 'x', 429))).toBe(
      'Too many test notices. Try again in 60 seconds.',
    );
    expect(
      testRefusal(
        new ApiError('validation', 'Set the webhook address first', 400),
      ),
    ).toBe('Set the webhook address first');
  });
});
