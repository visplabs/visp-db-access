// In-memory notice settings for the mock API. It follows docs/API.md closely
// enough for the screen and its tests; it sends nothing anywhere.
import type {
  NoticeEvent,
  NoticeFormat,
  NoticeSecret,
  NoticeSettings,
  NoticeTest,
} from './types';

type Fail = (
  code: string,
  message: string,
  status?: number,
  details?: unknown,
) => never;
/** Test notices in a minute, for everyone together, as on one gateway node. */
export const TESTS_PER_MINUTE = 5;
export const NOTICE_EVENTS: NoticeEvent[] = [
  'approval.created',
  'approval.previewed',
  'approval.approved',
  'approval.rejected',
  'approval.withdrawn',
  'approval.executed',
  'approval.failed',
  'approval.expired',
];
const SECRET_PREFIX = 'vda_whsec_';
const random = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(43)), (byte) =>
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.charAt(
      byte % 64,
    ),
  ).join('');
/** The audit action of a state change, and the notice it writes. */
const EVENT_OF: Record<string, NoticeEvent> = {
  'approval.create': 'approval.created',
  'approval.preview': 'approval.previewed',
  'approval.approve': 'approval.approved',
  'approval.reject': 'approval.rejected',
  'approval.withdraw': 'approval.withdrawn',
  'approval.executed': 'approval.executed',
  'approval.failed': 'approval.failed',
  'approval.expire': 'approval.expired',
};
const privateHost = (host: string) =>
  host === 'localhost' ||
  host.endsWith('.localhost') ||
  host.startsWith('[') ||
  /^(0|10|127)\./.test(host) ||
  /^169\.254\./.test(host) ||
  /^192\.168\./.test(host) ||
  /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host);
/** The host of an address the gateway would accept, or the reason it would not. */
export function noticeHost(raw: string): { host: string } | { error: string } {
  if (raw.length > 2048) return { error: 'The address is too long' };
  if (/[\s\p{Cc}]/u.test(raw))
    return {
      error: 'The address must not contain spaces or control characters',
    };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { error: 'The address is not a valid URL' };
  }
  if (url.protocol !== 'https:')
    return { error: 'The address must start with https://' };
  if (url.username || url.password)
    return { error: 'The address must not contain a user name or a password' };
  if (url.hash) return { error: 'The address must not contain a fragment' };
  if (!url.hostname) return { error: 'The address has no host' };
  if (privateHost(url.hostname))
    return { error: 'A notice cannot be sent to this address' };
  return { host: url.hostname };
}

export function createNotices(context: {
  fail: Fail;
  audit: (action: string, type: string, id: string, details?: unknown) => void;
  now: () => string;
}) {
  const { fail, audit, now } = context;
  let settings: Omit<NoticeSettings, 'delivery' | 'links'> = {
    enabled: false,
    format: 'webhook',
    url_set: false,
    url_host: null,
    secret_set: false,
    events: ['approval.created'],
    include_reason: false,
    include_row_count: false,
  };
  const delivery: NoticeSettings['delivery'] = {
    pending: 0,
    dead: 0,
    last_success_at: null,
    last_error: null,
    last_error_at: null,
  };
  let tests: number[] = [];
  // The demo has no public URL configured, like a fresh install.
  const view = (): NoticeSettings => ({
    ...settings,
    links: false,
    delivery: { ...delivery },
  });
  /** What the demo receiver answers: a host that starts with `down.` cannot
   * be reached and one that starts with `error.` answers 500. */
  const attempt = (): NoticeTest =>
    settings.url_host?.startsWith('down.')
      ? { delivered: false, status: null, error: 'connect' }
      : settings.url_host?.startsWith('error.')
        ? { delivered: false, status: 500, error: 'http_500' }
        : { delivered: true, status: 200, error: null };
  return {
    /** A state change happened: deliver its notice, as the worker would. */
    observe(action: string) {
      const event = EVENT_OF[action];
      if (!event || !settings.enabled || !settings.events.includes(event))
        return;
      const outcome = attempt();
      if (outcome.delivered) delivery.last_success_at = now();
      else {
        delivery.dead += 1;
        delivery.last_error = outcome.error;
        delivery.last_error_at = now();
      }
    },
    route(
      action: string | undefined,
      method: string,
      body: Record<string, unknown>,
    ): NoticeSettings | NoticeSecret | NoticeTest {
      if (!action && method === 'GET') return view();
      if (!action && method === 'PUT') {
        const known = [
          'enabled',
          'format',
          'url',
          'events',
          'include_reason',
          'include_row_count',
        ];
        if (
          Object.keys(body).some((key) => !known.includes(key)) ||
          typeof body.enabled !== 'boolean' ||
          typeof body.include_reason !== 'boolean' ||
          typeof body.include_row_count !== 'boolean' ||
          !['webhook', 'slack'].includes(String(body.format)) ||
          !Array.isArray(body.events)
        )
          fail('validation', 'Invalid JSON body');
        const chosen = (body.events as unknown[]).map(String);
        if (chosen.some((name) => !NOTICE_EVENTS.includes(name as NoticeEvent)))
          fail('validation', 'Unknown notice event');
        const next = { ...settings };
        if (body.url === '') {
          next.url_set = false;
          next.url_host = null;
        } else if (typeof body.url === 'string') {
          const checked = noticeHost(body.url);
          if ('error' in checked) fail('validation', checked.error);
          else {
            next.url_set = true;
            next.url_host = checked.host;
          }
        }
        next.enabled = body.enabled as boolean;
        next.format = body.format as NoticeFormat;
        next.events = NOTICE_EVENTS.filter((name) => chosen.includes(name));
        next.include_reason = body.include_reason as boolean;
        next.include_row_count = body.include_row_count as boolean;
        if (next.enabled) {
          if (!next.url_set)
            fail(
              'validation',
              'Set the webhook address before you turn notices on',
            );
          if (next.events.length === 0)
            fail('validation', 'Select at least one event');
          if (next.format === 'webhook' && !next.secret_set)
            fail(
              'validation',
              'Create the signing secret before you turn webhook notices on',
            );
        }
        settings = next;
        audit('settings.notices', 'settings', 'notices', {
          enabled: next.enabled,
          format: next.format,
          events: next.events,
          include_reason: next.include_reason,
          include_row_count: next.include_row_count,
          url_changed: typeof body.url === 'string',
          url_host: next.url_host,
        });
        return view();
      }
      if (action === 'secret' && method === 'POST') {
        const rotated = settings.secret_set;
        settings = { ...settings, secret_set: true };
        audit('settings.notices.secret', 'settings', 'notices', { rotated });
        return { secret: `${SECRET_PREFIX}${random()}`, rotated };
      }
      if (action === 'test' && method === 'POST') {
        if (!settings.url_set)
          fail('validation', 'Set the webhook address first');
        if (settings.format === 'webhook' && !settings.secret_set)
          fail('validation', 'Create the signing secret first');
        tests = tests.filter((at) => at > Date.now() - 60000);
        if (tests.length >= TESTS_PER_MINUTE)
          fail('rate_limited', 'Too many test notices in one minute', 429, {
            retry_after_seconds: 60,
          });
        tests.push(Date.now());
        const outcome = attempt();
        audit('settings.notices.test', 'settings', 'notices', outcome);
        return outcome;
      }
      return fail('not_found', 'Endpoint not found.', 404);
    },
  };
}
