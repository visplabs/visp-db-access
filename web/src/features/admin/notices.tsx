import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAction, useResource } from '../../lib/query';
import { useCopy } from '../../lib/clipboard';
import { formatTime, message } from '../../lib/utils';
import { ApiError } from '../../api/errors';
import {
  Button,
  Confirm,
  ErrorPanel,
  Field,
  Modal,
  SegmentedControl,
  Skeleton,
  SwitchRow,
} from '../../components/ui';
import { RelativeTime } from '../../components/ui/time';
import type {
  NoticeEvent,
  NoticeFormat,
  NoticeSecret,
  NoticeSettings,
  NoticeTest,
  NoticeUpdate,
} from '../../api/types';

const PATH = '/settings/notices';
/** How often the delivery status is read again while the tab is open. */
const REFRESH_MS = 15000;
const EVENTS: { value: NoticeEvent; label: string; description: string }[] = [
  {
    value: 'approval.created',
    label: 'A request is made',
    description: 'A new request for a write waits for approval.',
  },
  {
    value: 'approval.previewed',
    label: 'A request is previewed',
    description: 'A person ran the dry run of a request from an agent.',
  },
  {
    value: 'approval.approved',
    label: 'A request is approved',
    description: 'An approver said yes. The write has not run yet.',
  },
  {
    value: 'approval.rejected',
    label: 'A request is rejected',
    description: 'An approver said no.',
  },
  {
    value: 'approval.withdrawn',
    label: 'A request is withdrawn',
    description: 'The person or the agent that asked took it back.',
  },
  {
    value: 'approval.executed',
    label: 'A write ran',
    description: 'An approved write changed the database.',
  },
  {
    value: 'approval.failed',
    label: 'A write failed',
    description:
      'An approved write did not run, or nobody knows whether it ran.',
  },
  {
    value: 'approval.expired',
    label: 'A request expired',
    description: 'Nobody approved or ran it in time.',
  },
];
const FORMATS: Record<NoticeFormat, string> = {
  webhook: 'Signed webhook',
  slack: 'Slack',
};
/** A failure class from the gateway, in words. The gateway keeps only the
 * class: never a part of the address or of the receiver's answer. */
export function failureText(code: string | null): string {
  if (!code) return 'None';
  const status = /^http_(\d{3})$/.exec(code)?.[1];
  if (status)
    return status.startsWith('3')
      ? `The receiver answered ${status}. Redirects are not followed.`
      : `The receiver answered ${status}.`;
  return (
    {
      connect: 'Could not connect to the receiver.',
      tls: 'The TLS certificate of the receiver was not accepted.',
      timeout: 'The receiver did not answer in time.',
      not_deliverable:
        'The host name does not lead to a public address. Notices go only to public addresses.',
      protocol: 'The answer was not HTTP.',
      invalid_url: 'The stored address is not valid.',
      config: 'The stored address or secret cannot be read.',
      notices_off: 'Dropped: notices were turned off before it was sent.',
      address_changed: 'Dropped: the address changed before it was sent.',
      format_changed: 'Dropped: the format changed before it was sent.',
      event_off: 'Dropped: its event was deselected before it was sent.',
    }[code] ?? code
  );
}
type Draft = Omit<NoticeUpdate, 'url'> & { url: string };
/** What a person changed and has not saved. Each event switch is its own
 * edit: a switch that was not touched follows the stored settings, so a
 * save never undoes a selection that someone else made meanwhile. */
export type Edits = Partial<Omit<Draft, 'events'>> & {
  events?: Partial<Record<NoticeEvent, boolean>>;
};
/** The stored settings with the unsaved edits laid over them. */
export function applyEdits(saved: Draft, edits: Edits): Draft {
  const { events: touched = {}, ...fields } = edits;
  return {
    ...saved,
    ...fields,
    events: EVENTS.map((event) => event.value).filter(
      (value) => touched[value] ?? saved.events.includes(value),
    ),
  };
}
const draftOf = (settings: NoticeSettings): Draft => ({
  enabled: settings.enabled,
  format: settings.format,
  url: '',
  // In the order of the list, as `applyEdits` gives them.
  events: EVENTS.map((event) => event.value).filter((value) =>
    settings.events.includes(value),
  ),
  include_reason: settings.include_reason,
  include_row_count: settings.include_row_count,
});

/** Notices to approvers: one webhook that says a request waits. */
export function NoticeSettingsPanel() {
  // Read again after every save and test (they refresh all queries) and on
  // an interval, so the delivery status follows the worker.
  const query = useResource<NoticeSettings>(PATH, true, REFRESH_MS);
  // Held here, beside the secret's own section and not in the form.
  const [secret, setSecret] = useState<'create' | 'rotate' | null>(null);
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Notices</h1>
          <p>
            Tell approvers that a request waits, through one webhook. A notice
            never holds SQL, rows or database errors.
          </p>
        </div>
      </div>
      {query.isPending ? (
        <Skeleton />
      ) : query.error ? (
        <ErrorPanel error={query.error} />
      ) : (
        <div className="settings-page">
          <NoticeForm original={query.data} />
          <section className="settings-section">
            <h2>Signing secret</h2>
            <p className="muted">
              The gateway signs every webhook notice with this secret, so your
              receiver can tell a real notice from a forged one. Slack does not
              check signatures.
            </p>
            <dl className="review-policy">
              <dt>Secret</dt>
              <dd>{query.data.secret_set ? 'Set' : 'Not set'}</dd>
            </dl>
            <Button
              onClick={() =>
                setSecret(query.data.secret_set ? 'rotate' : 'create')
              }
            >
              {query.data.secret_set ? 'Rotate secret' : 'Create secret'}
            </Button>
          </section>
          <DeliveryStatus settings={query.data} />
        </div>
      )}
      {/* Mounted only while open: when it closes, the component that held
          the secret is gone, and nothing else ever saw it. */}
      {secret && (
        <SecretDialog
          rotating={secret === 'rotate'}
          onClose={() => setSecret(null)}
        />
      )}
    </>
  );
}

function NoticeForm({ original }: { original: NoticeSettings }) {
  // The form is never rebuilt when the settings are read again: it holds
  // only what the person changed and has not saved, laid over what is
  // stored. A refresh in the background moves the stored values under it
  // and leaves the typed address, the switches that were touched and an
  // open dialog as they are.
  const [edits, setEdits] = useState<Edits>({}),
    [confirm, setConfirm] = useState(false),
    [removing, setRemoving] = useState(false);
  const cache = useQueryClient();
  const save = useAction<NoticeSettings>('Notices saved');
  const remove = useAction<NoticeSettings>('Address removed');
  const saved = draftOf(original);
  const draft = applyEdits(saved, edits);
  const set = (change: Edits) =>
    setEdits((edits) => ({
      ...edits,
      ...change,
      events: { ...edits.events, ...change.events },
    }));
  /** The gateway's answer to a save is what is stored now. The form shows
   * it at once, and does not wait for the settings to be read again. */
  const stored = (settings: NoticeSettings) =>
    cache.setQueryData(['api', PATH], settings);
  const url = draft.url.trim();
  const changed =
    url !== '' ||
    JSON.stringify({ ...draft, url: '' }) !== JSON.stringify(saved);
  // The gateway checks all of this again; these are the reasons it would give.
  const problem =
    url !== '' && addressProblem(url)
      ? addressProblem(url)
      : !draft.enabled
        ? null
        : !original.url_set && url === ''
          ? 'Set the webhook address before you turn notices on.'
          : draft.events.length === 0
            ? 'Select at least one event.'
            : draft.format === 'webhook' && !original.secret_set
              ? 'Create the signing secret before you turn webhook notices on.'
              : null;
  const body: NoticeUpdate = {
    enabled: draft.enabled,
    format: draft.format,
    events: draft.events,
    include_reason: draft.include_reason,
    include_row_count: draft.include_row_count,
    ...(url ? { url } : {}),
  };
  return (
    <>
      <section className="settings-section">
        <h2>Delivery</h2>
        <SwitchRow
          label="Send notices"
          description="When off, nothing is written or sent, and notices that still wait are dropped."
          checked={draft.enabled}
          onChange={(enabled) => set({ enabled })}
        />
        <Field label="Format" group>
          <SegmentedControl
            label="Format"
            value={draft.format}
            onChange={(format) => set({ format: format as NoticeFormat })}
            items={(Object.keys(FORMATS) as NoticeFormat[]).map((value) => ({
              value,
              label: FORMATS[value],
            }))}
          />
        </Field>
        <Field
          label="Webhook address"
          hint={
            original.url_set
              ? `Set, on ${original.url_host}. The address is not shown again. Type a new one to replace it.`
              : 'An https address. It is stored encrypted and not shown again.'
          }
        >
          <input
            type="url"
            className="mono"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            maxLength={2048}
            placeholder={
              original.url_set ? 'Unchanged' : 'https://hooks.example.com/…'
            }
            value={draft.url}
            onChange={(event) => set({ url: event.currentTarget.value })}
          />
        </Field>
        {original.url_set && (
          <p>
            <Button size="small" onClick={() => setRemoving(true)}>
              Remove address
            </Button>
          </p>
        )}
        {!original.links && (
          <p className="muted">
            Notices have no link to the request: the gateway does not know its
            own address. Set <span className="mono">VISP_GATE_PUBLIC_URL</span>{' '}
            on the server to add one.
          </p>
        )}
      </section>
      <section className="settings-section">
        <h2>Events</h2>
        <p className="muted">One notice is sent for each selected change.</p>
        {EVENTS.map((event) => (
          <SwitchRow
            key={event.value}
            label={event.label}
            description={event.description}
            checked={draft.events.includes(event.value)}
            onChange={(on) => set({ events: { [event.value]: on } })}
          />
        ))}
      </section>
      <section className="settings-section">
        <h2>What a notice says</h2>
        <p className="muted">
          Always: what happened and when, the request, the database name, its
          environment and engine, who asked, and the agent when an agent asked.
          Never the SQL, a row, a preview or a database error.
        </p>
        <p className="muted">
          The person who asked is named by their display name, which is an email
          address where names are emails. An agent is named by the name its
          owner gave it. The receiver will hold both.
        </p>
        <SwitchRow
          label="Include the reason"
          description="Warning: the reason is free text from a person or an agent. It can hold names or data, and it leaves the gateway. Cut at 500 characters."
          checked={draft.include_reason}
          onChange={(include_reason) => set({ include_reason })}
        />
        <SwitchRow
          label="Include the row count"
          description="Warning: how many rows a write changes can tell an outsider how much data there is."
          checked={draft.include_row_count}
          onChange={(include_row_count) => set({ include_row_count })}
        />
        {changed && problem && (
          <p className="error-text" role="alert">
            {problem}
          </p>
        )}
        <Button
          variant="primary"
          disabled={!changed || !!problem}
          onClick={() => setConfirm(true)}
        >
          Review notice changes
        </Button>
      </section>
      <Confirm
        open={confirm}
        onOpenChange={(open) => {
          setConfirm(open);
          // A request that was refused still holds the typed address. It
          // goes when the dialog does.
          if (!open && !save.isPending) save.reset();
        }}
        title="Update notices?"
        description="Notices leave the gateway. Confirm where they go and what they say."
        busy={save.isPending}
        onConfirm={() =>
          save.mutate(
            { path: PATH, method: 'PUT', body },
            {
              onSuccess: (settings) => {
                setConfirm(false);
                // Nothing is unsaved now. The typed address is not kept
                // once it is saved: not in the field, and not in the
                // finished request, which the cache would otherwise hold
                // while this form is open.
                stored(settings);
                setEdits({});
                save.reset();
              },
            },
          )
        }
      >
        {original.enabled && waitingText(original, draft, url) && (
          <p className="muted">{waitingText(original, draft, url)}</p>
        )}
        <dl className="review-policy">
          <dt>Notices</dt>
          <dd>{draft.enabled ? 'On' : 'Off'}</dd>
          <dt>Format</dt>
          <dd>{FORMATS[draft.format]}</dd>
          <dt>Address</dt>
          <dd className="mono">
            {url
              ? `New address on ${hostOf(url)}`
              : original.url_set
                ? `Unchanged, on ${original.url_host}`
                : 'Not set'}
          </dd>
          <dt>Events</dt>
          <dd>
            {draft.events.length
              ? EVENTS.filter((event) => draft.events.includes(event.value))
                  .map((event) => event.label)
                  .join(', ')
              : 'None'}
          </dd>
          <dt>Reason</dt>
          <dd>{draft.include_reason ? 'Included' : 'Left out'}</dd>
          <dt>Row count</dt>
          <dd>{draft.include_row_count ? 'Included' : 'Left out'}</dd>
        </dl>
      </Confirm>
      <Confirm
        open={removing}
        onOpenChange={setRemoving}
        title="Remove the webhook address?"
        description="Notices are turned off. Notices that still wait are dropped, not sent. The other settings and the signing secret stay."
        danger
        busy={remove.isPending}
        onConfirm={() =>
          remove.mutate(
            {
              path: PATH,
              method: 'PUT',
              // What is saved, not what is typed: this removes the address
              // and nothing else.
              body: {
                enabled: false,
                format: original.format,
                url: '',
                events: original.events,
                include_reason: original.include_reason,
                include_row_count: original.include_row_count,
              } satisfies NoticeUpdate,
            },
            {
              onSuccess: (settings) => {
                stored(settings);
                setRemoving(false);
              },
            },
          )
        }
      />
    </>
  );
}
/** What a save does to the notices that still wait, or null when it leaves
 * them. The gateway drops them when notices go off, when the format changes
 * and when the address changes. A typed address may be the one in use: the
 * browser never sees the stored address, so it cannot tell, and says so. */
export function waitingText(
  original: Pick<NoticeSettings, 'format'>,
  draft: Pick<Draft, 'enabled' | 'format'>,
  url: string,
): string | null {
  const written =
    'Notices that still wait were written for the settings in use now.';
  if (!draft.enabled || draft.format !== original.format)
    return `${written} They are dropped, not sent.`;
  if (url !== '')
    return `${written} If the address you typed is not the one in use now, they are dropped, not sent. If it is the same address, they are kept.`;
  return null;
}
/** Why the gateway would refuse a typed address, as far as the browser can
 * tell. A loopback address over plain HTTP is let through: the gateway takes
 * it only when it runs for local development, and it decides. */
export function addressProblem(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return 'The address is not a valid URL.';
  }
  if (parsed.username || parsed.password)
    return 'The address must not contain a user name or a password.';
  const local =
    parsed.protocol === 'http:' &&
    ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !local)
    return 'The address must start with https://.';
  if (parsed.hash) return 'The address must not contain a fragment.';
  return null;
}
/** The host of a typed address, for the summary. Only the host is shown. */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname || 'an unknown host';
  } catch {
    return 'an unknown host';
  }
}

/** Why a test could not be sent, said under the button. A refusal for too
 * many tests says how long to wait. */
export function testRefusal(error: unknown): string {
  if (error instanceof ApiError && error.status === 429) {
    const wait = (error.details as { retry_after_seconds?: unknown } | null)
      ?.retry_after_seconds;
    return `Too many test notices. Try again in ${typeof wait === 'number' ? wait : 60} seconds.`;
  }
  return message(error);
}
function DeliveryStatus({ settings }: { settings: NoticeSettings }) {
  // The outcome and a refusal both show under the button, not in a toast
  // that leaves after a few seconds.
  const test = useAction<NoticeTest>('', { quietErrors: true });
  const [result, setResult] = useState<NoticeTest | null>(null),
    [refused, setRefused] = useState<string | null>(null);
  const { delivery } = settings;
  const ready =
    settings.url_set && (settings.format === 'slack' || settings.secret_set);
  return (
    <section className="settings-section">
      <h2>Delivery status</h2>
      <dl className="review-policy">
        <dt>Last delivered</dt>
        <dd>
          {delivery.last_success_at ? (
            <RelativeTime value={delivery.last_success_at} />
          ) : (
            'Never'
          )}
        </dd>
        <dt>Last error</dt>
        <dd>
          {delivery.last_error
            ? `${failureText(delivery.last_error)} ${formatTime(delivery.last_error_at)}`
            : 'None'}
        </dd>
        <dt>Waiting</dt>
        <dd>{delivery.pending}</dd>
        <dt>Given up</dt>
        <dd>{delivery.dead}</dd>
      </dl>
      <p className="muted">
        A notice is tried six times in about an hour, then given up. Send a test
        to check the saved address{' '}
        {settings.format === 'webhook' ? 'and secret' : ''} now.
      </p>
      <Button
        disabled={!ready || test.isPending}
        onClick={() => {
          setResult(null);
          setRefused(null);
          test.mutate(
            { path: `${PATH}/test` },
            {
              onSuccess: (outcome) => setResult(outcome),
              onError: (error) => setRefused(testRefusal(error)),
            },
          );
        }}
      >
        {test.isPending ? 'Sending…' : 'Send test'}
      </Button>
      <p
        className={
          refused || result?.delivered === false ? 'error-text' : 'muted'
        }
        role="status"
      >
        {!ready
          ? 'Save an address' +
            (settings.format === 'webhook' ? ' and create the secret' : '') +
            ' to send a test.'
          : refused
            ? refused
            : result === null
              ? ''
              : result.delivered
                ? `Delivered. The receiver answered ${result.status}.`
                : `Not delivered. ${failureText(result.error)}`}
      </p>
    </section>
  );
}

/** Makes a signing secret and shows it one time. It owns the secret, and it
 * is unmounted when it closes, so the secret does not outlive the dialog. */
function SecretDialog({
  rotating,
  onClose,
}: {
  rotating: boolean;
  onClose: () => void;
}) {
  const make = useAction<NoticeSecret>(
    rotating ? 'Secret rotated' : 'Secret created',
  );
  const copy = useCopy();
  const [fresh, setFresh] = useState<NoticeSecret | null>(null);
  // The one way to close. Not while the request is under way: a secret made
  // after the dialog closed would be in use and unseen.
  const close = () => {
    if (!make.isPending) onClose();
  };
  return (
    <Modal
      open
      // While the secret shows, only Done closes the dialog: a stray Escape
      // or a click beside it would lose a secret that cannot be shown again.
      dismissible={!fresh}
      onOpenChange={(open) => {
        if (!open) close();
      }}
      title={
        fresh
          ? 'Copy the secret now'
          : rotating
            ? 'Rotate the signing secret?'
            : 'Create the signing secret?'
      }
      description={
        fresh
          ? 'The secret cannot be shown again. Copy it and put it in your receiver, which uses it to check each notice. Only Done closes this dialog.'
          : rotating
            ? 'The secret in use stops working at once. Notices are signed with the new one, so your receiver refuses them until you update it.'
            : 'The gateway signs every webhook notice with it. You see it once.'
      }
    >
      {fresh ? (
        <>
          <Field label="Signing secret">
            <input
              readOnly
              className="mono"
              value={fresh.secret}
              onFocus={(event) => event.currentTarget.select()}
            />
          </Field>
          <div className="dialog-actions">
            <Button onClick={() => void copy(fresh.secret)}>Copy secret</Button>
            <Button variant="primary" onClick={close}>
              Done
            </Button>
          </div>
        </>
      ) : (
        <div className="dialog-actions">
          <Button disabled={make.isPending} onClick={close}>
            Cancel
          </Button>
          <Button
            variant={rotating ? 'danger' : 'primary'}
            disabled={make.isPending}
            onClick={() =>
              make.mutate(
                { path: `${PATH}/secret` },
                {
                  onSuccess: (secret) => {
                    setFresh(secret);
                    // Held by this dialog only, not by the finished request.
                    make.reset();
                  },
                },
              )
            }
          >
            {rotating ? 'Rotate secret' : 'Create secret'}
          </Button>
        </div>
      )}
    </Modal>
  );
}
