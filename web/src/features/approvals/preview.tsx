import { useEffect, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { json, request } from '../../api/client';
import type { Approval, Preview, RowSample } from '../../api/types';
import { Button, Confirm } from '../../components/ui';
import {
  boundText,
  changeSummary,
  matchRows,
  resolveWritten,
  whatHappened,
} from '../../lib/approval-presentation';
import { cellText, message } from '../../lib/utils';

export const PREVIEW_WARNING =
  'This runs the statement on the database and rolls it back. Triggers and defaults on the table still run.';
export const PREVIEWED_BY_SOMEONE_ELSE =
  'Someone else previewed this request; this is their preview.';

type Notice = {
  kind: 'error' | 'info';
  text: string;
  /** The status the request had when this was said; it is stale after. */
  status: Approval['status'];
};

/** "What changes": the dry run of a write, or why there is none. */
export function PreviewSection({
  approval,
  canPreview,
}: {
  approval: Approval;
  /** The caller may start the preview: the requester or a cluster admin. */
  canPreview: boolean;
}) {
  const preview = approval.preview;
  const path = `/approvals/${approval.id}`;
  const cache = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  // One preview at a time: a second click cannot send a second request.
  const lock = useRef(false);
  const shown = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // The answer appears where the person is looking, also in a short sheet.
    if (notice) shown.current?.scrollIntoView?.({ block: 'nearest' });
  }, [notice]);
  const run = useMutation({
    gcTime: 0,
    mutationFn: () =>
      request<Approval>(`${path}/preview`, json('POST', undefined)),
    onMutate: () => setNotice(null),
    onSuccess: () => setConfirming(false),
    onError: async (failure) => {
      setConfirming(false);
      // Show what is true now: another person may have previewed it, or
      // the request may have been reviewed, withdrawn or expired meanwhile.
      const fresh = await cache
        .fetchQuery({
          queryKey: ['api', path],
          queryFn: ({ signal }) => request<Approval>(path, { signal }),
          staleTime: 0,
        })
        .catch(() => null);
      setNotice(
        fresh?.preview && !approval.preview
          ? {
              kind: 'info',
              text: PREVIEWED_BY_SOMEONE_ELSE,
              status: fresh.status,
            }
          : {
              kind: 'error',
              // Say what happened meanwhile, not only that it failed.
              text: [
                message(failure),
                fresh && fresh.status !== approval.status
                  ? whatHappened(fresh)
                  : null,
              ]
                .filter(Boolean)
                .join(' '),
              status: fresh?.status ?? approval.status,
            },
      );
    },
    onSettled: () => {
      lock.current = false;
      void cache.invalidateQueries();
    },
  });
  const start = () => {
    if (lock.current) return;
    lock.current = true;
    run.mutate();
  };
  const current = notice?.status === approval.status ? notice : null;
  return (
    <section className="approval-preview" aria-label="What changes">
      <h3>What changes</h3>
      {current && (
        <div
          ref={shown}
          className={`callout ${current.kind === 'error' ? 'danger' : ''}`}
          role={current.kind === 'error' ? 'alert' : 'status'}
        >
          {current.text}
        </div>
      )}
      {!preview ? (
        <NoPreview
          approval={approval}
          canPreview={canPreview}
          busy={run.isPending}
          onPreview={() => setConfirming(true)}
        />
      ) : !preview.supported ? (
        <p>
          <strong>No preview.</strong>{' '}
          {preview.reason ??
            'This write is not previewed, and nothing is bound.'}
        </p>
      ) : (
        <PreviewBody preview={preview} status={approval.status} />
      )}
      <Confirm
        open={confirming}
        onOpenChange={setConfirming}
        title="Preview this write?"
        description={PREVIEW_WARNING}
        busy={run.isPending}
        busyLabel="Previewing…"
        onConfirm={start}
      >
        <pre
          className="sql-preview-block confirm-sql"
          tabIndex={0}
          aria-label="SQL to preview"
        >
          {approval.sql}
        </pre>
      </Confirm>
    </section>
  );
}

function NoPreview({
  approval,
  canPreview,
  busy,
  onPreview,
}: {
  approval: Approval;
  canPreview: boolean;
  busy: boolean;
  onPreview: () => void;
}) {
  const pending = approval.status === 'pending';
  // A deleted agent's request can never run: no preview, no approval.
  const agentDeleted = !!approval.agent && approval.agent.id === null;
  return (
    <>
      {!approval.agent ? (
        <p>This request has no preview.</p>
      ) : !pending ? (
        <p>Nothing ran: this request was never previewed.</p>
      ) : agentDeleted ? (
        <p>
          Nothing has run. The agent that asked was deleted, so this request
          cannot be previewed or approved. Reject it, or let it expire.
        </p>
      ) : (
        <p>
          Nothing has run yet. The agent&apos;s statement has not been tried on
          the database, so there are no rows to show. Preview it to see the rows
          it changes; it cannot be approved before that.
        </p>
      )}
      {canPreview && pending && !agentDeleted && (
        <div className="inline wrap">
          <Button variant="primary" disabled={busy} onClick={onPreview}>
            {busy ? 'Previewing…' : 'Preview'}
          </Button>
        </div>
      )}
    </>
  );
}

function PreviewBody({
  preview,
  status,
}: {
  preview: Preview;
  status: Approval['status'];
}) {
  const match = matchRows(preview.before, preview.after, preview.written);
  const written = preview.written
    ? resolveWritten(preview.written, [
        ...(preview.before?.columns ?? []),
        ...(preview.after?.columns ?? []),
      ]).names
    : [];
  const update = !!preview.before && !!preview.after;
  // The key first, then what it writes, so a narrow screen shows the change.
  // A column is listed once, also when the key is written (`INSERT (id, …)`).
  const first = [...new Set([match.key ?? 'id', ...written])];
  return (
    <>
      <p>
        <strong>{changeSummary(preview)}</strong>
        {preview.target && (
          <>
            {' '}
            in <code className="identifier">{preview.target}</code>
          </>
        )}
        . {boundText(preview.bound_to, status)}
      </p>
      {preview.notes.length > 0 && (
        <ul className="preview-notes">
          {preview.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
      {update && !match.key && (
        <p className="muted">
          {preview.written
            ? 'Rows cannot be matched one to one here; written columns are marked.'
            : 'Rows cannot be matched one to one here, so no value is marked as changed.'}
        </p>
      )}
      {preview.before && (
        <SampleTable
          title={preview.kind === 'delete' ? 'Rows it deletes' : 'Before'}
          sample={preview.before}
          masked={preview.before.masked ?? preview.before.hidden}
          written={written}
          first={first}
        />
      )}
      {preview.after && (
        <SampleTable
          title={update ? 'After' : 'Rows it adds'}
          sample={preview.after}
          masked={preview.after.masked ?? preview.before?.hidden ?? []}
          written={written}
          changed={match.changed}
          first={first}
          legend={
            match.changed.size > 0
              ? 'Changed values are bold and underlined.'
              : undefined
          }
        />
      )}
    </>
  );
}

/** Rows of a preview. A written or hidden column says so in its header, as
 * masked columns do in results. */
function SampleTable({
  title,
  sample,
  masked,
  written,
  changed,
  legend,
  first = [],
}: {
  title: string;
  sample: RowSample;
  /** Columns known to be protected. Other hidden ones are computed from
   * something that may not be shown, or not known to be protected. */
  masked: string[];
  /** Columns the statement writes. */
  written: string[];
  changed?: Set<string>;
  legend?: string;
  /** Columns to show first, when the sample has them. */
  first?: string[];
}) {
  const order = [
    ...new Set([
      ...first.filter((column) => sample.columns.includes(column)),
      ...sample.columns,
    ]),
  ].map((column) => sample.columns.indexOf(column));
  const label = (column: string) =>
    [
      written.includes(column) ? ' · written' : '',
      sample.hidden.includes(column)
        ? masked.includes(column)
          ? ' · masked'
          : ' · hidden'
        : '',
    ].join('');
  return (
    <div className="preview-sample">
      <p className="preview-sample-title">
        <strong>{title}</strong>
        {sample.total > sample.rows.length && (
          <span className="muted">
            showing {sample.rows.length} of {sample.total.toLocaleString('en')}
          </span>
        )}
        {legend && <span className="muted">{legend}</span>}
      </p>
      <div
        className="table-wrap"
        tabIndex={0}
        role="region"
        aria-label={`${title}: rows`}
      >
        <table>
          <thead>
            <tr>
              {order.map((index) => {
                const column = sample.columns[index] ?? '';
                return (
                  <th key={index} scope="col">
                    {column}
                    {label(column)}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {sample.rows.map((row, index) => (
              <tr key={index}>
                {order.map((cell) => {
                  const value = row[cell];
                  const marked = changed?.has(`${index}:${cell}`);
                  return (
                    <td
                      key={cell}
                      className={marked ? 'cell-changed' : undefined}
                    >
                      {marked && <span className="sr-only">Changed: </span>}
                      {value == null ? (
                        <span className="muted">NULL</span>
                      ) : (
                        <CellValue text={cellText(value)} />
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** A long value is cut in the middle on a phone, where its end tells rows
 * apart (an id); the whole value stays for screen readers and on hover. */
function CellValue({ text }: { text: string }) {
  if (text.length <= 24) return <>{text}</>;
  return (
    <span title={text}>
      <span className="cell-full">{text}</span>
      <span className="cell-short" aria-hidden="true">
        {`${text.slice(0, 4)}…${text.slice(-8)}`}
      </span>
    </span>
  );
}
