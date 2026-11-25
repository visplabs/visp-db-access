import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { EyeOff, Lock, TriangleAlert } from 'lucide-react';
import { json, request } from '../../api/client';
import type { Approval, Preview, RowSample } from '../../api/types';
import { Confirm, SqlText } from '../../components/ui';
import {
  boundText,
  changeSummary,
  matchRows,
  resolveWritten,
  whatHappened,
} from '../../lib/approval-presentation';
import { cellText, message } from '../../lib/utils';
import { formatSql, pairRows } from './decision';

export const PREVIEW_WARNING =
  'This runs the statement on the database and rolls it back. Triggers and defaults on the table still run.';
export const PREVIEWED_BY_SOMEONE_ELSE =
  'Someone else previewed this request; this is their preview.';

export type Notice = {
  kind: 'error' | 'info';
  text: string;
  /** The status the request had when this was said; it is stale after. */
  status: Approval['status'];
};

/**
 * Starting a preview: the confirmation, the request and what it said. The
 * button lives in the action bar; the answer shows under "What changes".
 */
export function usePreview(approval: Approval) {
  const path = `/approvals/${approval.id}`;
  const cache = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  // One preview at a time: a second click cannot send a second request.
  const lock = useRef(false);
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
  const dialog = (
    <Confirm
      open={confirming}
      onOpenChange={setConfirming}
      title="Preview this write?"
      description={PREVIEW_WARNING}
      busy={run.isPending}
      busyLabel="Previewing…"
      onConfirm={start}
    >
      {/* A scrolling region: keyboard users focus it to scroll long SQL. */}
      <pre
        className="sql-preview-block confirm-sql"
        role="region"
        tabIndex={0}
        aria-label="SQL to preview"
      >
        <SqlText sql={formatSql(approval.sql)} />
      </pre>
    </Confirm>
  );
  return {
    busy: run.isPending,
    notice: notice?.status === approval.status ? notice : null,
    ask: () => setConfirming(true),
    dialog,
  };
}

/** "What changes": the dry run of a write, or why there is none. */
export function ChangesSection({
  approval,
  notice,
}: {
  approval: Approval;
  notice: Notice | null;
}) {
  const preview = approval.preview;
  const shown = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // The answer appears where the person is looking, also on a phone.
    if (notice) shown.current?.scrollIntoView?.({ block: 'nearest' });
  }, [notice]);
  return (
    <section className="ar-changes" aria-label="What changes">
      <h3 className="ar-section-title">What changes</h3>
      {notice && (
        <div
          ref={shown}
          className={`callout ${notice.kind === 'error' ? 'danger' : ''}`}
          role={notice.kind === 'error' ? 'alert' : 'status'}
        >
          {notice.text}
        </div>
      )}
      {!preview ? (
        <NoPreview approval={approval} />
      ) : !preview.supported ? (
        <div className="ar-state" data-state="caution">
          <TriangleAlert size={18} aria-hidden="true" />
          <p>
            <strong>No preview.</strong>{' '}
            {preview.reason ??
              'This write is not previewed, and nothing is bound.'}
          </p>
        </div>
      ) : (
        <PreviewBody preview={preview} status={approval.status} />
      )}
    </section>
  );
}

function NoPreview({ approval }: { approval: Approval }) {
  const pending = approval.status === 'pending';
  // A deleted agent's request can never run: no preview, no approval.
  const agentDeleted = !!approval.agent && approval.agent.id === null;
  const needed = !!approval.agent && pending && !agentDeleted;
  return (
    <div className="ar-state" data-state={needed ? 'needed' : 'none'}>
      <EyeOff size={18} aria-hidden="true" />
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
          <strong>Nothing has run yet.</strong> The agent&apos;s statement has
          not been tried on the database, so there are no rows to show. Preview
          it to see the rows it changes; it cannot be approved before that.
        </p>
      )}
    </div>
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
  const paired =
    update && match.key
      ? pairRows(preview.before!, preview.after!, match.key)
      : null;
  return (
    <>
      <p className="ar-headline">
        <strong>{changeSummary(preview)}</strong>
        {preview.target && (
          <>
            {' '}
            in <code className="identifier">{preview.target}</code>
          </>
        )}
        .
      </p>
      <p className="ar-bound">
        <Lock size={14} aria-hidden="true" />
        {boundText(preview.bound_to, status)}
      </p>
      {preview.notes.length > 0 && (
        <ul className="ar-notes">
          {preview.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
      {!preview.before && !preview.after && (
        <p className="muted">No rows to show: the preview only counted them.</p>
      )}
      {update && !match.key && (
        <p className="muted">
          {preview.written
            ? 'Rows cannot be matched one to one here; written columns are marked.'
            : 'Rows cannot be matched one to one here, so no value is marked as changed.'}
        </p>
      )}
      {paired ? (
        <DiffTable
          before={preview.before!}
          after={preview.after!}
          pairs={paired}
          changed={match.changed}
          written={written}
          keyColumn={match.key!}
          first={first}
        />
      ) : (
        <>
          {preview.before && (
            <SampleTable
              title={preview.kind === 'delete' ? 'Rows it deletes' : 'Before'}
              change={preview.kind === 'delete' ? 'removed' : undefined}
              sample={preview.before}
              masked={preview.before.masked ?? preview.before.hidden}
              written={written}
              first={first}
            />
          )}
          {preview.after && (
            <SampleTable
              title={update ? 'After' : 'Rows it adds'}
              change={update ? undefined : 'added'}
              sample={preview.after}
              masked={preview.after.masked ?? preview.before?.hidden ?? []}
              written={written}
              first={first}
            />
          )}
        </>
      )}
    </>
  );
}

/** Column order: the given ones first, when the sample has them. */
const ordered = (columns: string[], first: string[]) => [
  ...new Set([...first.filter((c) => columns.includes(c)), ...columns]),
];

/** A column's header with what is known of it: written, masked or hidden. */
function ColumnHead({
  column,
  written,
  hidden,
  masked,
}: {
  column: string;
  written: boolean;
  hidden: boolean;
  masked: boolean;
}) {
  return (
    <th scope="col" data-written={written || undefined}>
      <span className="ar-col">{column}</span>
      {written && <Tag kind="written">written</Tag>}
      {hidden && (
        <Tag kind={masked ? 'masked' : 'hidden'}>
          {masked ? 'masked' : 'hidden'}
        </Tag>
      )}
    </th>
  );
}
function Tag({ kind, children }: { kind: string; children: ReactNode }) {
  return (
    <span className="ar-tag" data-tag={kind}>
      <span className="sr-only"> · </span>
      {children}
    </span>
  );
}

/**
 * Before and after in one table, for rows that pair one to one: a changed
 * value shows its old value struck through and its new value underlined.
 */
function DiffTable({
  before,
  after,
  pairs,
  changed,
  written,
  keyColumn,
  first,
}: {
  before: RowSample;
  after: RowSample;
  pairs: { before: unknown[]; after: unknown[] }[];
  changed: Set<string>;
  written: string[];
  keyColumn: string;
  first: string[];
}) {
  const columns = ordered(after.columns, first);
  const masked = [...(after.masked ?? []), ...(before.masked ?? before.hidden)];
  const hidden = (column: string) =>
    after.hidden.includes(column) || before.hidden.includes(column);
  return (
    <div className="ar-sample">
      <p className="ar-sample-title">
        <strong>Before → after</strong>
        {after.total > after.rows.length && (
          <span className="muted">
            showing {after.rows.length} of {after.total.toLocaleString('en')}
          </span>
        )}
        {changed.size > 0 && (
          <span className="ar-legend">
            <del>old</del> <ins>new</ins> marks a changed value.
          </span>
        )}
      </p>
      {/* A scrolling region: keyboard users focus it to scroll wide rows. */}
      <div
        className="table-wrap ar-table-wrap"
        role="region"
        tabIndex={0}
        aria-label="Before and after: rows"
      >
        <table className="ar-table">
          <thead>
            <tr>
              {columns.map((column) => (
                <ColumnHead
                  key={column}
                  column={column}
                  written={written.includes(column)}
                  hidden={hidden(column)}
                  masked={masked.includes(column)}
                />
              ))}
            </tr>
          </thead>
          <tbody>
            {pairs.map((pair, row) => (
              <tr key={row}>
                {columns.map((column) => {
                  const index = after.columns.indexOf(column);
                  const old = pair.before[before.columns.indexOf(column)];
                  const value = pair.after[index];
                  if (hidden(column))
                    return <MaskedCell key={column} value={value} />;
                  if (changed.has(`${row}:${index}`))
                    return (
                      <td key={column} className="cell-changed">
                        <span className="sr-only">Changed from </span>
                        <del>
                          <Value value={old} />
                        </del>
                        <span className="ar-arrow" aria-hidden="true">
                          →
                        </span>
                        <span className="sr-only"> to </span>
                        <ins>
                          <Value value={value} />
                        </ins>
                      </td>
                    );
                  const quiet =
                    column !== keyColumn && !written.includes(column);
                  return (
                    <td key={column} data-quiet={quiet || undefined}>
                      <Value value={value} />
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

/** Rows of a preview that cannot be paired, or that are only added or
 * removed. A written or hidden column says so in its header. */
function SampleTable({
  title,
  sample,
  masked,
  written,
  first = [],
  change,
}: {
  title: string;
  sample: RowSample;
  /** Columns known to be protected. Other hidden ones are computed from
   * something that may not be shown, or not known to be protected. */
  masked: string[];
  /** Columns the statement writes. */
  written: string[];
  /** Columns to show first, when the sample has them. */
  first?: string[];
  change?: 'added' | 'removed';
}) {
  const columns = ordered(sample.columns, first);
  return (
    <div className="ar-sample" data-change={change}>
      <p className="ar-sample-title">
        <strong>{title}</strong>
        {sample.total > sample.rows.length && (
          <span className="muted">
            showing {sample.rows.length} of {sample.total.toLocaleString('en')}
          </span>
        )}
      </p>
      {/* A scrolling region: keyboard users focus it to scroll wide rows. */}
      <div
        className="table-wrap ar-table-wrap"
        role="region"
        tabIndex={0}
        aria-label={`${title}: rows`}
      >
        <table className="ar-table">
          <thead>
            <tr>
              {columns.map((column) => (
                <ColumnHead
                  key={column}
                  column={column}
                  written={written.includes(column)}
                  hidden={sample.hidden.includes(column)}
                  masked={masked.includes(column)}
                />
              ))}
            </tr>
          </thead>
          <tbody>
            {sample.rows.map((row, index) => (
              <tr key={index}>
                {columns.map((column) => {
                  const value = row[sample.columns.indexOf(column)];
                  return sample.hidden.includes(column) ? (
                    <MaskedCell key={column} value={value} />
                  ) : (
                    <td
                      key={column}
                      data-written={written.includes(column) || undefined}
                    >
                      <Value value={value} />
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

/** A value the policy hides: shown as the server sent it, marked. */
function MaskedCell({ value }: { value: unknown }) {
  return (
    <td className="ar-masked">
      <span className="ar-masked-value">
        <EyeOff size={12} aria-hidden="true" />
        <Value value={value} />
      </span>
    </td>
  );
}

function Value({ value }: { value: unknown }) {
  return value == null ? (
    <span className="ar-null">NULL</span>
  ) : (
    <CellValue text={cellText(value)} />
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
