import { useEffect, useMemo, useRef, useState } from 'react';
import { Bot, X } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { expiryLabel, sqlDiff, guardedSqlChanged } from '../../lib/sql-diff';
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import type { Approval, Cluster, Page, Policy } from '../../api/types';
import { params, request } from '../../api/client';
import { useAction, useResource } from '../../lib/query';
import {
  Badge,
  Button,
  Empty,
  EnvBadge,
  ErrorPanel,
  Field,
  Modal,
  Skeleton,
  TabBar,
  Confirm,
  Picker,
  keepFocus,
} from '../../components/ui';
import { useUser } from '../auth/session';
import { RelativeTime } from '../../components/ui/time';
import { formatTime, message } from '../../lib/utils';
import { relativeTime } from '../../lib/time';

import { SafetyPanel } from '../console/safety';
import { ApprovalResult } from './result';
import { useMedia } from '../../lib/media';
import { ExpiryTime } from '../../components/ui/time';
import {
  agentLabel,
  awaitsAction,
  boundText,
  endedAt,
  isEffectChanged,
  needsPreview,
  whatHappened,
} from '../../lib/approval-presentation';
import { PreviewSection } from './preview';
import { ReceiptSection } from './receipt';
export function ApprovalsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [notes, setNotes] = useState<Record<string, string>>({});
  const phone = useMedia('(max-width: 600px)'),
    user = useUser();
  const counts = useResource<Page<Approval>>('/approvals?limit=50');
  const tab = searchParams.get('tab') ?? 'pending',
    selected = searchParams.get('id');
  const clusterFilter = searchParams.get('cluster_id') ?? 'all',
    search = searchParams.get('q') ?? '';
  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(searchParams);
    if (!value || (value === 'all' && key !== 'tab')) next.delete(key);
    else next.set(key, value);
    setSearchParams(next, { replace: true });
  };
  const setTab = (value: string) => update('tab', value),
    setSelected = (value: string | null) => update('id', value);
  const clusters = useResource<{ items: Cluster[] }>('/clusters');
  const filter = {
    cluster_id: clusterFilter === 'all' ? undefined : clusterFilter,
    status: tab === 'pending' || tab === 'approved' ? tab : undefined,
    mine: tab === 'mine' ? 'true' : undefined,
  };
  const query = useInfiniteQuery({
    queryKey: ['api', 'approvals', filter],
    queryFn: ({ pageParam, signal }) =>
      request<Page<Approval>>(
        `/approvals${params({ ...filter, limit: 50, cursor: pageParam })}`,
        { signal },
      ),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 5000,
  });
  const loaded = useMemo(
    () => query.data?.pages.flatMap((page) => page.items) ?? [],
    [query.data],
  );
  const items = useMemo(() => {
    const needle = search.toLowerCase();
    return loaded.filter((item) =>
      `${item.reason} ${item.sql} ${item.requester.name} ${item.agent?.name ?? ''}`
        .toLowerCase()
        .includes(needle),
    );
  }, [loaded, search]);
  const clusterById = useMemo(
    () => new Map(clusters.data?.items.map((c) => [c.id, c]) ?? []),
    [clusters.data],
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Approvals</h1>
          <p>Requests for a second person's review.</p>
        </div>
      </div>
      <div className="filterbar">
        <input
          aria-label="Search loaded approvals"
          placeholder="Search loaded requests…"
          value={search}
          onChange={(event) => update('q', event.target.value)}
        />
        <Picker
          label="Approval cluster"
          value={clusterFilter}
          onChange={(value) => update('cluster_id', value)}
          options={[
            { value: 'all', label: 'All clusters' },
            ...(clusters.data?.items.map((cluster) => ({
              value: cluster.id,
              label: cluster.name,
            })) ?? []),
          ]}
        />
      </div>
      <p className="loaded-note" role="status">
        {query.isPending ? (
          'Loading requests…'
        ) : !query.data ? (
          'Request count unavailable.'
        ) : (
          <>
            {items.length} matching of {loaded.length} loaded requests
            {query.hasNextPage ? ' · More available' : ''}.
            {counts.data &&
              ` Filter counts cover ${counts.data.items.length} loaded accessible requests.`}
          </>
        )}{' '}
        You cannot approve your own request.
        {counts.error ? ' Filter counts are unavailable.' : ''}
      </p>
      <TabBar
        value={tab}
        onChange={setTab}
        items={['pending', 'approved', 'mine', 'all'].map((value) => ({
          value,
          label: (
            <span>
              {value[0]?.toUpperCase() + value.slice(1)}{' '}
              <span className="muted">
                {counts.data?.items.filter(
                  (item) =>
                    value === 'all' ||
                    (value === 'mine'
                      ? item.requester.id === user?.id
                      : item.status === value),
                ).length ?? '—'}
                {counts.data?.next_cursor ? '+' : ''}
              </span>
            </span>
          ),
        }))}
      >
        <div className="approval-inbox-layout">
          <div>
            {query.isPending ? (
              <Skeleton />
            ) : query.error ? (
              <ErrorPanel
                error={query.error}
                retry={() => {
                  void query.refetch();
                  if (counts.isError) void counts.refetch();
                }}
              />
            ) : items.length === 0 ? (
              <Empty
                title={
                  tab === 'pending'
                    ? 'Nothing waiting for review'
                    : 'No matching requests'
                }
                description="Write queries can be submitted for approval from the console."
                action={
                  <Link className="button secondary" to="/console">
                    Open console
                  </Link>
                }
              />
            ) : (
              <ul className="approval-inbox-list" aria-label="Approval inbox">
                {items.map((approval) => {
                  const cluster = clusterById.get(approval.cluster_id);
                  return (
                    <li key={approval.id}>
                      <button
                        type="button"
                        className="approval-inbox-item"
                        aria-label="Review"
                        aria-describedby={`request-${approval.id}`}
                        aria-pressed={selected === approval.id}
                        onClick={() => setSelected(approval.id)}
                      >
                        <span className="requester-avatar" aria-hidden="true">
                          {approval.agent ? (
                            <Bot size={16} strokeWidth={1.5} />
                          ) : (
                            approval.requester.name
                              .split(' ')
                              .map((part) => part[0])
                              .join('')
                              .slice(0, 2)
                          )}
                        </span>
                        <span>
                          <strong id={`request-${approval.id}`}>
                            {approval.reason}
                          </strong>
                          <small>
                            {agentLabel(approval) ?? approval.requester.name} ·{' '}
                            {approval.cluster_name}
                            {cluster && (
                              <>
                                {' '}
                                · <EnvBadge environment={cluster.environment} />
                              </>
                            )}
                          </small>
                          <small>
                            <RelativeTime value={approval.created_at} />
                            <RequestEnd approval={approval} />
                          </small>
                          <small>
                            <ApprovalBadge status={approval.status} />
                            {approval.error && <span>{approval.error}</span>}
                          </small>
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
          <section
            className="approval-inbox-detail"
            aria-label="Query approval"
          >
            <div className="section-heading">
              <h2>Query approval</h2>
              {selected && (
                <Button
                  variant="ghost"
                  aria-label="Close approval"
                  onClick={() => setSelected(null)}
                >
                  <X size={16} />
                </Button>
              )}
            </div>
            {!phone && selected ? (
              <ApprovalDetail
                key={selected}
                id={selected}
                note={notes[selected] ?? ''}
                setNote={(note) =>
                  setNotes((notes) => ({ ...notes, [selected]: note }))
                }
              />
            ) : (
              <Empty
                title="Select a request to review"
                description="Choose a request from the inbox."
              />
            )}
          </section>
        </div>
        {query.isFetchNextPageError && (
          <ErrorPanel
            error={query.error}
            retry={() => void query.fetchNextPage()}
          />
        )}
        {query.hasNextPage && (
          <Button
            disabled={query.isFetchingNextPage}
            onClick={() => void query.fetchNextPage()}
          >
            {query.isFetchingNextPage ? 'Loading…' : 'Load more'}
          </Button>
        )}
      </TabBar>
      <Modal
        open={phone && !!selected}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
        drawer
        className="approval-sheet"
        title="Query approval"
        description="Review the SQL, target environment, and reason before deciding."
        wide
      >
        {phone && selected && (
          <ApprovalDetail
            key={selected}
            id={selected}
            note={notes[selected] ?? ''}
            setNote={(note) =>
              setNotes((notes) => ({ ...notes, [selected]: note }))
            }
          />
        )}
      </Modal>
    </>
  );
}
const statusTone: Record<Approval['status'], string> = {
  pending: 'warning',
  approved: 'success',
  executed: 'success',
  rejected: 'danger',
  failed: 'danger',
  executing: 'info',
  // Neither is a risk: the request simply will not run.
  withdrawn: 'neutral',
  expired: 'neutral',
};
export function ApprovalBadge({ status }: { status: Approval['status'] }) {
  return (
    <Badge variant="status" tone={statusTone[status]}>
      {status}
    </Badge>
  );
}
/** In a list row: when it expires while it can still run, else how it ended. */
function RequestEnd({ approval }: { approval: Approval }) {
  if (awaitsAction(approval))
    return (
      <>
        {' · '}
        <ExpiryTime value={approval.expires_at} />
      </>
    );
  const ended = endedAt(approval);
  if (!ended) return null;
  // "Ran just now", "Failed 3 min ago": the list refetches, so this stays fresh.
  const when = relativeTime(ended.at, Date.now());
  return (
    <>
      {' · '}
      <time dateTime={ended.at} title={formatTime(ended.at)}>
        {ended.label} {when.charAt(0).toLowerCase() + when.slice(1)}
      </time>
    </>
  );
}
function ExpiryNotice({ expiresAt }: { expiresAt: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <div className="approval-expiry" role="status">
      {expiryLabel(expiresAt, now)} · {formatTime(expiresAt)}
    </div>
  );
}
function ApprovalDetail({
  id,
  note,
  setNote,
}: {
  id: string;
  note: string;
  setNote: (note: string) => void;
}) {
  const path = `/approvals/${id}`;
  const approval = useQuery({
    queryKey: ['api', path],
    queryFn: ({ signal }) => request<Approval>(path, { signal }),
    refetchOnMount: 'always',
    refetchInterval: (query) =>
      query.state.data?.status === 'executing' ? 2000 : false,
  });
  const user = useUser();
  // Re-render once at the moment of expiry so review/execute controls are
  // withdrawn on time; the visible countdown lives in <ExpiryNotice />.
  const [now, setNow] = useState(() => Date.now());
  const expiresAt = approval.data?.expires_at;
  useEffect(() => {
    if (!expiresAt) return;
    const delay = Date.parse(expiresAt) - Date.now();
    setNow(Date.now());
    if (!Number.isFinite(delay) || delay <= 0 || delay > 2_147_483_000) return;
    const timer = setTimeout(() => setNow(Date.now()), delay + 20);
    return () => clearTimeout(timer);
  }, [expiresAt]);
  const [confirming, setConfirming] = useState<
    'execute' | 'run' | 'withdraw' | null
  >(null);
  const action = useAction<Approval>('Approval updated');
  const cache = useQueryClient();
  // One action at a time: a second click cannot send a second request
  // before the screen has caught up with the first.
  const lock = useRef(false);
  // An action that failed says why, here, until the request changes again.
  const [failure, setFailure] = useState<{
    text: string;
    status: Approval['status'];
  } | null>(null);
  const failureRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (failure) failureRef.current?.scrollIntoView?.({ block: 'nearest' });
  }, [failure]);
  const act = (target: string, body?: unknown) => {
    if (lock.current) return;
    lock.current = true;
    setFailure(null);
    // The control that started it; focus stays near it as the screen changes.
    const control = document.activeElement;
    const before = approval.data?.status;
    action.mutate(
      { path: `/approvals/${id}/${target}`, body },
      {
        onSuccess: () => setConfirming(null),
        onError: async (error) => {
          setConfirming(null);
          // Show what is true now, in the detail and in the list.
          const fresh = await approval.refetch();
          void cache.invalidateQueries({ queryKey: ['api', 'approvals'] });
          setFailure({
            // Say what happened meanwhile, not only that it failed.
            text: [
              message(error),
              fresh.data && fresh.data.status !== before
                ? whatHappened(fresh.data)
                : null,
            ]
              .filter(Boolean)
              .join(' '),
            status: fresh.data?.status ?? 'pending',
          });
        },
        onSettled: () => {
          lock.current = false;
          keepFocus(control);
        },
      },
    );
  };
  const cluster = useResource<Cluster>(
    `/clusters/${approval.data?.cluster_id}`,
    !!approval.data,
  );
  const policy = useResource<Policy>(
    `/clusters/${approval.data?.cluster_id}/policy`,
    !!approval.data,
  );
  if (approval.isPending) return <Skeleton />;
  if (approval.error) return <ErrorPanel error={approval.error} />;
  const data = approval.data;
  const live = Date.parse(data.expires_at) > now,
    mine = data.requester.id === user?.id,
    admin = cluster.data?.my_access === 'admin';
  const canReview = !mine && admin && data.status === 'pending' && live;
  const canExecute =
    data.status === 'approved' &&
    (mine || data.reviewer?.id === user?.id) &&
    live;
  const canWithdraw =
    mine && (data.status === 'pending' || data.status === 'approved') && live;
  // Only the requester and cluster admins can open a request at all.
  const canPreview = (mine || admin) && live;
  const previewFirst = needsPreview(data);
  // A deleted agent's request can only be rejected, or left to expire.
  const agentDeleted = !!data.agent && data.agent.id === null;
  const agent = agentLabel(data);
  const ended = endedAt(data);
  // A write that failed is explained once, by the callout above.
  const shownFailure =
    failure?.status === data.status && data.status !== 'failed'
      ? failure
      : null;
  return (
    <div className="approval-detail" data-focus-return>
      <div className="approval-scroll">
        <div className="section-toolbar">
          {/* Focus lands here when the control that opened a dialog is gone. */}
          <strong tabIndex={-1} data-focus-target>
            {data.cluster_name}
          </strong>
          <div className="inline">
            {cluster.data && (
              <EnvBadge environment={cluster.data.environment} />
            )}
            <ApprovalBadge status={data.status} />
            <Link
              className="button ghost small"
              to={`/approvals?id=${id}`}
              aria-label="Permalink to this approval"
            >
              Permalink
            </Link>
          </div>
        </div>
        <div className="approval-reason">
          <strong>{data.requester.name}</strong>
          <span className="muted">{data.requester.email}</span>
          {agent && (
            <span className="approval-agent">
              <Bot size={16} strokeWidth={1.5} aria-hidden="true" />
              {agent}
            </span>
          )}
          <p>{data.reason}</p>
        </div>
        {awaitsAction(data) ? (
          <ExpiryNotice expiresAt={data.expires_at} />
        ) : (
          ended && (
            <div className="approval-expiry">
              {ended.label} {formatTime(ended.at)}
            </div>
          )
        )}
        {data.error &&
          (isEffectChanged(data) ? (
            <div className="callout danger" role="alert">
              <div>
                <strong>The data changed after the approval.</strong>
                <p>{data.error}</p>
                <p>
                  Nothing was written, and this request cannot run again. To
                  make the change, ask again:{' '}
                  {data.agent
                    ? `the agent ${data.agent.name} can propose the write again,`
                    : 'make a new request,'}{' '}
                  and review its new preview.
                </p>
              </div>
            </div>
          ) : data.error_code === 'outcome_unknown' ? (
            <div className="callout danger" role="alert">
              <div>
                <strong>Nobody knows whether the write ran.</strong>
                <p>{data.error}</p>
                <p>
                  The server that ran it was lost before it could record the
                  result. This request cannot run again. Check the data on the
                  database before you ask again
                  {data.agent ? ` or let the agent ${data.agent.name} ask` : ''}
                  : the change may already be there.
                </p>
              </div>
            </div>
          ) : (
            <div className="callout danger" role="alert">
              {data.error}
            </div>
          ))}
        <pre
          className="sql-preview-block"
          tabIndex={0}
          aria-label="SQL preview"
        >
          {data.sql}
        </pre>
        {data.analysis.rewritten_sql &&
          guardedSqlChanged(data.sql, data.analysis.rewritten_sql) && (
            <details className="sql-comparison" open>
              <summary>Submitted SQL compared with guarded SQL</summary>
              <p className="muted">− removed · + added by analysis</p>
              <pre tabIndex={0}>
                {sqlDiff(data.sql, data.analysis.rewritten_sql).map(
                  (line, index) => (
                    <span className={`diff-line ${line.kind}`} key={index}>
                      {line.kind === 'added'
                        ? '+ '
                        : line.kind === 'removed'
                          ? '− '
                          : '  '}
                      {line.text}
                      {'\n'}
                    </span>
                  ),
                )}
              </pre>
            </details>
          )}
        <PreviewSection approval={data} canPreview={canPreview} />
        <SafetyPanel
          analysis={data.analysis}
          maxRows={policy.data?.max_rows}
          clusterId={data.cluster_id}
        />
        {mine && data.status === 'pending' && (
          <div className="callout warning">
            You requested this query. Another cluster administrator must review
            it.
          </div>
        )}
        {data.result && <ApprovalResult result={data.result} />}
        {data.status === 'executed' && <ReceiptSection approval={data} />}
        <ol className="timeline">
          <li>
            <strong>Created</strong>
            <span>
              <RelativeTime value={data.created_at} /> · {data.requester.name}
              {data.agent && ` (agent ${data.agent.name})`}
            </span>
          </li>
          <li className={data.reviewed_at ? '' : 'future'}>
            <strong>
              {data.status === 'rejected' ? 'Rejected' : 'Reviewed'}
            </strong>
            <span>
              {data.reviewed_at ? (
                <>
                  <RelativeTime value={data.reviewed_at} /> ·{' '}
                  {data.reviewer?.name}
                </>
              ) : data.status === 'withdrawn' || data.status === 'expired' ? (
                'Not reviewed'
              ) : (
                'Waiting for review'
              )}
            </span>
            {data.review_note && <p>{data.review_note}</p>}
          </li>
          <li className={data.executed_at ? '' : 'future'}>
            <strong>
              {data.status === 'failed'
                ? 'Failed'
                : data.status === 'executing'
                  ? 'Executing'
                  : data.status === 'withdrawn'
                    ? 'Withdrawn'
                    : data.status === 'expired'
                      ? 'Expired'
                      : data.executed_at
                        ? 'Executed'
                        : data.status === 'rejected'
                          ? 'Not executed'
                          : 'Awaiting execution'}
            </strong>
            <span>
              {data.executed_at ? (
                <RelativeTime value={data.executed_at} />
              ) : data.status === 'withdrawn' ? (
                'The requester withdrew it. It will not run.'
              ) : data.status === 'expired' ? (
                `Expired ${formatTime(data.expires_at)}. It will not run.`
              ) : data.status === 'executing' ? (
                'Running now'
              ) : data.status === 'rejected' ? (
                'It will not run.'
              ) : data.status === 'approved' ? (
                'Approved. It has not run yet.'
              ) : (
                'It runs only after a reviewer approves it.'
              )}
            </span>
            {!data.executed_at &&
              (data.status === 'pending' || data.status === 'approved') && (
                <p>Request valid until {formatTime(data.expires_at)}</p>
              )}
          </li>
        </ol>
      </div>
      {shownFailure && (
        <div
          className="callout danger approval-failure"
          role="alert"
          ref={failureRef}
        >
          {shownFailure.text}
        </div>
      )}
      {(canReview || canExecute || canWithdraw) && (
        <div className="approval-actions">
          {canReview && (
            <>
              <Field
                label="Review note"
                hint={`Required when rejecting a request. ${
                  data.agent
                    ? `The requester and the agent ${data.agent.name} can read this note.`
                    : 'The requester can read this note.'
                }`}
              >
                <textarea
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  rows={2}
                />
              </Field>
              {previewFirst && (
                <p className="approval-blocked" id={`approve-blocked-${id}`}>
                  {agentDeleted
                    ? 'The agent that asked was deleted: reject it, or let it expire.'
                    : 'Preview it before you approve it. Nothing has run yet.'}
                </p>
              )}
              <div className="dialog-actions">
                <Button
                  variant="danger"
                  disabled={action.isPending || !note.trim()}
                  onClick={() => act('reject', { note })}
                >
                  {action.isPending ? 'Saving…' : 'Reject'}
                </Button>
                <Button
                  disabled={action.isPending || previewFirst}
                  aria-describedby={
                    previewFirst ? `approve-blocked-${id}` : undefined
                  }
                  onClick={() => setConfirming('run')}
                >
                  Approve and run
                </Button>
                <Button
                  variant={previewFirst ? 'secondary' : 'primary'}
                  disabled={action.isPending || previewFirst}
                  aria-describedby={
                    previewFirst ? `approve-blocked-${id}` : undefined
                  }
                  onClick={() => act('approve', { note })}
                >
                  {action.isPending ? 'Saving…' : 'Approve'}
                </Button>
              </div>
            </>
          )}
          {(canExecute || canWithdraw) && (
            <div className="dialog-actions">
              {canWithdraw && (
                <Button
                  disabled={action.isPending}
                  onClick={() => setConfirming('withdraw')}
                >
                  Withdraw request
                </Button>
              )}
              {canExecute && (
                <Button
                  variant="primary"
                  disabled={action.isPending}
                  onClick={() => setConfirming('execute')}
                >
                  Execute approved query
                </Button>
              )}
            </div>
          )}
        </div>
      )}
      <Confirm
        open={confirming === 'execute'}
        onOpenChange={(open) => setConfirming(open ? 'execute' : null)}
        title="Execute this approved query?"
        description={`This will apply the approved SQL on ${data.cluster_name}. Current policy and access are checked again by the server.`}
        busy={action.isPending}
        onConfirm={() => act('execute')}
      />
      <Confirm
        open={confirming === 'run'}
        onOpenChange={(open) => setConfirming(open ? 'run' : null)}
        title="Approve and run this write?"
        description={`This approves the request and runs it on ${data.cluster_name} at once. ${boundText(data.preview?.bound_to, data.status)}`}
        busy={action.isPending}
        busyLabel="Running…"
        onConfirm={() => act('approve', { note, run: true })}
      />
      <Confirm
        open={confirming === 'withdraw'}
        onOpenChange={(open) => setConfirming(open ? 'withdraw' : null)}
        title="Withdraw this request?"
        description={`Nobody can approve or run it after this${
          data.agent
            ? `, and the agent ${data.agent.name} sees it as withdrawn`
            : ''
        }. This cannot be undone.`}
        busy={action.isPending}
        busyLabel="Withdrawing…"
        onConfirm={() => act('withdraw')}
      />
    </div>
  );
}
