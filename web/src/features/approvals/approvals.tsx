import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, Link2, X } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import type { Approval, Cluster, Page } from '../../api/types';
import { params, request } from '../../api/client';
import { useAction, useResource } from '../../lib/query';
import {
  ActorBadge,
  Badge,
  Button,
  Confirm,
  Empty,
  ErrorPanel,
  Field,
  Picker,
  Skeleton,
  TabBar,
  VerdictChip,
  keepFocus,
} from '../../components/ui';
import { useUser } from '../auth/session';
import { ExpiryTime, RelativeTime } from '../../components/ui/time';
import { formatTime, message } from '../../lib/utils';
import { relativeTime } from '../../lib/time';
import { expiryLabel } from '../../lib/sql-diff';
import { useMedia } from '../../lib/media';
import { verdictOfApproval } from '../../lib/verdict';
import {
  awaitsAction,
  boundText,
  endedAt,
  isEffectChanged,
  needsPreview,
  whatHappened,
} from '../../lib/approval-presentation';
import { ChangesSection, usePreview } from './preview';
import { ReceiptSection } from './receipt';
import { ApprovalResult } from './result';
import { ChecksSection, RiskMeter, StatementSection } from './statement';
import { nextStep, timelineOf, type Step } from './decision';

const TABS = ['pending', 'approved', 'mine', 'all'] as const;
const tabLabel = (tab: string) => tab.charAt(0).toUpperCase() + tab.slice(1);

export function ApprovalsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [notes, setNotes] = useState<Record<string, string>>({});
  // Below this width the list and the request are two views, not two panes.
  const narrow = useMedia('(max-width: 1023px)'),
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
  const view = narrow ? (selected ? 'detail' : 'list') : 'split';
  // Back to the list on a narrow screen: focus the request just left, once
  // the list is shown again.
  const returnTo = useRef<string | null>(null);
  const back = () => {
    returnTo.current = selected;
    setSelected(null);
  };
  useEffect(() => {
    if (view !== 'list' || !returnTo.current) return;
    document.getElementById(`row-${returnTo.current}`)?.focus();
    returnTo.current = null;
  }, [view]);
  return (
    <div className="ar-page" data-view={view}>
      <div className="ar-head">
        <div className="ar-title-block">
          <h1>Approvals</h1>
          <p>
            Writes wait here until a second person approves them. You cannot
            approve your own.
          </p>
        </div>
        <div className="ar-filters">
          <input
            aria-label="Search loaded approvals"
            placeholder="Search requests"
            type="search"
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
      </div>
      <TabBar
        className="ar-tabs"
        value={tab}
        onChange={setTab}
        items={TABS.map((value) => ({
          value,
          label: (
            <span>
              {tabLabel(value)}{' '}
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
        <div className="ar-split">
          <div className="ar-list-pane">
            <p className="ar-count" role="status">
              {query.isPending
                ? 'Loading requests…'
                : !query.data
                  ? 'Requests are unavailable.'
                  : search
                    ? `${items.length} of ${loaded.length} match “${search}”`
                    : `${loaded.length} ${loaded.length === 1 ? 'request' : 'requests'}`}
            </p>
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
                description="Writes from the console and from agents wait here for review."
                action={
                  <Link className="button secondary" to="/console">
                    Open console
                  </Link>
                }
              />
            ) : (
              <ul className="ar-list" aria-label="Approval inbox">
                {items.map((approval) => (
                  <li key={approval.id}>
                    <RequestRow
                      approval={approval}
                      cluster={clusterById.get(approval.cluster_id)}
                      selected={selected === approval.id}
                      onSelect={() => setSelected(approval.id)}
                    />
                  </li>
                ))}
              </ul>
            )}
            {query.isFetchNextPageError && (
              <ErrorPanel
                error={query.error}
                retry={() => void query.fetchNextPage()}
              />
            )}
            {query.hasNextPage && (
              <Button
                className="ar-more"
                disabled={query.isFetchingNextPage}
                onClick={() => void query.fetchNextPage()}
              >
                {query.isFetchingNextPage ? 'Loading…' : 'Load more'}
              </Button>
            )}
          </div>
          <section className="ar-detail-pane" aria-label="Query approval">
            {selected ? (
              <ApprovalDetail
                key={selected}
                id={selected}
                narrow={narrow}
                onClose={narrow ? back : () => setSelected(null)}
                note={notes[selected] ?? ''}
                setNote={(note) =>
                  setNotes((notes) => ({ ...notes, [selected]: note }))
                }
              />
            ) : (
              <Empty
                title="Select a request to review"
                description="Choose a request from the list to see what it changes."
              />
            )}
          </section>
        </div>
      </TabBar>
    </div>
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
/** The status of a request in words: for endings that are not a verdict. */
export function ApprovalBadge({ status }: { status: Approval['status'] }) {
  return (
    <Badge variant="status" tone={statusTone[status]}>
      {status}
    </Badge>
  );
}

/** The verdict of a request, or its status when it ended without one. */
function RequestState({
  status,
  size = 'sm',
}: {
  status: Approval['status'];
  size?: 'sm' | 'md';
}) {
  const verdict = verdictOfApproval(status);
  return verdict ? (
    <VerdictChip verdict={verdict} size={size} />
  ) : (
    <ApprovalBadge status={status} />
  );
}

/** Where a request runs. Production is filled and striped: never missed. */
export function EnvMark({ environment }: { environment: string }) {
  return (
    <span className="ar-env" data-environment={environment}>
      {environment.charAt(0).toUpperCase() + environment.slice(1)}
    </span>
  );
}

/** Who asked: an agent with the person it acts for, or the person. */
function Requester({
  approval,
}: {
  approval: Pick<Approval, 'agent' | 'requester'>;
}) {
  if (!approval.agent)
    return <ActorBadge kind="human" name={approval.requester.name} />;
  return (
    <>
      <ActorBadge
        kind="agent"
        name={`${approval.agent.name}${approval.agent.id ? '' : ' (deleted)'}`}
      />
      <span className="ar-for">
        for <span className="ar-person">{approval.requester.name}</span>
      </span>
    </>
  );
}

function RequestRow({
  approval,
  cluster,
  selected,
  onSelect,
}: {
  approval: Approval;
  cluster: Cluster | undefined;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      id={`row-${approval.id}`}
      className="ar-row"
      aria-label="Review"
      aria-describedby={`request-${approval.id}`}
      aria-pressed={selected}
      data-environment={cluster?.environment}
      onClick={onSelect}
    >
      <span className="ar-row-line">
        <RequestState status={approval.status} />
        <strong className="ar-row-reason" id={`request-${approval.id}`}>
          {approval.reason}
        </strong>
      </span>
      <span className="ar-row-line ar-row-who">
        <Requester approval={approval} />
        <span className="ar-row-age">
          <RelativeTime value={approval.created_at} />
        </span>
      </span>
      <span className="ar-row-line ar-row-meta">
        {cluster && <EnvMark environment={cluster.environment} />}
        <span className="ar-row-cluster">{approval.cluster_name}</span>
        <RiskMeter risk={approval.analysis.risk} compact />
        <RequestEnd approval={approval} />
      </span>
      {approval.error && (
        <span className="ar-row-line ar-row-error">{approval.error}</span>
      )}
    </button>
  );
}

/** In a list row: when it expires while it can still run, else how it ended. */
function RequestEnd({ approval }: { approval: Approval }) {
  if (awaitsAction(approval))
    return (
      <span className="ar-row-end">
        {approval.status === 'approved' && 'Approved · '}
        <ExpiryTime value={approval.expires_at} />
      </span>
    );
  if (approval.status === 'executing')
    return (
      <span className="ar-row-end">
        <ApprovalBadge status="executing" />
      </span>
    );
  const ended = endedAt(approval);
  if (!ended) return null;
  // "Ran just now", "Failed 3 min ago": the list refetches, so this stays fresh.
  const when = relativeTime(ended.at, Date.now());
  return (
    <time
      className="ar-row-end"
      dateTime={ended.at}
      title={formatTime(ended.at)}
    >
      {ended.label} {when.charAt(0).toLowerCase() + when.slice(1)}
    </time>
  );
}

/** "asked 10 min ago", in the middle of a sentence. */
function AskedAt({ value }: { value: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 60000);
    return () => clearInterval(timer);
  }, []);
  const when = relativeTime(value, now);
  return (
    <time dateTime={value} title={formatTime(value)}>
      {when.charAt(0).toLowerCase() + when.slice(1)}
    </time>
  );
}

function ExpiryNotice({ expiresAt }: { expiresAt: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <span
      className="approval-expiry"
      role="status"
      title={formatTime(expiresAt)}
    >
      {expiryLabel(expiresAt, now)}
    </span>
  );
}

function ApprovalDetail({
  id,
  narrow,
  onClose,
  note,
  setNote,
}: {
  id: string;
  narrow: boolean;
  onClose: () => void;
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
  const cluster = useResource<Cluster>(
    `/clusters/${approval.data?.cluster_id}`,
    !!approval.data,
  );
  if (approval.isPending)
    return (
      <div className="ar-loading">
        <Skeleton />
      </div>
    );
  if (approval.error)
    return (
      <div className="ar-loading">
        <ErrorPanel error={approval.error} />
      </div>
    );
  return (
    <Decision
      data={approval.data}
      cluster={cluster.data}
      now={now}
      userId={user?.id}
      narrow={narrow}
      onClose={onClose}
      note={note}
      setNote={setNote}
      refetch={async () => (await approval.refetch()).data}
    />
  );
}

/** One request as a decision: the state and next action, who asked and
 * why, what changes, the statement and its checks, what happened, and the
 * actions in a bar that stays in view. */
function Decision({
  data,
  cluster,
  now,
  userId,
  narrow,
  onClose,
  note,
  setNote,
  refetch,
}: {
  data: Approval;
  cluster: Cluster | undefined;
  now: number;
  userId: string | undefined;
  narrow: boolean;
  onClose: () => void;
  note: string;
  setNote: (note: string) => void;
  refetch: () => Promise<Approval | undefined>;
}) {
  const id = data.id;
  const [confirming, setConfirming] = useState<
    'execute' | 'run' | 'withdraw' | null
  >(null);
  const action = useAction<Approval>('Approval updated');
  const cache = useQueryClient();
  const preview = usePreview(data);
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
    const before = data.status;
    action.mutate(
      { path: `/approvals/${id}/${target}`, body },
      {
        onSuccess: () => setConfirming(null),
        onError: async (error) => {
          setConfirming(null);
          // Show what is true now, in the detail and in the list.
          const fresh = await refetch();
          void cache.invalidateQueries({ queryKey: ['api', 'approvals'] });
          setFailure({
            // Say what happened meanwhile, not only that it failed.
            text: [
              message(error),
              fresh && fresh.status !== before ? whatHappened(fresh) : null,
            ]
              .filter(Boolean)
              .join(' '),
            status: fresh?.status ?? 'pending',
          });
        },
        onSettled: () => {
          lock.current = false;
          keepFocus(control);
        },
      },
    );
  };
  const live = Date.parse(data.expires_at) > now,
    mine = data.requester.id === userId,
    admin = cluster?.my_access === 'admin';
  // Unknown until the cluster has loaded: say nothing about permission yet.
  const adminKnown = cluster ? admin : undefined;
  const canReview = !mine && admin && data.status === 'pending' && live;
  const canExecute =
    data.status === 'approved' &&
    (mine || data.reviewer?.id === userId) &&
    live;
  const canWithdraw =
    mine && (data.status === 'pending' || data.status === 'approved') && live;
  // Only the requester and cluster admins can open a request at all.
  const canPreview = (mine || admin) && live;
  const previewFirst = needsPreview(data);
  // A deleted agent's request can only be rejected, or left to expire.
  const agentDeleted = !!data.agent && data.agent.id === null;
  const offerPreview =
    canPreview && previewFirst && data.status === 'pending' && !agentDeleted;
  const step = nextStep(data, {
    live,
    mine,
    admin: adminKnown,
    canExecute,
  });
  const ended = endedAt(data);
  // A write that failed is explained once, in the timeline.
  const shownFailure =
    failure?.status === data.status && data.status !== 'failed'
      ? failure
      : null;
  const hasBar = canReview || canExecute || canWithdraw || offerPreview;
  const busy = action.isPending || preview.busy;
  return (
    <div
      className="ar-decision"
      data-focus-return
      data-verdict={step.verdict ?? 'none'}
      data-environment={cluster?.environment}
    >
      <header className="ar-header">
        <div className="ar-header-top">
          {narrow && (
            <Button variant="ghost" size="small" onClick={onClose}>
              <ArrowLeft size={15} aria-hidden="true" /> All requests
            </Button>
          )}
          <RequestState status={data.status} size="md" />
          <RiskMeter risk={data.analysis.risk} />
          <span className="ar-header-tools">
            <Link
              className="button ghost small"
              to={`/approvals?id=${id}`}
              aria-label="Permalink to this approval"
            >
              <Link2 size={14} aria-hidden="true" /> Permalink
            </Link>
            {!narrow && (
              <Button aria-label="Close approval" onClick={onClose}>
                <X size={16} />
              </Button>
            )}
          </span>
        </div>
        {/* Focus lands here when the control that opened a dialog is gone. */}
        <h2 className="ar-title" tabIndex={-1} data-focus-target>
          {step.title}
        </h2>
        <p className="ar-next">{step.detail}</p>
      </header>
      <div className="ar-body approval-scroll">
        <section className="ar-who" aria-label="Who asked">
          <p className="ar-who-line">
            <span className="ar-label">Asked by</span>
            <Requester approval={data} />
            <span className="ar-email">{data.requester.email}</span>
          </p>
          <p className="ar-where">
            {cluster && <EnvMark environment={cluster.environment} />}
            <strong className="ar-cluster">{data.cluster_name}</strong>
            {cluster && (
              <span className="muted">
                {cluster.engine === 'mysql' ? 'MySQL' : 'PostgreSQL'}
              </span>
            )}
            <span className="ar-sep" aria-hidden="true" />
            <span className="muted">
              Asked <AskedAt value={data.created_at} />
            </span>
            <span className="ar-sep" aria-hidden="true" />
            {awaitsAction(data) ? (
              <ExpiryNotice expiresAt={data.expires_at} />
            ) : (
              ended && (
                <span className="approval-expiry">
                  {ended.label} {formatTime(ended.at)}
                </span>
              )
            )}
          </p>
          <blockquote className="ar-reason">
            <p>{data.reason}</p>
          </blockquote>
        </section>
        <ChangesSection approval={data} notice={preview.notice} />
        <div className="ar-pair">
          <StatementSection
            sql={data.sql}
            rewritten={data.analysis.rewritten_sql}
          />
          <ChecksSection analysis={data.analysis} clusterId={data.cluster_id} />
        </div>
        <Timeline approval={data} live={live} />
      </div>
      {shownFailure && (
        <div
          className="callout danger ar-failure"
          role="alert"
          ref={failureRef}
        >
          {shownFailure.text}
        </div>
      )}
      {hasBar && (
        <footer className="ar-bar approval-actions" aria-label="Decision">
          {canReview && (
            <div className="ar-note-field">
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
                  rows={1}
                />
              </Field>
            </div>
          )}
          <div className="ar-buttons">
            {canReview && previewFirst && (
              <p className="approval-blocked" id={`approve-blocked-${id}`}>
                {agentDeleted
                  ? 'The agent that asked was deleted: reject it, or let it expire.'
                  : 'Preview it before you approve it. Nothing has run yet.'}
              </p>
            )}
            <div className="ar-button-row">
              {canWithdraw && (
                <Button
                  disabled={busy}
                  onClick={() => setConfirming('withdraw')}
                >
                  Withdraw request
                </Button>
              )}
              {canReview && (
                <>
                  <Button
                    variant="danger"
                    disabled={busy || !note.trim()}
                    onClick={() => act('reject', { note })}
                  >
                    {action.isPending ? 'Saving…' : 'Reject'}
                  </Button>
                  <Button
                    disabled={busy || previewFirst}
                    aria-describedby={
                      previewFirst ? `approve-blocked-${id}` : undefined
                    }
                    onClick={() => setConfirming('run')}
                  >
                    Approve and run
                  </Button>
                  <Button
                    variant={previewFirst ? 'secondary' : 'primary'}
                    disabled={busy || previewFirst}
                    aria-describedby={
                      previewFirst ? `approve-blocked-${id}` : undefined
                    }
                    onClick={() => act('approve', { note })}
                  >
                    {action.isPending ? 'Saving…' : 'Approve'}
                  </Button>
                </>
              )}
              {offerPreview && (
                <Button variant="primary" disabled={busy} onClick={preview.ask}>
                  {preview.busy ? 'Previewing…' : 'Preview'}
                </Button>
              )}
              {canExecute && (
                <Button
                  variant="primary"
                  disabled={busy}
                  onClick={() => setConfirming('execute')}
                >
                  Run approved write
                </Button>
              )}
            </div>
          </div>
        </footer>
      )}
      {preview.dialog}
      <Confirm
        open={confirming === 'execute'}
        onOpenChange={(open) => setConfirming(open ? 'execute' : null)}
        title="Run this approved write?"
        description={`This runs the approved SQL on ${data.cluster_name}. The server checks the current policy and access again.`}
        busy={action.isPending}
        busyLabel="Running…"
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

/** What happened to the request, in order, with the result and the receipt
 * where they belong. */
function Timeline({ approval, live }: { approval: Approval; live: boolean }) {
  const steps = timelineOf(approval, live);
  return (
    <section className="ar-timeline" aria-label="What happened">
      <h3 className="ar-section-title">What happened</h3>
      <ol>
        {steps.map((step) => (
          <li key={step.key} data-state={step.state}>
            <span className="ar-dot" aria-hidden="true" />
            <div className="ar-step">
              <p className="ar-step-head">
                <strong>{step.label}</strong>
                {step.state === 'current' && (
                  <span className="sr-only"> (now)</span>
                )}
                {step.at && (
                  <span className="muted">
                    <RelativeTime value={step.at} />
                  </span>
                )}
                {step.by && <span className="ar-step-by">{step.by}</span>}
              </p>
              {step.text && <p className="ar-step-text">{step.text}</p>}
              {step.note && (
                <blockquote className="ar-step-note">
                  <p>{step.note}</p>
                </blockquote>
              )}
              <StepDetail step={step} approval={approval} />
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function StepDetail({ step, approval }: { step: Step; approval: Approval }) {
  if (step.key === 'receipt' && approval.status === 'executed')
    return <ReceiptSection approval={approval} />;
  if (step.key !== 'run') return null;
  if (approval.result) return <ApprovalResult result={approval.result} />;
  if (!approval.error) return null;
  if (isEffectChanged(approval))
    return (
      <div className="callout danger" role="alert">
        <div>
          <strong>The data changed after the approval.</strong>
          <p>{approval.error}</p>
          <p>
            Nothing was written, and this request cannot run again. To make the
            change, ask again:{' '}
            {approval.agent
              ? `the agent ${approval.agent.name} can propose the write again,`
              : 'make a new request,'}{' '}
            and review its new preview.
          </p>
        </div>
      </div>
    );
  if (approval.error_code === 'outcome_unknown')
    return (
      <div className="callout danger" role="alert">
        <div>
          <strong>Nobody knows whether the write ran.</strong>
          <p>{approval.error}</p>
          <p>
            The server that ran it was lost before it could record the result.
            This request cannot run again. Check the data on the database before
            you ask again
            {approval.agent
              ? ` or let the agent ${approval.agent.name} ask`
              : ''}
            : the change may already be there.
          </p>
        </div>
      </div>
    );
  return (
    <div className="callout danger" role="alert">
      {approval.error}
    </div>
  );
}
