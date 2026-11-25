import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import type {
  Agent,
  Approval,
  Cluster,
  HistoryEntry,
  Page,
} from '../../api/types';
import { useResource } from '../../lib/query';
import { useUser } from '../auth/session';
import {
  EnvBadge,
  ErrorPanel,
  RiskMeter,
  SegmentedControl,
  Skeleton,
} from '../../components/ui';
import { ActorBadge, VerdictChip } from '../../components/ui/verdict';
import { RelativeTime, ExpiryTime } from '../../components/ui/time';
import { verdictOfHistory } from '../../lib/verdict';
import { RequestState } from '../approvals/request-state';
import { statementSummary } from '../../lib/activity';
import {
  actorOfHistory,
  rankReviews,
  reviewable,
  runStatusText,
} from './model';

/** How many reviews the overview lists before it points to Approvals. */
export const REVIEW_CAP = 5;

/** Ticks every 30s so expired approvals drop off without waiting for a refetch. */
function useMinuteClock() {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

function Requester({ approval }: { approval: Approval }) {
  return approval.agent ? (
    <span className="ov-who">
      <ActorBadge
        kind="agent"
        name={`${approval.agent.name}${approval.agent.id ? '' : ' (deleted)'}`}
      />
      <span className="ov-owner">for {approval.requester.name}</span>
    </span>
  ) : (
    <ActorBadge kind="human" name={approval.requester.name} />
  );
}

function ReviewRow({
  approval,
  cluster,
  mine,
}: {
  approval: Approval;
  cluster: Cluster | undefined;
  mine: boolean;
}) {
  const id = `ov-review-${approval.id}`;
  // Risk is the meter's to show; the row has no coloured edge, so the
  // chip is the only verdict on it. A request approved but not run yet,
  // or running, shows its status, never Held.
  return (
    <li className="ov-review">
      <div className="ov-review-who">
        <RequestState status={approval.status} />
        <Requester approval={approval} />
        <span className="ov-cluster">
          {approval.cluster_name}
          {cluster && <EnvBadge environment={cluster.environment} />}
        </span>
      </div>
      <p className="ov-review-what" id={id}>
        {approval.reason}
      </p>
      <span className="ov-review-risk">
        <RiskMeter risk={approval.analysis.risk} />
      </span>
      <span className="ov-review-expiry">
        <ExpiryTime value={approval.expires_at} />
      </span>
      <Link
        className={`button ${mine ? 'secondary' : 'primary'} ov-review-go`}
        to={`/approvals?id=${approval.id}&tab=all`}
        aria-describedby={id}
      >
        {mine ? 'Open' : 'Review'}
      </Link>
    </li>
  );
}

/** Actionable work comes from scoped approval and cluster APIs, never
 * fabricated totals. Reviews first, ranked by risk and expiry, then the
 * caller's own requests that still wait. */
export function NeedsYou() {
  const user = useUser();
  const mine = useResource<Page<Approval>>(
      '/approvals?mine=true&status=pending&limit=5',
    ),
    inbox = useResource<Page<Approval>>('/approvals?status=pending&limit=50'),
    clusters = useResource<{ items: Cluster[] }>('/clusters');
  const now = useMinuteClock();
  const clusterById = useMemo(
    () => new Map(clusters.data?.items.map((c) => [c.id, c]) ?? []),
    [clusters.data],
  );
  const waiting = useMemo(() => {
    const adminClusters = new Set(
      clusters.data?.items
        .filter((cluster) => cluster.my_access === 'admin')
        .map((cluster) => cluster.id),
    );
    return rankReviews(
      reviewable(inbox.data?.items ?? [], {
        userId: user?.id,
        adminClusters,
        now,
      }),
    );
  }, [inbox.data, clusters.data, user?.id, now]);
  const pending = useMemo(
    () =>
      mine.data?.items.filter(
        (approval) => Date.parse(approval.expires_at) > now,
      ) ?? [],
    [mine.data, now],
  );
  const error = mine.error ?? inbox.error ?? clusters.error;
  const more = !!inbox.data?.next_cursor;
  const shown = waiting.slice(0, REVIEW_CAP);
  return (
    <section className="ov-needs" aria-labelledby="ov-needs-title">
      <div className="ov-section-head">
        <h2 id="ov-needs-title">Needs you</h2>
        {!!waiting.length && (
          <span className="ov-count">
            {waiting.length}
            {more ? '+' : ''} to review
          </span>
        )}
      </div>
      {mine.isPending || inbox.isPending || clusters.isPending ? (
        <Skeleton />
      ) : error ? (
        <ErrorPanel
          error={error}
          retry={() => {
            void mine.refetch();
            void inbox.refetch();
            void clusters.refetch();
          }}
        />
      ) : !waiting.length && !pending.length ? (
        <p className="ov-calm">
          Nothing needs you. No write is waiting for your review.
        </p>
      ) : (
        <>
          {!!waiting.length && (
            <>
              <h3 className="ov-group">Waiting for your review</h3>
              <ul className="ov-reviews">
                {shown.map((approval) => (
                  <ReviewRow
                    key={approval.id}
                    approval={approval}
                    cluster={clusterById.get(approval.cluster_id)}
                    mine={false}
                  />
                ))}
              </ul>
              {(waiting.length > shown.length || more) && (
                <Link className="ov-more" to="/approvals">
                  See all {waiting.length}
                  {more ? '+' : ''} in Approvals
                  <ChevronRight size={14} aria-hidden />
                </Link>
              )}
            </>
          )}
          {!!pending.length && (
            <>
              <h3 className="ov-group">Your requests</h3>
              <ul className="ov-reviews">
                {pending.map((approval) => (
                  <ReviewRow
                    key={approval.id}
                    approval={approval}
                    cluster={clusterById.get(approval.cluster_id)}
                    mine
                  />
                ))}
              </ul>
              {mine.data?.next_cursor && (
                <Link className="ov-more" to="/approvals?tab=mine">
                  All your requests
                  <ChevronRight size={14} aria-hidden />
                </Link>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}

function ActivityRow({
  entry,
  cluster,
  agents,
}: {
  entry: HistoryEntry;
  cluster: Cluster | undefined;
  agents: ReadonlyMap<string, Agent>;
}) {
  const user = useUser();
  const verdict = verdictOfHistory(entry);
  const actor = actorOfHistory(entry, { agents, me: user });
  return (
    <li>
      <Link
        className="ov-activity-row"
        to={`/history?cluster_id=${entry.cluster_id}&entry=${entry.id}`}
      >
        <span className="ov-activity-verdict">
          {verdict ? (
            <VerdictChip verdict={verdict} />
          ) : (
            <span className="ov-run-status">{runStatusText(entry.status)}</span>
          )}
        </span>
        <code className="ov-activity-sql">{statementSummary(entry.sql)}</code>
        <span className="ov-activity-who">
          {actor.kind === 'agent' ? (
            <>
              <ActorBadge kind="agent" name={actor.name} />
              <span className="ov-owner">for {actor.owner}</span>
            </>
          ) : (
            <ActorBadge kind="human" name={actor.name} />
          )}
        </span>
        <span className="ov-cluster">
          {entry.cluster_name}
          {cluster && <EnvBadge environment={cluster.environment} />}
        </span>
        <span className="ov-activity-time">
          <RelativeTime value={entry.created_at} />
        </span>
      </Link>
    </li>
  );
}

/** The latest queries, with what the gate did and who ran them. */
export function MyWork() {
  const user = useUser(),
    [mode, setMode] = useState('mine');
  const everyone = user?.org_role === 'admin' && mode === 'everyone';
  const clusters = useResource<{ items: Cluster[] }>('/clusters');
  const history = useResource<Page<HistoryEntry>>(
    `/history?${everyone ? '' : `user_id=${user?.id}&`}limit=5`,
    everyone || !!user?.id,
  );
  const hasAgent = !!history.data?.items.some((entry) => entry.agent_id);
  // Names only: an agent the caller cannot list still shows as an agent.
  const agents = useResource<Page<Agent>>('/agents?limit=200', hasAgent);
  const agentById = useMemo(
    () => new Map(agents.data?.items.map((agent) => [agent.id, agent]) ?? []),
    [agents.data],
  );
  const clusterById = useMemo(
    () => new Map(clusters.data?.items.map((c) => [c.id, c]) ?? []),
    [clusters.data],
  );
  return (
    <section className="ov-activity" aria-labelledby="ov-activity-title">
      <div className="ov-section-head">
        <h2 id="ov-activity-title">Recent activity</h2>
        <div className="ov-section-tools">
          {user?.org_role === 'admin' && (
            <SegmentedControl
              label="Recent query scope"
              value={mode}
              onChange={setMode}
              items={[
                { value: 'mine', label: 'Mine' },
                { value: 'everyone', label: 'Everyone' },
              ]}
            />
          )}
          <Link
            to={everyone || !user ? '/history' : `/history?user_id=${user.id}`}
          >
            View history
          </Link>
        </div>
      </div>
      {history.isPending ? (
        <Skeleton />
      ) : history.error ? (
        <ErrorPanel
          error={history.error}
          retry={() => void history.refetch()}
        />
      ) : history.data.items.length ? (
        <ul className="ov-activity-list">
          {history.data.items.map((entry) => (
            <ActivityRow
              key={entry.id}
              entry={entry}
              cluster={clusterById.get(entry.cluster_id)}
              agents={agentById}
            />
          ))}
        </ul>
      ) : (
        <p className="ov-calm">
          {everyone ? 'No queries yet.' : 'You have not run a query yet.'}{' '}
          <Link to="/console">Open the console</Link> to run one through the
          gate.
        </p>
      )}
    </section>
  );
}
