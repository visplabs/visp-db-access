// What the overview says, worked out from the API's own numbers. Nothing
// here makes up a total: each value is a field of `GET /overview` or a row
// that a list endpoint returned.
import type {
  Agent,
  Approval,
  Cluster,
  HistoryEntry,
  Risk,
} from '../../api/types';
import type { GateVerdict } from '../../lib/verdict';

/** `GET /overview`. The 24-hour counts cover the clusters the caller can
 * reach, people's and agents' queries alike. `blocked_24h` counts the
 * history rows with status `blocked`: statements the guard refused, and
 * writes it stopped because they need a person. `errors_24h` counts status
 * `error`. `pending_approvals` is a count of right now, not of 24 h. */
export type Overview = {
  clusters_total: number;
  healthy: number;
  degraded: number;
  down: number;
  unknown: number;
  queries_24h: number;
  blocked_24h: number;
  errors_24h: number;
  pending_approvals: number;
  discovery: { new: number; gone: number; drifted: number } | null;
  recent_queries: HistoryEntry[];
  unhealthy_clusters: Cluster[];
};

export type GateTile = {
  verdict: GateVerdict;
  count: number;
  /** The time the count covers, said on the tile. */
  window: '24 h' | 'Now';
  /** One line under the number, in the users' words. */
  meaning: string;
  /** Where the matching list is. */
  to: string;
  /** A second, smaller fact, such as failures on the database. */
  note?: string;
};

/** Statements of the last 24 hours that the guard let through and that did
 * not fail: `queries_24h` less `blocked_24h` (status `blocked`) and
 * `errors_24h` (status `error`). That is the History list of status `ok`,
 * except runs still going, cancelled or of unknown outcome: the API does
 * not count those apart. */
export const allowedCount = (data: Overview) =>
  Math.max(0, data.queries_24h - data.blocked_24h - data.errors_24h);

/** One tile per verdict the API can back, each saying the time it covers.
 * There is no masked count, so Masked has no tile. Held counts the requests
 * that wait now; Allowed and Blocked count statements of the last 24 hours. */
export function gateTiles(data: Overview): GateTile[] {
  const allowed = allowedCount(data);
  return [
    {
      verdict: 'allowed',
      count: allowed,
      window: '24 h',
      meaning: allowed
        ? 'let through, and did not fail'
        : 'Nothing ran in 24 hours',
      to: '/history?status=ok',
      note: data.errors_24h
        ? `${data.errors_24h.toLocaleString('en')} more let through, then failed on the database`
        : undefined,
    },
    {
      verdict: 'held',
      count: data.pending_approvals,
      window: 'Now',
      meaning:
        data.pending_approvals === 0
          ? 'Nobody is waiting for a review'
          : data.pending_approvals === 1
            ? 'request waits for a person'
            : 'requests wait for a person',
      to: '/approvals',
    },
    {
      verdict: 'blocked',
      count: data.blocked_24h,
      window: '24 h',
      meaning: data.blocked_24h
        ? 'stopped by the guard'
        : 'Nothing blocked in 24 hours',
      to: '/history?status=blocked',
    },
  ];
}

const RISK_ORDER: Record<Risk, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Highest risk first, then the one that expires soonest. */
export function rankReviews<
  T extends Pick<Approval, 'analysis' | 'expires_at'>,
>(approvals: readonly T[]): T[] {
  return [...approvals].sort(
    (a, b) =>
      RISK_ORDER[a.analysis.risk] - RISK_ORDER[b.analysis.risk] ||
      Date.parse(a.expires_at) - Date.parse(b.expires_at),
  );
}

/** Reviews this person can act on: pending, not their own, not expired,
 * on a cluster they administer. */
export function reviewable(
  approvals: readonly Approval[],
  {
    userId,
    adminClusters,
    now,
  }: { userId: string | undefined; adminClusters: Set<string>; now: number },
) {
  return approvals.filter(
    (approval) =>
      approval.status === 'pending' &&
      approval.requester.id !== userId &&
      Date.parse(approval.expires_at) > now &&
      adminClusters.has(approval.cluster_id),
  );
}

export type Actor =
  | { kind: 'agent'; name?: string; owner: string }
  | { kind: 'human'; name: string };

/** Who ran a history row. An agent's query carries `agent_id` and its
 * owner's email; the agent's name comes from the agents the caller can
 * list, and is left out when the caller cannot see that agent. */
export function actorOfHistory(
  entry: Pick<HistoryEntry, 'agent_id' | 'user_id' | 'user_email'>,
  {
    agents,
    me,
  }: {
    agents: ReadonlyMap<string, Pick<Agent, 'name'>>;
    me: { id: string } | null | undefined;
  },
): Actor {
  const person = entry.user_id === me?.id ? 'You' : entry.user_email;
  if (entry.agent_id)
    return {
      kind: 'agent',
      name: agents.get(entry.agent_id)?.name,
      owner: person,
    };
  return { kind: 'human', name: person };
}

/** How a run ended when it was not a gate decision. */
export function runStatusText(status: HistoryEntry['status']) {
  switch (status) {
    case 'error':
      return 'Failed';
    case 'cancelled':
      return 'Cancelled';
    case 'unknown':
      return 'Outcome unknown';
    case 'running':
      return 'Running';
    case 'ok':
      return 'Completed';
    case 'blocked':
      return 'Blocked';
  }
}
