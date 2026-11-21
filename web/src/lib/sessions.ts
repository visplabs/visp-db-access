// Logic of the agent session view: how the live list is read and merged, and
// the plain words for a step.
import type { AgentSession, AgentStep, AgentSteps } from '../api/types';

/** How often the list is read while a session is going on. */
export const LIVE_INTERVAL_MS = 3000;

/**
 * The time to the next read of a session's steps, or `false` for none. The
 * list is read again only while the session is going on, its agent may act
 * and the page is visible: a session that is over gets no new step, a paused
 * agent makes none, and nobody looks at a hidden tab.
 */
export function pollEvery(
  session: Pick<AgentSession, 'active'> | undefined,
  hidden: boolean,
  paused = false,
): number | false {
  // A paused agent is refused at the door, so no step can arrive.
  return session?.active && !hidden && !paused ? LIVE_INTERVAL_MS : false;
}

/**
 * Add the steps of a new answer to what is already read. Steps are numbered
 * without a gap, so a step is kept once, by its number, and in order.
 */
export function mergeSteps(
  known: AgentSteps | undefined,
  next: AgentSteps,
): AgentSteps {
  const last = known?.items.at(-1)?.n ?? 0;
  return {
    session: next.session,
    items: [
      ...(known?.items ?? []),
      ...next.items.filter((step) => step.n > last),
    ],
    after: Math.max(known?.after ?? 0, next.after),
    more: next.more,
  };
}

/** Steps shown when a session is opened: its newest ones. A long session
 * shows the rest on request, so the page never holds thousands at once. */
export const WINDOW = 200;
/** A marker past every step: the answer then holds the session and no step. */
export const PAST_ALL = 2_147_483_647;
/** What the view has read: the steps from `from + 1` on. */
export type Loaded = AgentSteps & { from: number };

/** Where the first read of a session begins, so that it holds the newest
 * `WINDOW` steps. */
export function firstMarker(session: Pick<AgentSession, 'steps'>): number {
  return Math.max(0, session.steps - WINDOW);
}
/** The read that brings the steps before the first one shown. */
export function earlierRange(from: number): { after: number; limit: number } {
  const after = Math.max(0, from - WINDOW);
  return { after, limit: from - after };
}
/** Put earlier steps in front of what is read, once each. */
export function prependSteps(known: Loaded, earlier: AgentSteps): Loaded {
  const first = known.items[0]?.n ?? known.from + 1;
  const added = earlier.items.filter((step) => step.n < first);
  return {
    ...known,
    items: [...added, ...known.items],
    // An answer with no earlier step means that none remains (old steps are
    // deleted after the retention time): there is nothing more to show.
    from: added.length ? (added[0]?.n ?? 1) - 1 : 0,
  };
}

export type StepMark = 'ok' | 'approval' | 'refused' | 'failed';
/**
 * The mark of a step: what the gateway did with the call. A statement that
 * the guard refused is `refused` also when the tool itself answered (a
 * `check_sql` that says "deny"); an error that is not a refusal of the
 * agent's request (the gateway or the database failed) is `failed`.
 */
export function stepMark(
  step: Pick<AgentStep, 'outcome' | 'verdict'> &
    Partial<Pick<AgentStep, 'fix'>>,
): StepMark {
  if (step.verdict === 'deny') return 'refused';
  // A read that locks rows needs no person: the agent was told to change it.
  if (
    step.fix?.action === 'rewrite_sql' &&
    step.verdict === 'requires_approval'
  )
    return 'refused';
  if (step.outcome === 'approval_required') return 'approval';
  if (step.outcome === 'ok')
    return step.verdict === 'requires_approval' ? 'approval' : 'ok';
  return ['upstream', 'internal', 'busy', 'database_check_failed'].includes(
    step.outcome,
  )
    ? 'failed'
    : 'refused';
}
export const markText: Record<StepMark, string> = {
  ok: 'Done',
  approval: 'Needs a person',
  refused: 'Refused',
  failed: 'Failed',
};

/** What a tool does, for a person who reads the trail. */
export const toolText: Record<AgentStep['tool'], string> = {
  list_databases: 'Listed its databases',
  search_schema: 'Searched the schema',
  describe_table: 'Looked at a table',
  check_sql: 'Asked the guard about a statement',
  run_query: 'Ran a query',
  fetch_rows: 'Read more rows of a result',
  propose_write: 'Asked for a write',
  get_approval: 'Checked on a write it asked for',
  withdraw: 'Withdrew a write it asked for',
};

/** The guard's answer to a step in plain words, or null when there is none
 * to tell: the call was accepted and nothing was said. */
export function answerText(step: AgentStep): string | null {
  if (step.outcome === 'ok' && !step.fix) {
    if (step.verdict === 'allow') return 'The guard accepted the statement.';
    if (step.verdict === 'requires_approval')
      return 'A person must approve this write before it runs.';
    return null;
  }
  const code = step.outcome === 'ok' ? null : step.outcome;
  const said =
    step.verdict === 'deny'
      ? 'The guard refused the statement.'
      : step.verdict === 'requires_approval' &&
          step.fix?.action === 'rewrite_sql'
        ? 'The statement locks rows, so it did not run.'
        : code === 'approval_required'
          ? 'The statement changes data, so it did not run.'
          : code
            ? 'The gateway refused the call.'
            : null;
  return [said, step.fix?.told].filter(Boolean).join(' ') || null;
}

/** "3 rows", "1 row". */
export function rowsText(count: number): string {
  return `${count.toLocaleString('en')} ${count === 1 ? 'row' : 'rows'}`;
}

/** Where a step's query is in the history, and its write among the requests. */
export const historyLink = (step: AgentStep): string | null =>
  step.history_id
    ? `/history?${step.database ? `cluster_id=${step.database}&` : ''}entry=${step.history_id}`
    : null;
export const approvalLink = (step: AgentStep): string | null =>
  step.approval_id ? `/approvals?id=${step.approval_id}&tab=all` : null;

/** The state of a session, in the words of its badge. */
export function sessionState(
  session: Pick<AgentSession, 'active'>,
  paused: boolean,
): 'Live' | 'Agent paused' | 'Ended' {
  if (!session.active) return 'Ended';
  return paused ? 'Agent paused' : 'Live';
}
