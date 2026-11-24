// The decision trail of one agent session: what to count, how to filter and
// the plain words for why a step was held or refused. Everything here is
// computed from the steps the API returns; nothing is guessed.
import type { AgentStep, Approval } from '../../api/types';
import { verdictOfStep, type GateVerdict } from '../../lib/verdict';

/** The address of a session's own page. */
export const sessionPath = (agentId: string, sessionId: string) =>
  `/agents/${encodeURIComponent(agentId)}/sessions/${encodeURIComponent(sessionId)}`;

/** Tools that bring rows back to the agent. */
const READ_TOOLS: ReadonlySet<AgentStep['tool']> = new Set([
  'run_query',
  'fetch_rows',
]);

/** A call that read rows: a read tool that the gateway answered. */
export const isRead = (step: Pick<AgentStep, 'tool' | 'outcome'>) =>
  READ_TOOLS.has(step.tool) && step.outcome === 'ok';

/** A call that ended in an error that is not a decision of the gate. */
export const isFailed = (step: Pick<AgentStep, 'outcome' | 'verdict'>) =>
  step.outcome !== 'ok' && verdictOfStep(step) === undefined;

/** A step that asked to change data: a write it proposed, or a statement it
 * tried to run that changes data. */
export const isWrite = (step: Pick<AgentStep, 'tool' | 'outcome'>) =>
  step.tool === 'propose_write' || step.outcome === 'approval_required';

export type TrailFilter =
  'all' | 'reads' | 'rows' | 'allowed' | 'held' | 'blocked' | 'failed';

export interface TrailSummary {
  steps: number;
  reads: number;
  rows: number;
  allowed: number;
  held: number;
  blocked: number;
  failed: number;
}

/** The numbers of the summary strip, from the steps that were read. The
 * data says nothing of masking per step, so there is no Masked count. */
export function summarize(steps: readonly AgentStep[]): TrailSummary {
  const sum: TrailSummary = {
    steps: steps.length,
    reads: 0,
    rows: 0,
    allowed: 0,
    held: 0,
    blocked: 0,
    failed: 0,
  };
  for (const step of steps) {
    if (isRead(step)) sum.reads += 1;
    sum.rows += step.row_count ?? 0;
    const verdict = verdictOfStep(step);
    if (verdict && verdict !== 'masked') sum[verdict] += 1;
    else if (isFailed(step)) sum.failed += 1;
  }
  return sum;
}

/** Whether a step is shown under a filter of the summary strip. */
export function matches(step: AgentStep, filter: TrailFilter): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'reads':
      return isRead(step);
    case 'rows':
      return (step.row_count ?? 0) > 0;
    case 'failed':
      return isFailed(step);
    default:
      return verdictOfStep(step) === filter;
  }
}

/** Refusals of the gateway, said for a person. */
const REFUSED: Record<string, string> = {
  query_denied: 'The guard refused the statement.',
  forbidden: 'The agent may not do this.',
  not_found: 'The agent asked for something it cannot see.',
  cost_exceeded: 'The statement would cost more than the policy allows.',
  too_many_denials:
    'Too many of its queries were refused in a row, so the gateway paused its queries for a while.',
  budget_exceeded: 'The agent has used its hourly query budget.',
};
/** Errors that are not a decision of the gate, said for a person. */
const FAILED: Record<string, string> = {
  timeout: 'The call took too long and was stopped.',
  result_expired: 'The rows it asked for were no longer held.',
  upstream: 'The database could not be reached.',
  busy: 'The gateway was busy.',
  internal: 'The gateway could not complete the call.',
  rate_limited: 'The agent called too often and was asked to wait.',
  too_many_open_requests:
    'The agent has too many write requests waiting for a person.',
  validation: 'The arguments of the call were not valid.',
};

/**
 * Why the gate decided as it did, in one sentence, or null for a step that
 * needs no reason (an accepted call). It reads only the step's verdict,
 * outcome code and fix: a step keeps no other reason.
 */
export function reasonText(
  step: Pick<AgentStep, 'outcome' | 'verdict' | 'fix'>,
): string | null {
  if (step.verdict === 'deny') return 'The guard refused the statement.';
  if (
    step.verdict === 'requires_approval' &&
    step.fix?.action === 'rewrite_sql'
  )
    return 'The statement locks rows, so it did not run.';
  if (step.outcome === 'approval_required')
    return 'The statement changes data, so it did not run.';
  if (step.outcome === 'ok')
    return step.verdict === 'requires_approval'
      ? 'A person must approve this write before it runs.'
      : null;
  if (verdictOfStep(step) === 'blocked')
    return REFUSED[step.outcome] ?? 'The gateway refused the call.';
  return FAILED[step.outcome] ?? 'The call did not finish.';
}

/** Whether a step's decision gets its own panel: the gate held or refused
 * it, the call failed, or the agent was told what to do. */
export function needsDecision(
  step: Pick<AgentStep, 'outcome' | 'verdict' | 'fix'>,
): boolean {
  const verdict = verdictOfStep(step);
  return (
    verdict === 'held' ||
    verdict === 'blocked' ||
    !!step.fix ||
    step.outcome !== 'ok'
  );
}

/** SQL that does not fit one line of the trail is folded. */
export const foldsSql = (sql: string) => sql.includes('\n') || sql.length > 96;

/** A write request's state, as the trail says it. */
export const approvalText: Record<Approval['status'], string> = {
  pending: 'Waiting for a person',
  approved: 'Approved, not run yet',
  executing: 'Running',
  executed: 'Ran after approval',
  rejected: 'Rejected by a person',
  failed: 'The write failed',
  expired: 'The request expired',
  withdrawn: 'The agent withdrew it',
};

/** Counts of the strip and the verdict each one stands for. */
export const FILTER_VERDICT: Partial<Record<TrailFilter, GateVerdict>> = {
  allowed: 'allowed',
  held: 'held',
  blocked: 'blocked',
};
