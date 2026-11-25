// One vocabulary for what the gate did: Allowed, Masked, Held, Blocked.
// Each mapper reads a value the API already returns and gives its verdict,
// or `undefined` when the value is not a decision of the gate (a query that
// failed on the database, a request that expired). Every mapper is total.
import type {
  Analysis,
  Approval,
  AgentStep,
  Column,
  HistoryEntry,
  PreflightState,
  QueryResult,
  Verdict,
} from '../api/types';

export type GateVerdict = 'allowed' | 'masked' | 'held' | 'blocked';
export const VERDICTS: readonly GateVerdict[] = [
  'allowed',
  'masked',
  'held',
  'blocked',
];

/** The guard's verdict on a statement: `allow`, `requires_approval`, `deny`. */
export function verdictOfGuard(verdict: Verdict): GateVerdict {
  switch (verdict) {
    case 'allow':
      return 'allowed';
    case 'requires_approval':
      return 'held';
    case 'deny':
      return 'blocked';
  }
}

/** An analysis (`POST /clusters/:id/analyze`, or the one on a result or
 * request). It knows nothing of masking: use `verdictOfResult` for rows. */
export function verdictOfAnalysis(analysis: Pick<Analysis, 'verdict'>) {
  return verdictOfGuard(analysis.verdict);
}

/** The pre-flight bar's state: `safe`, `needs_approval`, `blocked`. */
export function verdictOfPreflight(state: PreflightState): GateVerdict {
  switch (state) {
    case 'safe':
      return 'allowed';
    case 'needs_approval':
      return 'held';
    case 'blocked':
      return 'blocked';
  }
}

/** Result columns: `masked` when the policy hid any of them. */
export function verdictOfColumns(
  columns: readonly Pick<Column, 'masked'>[],
): GateVerdict {
  return columns.some((column) => column.masked) ? 'masked' : 'allowed';
}

/** Rows that came back: masked when a column was hidden, otherwise what the
 * guard decided (a result exists only for a statement that ran). */
export function verdictOfResult(
  result: Pick<QueryResult, 'columns' | 'analysis'>,
): GateVerdict {
  return verdictOfColumns(result.columns) === 'masked'
    ? 'masked'
    : verdictOfAnalysis(result.analysis);
}

/** A history row. The server marks `blocked` for `query_denied`,
 * `approval_required` and `cost_exceeded`; a write stopped for approval is
 * held, not blocked. `ok` and `running` passed the gate. `error`,
 * `cancelled` and `unknown` are how the run ended, not a gate decision. */
export function verdictOfHistory(
  entry: Pick<HistoryEntry, 'status' | 'verdict'>,
): GateVerdict | undefined {
  switch (entry.status) {
    case 'blocked':
      return entry.verdict === 'requires_approval' ? 'held' : 'blocked';
    case 'ok':
    case 'running':
      return 'allowed';
    case 'error':
    case 'cancelled':
    case 'unknown':
      return undefined;
  }
}

/** A write request, where the gate's decision is the point: `pending` waits
 * for a person (held), `rejected` is a person's block, `executed` ran as
 * approved. `approved` and `executing` have no verdict: nothing has run
 * yet, so they must not read as Allowed; show the request's status
 * ("Approved — not run yet", "Running") instead. `failed`, `expired` and
 * `withdrawn` end the request without a decision to show. */
export function verdictOfApproval(
  status: Approval['status'],
): GateVerdict | undefined {
  switch (status) {
    case 'pending':
      return 'held';
    case 'executed':
      return 'allowed';
    case 'rejected':
      return 'blocked';
    case 'approved':
    case 'executing':
    case 'failed':
    case 'expired':
    case 'withdrawn':
      return undefined;
  }
}

/** Error codes with which the gateway refuses an agent's call (see
 * `counted` in crates/vda-server/src/mcp.rs and the streak limits). */
export const REFUSAL_CODES: ReadonlySet<string> = new Set([
  'query_denied',
  'forbidden',
  'not_found',
  'cost_exceeded',
  'too_many_denials',
  'budget_exceeded',
]);

/** One step of an agent session. `outcome` is `ok` or the error code the
 * agent got. `approval_required` is held; a refusal code is blocked; any
 * other code (`timeout`, `upstream`, `result_expired`...) is a failure, not
 * a decision. With `ok`, the guard's verdict decides (`check_sql` can say
 * deny without a refusal); a tool that checks no SQL has none. */
export function verdictOfStep(
  step: Pick<AgentStep, 'outcome' | 'verdict'>,
): GateVerdict | undefined {
  if (step.outcome === 'approval_required') return 'held';
  if (REFUSAL_CODES.has(step.outcome)) return 'blocked';
  if (step.outcome !== 'ok') return undefined;
  return step.verdict ? verdictOfGuard(step.verdict) : undefined;
}

/** One wording for a request that is approved but has not run. */
export const APPROVED_NOT_RUN = 'Approved — not run yet';
