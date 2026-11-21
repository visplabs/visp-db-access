// The pre-flight bar's logic: what it shows and what the one button may do.
// The server decides the state and the next step; this file only reads it,
// and keeps the gate on Run at least as strict as the verdict alone.
import type {
  AccessLevel,
  Checked,
  Preflight,
  PreflightState,
} from '../api/types';

export const stateLabel: Record<PreflightState, string> = {
  safe: 'Safe to run',
  needs_approval: 'Needs approval',
  blocked: 'Blocked',
};

/**
 * The pre-flight of an analysis. A server from before the pre-flight sends
 * the analysis alone; the state then follows from the verdict, with the
 * guard's own message as the reason, so the bar never shows nothing.
 */
export function preflightOf(
  analysis: Checked | undefined,
  access: AccessLevel | null,
): Preflight | undefined {
  if (!analysis) return undefined;
  if (analysis.preflight) return analysis.preflight;
  if (analysis.verdict === 'allow')
    return {
      state: 'safe',
      action: 'run',
      label: 'Run',
      hint: 'The guard found nothing that stops this statement.',
    };
  if (
    analysis.verdict === 'requires_approval' &&
    analysis.statements.length > 0 &&
    analysis.statements.every((statement) =>
      ['select', 'explain', 'show'].includes(statement.kind),
    )
  )
    // A read that locks rows: no approval can be asked for it.
    return {
      state: 'blocked',
      action: 'edit_sql',
      label: 'Edit the SQL',
      hint: 'This statement locks rows. Remove the locking clause (FOR UPDATE / FOR SHARE) to run it as a read.',
      code: 'locking_read',
    };
  if (analysis.verdict === 'requires_approval')
    return access === 'read' || !access
      ? {
          state: 'blocked',
          action: 'ask_admin',
          label: 'Ask for write access',
          hint: 'This statement needs approval, and your read access does not let you ask for it. A person with write access can ask for this change.',
          code: 'insufficient_access',
        }
      : {
          state: 'needs_approval',
          action: 'request_approval',
          label: 'Request approval',
          hint: 'Another person must approve this statement before it runs.',
          code: 'approval_required',
        };
  const block = analysis.issues.find((issue) => issue.severity === 'block');
  return {
    state: 'blocked',
    action: 'edit_sql',
    label: 'Edit the SQL',
    hint: block?.message ?? 'The guard refused this statement.',
    code: block?.code,
  };
}

/** What the check is doing, apart from its answer. */
export type CheckStatus =
  'empty' | 'checking' | 'updating' | 'failed' | 'ready';
export function checkStatus(state: {
  hasSql: boolean;
  fresh: boolean;
  failed: boolean;
  hasAnswer: boolean;
}): CheckStatus {
  if (!state.hasSql) return 'empty';
  if (state.failed) return 'failed';
  if (state.fresh) return 'ready';
  return state.hasAnswer ? 'updating' : 'checking';
}

/**
 * What the one button may do right now. Both the verdict and the pre-flight
 * must agree, and the answer must be for the text in the editor: a stale,
 * running or failed check never opens the gate, so the gate is never weaker
 * than the verdict alone.
 */
export function gate(input: {
  analysis: Checked | undefined;
  preflight: Preflight | undefined;
  status: CheckStatus;
  access: AccessLevel | null;
  busy: boolean;
}): { run: boolean; request: boolean; fix: boolean } {
  const { analysis, preflight, status, access, busy } = input;
  const settled = status === 'ready' && !busy && !!analysis && !!preflight;
  return {
    run: settled && analysis.verdict === 'allow' && preflight.action === 'run',
    request:
      settled &&
      analysis.verdict === 'requires_approval' &&
      preflight.action === 'request_approval' &&
      access !== 'read' &&
      access !== null,
    fix: settled && preflight.action === 'apply_fix' && !!preflight.fix,
  };
}

/**
 * How the status line names each state. It does not repeat the label that
 * is on screen ("Safe to run"), so that the label stays the one element with
 * that text, for people who look for it and for tests that do.
 */
export const spokenState: Record<PreflightState, string> = {
  safe: 'Check passed.',
  needs_approval: 'Approval needed.',
  blocked: 'Not allowed.',
};

/** One line for assistive technology: the state and why. */
export function spoken(
  status: CheckStatus,
  preflight: Preflight | undefined,
): string {
  if (status === 'failed')
    return 'The safety check failed. Nothing can run until it works.';
  if (status !== 'ready' || !preflight) return '';
  return [
    spokenState[preflight.state],
    preflight.hint,
    preflight.guard_change?.text,
  ]
    .filter(Boolean)
    .join(' ');
}
