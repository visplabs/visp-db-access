// The approval review as a decision: what the viewer can do next, the
// guard's checks, the statement as it reads best, and what happened so far.
// Pure functions of what the API sends; the screen only lays them out.
import type { Analysis, Approval, Issue, RowSample } from '../../api/types';
import { sqlParts } from '../../lib/activity';
import { verdictOfApproval, type GateVerdict } from '../../lib/verdict';

/** What the viewer may do with a request, as the server allows it. */
export type Viewer = {
  /** The request can still be approved or run (it has not expired). */
  live: boolean;
  /** The viewer asked for it (or owns the agent that did). */
  mine: boolean;
  /** The viewer is an admin of the request's cluster; undefined while
   * that is not known yet. */
  admin: boolean | undefined;
  /** The viewer may run an approved request: its requester or reviewer. */
  canExecute: boolean;
};

export type NextStep = {
  /** The status and the one next action, in a few words. */
  title: string;
  /** One sentence: why, or what happens next. */
  detail: string;
  /** The verdict shown beside it; none for an ending that is not a decision. */
  verdict: GateVerdict | undefined;
};

/** The header of the decision view: the state and the one thing to do. */
export function nextStep(
  approval: Pick<
    Approval,
    'status' | 'agent' | 'preview' | 'reviewer' | 'error_code' | 'cluster_name'
  >,
  viewer: Viewer,
): NextStep {
  const verdict = verdictOfApproval(approval.status);
  const agentDeleted = !!approval.agent && approval.agent.id === null;
  const previewFirst = !!approval.agent && !approval.preview;
  const reviewer = approval.reviewer?.name;
  switch (approval.status) {
    case 'pending':
      if (!viewer.live)
        return {
          title: 'Expired: it will not run',
          detail: 'Nobody reviewed it in time. Ask again to make the change.',
          verdict: undefined,
        };
      if (viewer.mine)
        return {
          title: 'You asked for this: you cannot approve it',
          detail: previewFirst
            ? 'Another cluster admin must review it. You can preview it meanwhile, or withdraw it.'
            : 'Another cluster admin must review it. You can withdraw it.',
          verdict,
        };
      if (viewer.admin === undefined)
        return {
          title: 'Waiting for review',
          detail: 'Checking what you can do with it…',
          verdict,
        };
      if (!viewer.admin)
        return {
          title: 'Waiting for a cluster admin',
          detail: `Only an admin of ${approval.cluster_name} can review it.`,
          verdict,
        };
      if (agentDeleted)
        return {
          title: 'The agent that asked was deleted',
          detail:
            'It cannot be previewed or approved. Reject it, or let it expire.',
          verdict,
        };
      if (previewFirst)
        return {
          title: 'Preview needed before approval',
          detail:
            'See the exact rows it changes first: Preview tries it and rolls it back.',
          verdict,
        };
      return {
        title: 'Waiting for your review',
        detail: 'Check what changes, then approve or reject it.',
        verdict,
      };
    case 'approved':
      if (!viewer.live)
        return {
          title: 'Expired before it ran',
          detail: 'It was approved but nobody ran it in time. It will not run.',
          verdict: undefined,
        };
      return {
        title: 'Approved: not run yet',
        detail: viewer.canExecute
          ? 'Run it before it expires, or withdraw it.'
          : `${reviewer ?? 'The reviewer'} or the requester can run it before it expires.`,
        verdict,
      };
    case 'executing':
      return {
        title: 'Running now',
        detail: `The approved write is running on ${approval.cluster_name}.`,
        verdict,
      };
    case 'executed':
      return {
        title: 'Done: it ran',
        detail: 'The receipt records who asked, who approved and what ran.',
        verdict,
      };
    case 'rejected':
      return {
        title: `Rejected${reviewer ? ` by ${reviewer}` : ''}`,
        detail: 'It will not run. The note says why.',
        verdict,
      };
    case 'failed':
      if (approval.error_code === 'effect_changed')
        return {
          title: 'Not run: the data changed after the approval',
          detail: 'Nothing was written. Ask again to review the new rows.',
          verdict,
        };
      if (approval.error_code === 'outcome_unknown')
        return {
          title: 'Unknown whether it ran',
          detail: 'Check the data on the database before you ask again.',
          verdict,
        };
      return {
        title: 'The write failed',
        detail: 'The database refused it or could not be reached.',
        verdict,
      };
    case 'withdrawn':
      return {
        title: 'Withdrawn by the requester',
        detail: 'It will not run.',
        verdict,
      };
    case 'expired':
      return {
        title: 'Expired: it will not run',
        detail: 'Nobody acted on it in time. Ask again to make the change.',
        verdict,
      };
  }
}

export type CheckLevel = 'block' | 'warn' | 'note' | 'pass';
export type Check = { level: CheckLevel; text: string; key: string };

const levelOf: Record<Issue['severity'], CheckLevel> = {
  block: 'block',
  warning: 'warn',
  info: 'note',
};
const rank: Record<CheckLevel, number> = {
  block: 0,
  warn: 1,
  note: 2,
  pass: 3,
};
const WRITES = new Set(['update', 'delete']);

/** The guard's findings as rows: what blocks, what warns, what passed.
 * Passes are read from the analysis' own fields, never assumed. */
export function checksOf(
  analysis: Pick<Analysis, 'issues' | 'statements'>,
): Check[] {
  const codes = new Set(analysis.issues.map((issue) => issue.code));
  const rows: Check[] = analysis.issues.map((issue, index) => ({
    level: levelOf[issue.severity],
    text: issue.message,
    key: `${issue.code}-${index}`,
  }));
  const writes = analysis.statements.filter((s) => WRITES.has(s.kind));
  if (
    writes.length > 0 &&
    writes.every((s) => s.has_where) &&
    !codes.has('missing_where')
  )
    rows.push({
      level: 'pass',
      text: 'It has a WHERE condition: it does not touch every row.',
      key: 'pass-where',
    });
  if (analysis.statements.length === 1 && !codes.has('multiple_statements'))
    rows.push({ level: 'pass', text: 'It is one statement.', key: 'pass-one' });
  if (!analysis.issues.some((issue) => issue.severity === 'block'))
    rows.push({
      level: 'pass',
      text: 'No table, function or statement in it is blocked.',
      key: 'pass-policy',
    });
  return rows.sort((a, b) => rank[a.level] - rank[b.level]);
}

/** "UPDATE on users", from the analysis. */
export function statementLine(analysis: Pick<Analysis, 'statements'>) {
  const kinds = [
    ...new Set(analysis.statements.map((s) => s.kind.toUpperCase())),
  ].join(', ');
  const tables = [...new Set(analysis.statements.flatMap((s) => s.tables))];
  return tables.length ? `${kinds} on ${tables.join(', ')}` : kinds;
}

const BREAK = new Set([
  'set',
  'from',
  'where',
  'values',
  'returning',
  'order',
  'group',
  'having',
  'limit',
  'offset',
  'using',
]);
const INDENT = new Set(['and', 'or']);
/**
 * One clause to a line, for reading. Only whitespace between tokens changes,
 * never a token; SQL that already has line breaks is shown as written.
 */
export function formatSql(sql: string) {
  if (sql.includes('\n')) return sql;
  let out = '',
    depth = 0,
    clause = '';
  for (const part of sqlParts(sql)) {
    const word = /^[A-Za-z_]/.test(part.text) ? part.text.toLowerCase() : '';
    const code = part.kind === 'plain' || part.kind === 'keyword';
    if (code && word && depth === 0 && out.trim()) {
      if (BREAK.has(word)) {
        out = `${out.trimEnd()}\n`;
        clause = word;
      } else if (INDENT.has(word) && clause === 'where')
        out = `${out.trimEnd()}\n  `;
    }
    if (code && !word)
      for (const char of part.text)
        depth += char === '(' ? 1 : char === ')' ? -1 : 0;
    out += part.text;
  }
  return out;
}

export type StepState = 'done' | 'current' | 'upcoming' | 'skipped' | 'ended';
export type Step = {
  key: 'asked' | 'preview' | 'review' | 'run' | 'receipt';
  label: string;
  state: StepState;
  at?: string | null;
  by?: string;
  text?: string;
  note?: string | null;
};

/** One timeline of a request: asked, previewed, reviewed, run, receipt. */
export function timelineOf(
  approval: Pick<
    Approval,
    | 'status'
    | 'agent'
    | 'requester'
    | 'preview'
    | 'reviewer'
    | 'review_note'
    | 'created_at'
    | 'reviewed_at'
    | 'executed_at'
    | 'expires_at'
  >,
  live: boolean,
): Step[] {
  const { status, preview } = approval;
  const open = (status === 'pending' || status === 'approved') && live;
  const asked: Step = {
    key: 'asked',
    label: 'Asked',
    state: 'done',
    at: approval.created_at,
    by: approval.agent
      ? `Agent ${approval.agent.name} for ${approval.requester.name}`
      : approval.requester.name,
  };
  let previewed: Step;
  if (preview)
    previewed = preview.supported
      ? {
          key: 'preview',
          label: 'Previewed',
          state: 'done',
          text: 'Tried on the database and rolled back.',
        }
      : { key: 'preview', label: 'Not previewed', state: 'skipped' };
  else if (approval.agent && status === 'pending' && live)
    previewed =
      approval.agent.id === null
        ? {
            key: 'preview',
            label: 'Cannot be previewed',
            state: 'skipped',
            text: 'The agent that asked was deleted.',
          }
        : {
            key: 'preview',
            label: 'Preview needed',
            state: 'current',
            text: 'An agent’s write is tried only after a person previews it.',
          };
  else
    previewed = { key: 'preview', label: 'Never previewed', state: 'skipped' };
  const decided = !!approval.reviewed_at;
  let review: Step;
  if (status === 'rejected')
    review = {
      key: 'review',
      label: 'Rejected',
      state: 'ended',
      at: approval.reviewed_at,
      by: approval.reviewer?.name,
      note: approval.review_note,
    };
  else if (decided)
    review = {
      key: 'review',
      label: 'Approved',
      state: 'done',
      at: approval.reviewed_at,
      by: approval.reviewer?.name,
      note: approval.review_note,
    };
  else if (status === 'withdrawn')
    review = {
      key: 'review',
      label: 'Withdrawn',
      state: 'ended',
      text: 'The requester withdrew it. It will not run.',
    };
  else if (status === 'expired' || (status === 'pending' && !live))
    review = {
      key: 'review',
      label: 'Expired',
      state: 'ended',
      at: approval.expires_at,
      text: 'Nobody reviewed it in time. It will not run.',
    };
  else
    review = {
      key: 'review',
      label: 'Review',
      state: previewed.state === 'current' ? 'upcoming' : 'current',
      text: 'Waiting for a cluster admin to approve or reject it.',
    };
  const notRun: Step = { key: 'run', label: 'Not run', state: 'skipped' };
  const lapsed: Step = {
    key: 'run',
    label: 'Expired',
    state: 'ended',
    at: approval.expires_at,
    text: 'It was not run in time. It will not run.',
  };
  let run: Step;
  switch (status) {
    case 'executed':
      run = {
        key: 'run',
        label: 'Ran',
        state: 'done',
        at: approval.executed_at,
      };
      break;
    case 'executing':
      run = {
        key: 'run',
        label: 'Running',
        state: 'current',
        text: 'Running now',
      };
      break;
    case 'failed':
      run = {
        key: 'run',
        label: 'Failed',
        state: 'ended',
        at: approval.executed_at,
      };
      break;
    case 'approved':
      run = live
        ? {
            key: 'run',
            label: 'Run',
            state: 'current',
            text: 'Approved. It has not run yet.',
          }
        : lapsed;
      break;
    case 'withdrawn':
      run = decided
        ? {
            key: 'run',
            label: 'Withdrawn',
            state: 'ended',
            text: 'The requester withdrew it. It will not run.',
          }
        : notRun;
      break;
    case 'expired':
      run = decided ? lapsed : notRun;
      break;
    case 'rejected':
      run = { ...notRun, text: 'It will not run.' };
      break;
    default:
      run = open
        ? {
            key: 'run',
            label: 'Run',
            state: 'upcoming',
            text: 'It runs only after a reviewer approves it.',
          }
        : notRun;
  }
  const steps = [asked, previewed, review, run];
  if (status === 'executed')
    steps.push({ key: 'receipt', label: 'Receipt signed', state: 'done' });
  else if (open || status === 'executing')
    steps.push({
      key: 'receipt',
      label: 'Receipt',
      state: 'upcoming',
      text: 'A signed receipt is made when it runs.',
    });
  return steps;
}

/** Rows of `after` with the row of `before` that has the same key. */
export function pairRows(
  before: RowSample,
  after: RowSample,
  key: string,
): { before: unknown[]; after: unknown[] }[] {
  const text = (value: unknown) => JSON.stringify(value ?? null);
  const beforeKey = before.columns.indexOf(key),
    afterKey = after.columns.indexOf(key);
  const byKey = new Map(before.rows.map((row) => [text(row[beforeKey]), row]));
  return after.rows.flatMap((row) => {
    const old = byKey.get(text(row[afterKey]));
    return old ? [{ before: old, after: row }] : [];
  });
}
