// What the Audit screen says about the hash chain and about an event, as
// plain functions so the words can be tested without a browser.
import { ApiError } from '../api/errors';
import type {
  AuditEvent,
  AuditIntegrity,
  AuditProblem,
  AuditProblemKind,
  AuditVerification,
} from '../api/types';
import { message } from './utils';

const count = (value: number) => value.toLocaleString('en-US');
const rows = (value: number) =>
  `${count(value)} ${value === 1 ? 'row' : 'rows'}`;

/** What a kind of break is, and what it means for the reader. */
export const PROBLEMS: Record<
  AuditProblemKind,
  { title: string; meaning: string }
> = {
  row_changed: {
    title: 'A sealed event was changed',
    meaning:
      'An audit event, or its link in the chain, no longer has the content it was sealed with. It was changed in the database, outside the gateway.',
  },
  row_missing: {
    title: 'A sealed event was deleted',
    meaning:
      'The chain holds a link for an event that is no longer in the audit log. It was deleted in the database, outside the gateway.',
  },
  row_inserted: {
    title: 'An event was added after the fact',
    meaning:
      'An event sits among sealed events but was never sealed. It was put into the database after the events around it.',
  },
  chain_broken: {
    title: 'The chain itself was changed',
    meaning:
      "A link is missing, moved, added or relabelled as another key's. Events may have been removed or changed together with their links.",
  },
  chain_truncated: {
    title: 'The end of the audit log was removed',
    meaning:
      'This gateway saw a longer chain earlier. The newest events and their links are gone.',
  },
  checkpoint_mismatch: {
    title: 'The chain was rebuilt or relabelled',
    meaning:
      'A link that this gateway saw earlier now has another hash or names another key. It was replaced or relabelled in the database.',
  },
};
/** Where the first problem is, in one sentence. */
export function problemPlace(problem: AuditProblem): string {
  const event =
    problem.seq === null ? '' : `, event number ${count(problem.seq)}`;
  return `First problem at chain position ${count(problem.position)}${event}.`;
}
/** How long sealing has waited, in words; nothing under a minute. */
export function sealingDelay(seconds: number | null): string | null {
  if (seconds === null || seconds < 60) return null;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
  const hours = Math.floor(minutes / 60);
  return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
}
/** How many rows were sealed with a key that is not the current one. */
export const unverifiableRows = (
  segments: AuditIntegrity['verification']['unverifiable'],
) =>
  segments.reduce(
    (total, segment) =>
      total + segment.last_position - segment.first_position + 1,
    0,
  );
export interface IntegrityView {
  state: AuditIntegrity['verification']['status'];
  /** Said before the time of the last check, when there is one. */
  headline: string;
  /** "N rows sealed · M waiting". */
  counts: string;
  /** A sentence under the line: a delay, or rows another key sealed. */
  notes: string[];
  problem: (AuditProblem & { title: string; meaning: string }) | null;
}
/** The integrity line of the Audit screen, in words. */
export function integrityView(integrity: AuditIntegrity): IntegrityView {
  const { verification } = integrity;
  const delay = sealingDelay(integrity.oldest_unsealed_seconds);
  const waiting =
    integrity.unsealed === 0
      ? 'none waiting'
      : `${count(integrity.unsealed)} waiting${delay ? `, the oldest for ${delay}` : ''}`;
  const notes: string[] = [];
  if (delay)
    notes.push(
      'An event is sealed once no older transaction is open on the metadata database. One has been open for a while; until it ends, new events are not protected by the chain.',
    );
  const foreign = unverifiableRows(verification.unverifiable);
  if (verification.status === 'partial')
    notes.push(
      `${rows(foreign)} of ${count(verification.links)} were sealed with another master key and cannot be checked with the current one. Check them with that key and the verify-audit command.`,
    );
  const problem = verification.problem
    ? {
        ...verification.problem,
        ...(PROBLEMS[verification.problem.kind] ?? {
          title: 'The audit log does not match its chain',
          meaning: verification.problem.message,
        }),
      }
    : null;
  return {
    state: verification.status,
    headline:
      verification.status === 'broken'
        ? 'The audit log was changed outside the gateway'
        : verification.status === 'partial'
          ? 'Nothing wrong where the chain can be checked, up to'
          : verification.status === 'intact'
            ? 'Chain intact up to'
            : 'Not checked yet',
    counts: `${rows(integrity.sealed)} sealed · ${waiting}`,
    notes,
    problem,
  };
}
/** The result of "Verify now", in one sentence. */
export function verificationText(result: AuditVerification): {
  text: string;
  bad: boolean;
} {
  if (result.links === 0 && !result.problem)
    return {
      text: 'Nothing is sealed yet, so there was nothing to check.',
      bad: false,
    };
  const range = `positions ${count(result.from_position)} to ${count(Math.max(result.to_position, result.from_position))}`;
  if (result.problem) {
    const known = PROBLEMS[result.problem.kind];
    return {
      text: `Checked ${range}: ${known?.title ?? result.problem.message}. ${problemPlace(result.problem)}`,
      bad: true,
    };
  }
  if (result.status === 'partial')
    return {
      text: `Checked the newest ${rows(result.links)} (${range}): nothing wrong, but ${rows(result.links - result.verified)} were sealed with another master key and could not be checked.`,
      bad: false,
    };
  return {
    text: `Checked the newest ${rows(result.links)} (${range}): intact.`,
    bad: false,
  };
}
/** Why a check could not run, said next to the button. */
export function verifyRefusal(error: unknown): string {
  if (error instanceof ApiError && error.status === 429) {
    const wait = (error.details as { retry_after_seconds?: unknown } | null)
      ?.retry_after_seconds;
    return `Too many checks. Try again in ${typeof wait === 'number' ? wait : 60} seconds.`;
  }
  return message(error);
}
const LOGIN_STATUS: Record<string, string> = {
  unchecked: 'Not checked',
  ok: 'In sync',
  drift: 'Too open',
  error: 'Could not check',
};
const text = (value: unknown) => (typeof value === 'string' ? value : null);
/** One line that says what an event's details mean, from the fields the
 * gateway really writes. `null` when the action speaks for itself. */
export function auditSummary(
  event: Pick<AuditEvent, 'action' | 'details'>,
): { text: string; blocked?: boolean } | null {
  const details =
    event.details &&
    typeof event.details === 'object' &&
    !Array.isArray(event.details)
      ? (event.details as Record<string, unknown>)
      : {};
  const { action } = event;
  if (action === 'query.execute') {
    const by = details.agent_id ? ' · by an agent' : '';
    // The event is written before the query runs: it says that the query
    // was started or refused, not how it ended. History has the rest.
    return details.status === 'blocked'
      ? { text: `Refused before it ran${by}`, blocked: true }
      : { text: `Started${by} · SQL and result are in History` };
  }
  if (action === 'agent.tool') {
    const tool = text(details.tool) ?? 'tool';
    const outcome = text(details.outcome) ?? 'unknown';
    const task = text(details.task);
    return {
      text: `${tool} · ${outcome === 'ok' ? 'ok' : `refused: ${outcome}`}${task ? ` · ${task}` : ''}`,
    };
  }
  if (action === 'agent_login.status') {
    const name = (value: unknown) =>
      LOGIN_STATUS[String(value)] ?? String(value);
    return { text: `${name(details.from)} → ${name(details.to)}` };
  }
  if (action === 'audit.verify') {
    const from = Number(details.from_position),
      to = Number(details.to_position);
    return {
      text: `Positions ${count(from)} to ${count(Math.max(from, to))} · ${text(details.status) ?? 'unknown'}`,
    };
  }
  // A request that failed is recorded with its method, path and status.
  if (
    /^(POST|PUT|PATCH|DELETE) /.test(action) &&
    typeof details.status === 'number'
  )
    return { text: `Answered with HTTP ${details.status}` };
  return null;
}
