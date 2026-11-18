// Plain words for approval requests, their previews and their receipts.
import type { Approval, Preview, ReceiptCheck, RowSample } from '../api/types';

/** "Asked by agent support-assistant for Jordan Lee". A deleted agent keeps its name. */
export function agentLabel(approval: Pick<Approval, 'agent' | 'requester'>) {
  if (!approval.agent) return null;
  return `Asked by agent ${approval.agent.name}${approval.agent.id ? '' : ' (deleted)'} for ${approval.requester.name}`;
}

type Tense = 'future' | 'present' | 'past';
/** Future while the request can still run, present while it runs, past after. */
export const tenseOf = (status: Approval['status']): Tense =>
  status === 'pending' || status === 'approved'
    ? 'future'
    : status === 'executing'
      ? 'present'
      : 'past';

const bound: Record<Tense, Record<'rows' | 'count' | 'none', string>> = {
  future: {
    rows: 'It will run only on these exact rows.',
    count: 'It will run only if it changes the same number of rows.',
    none: 'Nothing is bound: it runs the statement as written.',
  },
  present: {
    rows: 'It runs only on these exact rows.',
    count: 'It runs only if it changes the same number of rows.',
    none: 'Nothing is bound: it runs the statement as written.',
  },
  past: {
    rows: 'It was bound to these exact rows.',
    count: 'It was bound to the number of rows it changes.',
    none: 'Nothing was bound.',
  },
};
export function boundText(
  to: Preview['bound_to'] | null | undefined,
  status: Approval['status'] = 'pending',
) {
  return bound[tenseOf(status)][to ?? 'none'];
}

export function rowsText(count: number) {
  return `${count.toLocaleString('en')} ${count === 1 ? 'row' : 'rows'}`;
}

/** "Changes 2 rows", "Deletes 1 row", "Adds 3 rows". */
export function changeSummary(preview: Preview) {
  const verb =
    preview.kind === 'delete'
      ? 'Deletes'
      : preview.kind === 'insert'
        ? 'Adds'
        : 'Changes';
  return `${verb} ${rowsText(preview.affected_rows ?? 0)}`;
}

/** An agent's request cannot be approved before a person has previewed it. */
export const needsPreview = (approval: Pick<Approval, 'agent' | 'preview'>) =>
  !!approval.agent && !approval.preview;

/** The write did not run because the data changed after the approval. */
export const isEffectChanged = (
  approval: Pick<Approval, 'status' | 'error_code'>,
) => approval.status === 'failed' && approval.error_code === 'effect_changed';

/**
 * The written columns as the result names them. The server names them as
 * PostgreSQL does; as a backstop, a name without an exact match takes the one
 * column that matches it without regard to case. `complete` is false when a
 * name matches no column, or several.
 */
export function resolveWritten(
  written: string[],
  columns: string[],
): { names: string[]; complete: boolean } {
  const unique = [...new Set(columns)];
  const names: string[] = [];
  let complete = true;
  for (const name of written) {
    if (unique.includes(name)) {
      names.push(name);
      continue;
    }
    const folded = unique.filter(
      (column) => column.toLowerCase() === name.toLowerCase(),
    );
    if (folded.length === 1) names.push(folded[0]!);
    else complete = false;
  }
  return { names: [...new Set(names)], complete };
}

export type RowMatch = {
  /** Changed cells of `after`, as `row:column` keys. */
  changed: Set<string>;
  /** The column that paired the rows; null when they cannot be paired. */
  key: string | null;
};
const text = (value: unknown) => JSON.stringify(value ?? null);
const unique = (sample: RowSample, index: number) =>
  new Set(sample.rows.map((row) => text(row[index]))).size ===
  sample.rows.length;
/**
 * Pair the rows of `after` with those of `before`, and find the cells that
 * changed. Rows are paired only when that is certain: by a column that is in
 * both samples, shown in both, not written by the statement, and unique in
 * both, with every row of each sample present. A column the statement does
 * not write keeps its value, so a unique one names the same row before and
 * after. Without such a column nothing is marked; a guess could mark an
 * unchanged value as changed.
 */
export function matchRows(
  before: RowSample | undefined,
  after: RowSample | undefined,
  named: string[] | undefined,
): RowMatch {
  const none: RowMatch = { changed: new Set(), key: null };
  if (!before || !after || !named) return none;
  // Every written column must be found, or a written key could pass for
  // an unwritten one.
  const resolved = resolveWritten(named, [...before.columns, ...after.columns]);
  if (!resolved.complete) return none;
  const written = resolved.names;
  if (
    before.rows.length !== before.total ||
    after.rows.length !== after.total ||
    before.total !== after.total
  )
    return none;
  const candidates = after.columns.filter(
    (column) =>
      before.columns.includes(column) &&
      !written.includes(column) &&
      !before.hidden.includes(column) &&
      !after.hidden.includes(column) &&
      unique(before, before.columns.indexOf(column)) &&
      unique(after, after.columns.indexOf(column)),
  );
  // An `id` is the most likely key; any other qualifying column is as certain.
  const key = candidates.includes('id') ? 'id' : candidates[0];
  if (!key) return none;
  const beforeKey = before.columns.indexOf(key),
    afterKey = after.columns.indexOf(key);
  const byKey = new Map(before.rows.map((row) => [text(row[beforeKey]), row]));
  if (after.rows.some((row) => !byKey.has(text(row[afterKey])))) return none;
  const changed = new Set<string>();
  after.rows.forEach((row, rowIndex) => {
    const old = byKey.get(text(row[afterKey]))!;
    after.columns.forEach((column, columnIndex) => {
      const source = before.columns.indexOf(column);
      if (
        source < 0 ||
        !written.includes(column) ||
        before.hidden.includes(column) ||
        after.hidden.includes(column)
      )
        return;
      if (text(old[source]) !== text(row[columnIndex]))
        changed.add(`${rowIndex}:${columnIndex}`);
    });
  });
  return { changed, key };
}

export type ReceiptState = 'valid' | 'unverified' | 'changed';
/**
 * Whether a receipt is intact. A record whose content does not match its own
 * digest was changed, whatever key it names; so was one that is not this
 * request's (another id, SQL or database). One that names another key is not
 * verified: a key id proves nothing, so it may be from before a key change
 * or it may have been changed with a digest made to match.
 */
export function receiptState(
  check: Pick<
    ReceiptCheck,
    'valid' | 'digest_matches' | 'signed_with_current_key' | 'receipt'
  >,
  approval: Pick<Approval, 'id' | 'sql' | 'cluster_id' | 'status'>,
): ReceiptState {
  const belongs =
    approval.status === 'executed' &&
    check.receipt.approval_id === approval.id &&
    check.receipt.sql === approval.sql &&
    check.receipt.cluster.id === approval.cluster_id;
  if (!check.digest_matches || !belongs) return 'changed';
  if (check.valid) return 'valid';
  return check.signed_with_current_key ? 'changed' : 'unverified';
}
/** What a person should make of a receipt that is not plainly valid. */
export const receiptStateDetail: Record<ReceiptState, string | null> = {
  valid: null,
  changed:
    'Its content does not match its digest, or it is not the receipt of this request.',
  unverified:
    "This receipt was not signed with this server's current key. It may be from before a key change, or it may have been changed. Treat it as unproven.",
};
export const receiptStateText: Record<ReceiptState, string> = {
  valid: 'Signature valid',
  changed: 'Not valid: this record was changed',
  unverified: 'Not verified',
};

/** Expiry matters only while a request can still be approved or run. */
export const awaitsAction = (approval: Pick<Approval, 'status'>) =>
  approval.status === 'pending' || approval.status === 'approved';

/** How a request that can no longer run ended, and when; null when there is
 * nothing to add to its status (running, withdrawn) or the time is unknown. */
export function endedAt(
  approval: Pick<
    Approval,
    'status' | 'executed_at' | 'reviewed_at' | 'expires_at'
  >,
): { label: string; at: string } | null {
  const ended = {
    executed: ['Ran', approval.executed_at],
    failed: ['Failed', approval.executed_at],
    rejected: ['Rejected', approval.reviewed_at],
    expired: ['Expired', approval.expires_at],
  } as const;
  const entry =
    approval.status in ended
      ? ended[approval.status as keyof typeof ended]
      : null;
  return entry?.[1] ? { label: entry[0], at: entry[1] } : null;
}

/** The first and last eight characters of a digest. */
export const shortDigest = (digest: string) =>
  digest.length > 20 ? `${digest.slice(0, 8)}…${digest.slice(-8)}` : digest;

/** What happened to a request meanwhile, in one sentence, or null. */
export function whatHappened(
  approval: Pick<Approval, 'status' | 'reviewer' | 'agent'>,
): string | null {
  const by = approval.reviewer ? ` by ${approval.reviewer.name}` : '';
  switch (approval.status) {
    case 'approved':
      return `This request was approved${by} a moment ago.`;
    case 'rejected':
      return `This request was rejected${by} a moment ago.`;
    case 'withdrawn':
      return 'This request was withdrawn by its requester.';
    case 'expired':
      return 'This request has expired.';
    case 'executing':
    case 'executed':
    case 'failed':
      return `This request was approved${by} and has run.`;
    default:
      return null;
  }
}
