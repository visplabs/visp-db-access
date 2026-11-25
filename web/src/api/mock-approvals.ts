// Approval requests for the mock API: previews, review, execution, withdraw
// and signed receipts. It follows docs/API.md and the server's texts so the
// console can be used end to end without a server.
import { uuid } from './fixtures';
import { analyzeDemo } from './mock-guard';
import { databaseFunctions, previewWrite } from './mock-preview';
import type {
  Approval,
  Cluster,
  HistoryEntry,
  Policy,
  QueryResult,
  Receipt,
  ReceiptCheck,
  User,
} from './types';

type Fail = (
  code: string,
  message: string,
  status?: number,
  details?: unknown,
) => never;
type State = { approvals: Approval[]; clusters: Cluster[]; users: User[] };

/** The server's texts, kept word for word. */
export const TEXT = {
  denied: 'Access denied',
  notFound: 'Resource not found',
  previewTwice: 'Only a pending request without a preview can be previewed',
  agentGone: 'The agent that asked for this write was paused or deleted',
  previewFirst: (id: string) =>
    `Preview the write before you approve it (POST /approvals/${id}/preview)`,
  reviewed: 'Approval is expired or already reviewed',
  note: 'Rejection requires a note; notes must be at most 10000 bytes',
  rejectRun: 'A rejected request cannot run',
  consumed: 'Approval is expired, not approved or already consumed',
  withdraw: 'Only a request that is pending or approved can be withdrawn',
  effectChanged:
    'The data changed after the approval, so the write was not run: the rows it changes are not the rows that were approved',
  policy: 'Query denied by policy',
  outcomeUnknown: 'execution outcome unknown (node crashed or lost)',
  someHidden:
    'Some new values are not shown: they are protected, or computed from a protected column or another query.',
  input: 'Invalid SQL or approval reason',
  readOnly: 'Only a statement that changes data needs an approval',
  withWrite:
    'A write inside WITH cannot be previewed or bound. Send each change as its own statement.',
  functions: (found: string[]) =>
    `This agent's statement calls functions defined in this database (${found.join(', ')}). A preview would run them. Reject it, or make the change as your own request.`,
} as const;

// Receipts are signed as the server signs them: the digest is the SHA-256 of
// the receipt without `digest` and `signature`, as compact JSON with sorted
// keys, and the signature is an HMAC of the digest.
const encoder = new TextEncoder();
const hex = (buffer: ArrayBuffer) =>
  Array.from(new Uint8Array(buffer), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
function byCodeUnits(a: string, b: string) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}
const canonical = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          // Sorted by UTF-16 code units, not by locale, so the order (and the
          // digest) is the same everywhere. The server sorts by bytes; for
          // the ASCII keys of a receipt both orders agree.
          Object.keys(value)
            .sort(byCodeUnits)
            .map((key) => [
              key,
              canonical((value as Record<string, unknown>)[key]),
            ]),
        )
      : value;
/** SHA-256 where the browser has it. `crypto.subtle` exists only in a secure
 * context, and the demo may be served over plain HTTP on a LAN address; there
 * a stand-in hash keeps the receipts working (they are made-up anyway). */
async function sha256(text: string) {
  if (globalThis.crypto?.subtle)
    return hex(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
  let out = '';
  for (let round = 0; round < 8; round += 1) {
    let hash = 0x811c9dc5 ^ round;
    for (const byte of encoder.encode(text))
      hash = Math.imul(hash ^ byte, 0x01000193) >>> 0;
    out += hash.toString(16).padStart(8, '0');
  }
  return out;
}
/** A keyed hash of `text`; HMAC-SHA256 where the browser has it. */
async function hmac(key: string, text: string) {
  if (!globalThis.crypto?.subtle) return sha256(`${key}\u0000${text}`);
  const imported = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return hex(await crypto.subtle.sign('HMAC', imported, encoder.encode(text)));
}
const digestOf = (body: Record<string, unknown>) =>
  sha256(JSON.stringify(canonical(body)));
const CURRENT_KEY = 'mock master key';
const EARLIER_KEY = 'mock master key before rotation';
const keyId = async (key: string) =>
  (await hmac(key, 'receipt key id')).slice(0, 16);
async function seal(
  body: Omit<Receipt, 'digest' | 'signature' | 'key_id'>,
  key = CURRENT_KEY,
): Promise<Receipt> {
  const unsigned = { ...body, key_id: await keyId(key) };
  const digest = await digestOf(unsigned);
  return { ...unsigned, digest, signature: await hmac(key, digest) };
}
/** The content matches its own digest; that needs no key. */
async function digestMatches(receipt: Receipt) {
  const body: Partial<Receipt> = { ...receipt };
  delete body.digest;
  delete body.signature;
  return (await digestOf(body)) === receipt.digest;
}
async function intact(receipt: Receipt) {
  return (
    (await digestMatches(receipt)) &&
    (await hmac(CURRENT_KEY, receipt.digest)) === receipt.signature
  );
}

export function createApprovals(context: {
  state: State;
  policies: Map<string, Policy>;
  access: (cluster: Cluster) => string | null;
  fail: Fail;
  audit: (action: string, type: string, id: string, details: unknown) => void;
  history: (
    user: User,
    cluster: Cluster,
    sql: string,
    status: HistoryEntry['status'],
    analysis: ReturnType<typeof analyzeDemo>,
    result?: QueryResult,
    error?: string | null,
  ) => void;
  result: (cluster: Cluster, sql: string, query_id: string) => QueryResult;
  /** Whether an agent that the agents list knows is active (not paused). */
  agentActive: (id: string) => boolean | undefined;
  wait: () => Promise<void>;
  now: () => string;
}) {
  const { state, policies, access, fail, audit, now } = context;
  const required = <T>(value: T | undefined): T =>
    value ?? fail('not_found', TEXT.notFound, 404);
  const policy = (cluster: Cluster) => required(policies.get(cluster.id));
  const person = (user: User) => ({
    id: user.id,
    email: user.email,
    name: user.name,
  });
  const activeAgent = (approval: Approval) =>
    !!approval.agent?.id && context.agentActive(approval.agent.id) === true;

  function seed() {
    const [admin, reviewer, member] = state.users;
    const commerce = required(state.clusters[0]); // MySQL
    const staging = required(
      state.clusters.find((c) => c.name === 'checkout-staging'),
    ); // PostgreSQL
    // One colleague's pending request and one approved request make the
    // review flow demoable. They are on MySQL, so they have no preview.
    for (let i = 0; i < 4; i++) {
      const requester = required(i === 0 ? member : admin);
      const sql = "UPDATE users SET name = 'Maya Patel' WHERE id = 42";
      state.approvals.push({
        id: uuid(800 + i),
        cluster_id: commerce.id,
        cluster_name: commerce.name,
        requester: person(requester),
        agent: null,
        sql,
        reason:
          i === 0
            ? 'Correct a customer name after a verified support request.'
            : 'Repair an incorrect display name.',
        analysis: analyzeDemo(sql, policy(commerce)),
        preview: previewWrite(sql, commerce, policy(commerce)),
        receipt: null,
        status:
          (['pending', 'approved', 'executing', 'failed'] as const)[i] ??
          'pending',
        error: i === 3 ? 'Target database unavailable' : null,
        error_code: i === 3 ? 'upstream' : null,
        sql_truncated: false,
        reviewer: i === 0 ? null : person(required(reviewer)),
        review_note: i === 0 ? null : 'Verified the target record.',
        result: null,
        created_at: now(),
        reviewed_at: i === 0 ? null : now(),
        executed_at: i === 3 ? now() : null,
        expires_at: new Date(Date.now() + 86400000).toISOString(),
      });
    }
    // Older requests on PostgreSQL: agents' requests, and requests that
    // ended in each way. They sort after the ones above.
    const minutes = (n: number) =>
      new Date(Date.now() - n * 60000).toISOString();
    const base = (
      n: number,
      fields: Pick<Approval, 'sql' | 'reason' | 'status'> & Partial<Approval>,
    ): Approval => ({
      id: uuid(810 + n),
      cluster_id: staging.id,
      cluster_name: staging.name,
      requester: person(required(member)),
      agent: null,
      analysis: analyzeDemo(fields.sql, policy(staging)),
      preview: null,
      receipt: null,
      error: null,
      error_code: null,
      sql_truncated: false,
      reviewer: null,
      review_note: null,
      result: null,
      created_at: minutes(10 + n * 7),
      reviewed_at: null,
      executed_at: null,
      expires_at: new Date(Date.now() + 86400000 - n * 600000).toISOString(),
      ...fields,
    });
    const anonymize =
      "UPDATE users SET name = 'Closed account' WHERE id IN ('00000000-0000-4000-8000-000000002041', '00000000-0000-4000-8000-000000002042')";
    state.approvals.push(
      base(0, {
        agent: { id: uuid(900), name: 'support-assistant' },
        sql: anonymize,
        reason:
          'Anonymize the names on two accounts closed under a deletion request (ticket 4821).',
        status: 'pending',
      }),
      base(1, {
        agent: { id: uuid(901), name: 'pricing-bot' },
        sql: 'UPDATE orders SET total = apply_discount(total) WHERE id = 7',
        reason: 'Apply the agreed loyalty discount to order 7.',
        status: 'pending',
      }),
      base(2, {
        agent: { id: null, name: 'nightly-cleanup' },
        sql: "DELETE FROM subscriptions WHERE status = 'expired'",
        reason: 'Remove subscriptions that ended more than a year ago.',
        status: 'pending',
      }),
    );
    const update = "UPDATE subscriptions SET status = 'paused' WHERE id = 12";
    const changed = base(3, {
      sql: update,
      reason: 'Pause subscription 12 while billing is checked.',
      status: 'failed',
      preview: previewWrite(update, staging, policy(staging)),
      error: TEXT.effectChanged,
      error_code: 'effect_changed',
      reviewer: person(required(reviewer)),
      review_note: 'Checked with billing.',
      reviewed_at: minutes(20),
      executed_at: minutes(15),
    });
    const withdrawn = base(4, {
      requester: person(required(admin)),
      sql: "UPDATE orders SET metadata = '{}' WHERE id = 31",
      reason: 'Clear test metadata on order 31.',
      status: 'withdrawn',
    });
    withdrawn.preview = previewWrite(withdrawn.sql, staging, policy(staging));
    const expired = base(5, {
      sql: "UPDATE subscriptions SET status = 'active' WHERE id = 9",
      reason: 'Reactivate subscription 9 after payment.',
      status: 'expired',
      expires_at: minutes(60),
      created_at: minutes(60 * 25),
    });
    expired.preview = previewWrite(expired.sql, staging, policy(staging));
    state.approvals.push(changed, withdrawn, expired);
    // Previews whose rows cannot be paired one to one, and one bound to the
    // count only: the console must not mark a value as changed on a guess.
    const sample = (
      columns: string[],
      hidden: string[],
      rows: unknown[][],
      masked: string[] = hidden,
    ) => ({ columns, hidden, masked, rows, total: rows.length });
    state.approvals.push(
      base(10, {
        sql: "UPDATE ONLY subscriptions SET status = 'paused' WHERE id = 3",
        reason: 'Pause subscription 3 on the parent table only.',
        status: 'pending',
        preview: previewWrite(
          "UPDATE ONLY subscriptions SET status = 'paused' WHERE id = 3",
          staging,
          policy(staging),
          1,
        ),
      }),
      base(11, {
        sql: "UPDATE newsletter SET status = 'unsubscribed' WHERE email IN ('a@example.com', 'b@example.com')",
        reason: 'Unsubscribe two readers who asked by email.',
        status: 'pending',
        preview: {
          supported: true,
          kind: 'update',
          target: 'newsletter',
          affected_rows: 2,
          before: sample(
            ['email', 'status'],
            ['email'],
            [
              ['••••••', 'subscribed'],
              ['••••••', 'subscribed'],
            ],
          ),
          after: sample(
            ['email', 'status'],
            ['email'],
            [
              ['••••••', 'unsubscribed'],
              ['••••••', 'unsubscribed'],
            ],
          ),
          bound_to: 'rows',
          written: ['status'],
          notes: [TEXT.someHidden],
        },
      }),
      base(12, {
        sql: 'UPDATE order_events SET quantity = 0 WHERE order_id = 7',
        reason: 'Zero the quantities logged twice for order 7.',
        status: 'pending',
        preview: {
          supported: true,
          kind: 'update',
          target: 'order_events',
          affected_rows: 2,
          before: sample(
            ['order_id', 'quantity'],
            [],
            [
              [7, 2],
              [7, 5],
            ],
          ),
          after: sample(
            ['order_id', 'quantity'],
            [],
            [
              [7, 0],
              [7, 0],
            ],
          ),
          bound_to: 'rows',
          written: ['quantity'],
          notes: [],
        },
      }),
      base(13, {
        sql: "UPDATE subscriptions SET status = 'active' WHERE id = 21",
        reason: 'Reactivate subscription 21 after a refund.',
        status: 'failed',
        preview: previewWrite(
          "UPDATE subscriptions SET status = 'active' WHERE id = 21",
          staging,
          policy(staging),
        ),
        error: TEXT.outcomeUnknown,
        error_code: 'outcome_unknown',
        reviewer: person(required(reviewer)),
        review_note: 'Refund confirmed.',
        created_at: minutes(130),
        reviewed_at: minutes(120),
        executed_at: minutes(110),
      }),
    );
  }
  /** A request that ran last week, signed before the master key changed. */
  async function seedSignedEarlier() {
    const [, reviewer, member] = state.users.map(person);
    const staging = required(
      state.clusters.find((c) => c.name === 'checkout-staging'),
    );
    const sql = "UPDATE subscriptions SET status = 'cancelled' WHERE id = 5";
    const at = (days: number) =>
      new Date(Date.now() - days * 86400000).toISOString();
    const preview = previewWrite(sql, staging, policy(staging));
    const approval: Approval = {
      id: uuid(817),
      cluster_id: staging.id,
      cluster_name: staging.name,
      requester: required(member),
      agent: { id: uuid(900), name: 'support-assistant' },
      sql,
      reason: 'Cancel subscription 5 at the customer’s request.',
      analysis: analyzeDemo(sql, policy(staging)),
      preview,
      receipt: null,
      status: 'executed',
      error: null,
      error_code: null,
      sql_truncated: false,
      reviewer: required(reviewer),
      review_note: 'Customer confirmed by phone.',
      result: {
        ...context.result(staging, sql, uuid(818)),
        affected_rows: 1,
      },
      created_at: at(7.2),
      reviewed_at: at(7.1),
      executed_at: at(7),
      expires_at: at(6.2),
    };
    approval.receipt = await receiptOf(
      approval,
      required(reviewer),
      EARLIER_KEY,
    );
    state.approvals.push(approval);
  }
  const ready = (async () => {
    seed();
    await seedSignedEarlier();
  })();

  function receiptOf(
    approval: Approval,
    executor: { id: string; email: string },
    key?: string,
  ) {
    const cluster = required(
      state.clusters.find((c) => c.id === approval.cluster_id),
    );
    const reviewer = required(approval.reviewer ?? undefined);
    return seal(
      {
        version: 1,
        approval_id: approval.id,
        cluster: { id: cluster.id, name: cluster.name, engine: cluster.engine },
        sql: approval.sql,
        reason: approval.reason,
        requested_by: {
          id: approval.requester.id,
          email: approval.requester.email,
        },
        agent: approval.agent,
        approved_by: { id: reviewer.id, email: reviewer.email },
        review_note: approval.review_note,
        executed_by: { id: executor.id, email: executor.email },
        requested_at: approval.created_at,
        approved_at: approval.reviewed_at ?? now(),
        executed_at: approval.executed_at ?? now(),
        previewed_rows: approval.preview?.affected_rows ?? null,
        affected_rows: approval.result?.affected_rows ?? null,
        bound_to: approval.preview?.bound_to ?? null,
      },
      key,
    );
  }

  /** Requests the caller can see: their own, and those on clusters they administer. */
  const visible = (approval: Approval, actor: User) => {
    const cluster = state.clusters.find((c) => c.id === approval.cluster_id);
    return (
      !!cluster &&
      (approval.requester.id === actor.id
        ? !!access(cluster)
        : access(cluster) === 'admin')
    );
  };
  const expire = (approval: Approval) => {
    if (
      ['pending', 'approved'].includes(approval.status) &&
      Date.parse(approval.expires_at) <= Date.now()
    )
      approval.status = 'expired';
  };

  async function execute(approval: Approval, cluster: Cluster, actor: User) {
    if (
      approval.requester.id !== actor.id &&
      approval.reviewer?.id !== actor.id
    )
      fail('forbidden', TEXT.denied, 403);
    // Nobody approved it: there is no one whose approval it runs on.
    if (!approval.reviewer) fail('forbidden', TEXT.denied, 403);
    if (approval.agent && !activeAgent(approval))
      fail('conflict', TEXT.agentGone, 409);
    if (approval.status !== 'approved') fail('conflict', TEXT.consumed, 409);
    const analysis = analyzeDemo(approval.sql, policy(cluster));
    if (analysis.verdict === 'deny')
      fail('query_denied', TEXT.policy, 422, analysis);
    approval.status = 'executing';
    await context.wait();
    if (cluster.health.status === 'down') {
      approval.status = 'failed';
      approval.error = 'Target database unavailable';
      approval.error_code = 'upstream';
      approval.executed_at = now();
      context.history(
        actor,
        cluster,
        approval.sql,
        'error',
        analysis,
        undefined,
        approval.error,
      );
      audit('approval.failed', 'approval', approval.id, { code: 'upstream' });
      fail('upstream', approval.error, 502);
    }
    const result = context.result(cluster, approval.sql, crypto.randomUUID());
    approval.result = {
      ...result,
      affected_rows: approval.preview?.affected_rows ?? result.affected_rows,
    };
    approval.status = 'executed';
    approval.executed_at = now();
    approval.receipt = await receiptOf(approval, actor);
    context.history(
      actor,
      cluster,
      approval.sql,
      'ok',
      approval.analysis,
      approval.result,
    );
    audit('approval.executed', 'approval', approval.id, {
      affected_rows: approval.result.affected_rows,
      receipt_digest: approval.receipt.digest,
    });
  }

  /** The requests a list shows, before paging. */
  async function list(actor: User, query: URLSearchParams) {
    await ready;
    for (const approval of state.approvals) expire(approval);
    return state.approvals.filter(
      (a) =>
        visible(a, actor) &&
        (!query.get('status') || a.status === query.get('status')) &&
        (!query.get('cluster_id') ||
          a.cluster_id === query.get('cluster_id')) &&
        (query.get('mine') !== 'true' || a.requester.id === actor.id),
    );
  }
  async function route(
    id: string | undefined,
    action: string | undefined,
    method: string,
    body: Record<string, unknown>,
    actor: User,
  ): Promise<unknown> {
    await ready;
    if (!id) {
      const cluster = required(
        state.clusters.find((c) => c.id === body.cluster_id),
      );
      const level = access(cluster);
      if (level !== 'write' && level !== 'admin')
        fail('forbidden', TEXT.denied, 403);
      const sql = String(body.sql ?? ''),
        reason = String(body.reason ?? '');
      if (!reason.trim() || reason.length > 10000 || !sql.trim())
        fail('validation', TEXT.input);
      // The demo guard blocks a write inside WITH outright; the server's
      // guard lets it through to this check.
      const write =
        /\b(insert|update|delete|merge|create|alter|drop|truncate)\b/i;
      if (/^\s*with\b/i.test(sql) && write.test(sql))
        fail('unsupported_write', TEXT.withWrite, 422);
      const analysis = analyzeDemo(sql, policy(cluster));
      if (analysis.verdict === 'deny')
        fail('query_denied', TEXT.policy, 422, analysis);
      if (!write.test(sql)) fail('validation', TEXT.readOnly);
      const approval: Approval = {
        id: crypto.randomUUID(),
        cluster_id: cluster.id,
        cluster_name: cluster.name,
        requester: person(actor),
        agent: null,
        sql: String(body.sql),
        reason: String(body.reason),
        analysis,
        // A person's request is previewed when it is made.
        preview: previewWrite(String(body.sql), cluster, policy(cluster)),
        receipt: null,
        status: 'pending',
        error: null,
        error_code: null,
        sql_truncated: false,
        reviewer: null,
        review_note: null,
        result: null,
        created_at: new Date(
          Math.max(
            Date.now(),
            ...state.approvals.map((a) => Date.parse(a.created_at) + 1),
          ),
        ).toISOString(),
        reviewed_at: null,
        executed_at: null,
        expires_at: new Date(Date.now() + 86400000).toISOString(),
      };
      state.approvals.unshift(approval);
      audit('approval.create', 'approval', approval.id, {});
      return approval;
    }
    const approval = required(state.approvals.find((a) => a.id === id));
    const cluster = required(
      state.clusters.find((c) => c.id === approval.cluster_id),
    );
    if (!visible(approval, actor)) fail('forbidden', TEXT.denied, 403);
    expire(approval);
    if (!action) return approval;
    if (action === 'receipt') {
      if (!approval.receipt) fail('not_found', TEXT.notFound, 404);
      const receipt = required(approval.receipt ?? undefined);
      const belongs =
        approval.status === 'executed' &&
        receipt.approval_id === approval.id &&
        receipt.sql === approval.sql &&
        receipt.cluster.id === approval.cluster_id;
      const matches = await digestMatches(receipt);
      const check: ReceiptCheck = {
        receipt,
        valid: belongs && matches && (await intact(receipt)),
        digest_matches: matches,
        signed_with_current_key: receipt.key_id === (await keyId(CURRENT_KEY)),
      };
      return check;
    }
    if (method !== 'POST') fail('not_found', 'Endpoint not found.', 404);
    if (action === 'preview') {
      if (approval.status !== 'pending' || approval.preview)
        fail('conflict', TEXT.previewTwice, 409);
      if (approval.agent) {
        if (!activeAgent(approval)) fail('conflict', TEXT.agentGone, 409);
        const found = databaseFunctions(approval.sql);
        if (found.length) fail('unsupported_write', TEXT.functions(found), 422);
      }
      await context.wait();
      approval.preview = previewWrite(approval.sql, cluster, policy(cluster));
      audit('approval.preview', 'approval', approval.id, {
        affected_rows: approval.preview.affected_rows,
        bound_to: approval.preview.bound_to,
      });
      return approval;
    }
    if (action === 'approve' || action === 'reject') {
      if (action === 'reject' && body.run === true)
        fail('validation', TEXT.rejectRun);
      if (approval.requester.id === actor.id)
        fail('forbidden', TEXT.denied, 403);
      const note = typeof body.note === 'string' ? body.note : null;
      if (
        (note && encoder.encode(note).length > 10000) ||
        (action === 'reject' && !note?.trim())
      )
        fail('validation', TEXT.note);
      if (action === 'approve' && approval.agent && !approval.preview)
        fail('conflict', TEXT.previewFirst(approval.id), 409);
      if (approval.status !== 'pending') fail('conflict', TEXT.reviewed, 409);
      approval.status = action === 'approve' ? 'approved' : 'rejected';
      approval.reviewer = person(actor);
      approval.review_note = note;
      approval.reviewed_at = now();
      audit(`approval.${action}`, 'approval', approval.id, {});
      if (action === 'approve' && body.run === true)
        await execute(approval, cluster, actor);
      return approval;
    }
    if (action === 'execute') {
      await execute(approval, cluster, actor);
      return approval;
    }
    if (action === 'withdraw') {
      if (approval.requester.id !== actor.id)
        fail('forbidden', TEXT.denied, 403);
      if (approval.status !== 'pending' && approval.status !== 'approved')
        fail('conflict', TEXT.withdraw, 409);
      approval.status = 'withdrawn';
      audit('approval.withdraw', 'approval', approval.id, { agent_id: null });
      return approval;
    }
    return fail('not_found', 'Endpoint not found.', 404);
  }
  return { list, route };
}
