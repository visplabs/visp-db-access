// The audit hash chain for the mock API. It follows docs/API.md closely
// enough for the screen and its tests: events are sealed a moment after they
// are written, the head moves, and a check answers in the server's shape.
// Its hashes are made up; nothing here is cryptography.
import type {
  AuditChainHead,
  AuditEvent,
  AuditIntegrity,
  AuditVerification,
} from './types';

type Fail = (
  code: string,
  message: string,
  status?: number,
  details?: unknown,
) => never;
/** An event is sealed this long after it was written, as the sealer's tick. */
export const SEAL_AFTER_MS = 2000;
/** Checks in a minute, for everyone together, as on one gateway node. */
export const VERIFIES_PER_MINUTE = 6;
const VERIFY_DEFAULT = 1000;
const VERIFY_MOST = 10_000;
const KEY_ID = '4a1886b932e8ae81';
/** Sixty-four hex characters that depend on `text`. Not a hash to trust. */
function fakeHash(text: string): string {
  let out = '';
  for (let round = 0; out.length < 64; round += 1) {
    let value = 0x811c9dc5 ^ round;
    for (const character of text) {
      value ^= character.codePointAt(0) ?? 0;
      value = Math.imul(value, 0x01000193) >>> 0;
    }
    out += value.toString(16).padStart(8, '0');
  }
  return out.slice(0, 64);
}
export function createAuditChain({
  events,
  fail,
  audit,
}: {
  events: () => AuditEvent[];
  fail: Fail;
  audit: (
    action: string,
    target_type: string,
    target_id: string | null,
    details: unknown,
  ) => unknown;
}) {
  let verifies: number[] = [];
  /** The sealer's tick: seal what is old enough, in the order written. */
  const seal = () => {
    const limit = Date.now() - SEAL_AFTER_MS;
    for (const event of events())
      if (!event.sealed && Date.parse(event.created_at) <= limit)
        event.sealed = true;
  };
  const sealed = () =>
    events()
      .filter((event) => event.sealed)
      .sort((a, b) => a.seq - b.seq);
  const head = (): AuditChainHead | null => {
    const links = sealed();
    const last = links.at(-1);
    return last
      ? {
          position: links.length,
          hash: fakeHash(`${links.length}:${last.id}`),
          key_id: KEY_ID,
          sealed_at: new Date(
            Date.parse(last.created_at) + SEAL_AFTER_MS,
          ).toISOString(),
        }
      : null;
  };
  return {
    seal,
    integrity(): AuditIntegrity {
      seal();
      const waiting = events().filter((event) => !event.sealed);
      const oldest = waiting
        .map((event) => event.created_at)
        .sort()
        .at(0);
      const links = sealed().length;
      return {
        head: head(),
        key_id: KEY_ID,
        sealed: links,
        unsealed: waiting.length,
        oldest_unsealed_at: oldest ?? null,
        oldest_unsealed_seconds: oldest
          ? Math.max(0, (Date.now() - Date.parse(oldest)) / 1000)
          : null,
        verification: {
          status: 'intact',
          checked_at: new Date(Date.now() - 20_000).toISOString(),
          key_id: KEY_ID,
          links,
          verified: links,
          unverifiable: [],
          problem: null,
          running: null,
        },
      };
    },
    verify(body: Record<string, unknown>): AuditVerification {
      for (const key of Object.keys(body))
        if (!['limit', 'from_position'].includes(key))
          fail('validation', 'Invalid JSON body');
      const limit = body.limit ?? VERIFY_DEFAULT;
      if (
        typeof limit !== 'number' ||
        !Number.isInteger(limit) ||
        limit < 1 ||
        limit > VERIFY_MOST
      )
        fail('validation', `Limit must be 1..=${VERIFY_MOST}`);
      const from = body.from_position;
      if (
        from !== undefined &&
        (typeof from !== 'number' || !Number.isInteger(from) || from < 1)
      )
        fail('validation', 'Position must be 1 or more');
      verifies = verifies.filter((at) => at > Date.now() - 60_000);
      if (verifies.length >= VERIFIES_PER_MINUTE)
        fail(
          'rate_limited',
          'Too many checks of the audit chain in one minute',
          429,
          { retry_after_seconds: 60 },
        );
      verifies.push(Date.now());
      seal();
      const end = sealed().length;
      const size = limit as number;
      const first = (from as number | undefined) ?? Math.max(1, end - size + 1);
      const last = Math.min(first + size - 1, end);
      const links = Math.max(0, last - first + 1);
      const outcome: AuditVerification = {
        status: 'intact',
        key_id: KEY_ID,
        from_position: first,
        to_position: first + links - 1,
        links,
        verified: links,
        unverifiable: [],
        problem: null,
        head: head(),
      };
      audit('audit.verify', 'audit', null, {
        from_position: outcome.from_position,
        to_position: outcome.to_position,
        status: outcome.status,
        problem: null,
      });
      return outcome;
    },
  };
}
