// Plain facts about one agent, worked out from what `GET /agents` sends:
// its tokens' states and times. Nothing here is guessed.
import type { Agent, AgentToken } from '../../api/types';

export const levelText = {
  read: 'Read only',
  write: 'May ask for writes',
} as const;

export type TokenState = 'Active' | 'Expired' | 'Revoked';

export const tokenState = (
  token: Pick<AgentToken, 'revoked_at' | 'expires_at'>,
  now = Date.now(),
): TokenState =>
  token.revoked_at
    ? 'Revoked'
    : Date.parse(token.expires_at) <= now
      ? 'Expired'
      : 'Active';

/** The newest use of any of the agent's tokens, when the server sent one. */
export const lastActive = (agent: Pick<Agent, 'tokens'>) =>
  agent.tokens
    .map((token) => token.last_used_at)
    .filter((value): value is string => !!value)
    .sort((a, b) => a.localeCompare(b))
    .at(-1);

export type AgentState = 'active' | 'paused' | 'idle';

/** Paused wins; an agent with no active token cannot connect. */
export const agentState = (
  agent: Pick<Agent, 'paused' | 'tokens'>,
  now = Date.now(),
): AgentState =>
  agent.paused
    ? 'paused'
    : agent.tokens.some((token) => tokenState(token, now) === 'Active')
      ? 'active'
      : 'idle';

export const agentStateText: Record<AgentState, string> = {
  active: 'Active',
  paused: 'Paused',
  idle: 'No token',
};

/** The most recently used first; never used ones last, newest made first. */
export function byActivity<T extends Pick<Agent, 'tokens' | 'created_at'>>(
  agents: readonly T[],
): T[] {
  return [...agents].sort(
    (a, b) =>
      (lastActive(b) ?? '').localeCompare(lastActive(a) ?? '') ||
      b.created_at.localeCompare(a.created_at),
  );
}

const DAY = 86_400_000;

/** Active tokens, and in how many days the first of them stops working. */
export function activeTokens(
  agent: Pick<Agent, 'tokens'>,
  now = Date.now(),
): { count: number; endsInDays?: number } {
  const live = agent.tokens.filter(
    (token) => tokenState(token, now) === 'Active',
  );
  const soonest = live
    .map((token) => Date.parse(token.expires_at))
    .sort((a, b) => a - b)[0];
  return {
    count: live.length,
    endsInDays:
      soonest === undefined ? undefined : Math.ceil((soonest - now) / DAY),
  };
}
