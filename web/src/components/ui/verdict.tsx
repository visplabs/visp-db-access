import { Bot, CircleCheck, EyeOff, Hand, Ban, UserRound } from 'lucide-react';
import type { GateVerdict } from '../../lib/verdict';

const VERDICT = {
  allowed: { word: 'Allowed', Icon: CircleCheck },
  masked: { word: 'Masked', Icon: EyeOff },
  held: { word: 'Held', Icon: Hand },
  blocked: { word: 'Blocked', Icon: Ban },
} as const;

/** What the gate did with a statement or call. Always an icon and a word,
 * never colour alone. Map API values with `lib/verdict`. */
export function VerdictChip({
  verdict,
  size = 'sm',
  label,
  className = '',
}: {
  verdict: GateVerdict;
  size?: 'sm' | 'md';
  /** Replaces the verdict's word, such as "Held for review". */
  label?: string;
  className?: string;
}) {
  const { word, Icon } = VERDICT[verdict];
  return (
    <span
      className={`verdict-chip ${className}`.trim()}
      data-verdict={verdict}
      data-size={size}
    >
      <Icon size={size === 'md' ? 15 : 13} strokeWidth={2.25} aria-hidden />
      <span>{label ?? word}</span>
    </span>
  );
}

/** Who acted. An agent reads "Agent" on an inverted tab, then its name and
 * client; a person has an outline icon and a name. */
export function ActorBadge({
  kind,
  name,
  client,
  className = '',
}: {
  kind: 'agent' | 'human';
  name?: string;
  /** The program the agent runs in, such as "Claude Code". */
  client?: string;
  className?: string;
}) {
  if (kind === 'agent')
    return (
      <span className={`actor-badge ${className}`.trim()} data-actor="agent">
        <span className="actor-kind">
          <Bot size={13} strokeWidth={2.25} aria-hidden />
          Agent
        </span>
        {name && <span className="actor-name">{name}</span>}
        {client && <span className="actor-client">{client}</span>}
      </span>
    );
  return (
    <span className={`actor-badge ${className}`.trim()} data-actor="human">
      <UserRound size={13} strokeWidth={2} aria-hidden />
      <span className="actor-name">{name ?? 'Person'}</span>
    </span>
  );
}
