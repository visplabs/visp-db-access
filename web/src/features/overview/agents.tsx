import { Link } from 'react-router-dom';
import { Bot, ChevronRight, Plus } from 'lucide-react';
import { useMemo } from 'react';
import type { Agent, AgentSession, Cluster, Page } from '../../api/types';
import { useResource } from '../../lib/query';
import { EnvBadge, ErrorPanel, Skeleton } from '../../components/ui';
import { ActorBadge } from '../../components/ui/verdict';
import { useUser } from '../auth/session';
import {
  agentState,
  agentStateText,
  byActivity,
  levelText,
} from '../agents/facts';
import { sessionPath } from '../agents/session-trail';
import { InlineTime } from '../agents/sessions';

/** How many agents the overview shows before it points to the list. */
export const AGENT_CAP = 4;
/** The agents list as the overview reads it: one page, shared with the
 * names in Recent activity. */
export const AGENTS_PATH = '/agents?limit=200';

const plural = (n: number, one: string, many = `${one}s`) =>
  `${n.toLocaleString('en')} ${n === 1 ? one : many}`;

/** The newest session of one agent, as `GET /agents/:id/sessions` gives it. */
function LastSession({ agent }: { agent: Agent }) {
  const sessions = useResource<Page<AgentSession>>(
    `/agents/${encodeURIComponent(agent.id)}/sessions?limit=1`,
  );
  const session = sessions.data?.items[0];
  if (sessions.isPending)
    return <span className="ov-agent-session muted">Reading sessions…</span>;
  if (sessions.error)
    return (
      <span className="ov-agent-session muted">Sessions could not be read</span>
    );
  if (!session)
    return (
      <span className="ov-agent-session muted">
        {agent.tokens.length ? 'No call yet' : 'Needs a token to connect'}
      </span>
    );
  const live = session.active && !agent.paused;
  return (
    <Link
      className="ov-agent-session"
      to={sessionPath(agent.id, session.id)}
      data-live={live || undefined}
    >
      <span className="ov-agent-session-when">
        {live ? (
          <>
            <span className="ov-agent-live" aria-hidden />
            Live session
          </>
        ) : (
          <>
            Last session <InlineTime value={session.last_step_at} />
          </>
        )}
      </span>
      <span className="ov-agent-session-what">
        {plural(session.steps, 'step')}
        {session.refusals > 0 && `, ${session.refusals} refused`}
        {session.first_task && (
          <>
            {' · '}
            <span className="ov-agent-task">{session.first_task}</span>
          </>
        )}
      </span>
      <ChevronRight size={14} aria-hidden />
    </Link>
  );
}

function AgentRow({
  agent,
  mine,
  clusters,
}: {
  agent: Agent;
  mine: boolean;
  clusters: ReadonlyMap<string, Cluster>;
}) {
  const state = agentState(agent);
  const only =
    agent.cluster_ids.length === 1
      ? clusters.get(agent.cluster_ids[0] ?? '')
      : undefined;
  return (
    <li className="ov-agent" data-state={state}>
      <div className="ov-agent-who">
        <Link
          className="ov-agent-open"
          to={`/agents?agent=${encodeURIComponent(agent.id)}`}
          aria-label={`Agent ${agent.name}, for ${mine ? 'you' : agent.owner.name}`}
        >
          <ActorBadge kind="agent" name={agent.name} />
        </Link>
        <span className="ov-owner">for {mine ? 'you' : agent.owner.name}</span>
      </div>
      <div className="ov-agent-reach">
        {only ? (
          <span className="ov-cluster">
            {only.name}
            <EnvBadge environment={only.environment} />
          </span>
        ) : (
          <span>{plural(agent.cluster_ids.length, 'database')}</span>
        )}
        <span className="ov-owner">{levelText[agent.max_level]}</span>
      </div>
      <span className="agent-state" data-state={state}>
        {agentStateText[state]}
      </span>
      <LastSession agent={agent} />
    </li>
  );
}

/** The agents and what each did last: who acts through the gate, before
 * what the gate did. Everything comes from the agents and sessions APIs. */
export function AgentActivity() {
  const user = useUser();
  const agents = useResource<Page<Agent>>(AGENTS_PATH),
    clusters = useResource<{ items: Cluster[] }>('/clusters');
  const clusterById = useMemo(
    () => new Map(clusters.data?.items.map((c) => [c.id, c]) ?? []),
    [clusters.data],
  );
  const listed = agents.data ? byActivity(agents.data.items) : [];
  const shown = listed.slice(0, AGENT_CAP);
  const more = listed.length > shown.length || !!agents.data?.next_cursor;
  return (
    <section className="ov-agents" aria-labelledby="ov-agents-title">
      <div className="ov-section-head">
        <h2 id="ov-agents-title">Agents</h2>
        {listed.length > 0 && (
          <span className="ov-count">
            {listed.length}
            {agents.data?.next_cursor ? '+' : ''}{' '}
            {user?.org_role === 'admin' ? 'in the workspace' : 'of yours'}
          </span>
        )}
        <div className="ov-section-tools">
          {listed.length > 0 && (
            <Link to="/agents?connect=1" className="ov-head-link">
              <Plus size={14} aria-hidden />
              Connect an agent
            </Link>
          )}
        </div>
      </div>
      {agents.isPending ? (
        <Skeleton />
      ) : agents.error ? (
        <ErrorPanel error={agents.error} retry={() => void agents.refetch()} />
      ) : listed.length === 0 ? (
        <div className="ov-agents-empty">
          <Bot size={18} aria-hidden />
          <p>
            <strong>No agent is connected yet.</strong> Give Claude Code, Cursor
            or any MCP client its own token. Every call it makes goes through
            the guard and is on record.
          </p>
          <Link className="button primary" to="/agents?connect=1">
            Connect an agent
          </Link>
        </div>
      ) : (
        <>
          <ul className="ov-agent-list">
            {shown.map((agent) => (
              <AgentRow
                key={agent.id}
                agent={agent}
                mine={agent.owner.id === user?.id}
                clusters={clusterById}
              />
            ))}
          </ul>
          {more && (
            <Link className="ov-more" to="/agents">
              All {listed.length}
              {agents.data?.next_cursor ? '+' : ''} agents
              <ChevronRight size={14} aria-hidden />
            </Link>
          )}
        </>
      )}
    </section>
  );
}
