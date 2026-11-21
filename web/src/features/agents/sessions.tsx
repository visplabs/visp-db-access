import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  CircleAlert,
  CircleCheck,
  CircleSlash,
  UserRoundCheck,
} from 'lucide-react';
import type {
  Agent,
  AgentSession,
  AgentStep,
  AgentSteps,
  Cluster,
  Page,
} from '../../api/types';
import { request } from '../../api/client';
import { useAction, useResource } from '../../lib/query';
import { Badge, Button, ErrorPanel, Skeleton } from '../../components/ui';
import { RelativeTime } from '../../components/ui/time';
import { formatTime } from '../../lib/utils';
import {
  answerText,
  approvalLink,
  earlierRange,
  firstMarker,
  historyLink,
  markText,
  mergeSteps,
  PAST_ALL,
  pollEvery,
  prependSteps,
  rowsText,
  sessionState,
  stepMark,
  toolText,
  type Loaded,
  type StepMark,
} from '../../lib/sessions';

const PAGE = 20;

/** The sessions of one agent, newest first. */
export function SessionList({
  agent,
  onOpen,
}: {
  agent: Agent;
  onOpen: (session: string) => void;
}) {
  const [limit, setLimit] = useState(PAGE);
  // Read again now and then, so a session that just began shows up.
  const sessions = useResource<Page<AgentSession>>(
    `/agents/${agent.id}/sessions?limit=${limit}`,
    true,
    // A paused agent starts no session.
    agent.paused ? undefined : 10_000,
  );
  return (
    <>
      <h3>Sessions</h3>
      <p className="muted">
        What the agent did, call by call. A session is a run of calls of one
        token with no gap longer than 30 minutes. Steps keep the SQL, never the
        rows.
      </p>
      {sessions.isPending ? (
        <Skeleton />
      ) : sessions.error ? (
        <ErrorPanel
          error={sessions.error}
          retry={() => void sessions.refetch()}
        />
      ) : sessions.data.items.length === 0 ? (
        <p className="muted">This agent has made no call yet.</p>
      ) : (
        <>
          <div
            className="table-wrap"
            tabIndex={0}
            role="region"
            aria-label="Sessions list"
          >
            <table aria-label="Sessions">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Last step</th>
                  <th>Steps</th>
                  <th>Refused</th>
                  <th>First task</th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.items.map((session) => (
                  <tr key={session.id}>
                    <td>
                      <button
                        type="button"
                        className="link-button strong"
                        aria-label={`Open session started ${formatTime(session.started_at)}`}
                        onClick={() => onOpen(session.id)}
                      >
                        {formatTime(session.started_at)}
                      </button>{' '}
                      {session.active && (
                        <Badge tone={agent.paused ? 'warning' : 'success'}>
                          {sessionState(session, agent.paused)}
                        </Badge>
                      )}
                    </td>
                    <td>
                      <RelativeTime value={session.last_step_at} />
                    </td>
                    <td>{session.steps.toLocaleString('en')}</td>
                    <td>{session.refusals.toLocaleString('en')}</td>
                    <td className="session-task">
                      {session.first_task ?? (
                        <span className="muted">No task given</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {sessions.data.next_cursor && limit < 200 && (
            <Button onClick={() => setLimit(Math.min(200, limit + 60))}>
              Show older sessions
            </Button>
          )}
        </>
      )}
    </>
  );
}

/** Whether the page is hidden; a hidden page reads nothing. */
function useHidden() {
  const [hidden, setHidden] = useState(
    () => typeof document !== 'undefined' && document.hidden,
  );
  useEffect(() => {
    const listener = () => setHidden(document.hidden);
    document.addEventListener('visibilitychange', listener);
    return () => document.removeEventListener('visibilitychange', listener);
  }, []);
  return hidden;
}

/**
 * One session: a live list of its steps. While the session is going on and
 * the page is visible, the list asks every few seconds for the steps after
 * the last one it has.
 */
export function SessionView({
  agent,
  sessionId,
  clusters,
  onBack,
}: {
  agent: Agent;
  sessionId: string;
  clusters: Map<string, Cluster>;
  onBack: () => void;
}) {
  const path = `/agents/${agent.id}/sessions/${sessionId}/steps`;
  const key = ['api', path];
  const cache = useQueryClient();
  const hidden = useHidden();
  const read = (after: number, limit = 200, signal?: AbortSignal) =>
    request<AgentSteps>(`${path}?after=${after}&limit=${limit}`, { signal });
  const steps = useQuery({
    queryKey: key,
    queryFn: async ({ signal }): Promise<Loaded> => {
      const before = cache.getQueryData<Loaded>(key);
      // The first read begins at the newest steps of the session; every
      // later one asks only for the steps after the last one it has.
      const from =
        before?.from ?? firstMarker((await read(PAST_ALL, 1, signal)).session);
      let known = mergeSteps(
        before,
        await read(before?.after ?? from, 200, signal),
      );
      // A hard stop, so a server fault can never loop forever.
      for (let page = 0; known.more && page < 50; page += 1)
        known = mergeSteps(known, await read(known.after, 200, signal));
      return { ...known, from };
    },
    // No reading on a timer for a session that is over, a paused agent or a
    // hidden page; and none when the window gets focus either, for a
    // session that cannot change.
    refetchInterval: (query) =>
      pollEvery(query.state.data?.session, hidden, agent.paused),
    refetchOnWindowFocus: (query) => query.state.data?.session.active !== false,
    refetchIntervalInBackground: false,
  });
  const from = steps.data?.from ?? 0;
  const earlier = useMutation({
    mutationFn: () => {
      const range = earlierRange(from);
      return read(range.after, range.limit);
    },
    onSuccess: (answer) =>
      cache.setQueryData<Loaded>(key, (known) =>
        known ? prependSteps(known, answer) : known,
      ),
  });
  const pause = useAction<Agent>(
    agent.paused ? 'Agent resumed' : 'Agent paused',
  );
  const region = useRef<HTMLElement>(null);
  useEffect(() => {
    region.current?.scrollIntoView({ block: 'nearest' });
    region.current?.focus({ preventScroll: true });
  }, []);
  const session = steps.data?.session;
  const count = steps.data?.items.length ?? 0;
  return (
    <section
      className="agent-detail agent-session"
      aria-label={`Session of ${agent.name}`}
      ref={region}
      tabIndex={-1}
    >
      <header className="agent-detail-heading">
        <div>
          <Button variant="ghost" size="small" onClick={onBack}>
            <ArrowLeft size={14} aria-hidden="true" />
            Back to {agent.name}
          </Button>
          <h2>Session of {agent.name}</h2>
          {session && (
            <p className="muted">
              Started {formatTime(session.started_at)}. Token ending{' '}
              <span className="mono">{session.token.hint}</span>.{' '}
              {session.steps.toLocaleString('en')}{' '}
              {session.steps === 1 ? 'step' : 'steps'},{' '}
              {session.refusals.toLocaleString('en')} refused.
            </p>
          )}
        </div>
        <div className="agent-actions">
          {session && (
            <Badge
              tone={
                !session.active
                  ? 'neutral'
                  : agent.paused
                    ? 'warning'
                    : 'success'
              }
            >
              {sessionState(session, agent.paused)}
            </Badge>
          )}
          <Button
            variant={agent.paused ? 'secondary' : 'danger'}
            disabled={pause.isPending}
            onClick={() =>
              pause.mutate({
                path: `/agents/${agent.id}`,
                method: 'PATCH',
                body: { paused: !agent.paused },
              })
            }
          >
            {agent.paused ? 'Resume agent' : 'Pause agent'}
          </Button>
        </div>
      </header>
      {agent.paused && (
        <p className="agent-paused" role="status">
          This agent is paused. Its tokens are refused, and the queries it was
          running on this gateway were cancelled.
        </p>
      )}
      {/* Said once per change, not once per step. */}
      <p className="sr-only" role="status" aria-live="polite">
        {count > 0 ? `${count} ${count === 1 ? 'step' : 'steps'} shown.` : ''}
      </p>
      {steps.isPending ? (
        <Skeleton />
      ) : steps.error && !steps.data ? (
        <ErrorPanel error={steps.error} retry={() => void steps.refetch()} />
      ) : (
        <>
          {steps.error && (
            <p className="callout danger" role="alert">
              The list could not be read again. It shows what was read last.
            </p>
          )}
          {from > 0 && (
            <p className="session-earlier">
              <Button
                disabled={earlier.isPending}
                onClick={() => earlier.mutate()}
              >
                Show earlier steps
              </Button>{' '}
              <span className="muted">
                Steps 1 to {from.toLocaleString('en')} are not shown.
              </span>
            </p>
          )}
          <ol className="session-steps" aria-label="Steps">
            {steps.data?.items.map((step) => (
              <StepRow
                key={step.n}
                step={step}
                cluster={
                  step.database ? clusters.get(step.database) : undefined
                }
              />
            ))}
          </ol>
          {session && (
            <p className="muted session-foot">
              {!session.active
                ? 'This session is over. A new call of the token starts a new session.'
                : agent.paused
                  ? 'No new step can arrive while the agent is paused.'
                  : 'New steps appear here as the agent calls.'}
            </p>
          )}
        </>
      )}
    </section>
  );
}

const markIcon: Record<StepMark, typeof CircleCheck> = {
  ok: CircleCheck,
  approval: UserRoundCheck,
  refused: CircleSlash,
  failed: CircleAlert,
};

function StepRow({ step, cluster }: { step: AgentStep; cluster?: Cluster }) {
  const mark = stepMark(step);
  const Icon = markIcon[mark];
  const answer = answerText(step);
  const history = historyLink(step),
    approval = approvalLink(step);
  return (
    <li className={`session-step ${mark}`}>
      <div className="session-step-head">
        <span className="session-step-n">{step.n}</span>
        <span className={`session-mark ${mark}`}>
          <Icon size={15} aria-hidden="true" />
          {markText[mark]}
        </span>
        <span className="session-step-tool">
          {toolText[step.tool] ?? step.tool} <code>{step.tool}</code>
        </span>
        <time className="muted" dateTime={step.created_at}>
          {formatTime(step.created_at)}
        </time>
      </div>
      <p className="session-step-task">
        {step.task ?? <span className="muted">No valid task was given.</span>}
      </p>
      {(step.database || step.row_count !== null) && (
        <p className="muted session-step-facts">
          {step.database &&
            (cluster ? (
              <span className="identifier">{cluster.name}</span>
            ) : (
              <span>A database you cannot see</span>
            ))}
          {step.row_count !== null && (
            <span>{rowsText(step.row_count)} returned</span>
          )}
          <span>{step.elapsed_ms.toLocaleString('en')} ms</span>
        </p>
      )}
      {step.sql && (
        <>
          {/* A scrolling region: keyboard users focus it to scroll long SQL. */}
          <pre
            className="sql-preview-block session-step-sql"
            tabIndex={0}
            role="region"
            aria-label={`SQL of step ${step.n}`}
          >
            {step.sql}
          </pre>
          {step.sql_truncated && (
            <p className="muted">
              The statement is longer than a step keeps; this is its beginning.
            </p>
          )}
        </>
      )}
      {answer && (
        <div className="session-answer">
          <p>
            <strong>Guard&apos;s answer:</strong> {answer}
            {step.outcome !== 'ok' && (
              <>
                {' '}
                <code>{step.outcome}</code>
              </>
            )}
          </p>
          {step.fix && (
            <p className="muted">What the agent read: “{step.fix.hint}”</p>
          )}
        </div>
      )}
      {(history || approval) && (
        <p className="session-step-links">
          {history && <Link to={history}>History entry</Link>}
          {approval && <Link to={approval}>Approval request</Link>}
        </p>
      )}
    </li>
  );
}
