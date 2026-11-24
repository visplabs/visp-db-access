import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import type { Agent, AgentSession, AgentSteps, Page } from '../../api/types';
import { request } from '../../api/client';
import { useResource } from '../../lib/query';
import { Button, ErrorPanel, Skeleton } from '../../components/ui';
import { RelativeTime } from '../../components/ui/time';
import { formatTime } from '../../lib/utils';
import {
  earlierRange,
  firstMarker,
  mergeSteps,
  PAST_ALL,
  pollEvery,
  prependSteps,
  sessionState,
  type Loaded,
} from '../../lib/sessions';
import { sessionPath } from './session-trail';

const PAGE = 20;

/** The sessions of one agent, newest first. Each opens its own page. */
export function SessionList({ agent }: { agent: Agent }) {
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
            className="table-wrap session-list"
            tabIndex={0}
            role="region"
            aria-label="Sessions list"
          >
            <table aria-label="Sessions">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Last step</th>
                  <th className="numeric">Steps</th>
                  <th className="numeric">Refused</th>
                  <th>First task</th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.items.map((session) => (
                  <tr key={session.id}>
                    <td>
                      <Link
                        className="strong"
                        to={sessionPath(agent.id, session.id)}
                        aria-label={`Open session started ${formatTime(session.started_at)}`}
                      >
                        {formatTime(session.started_at)}
                      </Link>{' '}
                      {session.active && (
                        <span
                          className="trail-live"
                          data-state={agent.paused ? 'paused' : 'live'}
                        >
                          {sessionState(session, agent.paused)}
                        </span>
                      )}
                    </td>
                    <td>
                      <RelativeTime value={session.last_step_at} />
                    </td>
                    <td className="numeric">
                      {session.steps.toLocaleString('en')}
                    </td>
                    <td className="numeric">
                      {session.refusals.toLocaleString('en')}
                    </td>
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
export function useHidden() {
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
 * The steps of one session, read live. While the session is going on, its
 * agent may act and the page is visible, the list asks every few seconds for
 * the steps after the last one it has. `paused` is true until the agent is
 * known, so nothing is read on a timer for an agent that may be paused.
 */
export function useSessionSteps(
  agentId: string,
  sessionId: string,
  paused: boolean,
) {
  const path = `/agents/${agentId}/sessions/${sessionId}/steps`;
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
    // A session that is not there will not appear: no retry.
    retry: (count, error) =>
      !(error as { status?: number }).status?.toString().startsWith('4') &&
      count < 3,
    // No reading on a timer for a session that is over, a paused agent or a
    // hidden page; and none when the window gets focus either, for a
    // session that cannot change.
    refetchInterval: (query) =>
      pollEvery(query.state.data?.session, hidden, paused),
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
  return { steps, earlier, from };
}
