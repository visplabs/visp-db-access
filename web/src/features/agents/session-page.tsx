import { useId, useMemo, useState, type ReactNode } from 'react';
import { useQueries } from '@tanstack/react-query';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { MessageSquareText, PenLine } from 'lucide-react';
import type { Agent, AgentStep, Approval, Cluster } from '../../api/types';
import { request } from '../../api/client';
import { useAction, useResource } from '../../lib/query';
import {
  ActorBadge,
  Button,
  Empty,
  EnvBadge,
  ErrorPanel,
  Skeleton,
  SqlText,
  VerdictChip,
} from '../../components/ui';
import { ClockTime, RelativeTime } from '../../components/ui/time';
import { formatTime } from '../../lib/utils';
import { verdictOfApproval, verdictOfStep } from '../../lib/verdict';
import {
  historyLink,
  approvalLink,
  rowsText,
  sessionState,
  toolText,
} from '../../lib/sessions';
import { useHidden, useSessionSteps } from './sessions';
import {
  approvalText,
  foldsSql,
  isFailed,
  isWrite,
  matches,
  needsDecision,
  reasonText,
  summarize,
  type TrailFilter,
} from './session-trail';

const FILTERS: readonly TrailFilter[] = [
  'all',
  'reads',
  'rows',
  'allowed',
  'held',
  'blocked',
  'failed',
];
const filterOf = (value: string | null): TrailFilter =>
  FILTERS.find((filter) => filter === value) ?? 'all';

/** A missing or invisible agent or session: the server says 404, or 400 for
 * an id that is not one. */
const isMissing = (error: unknown) => {
  const status = (error as { status?: number } | null)?.status;
  return status === 404 || status === 400;
};

/** One agent session on a page of its own: a decision trail of every call. */
export function SessionPage() {
  const { agentId = '', sessionId = '' } = useParams();
  const agent = useResource<Agent>(`/agents/${encodeURIComponent(agentId)}`);
  const clusters = useResource<{ items: Cluster[] }>('/clusters');
  const names = useMemo(
    () => new Map(clusters.data?.items.map((c) => [c.id, c]) ?? []),
    [clusters.data],
  );
  const paused = agent.data?.paused ?? true;
  const { steps, earlier, from } = useSessionSteps(
    encodeURIComponent(agentId),
    encodeURIComponent(sessionId),
    paused,
  );
  if (
    (agent.error && isMissing(agent.error)) ||
    (steps.error && !steps.data && isMissing(steps.error))
  )
    return <SessionMissing />;
  if (agent.error && !agent.data)
    return (
      <ErrorPanel error={agent.error} retry={() => void agent.refetch()} />
    );
  if (agent.isPending)
    return (
      <div className="trail-page">
        <Skeleton />
      </div>
    );
  return (
    <SessionTrail
      agent={agent.data}
      steps={steps}
      earlier={earlier}
      from={from}
      clusters={names}
    />
  );
}

function SessionMissing() {
  return (
    <div className="trail-page">
      <Crumbs />
      <Empty
        title="Session not found"
        description="It may have been deleted with its agent or after the retention time, or you may not be able to see this agent."
        action={
          <Link className="button primary" to="/agents">
            Back to agents
          </Link>
        }
      />
    </div>
  );
}

function Crumbs({ agent }: { agent?: Agent }) {
  return (
    <nav className="trail-crumbs" aria-label="Breadcrumb">
      <ol>
        <li>
          <Link to="/agents">Agents</Link>
        </li>
        {agent && (
          <li>
            <Link to={`/agents?agent=${encodeURIComponent(agent.id)}`}>
              {agent.name}
            </Link>
          </li>
        )}
        <li aria-current="page">Session</li>
      </ol>
    </nav>
  );
}

type Steps = ReturnType<typeof useSessionSteps>;

function SessionTrail({
  agent,
  steps,
  earlier,
  from,
  clusters,
}: {
  agent: Agent;
  steps: Steps['steps'];
  earlier: Steps['earlier'];
  from: number;
  clusters: Map<string, Cluster>;
}) {
  const [params, setParams] = useSearchParams();
  const filter = filterOf(params.get('show'));
  const setFilter = (next: TrailFilter) => {
    const query = new URLSearchParams(params);
    if (next === 'all') query.delete('show');
    else query.set('show', next);
    setParams(query, { replace: true });
  };
  const pause = useAction<Agent>(
    agent.paused ? 'Agent resumed' : 'Agent paused',
  );
  const session = steps.data?.session;
  const items = useMemo(() => steps.data?.items ?? [], [steps.data]);
  const sum = useMemo(() => summarize(items), [items]);
  const shown = items.filter((step) => matches(step, filter));
  const approvals = useApprovals(items);
  const count = items.length;
  const state = session ? sessionState(session, agent.paused) : null;
  return (
    <section className="trail-page" aria-label={`Session of ${agent.name}`}>
      <Crumbs agent={agent} />
      <header className="trail-head">
        <div className="trail-heading">
          <h1>
            {session
              ? `Session started ${formatTime(session.started_at)}`
              : 'Session'}
          </h1>
          <div className="trail-who">
            <ActorBadge kind="agent" name={agent.name} />
            <span>
              Owner <strong>{agent.owner.name}</strong>
            </span>
            {session && (
              <span>
                Token ending <span className="mono">{session.token.hint}</span>
              </span>
            )}
          </div>
          {session && (
            <p className="trail-times">
              Last step <RelativeTime value={session.last_step_at} />.{' '}
              {session.steps.toLocaleString('en')}{' '}
              {session.steps === 1 ? 'step' : 'steps'},{' '}
              {session.refusals.toLocaleString('en')} refused.
            </p>
          )}
        </div>
        <div className="trail-actions">
          {state && (
            <span
              // A new key per step restarts the pulse of the live dot.
              key={count}
              className="trail-live"
              data-state={
                state === 'Live'
                  ? 'live'
                  : state === 'Ended'
                    ? 'ended'
                    : 'paused'
              }
            >
              {state}
            </span>
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
          <Summary
            steps={items}
            sum={sum}
            filter={filter}
            onFilter={setFilter}
            from={from}
          />
          {from > 0 && (
            <p className="trail-earlier">
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
          {items.length === 0 ? (
            <p className="muted trail-empty">This session has no step left.</p>
          ) : shown.length === 0 ? (
            <div className="trail-empty">
              <p className="muted">No step matches this count.</p>
              <Button size="small" onClick={() => setFilter('all')}>
                Show all steps
              </Button>
            </div>
          ) : null}
          <TrailList
            steps={shown}
            last={items.at(-1)?.n ?? 0}
            clusters={clusters}
            approvals={approvals}
          />
          {session && (
            <p className="muted trail-foot">
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

/** The steps, oldest first. New steps join at the end, so nothing above
 * them moves; a step that arrives while the page is open gets a short, calm
 * highlight. */
function TrailList({
  steps,
  last,
  clusters,
  approvals,
}: {
  steps: readonly AgentStep[];
  last: number;
  clusters: Map<string, Cluster>;
  approvals: Map<string, Approval['status']>;
}) {
  // The last step there was when the list first showed.
  const [seen] = useState(last);
  return (
    <ol className="trail" aria-label="Steps">
      {steps.map((step) => (
        <StepRow
          key={step.n}
          step={step}
          cluster={step.database ? clusters.get(step.database) : undefined}
          approval={
            step.approval_id ? approvals.get(step.approval_id) : undefined
          }
          fresh={step.n > seen}
        />
      ))}
    </ol>
  );
}

/** The write requests that steps link to, read once each. A request the
 * viewer cannot see is left out: the step keeps its own verdict. */
function useApprovals(steps: readonly AgentStep[]) {
  const hidden = useHidden();
  const ids = [
    ...new Set(
      steps.map((step) => step.approval_id).filter((id): id is string => !!id),
    ),
  ];
  const results = useQueries({
    queries: ids.map((id) => ({
      queryKey: ['api', `/approvals/${id}`],
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        request<Approval>(`/approvals/${id}`, { signal }),
      retry: false,
      refetchOnWindowFocus: false,
      // A request that is not settled is read again now and then.
      refetchInterval: (query: { state: { data?: Approval } }) =>
        !hidden &&
        ['pending', 'approved', 'executing'].includes(
          query.state.data?.status ?? '',
        )
          ? 10_000
          : false,
    })),
  });
  const known = new Map<string, Approval['status']>();
  results.forEach((result, index) => {
    const id = ids[index];
    if (id && result.data) known.set(id, result.data.status);
  });
  return known;
}

const COUNT_LABEL: Record<TrailFilter, string> = {
  all: 'Steps',
  reads: 'Reads',
  rows: 'Rows returned',
  allowed: 'Allowed',
  held: 'Held',
  blocked: 'Blocked',
  failed: 'Failed',
};

function Summary({
  steps,
  sum,
  filter,
  onFilter,
  from,
}: {
  steps: readonly AgentStep[];
  sum: ReturnType<typeof summarize>;
  filter: TrailFilter;
  onFilter: (filter: TrailFilter) => void;
  from: number;
}) {
  const value: Record<TrailFilter, number> = {
    all: sum.steps,
    reads: sum.reads,
    rows: sum.rows,
    allowed: sum.allowed,
    held: sum.held,
    blocked: sum.blocked,
    failed: sum.failed,
  };
  const button = (key: TrailFilter, label: ReactNode) => (
    <button
      key={key}
      type="button"
      className="trail-count"
      data-filter={key}
      aria-pressed={filter === key}
      onClick={() => onFilter(filter === key ? 'all' : key)}
    >
      <span className="trail-count-value">
        {value[key].toLocaleString('en')}
      </span>
      <span className="trail-count-label">{label}</span>
    </button>
  );
  return (
    <section className="trail-summary" aria-label="Summary">
      <Tape steps={steps} filter={filter} />
      <div
        className="trail-counts"
        role="group"
        aria-label="Show only the steps of a count"
      >
        <div className="trail-counts-set">
          {button('all', COUNT_LABEL.all)}
          {button('reads', COUNT_LABEL.reads)}
          {button('rows', COUNT_LABEL.rows)}
        </div>
        <div className="trail-counts-set" data-kind="verdicts">
          {button('allowed', <VerdictChip verdict="allowed" />)}
          {button('held', <VerdictChip verdict="held" />)}
          {button('blocked', <VerdictChip verdict="blocked" />)}
          {(sum.failed > 0 || filter === 'failed') &&
            button(
              'failed',
              <span className="trail-failed">{COUNT_LABEL.failed}</span>,
            )}
        </div>
      </div>
      {from > 0 && (
        <p className="muted trail-scope">
          Counts cover the steps shown, from step{' '}
          {(from + 1).toLocaleString('en')}.
        </p>
      )}
    </section>
  );
}

/** The session at a glance: one mark per step, oldest on the left, in the
 * colour of its verdict. Decisions stand tall; calls without one are short.
 * Words for the same facts are in the counts beside it. */
function Tape({
  steps,
  filter,
}: {
  steps: readonly AgentStep[];
  filter: TrailFilter;
}) {
  return (
    <div className="trail-tape" aria-hidden="true">
      {steps.map((step) => (
        <span
          key={step.n}
          data-verdict={
            verdictOfStep(step) ?? (isFailed(step) ? 'failed' : 'none')
          }
          data-write={isWrite(step) || undefined}
          data-dim={(filter !== 'all' && !matches(step, filter)) || undefined}
        />
      ))}
    </div>
  );
}

export function StepRow({
  step,
  cluster,
  approval,
  fresh = false,
}: {
  step: AgentStep;
  cluster?: Cluster;
  approval?: Approval['status'];
  fresh?: boolean;
}) {
  const verdict = verdictOfStep(step);
  const failed = isFailed(step);
  const write = isWrite(step);
  const ran = approval === 'executed';
  const reason = reasonText(step);
  const history = historyLink(step),
    requestLink = approvalLink(step);
  const requestVerdict = approval ? verdictOfApproval(approval) : undefined;
  return (
    <li
      className="trail-step"
      data-verdict={verdict ?? (failed ? 'failed' : 'none')}
      data-write={write || undefined}
      data-ran={ran || undefined}
      data-new={fresh || undefined}
    >
      <span className="trail-node" aria-hidden="true">
        {step.n}
      </span>
      <div className="trail-body">
        <div className="trail-line">
          <span className="sr-only">Step {step.n}.</span>
          {verdict ? (
            <VerdictChip verdict={verdict} />
          ) : failed ? (
            <span className="trail-failed">Failed</span>
          ) : null}
          <span className="trail-tool">
            {toolText[step.tool] ?? step.tool} <code>{step.tool}</code>
          </span>
          {write && (
            <span className="trail-write">
              <PenLine size={12} strokeWidth={2.25} aria-hidden="true" />
              Write
            </span>
          )}
          <span className="trail-time">
            <ClockTime value={step.created_at} />
          </span>
        </div>
        <div className="trail-what">
          <p className="trail-task">
            {step.task ?? (
              <span className="muted">No valid task was given.</span>
            )}
          </p>
          {(step.database ||
            step.row_count !== null ||
            step.elapsed_ms > 0) && (
            <p className="trail-facts">
              {step.database &&
                (cluster ? (
                  <span>
                    <span className="identifier">{cluster.name}</span>{' '}
                    <EnvBadge environment={cluster.environment} />
                  </span>
                ) : (
                  <span>A database you cannot see</span>
                ))}
              {step.row_count !== null && (
                <span>{rowsText(step.row_count)} returned</span>
              )}
              <span>{step.elapsed_ms.toLocaleString('en')} ms</span>
            </p>
          )}
        </div>
        {step.sql && (
          <StepSql
            n={step.n}
            sql={step.sql}
            truncated={step.sql_truncated}
            open={verdict === 'held' || verdict === 'blocked'}
          />
        )}
        {needsDecision(step) && (
          <div className="trail-decision">
            {reason && (
              <p className="trail-why">
                <strong>Why</strong> <span>{reason}</span>
              </p>
            )}
            {(step.fix || step.outcome !== 'ok') && (
              <figure className="trail-told">
                <figcaption>
                  <span>
                    <MessageSquareText
                      size={14}
                      strokeWidth={2}
                      aria-hidden="true"
                    />
                    What the agent was told
                  </span>
                  {step.outcome !== 'ok' && <code>{step.outcome}</code>}
                </figcaption>
                {step.fix ? (
                  <>
                    <blockquote>{step.fix.hint}</blockquote>
                    <p className="trail-told-gist">{step.fix.told}</p>
                  </>
                ) : (
                  <p className="trail-told-gist">
                    An error with this code, and no advice.
                  </p>
                )}
              </figure>
            )}
          </div>
        )}
        {approval && (
          <p className="trail-request">
            <span>Its request:</span>
            {requestVerdict ? (
              <VerdictChip
                verdict={requestVerdict}
                label={approvalText[approval]}
              />
            ) : (
              <span className="muted">{approvalText[approval]}</span>
            )}
          </p>
        )}
        {(history || requestLink) && (
          <p className="trail-links">
            {history && <Link to={history}>History entry</Link>}
            {requestLink && (
              <Link to={requestLink}>
                {ran ? 'Approval request and receipt' : 'Approval request'}
              </Link>
            )}
          </p>
        )}
      </div>
    </li>
  );
}

function StepSql({
  n,
  sql,
  truncated,
  open: initial,
}: {
  n: number;
  sql: string;
  truncated: boolean;
  open: boolean;
}) {
  const folds = foldsSql(sql);
  const [open, setOpen] = useState(initial || !folds);
  const id = useId();
  return (
    <div className="trail-sql" data-open={open}>
      {open ? (
        // A scrolling region: keyboard users focus it to scroll long SQL.
        <pre
          id={id}
          className="trail-sql-text"
          tabIndex={0}
          role="region"
          aria-label={`SQL of step ${n}`}
        >
          <SqlText sql={sql} />
        </pre>
      ) : (
        <code id={id} className="trail-sql-line">
          <SqlText sql={sql.replace(/\s+/g, ' ')} />
        </code>
      )}
      {folds && (
        <button
          type="button"
          className="link-button trail-sql-toggle"
          aria-expanded={open}
          aria-controls={id}
          onClick={() => setOpen(!open)}
        >
          {open ? 'Fold SQL' : 'Show all SQL'}
        </button>
      )}
      {truncated && (
        <p className="muted">
          The statement is longer than a step keeps; this is its beginning.
        </p>
      )}
    </div>
  );
}
