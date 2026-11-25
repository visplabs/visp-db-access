import { useState } from 'react';
import { useUser } from '../auth/session';
import { Link } from 'react-router-dom';
import { Check } from 'lucide-react';
import type {
  Agent,
  AuditEvent,
  Cluster,
  HistoryEntry,
  Page,
  User,
} from '../../api/types';
import { useResource } from '../../lib/query';
import { setupSteps } from '../../lib/workspace';
import { Button, ErrorPanel, Skeleton } from '../../components/ui';

/** A new workspace's guided path. All completion evidence comes from API
 * data; nothing is checked off locally. It leads the page until every step
 * is done or it is dismissed, then it is gone. */
export function SetupChecklist() {
  const user = useUser();
  const dismissalKey = `vda.setup.dismissed.${user?.id}`;
  const [all, setAll] = useState(false);
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem(dismissalKey) === '1';
    } catch {
      return false;
    }
  });
  const clusters = useResource<{ items: Cluster[] }>('/clusters'),
    users = useResource<{ items: User[] }>('/users'),
    history = useResource<Page<HistoryEntry>>('/history?status=ok&limit=1'),
    audit = useResource<Page<AuditEvent>>(
      '/audit?action=policy.update&limit=50',
    ),
    // An administrator lists every agent: one is enough to check it off.
    agents = useResource<Page<Agent>>('/agents?limit=1');
  if (dismissed) return null;
  const reads = [clusters, users, history, audit, agents];
  if (reads.some((read) => read.isPending)) return <Skeleton />;
  const error = reads.find((read) => read.error)?.error;
  if (error)
    return (
      <ErrorPanel
        error={error}
        retry={() => reads.forEach((read) => void read.refetch())}
      />
    );
  const clusterIds = new Set(clusters.data?.items.map((c) => c.id));
  const [database, policy, teammate, query] = setupSteps({
    clusters: clusters.data?.items.length ?? 0,
    policiesReviewed: new Set(
      audit.data?.items
        .map((event) => event.target_id)
        .filter((id): id is string => id !== null && clusterIds.has(id)),
    ).size,
    users: users.data?.items.filter((member) => !member.disabled).length ?? 0,
    queries: history.data?.items.length ?? 0,
  });
  const complete = [
    !!database,
    !!policy,
    (agents.data?.items.length ?? 0) > 0,
    !!teammate,
    !!query,
  ];
  if (complete.every(Boolean)) return null;
  const dismiss = () => {
    try {
      localStorage.setItem(dismissalKey, '1');
    } catch {
      /* Session-only dismissal remains available. */
    }
    setDismissed(true);
    // The button is gone with the checklist: the focus goes to the heading.
    requestAnimationFrame(() => document.getElementById('ov-title')?.focus());
  };
  const cluster = clusters.data?.items[0];
  const steps = [
    {
      title: 'Add a database',
      detail: 'Point the gate at a PostgreSQL or MySQL server.',
      to: '/clusters?add=true',
    },
    {
      title: 'Review its safety policy',
      detail: 'Row limits, masked columns and which writes wait for a person.',
      to: cluster ? `/clusters/${cluster.id}?tab=policy` : '/clusters?add=true',
    },
    {
      title: 'Connect an agent',
      detail:
        'Give Claude Code, Cursor or another MCP client its own token. Its calls go through the guard.',
      to: '/agents?connect=1',
    },
    {
      title: 'Invite a teammate',
      detail: 'Someone else to review the writes that are held.',
      to: '/users?add=true',
    },
    {
      title: 'Run a first query',
      detail: 'A small SELECT through the gate, from the console.',
      to: cluster ? `/console?cluster_id=${cluster.id}` : '/clusters?add=true',
    },
  ];
  const done = complete.filter(Boolean).length;
  const next = complete.findIndex((step) => !step);
  return (
    <section
      className="ov-setup"
      aria-label="Workspace setup"
      data-all={all || undefined}
    >
      <header className="ov-setup-head">
        <div>
          <h2>Set up the gate</h2>
          <p>
            {done} of {steps.length} done. Each step checks itself off when the
            gate sees it.
          </p>
        </div>
        <Button variant="ghost" size="small" onClick={dismiss}>
          Dismiss setup
        </Button>
      </header>
      <div
        className="ov-setup-meter"
        role="progressbar"
        aria-label="Setup progress"
        aria-valuemin={0}
        aria-valuemax={steps.length}
        aria-valuenow={done}
      >
        {steps.map((step, index) => (
          <i key={step.title} data-done={complete[index] || undefined} />
        ))}
      </div>
      <ol className="ov-setup-steps">
        {steps.map((step, index) => {
          const state = complete[index]
            ? 'done'
            : index === next
              ? 'next'
              : 'todo';
          return (
            <li key={step.title} data-state={state}>
              <span className="ov-setup-mark" aria-hidden>
                {state === 'done' ? (
                  <Check size={14} strokeWidth={2.5} />
                ) : (
                  index + 1
                )}
              </span>
              <div>
                <span className="sr-only">
                  {state === 'done' ? 'Completed: ' : `Step ${index + 1}: `}
                </span>
                {state === 'next' ? (
                  <strong>{step.title}</strong>
                ) : (
                  <Link to={step.to}>{step.title}</Link>
                )}
                <p>{step.detail}</p>
                {state === 'next' && (
                  <Link className="button primary" to={step.to}>
                    {step.title}
                  </Link>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      {/* On a phone only the next step shows, so that setup does not fill
          the first screen; this shows the others. */}
      <button
        type="button"
        className="ov-setup-all"
        aria-expanded={all}
        onClick={() => setAll(!all)}
      >
        {all ? 'Show the next step only' : `Show all ${steps.length} steps`}
      </button>
    </section>
  );
}
