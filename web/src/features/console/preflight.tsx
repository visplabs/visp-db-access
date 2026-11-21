import { memo, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Play,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  Square,
} from 'lucide-react';
import type { Environment, GuardChange, Preflight } from '../../api/types';
import { Button } from '../../components/ui';
import { spoken, stateLabel, type CheckStatus } from '../../lib/preflight';

const runLabel = (environment: Environment) =>
  environment === 'production'
    ? 'Run on production'
    : environment === 'staging'
      ? 'Run on staging'
      : 'Run';

/**
 * The pre-flight bar: the state of the safety check, one sentence of why,
 * and the one next step. It is always on screen, next to the button it
 * explains. The state is said in words and with a mark, never by colour
 * alone.
 */
export const PreflightBar = memo(function PreflightBar({
  preflight,
  status,
  can,
  running,
  cancelling,
  environment,
  clusterId,
  detailsOpen,
  onRun,
  onRequest,
  onApplyFix,
  onCancel,
  onRetry,
  onDetails,
}: {
  preflight?: Preflight;
  status: CheckStatus;
  /** What the gate allows now; see `gate` in lib/preflight. */
  can: { run: boolean; request: boolean; fix: boolean };
  running: boolean;
  cancelling: boolean;
  environment: Environment;
  clusterId: string;
  detailsOpen: boolean;
  onRun: () => void;
  onRequest: () => void;
  onApplyFix: () => void;
  onCancel: () => void;
  onRetry: () => void;
  onDetails: () => void;
}) {
  // While the next answer loads, the last one stays on screen, dimmed.
  const shown = status === 'ready' || status === 'updating' ? preflight : null;
  const tone = !shown
    ? 'neutral'
    : shown.state === 'safe'
      ? 'success'
      : shown.state === 'needs_approval'
        ? 'warning'
        : 'danger';
  const Icon = !shown
    ? ShieldQuestion
    : shown.state === 'safe'
      ? ShieldCheck
      : shown.state === 'needs_approval'
        ? ShieldAlert
        : ShieldX;
  const title = shown
    ? stateLabel[shown.state]
    : status === 'failed'
      ? 'Check failed'
      : status === 'empty'
        ? 'Waiting for SQL'
        : 'Checking…';
  const why = shown
    ? shown.hint
    : status === 'failed'
      ? 'The safety check could not run, so nothing can run. Try the check again.'
      : status === 'empty'
        ? 'Write a statement, and the guard checks it before anything runs.'
        : 'The guard is checking this statement.';
  // Assistive technology hears the settled answer once. Text that changes
  // while a person types is not announced: only what stands after a pause,
  // and only when it differs from what was said last.
  const settled = spoken(status, preflight);
  const [said, setSaid] = useState('');
  useEffect(() => {
    if (!settled) return;
    const timer = setTimeout(() => setSaid(settled), 700);
    return () => clearTimeout(timer);
  }, [settled]);
  const action = shown?.action;
  return (
    <div
      className={`preflight-bar ${tone}`}
      role="group"
      aria-label="Pre-flight check"
      data-state={shown?.state ?? status}
      aria-busy={status === 'checking' || status === 'updating'}
    >
      <p className="sr-only" role="status" aria-live="polite">
        {said}
      </p>
      <div className="preflight-state">
        <Icon size={18} aria-hidden="true" />
        <strong>{title}</strong>
        {status === 'updating' && (
          <small className="preflight-updating">Updating…</small>
        )}
      </div>
      <div
        className={`preflight-why ${shown?.guard_change ? 'has-change' : ''}`}
      >
        <p>{why}</p>
        {shown?.guard_change && <GuardChangeLine change={shown.guard_change} />}
        {action === 'change_policy' && (
          <p>
            <Link to={`/clusters/${clusterId}?tab=policy`}>
              Open the policy
            </Link>
          </p>
        )}
      </div>
      <div className="preflight-actions">
        {!detailsOpen && (
          <Button
            variant="ghost"
            size="small"
            aria-label="Open safety analysis"
            onClick={onDetails}
          >
            Details
          </Button>
        )}
        {running && (
          <Button variant="danger" disabled={cancelling} onClick={onCancel}>
            <Square size={12} />
            Cancel
          </Button>
        )}
        {status === 'failed' ? (
          <Button variant="primary" onClick={onRetry}>
            Check again
          </Button>
        ) : action === 'request_approval' ? (
          <Button variant="primary" disabled={!can.request} onClick={onRequest}>
            Request approval…
          </Button>
        ) : action === 'apply_fix' ? (
          <Button
            variant="primary"
            disabled={!can.fix}
            title="Replaces the editor text (undo with Ctrl/Cmd+Z)"
            onClick={onApplyFix}
          >
            {shown?.label}
          </Button>
        ) : action === 'ask_admin' || action === 'change_policy' ? null : (
          // Only an administrator can help: no button, the sentence says who.
          // Otherwise the button keeps its place; while the statement is
          // blocked or not checked it cannot be used.
          <Button
            variant="primary"
            className={`run-${environment}`}
            disabled={!can.run}
            onClick={onRun}
          >
            <Play size={14} />
            {running ? 'Running…' : runLabel(environment)}
            <kbd>⌘ ↵</kbd>
          </Button>
        )}
      </div>
    </div>
  );
});

/** The guard's own sentence about its change, with the clause it adds
 * marked, so that it reads as SQL beside the SQL. */
function GuardChangeLine({ change }: { change: GuardChange }) {
  const at = change.text.lastIndexOf(`${change.clause}:`);
  return (
    <p className="preflight-change">
      {at < 0 ? (
        change.text
      ) : (
        <>
          {change.text.slice(0, at)}
          <code>
            <mark>{change.clause}</mark>
          </code>
          {/* On a narrow screen the reason is for the ear only. */}
          <span className="preflight-change-why">
            {change.text.slice(at + change.clause.length)}
          </span>
        </>
      )}
    </p>
  );
}
