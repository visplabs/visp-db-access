import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import type { AgentStep, Cluster } from '../src/api/types';
import {
  approvalText,
  foldsSql,
  isFailed,
  isRead,
  isWrite,
  matches,
  needsDecision,
  reasonText,
  sessionPath,
  summarize,
  type TrailFilter,
} from '../src/features/agents/session-trail';
import { StepRow } from '../src/features/agents/session-page';

const step = (over: Partial<AgentStep>): AgentStep => ({
  n: 1,
  id: 'a',
  tool: 'run_query',
  task: 'Read',
  database: 'db',
  sql: 'SELECT 1',
  sql_truncated: false,
  verdict: 'allow',
  outcome: 'ok',
  fix: null,
  row_count: 1,
  elapsed_ms: 5,
  history_id: null,
  approval_id: null,
  created_at: '2026-01-01T00:00:00Z',
  ...over,
});
const stop = {
  action: 'stop',
  hint: 'This table is not available here.',
  told: 'The agent was told to stop.',
};
const trail: AgentStep[] = [
  step({
    n: 1,
    tool: 'list_databases',
    verdict: null,
    database: null,
    row_count: null,
  }),
  step({ n: 2, row_count: 4 }),
  step({ n: 3, tool: 'fetch_rows', verdict: null, row_count: 100 }),
  step({
    n: 4,
    tool: 'check_sql',
    verdict: 'deny',
    row_count: null,
    fix: stop,
  }),
  step({
    n: 5,
    outcome: 'query_denied',
    verdict: 'deny',
    row_count: null,
    fix: stop,
  }),
  step({
    n: 6,
    tool: 'propose_write',
    verdict: 'requires_approval',
    row_count: null,
    approval_id: 'r1',
  }),
  step({
    n: 7,
    tool: 'fetch_rows',
    outcome: 'result_expired',
    verdict: null,
    row_count: null,
  }),
];

describe('session trail logic', () => {
  it('counts what the steps say, and no masking it cannot know', () => {
    expect(summarize(trail)).toEqual({
      steps: 7,
      reads: 2,
      rows: 104,
      allowed: 1,
      held: 1,
      blocked: 2,
      failed: 1,
    });
    expect(summarize([])).toMatchObject({ steps: 0, rows: 0 });
    expect(summarize(trail)).not.toHaveProperty('masked');
  });
  it('filters the trail by each count', () => {
    const by = (filter: TrailFilter) =>
      trail.filter((s) => matches(s, filter)).map((s) => s.n);
    expect(by('all')).toEqual([1, 2, 3, 4, 5, 6, 7]);
    expect(by('reads')).toEqual([2, 3]);
    expect(by('rows')).toEqual([2, 3]);
    expect(by('allowed')).toEqual([2]);
    expect(by('held')).toEqual([6]);
    expect(by('blocked')).toEqual([4, 5]);
    expect(by('failed')).toEqual([7]);
  });
  it('knows reads, writes and failures', () => {
    expect(isRead(step({}))).toBe(true);
    expect(isRead(step({ outcome: 'query_denied' }))).toBe(false);
    expect(isRead(step({ tool: 'check_sql' }))).toBe(false);
    expect(isWrite(step({ tool: 'propose_write' }))).toBe(true);
    expect(isWrite(step({ outcome: 'approval_required' }))).toBe(true);
    expect(isWrite(step({}))).toBe(false);
    expect(isFailed(step({ outcome: 'timeout', verdict: null }))).toBe(true);
    expect(isFailed(step({ outcome: 'query_denied' }))).toBe(false);
    expect(isFailed(step({}))).toBe(false);
  });
  it('says why in plain words, from the verdict and the code only', () => {
    expect(reasonText(step({}))).toBeNull();
    expect(reasonText(step({ verdict: 'deny' }))).toBe(
      'The guard refused the statement.',
    );
    expect(
      reasonText(
        step({ outcome: 'approval_required', verdict: 'requires_approval' }),
      ),
    ).toBe('The statement changes data, so it did not run.');
    expect(reasonText(step({ verdict: 'requires_approval' }))).toBe(
      'A person must approve this write before it runs.',
    );
    expect(
      reasonText(
        step({
          outcome: 'query_denied',
          verdict: 'requires_approval',
          fix: { action: 'rewrite_sql', hint: 'x', told: 'y' },
        }),
      ),
    ).toBe('The statement locks rows, so it did not run.');
    expect(
      reasonText(step({ outcome: 'budget_exceeded', verdict: null })),
    ).toBe('The agent has used its hourly query budget.');
    expect(reasonText(step({ outcome: 'something_new', verdict: null }))).toBe(
      'The call did not finish.',
    );
    expect(needsDecision(step({}))).toBe(false);
    expect(needsDecision(step({ verdict: 'deny' }))).toBe(true);
    expect(needsDecision(step({ outcome: 'timeout', verdict: null }))).toBe(
      true,
    );
  });
  it('folds only SQL that does not fit one line', () => {
    expect(foldsSql('SELECT 1')).toBe(false);
    expect(foldsSql('SELECT 1\nFROM t')).toBe(true);
    expect(foldsSql(`SELECT ${'x, '.repeat(40)}y FROM t`)).toBe(true);
  });
  it('gives a session its own address and every request state words', () => {
    expect(sessionPath('a 1', 's/2')).toBe('/agents/a%201/sessions/s%2F2');
    expect(Object.values(approvalText).every((t) => t.length > 3)).toBe(true);
  });
});

describe('a step of the trail', () => {
  const cluster = {
    id: 'db',
    name: 'commerce-primary',
    environment: 'production',
  } as Cluster;
  const render = (
    s: AgentStep,
    approval?: Parameters<typeof StepRow>[0]['approval'],
  ) =>
    renderToStaticMarkup(
      <MemoryRouter>
        <StepRow step={s} cluster={cluster} approval={approval} />
      </MemoryRouter>,
    );
  it('marks a refused step with its verdict, why and the exact words the agent read', () => {
    const html = render(trail[4]!);
    expect(html).toContain('data-verdict="blocked"');
    expect(html).toContain('Blocked');
    expect(html).toContain('The guard refused the statement.');
    expect(html).toContain('What the agent was told');
    expect(html).toContain('<code>query_denied</code>');
    expect(html).toContain(
      '<blockquote>This table is not available here.</blockquote>',
    );
    expect(html).toContain('The agent was told to stop.');
    // Held and refused SQL is open, in a region to scroll.
    expect(html).toContain('aria-label="SQL of step 5"');
  });
  it('shows an accepted call quietly, with no decision panel', () => {
    const html = render(step({ n: 2, history_id: 'h1', row_count: 4 }));
    expect(html).toContain('data-verdict="allowed"');
    expect(html).not.toContain('What the agent was told');
    expect(html).not.toContain('trail-why');
    expect(html).toContain('4 rows returned');
    expect(html).toContain('commerce-primary');
    expect(html).toContain('href="/history?cluster_id=db&amp;entry=h1"');
  });
  it('has no chip when the gate made no decision', () => {
    const html = render(trail[0]!);
    expect(html).toContain('data-verdict="none"');
    expect(html).not.toContain('verdict-chip');
    const failed = render(trail[6]!);
    expect(failed).toContain('data-verdict="failed"');
    expect(failed).toContain('Failed');
    expect(failed).not.toContain('verdict-chip');
    expect(failed).toContain('The rows it asked for were no longer held.');
  });
  it('folds long SQL to one line with a control to open it', () => {
    const long = `SELECT ${'column_name, '.repeat(12)}id FROM orders`;
    const html = render(step({ sql: long }));
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain('Show all SQL');
    expect(html).not.toContain('role="region"');
  });
  it('marks a write that ran after a person approved it', () => {
    const write = trail[5]!;
    const waiting = render(write);
    expect(waiting).toContain('Write');
    expect(waiting).toContain('data-verdict="held"');
    expect(waiting).toContain('>Approval request<');
    expect(waiting).not.toContain('data-ran');
    const ran = render(write, 'executed');
    expect(ran).toContain('data-ran="true"');
    expect(ran).toContain('Ran after approval');
    expect(ran).toContain('data-verdict="allowed"');
    expect(ran).toContain('Approval request and receipt');
    expect(render(write, 'rejected')).toContain('Rejected by a person');
    // A request that ended without a decision has words, no chip.
    const expired = render(write, 'expired');
    expect(expired).toContain('The request expired');
  });
});
