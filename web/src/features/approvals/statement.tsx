import { Ban, CircleCheck, Info, TriangleAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { Analysis } from '../../api/types';
import { RiskMeter, SqlText, VerdictChip } from '../../components/ui';
import { guardedSqlChanged, sqlDiff } from '../../lib/sql-diff';
import { verdictOfAnalysis } from '../../lib/verdict';
import {
  checksOf,
  formatSql,
  statementLine,
  type CheckLevel,
} from './decision';

/** The statement once. When the gate changes what runs, the change is shown
 * inline: lines it adds are marked, lines it removes struck through. */
export function StatementSection({
  sql,
  rewritten,
}: {
  sql: string;
  rewritten: string | null;
}) {
  const changed = !!rewritten && guardedSqlChanged(sql, rewritten);
  return (
    <section className="ar-statement" aria-label="Statement">
      <h3 className="ar-section-title">
        {changed ? 'What will run' : 'Statement'}
        {changed && (
          <span className="ar-legend">
            <ins>+</ins> added by the gate, <del>−</del> removed
          </span>
        )}
      </h3>
      {changed ? (
        <pre className="ar-sql" tabIndex={0} aria-label="SQL preview">
          {sqlDiff(formatSql(sql), formatSql(rewritten)).map((line, index) => (
            <span className="ar-sql-line" data-diff={line.kind} key={index}>
              <span className="ar-sql-mark" aria-hidden="true">
                {line.kind === 'added'
                  ? '+'
                  : line.kind === 'removed'
                    ? '−'
                    : ''}
              </span>
              {line.kind !== 'same' && (
                <span className="sr-only">
                  {line.kind === 'added' ? 'Added: ' : 'Removed: '}
                </span>
              )}
              <SqlText sql={line.text} />
              {'\n'}
            </span>
          ))}
        </pre>
      ) : (
        <pre className="ar-sql" tabIndex={0} aria-label="SQL preview">
          <SqlText sql={formatSql(sql)} />
        </pre>
      )}
    </section>
  );
}

const ICON: Record<CheckLevel, typeof Ban> = {
  block: Ban,
  warn: TriangleAlert,
  note: Info,
  pass: CircleCheck,
};
const WORD: Record<CheckLevel, string> = {
  block: 'Blocks',
  warn: 'Warns',
  note: 'Note',
  pass: 'Passes',
};

/** The guard's findings: the overall verdict and risk, then one row each. */
export function ChecksSection({
  analysis,
  clusterId,
  decided = false,
}: {
  analysis: Analysis;
  clusterId: string;
  /** The request is no longer waiting: the checks are what was found when it
   * was asked, not what is true now. */
  decided?: boolean;
}) {
  const verdict = verdictOfAnalysis(analysis);
  return (
    <section className="ar-checks" aria-label="Checks">
      <h3 className="ar-section-title">
        Checks
        <Link
          className="ar-quiet-link"
          to={`/clusters/${clusterId}?tab=policy`}
        >
          View policy
        </Link>
      </h3>
      <div className="ar-checks-summary">
        <VerdictChip
          verdict={verdict}
          label={decided && verdict === 'held' ? 'Held when asked' : undefined}
        />
        <RiskMeter risk={analysis.risk} />
        <span className="ar-statement-line">{statementLine(analysis)}</span>
      </div>
      <ul className="ar-check-list">
        {checksOf(analysis).map((check) => {
          const Icon = ICON[check.level];
          return (
            <li key={check.key} data-level={check.level}>
              <Icon size={14} strokeWidth={2.25} aria-hidden="true" />
              <span className="ar-check-word">{WORD[check.level]}</span>
              <span>{check.text}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
