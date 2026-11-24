import { Ban, CircleCheck, Info, TriangleAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { Analysis, Risk } from '../../api/types';
import { VerdictChip } from '../../components/ui';
import { sqlParts } from '../../lib/activity';
import { guardedSqlChanged, sqlDiff } from '../../lib/sql-diff';
import { verdictOfAnalysis } from '../../lib/verdict';
import {
  checksOf,
  formatSql,
  statementLine,
  type CheckLevel,
} from './decision';

/** SQL with its keywords and strings marked; text nodes keep it inert. */
export function SqlText({ sql }: { sql: string }) {
  return (
    <>
      {sqlParts(sql).map((part, index) =>
        part.kind === 'plain' ? (
          part.text
        ) : (
          <span key={index} className={`sql-${part.kind}`}>
            {part.text}
          </span>
        ),
      )}
    </>
  );
}

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

const RISKS: Risk[] = ['low', 'medium', 'high', 'critical'];
const riskWord = (risk: Risk) => risk.charAt(0).toUpperCase() + risk.slice(1);

/** Four steps, filled up to the risk; the word says it, not the colour. */
export function RiskMeter({
  risk,
  compact = false,
}: {
  risk: Risk;
  compact?: boolean;
}) {
  const level = RISKS.indexOf(risk);
  return (
    <span
      className="ar-risk"
      data-risk={risk}
      data-compact={compact || undefined}
    >
      <span className="ar-risk-bars" aria-hidden="true">
        {RISKS.map((step, index) => (
          <i key={step} data-on={index <= level || undefined} />
        ))}
      </span>
      <span>
        {riskWord(risk)}
        {compact ? '' : ' risk'}
        {compact && <span className="sr-only"> risk</span>}
      </span>
    </span>
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
}: {
  analysis: Analysis;
  clusterId: string;
}) {
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
        <VerdictChip verdict={verdictOfAnalysis(analysis)} />
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
