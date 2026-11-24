import type { Risk } from '../../api/types';

const RISKS: Risk[] = ['low', 'medium', 'high', 'critical'];
const riskWord = (risk: Risk) => risk.charAt(0).toUpperCase() + risk.slice(1);

/** The guard's risk of a statement: four steps filled up to it and the
 * word, so the colour is never the only sign. `compact` drops the visible
 * "risk" for dense rows; a screen reader still hears it. */
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
      className="risk-gauge"
      data-risk={risk}
      data-compact={compact || undefined}
    >
      <span className="risk-gauge-bars" aria-hidden="true">
        {RISKS.map((step, index) => (
          <i key={step} data-on={index <= level || undefined} />
        ))}
      </span>
      <span>
        {riskWord(risk)}
        {compact ? <span className="sr-only"> risk</span> : ' risk'}
      </span>
    </span>
  );
}
