import { describe, expect, it } from 'vitest';
import {
  VERDICTS,
  verdictOfAnalysis,
  verdictOfApproval,
  verdictOfColumns,
  verdictOfGuard,
  verdictOfHistory,
  verdictOfPreflight,
  verdictOfResult,
  verdictOfStep,
} from '../src/lib/verdict';
import type {
  Approval,
  HistoryEntry,
  QueryResult,
  Verdict,
} from '../src/api/types';

describe('verdict vocabulary', () => {
  it('has four verdicts in reading order', () => {
    expect(VERDICTS).toEqual(['allowed', 'masked', 'held', 'blocked']);
  });

  it('maps the guard verdict', () => {
    expect(verdictOfGuard('allow')).toBe('allowed');
    expect(verdictOfGuard('requires_approval')).toBe('held');
    expect(verdictOfGuard('deny')).toBe('blocked');
    expect(verdictOfAnalysis({ verdict: 'deny' })).toBe('blocked');
  });

  it('maps the pre-flight state', () => {
    expect(verdictOfPreflight('safe')).toBe('allowed');
    expect(verdictOfPreflight('needs_approval')).toBe('held');
    expect(verdictOfPreflight('blocked')).toBe('blocked');
  });

  it('says masked when the policy hid a column of the rows', () => {
    const analysis = { verdict: 'allow' as Verdict };
    const column = (masked: boolean) => ({ masked });
    expect(verdictOfColumns([])).toBe('allowed');
    expect(verdictOfColumns([column(false), column(true)])).toBe('masked');
    const result = (masked: boolean) =>
      ({
        columns: [{ name: 'email', type_name: 'text', masked }],
        analysis,
      }) as Pick<QueryResult, 'columns' | 'analysis'>;
    expect(verdictOfResult(result(true))).toBe('masked');
    expect(verdictOfResult(result(false))).toBe('allowed');
  });

  it('maps every history status', () => {
    const table: [HistoryEntry['status'], Verdict, string | undefined][] = [
      ['blocked', 'deny', 'blocked'],
      ['blocked', 'allow', 'blocked'], // cost_exceeded
      ['blocked', 'requires_approval', 'held'],
      ['ok', 'allow', 'allowed'],
      ['ok', 'requires_approval', 'allowed'], // an approved write ran
      ['running', 'allow', 'allowed'],
      ['error', 'allow', undefined],
      ['cancelled', 'allow', undefined],
      ['unknown', 'allow', undefined],
    ];
    for (const [status, verdict, expected] of table)
      expect(verdictOfHistory({ status, verdict }), status).toBe(expected);
  });

  it('maps every approval status', () => {
    const table: [Approval['status'], string | undefined][] = [
      ['pending', 'held'],
      ['approved', 'allowed'],
      ['executing', 'allowed'],
      ['executed', 'allowed'],
      ['rejected', 'blocked'],
      ['failed', undefined],
      ['expired', undefined],
      ['withdrawn', undefined],
    ];
    for (const [status, expected] of table)
      expect(verdictOfApproval(status), status).toBe(expected);
  });

  it('maps agent steps by outcome, then by verdict', () => {
    const step = (outcome: string, verdict: Verdict | null) => ({
      outcome,
      verdict,
    });
    expect(verdictOfStep(step('approval_required', 'requires_approval'))).toBe(
      'held',
    );
    for (const code of [
      'query_denied',
      'forbidden',
      'not_found',
      'cost_exceeded',
      'too_many_denials',
      'budget_exceeded',
    ])
      expect(verdictOfStep(step(code, null)), code).toBe('blocked');
    for (const code of ['timeout', 'upstream', 'result_expired', 'busy'])
      expect(verdictOfStep(step(code, 'allow')), code).toBeUndefined();
    expect(verdictOfStep(step('ok', 'allow'))).toBe('allowed');
    expect(verdictOfStep(step('ok', 'requires_approval'))).toBe('held');
    expect(verdictOfStep(step('ok', 'deny'))).toBe('blocked'); // check_sql
    expect(verdictOfStep(step('ok', null))).toBeUndefined(); // list_databases
  });
});
