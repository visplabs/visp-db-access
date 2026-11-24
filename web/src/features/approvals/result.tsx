import type { QueryResult } from '../../api/types';
import { Button } from '../../components/ui';
import { presentCell } from '../../lib/result-presentation';
import { resultCsv, resultJson } from '../../lib/result-export';
import { cellText, download } from '../../lib/utils';

/** What the write returned; the interactive grid stays in the console. */
export function ApprovalResult({ result }: { result: QueryResult }) {
  return (
    <section aria-label="Execution result" className="ar-result">
      <p>
        <strong>
          {result.affected_rows !== null
            ? `${result.affected_rows.toLocaleString()} ${result.affected_rows === 1 ? 'row' : 'rows'} affected.`
            : `${result.rows.length.toLocaleString()} fetched rows.`}
        </strong>{' '}
        <span className="muted">
          {result.elapsed_ms} ms on the {result.routed_to}.
          {result.truncated &&
            ' The returned snapshot was truncated by the safety limit.'}
          {result.columns.some((column) => column.masked) &&
            ' Sensitive columns remain masked.'}
        </span>
      </p>
      {result.columns.length > 0 && (
        <div
          className="table-wrap ar-table-wrap"
          tabIndex={0}
          role="region"
          aria-label="Fetched execution rows"
        >
          <table className="ar-table">
            <thead>
              <tr>
                {result.columns.map((column, index) => (
                  <th key={index} scope="col">
                    {column.name}
                    {column.masked && ' · masked'}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row, index) => (
                <tr key={index}>
                  {row.map((value, cell) => (
                    <td
                      key={cell}
                      className={
                        ['number', 'uuid'].includes(
                          presentCell(value, result.columns[cell]!).kind,
                        )
                          ? 'mono'
                          : undefined
                      }
                    >
                      {value == null ? 'NULL' : cellText(value)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="ar-inline">
        <Button
          size="small"
          onClick={() =>
            download(
              `approval-${result.query_id}.csv`,
              resultCsv(result),
              'text/csv',
            )
          }
        >
          Export CSV
        </Button>
        <Button
          size="small"
          onClick={() =>
            download(
              `approval-${result.query_id}.json`,
              resultJson(result),
              'application/json',
            )
          }
        >
          Export JSON
        </Button>
      </div>
    </section>
  );
}
