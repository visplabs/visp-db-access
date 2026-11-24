import { Copy } from 'lucide-react';
import type { Approval, ReceiptCheck } from '../../api/types';
import { Badge, Button, ErrorPanel, Skeleton } from '../../components/ui';
import { useQuery } from '@tanstack/react-query';
import { request } from '../../api/client';
import { useCopy } from '../../lib/clipboard';
import { formatTime } from '../../lib/utils';
import {
  receiptState,
  receiptStateDetail,
  receiptStateText,
  rowsText,
  shortDigest,
} from '../../lib/approval-presentation';

const boundTo = {
  rows: 'These exact rows',
  count: 'The same number of rows',
} as const;
const tone = { valid: 'success', changed: 'danger', unverified: 'warning' };

/** The signed record of a write that ran, and whether it is intact. */
export function ReceiptSection({ approval }: { approval: Approval }) {
  const path = `/approvals/${approval.id}/receipt`;
  // Never from a cache: whether the record is intact is checked each time.
  const check = useQuery({
    queryKey: ['api', path],
    queryFn: ({ signal }) => request<ReceiptCheck>(path, { signal }),
    staleTime: 0,
    gcTime: 0,
    refetchOnMount: 'always',
  });
  const copy = useCopy();
  if (check.isPending)
    return (
      <section className="ar-receipt" aria-label="Receipt">
        <h4>Signed receipt</h4>
        <Skeleton />
      </section>
    );
  if (check.error)
    return (
      <section className="ar-receipt" aria-label="Receipt">
        <h4>Signed receipt</h4>
        <ErrorPanel error={check.error} retry={() => void check.refetch()} />
      </section>
    );
  const { receipt } = check.data,
    state = receiptState(check.data, approval);
  return (
    <section className="ar-receipt" aria-label="Receipt">
      <div className="ar-subhead">
        <h4>Signed receipt</h4>
        {/* A record that is not plainly valid is a risk: risk colour, with words. */}
        <Badge
          variant={state === 'valid' ? 'status' : 'verdict'}
          tone={tone[state]}
        >
          {receiptStateText[state]}
        </Badge>
      </div>
      {receiptStateDetail[state] && (
        <p className="ar-receipt-warning">{receiptStateDetail[state]}</p>
      )}
      <dl className="ar-receipt-list">
        <div>
          <dt>Asked by</dt>
          <dd>
            <span>
              {receipt.agent ? (
                <>
                  Agent <span className="identifier">{receipt.agent.name}</span>{' '}
                  for {receipt.requested_by.email}
                </>
              ) : (
                receipt.requested_by.email
              )}
            </span>
            <span className="muted">{formatTime(receipt.requested_at)}</span>
          </dd>
        </div>
        <div>
          <dt>Approved by</dt>
          <dd>
            {receipt.approved_by.email}
            <span className="muted">{formatTime(receipt.approved_at)}</span>
          </dd>
        </div>
        <div>
          <dt>Ran by</dt>
          <dd>
            {receipt.executed_by.email}
            <span className="muted">{formatTime(receipt.executed_at)}</span>
          </dd>
        </div>
        <div>
          <dt>Rows</dt>
          <dd>
            <span>
              {receipt.previewed_rows == null
                ? 'Not previewed'
                : `${rowsText(receipt.previewed_rows)} previewed`}
              ,{' '}
              {receipt.affected_rows == null
                ? 'changed rows unknown'
                : `${rowsText(receipt.affected_rows)} changed`}
            </span>
          </dd>
        </div>
        <div>
          <dt>Bound to</dt>
          <dd>{receipt.bound_to ? boundTo[receipt.bound_to] : 'Nothing'}</dd>
        </div>
        <div>
          <dt>Digest</dt>
          <dd>
            <code className="identifier" title={receipt.digest}>
              {shortDigest(receipt.digest)}
            </code>
            <Button
              aria-label="Copy digest"
              onClick={() => void copy(receipt.digest)}
            >
              <Copy size={16} />
            </Button>
          </dd>
        </div>
      </dl>
      <p className="ar-fine">
        The receipt proves who asked, who approved and what ran. It is not a
        backup and cannot undo the write.
      </p>
    </section>
  );
}
