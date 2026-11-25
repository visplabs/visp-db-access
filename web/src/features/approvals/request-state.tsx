import type { Approval } from '../../api/types';
import { Badge, VerdictChip } from '../../components/ui';
import { APPROVED_NOT_RUN, verdictOfApproval } from '../../lib/verdict';

const statusTone: Record<Approval['status'], string> = {
  pending: 'warning',
  approved: 'success',
  executed: 'success',
  rejected: 'danger',
  failed: 'danger',
  executing: 'info',
  // Neither is a risk: the request simply will not run.
  withdrawn: 'neutral',
  expired: 'neutral',
};
/** Statuses whose bare word would mislead: approved has not run yet. */
const statusWords: Partial<Record<Approval['status'], string>> = {
  approved: APPROVED_NOT_RUN,
  executing: 'Running',
};
/** The status of a request in words: for states that are not a verdict
 * (approved and running: nothing has run yet; and endings without one). */
export function ApprovalBadge({ status }: { status: Approval['status'] }) {
  return (
    <Badge variant="status" tone={statusTone[status]}>
      {statusWords[status] ?? status}
    </Badge>
  );
}

/** The verdict of a request, or its status when it has none. */
export function RequestState({
  status,
  size = 'sm',
}: {
  status: Approval['status'];
  size?: 'sm' | 'md';
}) {
  const verdict = verdictOfApproval(status);
  return verdict ? (
    <VerdictChip verdict={verdict} size={size} />
  ) : (
    <ApprovalBadge status={status} />
  );
}
