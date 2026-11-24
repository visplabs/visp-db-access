import type { Agent } from '../../api/types';
import { useAction } from '../../lib/query';
import { Button } from '../../components/ui';

/** Pause or resume an agent. While the request is under way the button
 * says so with `aria-disabled` and ignores clicks, but it stays focusable:
 * a disabled button drops the keyboard focus to the page. The same button
 * then reads "Resume agent", with the focus still on it. */
export function PauseButton({
  agent,
}: {
  agent: Pick<Agent, 'id' | 'paused'>;
}) {
  const pause = useAction<Agent>(
    agent.paused ? 'Agent resumed' : 'Agent paused',
  );
  return (
    <Button
      variant={agent.paused ? 'secondary' : 'danger'}
      aria-disabled={pause.isPending || undefined}
      onClick={() => {
        if (pause.isPending) return;
        pause.mutate({
          path: `/agents/${encodeURIComponent(agent.id)}`,
          method: 'PATCH',
          body: { paused: !agent.paused },
        });
      }}
    >
      {agent.paused ? 'Resume agent' : 'Pause agent'}
    </Button>
  );
}
