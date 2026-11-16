import { useCallback } from 'react';
import { useToast } from '../components/ui/toast';

/** Copy text and always say what happened. The clipboard is not available on
 * a plain-HTTP origin, and a browser can refuse the write. */
export function useCopy() {
  const toast = useToast();
  return useCallback(
    async (text: string) => {
      try {
        if (!navigator.clipboard) throw new Error('unavailable');
        await navigator.clipboard.writeText(text);
        toast('Copied');
      } catch {
        toast('Could not copy. Select the text and copy it yourself.', 'error');
      }
    },
    [toast],
  );
}
