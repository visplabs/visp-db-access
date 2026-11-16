import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request, json } from '../api/client';
import { useToast } from '../components/ui/toast';
import { message } from './utils';
export const useResource = <T>(path: string, enabled = true) =>
  useQuery({
    queryKey: ['api', path],
    queryFn: ({ signal }) => request<T>(path, { signal }),
    enabled,
  });
/** A keyset-paged list, read to its end. For lists that a person must see
 * whole, such as the agents an administrator can stop. */
export const useAllPages = <T>(path: string) =>
  useQuery({
    queryKey: ['api', path],
    queryFn: async ({ signal }) => {
      const items: T[] = [];
      let cursor: string | null = null;
      // A hard stop, so a server fault can never loop forever.
      for (let page = 0; page < 100; page += 1) {
        const query: string = `?limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
        const body = await request<{ items: T[]; next_cursor: string | null }>(
          `${path}${query}`,
          { signal },
        );
        items.push(...body.items);
        cursor = body.next_cursor;
        if (!cursor) break;
      }
      return { items };
    },
  });
export function useAction<T = unknown>(success = 'Saved') {
  const cache = useQueryClient(),
    toast = useToast();
  return useMutation({
    // Forget a request as soon as nothing watches it. Its body can hold a
    // password and its answer a token; the default keeps both for minutes.
    gcTime: 0,
    mutationFn: ({
      path,
      method = 'POST',
      body,
    }: {
      path: string;
      method?: string;
      body?: unknown;
    }) => request<T>(path, json(method, body)),
    onSuccess: () => {
      void cache.invalidateQueries();
      if (success) toast(success);
    },
    onError: (error) => toast(message(error), 'error'),
  });
}
