import { useCallback, useState } from 'react';
import { useResource } from '../utilities';
import type { Page } from '../types';

export function usePage<T>(loader: (cursor: string | null) => Promise<Page<T>>) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [previous, setPrevious] = useState<(string | null)[]>([]);
  const load = useCallback(() => loader(cursor), [loader, cursor]);
  const resource = useResource(load);
  return {
    ...resource,
    pagination: {
      previous: previous.length,
      hasNext: Boolean(resource.data?.next_cursor),
      pending: resource.pending,
      onPrevious: () => {
        setCursor(previous.at(-1) ?? null);
        setPrevious((items) => items.slice(0, -1));
      },
      onNext: () => {
        if (!resource.data?.next_cursor) return;
        setPrevious((items) => [...items, cursor]);
        setCursor(resource.data.next_cursor);
      },
    },
  };
}
