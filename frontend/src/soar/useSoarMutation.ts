import { useRef, useState } from 'react';
import { api } from '../api';
import type { Me } from '../types';
import type { SigmaScope } from '../sigma/useSigmaScope';

export function useSoarMutation(user: Me, scope: SigmaScope) {
  const busy = useRef(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function send<T>(
    path: string,
    body: unknown,
    options: { method?: string; headers?: Record<string, string> } = {},
  ) {
    if (busy.current || scope.expired) return null;
    const epoch = scope.capture();
    busy.current = true;
    setPending(true);
    setError(null);
    try {
      const me = await api.get<Me>('/auth/me');
      if (!scope.isCurrent(epoch)) return null;
      if (
        me.id !== user.id ||
        me.role !== user.role ||
        me.permissions.length !== user.permissions.length ||
        !user.permissions.every((p) => me.permissions.includes(p))
      ) {
        throw new Error('Uprawnienia zmieniły się. Otwórz ponownie panel procedur.');
      }
      const result = await api.request<T>(path, {
        method: options.method ?? 'POST',
        headers: options.headers,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15000),
      });
      return scope.isCurrent(epoch) ? result : null;
    } catch (failure) {
      if (scope.isCurrent(epoch)) setError(failure);
      return null;
    } finally {
      busy.current = false;
      if (scope.isCurrent(epoch)) setPending(false);
    }
  }
  return { send, pending, error };
}
