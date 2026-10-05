import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type { IntelligenceScope } from './useIntelligenceScope';

export function useIntelligenceResource<T>(path: string | null, scope: IntelligenceScope) {
  const { epoch, expired, capture, isCurrent } = scope;
  const [state, setState] = useState<{
    path: string | null;
    epoch: number;
    data: T | null;
    pending: boolean;
    error: unknown;
  }>({ path, epoch, data: null, pending: path !== null, error: null });
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => {
    setState({ path, epoch, data: null, pending: path !== null, error: null });
    setRevision((value) => value + 1);
  }, [path, epoch]);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    void Promise.resolve().then(async () => {
      if (!active || expired || path === null) return;
      const request = capture();
      setState({ path, epoch, data: null, pending: true, error: null });
      try {
        const data = await api.request<T>(path, {
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
        });
        if (active && isCurrent(request))
          setState({ path, epoch, data, pending: false, error: null });
      } catch (error) {
        if (active && isCurrent(request))
          setState({ path, epoch, data: null, pending: false, error });
      }
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [path, epoch, expired, capture, isCurrent, revision]);
  const visible = path !== null && !expired && state.epoch === epoch && state.path === path;
  return {
    data: visible ? state.data : null,
    error: visible ? state.error : null,
    pending: path !== null && !expired && (!visible || state.pending),
    reload,
  };
}
