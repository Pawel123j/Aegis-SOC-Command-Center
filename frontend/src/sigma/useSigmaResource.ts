import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type { SigmaScope } from './useSigmaScope';

export function useSigmaResource<T>(path: string, scope: SigmaScope) {
  const { epoch, expired, capture, isCurrent } = scope;
  const [state, setState] = useState<{
    path: string;
    epoch: number;
    data: T | null;
    pending: boolean;
    error: unknown;
  }>({ path, epoch, data: null, pending: true, error: null });
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => {
    setState({ path, epoch, data: null, pending: true, error: null });
    setRevision((value) => value + 1);
  }, [path, epoch]);
  useEffect(() => {
    let active = true;
    void Promise.resolve().then(async () => {
      if (!active || expired) return;
      const request = capture();
      setState({ path, epoch, data: null, pending: true, error: null });
      try {
        const response = await api.get<T>(path);
        if (active && isCurrent(request))
          setState({ path, epoch, data: response, pending: false, error: null });
      } catch (error) {
        if (active && isCurrent(request))
          setState({ path, epoch, data: null, pending: false, error });
      }
    });
    return () => {
      active = false;
    };
  }, [path, epoch, expired, capture, isCurrent, revision]);
  const visible = !expired && state.epoch === epoch && state.path === path;
  return {
    data: visible ? state.data : null,
    error: visible ? state.error : null,
    pending: !expired && (!visible || state.pending),
    reload,
  };
}
