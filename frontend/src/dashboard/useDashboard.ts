import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../api';
import { useSigmaScope } from '../sigma/useSigmaScope';
import type { DashboardReport } from './types';

export function useDashboard(path: string, automatic: boolean) {
  const scope = useSigmaScope();
  const { epoch, expired, capture, isCurrent } = scope;
  const [revision, setRevision] = useState(0);
  const [visible, setVisible] = useState(document.visibilityState !== 'hidden');
  const [state, setState] = useState<{
    path: string;
    epoch: number;
    data: DashboardReport | null;
    pending: boolean;
    error: unknown;
  }>({ path, epoch, data: null, pending: true, error: null });
  const reload = useCallback(() => setRevision((value) => value + 1), []);
  useEffect(() => {
    const changed = () => setVisible(document.visibilityState !== 'hidden');
    document.addEventListener('visibilitychange', changed);
    return () => document.removeEventListener('visibilitychange', changed);
  }, []);
  useEffect(() => {
    let active = true;
    void Promise.resolve().then(async () => {
      if (!active || expired) return;
      const request = capture();
      setState((old) => ({
        path,
        epoch,
        data: old.path === path && old.epoch === epoch ? old.data : null,
        pending: true,
        error: null,
      }));
      try {
        const data = await api.get<DashboardReport>(path);
        if (active && isCurrent(request))
          setState({ path, epoch, data, pending: false, error: null });
      } catch (error) {
        if (active && isCurrent(request))
          setState((old) => ({
            path,
            epoch,
            data: error instanceof ApiError && [401, 403].includes(error.status) ? null : old.data,
            pending: false,
            error,
          }));
      }
    });
    return () => {
      active = false;
    };
  }, [path, epoch, expired, capture, isCurrent, revision]);
  const current = !expired && state.path === path && state.epoch === epoch;
  const forbidden = state.error instanceof ApiError && [401, 403].includes(state.error.status);
  useEffect(() => {
    if (!current || !automatic || !visible || state.pending || forbidden) return;
    const timer = setTimeout(reload, 10_000);
    return () => clearTimeout(timer);
  }, [current, automatic, visible, state, forbidden, reload]);
  return {
    data: current ? state.data : null,
    error: current ? state.error : null,
    pending: !expired && (!current || state.pending),
    reload,
    expired,
    polling: automatic && visible && !expired && !forbidden,
  };
}
