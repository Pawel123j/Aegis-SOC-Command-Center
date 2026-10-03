import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api';
import type { MitreCoverage } from './types';

export function useCoverage(path: string) {
  const [state, setState] = useState<{
    path: string;
    data: MitreCoverage | null;
    pending: boolean;
    error: unknown;
  }>({ path, data: null, pending: true, error: null });
  const generation = useRef(0);
  const reload = useCallback(async () => {
    const revision = ++generation.current;
    setState({ path, data: null, pending: true, error: null });
    try {
      const result = await api.get<MitreCoverage>(path);
      if (generation.current === revision) {
        setState({ path, data: result, pending: false, error: null });
      }
    } catch (failure) {
      if (generation.current === revision) {
        setState({ path, data: null, pending: false, error: failure });
      }
    }
  }, [path]);
  useEffect(() => {
    let active = true;
    const counter = generation;
    void Promise.resolve().then(() => {
      if (active) return reload();
    });
    const unsubscribe = api.subscribe(() => {
      counter.current++;
      setState({
        path,
        data: null,
        pending: false,
        error: new Error('Sesja zmieniła się. Odśwież pokrycie po sprawdzeniu bieżącego konta.'),
      });
    });
    return () => {
      active = false;
      counter.current++;
      unsubscribe();
    };
  }, [path, reload]);
  return {
    data: state.path === path ? state.data : null,
    pending: state.path !== path || state.pending,
    error: state.path === path ? state.error : null,
    reload,
  };
}
