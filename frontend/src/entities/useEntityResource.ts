import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api';

export function useEntityResource<T>(path: string | null) {
  const [state, setState] = useState<{
    path: string | null;
    data: T | null;
    pending: boolean;
    error: unknown;
  }>({ path, data: null, pending: path !== null, error: null });
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const reload = useCallback(async () => {
    controller.current?.abort();
    const revision = ++generation.current;
    if (path === null) {
      setState({ path, data: null, pending: false, error: null });
      return;
    }
    const requestController = new AbortController();
    controller.current = requestController;
    setState({ path, data: null, pending: true, error: null });
    try {
      const data = await api.request<T>(path, {
        signal: AbortSignal.any([requestController.signal, AbortSignal.timeout(15000)]),
      });
      if (generation.current === revision) setState({ path, data, pending: false, error: null });
    } catch (error) {
      if (generation.current === revision) setState({ path, data: null, pending: false, error });
    }
  }, [path]);
  useEffect(() => {
    let active = true;
    const counter = generation;
    const currentController = controller;
    void Promise.resolve().then(() => {
      if (active) return reload();
    });
    const unsubscribe = api.subscribe(() => {
      counter.current++;
      currentController.current?.abort();
      setState({
        path,
        data: null,
        pending: false,
        error: new Error('Sesja zmieniła się. Odśwież profile po sprawdzeniu bieżącego konta.'),
      });
    });
    return () => {
      active = false;
      counter.current++;
      currentController.current?.abort();
      unsubscribe();
    };
  }, [path, reload]);
  return {
    data: state.path === path ? state.data : null,
    error: state.path === path ? state.error : null,
    pending: state.path !== path || state.pending,
    reload,
  };
}
